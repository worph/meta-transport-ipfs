//! [`TransportPlugin`] for the IPFS tier, plus the public `/ipfs/:cid` gateway
//! and the hull's `/ipfs-tier/*` facade (see `meta_feeder_sdk::transport::ipfs`).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use blockstore::Blockstore;
use meta_feeder_sdk::transport::ipfs::{
    Complete, Directory, DropRefs, FirstLeaf, ForgetLibrary, Imported, LeafBacking, Present,
    RelPath, ShareContainer, ShareLibrary, Shared,
};
use meta_feeder_sdk::transport::{
    ApiError, Capabilities, ConfigPlane, Deleted, FocusView, Health, Job, Lane, Manifest, ReconcileReport,
    ReconcileRequest, TransportPlugin, CONTRACT_VERSION,
};
use serde::Deserialize;
use tracing::{debug, warn};

use crate::api::files::{bitswap, bytes_to_response, PLAYER_HEADER};
use crate::api::AppState;
use crate::blockstore::parse_record_cid;
use crate::swarm::Command;

/// Ceiling on a hull → plugin object upload (`import`, `block`): the url
/// locator's own 512 MiB cap, plus headroom.
const IMPORT_BODY_LIMIT: usize = 600 * 1024 * 1024;

pub struct IpfsPlugin {
    pub state: Arc<AppState>,
    pub config: Arc<ConfigPlane>,
}

fn lane_of(headers: &HeaderMap) -> Lane {
    Lane::from_header(
        headers
            .get(meta_feeder_sdk::transport::dto::HDR_LANE)
            .and_then(|v| v.to_str().ok()),
    )
}

#[async_trait]
impl TransportPlugin for IpfsPlugin {
    fn manifest(&self) -> Manifest {
        Manifest {
            id: "ipfs".into(),
            implementation: "meta-transport-ipfs (rust-libp2p + beetswap, nocopy filestore)".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            contract: CONTRACT_VERSION,
            capabilities: Capabilities { fetch: true, share: true },
            config: true,
        }
    }

    async fn health(&self) -> Health {
        Health {
            ok: !self.state.swarm_tx.is_closed(),
            detail: None,
        }
    }

    /// The bitswap byte path (`fetch_raw_via_bitswap`): local blockstore, else a
    /// bitswap WANT; dag-pb walks only the leaves the range covers.
    async fn raw(&self, cid: String, headers: HeaderMap) -> Response {
        let lane = lane_of(&headers);
        let player = headers.contains_key(PLAYER_HEADER);
        match bitswap::fetch_raw_via_bitswap(&self.state, &cid, headers.get(header::RANGE), lane, player).await {
            Ok(r) => r,
            Err(e) => e.into_response(),
        }
    }

    async fn jobs(&self) -> Result<Vec<Job>, ApiError> {
        Ok(self
            .state
            .ingress
            .jobs()
            .into_iter()
            .map(|j| Job {
                id: j.container.clone(),
                cids: vec![j.root.clone()],
                bytes_on_disk: j.received_bytes(),
                complete: j.is_complete(),
                filling: j.is_filling(),
                state: if j.is_committed() { "committed".into() } else { "streaming".into() },
                extra: serde_json::Value::Null,
            })
            .collect())
    }

    /// Drop a cid's blocks (and any in-flight ingress for it).
    async fn delete(&self, cid: String, _keep: Vec<String>) -> Result<Deleted, ApiError> {
        let Ok(mscid) = parse_record_cid(&cid) else {
            return Err(ApiError::NotFound);
        };
        self.state.ingress.discard(&cid).await;
        crate::share::remove_dag(&self.state, &mscid).await;
        Ok(Deleted::default())
    }

    async fn reconcile(&self, _req: ReconcileRequest) -> Result<ReconcileReport, ApiError> {
        Ok(ReconcileReport::default())
    }

    fn focus(&self) -> &Arc<FocusView> {
        &self.state.focus
    }

    fn config(&self) -> Option<Arc<ConfigPlane>> {
        Some(Arc::clone(&self.config))
    }

    fn extra_routes(self: Arc<Self>) -> Router {
        let gateway = Router::new()
            .route("/ipfs/:cid", get(crate::api::ipfs_gateway::get_ipfs))
            .route("/ipfs-tier/resolve/:cid", get(crate::resolve::resolve))
            .with_state(Arc::clone(&self.state));
        Router::new()
            .route("/ipfs-tier/peers", get(peers))
            .route("/ipfs-tier/directory", get(directory))
            .route("/ipfs-tier/local/:cid", get(local))
            .route("/ipfs-tier/has/:cid", get(has))
            .route("/ipfs-tier/complete/:cid", get(complete))
            .route("/ipfs-tier/cat/:cid", get(cat))
            .route("/ipfs-tier/fetch/:cid", get(fetch))
            // Whole objects arrive here (the url locator buffers up to 512 MiB,
            // a redeem up to 32 MiB) — axum's default 2 MiB body limit would cut
            // them off. In-process there was no limit at all.
            .route(
                "/ipfs-tier/block/:cid",
                put(put_block).layer(DefaultBodyLimit::max(IMPORT_BODY_LIMIT)),
            )
            .route(
                "/ipfs-tier/import",
                post(import).layer(DefaultBodyLimit::max(IMPORT_BODY_LIMIT)),
            )
            .route("/ipfs-tier/forget/:cid", post(forget))
            .route("/ipfs-tier/forget-library", post(forget_library))
            .route("/ipfs-tier/provide/:cid", post(provide))
            .route("/ipfs-tier/unprovide/:cid", post(unprovide))
            .route("/ipfs-tier/drop-refs", post(drop_refs))
            .route("/ipfs-tier/first-leaf/:cid", get(first_leaf))
            .route("/ipfs-tier/rel-path/:midhash", get(rel_path))
            .route("/ipfs-tier/share/library", post(share_library))
            .route("/ipfs-tier/share/container", post(share_container))
            .route("/ipfs-tier/stats/blockstore", get(blockstore_stats))
            .route("/ipfs-tier/debug/:cid", get(debug_block))
            .route("/ipfs-tier/restart", post(restart))
            .with_state(self)
            .merge(gateway)
    }
}

type S = State<Arc<IpfsPlugin>>;

fn bad_cid(e: anyhow::Error) -> Response {
    ApiError::BadRequest(format!("cid: {e:#}")).into_response()
}

async fn peers(State(p): S) -> Response {
    let (tx, rx) = tokio::sync::oneshot::channel();
    if p.state.swarm_tx.send(Command::Peers { reply: tx }).await.is_err() {
        return ApiError::SwarmGone.into_response();
    }
    match rx.await {
        Ok(info) => Json(info).into_response(),
        Err(_) => ApiError::SwarmGone.into_response(),
    }
}

async fn directory(State(p): S) -> Response {
    Json(Directory { peers: p.state.peer_directory.snapshot() }).into_response()
}

/// `try_local_block`: a single raw/midhash block straight out of the store.
async fn local(State(p): S, Path(cid): Path<String>, headers: HeaderMap) -> Response {
    match bitswap::try_local_block(&p.state, &cid, headers.get(header::RANGE)).await {
        Some(r) => r,
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn has(State(p): S, Path(cid): Path<String>) -> Response {
    let present = match parse_record_cid(&cid) {
        Ok(m) => matches!(p.state.block_store.get(&m).await, Ok(Some(_))),
        Err(_) => false,
    };
    Json(Present { present }).into_response()
}

async fn complete(State(p): S, Path(cid): Path<String>) -> Response {
    let complete = match parse_record_cid(&cid) {
        Ok(m) => crate::share::local_dag_complete(&p.state, &m).await,
        Err(_) => false,
    };
    Json(Complete { complete }).into_response()
}

#[derive(Deserialize)]
struct CatQuery {
    #[serde(default)]
    max: Option<usize>,
}

/// A block (or a dag-pb file, assembled) through `ipfs_walker::get_block` —
/// local, else bitswap. No seed row, no ingress job: a side-effect-free read
/// (the `.nzb` manifest fetch).
async fn cat(State(p): S, Path(cid): Path<String>, Query(q): Query<CatQuery>) -> Response {
    let mscid = match parse_record_cid(&cid) {
        Ok(m) => m,
        Err(e) => return bad_cid(e),
    };
    let max = q.max.unwrap_or_else(crate::api::ipfs_walker::max_body_bytes);
    match read_object(&p.state, &mscid, max).await {
        Ok(bytes) => (StatusCode::OK, bytes).into_response(),
        Err(e) => ApiError::Upstream(format!("{e:#}")).into_response(),
    }
}

/// A block, or a dag-pb file assembled, up to `max` bytes — local, else bitswap.
pub(crate) async fn read_object(
    state: &AppState,
    mscid: &crate::blockstore::MsCid,
    max: usize,
) -> anyhow::Result<Vec<u8>> {
    let block = crate::api::ipfs_walker::get_block(state, mscid, Lane::Focused).await?;
    if mscid.codec() == crate::api::ipfs_walker::DAGPB_CODEC {
        return crate::api::ipfs_walker::assemble_dagpb_file(state, &block, max, Lane::Focused).await;
    }
    anyhow::ensure!(
        block.len() <= max,
        "{mscid} is {} bytes, over the {max}-byte ceiling",
        block.len()
    );
    Ok(block)
}

#[derive(Deserialize)]
struct FetchQuery {
    #[serde(default)]
    timeout_ms: Option<u64>,
}

/// One block: local, else a bitswap WANT bounded by `timeout_ms`. Header
/// `x-metamesh-source: local|bitswap` says which (the probe grades on it).
async fn fetch(State(p): S, Path(cid): Path<String>, Query(q): Query<FetchQuery>) -> Response {
    let mscid = match parse_record_cid(&cid) {
        Ok(m) => m,
        Err(e) => return bad_cid(e),
    };
    if let Ok(Some(bytes)) = p.state.block_store.get(&mscid).await {
        return ([("x-metamesh-source", "local")], bytes).into_response();
    }
    let timeout = Duration::from_millis(q.timeout_ms.unwrap_or(5_000));
    match crate::swarm::bitswap_get_block(&p.state.swarm_tx, mscid, timeout).await {
        Ok(bytes) => ([("x-metamesh-source", "bitswap")], bytes).into_response(),
        Err(e) => {
            debug!(%cid, error = %e, "ipfs-tier fetch: bitswap miss");
            ApiError::NotFound.into_response()
        }
    }
}

async fn put_block(State(p): S, Path(cid): Path<String>, body: Bytes) -> Response {
    match crate::blockstore::put_ipfs_block(p.state.block_store.as_ref(), &cid, &body).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => ApiError::Upstream(format!("put block: {e:#}")).into_response(),
    }
}

/// Chunk a whole object into kubo-identical blocks and store them material
/// (`put_ipfs_blocks(compute_ipfs_blocks(..))` — the url locator and redeem).
async fn import(State(p): S, body: Bytes) -> Response {
    let size = body.len() as u64;
    let blocks = crate::ipfs_chunk::compute_ipfs_blocks(&body);
    let root = blocks.root.clone();
    match crate::blockstore::put_ipfs_blocks(p.state.block_store.as_ref(), &blocks).await {
        Ok(()) => Json(Imported { root, size }).into_response(),
        Err(e) => ApiError::Upstream(format!("import: {e:#}")).into_response(),
    }
}

/// Drop a dag's blocks (the teardown of an ipfs seed row).
async fn forget(State(p): S, Path(cid): Path<String>) -> Response {
    match parse_record_cid(&cid) {
        Ok(m) => {
            crate::share::remove_dag(&p.state, &m).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => bad_cid(e),
    }
}

async fn forget_library(State(p): S, Json(req): Json<ForgetLibrary>) -> Response {
    let root = match parse_record_cid(&req.root) {
        Ok(m) => m,
        Err(e) => return bad_cid(e),
    };
    match p.state.block_store.remove_library_dag(&root, &req.midhash).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => ApiError::Upstream(format!("{e:#}")).into_response(),
    }
}

async fn provide(State(p): S, Path(cid): Path<String>) -> Response {
    if !p.state.seed_dht_provide {
        return StatusCode::NO_CONTENT.into_response();
    }
    match parse_record_cid(&cid) {
        Ok(m) => {
            let _ = p.state.swarm_tx.send(Command::Provide { cid: m }).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => bad_cid(e),
    }
}

async fn unprovide(State(p): S, Path(cid): Path<String>) -> Response {
    if !p.state.seed_dht_provide {
        return StatusCode::NO_CONTENT.into_response();
    }
    match parse_record_cid(&cid) {
        Ok(m) => {
            let _ = p.state.swarm_tx.send(Command::StopProviding { cid: m }).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => bad_cid(e),
    }
}

async fn drop_refs(State(p): S, Json(req): Json<DropRefs>) -> Response {
    match p.state.block_store.drop_refs_for_materials(&req.materials).await {
        Ok(n) => Json(serde_json::json!({ "dropped": n })).into_response(),
        Err(e) => ApiError::Upstream(format!("{e:#}")).into_response(),
    }
}

async fn first_leaf(State(p): S, Path(cid): Path<String>) -> Response {
    let root = match parse_record_cid(&cid) {
        Ok(m) => m,
        Err(e) => return bad_cid(e),
    };
    match p.state.block_store.first_leaf_backing(&root).await {
        Ok(b) => {
            let backing = match b {
                crate::filestore::LeafBacking::MetaCore(m) => LeafBacking::MetaCore(m),
                crate::filestore::LeafBacking::Cache => LeafBacking::Cache,
                crate::filestore::LeafBacking::Material => LeafBacking::Material,
                crate::filestore::LeafBacking::Unknown => LeafBacking::Unknown,
            };
            Json(FirstLeaf { backing }).into_response()
        }
        Err(e) => ApiError::Upstream(format!("{e:#}")).into_response(),
    }
}

async fn rel_path(State(p): S, Path(midhash): Path<String>) -> Response {
    match p.state.block_store.resolver().rel_path_for(&midhash).await {
        Ok(rel) => Json(RelPath { rel }).into_response(),
        Err(e) => ApiError::Upstream(format!("{e:#}")).into_response(),
    }
}

async fn share_library(State(p): S, Json(req): Json<ShareLibrary>) -> Response {
    match crate::share::share_library(&p.state, &req.rel, &req.midhash).await {
        Ok((root, size)) => Json(Shared { root, size, refs: 0, complete: false }).into_response(),
        Err(e) => ApiError::Upstream(format!("{e:#}")).into_response(),
    }
}

async fn share_container(State(p): S, Json(req): Json<ShareContainer>) -> Response {
    let path = std::path::PathBuf::from(&req.path);
    match crate::share::share_container(&p.state, &req.container, &req.rel, &path).await {
        Ok((root, size, refs)) => {
            let complete = if req.verify_complete {
                match parse_record_cid(&root) {
                    Ok(m) => crate::share::local_dag_complete(&p.state, &m).await,
                    Err(_) => false,
                }
            } else {
                false
            };
            Json(Shared { root, size, refs, complete }).into_response()
        }
        Err(e) => ApiError::Upstream(format!("{e:#}")).into_response(),
    }
}

/// The `/api/stats/blockstore` body. Walks every btree — never polled.
async fn blockstore_stats(State(p): S) -> Response {
    let db_path = p.state.data_dir.join("ipfs").join("blocks.redb");
    match p.state.block_store.stats(Some(db_path)).await {
        Ok(stats) => Json(serde_json::to_value(stats).unwrap_or_else(|_| serde_json::json!({}))).into_response(),
        Err(e) => ApiError::Upstream(format!("blockstore stats: {e:#}")).into_response(),
    }
}

/// The `/api/debug/blockstore/:cid` body.
async fn debug_block(State(p): S, Path(cid): Path<String>) -> Response {
    let mscid = match parse_record_cid(&cid) {
        Ok(m) => m,
        Err(e) => return bad_cid(e),
    };
    let mscid_bytes_hex: String = mscid.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
    match p.state.block_store.get(&mscid).await {
        Ok(Some(bytes)) => Json(serde_json::json!({
            "has": true,
            "bytes": bytes.len(),
            "mscid_debug": format!("{:?}", mscid),
            "mscid_bytes_hex": mscid_bytes_hex,
        }))
        .into_response(),
        Ok(None) => Json(serde_json::json!({
            "has": false,
            "bytes": 0,
            "mscid_debug": format!("{:?}", mscid),
            "mscid_bytes_hex": mscid_bytes_hex,
        }))
        .into_response(),
        Err(e) => ApiError::Upstream(format!("blockstore.get: {e}")).into_response(),
    }
}

/// Small-body helper kept for parity with the monolith's single-block path.
#[allow(dead_code)]
pub fn bytes_response(bytes: Vec<u8>, range: Option<&HeaderValue>) -> Response {
    bytes_to_response(bytes, range)
}

/// The hull changed the endpoints this plugin announces (`peer_url`) or reads
/// through (`meta_core_url`): exit so `restart: unless-stopped` re-execs us and
/// `main` asks the hull again.
async fn restart() -> StatusCode {
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        warn!("restarting to pick up the hull's new network settings");
        std::process::exit(0);
    });
    StatusCode::NO_CONTENT
}
