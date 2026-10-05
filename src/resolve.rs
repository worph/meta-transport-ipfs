//! `GET /ipfs-tier/resolve/:cid?hint=` — a [pointer](meta_feeder_sdk::transport::pointer)'s bytes.
//!
//! A pointer (an `nzb-release`'s `.nzb`, a `provider-file`'s subtitle) costs
//! quota on an account this peer does not hold, so only a gateway whose feeder
//! holds the key can answer it — never bitswap: the cid is an address, not a
//! hash of the bytes.
//!
//! 1. **Stored.** `hint` is the content cid the record's pointer field names
//!    (the hull reads it). Held locally → served, no network.
//! 2. **Redeemed.** Otherwise `POST {gateway}/api/file/:cid/redeem` at each
//!    gateway whose claim covers the pointer, fastest first
//!    ([`crate::gateways`]). The gateway names the bytes' content cid; we
//!    re-derive it with the kubo-identical chunker and refuse a mismatch, then
//!    store the blocks. A repeat redeem is answered from the gateway's own store
//!    without spending quota, so a second box pays nothing.
//!
//! The hull owns what follows — the seed row, the permanent copy in meta-core,
//! the record link — so this route only fetches, verifies and stores blocks.
//! Moved here from the hull's `redeem.rs` (meta-share 2.4.0), unchanged in
//! behaviour: ordering, timeout, size cap, verification, error ranking.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{header::RETRY_AFTER, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use meta_feeder_sdk::transport::dto::{
    HDR_RESOLVE_ERROR, RESOLVE_NOT_FOUND, RESOLVE_NO_GATEWAY, RESOLVE_QUOTA, RESOLVE_UNCLAIMED,
    RESOLVE_UPSTREAM,
};
use meta_feeder_sdk::transport::hull::{HDR_MANIFEST_CID, HDR_MANIFEST_SOURCE};
use meta_feeder_sdk::transport::pointer;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::api::AppState;
use crate::blockstore::parse_record_cid;
use crate::ipfs_chunk::IpfsBlocks;

/// Response header naming the redeemed bytes' content cid.
pub const CONTENT_CID_HEADER: &str = "x-metamesh-content-cid";

/// One redeem's wall-clock budget: the gateway makes a metered upstream call and
/// a store-back before it answers.
const REDEEM_TIMEOUT: Duration = Duration::from_secs(60);

/// Ceiling on a redeemed body. A 100k-segment `.nzb` is ~16 MiB; a subtitle is
/// kilobytes. Bounds a broken or hostile gateway.
pub const MAX_REDEEM_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug)]
pub enum RedeemError {
    /// Every claiming gateway answered `404`.
    NotFound,
    /// A gateway refused on quota; `retry_after` in seconds.
    Quota { retry_after: Option<u64> },
    /// Transport failure, unexpected status, or a body that doesn't hash to the
    /// cid the gateway named.
    Upstream(String),
}

#[derive(Deserialize)]
pub struct ResolveQuery {
    #[serde(default)]
    hint: Option<String>,
}

pub async fn resolve(
    State(state): State<Arc<AppState>>,
    Path(cid): Path<String>,
    Query(q): Query<ResolveQuery>,
) -> Response {
    let ptr = match pointer::decode(&cid) {
        Some(Ok(p)) => p,
        Some(Err(e)) => return refuse(StatusCode::BAD_REQUEST, RESOLVE_NOT_FOUND, None, format!("{e:#}")),
        None => {
            return refuse(
                StatusCode::BAD_REQUEST,
                RESOLVE_NOT_FOUND,
                None,
                format!("`{cid}` is not a pointer cid"),
            )
        }
    };

    if let Some(hint) = q.hint.as_deref().filter(|h| !h.is_empty()) {
        if let Some(bytes) = stored(&state, hint).await {
            debug!(cid, hint, "resolve: served the stored copy");
            return answer(bytes, "store", hint);
        }
    }

    let Some(key) = ptr.redeem else {
        return refuse(
            StatusCode::NOT_FOUND,
            RESOLVE_NOT_FOUND,
            None,
            format!("`{cid}` resolves only from a stored copy, and none is held here"),
        );
    };
    let targets = state.gateways.candidates(&state.peer_directory, key.codec, &key.key);
    if targets.is_empty() {
        return if state.gateways.knows_any(&state.peer_directory) {
            refuse(
                StatusCode::NOT_FOUND,
                RESOLVE_UNCLAIMED,
                None,
                format!("no known gateway redeems {} `{}`", key.codec, key.key),
            )
        } else {
            refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                RESOLVE_NO_GATEWAY,
                Some(2),
                "no gateway reachable yet".into(),
            )
        };
    }

    match redeem_from(&state.http, &targets, &cid).await {
        Ok((blocks, body)) => {
            let root = blocks.root.clone();
            if let Err(e) = crate::blockstore::put_ipfs_blocks(state.block_store.as_ref(), &blocks).await {
                // The bytes are verified; failing to keep them only costs a
                // repeat redeem, which the gateway answers from its store.
                warn!(cid, root, error = %format!("{e:#}"), "resolve: storing the redeemed blocks failed");
            }
            debug!(cid, root, size = body.len(), "resolve: redeemed through a gateway");
            answer(body, "redeem", &root)
        }
        Err(RedeemError::NotFound) => refuse(
            StatusCode::NOT_FOUND,
            RESOLVE_NOT_FOUND,
            None,
            "every gateway that claims it answered not found".into(),
        ),
        Err(RedeemError::Quota { retry_after }) => refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            RESOLVE_QUOTA,
            Some(retry_after.unwrap_or(3600)),
            "the provider's quota is spent".into(),
        ),
        Err(RedeemError::Upstream(e)) => refuse(StatusCode::BAD_GATEWAY, RESOLVE_UPSTREAM, None, e),
    }
}

/// The stored copy `hint` names, when its whole dag is held locally.
async fn stored(state: &AppState, hint: &str) -> Option<Vec<u8>> {
    let mscid = parse_record_cid(hint).ok()?;
    if !crate::share::local_dag_complete(state, &mscid).await {
        return None;
    }
    crate::plugin::read_object(state, &mscid, MAX_REDEEM_BYTES).await.ok()
}

fn answer(bytes: Vec<u8>, source: &'static str, root: &str) -> Response {
    let mut r = (StatusCode::OK, bytes).into_response();
    r.headers_mut().insert(HDR_MANIFEST_SOURCE, HeaderValue::from_static(source));
    if let Ok(v) = HeaderValue::from_str(root) {
        r.headers_mut().insert(HDR_MANIFEST_CID, v);
    }
    r
}

fn refuse(status: StatusCode, why: &'static str, retry_after: Option<u64>, msg: String) -> Response {
    let mut r = (status, msg).into_response();
    r.headers_mut().insert(HDR_RESOLVE_ERROR, HeaderValue::from_static(why));
    if let Some(s) = retry_after {
        r.headers_mut().insert(RETRY_AFTER, HeaderValue::from(s));
    }
    r
}

/// Try each target in turn and return the first verified answer.
///
/// A `404` moves on silently. A quota refusal or an upstream failure also moves
/// on (another gateway may hold its own quota) but is remembered: when nobody
/// delivers, quota outranks an upstream error, which outranks not-found.
pub(crate) async fn redeem_from(
    http: &reqwest::Client,
    targets: &[String],
    cid: &str,
) -> Result<(IpfsBlocks, Vec<u8>), RedeemError> {
    let mut quota: Option<Option<u64>> = None;
    let mut upstream: Option<String> = None;
    for base in targets {
        match redeem_one(http, base, cid).await {
            Ok(v) => return Ok(v),
            Err(RedeemError::Quota { retry_after }) => {
                quota.get_or_insert(retry_after);
            }
            Err(RedeemError::Upstream(e)) => {
                debug!(cid, gateway = %base, error = %e, "redeem: gateway failed; trying the next");
                upstream.get_or_insert(e);
            }
            Err(RedeemError::NotFound) => {}
        }
    }
    if let Some(retry_after) = quota {
        return Err(RedeemError::Quota { retry_after });
    }
    if let Some(e) = upstream {
        return Err(RedeemError::Upstream(e));
    }
    Err(RedeemError::NotFound)
}

async fn redeem_one(
    http: &reqwest::Client,
    base: &str,
    cid: &str,
) -> Result<(IpfsBlocks, Vec<u8>), RedeemError> {
    let url = format!("{}/api/file/{}/redeem", base.trim_end_matches('/'), cid);
    let resp = http
        .post(&url)
        .timeout(REDEEM_TIMEOUT)
        .send()
        .await
        .map_err(|e| RedeemError::Upstream(format!("POST {url}: {e}")))?;
    match resp.status() {
        s if s.is_success() => {}
        reqwest::StatusCode::NOT_FOUND => return Err(RedeemError::NotFound),
        reqwest::StatusCode::TOO_MANY_REQUESTS => {
            let retry_after = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse().ok());
            return Err(RedeemError::Quota { retry_after });
        }
        s => return Err(RedeemError::Upstream(format!("POST {url} answered {s}"))),
    }
    let advertised = resp
        .headers()
        .get(CONTENT_CID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| RedeemError::Upstream(format!("POST {url}: no {CONTENT_CID_HEADER} header")))?;
    if resp.content_length().is_some_and(|n| n > MAX_REDEEM_BYTES as u64) {
        return Err(RedeemError::Upstream(format!(
            "POST {url}: body over the {MAX_REDEEM_BYTES}-byte ceiling"
        )));
    }
    let body = resp
        .bytes()
        .await
        .map_err(|e| RedeemError::Upstream(format!("POST {url}: body: {e}")))?
        .to_vec();
    if body.len() > MAX_REDEEM_BYTES {
        return Err(RedeemError::Upstream(format!(
            "POST {url}: body over the {MAX_REDEEM_BYTES}-byte ceiling"
        )));
    }
    // Kubo-identical chunking is CPU-bound; keep it off the async runtime.
    let (blocks, body) =
        tokio::task::spawn_blocking(move || (crate::ipfs_chunk::compute_ipfs_blocks(&body), body))
            .await
            .map_err(|e| RedeemError::Upstream(format!("ipfs chunker task: {e}")))?;
    if blocks.root != advertised {
        // Without this any gateway could answer with unrelated bytes and we
        // would store them as the subtitle or the `.nzb`.
        return Err(RedeemError::Upstream(format!(
            "POST {url}: body hashes to {} but the gateway named {advertised}",
            blocks.root
        )));
    }
    Ok((blocks, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use axum::routing::post;

    const BODY: &[u8] = b"1\n00:00:01,000 --> 00:00:02,000\nhi\n";

    /// A loopback gateway: `/ok` answers truthfully, `/lie` names the wrong cid,
    /// `/quota` refuses, `/missing` 404s.
    async fn gateway() -> String {
        async fn answer(bytes: &'static [u8], cid: String) -> (HeaderMap, Vec<u8>) {
            let mut h = HeaderMap::new();
            h.insert(CONTENT_CID_HEADER, HeaderValue::from_str(&cid).unwrap());
            (h, bytes.to_vec())
        }
        let good = crate::ipfs_chunk::compute_ipfs_blocks(BODY).root;
        let other = crate::ipfs_chunk::compute_ipfs_blocks(b"something else").root;
        let app = axum::Router::new()
            .route("/ok/api/file/:cid/redeem", post(move || answer(BODY, good.clone())))
            .route("/lie/api/file/:cid/redeem", post(move || answer(BODY, other.clone())))
            .route(
                "/quota/api/file/:cid/redeem",
                post(|| async {
                    let mut h = HeaderMap::new();
                    h.insert(RETRY_AFTER, HeaderValue::from_static("120"));
                    (StatusCode::TOO_MANY_REQUESTS, h, "quota")
                }),
            )
            .route("/missing/api/file/:cid/redeem", post(|| async { StatusCode::NOT_FOUND }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        base
    }

    const LOCATOR: &str = "bagfcaaa2bvxxazloon2we5djorwgk43gnfwgkorxga3dcobtgq";

    #[tokio::test]
    async fn a_verified_answer_comes_back_with_its_blocks() {
        let gw = gateway().await;
        let (blocks, body) = redeem_from(&reqwest::Client::new(), &[format!("{gw}/ok")], LOCATOR)
            .await
            .expect("redeemed");
        assert_eq!(body, BODY);
        assert_eq!(blocks.root, crate::ipfs_chunk::compute_ipfs_blocks(&body).root);
    }

    #[tokio::test]
    async fn a_body_that_does_not_hash_to_the_named_cid_is_refused() {
        let gw = gateway().await;
        match redeem_from(&reqwest::Client::new(), &[format!("{gw}/lie")], LOCATOR).await {
            Err(RedeemError::Upstream(e)) => assert!(e.contains("hashes to"), "{e}"),
            other => panic!("expected an upstream refusal, got {:?}", other.map(|_| ())),
        }
    }

    #[tokio::test]
    async fn a_not_found_moves_on_to_the_next_gateway() {
        let gw = gateway().await;
        let targets = [format!("{gw}/missing"), format!("{gw}/ok")];
        assert!(redeem_from(&reqwest::Client::new(), &targets, LOCATOR).await.is_ok());
    }

    #[tokio::test]
    async fn quota_outranks_not_found_when_nobody_delivers() {
        let gw = gateway().await;
        let targets = [format!("{gw}/missing"), format!("{gw}/quota")];
        match redeem_from(&reqwest::Client::new(), &targets, LOCATOR).await {
            Err(RedeemError::Quota { retry_after }) => assert_eq!(retry_after, Some(120)),
            other => panic!("expected quota, got {:?}", other.map(|_| ())),
        }
        match redeem_from(&reqwest::Client::new(), &[format!("{gw}/missing")], LOCATOR).await {
            Err(RedeemError::NotFound) => {}
            other => panic!("expected not found, got {:?}", other.map(|_| ())),
        }
    }
}
