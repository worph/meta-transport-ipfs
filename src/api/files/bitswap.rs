//! The IPFS tier: serve from the local blockstore, fetch raw blocks over bitswap,
//! walk dag-pb for ranges, and the hinted-HTTP fallback.

use std::sync::Arc;

use axum::{
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use blockstore::Blockstore;
use meta_feeder_sdk::transport::dto::{HDR_METER, METER_EGRESS};
use tracing::{debug, trace, warn};

use crate::blockstore::parse_record_cid;
use crate::focus::Lane;
use crate::swarm::bitswap_get_block;

use crate::api::{ApiError, AppState};
use crate::api::files::{bytes_to_response, raw_timeout};

/// The display name a seed row gets: the cached record's title, else its
/// `fileName`, else the cid. Asked of the hull's record cache only — never a
/// meta-core round trip on the byte path (same as the monolith).
async fn seed_display_name(state: &AppState, cid: &str) -> String {
    if let Ok(Some(info)) = state.hull.cached_record(cid).await {
        if let Some(t) = info.title.filter(|t| !t.is_empty()) {
            return t;
        }
        if let Some(n) = info.file_name.filter(|n| !n.is_empty()) {
            return n;
        }
    }
    cid.to_string()
}

/// midhash256 — the other single-block content codec alongside raw IPFS.
const MIDHASH256_CODEC: u64 = 0x1000;

/// Serve `cid` straight out of the local blockstore, or `None`.
///
/// The block twin of `try_local_material`'s file check, and the same argument:
/// when we already hold the bytes, no fetch machinery should run first.
///
/// It exists because the meta-core/WebDAV tier sits between the request and
/// this blockstore read, and for artwork that tier is a **guaranteed miss that
/// is not free**. Resolving a record in meta-core costs a read there, and every
/// poster paid one before we ever looked at bytes we already had; the record's
/// `filePath` then 404s on WebDAV (the artwork is seeded, not on meta-core's
/// disk) and the request falls through to exactly this lookup anyway. Measured
/// on watch.nsl.sh: ~0.5-3.0s of meta-core round-trip per poster, 220 posters
/// on a cold home page.
///
/// Deliberately narrow, so nothing but that case changes:
///
/// - **Single-block content codecs only** (raw IPFS `0x55`, midhash256
///   `0x1000`) — the two the single-block branch of [`fetch_raw_via_bitswap`]
///   handles. dag-pb belongs to the walker, and every locator codec
///   (`nzb-release`, `url`, `card`, `btih:`) must keep reaching its own
///   dispatch below.

pub async fn try_local_block(
    state: &Arc<AppState>,
    cid: &str,
    inbound_range: Option<&HeaderValue>,
) -> Option<Response> {
    let mscid = parse_record_cid(cid).ok()?;
    let codec = mscid.codec();
    if codec != crate::api::ipfs_walker::RAW_CODEC && codec != MIDHASH256_CODEC {
        return None;
    }

    match state.block_store.get(&mscid).await {
        Ok(Some(bytes)) => {
            trace!(cid = %cid, source = "blockstore-local-first", bytes = bytes.len(),
                "served raw bytes without touching meta-core");
            Some(bytes_to_response(bytes, inbound_range))
        }
        Ok(None) => None,
        Err(e) => {
            warn!(cid = %cid, error = %e, "local-first blockstore lookup failed; falling through");
            None
        }
    }
}

/// `player` marks a request meta-watch's byte proxy sent for a demuxer source —
/// i.e. a viewer is blocked on these bytes. It is the *commit* signal for the
/// IPFS tier: a title someone genuinely played is worth finishing in the
/// background so this peer seeds the whole file rather than the slice that was
/// watched (`crate::ingress_commit`). Deliberately not "any successful `/raw`":
/// a probe, a `warm` and a poster fetch all reach here and none of them is a
/// viewer. No remote peer sends the header.
pub async fn fetch_raw_via_bitswap(
    state: &Arc<AppState>,
    cid: &str,
    inbound_range: Option<&HeaderValue>,
    lane: Lane,
    player: bool,
) -> Result<Response, ApiError> {
    let mscid = parse_record_cid(cid)
        .map_err(|e| ApiError::BadRequest(format!("cid: {e:#}")))?;

    let codec = mscid.codec();
    // Multi-block IPFS files: walk the dag-pb tree. The walker fetches
    // every block it needs through `ipfs_walker::get_block`, which goes
    // through the same blockstore-then-bitswap path as the single-block
    // branch below — no duplication, just a tree on top.
    if codec == crate::api::ipfs_walker::DAGPB_CODEC {
        return serve_dagpb_range(state, cid, &mscid, inbound_range, lane, player).await;
    }

    // Single-block CIDs (midhash256, raw IPFS). Local blockstore →
    // bitswap WANT, then either slice or serve whole.
    match state.block_store.get(&mscid).await {
        Ok(Some(bytes)) => {
            trace!(cid = %cid, source = "blockstore", bytes = bytes.len(), "served raw bytes");
            return Ok(bytes_to_response(bytes, inbound_range));
        }
        Ok(None) => {}
        Err(e) => warn!(cid = %cid, error = %e, "blockstore raw lookup failed; trying bitswap"),
    }

    let started = std::time::Instant::now();
    match bitswap_get_block(&state.swarm_tx, mscid, raw_timeout()).await {
        Ok(bytes) => {
            trace!(
                cid = %cid,
                source = "bitswap",
                bytes = bytes.len(),
                elapsed_ms = started.elapsed().as_millis() as u64,
                "served raw bytes via bitswap"
            );
            // The single-block twin of the meter in `ipfs_walker::get_block` —
            // this branch reaches bitswap directly and would otherwise be an
            // un-metered hole in the inbound floor.
            state.focus.throttle_in(lane, bytes.len() as u64).await;
            Ok(bytes_to_response(bytes, inbound_range))
        }
        Err(e) => {
            debug!(
                cid = %cid,
                error = %e,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "bitswap raw fetch failed"
            );
            Err(ApiError::NotFound)
        }
    }
}

/// Serve a multi-block dag-pb (IPFS UnixFS file) via the
/// [`crate::api::ipfs_walker`] tree walker. Honors inbound `Range:`
/// when present; otherwise streams the whole file.
pub async fn serve_dagpb_range(
    state: &Arc<AppState>,
    cid: &str,
    mscid: &crate::blockstore::MsCid,
    inbound_range: Option<&HeaderValue>,
    lane: Lane,
    player: bool,
) -> Result<Response, ApiError> {
    use axum::body::Body;
    use axum::response::IntoResponse;

    // 1. Fetch the root block (cache → bitswap). We need it for
    //    blocksizes / filesize.
    let root_block = crate::api::ipfs_walker::get_block(state, mscid, lane)
        .await
        .map_err(|e| {
            debug!(cid = %cid, error = %e, "dag-pb root fetch failed");
            ApiError::NotFound
        })?;

    // 2. Parse the root's PBNode to learn the total file size.
    let meta = crate::api::ipfs_walker::parse_pbnode(&root_block)
        .map_err(|e| ApiError::Upstream(format!("parse dag-pb root: {e:#}")))?;
    // No links: root is itself the data. Fall back to single-block
    // slicing.
    if meta.children.is_empty() {
        return Ok(bytes_to_response(root_block, inbound_range));
    }
    let total = meta
        .filesize
        .or_else(|| meta.declared_total())
        .ok_or_else(|| {
            ApiError::Upstream(
                "dag-pb root has no filesize and no declared blocksizes — can't serve".into(),
            )
        })?;

    // Open (or adopt) the materialisation this fetch fills. From here the leaves
    // this walk pulls are written into `tmp/<cid>/` and never into `blocks.redb`
    // — the whole point of Phase 4. `None` for a file small enough that a
    // container costs more than the copy it saves, which then behaves exactly as
    // before. The job lookup comes first so the display-name resolution (a record
    // fetch) happens once per fetch rather than once per range.
    let job = match state.ingress.job(cid) {
        Some(j) => {
            j.touch();
            Some(j)
        }
        None => {
            let name = seed_display_name(state, cid).await;
            match state.ingress.begin(cid, cid, &name, total).await {
                Ok(j) => j,
                Err(e) => {
                    // Materialising is an optimisation; serving is not. Fall back
                    // to the pre-Phase-4 path rather than failing the request.
                    warn!(cid = %cid, error = %format!("{e:#}"),
                        "ingress: could not open a materialisation; leaves stay material");
                    None
                }
            }
        }
    };
    if player {
        if let Some(j) = job.as_ref() {
            if j.commit() {
                debug!(cid = %cid, total,
                    "genuine play — ipfs materialisation committed to a full fill");
            }
        }
    }
    let ingress_ctx = job
        .as_ref()
        .map(|j| crate::ingress::IngressCtx { job: Arc::clone(j), base: 0 });

    // 3. Parse inbound Range (if any) against the file's total size.
    let ceiling = crate::api::ipfs_walker::max_body_bytes();
    let (start, end, partial) = match crate::api::range::parse_range_header(inbound_range, total) {
        crate::api::range::RangeOutcome::Ok { start, end } => (start, end, true),
        crate::api::range::RangeOutcome::Unsatisfiable => {
            let mut headers = HeaderMap::new();
            let cr = format!("bytes */{total}");
            headers.insert(
                header::CONTENT_RANGE,
                HeaderValue::from_str(&cr).expect("ascii content-range"),
            );
            return Ok(
                (StatusCode::RANGE_NOT_SATISFIABLE, headers, Body::empty()).into_response(),
            );
        }
        crate::api::range::RangeOutcome::Absent | crate::api::range::RangeOutcome::Unsupported => {
            // Whole file. Walker will fetch every leaf but only the
            // bytes go into the response stream — no extra
            // concatenation step.
            (0u64, total.saturating_sub(1), false)
        }
    };

    // Reject the request when the requested range (or whole file) is
    // larger than the in-memory chunking ceiling. Done before any
    // expensive child fetches.
    let requested = end - start + 1;
    if requested as usize > ceiling {
        return Err(ApiError::Upstream(format!(
            "dag-pb requested {requested} bytes exceeds {ceiling}-byte ceiling \
             (META_SHARE_IPFS_MAX_BYTES)"
        )));
    }

    // 4. Walk only the leaves intersecting [start, end].
    let chunks = crate::api::ipfs_walker::walk_range(
        state,
        &root_block,
        start,
        end,
        ceiling,
        lane,
        ingress_ctx.as_ref(),
    )
    .await
        .map_err(|e| {
            debug!(cid = %cid, error = %e, "dag-pb walk_range failed");
            ApiError::Upstream(format!("dag-pb walk: {e:#}"))
        })?;

    // We now hold (and bitswap-serve to cohort peers) the leaf blocks
    // covering this request — i.e. this peer is seeding the file. Record it
    // so it appears in Settings → Seeded files. Idempotent; ranged previews
    // seed the pieces they touched, matching the torrent tier's model. Only
    // multi-block dag-pb files reach here — single raw blocks (posters,
    // thumbnails) are deliberately not auto-recorded to keep the list to
    // real files.
    //
    // **Only when the leaves stayed material.** With a job open the bytes are in
    // a `tmp/` file that no `rename(2)` has published yet: they are servable
    // (design §2a, through the in-flight set) but they are not a *seed*, and a row
    // here would bind a container that does not exist and survive a restart that
    // drops the job — the dangling shape that makes this peer a black hole.
    // `crate::ingress_commit` records the row at promotion, where the file is real.
    if job.is_none() {
        crate::api::record_ipfs_seed(state, cid, &seed_display_name(state, cid).await, total, None).await;
    }

    // Egress meter. Distinct from the inbound charge in `ipfs_walker::get_block`:
    // that paid for pulling the blocks off the swarm, this pays for pushing them
    // back out. Applied by the hull when it relays this body (`HDR_METER`).
    let body = Body::from_stream(crate::api::ipfs_walker::chunks_to_stream(chunks));
    let mut headers = HeaderMap::new();
    headers.insert(HDR_METER, HeaderValue::from_static(METER_EGRESS));
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(
        header::ACCEPT_RANGES,
        HeaderValue::from_static("bytes"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(requested));
    if partial {
        let cr = format!("bytes {start}-{end}/{total}");
        headers.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&cr).expect("ascii content-range"),
        );
        Ok((StatusCode::PARTIAL_CONTENT, headers, body).into_response())
    } else {
        Ok((StatusCode::OK, headers, body).into_response())
    }
}
