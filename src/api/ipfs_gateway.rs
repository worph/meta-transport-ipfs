//! `GET /ipfs/{cid}` — IPFS HTTP gateway endpoint (M13).
//!
//! Resolves an IPFS-compatible cid by:
//!
//! 1. **Codec dispatch.** Raw cids (codec `0x55`) resolve to a single
//!    block; dag-pb cids (codec `0x70`) carry a UnixFS file and need
//!    recursive child fetches.
//! 2. **Block fetch via bitswap.** Each block is requested through the
//!    swarm task via [`crate::swarm::bitswap_get_block`]. The gateway
//!    tier is the seed; sibling consumers that cached the block on a
//!    previous fetch also answer.
//! 3. **Local cache short-circuit.** Before issuing a bitswap fetch,
//!    we check `AppState.block_store` directly — a repeat hit on the
//!    same cid never goes back over the wire.
//! 4. **Reassembly.** For dag-pb cids, child cids are extracted from
//!    the PBNode `Links` field (tag 2) in wire order, fetched in
//!    parallel (bounded fan-out), and concatenated. Internal nodes
//!    recurse; raw leaves contribute their body bytes verbatim.
//!
//! ## Codecs we don't handle
//!
//! Midhash cids (codec `0x1000`, multibase `bagacb…`) deliberately
//! fall through with `400 Bad Request`. They aren't IPFS-spec — the
//! caller should use the legacy `/api/peer/{peer}/file/{cid}/raw`
//! cross-peer proxy for those instead. The UI's `isIpfsCompatibleCid`
//! check already routes correctly; this endpoint enforces the
//! invariant server-side.
//!
//! ## Content-Type
//!
//! IPFS doesn't carry mime types. The endpoint accepts `?type=<mime>`
//! as an explicit hint from the caller (the UI passes the search
//! hit's `content_type` field). When the hint is absent or empty we
//! fall back to `application/octet-stream` — the browser still
//! renders images, audio, and video from that for `<img>` / `<audio>`
//! / `<video>` tags, but won't display HTML / PDF inline.

use std::str::FromStr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use tracing::{debug, warn};

use crate::api::AppState;
use crate::api::ipfs_walker::{
    assemble_dagpb_file, get_block, max_body_bytes, DAGPB_CODEC, RAW_CODEC,
};
use crate::blockstore::MsCid;

/// Query-string parameters.
#[derive(Debug, Default, Deserialize)]
pub struct IpfsParams {
    /// Optional `Content-Type` hint. The UI passes the search hit's
    /// declared `content_type` here so `<img>` tags render correctly.
    /// Empty / absent → `application/octet-stream`.
    #[serde(default, rename = "type")]
    pub content_type: Option<String>,
}

/// `GET /ipfs/:cid` handler.
pub async fn get_ipfs(
    State(state): State<Arc<AppState>>,
    Path(cid_str): Path<String>,
    Query(params): Query<IpfsParams>,
) -> Response {
    let cid: MsCid = match MsCid::from_str(&cid_str) {
        Ok(c) => c,
        Err(e) => {
            debug!(cid = %cid_str, error = %e, "ipfs: cid parse failed");
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("invalid cid `{cid_str}`: {e}"),
            );
        }
    };

    // Codec gate: only raw + dag-pb. Midhash records have their own
    // path (`/api/peer/{peer}/file/{cid}/raw`); rejecting them here
    // makes the UI's codec dispatch authoritative.
    let codec = cid.codec();
    match codec {
        RAW_CODEC | DAGPB_CODEC => {}
        other => {
            debug!(cid = %cid_str, codec = format!("0x{:x}", other), "ipfs: unsupported codec");
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("cid codec 0x{other:x} not supported by /ipfs (raw=0x55, dag-pb=0x70 only)"),
            );
        }
    }

    // The public IPFS gateway is, by definition, someone else pulling bytes out
    // of this peer. It gets the focus lane of whatever title the cid belongs to —
    // which, while our own viewer is watching something else, means the background
    // floor. Serving a *focused* cid stays full-speed (the viewer may be the one
    // asking).
    let lane = state.focus.lane(&cid_str);

    let max_bytes = max_body_bytes();
    let body = match fetch_ipfs_file(&state, &cid, max_bytes, lane).await {
        Ok(b) => b,
        Err(e) => {
            warn!(cid = %cid_str, error = %e, "ipfs: fetch failed");
            return error_response(StatusCode::BAD_GATEWAY, format!("fetch `{cid_str}`: {e}"));
        }
    };

    let content_type = params
        .content_type
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("application/octet-stream")
        .to_string();

    debug!(
        cid = %cid_str,
        codec = format!("0x{:x}", codec),
        bytes = body.len(),
        content_type = %content_type,
        "ipfs: served"
    );

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, body.len().to_string())
        // Immutable cache: cids are content-addressed, so the bytes
        // for a given cid never change. Browsers cache aggressively.
        .header(header::CACHE_CONTROL, "public, max-age=86400, immutable")
        .body(Body::from(body))
        .expect("static response builder")
}

/// Resolve `cid` to file bytes. For raw codec, one bitswap fetch.
/// For dag-pb, recursive UnixFS traversal.
async fn fetch_ipfs_file(
    state: &AppState,
    cid: &MsCid,
    max_bytes: usize,
    lane: crate::focus::Lane,
) -> anyhow::Result<Vec<u8>> {
    let codec = cid.codec();
    let block = get_block(state, cid, lane).await?;
    match codec {
        RAW_CODEC => {
            if block.len() > max_bytes {
                anyhow::bail!(
                    "raw block exceeds {max_bytes}-byte ceiling ({} bytes)",
                    block.len()
                );
            }
            Ok(block)
        }
        DAGPB_CODEC => assemble_dagpb_file(state, &block, max_bytes, lane).await,
        other => anyhow::bail!("unsupported codec 0x{other:x}"),
    }
}

fn error_response(status: StatusCode, msg: String) -> Response {
    (status, axum::Json(serde_json::json!({ "error": msg }))).into_response()
}


// PBNode-parsing tests live in `super::ipfs_walker::tests` — that's where
// the parser actually lives. This handler is just a codec-dispatch shell.
