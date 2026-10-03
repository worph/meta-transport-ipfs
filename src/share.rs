//! The blockstore operations the hull drives over `/ipfs-tier/*`, gathered from
//! where they lived in the monolith:
//!
//! - [`local_dag_complete`] — `nzb/serve.rs` (it was always an IPFS question);
//! - [`remove_dag`] — `api/seeds.rs::remove_ipfs_blocks`;
//! - [`share_library`] — `ipfs_seed::seed_file_as_refs`;
//! - [`share_container`] — the re-chunk the Usenet seal and the material
//!   rebuild both ran over a cache container.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use blockstore::Blockstore;
use tracing::debug;

use crate::api::ipfs_walker::{parse_pbnode, DAGPB_CODEC, RAW_CODEC};
use crate::api::AppState;
use crate::blockstore::MsCid;

/// Is the dag rooted at `root` fully present in the local blockstore? Local
/// only — no bitswap, no network. Raw leaves are checked with `has` (a key
/// lookup; for a ref it doesn't re-read and re-hash the source), internal nodes
/// are read to learn their children. Any miss, unparseable node or unexpected
/// codec → `false`.
pub async fn local_dag_complete(state: &AppState, root: &MsCid) -> bool {
    let mut stack = vec![*root];
    while let Some(mscid) = stack.pop() {
        match mscid.codec() {
            RAW_CODEC => match state.block_store.has(&mscid).await {
                Ok(true) => {}
                _ => return false,
            },
            DAGPB_CODEC => match state.block_store.get(&mscid).await {
                Ok(Some(block)) => match parse_pbnode(&block) {
                    Ok(meta) => stack.extend(meta.children.into_iter().map(|(child, _sz)| child)),
                    Err(_) => return false,
                },
                _ => return false,
            },
            _ => return false,
        }
    }
    true
}

/// Remove a cid's blocks: for a dag-pb root, walk the tree (local reads only)
/// and remove every node and leaf; for a single block, just that key.
/// Best-effort — an absent block is a no-op.
pub async fn remove_dag(state: &AppState, root: &MsCid) {
    let mut stack = vec![*root];
    let mut seen = std::collections::HashSet::new();
    while let Some(cid) = stack.pop() {
        if !seen.insert(cid.to_bytes()) {
            continue;
        }
        if cid.codec() == DAGPB_CODEC {
            if let Ok(Some(bytes)) = state.block_store.get(&cid).await {
                if let Ok(meta) = parse_pbnode(&bytes) {
                    for (child, _sz) in meta.children {
                        stack.push(child);
                    }
                }
            }
        }
        if let Err(e) = state.block_store.remove(&cid).await {
            debug!(%cid, error = %e, "seed delete: blockstore remove failed (block may be absent)");
        }
    }
}

/// Nocopy library seed: stream the file over meta-core's WebDAV once and
/// register each leaf as a `(midhash, offset, len)` ref, writing only the small
/// synthesized internal dag-pb nodes as material. Returns `(root, size)`.
pub async fn share_library(state: &AppState, rel: &str, midhash: &str) -> Result<(String, u64)> {
    use futures::TryStreamExt;

    let meta_core_url = state
        .meta_core_url
        .as_deref()
        .context("no META_CORE_URL: library files can't be read")?;
    // Prime the resolver's path cache so serving these leaves is a cache hit
    // rather than a meta-core round-trip per leaf.
    state.block_store.resolver().prime_path(midhash, rel).await;

    let webdav_base = crate::webdav::resolve_webdav_url(&state.http, meta_core_url, &state.webdav_url_cache)
        .await
        .context("resolve webdav url")?;
    let encoded: String = rel
        .split('/')
        .map(crate::webdav::urlencode_path_segment)
        .collect::<Vec<_>>()
        .join("/");
    let file_url = format!("{webdav_base}/{encoded}");
    let resp = state
        .http
        .get(&file_url)
        // Generous: a multi-GB stream must not trip the 30s default.
        .timeout(Duration::from_secs(60 * 30))
        .send()
        .await
        .with_context(|| format!("GET {file_url}"))?
        .error_for_status()
        .with_context(|| format!("webdav {file_url}"))?;
    let byte_stream = resp
        .bytes_stream()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));
    let reader = tokio_util::io::StreamReader::new(byte_stream);

    let bs_ref = Arc::clone(&state.block_store);
    let bs_node = Arc::clone(&state.block_store);
    let mh = midhash.to_string();
    crate::ipfs_chunk::stream_ipfs_refs(
        reader,
        move |leaf| {
            let bs = Arc::clone(&bs_ref);
            let mh = mh.clone();
            async move { bs.put_leaf_ref(&leaf, &mh).await }
        },
        move |cid, bytes| {
            let bs = Arc::clone(&bs_node);
            async move { crate::blockstore::put_ipfs_block(bs.as_ref(), &cid, &bytes).await }
        },
    )
    .await
    .context("stream file into refs")
}

/// Chunk a file that lives in a cache container into kubo-identical cids,
/// storing each **leaf as a ref** into the file (`(container, rel, offset,
/// len)`) and only the internal nodes as material. Returns `(root, size, refs)`.
pub async fn share_container(
    state: &AppState,
    container: &str,
    rel: &str,
    path: &std::path::Path,
) -> Result<(String, u64, u64)> {
    let file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("open {}", path.display()))?;
    let bs_ref = state.block_store.clone();
    let bs_node = state.block_store.clone();
    let (ref_cid, ref_rel) = (container.to_string(), rel.to_string());
    let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counted = Arc::clone(&counter);
    let (root, size) = crate::ipfs_chunk::stream_ipfs_refs(
        file,
        move |leaf| {
            let bs = bs_ref.clone();
            let (c, r) = (ref_cid.clone(), ref_rel.clone());
            let n = Arc::clone(&counted);
            async move {
                bs.put_cache_leaf_ref(&leaf, &c, &r).await?;
                n.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
        },
        move |cid, bytes| {
            let bs = bs_node.clone();
            async move { crate::blockstore::put_ipfs_block(bs.as_ref(), &cid, &bytes).await }
        },
    )
    .await
    .context("stream file into refs")?;
    Ok((root, size, counter.load(std::sync::atomic::Ordering::Relaxed)))
}
