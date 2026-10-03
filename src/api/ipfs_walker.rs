//! Shared dag-pb / UnixFS walker.
//!
//! Originally lived inside `super::ipfs_gateway` next to the
//! `/ipfs/{cid}` handler. Lifted out here so the canonical byte-fetch
//! endpoint (`super::files::get_file_raw`) can also assemble (and
//! partial-fetch) multi-block dag-pb files — needed for HTTP `Range:`
//! support on gateway-seeded videos. The `/ipfs/{cid}` route still
//! delegates here for back-compat (see [`assemble_dagpb_file`]).
//!
//! ## Capabilities exposed
//!
//! - [`parse_pbnode`] — given a PBNode block, return the link cids
//!   *with their blocksizes* plus the UnixFS `filesize`. Newer surface
//!   than the original `parse_pbnode_links`: that one only returned the
//!   cids, which was enough for whole-file assembly but not for range
//!   slicing (we need offsets to know which children to fetch).
//! - [`walk_range`] — yield a stream of `Bytes` chunks that together
//!   cover `[start, end]` of the underlying UnixFS file. Fetches only
//!   the leaf blocks that intersect the range; slices the boundary
//!   leaves. Recurses into internal dag-pb children for balanced-tree
//!   files.
//! - [`assemble_dagpb_file`] — back-compat shim. Equivalent to
//!   `walk_range(0, filesize-1)` collected into one `Vec<u8>`. Used by
//!   the legacy `/ipfs/{cid}` handler.
//! - [`get_block`] — single-block fetch (cache hit → bitswap).
//! - Codec constants [`RAW_CODEC`] / [`DAGPB_CODEC`] and the byte
//!   ceiling helper [`max_body_bytes`].

use std::sync::Arc;
use std::time::Duration;

use blockstore::Blockstore;
use bytes::Bytes;
use futures::stream::{self, Stream, StreamExt, TryStreamExt};
use tracing::debug;

use crate::api::AppState;
use crate::blockstore::MsCid;
use crate::focus::Lane;
use crate::swarm::bitswap_get_block;

pub const RAW_CODEC: u64 = 0x55;
pub const DAGPB_CODEC: u64 = 0x70;

/// Per-block timeout for a single bitswap fetch during dag-pb walks.
pub const BITSWAP_BLOCK_TIMEOUT: Duration = Duration::from_secs(15);

/// Concurrency cap for parallel child-block fetches.
pub const PARALLEL_FETCH: usize = 8;

/// Hard ceiling on the assembled body size for one walked file.
/// Aborts the response rather than streaming an unbounded payload —
/// bitswap doesn't know the final UnixFS file's size until it walks the
/// tree, so a malicious cid could otherwise exhaust memory. Default
/// 256 MiB; override via `META_SHARE_IPFS_MAX_BYTES`.
pub fn max_body_bytes() -> usize {
    std::env::var("META_SHARE_IPFS_MAX_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(256 * 1024 * 1024)
}

/// Parsed metadata for a dag-pb PBNode that wraps a UnixFS File.
#[derive(Debug, Clone)]
pub struct PbNodeMeta {
    /// Link cids paired with their declared blocksizes (UnixFS Data
    /// tag 4, one per link in link order). When the encoder doesn't
    /// write blocksizes, the per-link size is `None` — the walker
    /// can't range-slice in that case and the caller has to fall back
    /// to full assembly.
    pub children: Vec<(MsCid, Option<u64>)>,
    /// UnixFS Data tag 3 — the file's total payload size. Optional
    /// because some PBNode shapes (directories, headerless raw wraps)
    /// don't carry it.
    pub filesize: Option<u64>,
}

impl PbNodeMeta {
    /// Sum of declared blocksizes when every link has one declared.
    /// Used when `filesize` is absent to derive the same number.
    pub fn declared_total(&self) -> Option<u64> {
        let mut total: u64 = 0;
        for (_, sz) in &self.children {
            let s = (*sz)?;
            total = total.checked_add(s)?;
        }
        Some(total)
    }
}

/// Parse a PBNode block. Generalises the original `parse_pbnode_links`
/// to also pull blocksizes (UnixFS Data tag 4) and filesize (Data tag
/// 3) out of the inner Data field, zipped against the link order.
pub fn parse_pbnode(bytes: &[u8]) -> anyhow::Result<PbNodeMeta> {
    let mut links: Vec<MsCid> = Vec::new();
    let mut blocksizes: Vec<u64> = Vec::new();
    let mut filesize: Option<u64> = None;
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let (tag_wire, n) = read_varint(&bytes[cursor..])?;
        cursor += n;
        let field = (tag_wire >> 3) as u32;
        let wire_type = (tag_wire & 0x7) as u8;
        match (field, wire_type) {
            // Outer tag 2 = Links (length-delimited PBLink).
            (2, 2) => {
                let (link_len, n) = read_varint(&bytes[cursor..])?;
                cursor += n;
                let link_end = cursor
                    .checked_add(link_len as usize)
                    .ok_or_else(|| anyhow::anyhow!("PBLink length overflow"))?;
                if link_end > bytes.len() {
                    anyhow::bail!("PBLink length runs off end of buffer");
                }
                let link_bytes = &bytes[cursor..link_end];
                cursor = link_end;
                if let Some(hash) = parse_pblink_hash(link_bytes)? {
                    let cid = MsCid::try_from(hash.as_slice()).map_err(|e| {
                        anyhow::anyhow!("PBLink.Hash isn't a valid cid: {e}")
                    })?;
                    links.push(cid);
                }
            }
            // Outer tag 1 = Data (length-delimited). The Data field
            // itself encodes a UnixFS protobuf; recurse to pluck out
            // filesize (tag 3) and blocksizes (tag 4 repeated).
            (1, 2) => {
                let (data_len, n) = read_varint(&bytes[cursor..])?;
                cursor += n;
                let data_end = cursor
                    .checked_add(data_len as usize)
                    .ok_or_else(|| anyhow::anyhow!("PBNode Data length overflow"))?;
                if data_end > bytes.len() {
                    anyhow::bail!("PBNode Data length runs off end of buffer");
                }
                let (fsz, sizes) = parse_unixfs_data(&bytes[cursor..data_end])?;
                if fsz.is_some() {
                    filesize = fsz;
                }
                blocksizes = sizes;
                cursor = data_end;
            }
            // Skip unknown / unrecognised fields per proto3 rules.
            (_, 0) => {
                let (_, n) = read_varint(&bytes[cursor..])?;
                cursor += n;
            }
            (_, 2) => {
                let (skip_len, n) = read_varint(&bytes[cursor..])?;
                cursor += n;
                cursor = cursor
                    .checked_add(skip_len as usize)
                    .ok_or_else(|| anyhow::anyhow!("unknown field skip overflow"))?;
                if cursor > bytes.len() {
                    anyhow::bail!("unknown field length runs off end of buffer");
                }
            }
            (_, 1) => {
                cursor = cursor
                    .checked_add(8)
                    .ok_or_else(|| anyhow::anyhow!("fixed64 skip overflow"))?;
            }
            (_, 5) => {
                cursor = cursor
                    .checked_add(4)
                    .ok_or_else(|| anyhow::anyhow!("fixed32 skip overflow"))?;
            }
            _ => anyhow::bail!("unsupported wire type {wire_type} on field {field}"),
        }
    }
    // Zip links with blocksizes. If counts don't match, we deliberately
    // pair as many as we can and leave the rest with `None` — the
    // walker handles that by falling back to whole-block fetches for
    // those leaves (it can't slice without a known size).
    let mut children: Vec<(MsCid, Option<u64>)> = Vec::with_capacity(links.len());
    for (i, cid) in links.into_iter().enumerate() {
        let sz = blocksizes.get(i).copied();
        children.push((cid, sz));
    }
    Ok(PbNodeMeta { children, filesize })
}

/// Parse the inner UnixFS Data protobuf message. Returns `(filesize,
/// blocksizes)`. Both can be empty / `None` for headerless or
/// directory-shaped Data.
fn parse_unixfs_data(bytes: &[u8]) -> anyhow::Result<(Option<u64>, Vec<u64>)> {
    let mut filesize: Option<u64> = None;
    let mut blocksizes: Vec<u64> = Vec::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let (tag_wire, n) = read_varint(&bytes[cursor..])?;
        cursor += n;
        let field = (tag_wire >> 3) as u32;
        let wire_type = (tag_wire & 0x7) as u8;
        match (field, wire_type) {
            // UnixFS tag 3 = filesize (varint).
            (3, 0) => {
                let (v, n) = read_varint(&bytes[cursor..])?;
                cursor += n;
                filesize = Some(v);
            }
            // UnixFS tag 4 = blocksizes (varint, repeated).
            (4, 0) => {
                let (v, n) = read_varint(&bytes[cursor..])?;
                cursor += n;
                blocksizes.push(v);
            }
            // Everything else (Type, inline Data, hashType, fanout) is
            // either irrelevant to slicing or a future-proofing tag we
            // skip.
            (_, 0) => {
                let (_, n) = read_varint(&bytes[cursor..])?;
                cursor += n;
            }
            (_, 2) => {
                let (skip_len, n) = read_varint(&bytes[cursor..])?;
                cursor += n;
                cursor = cursor
                    .checked_add(skip_len as usize)
                    .ok_or_else(|| anyhow::anyhow!("UnixFS field skip overflow"))?;
                if cursor > bytes.len() {
                    anyhow::bail!("UnixFS field length runs off end of buffer");
                }
            }
            (_, 1) => cursor = cursor.checked_add(8).unwrap_or(usize::MAX),
            (_, 5) => cursor = cursor.checked_add(4).unwrap_or(usize::MAX),
            _ => anyhow::bail!("unsupported UnixFS Data wire type {wire_type} on field {field}"),
        }
    }
    Ok((filesize, blocksizes))
}

/// Inside a PBLink, extract `Hash` (tag 1). Returns `Ok(None)` if the
/// link is malformed in a tolerable way (no Hash field) — the link is
/// then skipped at the caller.
fn parse_pblink_hash(bytes: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let (tag_wire, n) = read_varint(&bytes[cursor..])?;
        cursor += n;
        let field = (tag_wire >> 3) as u32;
        let wire_type = (tag_wire & 0x7) as u8;
        match (field, wire_type) {
            (1, 2) => {
                let (len, n) = read_varint(&bytes[cursor..])?;
                cursor += n;
                let end = cursor
                    .checked_add(len as usize)
                    .ok_or_else(|| anyhow::anyhow!("PBLink.Hash length overflow"))?;
                if end > bytes.len() {
                    anyhow::bail!("PBLink.Hash runs off end of buffer");
                }
                return Ok(Some(bytes[cursor..end].to_vec()));
            }
            (_, 0) => {
                let (_, n) = read_varint(&bytes[cursor..])?;
                cursor += n;
            }
            (_, 2) => {
                let (skip_len, n) = read_varint(&bytes[cursor..])?;
                cursor += n;
                cursor = cursor
                    .checked_add(skip_len as usize)
                    .ok_or_else(|| anyhow::anyhow!("PBLink field skip overflow"))?;
                if cursor > bytes.len() {
                    anyhow::bail!("PBLink field length runs off end of buffer");
                }
            }
            (_, 1) => cursor = cursor.checked_add(8).unwrap_or(usize::MAX),
            (_, 5) => cursor = cursor.checked_add(4).unwrap_or(usize::MAX),
            _ => anyhow::bail!("unsupported PBLink wire type {wire_type} on field {field}"),
        }
    }
    Ok(None)
}

/// Decode one LEB128 unsigned varint. Returns `(value, bytes_consumed)`.
fn read_varint(bytes: &[u8]) -> anyhow::Result<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    let mut n: usize = 0;
    for &b in bytes {
        n += 1;
        value |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok((value, n));
        }
        shift += 7;
        if shift >= 64 {
            anyhow::bail!("varint overflow (more than 10 bytes)");
        }
    }
    anyhow::bail!("varint truncated")
}

/// Fetch one block by cid. Cache short-circuit first; on miss, issues
/// a bitswap fetch and (because the bitswap behaviour shares the same
/// store) implicitly caches the result for future requests.
///
/// This is the single point at which an IPFS file byte enters the process, so it
/// is where the playback focus meters **inbound** bitswap: a block fetched for a
/// title nobody is watching is charged against the background rate
/// ([`FocusGate::throttle_in`](crate::focus::FocusGate::throttle_in)) while a
/// title is playing. `lane` is resolved once per request from the *requested* cid
/// and threaded down — never re-derived here, because a dag-pb **leaf** cid isn't
/// a sibling of the record and wouldn't resolve.
///
/// A blockstore hit is free: it moved no bytes over the wire, so it isn't charged.
pub async fn get_block(state: &AppState, cid: &MsCid, lane: Lane) -> anyhow::Result<Vec<u8>> {
    if let Some(bytes) = blockstore_get(state.block_store.as_ref(), cid).await? {
        debug!(%cid, "ipfs walker: blockstore cache hit");
        return Ok(bytes);
    }
    debug!(%cid, "ipfs walker: cache miss, issuing bitswap fetch");
    let bytes = bitswap_get_block(&state.swarm_tx, cid.clone(), BITSWAP_BLOCK_TIMEOUT)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    debug!(%cid, bytes = bytes.len(), "ipfs walker: bitswap fetch returned");
    state.focus.throttle_in(lane, bytes.len() as u64).await;
    Ok(bytes)
}

async fn blockstore_get<B: Blockstore>(
    store: &B,
    cid: &MsCid,
) -> anyhow::Result<Option<Vec<u8>>> {
    store
        .get(cid)
        .await
        .map_err(|e| anyhow::anyhow!("blockstore get: {e}"))
}

/// Back-compat: assemble the whole UnixFS file by walking every leaf in
/// link order. Equivalent to `walk_range(0, filesize-1)` collected into
/// a single `Vec<u8>`. Used by the legacy `/ipfs/{cid}` handler.
///
/// Note: this still builds a single Vec in memory. The streaming entry
/// point for callers who can consume chunks is [`walk_range`].
pub fn assemble_dagpb_file<'a>(
    state: &'a AppState,
    root_block: &'a [u8],
    max_bytes: usize,
    lane: Lane,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Vec<u8>>> + Send + 'a>> {
    Box::pin(async move {
        let meta = parse_pbnode(root_block)?;
        if meta.children.is_empty() {
            // No links — return the raw block bytes; caller decides how
            // to render application/octet-stream.
            return Ok(root_block.to_vec());
        }
        // Parallel-fetch every child whole (legacy semantics).
        let children = stream::iter(meta.children.into_iter().map(|(child_cid, _sz)| async move {
            let codec = child_cid.codec();
            let block = get_block(state, &child_cid, lane).await?;
            match codec {
                RAW_CODEC => Ok::<Vec<u8>, anyhow::Error>(block),
                DAGPB_CODEC => assemble_dagpb_file(state, &block, max_bytes, lane).await,
                other => anyhow::bail!("unsupported child codec 0x{other:x}"),
            }
        }))
        .buffered(PARALLEL_FETCH)
        .try_collect::<Vec<Vec<u8>>>()
        .await?;
        let total: usize = children.iter().map(Vec::len).sum();
        if total > max_bytes {
            anyhow::bail!(
                "assembled UnixFS file would be {total} bytes — exceeds {max_bytes}-byte ceiling"
            );
        }
        let mut out = Vec::with_capacity(total);
        for chunk in children {
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    })
}

/// Walk a dag-pb tree yielding only the bytes inside `[start, end]`
/// (inclusive). Returns the chunks as a `Vec<Bytes>` so the caller can
/// hand them to `axum::body::Body::from_stream(stream::iter(...))`
/// without re-concatenating into a single buffer.
///
/// Skips leaves wholly outside `[start, end]` — no bitswap fetch for
/// them — and slices the boundary leaves to align. Recurses into
/// internal dag-pb children with the sub-range translated into the
/// child's offset space.
///
/// `max_bytes` is the cap on the resulting body size — i.e. the
/// requested range size, NOT the whole file. So a 4 GiB file with
/// `start=0, end=65535` succeeds even when the whole file would have
/// hit the ceiling.
///
/// A leaf without a declared blocksize forces a fall-back fetch + size
/// inspection. Errors when a child codec is neither raw nor dag-pb.
/// `ingress` carries the in-flight materialisation this walk is filling, if any
/// (`crate::ingress`). It is what turns a walk into a *download*: every raw leaf
/// is registered with its **file-absolute** offset before its WANT goes out, so
/// the block that comes back can be written straight into the file instead of
/// into `blocks.redb`. `None` walks behave exactly as they did before Phase 4.
pub fn walk_range<'a>(
    state: &'a Arc<AppState>,
    root_block: &'a [u8],
    start: u64,
    end: u64,
    max_bytes: usize,
    lane: Lane,
    ingress: Option<&'a crate::ingress::IngressCtx>,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = anyhow::Result<Vec<Bytes>>> + Send + 'a>,
> {
    Box::pin(async move {
        if start > end {
            anyhow::bail!("walk_range: empty range start={start} end={end}");
        }
        let requested = end - start + 1;
        if requested as usize > max_bytes {
            anyhow::bail!(
                "walk_range: requested {requested} bytes exceeds {max_bytes}-byte ceiling"
            );
        }
        let meta = parse_pbnode(root_block)?;
        if meta.children.is_empty() {
            // No links — root IS the data. Slice it.
            let total = root_block.len() as u64;
            if end >= total {
                anyhow::bail!("walk_range: end={end} past root block size={total}");
            }
            let s = start as usize;
            let e = end as usize;
            return Ok(vec![Bytes::copy_from_slice(&root_block[s..=e])]);
        }

        let mut out: Vec<Bytes> = Vec::new();
        // Cumulative offset of the current child in the file's byte space.
        let mut cursor: u64 = 0;
        for (child_cid, child_size_opt) in meta.children {
            // Without a declared blocksize we have to fetch the child
            // to learn its size — that defeats the purpose of range
            // walking but is correct for headerless blocks. We bound
            // the cost with the recursion + max_bytes ceiling.
            let (child_block, child_size) = match child_size_opt {
                Some(sz) => (None, sz),
                None => {
                    let b = get_block(state, &child_cid, lane).await?;
                    let sz = b.len() as u64;
                    (Some(b), sz)
                }
            };
            let child_start = cursor;
            let child_end = cursor.saturating_add(child_size);
            cursor = child_end;
            // Skip children wholly before `[start, end]`.
            if child_end <= start {
                continue;
            }
            // Stop once we're past the requested range.
            if child_start > end {
                break;
            }
            // Range inside the child's local byte space:
            // overlap of [start, end] with [child_start, child_end-1].
            let overlap_lo = start.max(child_start);
            let overlap_hi = end.min(child_end - 1);
            let local_lo = overlap_lo - child_start;
            let local_hi = overlap_hi - child_start;

            let codec = child_cid.codec();
            match codec {
                RAW_CODEC => {
                    // Claim the leaf *before* the fetch: the block may come back
                    // on another task, and an unclaimed arrival is indistinguishable
                    // from an unsolicited one (which we drop). `base` makes the
                    // offset file-absolute through however many dag levels deep
                    // this leaf sits.
                    if let Some(ctx) = ingress {
                        state.ingress.expect_leaf(
                            ctx,
                            child_cid.to_bytes(),
                            ctx.base.saturating_add(child_start),
                            child_size,
                        );
                    }
                    let block = match child_block {
                        Some(b) => b,
                        None => get_block(state, &child_cid, lane).await?,
                    };
                    if (block.len() as u64) < child_size {
                        anyhow::bail!(
                            "leaf block shorter than declared blocksize ({} < {})",
                            block.len(),
                            child_size
                        );
                    }
                    let s = local_lo as usize;
                    let e = local_hi as usize;
                    out.push(Bytes::copy_from_slice(&block[s..=e]));
                }
                DAGPB_CODEC => {
                    let block = match child_block {
                        Some(b) => b,
                        None => get_block(state, &child_cid, lane).await?,
                    };
                    // Recurse with the sub-range translated into the
                    // child's own offset space — and the ingress base translated
                    // the opposite way, so leaves keep reporting where they land
                    // in the file rather than in this subtree.
                    let nested_ctx = ingress.map(|c| c.nested(child_start));
                    let nested = walk_range(
                        state,
                        &block,
                        local_lo,
                        local_hi,
                        max_bytes,
                        lane,
                        nested_ctx.as_ref(),
                    )
                    .await?;
                    out.extend(nested);
                }
                other => anyhow::bail!("unsupported child codec 0x{other:x}"),
            }
        }
        Ok(out)
    })
}

/// Adapter: convert a `Vec<Bytes>` chunk list into a `Stream` that
/// `axum::body::Body::from_stream` accepts. The stream yields
/// `Result<Bytes, std::io::Error>` per axum's body-stream bound.
pub fn chunks_to_stream(
    chunks: Vec<Bytes>,
) -> impl Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static {
    stream::iter(chunks.into_iter().map(Ok::<_, std::io::Error>))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn cid_wire(codec: u8, digest: &[u8; 32]) -> Vec<u8> {
        let mut w = Vec::with_capacity(36);
        w.push(0x01);
        w.push(codec);
        w.push(0x12);
        w.push(0x20);
        w.extend_from_slice(digest);
        w
    }
    fn write_varint(value: u64, out: &mut Vec<u8>) {
        let mut v = value;
        while v >= 0x80 {
            out.push((v as u8) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }
    fn write_varint_field(field: u32, value: u64, out: &mut Vec<u8>) {
        write_varint((field as u64) << 3, out);
        write_varint(value, out);
    }
    fn write_bytes_field(field: u32, value: &[u8], out: &mut Vec<u8>) {
        write_varint(((field as u64) << 3) | 2, out);
        write_varint(value.len() as u64, out);
        out.extend_from_slice(value);
    }

    /// Build a 2-leaf dag-pb root encoding `chunk_a || chunk_b` exactly
    /// the way the meta-gateway encoder does.
    fn make_root(chunk_a: &[u8], chunk_b: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let cid_a = cid_wire(0x55, &Sha256::digest(chunk_a).into());
        let cid_b = cid_wire(0x55, &Sha256::digest(chunk_b).into());

        let mut link_a = Vec::new();
        write_bytes_field(1, &cid_a, &mut link_a);
        write_varint_field(3, chunk_a.len() as u64, &mut link_a);
        let mut link_b = Vec::new();
        write_bytes_field(1, &cid_b, &mut link_b);
        write_varint_field(3, chunk_b.len() as u64, &mut link_b);

        let mut unixfs_data = Vec::new();
        write_varint_field(1, 2, &mut unixfs_data); // Type=File
        write_varint_field(3, (chunk_a.len() + chunk_b.len()) as u64, &mut unixfs_data);
        write_varint_field(4, chunk_a.len() as u64, &mut unixfs_data);
        write_varint_field(4, chunk_b.len() as u64, &mut unixfs_data);

        let mut pbnode = Vec::new();
        write_bytes_field(2, &link_a, &mut pbnode);
        write_bytes_field(2, &link_b, &mut pbnode);
        write_bytes_field(1, &unixfs_data, &mut pbnode);
        (pbnode, cid_a, cid_b)
    }

    #[test]
    fn parse_pbnode_emits_links_with_blocksizes_and_filesize() {
        let chunk_a: &[u8] = b"AAAA";
        let chunk_b: &[u8] = b"BBBBB";
        let (root, _ca, _cb) = make_root(chunk_a, chunk_b);
        let meta = parse_pbnode(&root).expect("parse");
        assert_eq!(meta.filesize, Some(9));
        assert_eq!(meta.children.len(), 2);
        assert_eq!(meta.children[0].1, Some(4));
        assert_eq!(meta.children[1].1, Some(5));
    }

    #[test]
    fn parse_pbnode_links_empty_when_no_links() {
        let mut data = Vec::new();
        write_varint_field(1, 2, &mut data); // Type=File
        let mut pbnode = Vec::new();
        write_bytes_field(1, &data, &mut pbnode);
        let meta = parse_pbnode(&pbnode).expect("parse");
        assert!(meta.children.is_empty());
    }

    #[test]
    fn parse_pbnode_truncated_returns_err() {
        let mut bytes = Vec::new();
        // tag 2 wire-type 2, length 100, but only 5 bytes follow.
        bytes.push((2u8 << 3) | 2);
        bytes.push(100);
        bytes.extend_from_slice(b"short");
        assert!(parse_pbnode(&bytes).is_err());
    }

    #[test]
    fn declared_total_matches_filesize() {
        let chunk_a: &[u8] = b"AAAA";
        let chunk_b: &[u8] = b"BBBBB";
        let (root, _, _) = make_root(chunk_a, chunk_b);
        let meta = parse_pbnode(&root).expect("parse");
        assert_eq!(meta.declared_total(), Some(9));
        assert_eq!(meta.declared_total(), meta.filesize);
    }
}
