//! Kubo-compatible IPFS UnixFS chunker — the "ipfs add" direction.
//!
//! Takes a whole file's bytes and produces a standard IPFS CIDv1 plus
//! **every block** of the resulting dag (leaf chunks + internal dag-pb
//! nodes), so the caller can populate the bitswap blockstore in one pass
//! and serve `/ipfs/{cid}` / answer bitswap WANTs for the file.
//!
//! Output matches `ipfs add --cid-version=1 --raw-leaves=true
//! --chunker=size-262144 --hash=sha2-256 <file>`:
//!   - file ≤ 256 KiB → a single raw-codec (`0x55`) leaf; the leaf cid IS
//!     the file cid (no UnixFS wrapping, matching `--raw-leaves`).
//!   - larger → chunk at 256 KiB boundaries into raw leaves, then a
//!     balanced UnixFS dag-pb (`0x70`) tree over them at fanout 174.
//!
//! ## Parity invariant (load-bearing — see CLAUDE.md)
//!
//! This module is a **byte-for-byte port** of meta-gateway's
//! `crates/meta-gateway/src/hash.rs` IPFS family (`compute_ipfs_blocks` /
//! `compute_ipfs_cid` + the dag-pb / UnixFS / base32 / varint encoders).
//! The two crates can't share a path-dep (meta-share is a standalone git
//! submodule), so the code is duplicated and pinned by the same
//! kubo-derived CID test vectors on both sides. **If you change the
//! encoding here, change it there too** — drift silently produces CIDs
//! that public IPFS tooling (and gateway-seeded peers) can't resolve.

use std::path::Path;

use anyhow::Result;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

/// Per-block IPFS chunk size (256 KiB), matches kubo's
/// `--chunker=size-262144` default.
pub const IPFS_CHUNK_SIZE: usize = 256 * 1024;

/// dag-pb fanout — children per internal node. Matches kubo's balanced
/// builder default.
pub const IPFS_FANOUT: usize = 174;

/// Output of [`compute_ipfs_blocks`]. Carries the root CID **plus every
/// intermediate block** (leaf chunks AND internal dag-pb nodes) keyed by
/// their own CID. Pass `.blocks` to the blockstore so peers can fetch the
/// file by CID via bitswap.
#[derive(Debug, Clone)]
pub struct IpfsBlocks {
    /// Canonical "bafy…" / "bafk…" root cid string. Identical to what
    /// [`compute_ipfs_cid`] returns for the same input.
    pub root: String,
    /// Every block — root included — keyed by its own cid. For a
    /// single-leaf file, this is a one-entry vec `[(root, payload)]`
    /// (raw codec, payload is the file bytes). For multi-leaf files, it
    /// is `leaves ++ internal_nodes` in build order; the **last** entry
    /// is the root.
    pub blocks: Vec<(String, Bytes)>,
}

/// Compute a standard IPFS CIDv1 over `bytes`. See module docs for the
/// kubo-equivalence guarantee. Thin wrapper over [`compute_ipfs_blocks`].
///
/// Kept for parity with meta-gateway's `hash.rs` surface (and used by the
/// parity tests below); the seeder itself calls [`compute_ipfs_blocks`] to
/// get the blocks alongside the root, so this convenience wrapper has no
/// non-test caller in this crate yet.
#[allow(dead_code)]
pub fn compute_ipfs_cid(bytes: &[u8]) -> String {
    compute_ipfs_blocks(bytes).root
}

/// Same wire-format guarantee as [`compute_ipfs_cid`], but exposes every
/// block produced along the way (leaf chunks + internal dag-pb nodes) so
/// callers can populate a bitswap blockstore in one pass.
///
/// For a single-leaf file (≤ 256 KiB), `blocks` is one entry: the raw-
/// codec leaf containing the file bytes; its cid equals `root`.
///
/// For larger files, `blocks` is the leaves in chunk-order followed by
/// each level's internal nodes in build-order. The **last** entry is the
/// root. Storing the whole vec in a blockstore makes every cid in the
/// tree fetchable.
pub fn compute_ipfs_blocks(bytes: &[u8]) -> IpfsBlocks {
    // Leaves: chunk bytes into raw-codec blocks. Empty input still gets
    // one (empty) leaf so the cid is well-defined; kubo treats `ipfs add`
    // of an empty file the same way (single raw block of empty content).
    let mut blocks: Vec<(String, Bytes)> = Vec::new();
    let leaves: Vec<(Vec<u8>, u64)> = if bytes.is_empty() {
        let cid_wire = ipfs_cid_wire(0x55, &sha2_256(b""));
        blocks.push((cid_string(&cid_wire), Bytes::new()));
        vec![(cid_wire, 0)]
    } else {
        bytes
            .chunks(IPFS_CHUNK_SIZE)
            .map(|chunk| {
                let cid_wire = ipfs_cid_wire(0x55, &sha2_256(chunk));
                blocks.push((cid_string(&cid_wire), Bytes::copy_from_slice(chunk)));
                (cid_wire, chunk.len() as u64)
            })
            .collect()
    };

    // Single-leaf file: return the leaf cid as the file cid. No UnixFS
    // wrapping — matches kubo behaviour under `--raw-leaves`.
    if leaves.len() == 1 {
        let root = cid_string(&leaves[0].0);
        return IpfsBlocks { root, blocks };
    }

    // Multi-leaf: build a balanced tree of UnixFS dag-pb internal nodes.
    // Each level groups up to `IPFS_FANOUT` children into one parent.
    // Repeat until a single root remains. Tracking tuple per node:
    //   (cid_wire, total_filesize_under_this_node, tsize)
    let mut level: Vec<(Vec<u8>, u64, u64)> = leaves
        .into_iter()
        .map(|(cid, size)| (cid, size, size))
        .collect();

    while level.len() > 1 {
        let mut next: Vec<(Vec<u8>, u64, u64)> =
            Vec::with_capacity(level.len().div_ceil(IPFS_FANOUT));
        for batch in level.chunks(IPFS_FANOUT) {
            let blocksizes: Vec<u64> = batch.iter().map(|(_, sz, _)| *sz).collect();
            let filesize: u64 = blocksizes.iter().sum();
            let unixfs_data = encode_unixfs_file(filesize, &blocksizes);
            let node_bytes = encode_dagpb_node(batch, &unixfs_data);
            let node_cid = ipfs_cid_wire(0x70, &sha2_256(&node_bytes));
            blocks.push((cid_string(&node_cid), Bytes::from(node_bytes.clone())));
            let own_tsize: u64 =
                batch.iter().map(|(_, _, t)| *t).sum::<u64>() + node_bytes.len() as u64;
            next.push((node_cid, filesize, own_tsize));
        }
        level = next;
    }
    let root = cid_string(&level[0].0);
    IpfsBlocks { root, blocks }
}

/// Streaming equivalent of [`compute_ipfs_blocks`] for large files: reads the
/// file at `path` in 256 KiB leaf chunks, handing each `(cid, bytes)` block to
/// `sink` as it is produced (so the caller persists then drops it), and returns
/// `(root_cid, total_size)`. Only one chunk + the small per-leaf cid metadata +
/// the (tiny) internal nodes are ever in memory — never the whole file, nor a
/// second copy of it. Produces byte-for-byte identical CIDs to
/// `compute_ipfs_blocks`, so a large posting can be re-seeded on a memory-capped
/// peer without the ~2× file-size heap spike that OOMs the whole-slice path.
/// No production caller since the Usenet re-seed moved to [`stream_ipfs_refs`] —
/// nothing copies a file's bytes into the blockstore any more, which is the
/// point of the unified cache. Kept deliberately, for two reasons: it is the
/// **material-path reference encoder** that `stream_matches_whole_slice` pins
/// against `compute_ipfs_blocks`, and this file is byte-for-byte mirrored with
/// meta-gateway's `hash.rs` (invariant 5), so deleting a function from one side
/// silently drifts the pair.
#[allow(dead_code)]
pub async fn stream_ipfs_blocks<F, Fut>(path: &Path, mut sink: F) -> Result<(String, u64)>
where
    F: FnMut(String, Bytes) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let file = tokio::fs::File::open(path).await?;
    let mut reader = tokio::io::BufReader::with_capacity(IPFS_CHUNK_SIZE, file);
    let mut buf = vec![0u8; IPFS_CHUNK_SIZE];

    // Leaves: stream to the sink, keeping only (cid_wire, size) metadata.
    let mut leaves: Vec<(Vec<u8>, u64)> = Vec::new();
    let mut total: u64 = 0;
    loop {
        let n = read_chunk(&mut reader, &mut buf).await?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        let cid_wire = ipfs_cid_wire(0x55, &sha2_256(chunk));
        sink(cid_string(&cid_wire), Bytes::copy_from_slice(chunk)).await?;
        leaves.push((cid_wire, n as u64));
        total += n as u64;
    }

    // Empty file → a single empty raw leaf (matches `ipfs add` of an empty file).
    if leaves.is_empty() {
        let cid_wire = ipfs_cid_wire(0x55, &sha2_256(b""));
        sink(cid_string(&cid_wire), Bytes::new()).await?;
        leaves.push((cid_wire, 0));
    }

    // Single leaf → the leaf cid IS the file cid (no UnixFS wrapping).
    if leaves.len() == 1 {
        return Ok((cid_string(&leaves[0].0), total));
    }

    // Multi-leaf: build the balanced dag-pb tree from the leaf metadata, writing
    // each internal node to the sink (identical to `compute_ipfs_blocks`).
    let mut level: Vec<(Vec<u8>, u64, u64)> =
        leaves.into_iter().map(|(cid, size)| (cid, size, size)).collect();
    while level.len() > 1 {
        let mut next: Vec<(Vec<u8>, u64, u64)> =
            Vec::with_capacity(level.len().div_ceil(IPFS_FANOUT));
        for batch in level.chunks(IPFS_FANOUT) {
            let blocksizes: Vec<u64> = batch.iter().map(|(_, sz, _)| *sz).collect();
            let filesize: u64 = blocksizes.iter().sum();
            let unixfs_data = encode_unixfs_file(filesize, &blocksizes);
            let node_bytes = encode_dagpb_node(batch, &unixfs_data);
            let node_cid = ipfs_cid_wire(0x70, &sha2_256(&node_bytes));
            let own_tsize: u64 =
                batch.iter().map(|(_, _, t)| *t).sum::<u64>() + node_bytes.len() as u64;
            sink(cid_string(&node_cid), Bytes::from(node_bytes)).await?;
            next.push((node_cid, filesize, own_tsize));
        }
        level = next;
    }
    Ok((cid_string(&level[0].0), total))
}

/// A leaf's position in its backing file — the nocopy unit. Instead of storing
/// the 256 KiB leaf bytes, the filestore stores this: the leaf `cid` (what
/// bitswap asks for) plus the `offset`/`len` slice of the source file that *is*
/// those bytes. Sound because a kubo raw leaf is literally
/// `file[offset..offset+len]` (the parity invariant above), so re-reading that
/// slice and hashing it reproduces the same cid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafRef {
    /// The raw-leaf CID string (`bafk…`), byte-identical to what
    /// [`stream_ipfs_blocks`] would emit for the same chunk.
    pub cid: String,
    /// Byte offset of the leaf within the source file.
    pub offset: u64,
    /// Leaf length in bytes (== `IPFS_CHUNK_SIZE` for every leaf but the last).
    pub len: u64,
}

/// Nocopy variant of [`stream_ipfs_blocks`]: reads `reader` in 256 KiB leaf
/// chunks and, instead of storing the leaf bytes, hands each leaf's position to
/// `ref_sink` as a [`LeafRef`]. Internal dag-pb nodes are **synthesized**
/// (protobuf, not file slices), so they can't be refs and go to `block_sink`
/// for material storage — exactly as `stream_ipfs_blocks` writes them. Returns
/// `(root_cid, total_size)`, byte-identical to the whole-slice path.
///
/// The reader is still consumed once end-to-end (leaf CIDs are content hashes —
/// there is no way to know a leaf's cid without hashing its bytes), but nothing
/// is duplicated onto disk: the caller registers refs and, at serve time, the
/// filestore re-reads `file[offset..offset+len]` on demand. This is what lets a
/// library file be seeded for ~0 extra bytes (refs + a handful of internal
/// nodes) instead of a second full copy in `blocks.redb`.
pub async fn stream_ipfs_refs<R, RF, RFut, BF, BFut>(
    reader: R,
    mut ref_sink: RF,
    mut block_sink: BF,
) -> Result<(String, u64)>
where
    R: AsyncReadExt + Unpin,
    RF: FnMut(LeafRef) -> RFut,
    RFut: std::future::Future<Output = Result<()>>,
    BF: FnMut(String, Bytes) -> BFut,
    BFut: std::future::Future<Output = Result<()>>,
{
    let mut reader = tokio::io::BufReader::with_capacity(IPFS_CHUNK_SIZE, reader);
    let mut buf = vec![0u8; IPFS_CHUNK_SIZE];

    // Leaves: emit a ref per chunk, keep (cid_wire, size) metadata for the tree.
    let mut leaves: Vec<(Vec<u8>, u64)> = Vec::new();
    let mut total: u64 = 0;
    loop {
        let n = read_chunk(&mut reader, &mut buf).await?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        let cid_wire = ipfs_cid_wire(0x55, &sha2_256(chunk));
        ref_sink(LeafRef {
            cid: cid_string(&cid_wire),
            offset: total,
            len: n as u64,
        })
        .await?;
        leaves.push((cid_wire, n as u64));
        total += n as u64;
    }

    // Empty file → a single empty raw leaf. A zero-length ref is still valid:
    // reading `file[0..0]` yields the empty slice, which hashes to this cid.
    if leaves.is_empty() {
        let cid_wire = ipfs_cid_wire(0x55, &sha2_256(b""));
        ref_sink(LeafRef { cid: cid_string(&cid_wire), offset: 0, len: 0 }).await?;
        leaves.push((cid_wire, 0));
    }

    // Single leaf → the leaf cid IS the file cid (no UnixFS wrapping).
    if leaves.len() == 1 {
        return Ok((cid_string(&leaves[0].0), total));
    }

    // Multi-leaf: build the balanced dag-pb tree, writing each internal node to
    // `block_sink` (material). Identical tree maths to `stream_ipfs_blocks`.
    let mut level: Vec<(Vec<u8>, u64, u64)> =
        leaves.into_iter().map(|(cid, size)| (cid, size, size)).collect();
    while level.len() > 1 {
        let mut next: Vec<(Vec<u8>, u64, u64)> =
            Vec::with_capacity(level.len().div_ceil(IPFS_FANOUT));
        for batch in level.chunks(IPFS_FANOUT) {
            let blocksizes: Vec<u64> = batch.iter().map(|(_, sz, _)| *sz).collect();
            let filesize: u64 = blocksizes.iter().sum();
            let unixfs_data = encode_unixfs_file(filesize, &blocksizes);
            let node_bytes = encode_dagpb_node(batch, &unixfs_data);
            let node_cid = ipfs_cid_wire(0x70, &sha2_256(&node_bytes));
            let own_tsize: u64 =
                batch.iter().map(|(_, _, t)| *t).sum::<u64>() + node_bytes.len() as u64;
            block_sink(cid_string(&node_cid), Bytes::from(node_bytes)).await?;
            next.push((node_cid, filesize, own_tsize));
        }
        level = next;
    }
    Ok((cid_string(&level[0].0), total))
}

/// Read up to `buf.len()` bytes, looping over short reads; returns the number
/// read (0 only at EOF). So every leaf but the last is exactly `IPFS_CHUNK_SIZE`.
async fn read_chunk<R: AsyncReadExt + Unpin>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = r.read(&mut buf[filled..]).await?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

fn cid_string(wire: &[u8]) -> String {
    format!("b{}", base32_lower_no_padding(wire))
}

/// CIDv1 wire-form bytes: `[version=0x01][codec varint][multihash code
/// varint=0x12 sha2-256][len=0x20][digest...]`. Both `raw` (`0x55`) and
/// `dag-pb` (`0x70`) codecs encode as single-byte varints since they're
/// under 0x80.
fn ipfs_cid_wire(codec: u8, digest: &[u8; 32]) -> Vec<u8> {
    debug_assert!(
        codec < 0x80,
        "codec varint must fit in one byte for this helper"
    );
    let mut wire = Vec::with_capacity(36);
    wire.push(0x01); // CIDv1
    wire.push(codec);
    wire.push(0x12); // multihash code: sha2-256
    wire.push(0x20); // digest length: 32
    wire.extend_from_slice(digest);
    wire
}

fn sha2_256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// LEB128 unsigned varint encoding into `out`.
fn write_pb_varint(value: u64, out: &mut Vec<u8>) {
    let mut v = value;
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn write_pb_varint_field(field: u32, value: u64, out: &mut Vec<u8>) {
    // `| 0` (wire type 0 = varint) is a no-op kept verbatim for byte-for-byte
    // parity with meta-gateway's encoder — the explicit wire-type makes the
    // protobuf tag construction self-documenting. See invariant 8 in CLAUDE.md.
    #[allow(clippy::identity_op)]
    write_pb_varint(((field as u64) << 3) | 0, out);
    write_pb_varint(value, out);
}

fn write_pb_bytes_field(field: u32, value: &[u8], out: &mut Vec<u8>) {
    write_pb_varint(((field as u64) << 3) | 2, out); // wire type 2 = length-delimited
    write_pb_varint(value.len() as u64, out);
    out.extend_from_slice(value);
}

/// UnixFS protobuf payload for a File node: `Type=File, filesize,
/// blocksizes[]`. Used as the `Data` field of the wrapping dag-pb node.
/// (Type=File is enum value 2 in the UnixFS schema.)
fn encode_unixfs_file(filesize: u64, blocksizes: &[u64]) -> Vec<u8> {
    let mut out = Vec::new();
    write_pb_varint_field(1, 2, &mut out); // Type = File
    write_pb_varint_field(3, filesize, &mut out); // filesize
    for &bs in blocksizes {
        write_pb_varint_field(4, bs, &mut out); // blocksizes (repeated)
    }
    out
}

/// dag-pb PBNode for an internal UnixFS file node. Canonical wire order
/// pinned by the dag-pb spec: `Links` (tag 2) first, `Data` (tag 1)
/// second. Each PBLink emits `Hash` (tag 1) and `Tsize` (tag 3); `Name`
/// is omitted (kubo doesn't emit it for UnixFS file children either).
fn encode_dagpb_node(children: &[(Vec<u8>, u64, u64)], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for (cid_wire, _filesize, tsize) in children {
        let mut link_bytes = Vec::new();
        write_pb_bytes_field(1, cid_wire, &mut link_bytes); // Hash
        write_pb_varint_field(3, *tsize, &mut link_bytes); // Tsize
        write_pb_bytes_field(2, &link_bytes, &mut out); // Links (tag 2) first
    }
    write_pb_bytes_field(1, data, &mut out); // Data (tag 1) last
    out
}

/// RFC 4648 base32 with the lowercase alphabet and no padding. Used for the
/// multibase `b` prefix.
pub(crate) fn base32_lower_no_padding(input: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(input.len().div_ceil(5) * 8);
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    for &b in input {
        buffer = (buffer << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1F) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // The streaming chunker must produce byte-identical CIDs (root + every
    // block) to the whole-slice `compute_ipfs_blocks` — else a large posting
    // re-seeded via the streaming path publishes a root that doesn't match what
    // gateway-seeded peers expect, breaking federation silently.
    #[tokio::test]
    async fn stream_matches_whole_slice() {
        // A few sizes: single sub-chunk leaf, exact multi-leaf, multi-level tree.
        for size in [0usize, 100, IPFS_CHUNK_SIZE, IPFS_CHUNK_SIZE * 3 + 7, IPFS_CHUNK_SIZE * (IPFS_FANOUT + 5)] {
            let data: Vec<u8> = (0..size).map(|i| (i * 31 + 7) as u8).collect();
            let expected = compute_ipfs_blocks(&data);

            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("f.bin");
            tokio::fs::write(&path, &data).await.unwrap();

            let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(String, usize)>::new()));
            let seen2 = seen.clone();
            let (root, total) = stream_ipfs_blocks(&path, move |cid, bytes| {
                let seen = seen2.clone();
                async move {
                    seen.lock().unwrap().push((cid, bytes.len()));
                    Ok(())
                }
            })
            .await
            .unwrap();

            assert_eq!(root, expected.root, "root mismatch at size {size}");
            assert_eq!(total as usize, size, "size mismatch at {size}");
            // Same set of block cids (order matches: leaves then internal nodes).
            let streamed: Vec<String> = seen.lock().unwrap().iter().map(|(c, _)| c.clone()).collect();
            let whole: Vec<String> = expected.blocks.iter().map(|(c, _)| c.clone()).collect();
            assert_eq!(streamed, whole, "block cid set mismatch at size {size}");
        }
    }

    #[tokio::test]
    async fn stream_ipfs_refs_matches_whole_slice_and_reslices() {
        // Cover single-leaf, exact-boundary, multi-leaf, and multi-level trees.
        for size in [0usize, 11, IPFS_CHUNK_SIZE, IPFS_CHUNK_SIZE + 1, 3 * IPFS_CHUNK_SIZE + 7] {
            let data: Vec<u8> = (0..size).map(|i| (i * 31 + 7) as u8).collect();
            let expected = compute_ipfs_blocks(&data);

            let refs = std::sync::Arc::new(std::sync::Mutex::new(Vec::<LeafRef>::new()));
            let nodes = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
            let refs2 = refs.clone();
            let nodes2 = nodes.clone();
            let (root, total) = stream_ipfs_refs(
                std::io::Cursor::new(data.clone()),
                move |r| {
                    let refs = refs2.clone();
                    async move {
                        refs.lock().unwrap().push(r);
                        Ok(())
                    }
                },
                move |cid, _bytes| {
                    let nodes = nodes2.clone();
                    async move {
                        nodes.lock().unwrap().push(cid);
                        Ok(())
                    }
                },
            )
            .await
            .unwrap();

            assert_eq!(root, expected.root, "root mismatch at size {size}");
            assert_eq!(total as usize, size, "size mismatch at {size}");

            let refs = refs.lock().unwrap();
            // Re-reading each ref's slice and hashing it must reproduce its cid —
            // this is the soundness property the filestore relies on.
            for r in refs.iter() {
                let slice = &data[r.offset as usize..(r.offset + r.len) as usize];
                assert_eq!(
                    compute_ipfs_cid(slice),
                    r.cid,
                    "re-sliced leaf at {}+{} must hash to its cid (size {size})",
                    r.offset,
                    r.len
                );
            }
            // Leaf refs + internal-node blocks together == the whole-slice block
            // set, in the same order (leaves first, then nodes).
            let streamed: Vec<String> = refs
                .iter()
                .map(|r| r.cid.clone())
                .chain(nodes.lock().unwrap().iter().cloned())
                .collect();
            let whole: Vec<String> = expected.blocks.iter().map(|(c, _)| c.clone()).collect();
            assert_eq!(streamed, whole, "ref+node cid set mismatch at size {size}");
        }
    }

    // ---- Parity corpus -----------------------------------------------------
    //
    // These CID vectors are pinned byte-identical to meta-gateway's
    // `hash.rs` tests (which are themselves pinned against kubo's
    // `ipfs add --cid-version=1 --raw-leaves=true --chunker=size-262144
    // --hash=sha2-256`). If either side drifts, federation breaks
    // silently — a CID this peer publishes stops resolving on a
    // gateway-seeded peer (and vice versa). Keep both in lockstep.

    #[test]
    fn base32_known_vectors() {
        assert_eq!(base32_lower_no_padding(b""), "");
        assert_eq!(base32_lower_no_padding(b"f"), "my");
        assert_eq!(base32_lower_no_padding(b"fo"), "mzxq");
        assert_eq!(base32_lower_no_padding(b"foo"), "mzxw6");
        assert_eq!(base32_lower_no_padding(b"foob"), "mzxw6yq");
        assert_eq!(base32_lower_no_padding(b"foobar"), "mzxw6ytboi");
    }

    /// Single raw leaf — pinned against kubo:
    ///   echo -n "hello world" | ipfs add --cid-version=1 --raw-leaves=true
    #[test]
    fn ipfs_cid_single_leaf_matches_kubo() {
        assert_eq!(
            compute_ipfs_cid(b"hello world"),
            "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e"
        );
    }

    /// Empty file: `ipfs add` of `/dev/null` with raw-leaves.
    #[test]
    fn ipfs_cid_empty_matches_kubo() {
        assert_eq!(
            compute_ipfs_cid(b""),
            "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
        );
    }

    /// Multi-chunk file (1 MiB zeros = 4 × 256 KiB leaves + 1 dag-pb root)
    /// — pins the UnixFS dag-pb canonical encoding (Links-before-Data wire
    /// order, omitted PBLink.Name, Tsize=raw-bytes for leaves).
    #[test]
    fn ipfs_cid_multi_leaf_zeros_stable() {
        let mb_zeros = vec![0u8; 1024 * 1024];
        assert_eq!(
            compute_ipfs_cid(&mb_zeros),
            "bafybeiadh3bekpwtewjvauqeucf7yzqrb3ixsxzltnuwed4pxangtpou6m"
        );
    }

    /// Single-leaf path: blocks vec is one entry, raw chunk, cid == root.
    #[test]
    fn ipfs_blocks_single_leaf() {
        let payload = b"hello world";
        let out = compute_ipfs_blocks(payload);
        assert_eq!(out.root, compute_ipfs_cid(payload));
        assert_eq!(out.blocks.len(), 1);
        assert_eq!(out.blocks[0].0, out.root);
        assert_eq!(out.blocks[0].1.as_ref(), payload);
    }

    /// Multi-leaf path: 4 leaves + 1 root = 5 blocks, leaves first, root last.
    #[test]
    fn ipfs_blocks_multi_leaf() {
        let mb_zeros = vec![0u8; 1024 * 1024];
        let out = compute_ipfs_blocks(&mb_zeros);
        assert_eq!(
            out.root,
            "bafybeiadh3bekpwtewjvauqeucf7yzqrb3ixsxzltnuwed4pxangtpou6m"
        );
        assert_eq!(out.blocks.len(), 5);
        assert_eq!(out.blocks.last().unwrap().0, out.root);
        for (_cid, block) in &out.blocks[..4] {
            assert_eq!(block.len(), 256 * 1024);
            assert!(block.iter().all(|&b| b == 0));
        }
    }

    /// Empty input → well-defined cid + one-entry blocks vec.
    #[test]
    fn ipfs_blocks_empty() {
        let out = compute_ipfs_blocks(b"");
        assert_eq!(
            out.root,
            "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
        );
        assert_eq!(out.blocks.len(), 1);
        assert_eq!(out.blocks[0].1.len(), 0);
        assert_eq!(out.blocks[0].0, out.root);
    }
}
