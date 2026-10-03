//! Consumer-side IPFS blockstore. Shared between the bitswap behaviour
//! (M12 — `swarm/mod.rs`) and the `/ipfs/{cid}` HTTP gateway (M13).
//!
//! When bitswap fetches a block on behalf of `/ipfs/{cid}`, the
//! Behaviour's `Blockstore::put_keyed` stores it locally. Future requests
//! for the same cid (from this peer OR from another peer that connects
//! to us via bitswap) read directly from the store — that's how
//! multi-source pulls emerge: the gateway is the seed, every consumer
//! that fetched it once becomes a re-seeding candidate.
//!
//! Lives under `{META_SHARE_DATA}/ipfs/blocks.redb`. Persistent across
//! restarts. There is no GC in v1 — operators wipe the file to clear
//! the cache. Storage is bounded only by the size of cids the consumer
//! has actually fetched; the worst-case footprint is a few hundred MB
//! per gigabyte of media fetched through the gateway tier.

use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result};
use blockstore::{Blockstore, RedbBlockstore};
use cid::CidGeneric;
use tokio::fs;

/// Multihash byte ceiling. 64 matches the gateway side; both ends must
/// agree because the const parameter feeds into beetswap's
/// `Behaviour<const MAX_MULTIHASH_SIZE, B>`.
pub const MAX_MULTIHASH_SIZE: usize = 64;

/// CID type alias matching the blockstore's generic param.
pub type MsCid = CidGeneric<MAX_MULTIHASH_SIZE>;

/// Magic prefix for bincode-encoded `Record` blocks stored in the
/// blockstore. Future record-shape changes bump the version (e.g.
/// `MSR2`); decoders reject mismatched prefixes loudly so we never
/// confuse one shape for another.
///
/// Lives next to the blockstore because the rest of the module owns
/// the on-disk representation; the `Record`-side helpers in `store.rs`
/// just consume this constant.
pub const RECORD_BLOCK_MAGIC: &[u8; 4] = b"MSR1";

/// Parse a `Record.cid` into an `MsCid` usable by the blockstore + beetswap.
///
/// **Strict**: a bare CIDv1 multibase string and nothing else. This is the
/// reference parse behaviour, matching `cid.Decode` in
/// `packages/meta-core/internal/cid/rank.go`. Two shapes are deliberately
/// rejected:
///
///   - **The `<algo>:<cid>` token form** (`midhash256:bagacb…`). Removed — a
///     CIDv1 already names its hash function in the multicodec, so the prefix
///     was redundant and let one digest be spelled two ways. This function used
///     to strip it, which kept the deprecated shape alive on the wire.
///   - **CIDv0** (`Qm…`). `MsCid::from_str` accepts it and reports codec
///     dag-pb, so a CIDv0 used to rank 40 here while meta-core ranked it 0 —
///     the two disagreed about the top of the ladder. Pinned by the
///     `cidv0-rejected` golden vector.
pub fn parse_record_cid(cid_str: &str) -> Result<MsCid> {
    if cid_str.contains(':') {
        anyhow::bail!(
            "parse record cid `{cid_str}`: the `<algo>:<cid>` token form was removed; \
             pass the bare CIDv1 (the multicodec already names the algorithm)"
        );
    }
    let parsed = MsCid::from_str(cid_str)
        .with_context(|| format!("parse record cid `{cid_str}`"))?;
    if parsed.version() != cid::Version::V1 {
        anyhow::bail!("parse record cid `{cid_str}`: only CIDv1 is supported, got {:?}", parsed.version());
    }
    Ok(parsed)
}




/// redb page-cache ceiling for the blockstore. redb's own default is **1 GiB**
/// (`redb::Builder::new` → `set_cache_size(1 << 30)`), which the convenience
/// `RedbBlockstore::open` inherits. Under a multi-GB nzb re-seed (thousands of
/// block-writes) that cache fills toward 1 GiB of resident B-tree pages and
/// OOM-kills a memory-capped peer. 256 MiB keeps write batching healthy while
/// bounding the footprint. Override with `META_SHARE_BLOCKSTORE_CACHE_MB`.
const DEFAULT_BLOCKSTORE_CACHE_BYTES: usize = 256 * 1024 * 1024;

fn blockstore_cache_bytes() -> usize {
    std::env::var("META_SHARE_BLOCKSTORE_CACHE_MB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map(|mb| mb.saturating_mul(1024 * 1024))
        .unwrap_or(DEFAULT_BLOCKSTORE_CACHE_BYTES)
}

/// Open the persistent consumer-side blockstore at
/// `<data_dir>/ipfs/blocks.redb`. Creates the parent dir on first run.
///
/// Both bitswap's `Behaviour::new(Arc<Blockstore>)` and the
/// `/ipfs/{cid}` HTTP handler take the same `Arc<RedbBlockstore>`
/// returned here; redb provides snapshot isolation so concurrent
/// reads-while-writes are safe.
///
/// Opens the underlying `redb::Database` with an explicit, bounded cache (see
/// [`DEFAULT_BLOCKSTORE_CACHE_BYTES`]) rather than `RedbBlockstore::open`, whose
/// 1 GiB redb default OOMs a memory-capped peer during a large re-seed.
pub async fn open_redb_blockstore(data_dir: &Path) -> Result<Arc<RedbBlockstore>> {
    let ipfs_dir = data_dir.join("ipfs");
    fs::create_dir_all(&ipfs_dir).await.with_context(|| {
        format!("create ipfs dir at {}", ipfs_dir.display())
    })?;
    let db_path = ipfs_dir.join("blocks.redb");
    let db_path_disp = db_path.display().to_string();
    let cache_bytes = blockstore_cache_bytes();
    let db = tokio::task::spawn_blocking(move || {
        redb::Database::builder()
            .set_cache_size(cache_bytes)
            .create(db_path)
    })
    .await
    .context("join redb open task")?
    .with_context(|| format!("open redb Database at {db_path_disp}"))?;
    Ok(Arc::new(RedbBlockstore::new(Arc::new(db))))
}

/// A [`Blockstore`] that charges every block it hands out against the playback
/// focus's outbound budget. **Only `beetswap::Behaviour` gets one of these** —
/// every local read path keeps the raw `Arc<RedbBlockstore>` from
/// [`open_redb_blockstore`], so nothing this peer does for itself can be
/// throttled by its own gate.
///
/// This is the one lever that exists for outbound bitswap: beetswap answers a
/// remote WANT by calling `store.get()` on whatever blockstore it was built with
/// (`beetswap::server::get_multiple_cids_from_store`), and that call happens
/// inside a spawned task on beetswap's `FuturesUnordered` — never on the swarm
/// poll loop — so awaiting a token bucket in here slows block *service* without
/// stalling the swarm. There is no rate knob anywhere else in the bitswap stack.
///
/// ## Why the throttle is after the read, not before it
///
/// beetswap's **client** side also calls `store.get()` — before issuing a WANT,
/// to check whether we already hold the block (`beetswap::client`, "if the
/// blockstore doesn't have the data, add the CID to the wantlist"). Gating on the
/// way *in* would therefore delay our own outbound WANTs, i.e. throttle the very
/// stream the focus exists to protect. Charging only when the inner store returns
/// `Some` sidesteps it exactly: a client precheck for a block we don't have
/// returns `None` instantly and its WANT goes out unimpeded, and we spend tokens
/// only when we are genuinely about to hand bytes to a peer.
///
/// ## Why it isn't per-title
///
/// The server-side `get()` sees a bare CID and no request context, and a dag-pb
/// **leaf** cid is not a sibling on any record — so "is this block part of the
/// focused title?" is not answerable here. The bucket is therefore aggregate:
/// while any title is focused, *all* bitswap block service is floored at the
/// background rate, including the focused title's own blocks if a third peer asks
/// for them. That's the right priority — our viewer's inbound beats a stranger's
/// outbound — and it's the honest reading of "pause seeding while I'm watching".
pub struct GatedBlockstore<B> {
    inner: Arc<B>,
    focus: Arc<meta_feeder_sdk::transport::FocusView>,
}

impl<B> GatedBlockstore<B> {
    pub fn new(inner: Arc<B>, focus: Arc<meta_feeder_sdk::transport::FocusView>) -> Self {
        Self { inner, focus }
    }
}

impl<B: Blockstore> Blockstore for GatedBlockstore<B> {
    async fn get<const S: usize>(&self, cid: &CidGeneric<S>) -> blockstore::Result<Option<Vec<u8>>> {
        let out = self.inner.get(cid).await?;
        if let Some(bytes) = &out {
            // `Lane::Background`: a block leaving this peer over bitswap is, by
            // construction, being served to someone else. See the type docs for
            // why this isn't resolved per-title.
            self.focus
                .throttle_out(crate::focus::Lane::Background, bytes.len() as u64)
                .await;
        }
        Ok(out)
    }

    async fn put_keyed<const S: usize>(
        &self,
        cid: &CidGeneric<S>,
        data: &[u8],
    ) -> blockstore::Result<()> {
        // Inbound blocks bitswap fetched for us. Metered at the WANT site
        // (`ipfs_walker::get_block`), where the lane is actually known — charging
        // again here would double-count.
        self.inner.put_keyed(cid, data).await
    }

    async fn remove<const S: usize>(&self, cid: &CidGeneric<S>) -> blockstore::Result<()> {
        self.inner.remove(cid).await
    }

    /// Forwarded explicitly so a presence check doesn't route through the gated
    /// `get` above and pay for bytes it never returns.
    async fn has<const S: usize>(&self, cid: &CidGeneric<S>) -> blockstore::Result<bool> {
        self.inner.has(cid).await
    }

    async fn close(self) -> blockstore::Result<()> {
        // `Blockstore::close` takes `self` by value but the inner store is shared
        // (`Arc`), so there is nothing we may consume. Nothing in meta-share calls
        // it — the redb file is closed when the process exits.
        Ok(())
    }
}

/// Default ceiling for a block this peer will keep as **material** when no
/// ingress job claims it: records, posters, thumbnails, dag-pb internal nodes —
/// the small objects that have no file to live in and that the poster-recovery
/// path depends on. Override with `META_SHARE_LOOSE_BLOCK_MAX_BYTES`.
const DEFAULT_LOOSE_BLOCK_MAX_BYTES: u64 = 1024 * 1024;

fn loose_block_max_bytes() -> u64 {
    std::env::var("META_SHARE_LOOSE_BLOCK_MAX_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_LOOSE_BLOCK_MAX_BYTES)
}

/// Routes an arriving bitswap block to **a file** instead of the block table
/// whenever some in-flight fetch is expecting it. Phase 4's single write
/// decision; see `crate::ingress`.
///
/// Only `beetswap::Behaviour` is given one of these, because its client is the
/// one thing that writes blocks this peer did not produce. Every local write path
/// keeps talking to the store underneath, so nothing else changes shape.
///
/// | block | destination |
/// |---|---|
/// | a leaf an [`crate::ingress::IngressJob`] is waiting for | that job's file, by `pwrite` at the leaf's offset |
/// | anything else ≤ `META_SHARE_LOOSE_BLOCK_MAX_BYTES` | material, as before — records, posters, internal nodes |
/// | anything else, larger | dropped |
///
/// **Why the fall-through keeps small objects rather than dropping them.** The
/// job lookup answers "is this file content we are materialising?", not "did we
/// ask for this?". A poster, an `MSR1` record and a dag-pb node all arrive
/// unattributed by construction — they have no file to belong to — and they are
/// exactly what the artwork and record-resolution paths need locally. The size
/// ceiling is what keeps that exception from quietly becoming the old behaviour:
/// file content arrives as 256 KiB leaves *of a job*, so a large unattributed
/// block means something walked a dag without opening a job, and the honest
/// answer is to serve it from memory and keep nothing.
pub struct IngressRouter<B> {
    inner: Arc<B>,
    ingress: Arc<crate::ingress::IngressRegistry>,
    loose_max: u64,
}

impl<B> IngressRouter<B> {
    pub fn new(inner: Arc<B>, ingress: Arc<crate::ingress::IngressRegistry>) -> Self {
        Self { inner, ingress, loose_max: loose_block_max_bytes() }
    }

    /// Explicit ceiling, so a test can exercise the drop branch without a 1 MiB
    /// fixture (and without an env var, which every other test in the process
    /// would see).
    #[cfg(test)]
    fn with_loose_max(
        inner: Arc<B>,
        ingress: Arc<crate::ingress::IngressRegistry>,
        loose_max: u64,
    ) -> Self {
        Self { inner, ingress, loose_max }
    }
}

impl<B: Blockstore> Blockstore for IngressRouter<B> {
    async fn get<const S: usize>(&self, cid: &CidGeneric<S>) -> blockstore::Result<Option<Vec<u8>>> {
        self.inner.get(cid).await
    }

    async fn put_keyed<const S: usize>(
        &self,
        cid: &CidGeneric<S>,
        data: &[u8],
    ) -> blockstore::Result<()> {
        if self.ingress.accept(&cid.to_bytes(), data).await {
            return Ok(());
        }
        if data.len() as u64 <= self.loose_max {
            return self.inner.put_keyed(cid, data).await;
        }
        tracing::debug!(%cid, bytes = data.len(),
            "blockstore: unattributed block over the loose ceiling; not stored");
        Ok(())
    }

    async fn remove<const S: usize>(&self, cid: &CidGeneric<S>) -> blockstore::Result<()> {
        self.inner.remove(cid).await
    }

    async fn has<const S: usize>(&self, cid: &CidGeneric<S>) -> blockstore::Result<bool> {
        self.inner.has(cid).await
    }

    async fn close(self) -> blockstore::Result<()> {
        Ok(())
    }
}

/// Persist every block from [`crate::ipfs_chunk::IpfsBlocks`] (leaves +
/// internal dag-pb nodes) into the blockstore. After this returns, the
/// peer can answer a bitswap WANT for any cid in the dag — including the
/// root — and the `/ipfs/{cid}` gateway resolves the file from the local
/// store without a network round-trip.
///
/// Mirror of meta-gateway's `blockstore::put_ipfs_blocks` (the gateway
/// seeds upstream-fetched bytes the same way). These are real IPFS blocks
/// (raw `0x55` / dag-pb `0x70`), keyed by their own content CID — they
/// never collide with the `MSR1` record blocks ingest writes, which are
/// keyed by the record's canonical CID.
///
/// Errors are returned, not panicked: the caller (the event-driven seeder)
/// logs-and-continues so a single block-write failure doesn't abort the
/// seed loop.
pub async fn put_ipfs_blocks<B: Blockstore>(
    store: &B,
    blocks: &crate::ipfs_chunk::IpfsBlocks,
) -> Result<()> {
    for (cid_str, bytes) in &blocks.blocks {
        let cid: MsCid =
            MsCid::from_str(cid_str).with_context(|| format!("parse ipfs cid `{cid_str}`"))?;
        store
            .put_keyed(&cid, bytes.as_ref())
            .await
            .with_context(|| format!("blockstore put_keyed `{cid_str}` ({} bytes)", bytes.len()))?;
        tracing::debug!(cid = %cid_str, bytes = bytes.len(), "ipfs block stored");
    }
    Ok(())
}

/// Persist a single IPFS block by its string cid — the incremental counterpart
/// of [`put_ipfs_blocks`], used by the streaming re-seed
/// ([`crate::ipfs_chunk::stream_ipfs_blocks`]) so a multi-GB posting is chunked
/// into the store without ever holding the whole file (or all its blocks) at once.
pub async fn put_ipfs_block<B: Blockstore>(store: &B, cid_str: &str, bytes: &[u8]) -> Result<()> {
    let cid: MsCid =
        MsCid::from_str(cid_str).with_context(|| format!("parse ipfs cid `{cid_str}`"))?;
    store
        .put_keyed(&cid, bytes)
        .await
        .with_context(|| format!("blockstore put_keyed `{cid_str}` ({} bytes)", bytes.len()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parse_record_cid_accepts_bare_cidv1() {
        let bare = "bagacbabaec7v3fu2ygzh3e2sybg3fbzmisry2hbtpmck6vx3yftea6vzq35r4";
        parse_record_cid(bare).expect("a bare CIDv1 is the only accepted shape");
    }

    /// The `<algo>:<cid>` token form was removed. This function used to strip
    /// the prefix, which is what kept the deprecated shape alive on the wire —
    /// rejecting it is the point.
    #[test]
    fn parse_record_cid_rejects_typed_prefix() {
        let typed = "midhash256:bagacbabaec7v3fu2ygzh3e2sybg3fbzmisry2hbtpmck6vx3yftea6vzq35r4";
        assert!(
            parse_record_cid(typed).is_err(),
            "the typed token form must be rejected, not silently stripped"
        );
    }

    /// CIDv0 used to parse here and report codec dag-pb — ranking 40, the top
    /// tier — while meta-core's strict decoder rejected it and ranked it 0. The
    /// two disagreed about the top of the ladder.
    #[test]
    fn parse_record_cid_rejects_cidv0() {
        assert!(
            parse_record_cid("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG").is_err(),
            "CIDv0 must be rejected so Rust and Go agree (see the cidv0-rejected golden vector)"
        );
    }

    #[test]
    fn parse_record_cid_rejects_garbage() {
        assert!(parse_record_cid("not-a-cid").is_err());
        assert!(parse_record_cid("midhash256:").is_err());
        assert!(parse_record_cid("").is_err());
    }

    /// Round-trip a single payload via put_keyed → store.get. Validates that
    /// the cid-string ↔ CidGeneric parse round-trip the gateway side
    /// produces is symmetric on the consumer side.
    #[tokio::test]
    async fn put_keyed_and_get_roundtrip() {
        use sha2::{Digest, Sha256};
        let dir = tempdir().expect("tempdir");
        let store = open_redb_blockstore(dir.path()).await.expect("open");
        let payload = b"hello bitswap";

        // Build a raw-codec cid the same way `crate::hash::compute_ipfs_blocks`
        // would on the gateway side, so we exercise the same cid shape
        // that arrives over the wire.
        let digest: [u8; 32] = Sha256::digest(payload).into();
        // CIDv1 wire: [version=0x01][codec=0x55][mh code=0x12][len=0x20][digest].
        let mut wire = Vec::with_capacity(36);
        wire.push(0x01);
        wire.push(0x55);
        wire.push(0x12);
        wire.push(0x20);
        wire.extend_from_slice(&digest);
        let cid_str = format!("b{}", base32_lower_no_padding(&wire));

        let cid = MsCid::from_str(&cid_str).expect("parse");
        store.put_keyed(&cid, payload).await.expect("put");
        let got = store.get(&cid).await.expect("get").expect("present");
        assert_eq!(got, payload);
    }

    /// Same base32 alphabet `crate::hash` uses on the gateway side —
    /// inlined here because that module lives in another package.
    fn base32_lower_no_padding(input: &[u8]) -> String {
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

    /// The routing table in `IngressRouter::put_keyed`, which is where Phase 4
    /// decides whether an arriving block becomes a file or a row.
    mod ingress_router {
        use super::*;
        use crate::ingress::{IngressCtx, IngressRegistry};
        use blockstore::InMemoryBlockstore;
        use std::sync::Arc;

        fn leaf_cid(bytes: &[u8]) -> MsCid {
            parse_record_cid(&crate::ipfs_chunk::compute_ipfs_cid(bytes)).expect("cid")
        }

        /// A leaf some fetch is waiting for goes to that fetch's file, and
        /// **not** into the block table — the whole point of the phase.
        #[tokio::test]
        async fn expected_leaf_lands_in_the_file_not_the_block_table() {
            let dir = tempfile::tempdir().expect("tmpdir");
            let ingress = Arc::new(IngressRegistry::with_min_bytes(
                dir.path().join("tmp"),
                dir.path().join("cache"),
                1,
            ));
            let inner = Arc::new(InMemoryBlockstore::<64>::new());
            let router = IngressRouter::new(Arc::clone(&inner), Arc::clone(&ingress));

            let payload = vec![b'x'; 64];
            let job = ingress
                .begin("bafycontainer", "bafycontainer", "movie.mkv", 64)
                .await
                .expect("begin")
                .expect("job");
            let ctx = IngressCtx { job: Arc::clone(&job), base: 0 };
            let cid = leaf_cid(&payload);
            ingress.expect_leaf(&ctx, cid.to_bytes(), 0, 64);

            router.put_keyed(&cid, &payload).await.expect("put");
            assert!(!inner.has(&cid).await.expect("has"), "must not be material");
            assert_eq!(tokio::fs::read(&job.path).await.expect("read"), payload);
        }

        /// Records, posters, thumbnails and dag-pb internal nodes arrive
        /// unattributed by construction — they have no file to belong to, and the
        /// artwork and record-resolution paths need them locally.
        #[tokio::test]
        async fn small_unattributed_block_stays_material() {
            let dir = tempfile::tempdir().expect("tmpdir");
            let ingress = Arc::new(IngressRegistry::new(
                dir.path().join("tmp"),
                dir.path().join("cache"),
            ));
            let inner = Arc::new(InMemoryBlockstore::<64>::new());
            let router = IngressRouter::new(Arc::clone(&inner), ingress);
            let payload = b"a poster".to_vec();
            let cid = leaf_cid(&payload);
            router.put_keyed(&cid, &payload).await.expect("put");
            assert_eq!(inner.get(&cid).await.expect("get"), Some(payload));
        }

        /// Provider-only: file content arrives as leaves *of a job*, so a large
        /// block nobody is waiting for is content we were never asked to keep.
        #[tokio::test]
        async fn large_unattributed_block_is_dropped() {
            let dir = tempfile::tempdir().expect("tmpdir");
            let ingress = Arc::new(IngressRegistry::new(
                dir.path().join("tmp"),
                dir.path().join("cache"),
            ));
            let inner = Arc::new(InMemoryBlockstore::<64>::new());
            let router = IngressRouter::with_loose_max(Arc::clone(&inner), ingress, 8);
            let payload = vec![b'z'; 4096];
            let cid = leaf_cid(&payload);
            router.put_keyed(&cid, &payload).await.expect("put");
            assert!(!inner.has(&cid).await.expect("has"));
        }
    }
}
