//! Bitswap ingress as **files** — Phase 4 of `docs/unified-cache-filesystem.md`.
//!
//! ## Why
//!
//! Three of the four ways bytes enter this peer put them in a file and register
//! the dag's leaves as refs: Usenet into `cache/<cid>/` ([`crate::nzb::serve`]),
//! the library into meta-core's `/files` ([`crate::ipfs_seed`]), and the torrent
//! tier into its own sparse files. Bitswap was the exception — every fetched
//! leaf was written into `blocks.redb` as **material bytes**, a second full copy
//! of the file with no GC (`crate::blockstore`) and no compaction anywhere in the
//! crate. Measured consequence on a live peer: **112 GiB of blockstore against 59
//! GB of cache it was serving entirely through refs** — unreclaimable, because
//! redb never returns pages to the filesystem.
//!
//! This module closes that: a fetch materialises into `tmp/<cid>/`, is promoted
//! into `cache/<cid>/` by `rename(2)` once the dag is whole, and its leaves
//! become refs into that file. The same shape the Usenet tier already proved,
//! where the measurement was *"a 1.49 GB posting sealed with the blockstore
//! growing 0 MB"*.
//!
//! ## "Fetch for our user implies seed"
//!
//! `CLAUDE.md` invariant 7 used to read "fetch implies seed", which was true only
//! because every received block was written material. It is narrowed here: a
//! fetch **driven by this peer's HTTP API** is ours and is kept; the libp2p side
//! is provider-only — we answer WANTs from what we hold and never persist a block
//! that no local request asked for. The enforcement point is
//! [`IngressRegistry::accept`], called from `crate::blockstore::IngressRouter`:
//! a block is written to a file only when a job is *expecting* that exact leaf,
//! and anything unattributable is dropped rather than stored.
//!
//! ## Serving while filling (design §2a)
//!
//! Rule R1 says leaf refs may only point at `cache/`, never `tmp/` — a ref into a
//! file the next `rename(2)` invalidates would advertise blocks this peer cannot
//! produce. Applied flatly that would stop the IPFS tier contributing for the
//! whole duration of a download, which is a swarm regression the design
//! explicitly narrows away: *a bitswap-filled `tmp/` file may serve the leaves it
//! has already received, from its own in-flight set.*
//!
//! [`IngressJob::read_leaf`] is that set. It is consulted by
//! [`crate::filestore::FilestoreBlockstore::get`] after the material store and
//! the refs table both miss — so nothing is persisted, R1 holds literally, and
//! because the lookup sits *under* `GatedBlockstore` an in-flight leaf served to
//! a stranger is throttled like any other block. It also keeps **our own**
//! re-reads local: after Phase 4 a leaf is no longer in redb, so without this a
//! second range over the same bytes would re-WANT it off the swarm.
//!
//! ## Ownership
//!
//! One job per **initiating cid** — the cid the HTTP client asked for, which is
//! immutable (D1 in the design doc). The elected canonical of a record moves the
//! moment a dag-pb root outranks a locator, so it can never name a directory.

use std::collections::HashMap;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use tracing::{debug, warn};

use crate::ipfs_chunk::LeafRef;

/// Below this, a dag-pb file stays material rather than becoming a container.
/// A container costs a directory, an index row, one ref per leaf and an eviction
/// unit; for a small multi-block asset that is more bookkeeping than the bytes it
/// saves. Override with `META_SHARE_INGRESS_MIN_BYTES`.
const DEFAULT_INGRESS_MIN_BYTES: u64 = 4 * 1024 * 1024;

/// How long a job with no arrivals and no commit survives before the sweeper
/// discards it and its partial file. Override with `META_SHARE_INGRESS_JOB_TTL_SECS`.
const DEFAULT_JOB_TTL_SECS: u64 = 30 * 60;

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Where a leaf this peer is waiting for belongs in the file being filled.
#[derive(Clone)]
struct Pending {
    job: Arc<IngressJob>,
    offset: u64,
    len: u64,
}

#[derive(Default)]
struct Inner {
    /// Initiating cid → job.
    jobs: HashMap<String, Arc<IngressJob>>,
    /// Leaf cid (wire bytes) → where it goes. The router's whole lookup, and the
    /// reason an unsolicited block is distinguishable from a wanted one.
    pending: HashMap<Vec<u8>, Pending>,
}

/// Process-wide registry of in-flight bitswap materialisations.
pub struct IngressRegistry {
    inner: RwLock<Inner>,
    tmp_dir: PathBuf,
    cache_dir: PathBuf,
    min_bytes: u64,
    job_ttl_secs: u64,
}

/// A leaf's placement in the file, resolved from the walk. Threaded into
/// `ipfs_walker::walk_range` so every child it descends through is registered
/// with its **file-absolute** offset before the fetch is issued.
pub struct IngressCtx {
    pub job: Arc<IngressJob>,
    /// Absolute offset, in the file's byte space, of the node being walked.
    pub base: u64,
}

impl IngressCtx {
    /// A context for a nested dag-pb child at `child_start` within this node.
    pub fn nested(&self, child_start: u64) -> IngressCtx {
        IngressCtx {
            job: Arc::clone(&self.job),
            base: self.base.saturating_add(child_start),
        }
    }
}

impl IngressRegistry {
    /// Build against the shared cache tree (`crate::material::storage_dirs`), so
    /// ingress promotes into the same `cache/` every other tier does.
    pub fn from_data_dir(data_dir: &Path) -> Self {
        let (tmp_dir, cache_dir) = crate::material::storage_dirs(data_dir);
        Self::new(tmp_dir, cache_dir)
    }

    /// Same registry with an explicit container floor, so a test can exercise
    /// the accept/complete machinery on a few bytes instead of the 4 MiB a real
    /// container is worth.
    #[cfg(test)]
    pub(crate) fn with_min_bytes(tmp_dir: PathBuf, cache_dir: PathBuf, min_bytes: u64) -> Self {
        let mut r = Self::new(tmp_dir, cache_dir);
        r.min_bytes = min_bytes;
        r
    }

    pub fn new(tmp_dir: PathBuf, cache_dir: PathBuf) -> Self {
        Self {
            inner: RwLock::new(Inner::default()),
            tmp_dir,
            cache_dir,
            min_bytes: env_u64("META_SHARE_INGRESS_MIN_BYTES", DEFAULT_INGRESS_MIN_BYTES),
            job_ttl_secs: env_u64("META_SHARE_INGRESS_JOB_TTL_SECS", DEFAULT_JOB_TTL_SECS),
        }
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    pub fn tmp_dir(&self) -> &Path {
        &self.tmp_dir
    }

    /// Start (or adopt) the job filling `container`. `Ok(None)` when the file is
    /// too small to be worth a container — the caller then behaves exactly as
    /// before this module existed and the leaves stay material.
    ///
    /// Creating the sparse file up front is what makes every later write a plain
    /// `pwrite` at a known offset: leaves arrive out of order by nature, and a
    /// file that already has its final length has nowhere to race.
    pub async fn begin(
        &self,
        container: &str,
        root: &str,
        name: &str,
        total: u64,
    ) -> Result<Option<Arc<IngressJob>>> {
        if total < self.min_bytes {
            return Ok(None);
        }
        if let Some(existing) = self.job(container) {
            return Ok(Some(existing));
        }
        let rel = sanitize_rel(name, container);
        let dir = self.tmp_dir.join(container);
        let path = dir.join(&rel);
        tokio::fs::create_dir_all(&dir)
            .await
            .with_context(|| format!("create ingress tmp dir {}", dir.display()))?;

        let file_path = path.clone();
        let file = tokio::task::spawn_blocking(move || -> std::io::Result<std::fs::File> {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .open(&file_path)?;
            f.set_len(total)?;
            Ok(f)
        })
        .await
        .context("join ingress file create")?
        .with_context(|| format!("create sparse file {}", path.display()))?;

        let job = Arc::new(IngressJob {
            container: container.to_string(),
            root: root.to_string(),
            rel,
            path,
            total,
            file: Arc::new(file),
            state: RwLock::new(JobState {
                received: HashMap::new(),
                received_bytes: 0,
                last_touch: now_secs(),
                promoted: false,
                committed: false,
                filling: false,
            }),
        });
        // Re-check under the write lock: two concurrent range requests for the
        // same cid both reach `begin`, and the loser must adopt the winner's job
        // rather than hand out a second handle to the same file.
        let mut inner = self.inner.write().expect("ingress lock");
        let job = inner
            .jobs
            .entry(container.to_string())
            .or_insert(job)
            .clone();
        debug!(container, total, path = %job.path.display(), "ingress: filling");
        Ok(Some(job))
    }

    pub fn job(&self, container: &str) -> Option<Arc<IngressJob>> {
        self.inner.read().expect("ingress lock").jobs.get(container).cloned()
    }

    pub fn jobs(&self) -> Vec<Arc<IngressJob>> {
        self.inner.read().expect("ingress lock").jobs.values().cloned().collect()
    }

    /// Declare that `job` wants `leaf_cid` at `offset`. Called by the walker for
    /// every raw leaf it is about to fetch, *before* the WANT goes out, so the
    /// block can be attributed the moment it lands.
    pub fn expect_leaf(&self, ctx: &IngressCtx, leaf_cid_bytes: Vec<u8>, offset: u64, len: u64) {
        if ctx.job.is_promoted() || len == 0 {
            return;
        }
        let mut inner = self.inner.write().expect("ingress lock");
        inner.pending.insert(
            leaf_cid_bytes,
            Pending { job: Arc::clone(&ctx.job), offset, len },
        );
    }

    /// Route an arriving block. `true` when it belonged to a job and was written
    /// to that job's file — the caller must then **not** store it as material.
    ///
    /// This is the provider-only boundary: a block nobody is waiting for returns
    /// `false` and is dropped by the router.
    pub async fn accept(&self, cid_bytes: &[u8], bytes: &[u8]) -> bool {
        let pending = {
            let inner = self.inner.read().expect("ingress lock");
            match inner.pending.get(cid_bytes) {
                Some(p) => p.clone(),
                None => return false,
            }
        };
        // A leaf shorter than declared would tear a hole at the next offset;
        // refuse it and let the block fall through to the material path, where
        // the dag walk's own length check reports it.
        if bytes.len() as u64 != pending.len {
            warn!(offset = pending.offset, declared = pending.len, got = bytes.len(),
                container = %pending.job.container,
                "ingress: leaf length disagrees with the dag; not writing it to the file");
            return false;
        }
        if let Err(e) = pending.job.write_leaf(pending.offset, bytes).await {
            warn!(container = %pending.job.container, offset = pending.offset,
                error = %format!("{e:#}"), "ingress: leaf write failed; keeping it material");
            return false;
        }
        pending.job.mark_received(cid_bytes, pending.offset, pending.len);
        self.inner.write().expect("ingress lock").pending.remove(cid_bytes);
        true
    }

    /// Does some job already hold this leaf? The presence half of
    /// [`read_leaf`](Self::read_leaf), for `has()` — which must agree with `get`
    /// or this peer advertises blocks it declines to serve, but must not pay a
    /// 256 KiB `pread` to answer.
    pub fn has_leaf(&self, cid_bytes: &[u8]) -> bool {
        self.inner
            .read()
            .expect("ingress lock")
            .jobs
            .values()
            .any(|j| j.received_at(cid_bytes).is_some())
    }

    /// The §2a read: bytes of a leaf some job has already received. `None` when
    /// no job holds it — which is the common case and costs one map lookup.
    pub async fn read_leaf(&self, cid_bytes: &[u8]) -> Option<Vec<u8>> {
        let (job, offset, len) = {
            let inner = self.inner.read().expect("ingress lock");
            let mut found = None;
            for job in inner.jobs.values() {
                if let Some((offset, len)) = job.received_at(cid_bytes) {
                    found = Some((Arc::clone(job), offset, len));
                    break;
                }
            }
            found?
        };
        match job.read_at(offset, len).await {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                debug!(container = %job.container, offset, error = %format!("{e:#}"),
                    "ingress: in-flight leaf read failed");
                None
            }
        }
    }

    /// Drop a job and every leaf still pending for it. Does **not** touch the
    /// file — promotion has already renamed it, or the caller is discarding it.
    pub fn close(&self, container: &str) {
        let mut inner = self.inner.write().expect("ingress lock");
        inner.jobs.remove(container);
        inner.pending.retain(|_, p| p.job.container != container);
    }

    /// Jobs whose dag is fully present in their file — ready to promote.
    pub fn complete_jobs(&self) -> Vec<Arc<IngressJob>> {
        self.jobs().into_iter().filter(|j| j.is_complete() && !j.is_promoted()).collect()
    }

    /// Jobs idle past the TTL. The caller decides whether a job is exempt
    /// (committed titles are still being filled).
    pub fn stale_jobs(&self) -> Vec<Arc<IngressJob>> {
        let cutoff = now_secs().saturating_sub(self.job_ttl_secs);
        self.jobs().into_iter().filter(|j| j.last_touch() < cutoff).collect()
    }

    /// Discard a job's partial file along with the job.
    pub async fn discard(&self, container: &str) {
        self.close(container);
        let dir = self.tmp_dir.join(container);
        if let Err(e) = tokio::fs::remove_dir_all(&dir).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                debug!(container, dir = %dir.display(), error = %e,
                    "ingress: discarding the partial dir failed");
            }
        }
    }

    /// Boot sweep: delete `tmp/` dirs left by jobs that died mid-fill.
    ///
    /// Safe by construction and deliberately asymmetric with the cache scrub,
    /// which *keeps* orphan dirs: a directory under `cache/` is complete bytes
    /// that eviction owns, while one under `tmp/` is incomplete by definition —
    /// nothing indexes it, nothing serves it after a restart (the in-flight set
    /// lived in memory), and its content is re-fetchable. Leaving them would be a
    /// slow leak of exactly the disk this phase is trying to save.
    ///
    /// Skips `<cid>.work` scratch dirs, which belong to the Usenet bridge.
    pub async fn sweep_tmp(&self) -> u64 {
        let mut removed = 0u64;
        let mut rd = match tokio::fs::read_dir(&self.tmp_dir).await {
            Ok(rd) => rd,
            Err(_) => return 0,
        };
        let live: Vec<String> = self.jobs().iter().map(|j| j.container.clone()).collect();
        while let Ok(Some(entry)) = rd.next_entry().await {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".work") || live.contains(&name) {
                continue;
            }
            if !entry.path().is_dir() {
                continue;
            }
            if tokio::fs::remove_dir_all(entry.path()).await.is_ok() {
                removed += 1;
            }
        }
        if removed > 0 {
            debug!(removed, "ingress: swept abandoned tmp dirs");
        }
        removed
    }
}

struct JobState {
    /// Leaf cid wire bytes → (offset, len). Both the §2a serving set and, via
    /// `received_bytes`, the completion test.
    received: HashMap<Vec<u8>, (u64, u64)>,
    received_bytes: u64,
    last_touch: u64,
    promoted: bool,
    /// A viewer played this title; `crate::ingress_commit` should finish the file.
    committed: bool,
    /// A background fill is running for this job right now. Read from the job
    /// rather than tracked by the supervisor so a pass that overlaps the previous
    /// one can't start a second fill over the same file.
    filling: bool,
}

/// One file being filled from the swarm.
pub struct IngressJob {
    /// The immutable cid that initiated the fetch — the container's name.
    pub container: String,
    /// The dag-pb root actually walked. Same value as `container` on today's
    /// path; kept separate because the container name may not be a content id.
    pub root: String,
    /// File name inside the container.
    pub rel: String,
    /// `tmp/<container>/<rel>`.
    pub path: PathBuf,
    pub total: u64,
    file: Arc<std::fs::File>,
    state: RwLock<JobState>,
}

impl IngressJob {
    /// `pwrite` — no seek, so concurrent leaf writes to one file never race.
    async fn write_leaf(&self, offset: u64, bytes: &[u8]) -> Result<()> {
        let file = Arc::clone(&self.file);
        let buf = bytes.to_vec();
        tokio::task::spawn_blocking(move || file.write_all_at(&buf, offset))
            .await
            .context("join leaf write")?
            .context("pwrite leaf")
    }

    async fn read_at(&self, offset: u64, len: u64) -> Result<Vec<u8>> {
        let file = Arc::clone(&self.file);
        tokio::task::spawn_blocking(move || -> std::io::Result<Vec<u8>> {
            let mut buf = vec![0u8; len as usize];
            file.read_exact_at(&mut buf, offset)?;
            Ok(buf)
        })
        .await
        .context("join leaf read")?
        .context("pread leaf")
    }

    fn mark_received(&self, cid_bytes: &[u8], offset: u64, len: u64) {
        let mut st = self.state.write().expect("job lock");
        st.last_touch = now_secs();
        if st.received.insert(cid_bytes.to_vec(), (offset, len)).is_none() {
            st.received_bytes = st.received_bytes.saturating_add(len);
        }
    }

    fn received_at(&self, cid_bytes: &[u8]) -> Option<(u64, u64)> {
        self.state.read().expect("job lock").received.get(cid_bytes).copied()
    }

    pub fn received_bytes(&self) -> u64 {
        self.state.read().expect("job lock").received_bytes
    }

    /// Every leaf of the file is on disk.
    ///
    /// Leaves tile the file exactly — kubo chunking leaves no gaps and no
    /// overlaps — so the received bytes summing to the declared size *is* full
    /// coverage. No bitmap, which is what the design's §2a narrowing is careful
    /// to avoid inventing: the arrival set the fetch already keeps is enough.
    pub fn is_complete(&self) -> bool {
        self.received_bytes() >= self.total && self.total > 0
    }

    pub fn is_promoted(&self) -> bool {
        self.state.read().expect("job lock").promoted
    }

    pub fn last_touch(&self) -> u64 {
        self.state.read().expect("job lock").last_touch
    }

    pub fn touch(&self) {
        self.state.write().expect("job lock").last_touch = now_secs();
    }

    pub fn mark_promoted(&self) {
        self.state.write().expect("job lock").promoted = true;
    }

    /// A viewer genuinely played this title, so the rest of the file is worth
    /// fetching in the background rather than stopping at the playhead. Returns
    /// `true` on the transition only, so a per-range call doesn't log per range.
    ///
    /// **In-memory, unlike the torrent tier's `SeedEntry.committed`.** The intent
    /// only has to outlive the job, and the job dies with the process — a restart
    /// drops a half-filled `tmp/` file anyway (`sweep_tmp`), so there is nothing
    /// for a persisted flag to re-arm. Once promoted, filling is finished by
    /// definition.
    pub fn commit(&self) -> bool {
        let mut st = self.state.write().expect("job lock");
        if st.committed {
            return false;
        }
        st.committed = true;
        true
    }

    pub fn is_committed(&self) -> bool {
        self.state.read().expect("job lock").committed
    }

    /// Claim the fill slot. `false` when one is already running.
    pub fn begin_fill(&self) -> bool {
        let mut st = self.state.write().expect("job lock");
        if st.filling {
            return false;
        }
        st.filling = true;
        true
    }

    pub fn end_fill(&self) {
        self.state.write().expect("job lock").filling = false;
    }

    pub fn is_filling(&self) -> bool {
        self.state.read().expect("job lock").filling
    }

    /// Every received leaf as a [`LeafRef`], for registration against the
    /// promoted file.
    ///
    /// This is why bitswap ingress is cheaper to seal than the Usenet tier: a
    /// ref *is* `(cid, offset, len)`, and the walk already knew all three for
    /// every leaf, so promotion registers them directly instead of re-reading
    /// the file end-to-end to re-derive cids it was told.
    pub fn leaf_refs(&self) -> Vec<LeafRef> {
        let st = self.state.read().expect("job lock");
        st.received
            .iter()
            .filter_map(|(cid_bytes, (offset, len))| {
                let cid = crate::blockstore::MsCid::try_from(cid_bytes.as_slice()).ok()?;
                Some(LeafRef { cid: cid.to_string(), offset: *offset, len: *len })
            })
            .collect()
    }
}

/// A safe file name inside the container dir. Falls back to the cid when the
/// record's display name is empty or path-like — the name is cosmetic (the
/// container's identity is its directory), so anything unusable becomes the cid
/// rather than an error.
fn sanitize_rel(name: &str, container: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name).trim();
    let cleaned: String = base
        .chars()
        .filter(|c| !matches!(c, '\0' | '\x1f'))
        .collect();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        container.to_string()
    } else {
        cleaned
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Default floor — for the "small objects stay material" assertion.
    fn reg(dir: &Path) -> IngressRegistry {
        IngressRegistry::new(dir.join("tmp"), dir.join("cache"))
    }

    /// Floor of one byte, so a 16-byte fixture is a container.
    fn reg_tiny(dir: &Path) -> IngressRegistry {
        IngressRegistry::with_min_bytes(dir.join("tmp"), dir.join("cache"), 1)
    }

    /// Wire bytes of the raw-leaf cid for `bytes`. Anything ≤ 256 KiB is a
    /// single leaf, so `compute_ipfs_cid` *is* the leaf cid.
    fn leaf_cid(bytes: &[u8]) -> Vec<u8> {
        crate::blockstore::parse_record_cid(&crate::ipfs_chunk::compute_ipfs_cid(bytes))
            .expect("cid")
            .to_bytes()
    }

    #[tokio::test]
    async fn accepts_out_of_order_leaves_and_completes() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let r = reg_tiny(dir.path());
        let a = vec![b'a'; 8];
        let b = vec![b'b'; 8];
        let job = r
            .begin("bafyc", "bafyc", "movie.mkv", 16)
            .await
            .expect("begin")
            .expect("job");
        let ctx = IngressCtx { job: Arc::clone(&job), base: 0 };
        r.expect_leaf(&ctx, leaf_cid(&a), 0, 8);
        r.expect_leaf(&ctx, leaf_cid(&b), 8, 8);

        // Second leaf first — arrival order is the swarm's business, not ours.
        assert!(r.accept(&leaf_cid(&b), &b).await);
        assert!(!job.is_complete());
        assert!(r.accept(&leaf_cid(&a), &a).await);
        assert!(job.is_complete());

        let on_disk = tokio::fs::read(&job.path).await.expect("read");
        assert_eq!(on_disk, [a.clone(), b.clone()].concat());
        assert_eq!(r.read_leaf(&leaf_cid(&b)).await.expect("in-flight read"), b);
    }

    /// The provider-only property: a block no job asked for is not ours to keep.
    #[tokio::test]
    async fn unattributed_block_is_refused() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let r = reg(dir.path());
        let stray = vec![b'z'; 8];
        assert!(!r.accept(&leaf_cid(&stray), &stray).await);
        assert!(r.read_leaf(&leaf_cid(&stray)).await.is_none());
    }

    /// A leaf that doesn't match its declared length would tear a hole at the
    /// next offset, so it must not reach the file.
    #[tokio::test]
    async fn short_leaf_is_refused() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let r = reg_tiny(dir.path());
        let job = r.begin("bafyc", "bafyc", "x.mkv", 16).await.expect("begin").expect("job");
        let ctx = IngressCtx { job, base: 0 };
        let short = vec![b'a'; 4];
        r.expect_leaf(&ctx, leaf_cid(&short), 0, 8);
        assert!(!r.accept(&leaf_cid(&short), &short).await);
    }

    #[tokio::test]
    async fn small_files_stay_material() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let r = reg(dir.path());
        assert!(r.begin("bafyc", "bafyc", "poster.jpg", 1024).await.expect("begin").is_none());
    }

    #[tokio::test]
    async fn duplicate_leaf_is_counted_once() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let r = reg_tiny(dir.path());
        let job = r.begin("bafyc", "bafyc", "x.mkv", 16).await.expect("begin").expect("job");
        let ctx = IngressCtx { job: Arc::clone(&job), base: 0 };
        let a = vec![b'a'; 8];
        r.expect_leaf(&ctx, leaf_cid(&a), 0, 8);
        assert!(r.accept(&leaf_cid(&a), &a).await);
        // Re-expect + re-accept the same leaf (a second range over it).
        r.expect_leaf(&ctx, leaf_cid(&a), 0, 8);
        assert!(r.accept(&leaf_cid(&a), &a).await);
        assert_eq!(job.received_bytes(), 8);
    }

    #[tokio::test]
    async fn nested_ctx_accumulates_absolute_offsets() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let r = reg_tiny(dir.path());
        let job = r
            .begin("c", "c", "x", 8 * 1024 * 1024)
            .await
            .expect("begin")
            .expect("job");
        let root = IngressCtx { job, base: 0 };
        assert_eq!(root.nested(1024).nested(256).base, 1280);
    }

    #[test]
    fn sanitize_rel_falls_back_to_the_cid() {
        assert_eq!(sanitize_rel("a/b/c.mkv", "cid"), "c.mkv");
        assert_eq!(sanitize_rel("   ", "cid"), "cid");
        assert_eq!(sanitize_rel("..", "cid"), "cid");
    }
}
