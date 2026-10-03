//! Nocopy filestore layer over the IPFS blockstore.
//!
//! ## Why
//!
//! A **library** file (one this peer's meta-core owns, under `/files`) used to be
//! seeded by reading the whole file over WebDAV, chunking it into 256 KiB IPFS
//! blocks, and writing every block into `blocks.redb` — a *second full copy* of
//! bytes meta-core already persists (CLAUDE.md invariant 9's one violation, and
//! the reason `META_SHARE_IPFS_SEED_MAX_FILE_BYTES` existed to skip big files).
//!
//! This layer removes the copy. Instead of storing a leaf's bytes it stores a
//! **ref** — `(midhash256, offset, len)` — and reconstructs the leaf on demand by
//! re-reading `file[offset..offset+len]` (from a co-located read-only `/files`
//! mount when present, else meta-core WebDAV `Range`). Sound because a kubo raw
//! leaf *is* that byte slice (`ipfs_chunk`'s parity invariant), so the re-read
//! hashes back to the same CID; every served block is verified against its CID
//! before delivery, so a file changed underneath us is caught, not served
//! corrupt.
//!
//! Internal dag-pb nodes are **synthesized** (protobuf, not file slices) and
//! can't be refs — they stay material in the inner store, a few KB per file.
//!
//! ## Two backings, one mechanism
//!
//! A ref names bytes in a file *someone* owns, and there are two owners:
//!
//! - [`Backing::MetaCore`] — the **library**: meta-core owns the path, resolved
//!   by midhash through `/meta/{midhash}`. Registered by [`crate::ipfs_seed`].
//! - [`Backing::Material`] — the **cache**: meta-share owns the path, resolved
//!   through `crate::material`'s index. Registered by the Usenet re-seed
//!   ([`crate::nzb::serve`]) via [`FilestoreBlockstore::put_cache_leaf_ref`].
//!
//! Neither stores a path, for the same reason: the owner of "where does this
//! live" is the one authority allowed to answer, so a rename — meta-core moving
//! a library file, or a `tmp/`→`cache/` promotion here — costs one index update
//! and never a ref rewrite.
//!
//! ## What stays material
//!
//! Internal dag-pb nodes (synthesized, not slices) and anything
//! arriving as loose blocks off the swarm (`put_keyed`) — bytes with no file
//! behind them to ref. `put_keyed` is still a straight forward to the inner
//! store.
//!
//! ## Layering
//!
//! `GatedBlockstore<FilestoreBlockstore<RedbBlockstore>>` — the focus gate wraps
//! the filestore (so a ref-resolved library leaf served to a stranger is still
//! throttled while our viewer watches), and the filestore wraps the raw redb
//! store. The refs table lives in the *same* `blocks.redb` database (via
//! `RedbBlockstore::raw_db`), so there is one file, one fsync domain.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use blockstore::{Blockstore, RedbBlockstore};
use cid::CidGeneric;
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle};
use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;
use tracing::{debug, warn};

use crate::ipfs_chunk::LeafRef;

/// Concrete filestore type used across the process (over the persistent redb
/// store). One alias so the type-threading through swarm/AppState/helpers reads
/// as a single name.
pub type SharedBlockstore = FilestoreBlockstore<RedbBlockstore>;

/// Multihash code for sha2-256 — the only hash a raw IPFS leaf (and therefore a
/// ref) ever uses. Verification rejects anything else rather than trusting an
/// unverifiable slice.
const SHA2_256_CODE: u64 = 0x12;

/// Leaf-ref table, keyed by the leaf CID's wire bytes, valued by the encoded
/// [`RefValue`]. Distinct table name from `RedbBlockstore`'s
/// `BLOCKSTORE.BLOCKS`, so the two coexist in one database.
const LEAF_REFS: TableDefinition<'static, &[u8], &[u8]> =
    TableDefinition::new("FILESTORE.LEAF_REFS");

/// Separator between a container id and a material's relative path inside a
/// [`Backing::Material`] payload. The same ASCII unit separator
/// `crate::material` keys entries with, and the thing that makes the two
/// backings distinguishable without a version byte (see [`RefValue::decode`]).
const SEP: char = '\x1f';

/// Who owns the file a leaf ref points into — the two storage regimes this peer
/// has, and the reason a ref needs a discriminant at all.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Backing {
    /// **meta-core owns the path.** Identified by the file's midhash256; the
    /// current path is resolved through meta-core (`/meta/{midhash}` → `filePath`)
    /// and read off the local `/files` mount or WebDAV. D3: refs survive renames
    /// precisely because we don't store the path.
    MetaCore(String),
    /// **meta-share owns the path** — a file in its own cache. Identified by the
    /// material index's `(container, rel)`, which is that tier's equivalent of
    /// the same rule: the index owns "where does this live", the ref owns only
    /// "which bytes of it". A torrent retarget or a tmp→cache rename therefore
    /// costs one index update, not a ref rewrite.
    Material { container: String, rel: String },
}

impl std::fmt::Display for Backing {
    /// For log lines — enough to identify the file without dumping a path.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Backing::MetaCore(midhash) => write!(f, "core:{midhash}"),
            Backing::Material { container, rel } => write!(f, "cache:{container}/{rel}"),
        }
    }
}

/// Where a leaf lives in its backing file. Encoded as
/// `[offset u64-LE][len u64-LE][payload utf8]`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RefValue {
    backing: Backing,
    offset: u64,
    len: u64,
}

impl RefValue {
    fn encode(&self) -> Vec<u8> {
        let payload = match &self.backing {
            Backing::MetaCore(midhash) => midhash.clone(),
            Backing::Material { container, rel } => format!("{container}{SEP}{rel}"),
        };
        let mut out = Vec::with_capacity(16 + payload.len());
        out.extend_from_slice(&self.offset.to_le_bytes());
        out.extend_from_slice(&self.len.to_le_bytes());
        out.extend_from_slice(payload.as_bytes());
        out
    }

    /// Decode, discriminating on the payload rather than a version byte.
    ///
    /// A midhash payload is a bare multibase CID — alphanumeric, so it can never
    /// contain `\x1f`. A material payload always does, by construction. That
    /// makes the two unambiguous **and** leaves every ref written before this
    /// existed decoding exactly as it used to, so the library tier needs no
    /// migration and no re-seed. A tag byte would have silently mis-decoded
    /// every stored row and taken the library dark on bitswap until it was
    /// re-seeded.
    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 16 {
            return None;
        }
        let offset = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
        let len = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
        let payload = String::from_utf8(bytes[16..].to_vec()).ok()?;
        let backing = match payload.split_once(SEP) {
            Some((container, rel)) => Backing::Material {
                container: container.to_string(),
                rel: rel.to_string(),
            },
            None => Backing::MetaCore(payload),
        };
        Some(Self { backing, offset, len })
    }
}

/// The bytes-resolution context — everything needed to turn a ref back into
/// bytes, cloned from config at startup (the filestore is built before
/// `AppState`, so it can't borrow from it). Cheap to share behind an `Arc`.
pub struct FilestoreResolver {
    http: reqwest::Client,
    /// `None` on a consumer-only peer (no meta-core) — then refs can't be
    /// resolved, but such a peer never registers any either.
    meta_core_url: Option<String>,
    /// Prefix on meta-core's absolute `filePath`s (e.g. `/files`), stripped to
    /// get the path relative to the files volume.
    files_path_prefix: String,
    /// Read-only `/files` mount inside *this* container, when meta-core is
    /// co-located (D2). `Some` → read slices straight off disk; `None` → always
    /// WebDAV. Falls back to WebDAV on any local miss, so a stale mount never
    /// wedges serving.
    local_files_root: Option<PathBuf>,
    /// Shared with `AppState` so the WebDAV base URL is resolved once per
    /// process, not once per tier.
    webdav_url_cache: Arc<OnceCell<String>>,
    /// midhash → files-relative path, primed by the seeder at registration and
    /// refilled from meta-core on a serve-time miss (after a restart). Keeps the
    /// common per-leaf serve from hitting meta-core for the path every time.
    path_cache: tokio::sync::Mutex<HashMap<String, String>>,
    /// Path authority for [`Backing::Material`] refs: `<cache_dir>/<container>/<rel>`.
    ///
    /// In the monolith this was the material index (a redb read). The index
    /// lives in meta-share's hull now, and the path it stored for a promoted
    /// container is exactly this one — a container is named for its initiating
    /// cid and never renamed — so the plugin derives it instead of asking. A
    /// missing file is still `Ok(None)`, i.e. "drop the ref".
    cache_dir: PathBuf,
}

impl FilestoreResolver {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        http: reqwest::Client,
        meta_core_url: Option<String>,
        files_path_prefix: String,
        local_files_root: Option<PathBuf>,
        webdav_url_cache: Arc<OnceCell<String>>,
        cache_dir: PathBuf,
    ) -> Self {
        Self {
            cache_dir,
            http,
            meta_core_url,
            files_path_prefix,
            local_files_root,
            webdav_url_cache,
            path_cache: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Prime the path cache with a midhash → files-relative path the seeder
    /// already knows, so serving this file's leaves in the same process is a
    /// cache hit rather than a meta-core round-trip.
    pub async fn prime_path(&self, midhash: &str, rel_path: &str) {
        if midhash.is_empty() || rel_path.is_empty() {
            return;
        }
        self.path_cache
            .lock()
            .await
            .insert(midhash.to_string(), rel_path.to_string());
    }

    /// Resolve a midhash to its files-relative path (cache → meta-core `/meta`).
    /// `Ok(None)` when the record is gone (404) — a signal to drop the ref.
    pub(crate) async fn rel_path_for(&self, midhash: &str) -> Result<Option<String>> {
        if let Some(p) = self.path_cache.lock().await.get(midhash).cloned() {
            return Ok(Some(p));
        }
        let Some(meta_core_url) = self.meta_core_url.as_deref() else {
            anyhow::bail!("no meta-core url; cannot resolve ref path");
        };
        let url = format!("{}/meta/{}", meta_core_url.trim_end_matches('/'), midhash);
        let resp = self
            .http
            .get(&url)
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = resp.error_for_status().with_context(|| format!("upstream {url}"))?;
        #[derive(serde::Deserialize)]
        struct MetaResp {
            #[serde(default)]
            metadata: HashMap<String, String>,
        }
        let parsed: MetaResp = resp.json().await.context("decode /meta json")?;
        let Some(abs) = parsed.metadata.get("filePath").filter(|s| !s.is_empty()) else {
            return Ok(None);
        };
        let rel = abs
            .strip_prefix(self.files_path_prefix.trim_end_matches('/'))
            .unwrap_or(abs)
            .trim_start_matches('/')
            .to_string();
        if rel.is_empty() {
            return Ok(None);
        }
        self.path_cache
            .lock()
            .await
            .insert(midhash.to_string(), rel.clone());
        Ok(Some(rel))
    }

    /// Read `file[offset..offset+len]` for a ref: local mount first (when set),
    /// WebDAV `Range` otherwise or on a local miss. `Ok(None)` when the record
    /// is gone (drop the ref); `Err` on a transient failure (keep it, retry
    /// later).
    async fn resolve_slice(&self, r: &RefValue) -> Result<Option<Vec<u8>>> {
        let midhash = match &r.backing {
            Backing::MetaCore(m) => m,
            // Cache-backed: the container path is derived (see `cache_dir`), so
            // there is no meta-core round trip and no WebDAV fallback — these
            // bytes are ours and local by definition. A missing file is
            // `Ok(None)`, i.e. "drop the ref": the filesystem is authoritative,
            // and a ref into a file we no longer hold is exactly the dangling
            // entry that would make us a black hole on bitswap.
            Backing::Material { container, rel } => {
                let path = self.cache_dir.join(container).join(rel);
                return match read_local_slice(
                    &path,
                    r.offset,
                    r.len,
                )
                .await
                {
                    Ok(bytes) => Ok(Some(bytes)),
                    Err(e) => {
                        debug!(container = %container, rel = %rel, error = %e,
                            "filestore: cache slice read failed; dropping ref");
                        Ok(None)
                    }
                };
            }
        };

        let Some(rel) = self.rel_path_for(midhash).await? else {
            return Ok(None);
        };

        if let Some(root) = &self.local_files_root {
            match read_local_slice(&root.join(&rel), r.offset, r.len).await {
                Ok(bytes) => return Ok(Some(bytes)),
                Err(e) => debug!(rel = %rel, error = %e,
                    "filestore: local slice read failed; falling back to webdav"),
            }
        }

        let bytes = self.webdav_range(&rel, r.offset, r.len).await?;
        Ok(Some(bytes))
    }

    /// WebDAV `Range` fetch of one leaf-sized slice.
    async fn webdav_range(&self, rel: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
        let Some(meta_core_url) = self.meta_core_url.as_deref() else {
            anyhow::bail!("no meta-core url; cannot webdav-fetch ref");
        };
        let base = crate::webdav::resolve_webdav_url(&self.http, meta_core_url, &self.webdav_url_cache)
            .await
            .context("resolve webdav url")?;
        let encoded: String = rel
            .split('/')
            .map(crate::webdav::urlencode_path_segment)
            .collect::<Vec<_>>()
            .join("/");
        let url = format!("{base}/{encoded}");
        // Inclusive end per HTTP byte-range semantics; a zero-length leaf (empty
        // file) needs no fetch.
        if len == 0 {
            return Ok(Vec::new());
        }
        let end = offset + len - 1;
        let resp = self
            .http
            .get(&url)
            .header(reqwest::header::RANGE, format!("bytes={offset}-{end}"))
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .with_context(|| format!("GET {url} range {offset}-{end}"))?
            .error_for_status()
            .with_context(|| format!("webdav {url}"))?;
        let bytes = resp.bytes().await.context("read webdav range body")?;
        Ok(bytes.to_vec())
    }
}

/// Read `len` bytes at `offset` from a local file.
async fn read_local_slice(path: &std::path::Path, offset: u64, len: u64) -> Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut f = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("open {}", path.display()))?;
    f.seek(std::io::SeekFrom::Start(offset)).await.context("seek")?;
    let mut buf = vec![0u8; len as usize];
    f.read_exact(&mut buf).await.context("read_exact slice")?;
    Ok(buf)
}

/// What backs a seeded dag's leaves, as far as this peer's blockstore can tell.
/// Answered by [`FilestoreBlockstore::first_leaf_backing`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeafBacking {
    /// A ref into a file meta-core owns, identified by the file's midhash256.
    MetaCore(String),
    /// A ref into a file in meta-share's own cache (the material index).
    Cache,
    /// The leaf's bytes are stored material — swarm-fetched, no file behind it.
    Material,
    /// Nothing to go on: the root or a node on the way down is absent.
    Unknown,
}

/// Deepest dag this walks before giving up. A balanced kubo dag at fanout 174
/// is 4 levels deep at ~200 GB, so anything deeper is not one of ours.
const MAX_DAG_DEPTH: usize = 8;

/// Nocopy blockstore: material blocks in `inner`, library leaves as refs in a
/// side table, resolved + verified on read. See the module docs.
pub struct FilestoreBlockstore<B> {
    inner: Arc<B>,
    db: Arc<Database>,
    resolver: Arc<FilestoreResolver>,
    /// In-flight bitswap materialisations. Consulted on a read miss so a leaf
    /// already written into a `tmp/` file is served without a refetch — for our
    /// own next range as much as for a peer's WANT (design §2a). Never written
    /// to from here: registration is `crate::ingress`'s business.
    ingress: Arc<crate::ingress::IngressRegistry>,
}

impl<B> FilestoreBlockstore<B> {
    /// Wrap an inner store, sharing its redb database for the refs table.
    /// `db` must be the same `Database` backing `inner` (pass
    /// `inner.raw_db()`), so refs and blocks share one file.
    pub fn new(
        inner: Arc<B>,
        db: Arc<Database>,
        resolver: Arc<FilestoreResolver>,
        ingress: Arc<crate::ingress::IngressRegistry>,
    ) -> Self {
        Self { inner, db, resolver, ingress }
    }

    /// The resolver, so the seeder can prime the path cache at registration.
    pub fn resolver(&self) -> &Arc<FilestoreResolver> {
        &self.resolver
    }

    /// Register one library leaf as a ref instead of storing its bytes. Called
    /// only by the library seeder. `midhash` is the file's meta-core content id.
    pub async fn put_leaf_ref(&self, leaf: &LeafRef, midhash: &str) -> Result<()> {
        self.put_ref(leaf, Backing::MetaCore(midhash.to_string())).await
    }

    /// Register one **cache** leaf as a ref into a material this peer owns.
    ///
    /// The Usenet counterpart of [`put_leaf_ref`](Self::put_leaf_ref): after a
    /// posting is materialised and renamed into the cache, its leaves are refs
    /// into that file rather than a second copy of it in `blocks.redb`. This is
    /// what makes the Usenet→IPFS re-seed cost zero extra bytes — measured
    /// before this change as a 1.5 GB blockstore against a 724 MB file.
    ///
    /// **Only ever call this once the file is at its final path.** A ref
    /// registered against a `tmp/` file would advertise blocks to the swarm that
    /// the next `rename(2)` invalidates.
    pub async fn put_cache_leaf_ref(
        &self,
        leaf: &LeafRef,
        container: &str,
        rel: &str,
    ) -> Result<()> {
        self.put_ref(
            leaf,
            Backing::Material { container: container.to_string(), rel: rel.to_string() },
        )
        .await
    }

    async fn put_ref(&self, leaf: &LeafRef, backing: Backing) -> Result<()> {
        let key = crate::blockstore::parse_record_cid(&leaf.cid)
            .with_context(|| format!("parse leaf cid `{}`", leaf.cid))?
            .to_bytes();
        let value = RefValue { backing, offset: leaf.offset, len: leaf.len }.encode();
        let db = Arc::clone(&self.db);
        tokio::task::spawn_blocking(move || -> Result<()> {
            let txn = db.begin_write().context("begin_write refs")?;
            {
                let mut table = txn.open_table(LEAF_REFS).context("open refs table")?;
                table
                    .insert(key.as_slice(), value.as_slice())
                    .context("insert ref")?;
            }
            txn.commit().context("commit ref")?;
            Ok(())
        })
        .await
        .context("join refs write")?
    }

    /// Look up a ref by CID wire bytes.
    async fn get_ref(&self, key: Vec<u8>) -> Result<Option<RefValue>> {
        let db = Arc::clone(&self.db);
        tokio::task::spawn_blocking(move || -> Result<Option<RefValue>> {
            let txn = db.begin_read().context("begin_read refs")?;
            let table = match txn.open_table(LEAF_REFS) {
                Ok(t) => t,
                // Table not created yet → no refs at all.
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
                Err(e) => return Err(e).context("open refs table (read)"),
            };
            let Some(v) = table.get(key.as_slice()).context("get ref")? else {
                return Ok(None);
            };
            Ok(RefValue::decode(v.value()))
        })
        .await
        .context("join refs read")?
    }

    /// Delete a ref by CID wire bytes. Best-effort presence — deleting an absent
    /// key is fine.
    async fn remove_ref(&self, key: Vec<u8>) -> Result<()> {
        let db = Arc::clone(&self.db);
        tokio::task::spawn_blocking(move || -> Result<()> {
            let txn = db.begin_write().context("begin_write refs (remove)")?;
            {
                let mut table = match txn.open_table(LEAF_REFS) {
                    Ok(t) => t,
                    Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
                    Err(e) => return Err(e).context("open refs table (remove)"),
                };
                table.remove(key.as_slice()).context("remove ref")?;
            }
            txn.commit().context("commit ref remove")?;
            Ok(())
        })
        .await
        .context("join refs remove")?
    }

    /// Drop every leaf ref pointing into any of `materials` (`(container, rel)`
    /// pairs), in **one** table scan. Returns how many were removed.
    ///
    /// Called when a material leaves the index — the boot scrub finding a file
    /// gone or drifted, or a container teardown. Refs must not outlive their
    /// material: `has()` consults the refs table, so a stale ref keeps this peer
    /// answering "yes, I have that block" for bytes it can no longer produce.
    /// That is the dangling-entry failure at block granularity, and it is worse
    /// than a local error — the CID was announced to the DHT, so every peer that
    /// asks stalls on a promise nobody will keep.
    ///
    /// One scan rather than one per material: the boot scrub can remove many at
    /// once, and refs outnumber materials by ~4 per MiB.
    pub async fn drop_refs_for_materials(
        &self,
        materials: &[(String, String)],
    ) -> Result<u64> {
        if materials.is_empty() {
            return Ok(0);
        }
        let targets: std::collections::HashSet<(String, String)> =
            materials.iter().cloned().collect();
        let db = Arc::clone(&self.db);
        tokio::task::spawn_blocking(move || -> Result<u64> {
            let txn = db.begin_write().context("begin_write refs (sweep)")?;
            let mut removed = 0u64;
            {
                let mut table = match txn.open_table(LEAF_REFS) {
                    Ok(t) => t,
                    Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
                    Err(e) => return Err(e).context("open refs table (sweep)"),
                };
                let doomed: Vec<Vec<u8>> = table
                    .iter()
                    .context("iter refs")?
                    .filter_map(|r| r.ok())
                    .filter_map(|(k, v)| {
                        let rv = RefValue::decode(v.value())?;
                        let Backing::Material { container, rel } = rv.backing else {
                            return None;
                        };
                        targets.contains(&(container, rel)).then(|| k.value().to_vec())
                    })
                    .collect();
                for key in doomed {
                    table.remove(key.as_slice()).context("remove ref")?;
                    removed += 1;
                }
            }
            txn.commit().context("commit refs sweep")?;
            Ok(removed)
        })
        .await
        .context("join refs sweep")?
    }

    /// Per-table storage accounting for the shared redb database, plus the file
    /// on disk.
    ///
    /// **The question this exists to answer**: how much of `blocks.redb` is
    /// material block bytes, how much is index, and how much is neither. There
    /// was no way to ask from outside the process — which is how a peer reached
    /// **112 GiB of blockstore against 59 GB of cache it was serving entirely
    /// through refs** without anything noticing. `file_bytes` against
    /// `stored_bytes` is the whole diagnosis: redb never truncates and the crate
    /// never compacts, so a large gap is dead high-water from bytes that were
    /// once material.
    ///
    /// Read transaction, not `WriteTransaction::stats()`: the write-txn variant
    /// is the only way to get redb's global `allocated_pages`, but it takes the
    /// write lock, which on this database is the block-ingest path. Per-table
    /// stats answer the question without ever blocking a write, and the file
    /// size covers what `allocated_pages` would have told us.
    ///
    /// **Not cheap** — each table's stats walk its btree. This is an operator
    /// surface (`GET /api/stats/blockstore`), deliberately not folded into the
    /// dashboard-polled `/api/stats`.
    pub async fn stats(&self, db_path: Option<PathBuf>) -> Result<BlockstoreStats> {
        let file_bytes = match db_path {
            Some(p) => tokio::fs::metadata(&p).await.map(|m| m.len()).unwrap_or(0),
            None => 0,
        };
        let db = Arc::clone(&self.db);
        let mut tables = tokio::task::spawn_blocking(move || -> Result<Vec<TableStats>> {
            let txn = db.begin_read().context("begin_read stats")?;
            let handles: Vec<redb::UntypedTableHandle> =
                txn.list_tables().context("list tables")?.collect();
            let mut out = Vec::with_capacity(handles.len());
            for handle in handles {
                let name = handle.name().to_string();
                let table = txn.open_untyped_table(handle).context("open untyped table")?;
                let s = table.stats().context("table stats")?;
                out.push(TableStats {
                    name,
                    entries: table.len().context("table len")?,
                    stored_bytes: s.stored_bytes(),
                    metadata_bytes: s.metadata_bytes(),
                    fragmented_bytes: s.fragmented_bytes(),
                });
            }
            Ok(out)
        })
        .await
        .context("join blockstore stats")??;
        tables.sort_by(|a, b| b.stored_bytes.cmp(&a.stored_bytes));

        let stored_bytes: u64 = tables.iter().map(|t| t.stored_bytes).sum();
        let leaf_refs = tables
            .iter()
            .find(|t| t.name == LEAF_REFS.name())
            .map(|t| t.entries)
            .unwrap_or(0);
        let blocks = tables
            .iter()
            .find(|t| t.name == BLOCKS_TABLE_NAME)
            .map(|t| (t.entries, t.stored_bytes))
            .unwrap_or((0, 0));
        Ok(BlockstoreStats {
            file_bytes,
            stored_bytes,
            // What the file holds beyond live data: redb free pages from removed
            // blocks (never returned to the filesystem) plus per-page slack.
            unaccounted_bytes: file_bytes.saturating_sub(stored_bytes),
            material_blocks: blocks.0,
            material_bytes: blocks.1,
            leaf_refs,
            tables,
        })
    }
}

/// Name of `RedbBlockstore`'s own table. Not exported by the `blockstore` crate,
/// so it is matched by string — a rename upstream turns the `material_*` figures
/// into zeros rather than into a wrong answer, and the per-table list still shows
/// the truth.
const BLOCKS_TABLE_NAME: &str = "BLOCKSTORE.BLOCKS";

/// Typed handle on that table, for the one pass that has to walk it. The same
/// `&[u8] → &[u8]` shape the `blockstore` crate declares.
const BLOCKS_TABLE: TableDefinition<'static, &[u8], &[u8]> = TableDefinition::new(BLOCKS_TABLE_NAME);

/// One-shot maintenance passes that have already run against this database,
/// keyed by pass name. Lets a boot-time sweep over the whole block table run
/// once per database instead of once per restart.
const SCRUBS_DONE: TableDefinition<'static, &str, u64> = TableDefinition::new("META_SHARE.SCRUBS");

/// Key in [`SCRUBS_DONE`] for [`scrub_record_blocks`].
const RECORD_BLOCK_SCRUB: &str = "record-blocks";

/// Remove every `MSR1` record block earlier builds left in the block table.
/// Returns how many were removed (`0` on every run after the first).
///
/// Ingest used to mirror each meta-core record into the blockstore under the
/// record's canonical cid. For a file that cid **is** the file's content cid,
/// so the record replaced a material block or hid a leaf ref (`get` reads
/// material first) — a peer asked for a poster answered with ~600 bytes of
/// bincode. The blocks could not do the job they were written for either: a
/// bitswap receiver derives a block's cid by hashing the payload, so a record
/// stored under any cid but its own hash never satisfies a want.
///
/// The writer is gone. Removing a block un-hides the ref beneath it, so seeded
/// content becomes servable again with no refetch. The sweep reads the whole
/// table, so it records itself in [`SCRUBS_DONE`] and later boots skip it.
pub async fn scrub_record_blocks(db: Arc<Database>) -> Result<u64> {
    tokio::task::spawn_blocking(move || -> Result<u64> {
        {
            let txn = db.begin_read().context("begin_read scrubs")?;
            match txn.open_table(SCRUBS_DONE) {
                Ok(t) => {
                    if t.get(RECORD_BLOCK_SCRUB).context("read scrub marker")?.is_some() {
                        return Ok(0);
                    }
                }
                Err(redb::TableError::TableDoesNotExist(_)) => {}
                Err(e) => return Err(e).context("open scrubs table"),
            }
        }
        let txn = db.begin_write().context("begin_write blocks (record scrub)")?;
        let mut removed = 0u64;
        {
            match txn.open_table(BLOCKS_TABLE) {
                Ok(mut table) => {
                    let doomed: Vec<Vec<u8>> = table
                        .iter()
                        .context("iter blocks")?
                        .filter_map(|r| r.ok())
                        .filter(|(_, v)| crate::store::Record::decode_block(v.value()).is_ok())
                        .map(|(k, _)| k.value().to_vec())
                        .collect();
                    for key in doomed {
                        table.remove(key.as_slice()).context("remove record block")?;
                        removed += 1;
                    }
                }
                Err(redb::TableError::TableDoesNotExist(_)) => {}
                Err(e) => return Err(e).context("open blocks table (record scrub)"),
            }
            let mut marker = txn.open_table(SCRUBS_DONE).context("open scrubs table (write)")?;
            marker
                .insert(RECORD_BLOCK_SCRUB, removed)
                .context("write scrub marker")?;
        }
        txn.commit().context("commit record scrub")?;
        Ok(removed)
    })
    .await
    .context("join record scrub")?
}

/// One redb table's contribution to the file. Serialized as-is.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TableStats {
    pub name: String,
    pub entries: u64,
    pub stored_bytes: u64,
    pub metadata_bytes: u64,
    pub fragmented_bytes: u64,
}

/// What `blocks.redb` is actually made of. See [`FilestoreBlockstore::stats`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct BlockstoreStats {
    /// The database file's size on disk — the figure that competes with the
    /// cache for the volume.
    pub file_bytes: u64,
    /// Live keys + values across every table.
    pub stored_bytes: u64,
    /// `file_bytes - stored_bytes`: free pages and slack. Large means the file is
    /// a high-water mark of bytes that are no longer there.
    pub unaccounted_bytes: u64,
    /// Blocks held as **material bytes** — the thing the filestore exists to
    /// avoid for file content.
    pub material_blocks: u64,
    pub material_bytes: u64,
    /// Leaf refs — file content served without a copy.
    pub leaf_refs: u64,
    pub tables: Vec<TableStats>,
}

impl<B: Blockstore> FilestoreBlockstore<B> {
    /// Resolve a ref to verified bytes. `None` = serve nothing (record gone,
    /// verify mismatch, or transient failure): bitswap then tries another peer,
    /// and for a library file a warn is logged since we are the intended host.
    ///
    async fn serve_ref<const S: usize>(
        &self,
        cid: &CidGeneric<S>,
        r: RefValue,
    ) -> Option<Vec<u8>> {
        let bytes = match self.resolver.resolve_slice(&r).await {
            Ok(Some(b)) => b,
            Ok(None) => {
                // Record vanished — the ref is stale; drop it so we stop
                // advertising a block we can no longer produce.
                debug!(cid = %cid, backing = %r.backing,
                    "filestore: ref target gone; dropping ref");
                let _ = self.remove_ref(cid.to_bytes()).await;
                return None;
            }
            Err(e) => {
                warn!(cid = %cid, backing = %r.backing, error = %format!("{e:#}"),
                    "filestore: ref resolve failed (transient); keeping ref");
                return None;
            }
        };
        if !verify_cid(cid, &bytes) {
            // The file changed under the ref — never serve unverified bytes to
            // the swarm. Drop the ref; a re-seed will re-register correct ones.
            warn!(cid = %cid, backing = %r.backing, len = bytes.len(),
                "filestore: ref bytes fail CID verification; dropping ref");
            let _ = self.remove_ref(cid.to_bytes()).await;
            return None;
        }
        Some(bytes)
    }
}

impl<B: Blockstore> FilestoreBlockstore<B> {
    /// Follow a dag's first-child chain down to a leaf and report what backs
    /// it. One leaf speaks for the file: every leaf of one seed is registered by
    /// one writer against one backing (`ipfs_seed`'s library refs, or the
    /// cache tiers' material refs).
    pub async fn first_leaf_backing(&self, root: &crate::blockstore::MsCid) -> Result<LeafBacking> {
        let mut cur = *root;
        for _ in 0..MAX_DAG_DEPTH {
            if let Some(r) = self.get_ref(cur.to_bytes()).await? {
                return Ok(match r.backing {
                    Backing::MetaCore(m) => LeafBacking::MetaCore(m),
                    Backing::Material { .. } => LeafBacking::Cache,
                });
            }
            let Some(bytes) = self.inner.get(&cur).await.context("inner get")? else {
                return Ok(LeafBacking::Unknown);
            };
            if cur.codec() != crate::api::ipfs_walker::DAGPB_CODEC {
                return Ok(LeafBacking::Material);
            }
            let node = crate::api::ipfs_walker::parse_pbnode(&bytes).context("parse dag-pb")?;
            let Some((child, _)) = node.children.first() else {
                return Ok(LeafBacking::Unknown);
            };
            cur = *child;
        }
        Ok(LeafBacking::Unknown)
    }

    /// Remove a **library** seed's blocks: its internal dag-pb nodes, and every
    /// leaf ref that points into `midhash` — and nothing else. Returns how many
    /// entries went.
    ///
    /// Narrower than a plain walk-and-remove on purpose. A leaf key holds one ref,
    /// so if the same 256 KiB leaf also belongs to a cache seed, its ref may be
    /// that seed's; removing it would take a block out from under a container
    /// this pass is keeping. Only refs this library seed wrote (same midhash) are
    /// ours to drop.
    pub async fn remove_library_dag(
        &self,
        root: &crate::blockstore::MsCid,
        midhash: &str,
    ) -> Result<u64> {
        let mut stack = vec![*root];
        let mut seen = std::collections::HashSet::new();
        let mut removed = 0u64;
        while let Some(cid) = stack.pop() {
            if !seen.insert(cid.to_bytes()) {
                continue;
            }
            if let Some(r) = self.get_ref(cid.to_bytes()).await? {
                if r.backing == Backing::MetaCore(midhash.to_string()) {
                    self.remove_ref(cid.to_bytes()).await?;
                    removed += 1;
                }
                continue;
            }
            if cid.codec() != crate::api::ipfs_walker::DAGPB_CODEC {
                continue; // a material leaf: not a library ref, not ours
            }
            let Some(bytes) = self.inner.get(&cid).await.context("inner get")? else {
                continue;
            };
            if let Ok(node) = crate::api::ipfs_walker::parse_pbnode(&bytes) {
                stack.extend(node.children.into_iter().map(|(c, _)| c));
            }
            self.inner.remove(&cid).await.context("inner remove")?;
            removed += 1;
        }
        Ok(removed)
    }
}

impl<B: Blockstore> Blockstore for FilestoreBlockstore<B> {
    async fn get<const S: usize>(&self, cid: &CidGeneric<S>) -> blockstore::Result<Option<Vec<u8>>> {
        // Material first: swarm-fetched blocks, internal dag-pb nodes, and every
        // cache leaf live here. The common case (any non-library block) never
        // touches the refs table.
        if let Some(bytes) = self.inner.get(cid).await? {
            return Ok(Some(bytes));
        }
        // Miss → maybe a leaf ref into a published file. Resolve + verify on demand.
        match self.get_ref(cid.to_bytes()).await {
            Ok(Some(r)) => return Ok(self.serve_ref(cid, r).await),
            Ok(None) => {}
            Err(e) => {
                warn!(cid = %cid, error = %format!("{e:#}"), "filestore: refs lookup failed");
                return Ok(None);
            }
        }
        // Still a miss → maybe a leaf an in-flight fetch has already received
        // into its `tmp/` file (design §2a). No ref exists for it and none may:
        // the next `rename(2)` would invalidate it. Verified like any other
        // reconstructed block, so a torn or racing write is caught rather than
        // served.
        match self.ingress.read_leaf(&cid.to_bytes()).await {
            Some(bytes) if verify_cid(cid, &bytes) => Ok(Some(bytes)),
            Some(_) => {
                debug!(cid = %cid, "filestore: in-flight leaf failed verification; not serving");
                Ok(None)
            }
            None => Ok(None),
        }
    }

    async fn put_keyed<const S: usize>(
        &self,
        cid: &CidGeneric<S>,
        data: &[u8],
    ) -> blockstore::Result<()> {
        // All material writes (cache tiers, internal nodes) go straight to the
        // inner store. Refs are registered only via `put_leaf_ref`.
        self.inner.put_keyed(cid, data).await
    }

    async fn remove<const S: usize>(&self, cid: &CidGeneric<S>) -> blockstore::Result<()> {
        // Drop from both: a cid is only ever in one, but teardown shouldn't have
        // to know which, and removing an absent key is a no-op.
        self.inner.remove(cid).await?;
        if let Err(e) = self.remove_ref(cid.to_bytes()).await {
            warn!(cid = %cid, error = %format!("{e:#}"), "filestore: ref remove failed");
        }
        Ok(())
    }

    async fn has<const S: usize>(&self, cid: &CidGeneric<S>) -> blockstore::Result<bool> {
        if self.inner.has(cid).await? {
            return Ok(true);
        }
        if matches!(self.get_ref(cid.to_bytes()).await, Ok(Some(_))) {
            return Ok(true);
        }
        // Same three sources as `get`, in the same order — `has` answering
        // differently is what would make this peer advertise a block it declines
        // to serve, or decline one it holds. Presence only: no `pread`.
        Ok(self.ingress.has_leaf(&cid.to_bytes()))
    }

    async fn close(self) -> blockstore::Result<()> {
        // Inner store is shared (`Arc`); nothing to consume. The redb file is
        // closed on process exit.
        Ok(())
    }
}

/// Verify that `bytes` hash to `cid`'s multihash digest. Only sha2-256 is
/// accepted — the only hash a raw leaf (and thus a ref) ever uses; anything else
/// is treated as unverifiable and rejected.
fn verify_cid<const S: usize>(cid: &CidGeneric<S>, bytes: &[u8]) -> bool {
    let mh = cid.hash();
    if mh.code() != SHA2_256_CODE {
        return false;
    }
    let digest = Sha256::digest(bytes);
    mh.digest() == digest.as_slice()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The poisoned shape from watch.nsl.sh: a record under a poster's content
    /// cid. The scrub must take the record and leave real content alone — and
    /// run once, not on every boot.
    #[tokio::test]
    async fn record_scrub_removes_msr1_blocks_and_keeps_content() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("blocks.redb")).unwrap());
        let store = RedbBlockstore::new(Arc::clone(&db));
        let poisoned = crate::blockstore::parse_record_cid(
            "bafkreia5mnykkptlj3dbpppuclcsdi7ncjgv37nd7jcolzqlgk7cryt56m",
        )
        .unwrap();
        let content = crate::blockstore::parse_record_cid(
            "bafkreiacfsxkljphqdmt4bddvg6fuox62l4cxlg6dzwambmp76cfgxbqta",
        )
        .unwrap();
        let record = crate::store::Record {
            cid: poisoned.to_string(),
            title: "poster".into(),
            year: None,
            tokens: Vec::new(),
            cids: vec![poisoned.to_string()],
            fields: Default::default(),
        };
        store.put_keyed(&poisoned, &record.encode_block().unwrap()).await.unwrap();
        store.put_keyed(&content, b"\xff\xd8\xff jpeg bytes").await.unwrap();

        assert_eq!(scrub_record_blocks(Arc::clone(&db)).await.unwrap(), 1);
        assert!(store.get(&poisoned).await.unwrap().is_none());
        assert_eq!(
            store.get(&content).await.unwrap().as_deref(),
            Some(&b"\xff\xd8\xff jpeg bytes"[..])
        );

        // A record written after the marker would be a regression elsewhere; the
        // pass itself must not re-walk the table.
        store.put_keyed(&poisoned, &record.encode_block().unwrap()).await.unwrap();
        assert_eq!(scrub_record_blocks(db).await.unwrap(), 0);
    }

    /// A brand-new database has neither table; the scrub must not fail on it.
    #[tokio::test]
    async fn record_scrub_on_an_empty_database_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("blocks.redb")).unwrap());
        assert_eq!(scrub_record_blocks(db).await.unwrap(), 0);
    }

    #[test]
    fn refvalue_roundtrip_meta_core() {
        let r = RefValue {
            backing: Backing::MetaCore("bagacbabc".into()),
            offset: 262144,
            len: 100,
        };
        assert_eq!(RefValue::decode(&r.encode()).expect("decode"), r);
    }

    #[test]
    fn refvalue_roundtrip_material() {
        let r = RefValue {
            backing: Backing::Material {
                container: "bagcsaaa5locator".into(),
                rel: "Some.Show.S01E21.mkv".into(),
            },
            offset: 524288,
            len: 262144,
        };
        assert_eq!(RefValue::decode(&r.encode()).expect("decode"), r);
    }

    /// The discriminant is the payload's shape, not a version byte — which is
    /// what lets refs written before `Backing` existed keep decoding as library
    /// refs instead of silently mis-parsing and taking the library dark.
    #[test]
    fn refvalue_decodes_legacy_bare_midhash_as_meta_core() {
        let mut legacy = Vec::new();
        legacy.extend_from_slice(&262144u64.to_le_bytes());
        legacy.extend_from_slice(&100u64.to_le_bytes());
        legacy.extend_from_slice(b"bagacbabc");
        let decoded = RefValue::decode(&legacy).expect("decode");
        assert_eq!(decoded.backing, Backing::MetaCore("bagacbabc".into()));
        assert_eq!(decoded.offset, 262144);
        assert_eq!(decoded.len, 100);
    }

    /// A rel path may itself contain separators-ish characters; only the *first*
    /// unit separator splits, so nested torrent paths survive the round trip.
    #[test]
    fn refvalue_material_rel_may_contain_slashes() {
        let r = RefValue {
            backing: Backing::Material {
                container: "c".into(),
                rel: "Season 01/Ep 21.mkv".into(),
            },
            offset: 0,
            len: 1,
        };
        assert_eq!(RefValue::decode(&r.encode()).expect("decode"), r);
    }

    #[test]
    fn refvalue_decode_rejects_short() {
        assert!(RefValue::decode(&[0u8; 8]).is_none());
    }

    #[test]
    fn verify_cid_accepts_matching_sha256_leaf() {
        // CID for "hello world" as a raw sha2-256 leaf (pinned in ipfs_chunk).
        let cid = crate::blockstore::parse_record_cid(
            "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e",
        )
        .expect("parse");
        assert!(verify_cid(&cid, b"hello world"));
        assert!(!verify_cid(&cid, b"hello worlx"));
    }
}
