//! Watch-commit supervisor for the **IPFS tier** — "once a viewer really watches
//! it, finish the file" — plus the promotion that turns a finished
//! materialisation into a cache container.
//!
//! ## Why a supervisor at all
//!
//! Playback is read-driven: `api/files/bitswap.rs` walks only the leaves a
//! `Range` intersects. So a viewer who watches twenty minutes and closes the tab
//! leaves the dag *incomplete*, and "promote when the dag completes" would keep
//! almost nothing — the peer would fetch a title, serve it, and throw it away.
//!
//! The torrent tier already solved this shape ([`crate::bt_commit`]): a genuine
//! play records *intent*, and a supervisor turns intent into a full download
//! under a disk floor and a concurrency cap. This is the same design for bitswap,
//! with the same asymmetry — intent is recorded, state is read from the job
//! rather than stored, so a drifted view can only mislabel a pass, never strand a
//! fill.
//!
//! ## What a pass does
//!
//! 1. **Promote** every job whose file is whole — regardless of commit. A fetch
//!    that completed on its own (`POST /api/add/…`, a `warm`, an unranged GET) is
//!    finished content and belongs in `cache/` immediately.
//! 2. **Fill** committed jobs, up to `max_concurrent`, while free disk is above
//!    `min_free_bytes`. A commit is a want, not a promise: filling a disk to
//!    honour one is strictly worse than streaming it, and the eviction sweeper
//!    reclaims on its own schedule so a later pass re-arms.
//! 3. **Discard** jobs that are idle, uncommitted and incomplete — their partial
//!    file is re-fetchable and nothing indexes it.
//!
//! ## Filling is a windowed re-walk, not a second fetch path
//!
//! The fill asks `ipfs_walker::walk_range` for the file in windows and drops the
//! bytes. That looks wasteful and is exactly the opposite: the walker already
//! resolves each leaf blockstore → refs → in-flight file → bitswap, so a leaf
//! already in the `tmp/` file is a local read and only genuinely missing leaves
//! hit the swarm. One fetch path, one place where a leaf can be attributed to a
//! file, and no second implementation of dag traversal to drift.
//!
//! Windows bound memory: `walk_range` returns the range it walked, so asking for
//! a whole 2 GB file would materialise 2 GB of `Bytes` to throw away.

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::api::AppState;
use crate::ingress::{IngressCtx, IngressJob};

/// Bytes pulled per `walk_range` call during a fill. Big enough that the
/// per-window overhead is noise against 256 KiB leaves, small enough that the
/// discarded buffer never dominates RSS.
const FILL_WINDOW_BYTES: u64 = 32 * 1024 * 1024;

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn enabled() -> bool {
    !matches!(std::env::var("META_SHARE_INGRESS_COMMIT").as_deref(), Ok("0") | Ok("false"))
}

/// Start the supervisor. No-op when `META_SHARE_INGRESS_COMMIT=0`, in which case
/// jobs still promote on their own completion — only the background filling of a
/// partially-watched title is off.
pub fn spawn(state: Arc<AppState>) {
    let interval =
        Duration::from_secs(env_u64("META_SHARE_INGRESS_COMMIT_INTERVAL_SECS", 30).max(1));
    let max_concurrent = env_u64("META_SHARE_INGRESS_COMMIT_MAX_CONCURRENT", 2).max(1) as usize;
    // Same floor as the torrent tier's default: below this, fills stand down.
    let min_free_bytes = env_u64("META_SHARE_INGRESS_COMMIT_MIN_FREE_BYTES", 5 * 1024 * 1024 * 1024);
    let commit_enabled = enabled();
    info!(
        commit_enabled,
        max_concurrent,
        min_free_bytes,
        interval_secs = interval.as_secs(),
        "ipfs ingress supervisor started"
    );
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        loop {
            tick.tick().await;
            run_pass(&state, commit_enabled, max_concurrent, min_free_bytes).await;
        }
    });
}

async fn run_pass(
    state: &Arc<AppState>,
    commit_enabled: bool,
    max_concurrent: usize,
    min_free_bytes: u64,
) {
    for job in state.ingress.complete_jobs() {
        promote(state, &job).await;
    }

    if commit_enabled {
        let free = meta_feeder_sdk::transport::fsutil::available_bytes(&state.data_dir).unwrap_or(u64::MAX);
        if free >= min_free_bytes {
            let mut started = 0usize;
            for job in state.ingress.jobs() {
                if started >= max_concurrent {
                    break;
                }
                if job.is_promoted() || job.is_complete() || !job.is_committed() {
                    continue;
                }
                if !job.begin_fill() {
                    // Already filling from an earlier pass.
                    continue;
                }
                started += 1;
                let state = Arc::clone(state);
                let job = Arc::clone(&job);
                tokio::spawn(async move {
                    if let Err(e) = fill(&state, &job).await {
                        debug!(container = %job.container, error = %format!("{e:#}"),
                            "ingress fill: stopped short; a later pass retries");
                    }
                    job.end_fill();
                    if job.is_complete() {
                        promote(&state, &job).await;
                    }
                });
            }
        } else {
            debug!(free, min_free_bytes, "ingress fill: standing down, disk floor");
        }
    }

    // Idle, uncommitted, incomplete: nothing is coming. The partial file is
    // re-fetchable and no index points at it.
    for job in state.ingress.stale_jobs() {
        if job.is_committed() || job.is_filling() || job.is_promoted() {
            continue;
        }
        debug!(container = %job.container, received = job.received_bytes(), total = job.total,
            "ingress: discarding an idle partial fetch");
        state.ingress.discard(&job.container).await;
    }
}

/// Fetch every leaf the job is still missing, in windows.
///
/// **The lane is the title's own, not a blanket `Background`.** A fill exists
/// because a viewer played *this* title, and the play claimed a focus lease for
/// it — so hardcoding `Background` makes the peer throttle the fill of the very
/// thing being watched to `bg_rate_bytes` (10 KiB/s by default). Measured before
/// this: 1.7 MB in 90 s. `focus.lane` answers per title, which gives the right
/// behaviour in both directions — the focused title's fill runs free, and a fill
/// for anything *else* is floored while someone is watching.
async fn fill(state: &Arc<AppState>, job: &Arc<IngressJob>) -> anyhow::Result<()> {
    let lane = state.focus.lane(&job.root);
    let root = crate::blockstore::parse_record_cid(&job.root)?;
    let root_block = crate::api::ipfs_walker::get_block(state, &root, lane).await?;
    let ceiling = crate::api::ipfs_walker::max_body_bytes();
    let window = FILL_WINDOW_BYTES.min(ceiling as u64).max(1);
    let mut start = 0u64;
    while start < job.total {
        if job.is_promoted() {
            break;
        }
        let end = (start + window - 1).min(job.total - 1);
        let ctx = IngressCtx { job: Arc::clone(job), base: 0 };
        // The bytes are the point of a `/raw` request, not of a fill — the leaves
        // land in the file as a side effect of the walk, and the buffer here is
        // dropped immediately.
        // Re-resolved per window: a lease can be claimed or expire mid-fill, and
        // a multi-GB file is many windows.
        let lane = state.focus.lane(&job.root);
        let _ = crate::api::ipfs_walker::walk_range(
            state,
            &root_block,
            start,
            end,
            ceiling,
            lane,
            Some(&ctx),
        )
        .await?;
        job.touch();
        start = end.saturating_add(1);
    }
    Ok(())
}

/// Publish a finished materialisation: file → index → refs → seed row, each step
/// depending only on the one before it.
///
/// The ordering is the same one every other tier uses and it is not stylistic:
/// a ref resolves *through* the material index, so a ref written first would be
/// unresolvable; and a seed row written before the refs would advertise a cid
/// this peer cannot yet serve.
async fn promote(state: &Arc<AppState>, job: &Arc<IngressJob>) {
    if job.is_promoted() {
        return;
    }
    // Claim first: two passes can see the same complete job, and promoting twice
    // would register the refs twice against a directory the second rename didn't
    // move.
    job.mark_promoted();

    let container = job.container.clone();
    let dir = match crate::material::promote_container(
        state.ingress.tmp_dir(),
        state.ingress.cache_dir(),
        &container,
    )
    .await
    {
        Ok(d) => d,
        Err(e) => {
            warn!(container = %container, error = %e, "ingress promote: rename failed");
            return;
        }
    };
    let path = dir.join(&job.rel);
    let size = match tokio::fs::metadata(&path).await {
        Ok(m) => m.len(),
        Err(e) => {
            warn!(container = %container, path = %path.display(), error = %e,
                "ingress promote: the promoted file vanished");
            return;
        }
    };

    // The hull indexes the container for local-first reads before any ref
    // advertises its bytes: file → index → refs, as before.
    let ev = meta_feeder_sdk::transport::Event::Promoted {
        container: container.clone(),
        cids: vec![job.root.clone()],
        files: vec![meta_feeder_sdk::transport::PromotedFile {
            rel: job.rel.clone(),
            path: path.display().to_string(),
            size,
        }],
    };
    if let Err(e) = state.hull.emit(&ev).await {
        warn!(container = %container, error = %e, "ingress promote: the hull did not index the container");
    }

    // Register every leaf as a ref into the published file. No re-chunk: the walk
    // that fetched them already knew each leaf's cid, offset and length, which is
    // exactly what a ref is. (The Usenet tier has to stream the whole file back
    // through the chunker precisely because it never saw a dag.)
    let refs = job.leaf_refs();
    let mut written = 0u64;
    for leaf in &refs {
        match state.block_store.put_cache_leaf_ref(leaf, &container, &job.rel).await {
            Ok(()) => written += 1,
            Err(e) => warn!(container = %container, cid = %leaf.cid, error = %format!("{e:#}"),
                "ingress promote: ref write failed"),
        }
    }

    // Never seal onto a dag we don't fully hold: a hole here surfaces later as a
    // bitswap WANT stalling some peer mid-stream, long after the cause. Refs make
    // `has()` true, so this is a local walk — no network.
    let complete = match crate::blockstore::parse_record_cid(&job.root) {
        Ok(root) => crate::share::local_dag_complete(state, &root).await,
        Err(e) => {
            warn!(container = %container, error = %format!("{e:#}"),
                "ingress promote: unparseable root; not recording a seed");
            return;
        }
    };
    if !complete {
        warn!(container = %container, refs = written,
            "ingress promote: dag incomplete after ref registration; file kept, not seeded");
        return;
    }

    // The seed row, bound to the container its bytes live in (or eviction knows
    // the size but not the files and tearing it down frees nothing).
    crate::api::record_ipfs_seed(state, &job.root, &job.rel, job.total, Some(&container)).await;

    info!(container = %container, refs = written, bytes = job.total,
        "ingress: promoted a bitswap fetch into the cache");
    state.ingress.close(&container);
}
