//! The plugin's slice of meta-share's former `api` module: the state the moved
//! IPFS code reads (kept under the same names, so it moved unedited), the dag
//! walker, the `/ipfs/:cid` gateway handler and the bitswap byte path.

use std::path::PathBuf;
use std::sync::Arc;

use meta_feeder_sdk::transport::{Event, FocusView, HullClient};
use tokio::sync::{mpsc, OnceCell};
use tracing::debug;

pub mod files;
pub mod ipfs_gateway;
pub mod ipfs_walker;

pub use meta_feeder_sdk::transport::ApiError;
pub mod range {
    pub use meta_feeder_sdk::transport::range::*;
}

/// What the IPFS tier reaches for — the subset of meta-share's `AppState` it
/// used, under the same field names.
pub struct AppState {
    pub block_store: Arc<crate::filestore::SharedBlockstore>,
    pub ingress: Arc<crate::ingress::IngressRegistry>,
    pub swarm_tx: mpsc::Sender<crate::swarm::Command>,
    pub peer_directory: crate::swarm::PeerDirectory,
    /// The playback focus the hull pushes.
    pub focus: Arc<FocusView>,
    pub http: reqwest::Client,
    /// Callbacks into the hull (seed rows, promoted containers, display names).
    pub hull: HullClient,
    pub data_dir: PathBuf,
    /// For reading library bytes (refs into meta-core files) — byte reads only.
    pub meta_core_url: Option<String>,
    pub webdav_url_cache: Arc<OnceCell<String>>,
    /// Announce seeded cids on the public DHT (`META_SHARE_SEED_DHT_PROVIDE`,
    /// default = public mode). Decided here, where `PUBLIC_ADDR` is known; the
    /// hull always asks and this gates.
    pub seed_dht_provide: bool,
}

/// "This peer now seeds `cid`" — the hull writes the seed row (and decides on
/// the DHT announce). Every seed this plugin reports on its own is cache-origin;
/// library seeds are recorded by the hull, which drives them.
pub async fn record_ipfs_seed(state: &AppState, cid: &str, name: &str, size: u64, container: Option<&str>) {
    let ev = Event::Seed {
        cid: cid.to_string(),
        kind: "ipfs".into(),
        name: name.to_string(),
        size_bytes: size,
        container: container.map(str::to_string),
    };
    if let Err(e) = state.hull.emit(&ev).await {
        debug!(cid, error = %e, "seed notification not delivered");
    }
}
