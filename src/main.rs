//! `meta-transport-ipfs` — meta-share's IPFS tier as a transport plugin.
//!
//! Owns the libp2p host (`P2P_LISTEN`, default `/ip4/0.0.0.0/tcp/4001`, the
//! port meta-share always published): identify + kad + mdns + bitswap, the
//! blockstore (`<data>/ipfs/blocks.redb`) and bitswap ingress into `tmp/` →
//! `cache/`. Serves the transport contract on `HTTP_LISTEN` (internal only) and
//! the public `/ipfs/:cid` gateway, which the hull relays.
//!
//! The swarm announces the **hull's** URL in identify (`baseUrl=`, from the
//! hull's `settings.json`), so peers and gateways keep calling meta-share's
//! public API exactly as before — the plugin is invisible on the wire.

mod api;
mod blockstore;
mod config;
mod filestore;
mod gateway_discovery;
mod ingress;
mod ingress_commit;
mod ipfs_chunk;
mod material;
mod plugin;
mod settings;
mod share;
mod store;
mod swarm;
mod webdav;

/// Path alias so the moved code keeps its `crate::focus::Lane` imports.
mod focus {
    pub use meta_feeder_sdk::transport::focus::Lane;
}

use std::sync::Arc;

use anyhow::{Context, Result};
use libp2p::identity;
use meta_feeder_sdk::transport::{serve_transport, FocusView, HullClient};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("info,meta_transport_ipfs=info,libp2p=warn,beetswap=warn,yamux=warn")
    });
    tracing_subscriber::fmt().with_env_filter(filter).with_target(false).init();

    let cfg = config::Config::from_env()?;
    let keypair = identity::Keypair::generate_ed25519();
    let local_peer_id = libp2p::PeerId::from(keypair.public());
    let agent_version = swarm::build_agent_version(cfg.peer_api_url.as_deref());
    let peer_directory = swarm::PeerDirectory::new();

    info!(
        %local_peer_id,
        listen_p2p = %cfg.listen_p2p,
        http_addr = %cfg.http_addr,
        network_mode = cfg.network.mode.as_str(),
        public_addr = cfg.network.mode.public_addr().map(|a| a.to_string()).unwrap_or_default(),
        kad_provide_enabled = cfg.kad.provide_enabled,
        seed_dht_provide = cfg.seed_dht_provide,
        agent_version = %agent_version,
        "starting meta-transport-ipfs"
    );

    let raw_block_store = blockstore::open_redb_blockstore(&cfg.data_dir)
        .await
        .context("open ipfs blockstore")?;
    let http = reqwest::Client::builder()
        .user_agent(concat!("meta-transport-ipfs/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("build shared reqwest client")?;
    let webdav_url_cache = Arc::new(tokio::sync::OnceCell::new());
    let redb_handle = raw_block_store.raw_db();
    let ingress = Arc::new(ingress::IngressRegistry::from_data_dir(&cfg.data_dir));
    let (_, cache_dir) = material::storage_dirs(&cfg.data_dir);

    let filestore_resolver = Arc::new(filestore::FilestoreResolver::new(
        http.clone(),
        cfg.meta_core_url.clone(),
        cfg.files_path_prefix.clone(),
        cfg.local_files_root.clone(),
        Arc::clone(&webdav_url_cache),
        cache_dir,
    ));
    // Drop the MSR1 record blocks earlier builds mirrored into the block table,
    // once, before the swarm can answer a WANT from a table mid-sweep.
    match filestore::scrub_record_blocks(Arc::clone(&redb_handle)).await {
        Ok(0) => debug!("record-block scrub: nothing to remove"),
        Ok(removed) => info!(removed, "record-block scrub: removed MSR1 record blocks from the blockstore"),
        Err(e) => warn!(error = %format!("{e:#}"), "record-block scrub failed; continuing"),
    }
    let block_store = Arc::new(filestore::FilestoreBlockstore::new(
        raw_block_store,
        redb_handle,
        filestore_resolver,
        Arc::clone(&ingress),
    ));

    let focus = FocusView::new();
    let (mut swarm, _peer_id) = swarm::build_swarm(
        keypair,
        &cfg.listen_p2p,
        cfg.enable_mdns,
        agent_version,
        Arc::clone(&block_store),
        Arc::clone(&focus),
        Arc::clone(&ingress),
    )
    .context("build swarm")?;
    if let Some(addr) = cfg.network.mode.public_addr() {
        info!(external_addr = %addr, "advertising external libp2p multiaddr");
        swarm.add_external_address(addr.clone());
    }
    let swarm_tx = swarm::spawn(
        swarm,
        local_peer_id,
        cfg.bootstrap_peers,
        cfg.redial_interval,
        cfg.kad,
        peer_directory.clone(),
        http.clone(),
        cfg.gateway_caps,
    );

    let state = Arc::new(api::AppState {
        block_store,
        ingress,
        swarm_tx,
        peer_directory,
        focus,
        http: http.clone(),
        hull: HullClient::from_env(http),
        data_dir: cfg.data_dir.clone(),
        meta_core_url: cfg.meta_core_url.clone(),
        webdav_url_cache,
        seed_dht_provide: cfg.seed_dht_provide,
    });

    // Bitswap ingress: sweep partial fetches a previous process left in `tmp/`,
    // then promote/fill on a timer.
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            state.ingress.sweep_tmp().await;
        });
    }
    ingress_commit::spawn(Arc::clone(&state));

    serve_transport(Arc::new(plugin::IpfsPlugin { state }), cfg.http_addr).await
}
