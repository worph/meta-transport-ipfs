//! libp2p swarm — composite `NetworkBehaviour`, command channel, and the
//! tokio task that drives them.
//!
//! The Swarm itself is `!Send` once it owns the libp2p connection state, so
//! we follow the standard pattern: the Swarm is owned by a single tokio task
//! that loops over events and a command receiver. The HTTP layer talks to
//! the swarm by sending [`Command`] messages and awaiting oneshot replies.
//!
//! The behaviour is a `NetworkBehaviour`-derive composite of:
//! - `identify` — exchanges listen addresses on connection. Load-bearing for
//!   bitswap reachability: without it the listener side of a connection only
//!   sees the dialer's ephemeral source port, so peers can't be re-dialed for
//!   block transfer.
//! - `kad` — Kademlia DHT in `Mode::Client` against the public IPFS DHT.
//!   Two responsibilities: peer discovery via namespace-key provider records,
//!   and cid → peer lookup for the metadata fetch path. See ADR 0001
//!   §"Operational discovery in v0.2".
//! - `mdns` — local-network discovery (`Toggle`'d so it can be cheaply
//!   disabled when the network blocks multicast).
//!
//! Submodule layout:
//! - [`peer_directory`] — `peer_id → PeerInfo` shared with the HTTP layer.
//! - [`identify_agent`] — the `agent_version` overload (baseUrl).
//! - [`kad_discovery`] — kad config, namespace-key, DHT helpers.
//! - [`bootstrap`] — the auto-redial machine for operator-configured
//!   multiaddrs (distinct from kad — see the module doc).
//! - [`event_loop`] — the `SwarmTask` struct + per-arm handler methods.

use std::time::Duration;

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use libp2p::connection_limits::{self, ConnectionLimits};
use libp2p::kad::{self, store::MemoryStore};
use libp2p::mdns::tokio::Behaviour as MdnsBehaviour;
use libp2p::mdns::Config as MdnsConfig;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{identify, identity, Multiaddr, PeerId, StreamProtocol, Swarm};
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use crate::blockstore::{GatedBlockstore, IngressRouter, MAX_MULTIHASH_SIZE};
use crate::filestore::SharedBlockstore;

/// Concrete bitswap behaviour alias — fixes the const generic so the
/// `#[derive(NetworkBehaviour)]` macro on `Behaviour` doesn't need to
/// carry generic params of its own. `MAX_MULTIHASH_SIZE = 64` matches
/// the gateway side; both peers must agree because the const flows
/// through bitswap's wire-format multihash truncation.
///
/// The store is three layers, outermost first:
///
/// 1. [`IngressRouter`](crate::blockstore::IngressRouter) — decides where an
///    *arriving* block goes: into the file an in-flight fetch is materialising,
///    or (for small unattributed objects) the block table. Phase 4.
/// 2. [`GatedBlockstore`](crate::blockstore::GatedBlockstore) — meters blocks
///    *leaving* over bitswap, the only place outbound bitswap bytes can be
///    throttled while this peer's own viewer is watching something.
/// 3. [`SharedBlockstore`](crate::filestore::SharedBlockstore) — the nocopy
///    filestore, which resolves a leaf ref (or an in-flight leaf) to real bytes.
///
/// The order is load-bearing: routing must happen before the gate (a write is
/// not egress and must not be metered as one), and the gate must wrap the
/// filestore so a ref-resolved or in-flight leaf served to a stranger is
/// throttled like any other block. See `crate::ingress`, `crate::filestore`,
/// `crate::focus`.
pub type Bitswap =
    beetswap::Behaviour<MAX_MULTIHASH_SIZE, IngressRouter<GatedBlockstore<SharedBlockstore>>>;

/// Custom `Multihasher` for the meta-hash `midhash256` codec (0x1000).
/// Without this, beetswap rejects BLOCK responses keyed by midhash
/// with `Unknown multihash code: 4096` and the WANT silently times
/// out. The arithmetic is the same as `crate::hash::compute_midhash256`
/// but applied to the verbatim block bytes — beetswap doesn't care
/// what the bytes are, only that the multihash round-trips.
///
/// **Important caveat**: beetswap hashes whatever bytes it received
/// from the wire. For midhash, the CID's digest is computed over
/// `[size:u64-be][middle-1MiB slice]`, **not** the raw record bytes.
/// So calling `Sha256(record_bytes)` here would not match the
/// midhash digest we keyed the block by. To make midhash blocks
/// bitswap-verifiable we'd need beetswap to hash a transformed
/// input — which beetswap's `Multihasher` trait does not expose.
///
/// In practice this isn't a problem today because every meta-core
/// record carries a sha-family CID alongside its midhash (the
/// `fullhash` plugin runs unconditionally) and
/// `canonical_cid_from_metadata` ranks sha-family above midhash. So
/// the canonical CID Kamilata announces is sha-family, and bitswap
/// only ever needs sha2/sha3 verification — which the
/// `multihash-codetable` features unlock cleanly.
///
/// The midhash multihasher below exists for completeness (so the
/// codec is *registered* and beetswap's error mode is "verify
/// mismatch", a deliberate signal that the design needs revisiting,
/// rather than "unknown code", which looks like a missing dependency).
/// If a record ever ends up with midhash as its canonical CID, the
/// resulting bitswap fetch will fail with a verify mismatch and the
/// `/api/file/{cid}` handler will return 404 — same observable
/// behavior as if midhash had been rejected up-front, just clearer
/// in the logs.
struct MidhashMultihasher;

impl beetswap::multihasher::Multihasher<MAX_MULTIHASH_SIZE> for MidhashMultihasher {
    async fn hash(
        &self,
        multihash_code: u64,
        input: &[u8],
    ) -> Result<libp2p::multihash::Multihash<MAX_MULTIHASH_SIZE>, beetswap::multihasher::MultihasherError> {
        // 0x1000 = the meta-hash midhash256 codec (see hash.rs).
        if multihash_code != 0x1000 {
            return Err(beetswap::multihasher::MultihasherError::UnknownMultihashCode);
        }
        use sha2::{Digest, Sha256};
        let digest: [u8; 32] = Sha256::digest(input).into();
        // CIDv1 multihash field is `[code varint][len][digest]`; the
        // Multihash<S> type holds just `(code, len, digest_bytes)`.
        libp2p::multihash::Multihash::<MAX_MULTIHASH_SIZE>::wrap(0x1000, &digest)
            .map_err(|_| beetswap::multihasher::MultihasherError::InvalidMultihashSize)
    }
}

mod bitswap_client;
mod bootstrap;
mod event_loop;
mod identify_agent;
mod kad_discovery;
mod peer_directory;
mod provide_queue;

pub use bitswap_client::bitswap_get_block;
pub use identify_agent::build_agent_version;
pub use kad_discovery::{is_dialable_addr, KadConfig, DEFAULT_KAD_BOOTSTRAPS};
pub use peer_directory::PeerDirectory;

use identify_agent::IDENTIFY_PROTOCOL;
use kad_discovery::IPFS_KAD_PROTOCOL;

/// Composite behaviour: identify for address exchange, kad for namespace-key
/// based peer discovery on the public IPFS DHT, mdns for local-network
/// discovery (`Toggle`'d so it can be cheaply disabled when the network
/// blocks multicast), and bitswap for IPFS block transfer. meta-share is
/// wire-level pure content transport — the kamilata federated-search routing
/// primitive was removed, so there is no search/gateway/gossipsub behaviour.
#[derive(NetworkBehaviour)]
pub struct Behaviour {
    pub identify: identify::Behaviour,
    pub kad: kad::Behaviour<MemoryStore>,
    pub mdns: Toggle<MdnsBehaviour>,
    /// Protocol-level connection ceiling. A pure guard behaviour (it emits no
    /// events — the derived `BehaviourEvent::Conns` variant is uninhabited and
    /// falls through the `_ => {}` arm in `event_loop::default_log`): it vetoes
    /// new connections once the swarm is at capacity, so process RSS — which
    /// scales with noise + yamux + per-substream buffers per connection —
    /// stays bounded without capping meta-share's HTTP / ingest / seeding work.
    /// Limits from [`connection_limits_config`] (`META_SHARE_MAX_CONNS`).
    pub conns: connection_limits::Behaviour,
    /// M12: IPFS bitswap. Client-side use case: the M13
    /// `/ipfs/{cid}` HTTP endpoint sends a `BitswapGet` command to
    /// the swarm task, which calls `bitswap.get(cid)`; bitswap
    /// negotiates with connected peers (gateway or other consumers
    /// that already cached the cid) and surfaces the bytes via
    /// `Event::GetQueryResponse`. The shared
    /// `Arc<RedbBlockstore>` also makes us a candidate provider for
    /// every cid we've fetched once — multi-source pulls emerge.
    pub bitswap: Bitswap,
}

/// Messages from the HTTP layer to the swarm task. Each variant carries a
/// oneshot reply channel so the caller can `await` the result.
pub enum Command {
    /// Returns the connected peer count and our own peer-id.
    Peers {
        reply: oneshot::Sender<PeersInfo>,
    },
    /// M12: fetch a single block via bitswap. The swarm task calls
    /// `bitswap.get(&cid)`, registers the resulting `QueryId` with
    /// `BitswapInflight`, and fires `reply` on `Event::GetQueryResponse`
    /// / `GetQueryError`. The HTTP layer wraps this with a timeout
    /// (per-block deadline) in [`bitswap_get_block`].
    BitswapGet {
        cid: crate::blockstore::MsCid,
        reply: oneshot::Sender<Result<Vec<u8>, BitswapGetError>>,
    },
    /// Announce that this peer provides `cid` on the public IPFS DHT
    /// (`kad.start_providing`, keyed by the CID's multihash so external
    /// IPFS nodes resolve it). Fire-and-forget — no reply; the outcome is
    /// logged by the `StartProviding` arm in `default_log`. Sent from the
    /// seed-manifest upsert path when `seed_dht_provide` is on.
    Provide {
        cid: crate::blockstore::MsCid,
    },
    /// Stop announcing `cid` (`kad.stop_providing`). Fire-and-forget. Sent
    /// from the DELETE /api/seeds/:cid teardown for an IPFS seed.
    StopProviding {
        cid: crate::blockstore::MsCid,
    },
}

/// Failure modes for the consumer-side `BitswapGet` round-trip.
#[derive(Debug, thiserror::Error)]
pub enum BitswapGetError {
    /// beetswap's `GetQueryError`. Wraps the original error string —
    /// the typed enum lives in beetswap and isn't worth re-exporting.
    #[error("bitswap query error: {0}")]
    QueryFailed(String),
    /// The swarm task dropped the reply channel (process shutting
    /// down).
    #[error("swarm reply channel closed")]
    ReplyChannelClosed,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PeersInfo {
    pub local_peer_id: String,
    pub connected: Vec<String>,
}

/// Default ceiling on total established connections. Each libp2p connection
/// carries a noise session + yamux state + per-substream buffers, so process
/// RSS grows with the connection count. 128 is generous for a transport /
/// seeding node (bootstraps + content peers) while bounding that growth.
/// Override with `META_SHARE_MAX_CONNS`.
const DEFAULT_MAX_ESTABLISHED_CONNS: u32 = 128;

/// Build the [`ConnectionLimits`] for the `connection_limits` guard behaviour.
///
/// - `max_established` (total, across all peers) is the primary RSS lever,
///   env-tunable via `META_SHARE_MAX_CONNS`.
/// - per-peer is capped at 3: enough for TCP + QUIC to the same peer plus one
///   in-flight address migration, but no runaway fan-out from a single peer.
/// - pending-incoming is capped so half-open inbound handshakes (each holding
///   a noise buffer) can't pile up.
fn connection_limits_config() -> ConnectionLimits {
    let max_established = std::env::var("META_SHARE_MAX_CONNS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_ESTABLISHED_CONNS);
    ConnectionLimits::default()
        .with_max_established(Some(max_established))
        .with_max_established_per_peer(Some(3))
        .with_max_pending_incoming(Some(32))
}

/// Build the libp2p Swarm — TCP + QUIC + DNS, noise auth, yamux mux,
/// identify + kad + mdns + bitswap.
///
/// QUIC was added in v0.2 because the public IPFS DHT bootstraps that kad
/// rides advertise `/quic-v1` and `/wss` multiaddrs (no plain `/tcp` after
/// dnsaddr resolution). Without QUIC the kad layer can't reach the public
/// bootstraps.
///
/// `enable_mdns` controls whether multicast-DNS local discovery is started.
/// Default `true` — purely additive, automatically finds peers on the same
/// LAN/docker network without any per-cohort bootstrap config. Set false
/// only on networks that actively block multicast (some VPNs, some
/// mDNS-isolating switches). When false, `Toggle::default()` makes the
/// behaviour an inert no-op.
///
/// `agent_version` becomes the identify-protocol `agent_version` string.
/// Build it via [`build_agent_version`] so other peers can parse our HTTP
/// API URL out of it for cross-peer file fetches.
pub fn build_swarm(
    keypair: identity::Keypair,
    listen_addr: &Multiaddr,
    enable_mdns: bool,
    agent_version: String,
    blockstore: Arc<SharedBlockstore>,
    focus: Arc<meta_feeder_sdk::transport::FocusView>,
    ingress: Arc<crate::ingress::IngressRegistry>,
) -> Result<(Swarm<Behaviour>, PeerId)> {
    let local_peer_id = PeerId::from(keypair.public());

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .context("tcp transport")?
        .with_quic()
        // .with_dns() wraps the transport so `/dns/host/tcp/port` and
        // `/dnsaddr/.../p2p/<id>` multiaddrs resolve via the system resolver
        // before dial. Without this, the raw transport sees a /dns/... or
        // /dnsaddr/... multiaddr as "unsupported" and fails — surfaced when
        // dialing docker DNS names AND when riding the public IPFS DHT
        // bootstraps.
        .with_dns()
        .context("dns transport")?
        .with_behaviour(|keypair| {
            let kad_store = MemoryStore::new(local_peer_id);
            let kad_config = kad::Config::new(StreamProtocol::new(IPFS_KAD_PROTOCOL));
            let mut kad_behaviour = kad::Behaviour::with_config(local_peer_id, kad_store, kad_config);
            // Mode::Client: we use the public DHT to publish/find provider
            // records but don't serve queries for unrelated IPFS traffic.
            // Keeps the bandwidth/CPU footprint small and avoids becoming a
            // routing node for the world. ADR §"Operational discovery in v0.2".
            kad_behaviour.set_mode(Some(kad::Mode::Client));
            let mdns_behaviour: Toggle<MdnsBehaviour> = if enable_mdns {
                match MdnsBehaviour::new(MdnsConfig::default(), local_peer_id) {
                    Ok(b) => Some(b).into(),
                    Err(e) => {
                        warn!(error = %e,
                            "mdns: failed to start (network may not support multicast); continuing without it");
                        None.into()
                    }
                }
            } else {
                None.into()
            };
            // M12: bitswap. The Behaviour is both client (`.get(cid)`
            // calls fan out WANT-HAVE to connected peers — gateways +
            // siblings) AND server (peers we serve `.put_keyed` blocks
            // to from the shared `RedbBlockstore`).
            //
            // The builder registers `MidhashMultihasher` on top of
            // beetswap's `StandardMultihasher`. `StandardMultihasher`
            // covers sha2 + sha3 (both unlocked by `multihash-codetable`
            // features in our Cargo.toml — required because beetswap
            // pulls multihash-codetable in with no features by default,
            // which would leave sha3-256 unrecognised and silently drop
            // every BLOCK response that uses it). `MidhashMultihasher`
            // is the meta-hash custom codec 0x1000.
            //
            // Without these registrations, every Kamilata-discovered
            // record fetch failed with "Unknown multihash code: N" on
            // the receive side (root-caused via beetswap=trace logs in
            // the 2026-05-25 ADR 0002 follow-up session).
            // Hand bitswap the *gated* view of the store — the throttle point for
            // blocks this peer serves to others while its own viewer is watching
            // something. `blockstore` itself (the raw handle) is untouched and
            // still backs every local read.
            let bitswap = beetswap::Behaviour::builder(Arc::new(IngressRouter::new(
                Arc::new(GatedBlockstore::new(
                    Arc::clone(&blockstore),
                    Arc::clone(&focus),
                )),
                Arc::clone(&ingress),
            )))
            .register_multihasher(MidhashMultihasher)
            .build();
            Behaviour {
                identify: identify::Behaviour::new(
                    identify::Config::new(IDENTIFY_PROTOCOL.to_string(), keypair.public())
                        .with_agent_version(agent_version.clone()),
                ),
                kad: kad_behaviour,
                mdns: mdns_behaviour,
                bitswap,
                conns: connection_limits::Behaviour::new(connection_limits_config()),
            }
        })
        .map_err(|e| anyhow!("behaviour stage: {e}"))?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();

    swarm
        .listen_on(listen_addr.clone())
        .with_context(|| format!("listen on {listen_addr}"))?;

    Ok((swarm, local_peer_id))
}

/// Spawn the swarm event-loop task. Returns the command sender the HTTP
/// layer uses to talk to the swarm.
///
/// `bootstrap_peers` are dialed once on startup, then re-dialed every
/// `redial_interval` for any entry whose target peer is not currently
/// connected. Pass an empty list (or zero interval) to disable auto-redial.
///
/// `kad_config` configures the libp2p-kad-based peer discovery loop: kad
/// bootstrap addresses are added to the routing table, an initial bootstrap
/// query is issued, and the namespace key is periodically (re)provided and
/// looked up. Discovered providers are dialed; identify finishes the
/// connection handshake.
///
/// `http` is the process-wide client, cloned into the task for the gateway
/// capability fetch (`GET {baseUrl}/api/gateway/plugins`) that runs off an
/// identify from a meta-gateway peer. That fetch is plain HTTP by design — it
/// adds no libp2p behaviour to the transport-only swarm.
#[allow(clippy::too_many_arguments)]
pub fn spawn(
    swarm: Swarm<Behaviour>,
    local_peer_id: PeerId,
    bootstrap_peers: Vec<Multiaddr>,
    redial_interval: Duration,
    kad_config: KadConfig,
    peer_directory: PeerDirectory,
    http: reqwest::Client,
    gateway_caps: GatewayCapsConfig,
) -> mpsc::Sender<Command> {
    let (tx, rx) = mpsc::channel::<Command>(64);

    let task = event_loop::SwarmTask::new(
        local_peer_id,
        bootstrap_peers,
        redial_interval,
        kad_config,
        peer_directory,
        http,
        gateway_caps,
    );

    tokio::spawn(task.run(swarm, rx));
    tx
}

/// Knobs for the gateway capability fetch triggered off identify.
#[derive(Clone, Copy, Debug)]
pub struct GatewayCapsConfig {
    /// Per-request timeout for `GET {baseUrl}/api/gateway/plugins`.
    pub fetch_timeout: Duration,
    /// Don't re-fetch a peer's capabilities more often than this. Sized to
    /// identify's ~5-minute re-announce cadence, so a connected gateway is
    /// re-stamped roughly once per identify and stays inside the directory's
    /// 600s freshness TTL without any extra timer.
    pub refresh_after: Duration,
}
