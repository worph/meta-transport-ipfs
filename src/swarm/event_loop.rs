//! The swarm task — owns the libp2p `Swarm`, the HTTP command channel,
//! and the kad-DHT/bootstrap/peer-directory state, and drives them all
//! from one `tokio::select!` loop.
//!
//! Refactored from the previous monolithic `swarm::spawn` closure into a
//! `SwarmTask` struct with per-arm handler methods. The select! itself
//! stays in [`SwarmTask::run`] because tokio's macro needs all arm futures
//! to be constructed in one scope — `swarm` and `rx` are passed in as
//! locals (not held on `self`) so each handler method can borrow
//! `&mut self` cleanly without conflicting with the arm futures.

use std::collections::HashMap;
use std::time::Duration;

use futures::StreamExt;
use libp2p::core::ConnectedPoint;
use libp2p::kad::{self, GetProvidersOk, QueryResult, RecordKey};
use libp2p::mdns;
use libp2p::swarm::SwarmEvent;
use libp2p::{identify, Multiaddr, PeerId, Swarm};
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

use crate::gateway_discovery::{advertises_gateways, fetch_gateway_caps};

use super::bootstrap::{addr_targets_match, redial_bootstrap, BootstrapEntry};
use super::bitswap_client::BitswapInflight;
use super::identify_agent::parse_base_url;
use super::kad_discovery::{is_dialable_addr, namespace_key, peer_id_from_multiaddr, KadConfig};
use super::peer_directory::PeerDirectory;
use super::provide_queue::{ProvideQueue, DEFAULT_PROVIDE_CONCURRENCY};
use super::{Behaviour, BehaviourEvent, Command, GatewayCapsConfig, PeersInfo};

/// How often [`SwarmTask::on_gateway_keepalive_tick`] re-dials dropped
/// gateways and re-stamps live ones. Half meta-search's 60 s: an NZB play is
/// blocked for as long as the gateway is missing (no one else can redeem).
const GATEWAY_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// A gateway we've identified and now pin for keep-alive: its API base URL (for
/// the periodic caps refresh that keeps it routable) plus dialable addresses
/// (for re-pinning the connection if it drops). Persists across TTL expiry and
/// disconnect — unlike the read-side directory entry, which `forget_peer` drops
/// on the last close — so a gateway is never permanently forgotten once seen.
///
/// Ported from meta-search. Without it a gateway that restarts under the same
/// peer id is lost for good: its mDNS record never expires, so `Discovered`
/// never fires again, and the gateway itself never dials consumers
/// (watch.nsl.sh 2026-10-04: every NZB answered "no gateway can redeem it"
/// until this container was restarted).
#[derive(Clone, Debug, PartialEq)]
struct GatewayPin {
    base_url: Option<String>,
    addrs: Vec<Multiaddr>,
}

/// The pin an identify from a gateway yields, or `None` for any other peer.
/// Only dialable addresses are kept: a pin is retried for the life of the
/// process, so a loopback / unspecified listener would be a permanent cost.
fn gateway_pin(agent_version: &str, listen_addrs: &[Multiaddr], base_url: Option<String>) -> Option<GatewayPin> {
    if !advertises_gateways(agent_version) {
        return None;
    }
    Some(GatewayPin {
        base_url,
        addrs: listen_addrs.iter().filter(|a| is_dialable_addr(a)).cloned().collect(),
    })
}

/// All the state that lives across iterations of the event loop. `swarm`
/// and the channel receivers stay as locals in [`SwarmTask::run`] so the
/// `tokio::select!` arms can borrow them without conflicting with
/// `&mut self` calls in the arm bodies.
pub(super) struct SwarmTask {
    local_peer_id: PeerId,
    /// Bootstrap targets we keep alive across reconnects.
    bootstrap: Vec<BootstrapEntry>,
    /// Shared peer→info directory (populated from identify events).
    peer_directory: PeerDirectory,
    /// kad-DHT discovery state.
    kad_namespace: String,
    ns_key: RecordKey,
    kad_target_peer_count: usize,
    kad_fast_discovery_interval: Duration,
    kad_discovery_interval: Duration,
    kad_provide_interval: Duration,
    /// Whether to publish the namespace provider record at all — see
    /// [`KadConfig::provide_enabled`]. False when this peer isn't publicly
    /// reachable.
    kad_provide_enabled: bool,
    kad_bootstrap_peers: Vec<Multiaddr>,
    /// Rate-limit floor for reactive kad kicks on `ConnectionClosed`.
    last_kad_query_at: tokio::time::Instant,
    /// Auto-redial cadence; zero / empty bootstrap effectively disables.
    redial_interval: Duration,
    /// In-flight `bitswap.get(cid)` calls awaiting block delivery.
    /// Populated by `Command::BitswapGet`, drained by the
    /// `BehaviourEvent::Bitswap` arm of `on_swarm_event`.
    bitswap_inflight: BitswapInflight,
    /// Process-wide HTTP client, for the gateway capability fetch off identify.
    http: reqwest::Client,
    /// Timeout + debounce for that fetch.
    gateway_caps: GatewayCapsConfig,
    /// Gateways kept connected + routable by the keep-alive tick. See
    /// [`GatewayPin`].
    pinned_gateways: HashMap<PeerId, GatewayPin>,
    /// Per-CID announcements waiting for a walk slot. See [`ProvideQueue`].
    provides: ProvideQueue,
}

impl SwarmTask {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        local_peer_id: PeerId,
        bootstrap_peers: Vec<Multiaddr>,
        redial_interval: Duration,
        kad_config: KadConfig,
        peer_directory: PeerDirectory,
        http: reqwest::Client,
        gateway_caps: GatewayCapsConfig,
    ) -> Self {
        let bootstrap: Vec<BootstrapEntry> =
            bootstrap_peers.into_iter().map(BootstrapEntry::new).collect();
        let ns_key = namespace_key(&kad_config.namespace);
        // Initialise far enough in the past that the very first reactive kick
        // can fire (subject to the fast-discovery rate-limit floor).
        let last_kad_query_at = tokio::time::Instant::now()
            .checked_sub(kad_config.fast_discovery_interval)
            .unwrap_or_else(tokio::time::Instant::now);
        Self {
            local_peer_id,
            bootstrap,
            peer_directory,
            kad_namespace: kad_config.namespace,
            ns_key,
            kad_target_peer_count: kad_config.target_peer_count,
            kad_fast_discovery_interval: kad_config.fast_discovery_interval,
            kad_discovery_interval: kad_config.discovery_interval,
            kad_provide_interval: kad_config.provide_interval,
            kad_provide_enabled: kad_config.provide_enabled,
            kad_bootstrap_peers: kad_config.bootstrap_peers,
            last_kad_query_at,
            redial_interval,
            bitswap_inflight: BitswapInflight::new(),
            http,
            gateway_caps,
            pinned_gateways: HashMap::new(),
            provides: ProvideQueue::new(
                std::env::var("META_SHARE_PROVIDE_CONCURRENCY")
                    .ok()
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(DEFAULT_PROVIDE_CONCURRENCY),
            ),
        }
    }

    /// Drive the swarm task to completion. Owns `swarm` and the channel
    /// receivers as locals — the `tokio::select!` arms borrow these
    /// directly, and the arm bodies are free to call `&mut self` methods
    /// because the arm futures have completed (and their borrows
    /// released) by the time a body runs.
    pub(super) async fn run(
        mut self,
        mut swarm: Swarm<Behaviour>,
        mut rx: mpsc::Receiver<Command>,
    ) {
        // Initial bootstrap dials.
        for entry in &self.bootstrap {
            match swarm.dial(entry.addr.clone()) {
                Ok(()) => info!(addr = %entry.addr, "bootstrap dial issued"),
                Err(e) => warn!(addr = %entry.addr, error = %e, "bootstrap dial failed"),
            }
        }

        // Seed kad's routing table with the configured bootstrap multiaddrs.
        // Each entry must include `/p2p/<peer_id>` so we can register the
        // peer-id without an extra round-trip; entries without are skipped
        // with a warning (the kad routing table is keyed by peer-id).
        let mut kad_seeded = 0usize;
        for addr in &self.kad_bootstrap_peers {
            match peer_id_from_multiaddr(addr) {
                Some(pid) => {
                    swarm.behaviour_mut().kad.add_address(&pid, addr.clone());
                    kad_seeded += 1;
                    debug!(%pid, %addr, "kad: bootstrap address registered");
                }
                None => warn!(%addr, "kad: bootstrap multiaddr lacks /p2p/<id>; skipped"),
            }
        }
        if kad_seeded > 0 {
            match swarm.behaviour_mut().kad.bootstrap() {
                Ok(qid) => info!(?qid, kad_seeded, "kad: bootstrap query issued"),
                Err(e) => warn!(error = %e, "kad: bootstrap query failed"),
            }
        } else {
            // Not a fault — it's the local-mode default. An empty bootstrap list
            // is exactly what keeps an unreachable peer off the public DHT, so
            // saying it at WARN would train operators to ignore a real warning.
            info!(
                "kad: no bootstrap peers configured; public-DHT discovery is off \
                 (local mode — mDNS still works). Set PUBLIC_ADDR to join the public DHT."
            );
        }
        info!(namespace = %self.kad_namespace, "kad: discovery namespace");

        // Auto-redial ticker. `redial_interval == 0` disables; we still need a
        // ticker (`tokio::select!` requires all branches to compile) so use a
        // very long interval that effectively never fires.
        let effective_interval = if self.redial_interval.is_zero() || self.bootstrap.is_empty() {
            Duration::from_secs(60 * 60 * 24 * 365) // 1y; effectively never
        } else {
            self.redial_interval
        };
        let mut redial_tick = tokio::time::interval(effective_interval);
        // Skip the immediate first tick — we just did the initial dials above.
        redial_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        redial_tick.tick().await;

        // kad provide ticker — fires immediately so we publish on startup,
        // then every kad_provide_interval. Provider records on remote peers
        // expire (~24 h default), so this must be lower than that.
        let mut kad_provide_tick = tokio::time::interval(self.kad_provide_interval);
        kad_provide_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // kad discovery ticker — same pattern, fires immediately.
        let mut kad_discovery_tick = tokio::time::interval(self.kad_discovery_interval);
        kad_discovery_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // Keep known gateways connected + routable (re-dial dropped ones,
        // re-fetch caps on live ones). See [`GatewayPin`].
        let mut gateway_keepalive_tick = tokio::time::interval(GATEWAY_KEEPALIVE_INTERVAL);
        gateway_keepalive_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                cmd = rx.recv() => match cmd {
                    Some(cmd) => self.on_command(&mut swarm, cmd).await,
                    None => {
                        debug!("command channel closed; shutting down swarm task");
                        break;
                    }
                },
                _ = redial_tick.tick() => {
                    redial_bootstrap(&mut swarm, &self.bootstrap);
                },
                _ = kad_provide_tick.tick() => {
                    // A provider record is a promise that this peer can be
                    // dialed. In local mode it can't be (no public address,
                    // only container-internal listeners), so publishing one
                    // would send every peer that walks the DHT into a dial
                    // that can never connect. Stay quiet.
                    if self.kad_provide_enabled {
                        match swarm.behaviour_mut().kad.start_providing(self.ns_key.clone()) {
                            Ok(qid) => debug!(?qid, namespace = %self.kad_namespace,
                                "kad: re-publishing provider record"),
                            Err(e) => warn!(error = %e, namespace = %self.kad_namespace,
                                "kad: start_providing failed"),
                        }
                    }
                },
                _ = kad_discovery_tick.tick() => {
                    self.on_kad_discovery_tick(&mut swarm, &mut kad_discovery_tick);
                },
                _ = gateway_keepalive_tick.tick() => {
                    self.on_gateway_keepalive_tick(&mut swarm);
                },
                event = swarm.select_next_some() => {
                    self.on_swarm_event(&mut swarm, event, &mut kad_discovery_tick).await;
                }
            }
        }
    }

    /// Handle a single HTTP-layer command.
    async fn on_command(&mut self, swarm: &mut Swarm<Behaviour>, cmd: Command) {
        match cmd {
            Command::Peers { reply } => {
                let connected: Vec<String> =
                    swarm.connected_peers().map(|p| p.to_string()).collect();
                let info = PeersInfo {
                    local_peer_id: self.local_peer_id.to_string(),
                    connected,
                };
                let _ = reply.send(info);
            }
            Command::BitswapGet { cid, reply } => {
                // M12: issue a bitswap fetch for one block. The
                // behaviour fans WANT-HAVE / WANT-BLOCK to connected
                // peers (gateways + sibling consumers that already
                // cached the cid). `bitswap.get` returns a QueryId;
                // we register it with the inflight map and the
                // `BehaviourEvent::Bitswap` arm fires the reply when
                // either `GetQueryResponse` (success) or
                // `GetQueryError` (transport / no-providers /
                // timeout) arrives.
                let query_id = swarm.behaviour_mut().bitswap.get(&cid);
                tracing::debug!(%cid, ?query_id, "bitswap: issued .get()");
                self.bitswap_inflight.register(query_id, reply);
            }
            Command::Provide { cid } => {
                // Announce on the public IPFS DHT, keyed by the CID's
                // multihash bytes — that's the kubo-compatible provider key,
                // so a vanilla IPFS node `get_providers`ing the same content
                // finds us. Queued, not fired: each announce is a DHT walk, and
                // a burst of seeds must not become a burst of walks (see
                // `provide_queue`). The StartProviding result is logged in
                // `default_log`. Works in `Mode::Client`.
                let key = RecordKey::new(&cid.hash().to_bytes());
                if self.provides.enqueue(key) {
                    debug!(%cid, pending = self.provides.pending_len(),
                        "kad: queued seeded cid for announce");
                }
                self.pump_provides(swarm);
            }
            Command::StopProviding { cid } => {
                let key = RecordKey::new(&cid.hash().to_bytes());
                self.provides.cancel(&key);
                swarm.behaviour_mut().kad.stop_providing(&key);
                debug!(%cid, "kad: stopped providing seeded cid");
            }
        }
    }

    /// Start queued announcements while walk slots are free.
    fn pump_provides(&mut self, swarm: &mut Swarm<Behaviour>) {
        while let Some(key) = self.provides.next_to_start() {
            match swarm.behaviour_mut().kad.start_providing(key) {
                Ok(qid) => {
                    self.provides.started(qid);
                    debug!(?qid, in_flight = self.provides.in_flight_len(),
                        pending = self.provides.pending_len(), "kad: announcing seeded cid");
                }
                Err(e) => {
                    self.provides.failed_to_start();
                    warn!(error = %e, "kad: start_providing(cid) failed");
                }
            }
        }
    }

    /// Fired every `kad_discovery_interval` (steady-state) or
    /// `kad_fast_discovery_interval` (below floor). Issues a fresh
    /// `get_providers` query and adapts the next tick's cadence based on
    /// the current connection count.
    fn on_kad_discovery_tick(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        kad_discovery_tick: &mut tokio::time::Interval,
    ) {
        let connected = swarm.connected_peers().count();
        let qid = swarm.behaviour_mut().kad.get_providers(self.ns_key.clone());
        self.last_kad_query_at = tokio::time::Instant::now();
        // Adapt the next tick's cadence to whether we're below the
        // connection-floor. `reset_after` only affects the *next* tick —
        // current behaviour keeps the steady-state config-driven topup rate
        // when the swarm is full and accelerates discovery when it's not.
        let next = if connected < self.kad_target_peer_count {
            self.kad_fast_discovery_interval
        } else {
            self.kad_discovery_interval
        };
        debug!(
            ?qid, namespace = %self.kad_namespace,
            connected, target = self.kad_target_peer_count,
            next_tick_secs = next.as_secs(),
            "kad: querying for providers"
        );
        kad_discovery_tick.reset_after(next);
    }

    /// Top-level swarm-event dispatch. Each branch inspects `&event` and
    /// falls through to `default_log` at the end.
    /// Keep pinned gateways connected + routable (ported from meta-search):
    ///
    /// 1. **Connection drop** — re-dial a pinned gateway that isn't connected,
    ///    directly (not through the mDNS / kad-provider dial-gates), re-seeding
    ///    its addresses into kad first in case they were evicted. The redial
    ///    triggers identify, which restores its base URL and redeem claims.
    /// 2. **Directory staleness** — identify goes quiet on an idle connection,
    ///    so the 600 s gateway TTL can lapse on a live peer. Re-fetch caps
    ///    over HTTP to re-stamp it.
    fn on_gateway_keepalive_tick(&mut self, swarm: &mut Swarm<Behaviour>) {
        // Small, stable set — clone to sidestep the self/swarm borrow overlap.
        for (pid, pin) in self.pinned_gateways.clone() {
            if swarm.is_connected(&pid) {
                if self
                    .peer_directory
                    .needs_cap_refresh(&pid, self.gateway_caps.refresh_after)
                {
                    if let Some(base_url) = pin.base_url {
                        self.spawn_caps_fetch(pid, base_url);
                    }
                }
            } else if pin.addrs.is_empty() {
                // Every address it announced was undialable — most likely a
                // gateway without PUBLIC_ADDR seen only over a relay. A dial
                // would fail every tick for the life of the process.
                trace!(peer_id = %pid,
                    "gateway keep-alive: no dialable address for pinned gateway; skipping re-dial");
            } else {
                for addr in &pin.addrs {
                    swarm.behaviour_mut().kad.add_address(&pid, addr.clone());
                }
                match swarm.dial(pid) {
                    Ok(()) => debug!(peer_id = %pid,
                        "gateway keep-alive: re-dialing dropped gateway"),
                    Err(e) => debug!(peer_id = %pid, error = %e,
                        "gateway keep-alive: re-dial failed"),
                }
            }
        }
    }

    /// Fetch a gateway's capabilities over HTTP off its `base_url` and record
    /// them in the directory. Fire-and-forget: a slow/dead gateway must not
    /// stall the swarm loop; a failure keeps whatever was held (it ages out on
    /// its own TTL) and is retried on the next identify / keep-alive tick.
    fn spawn_caps_fetch(&self, pid: PeerId, base_url: String) {
        let http = self.http.clone();
        let dir = self.peer_directory.clone();
        let timeout = self.gateway_caps.fetch_timeout;
        tokio::spawn(async move {
            match fetch_gateway_caps(&http, &base_url, timeout).await {
                Ok(caps) => {
                    let redeems = caps.redeem_claims();
                    debug!(peer_id = %pid, base_url = %base_url,
                        nzb_fetch = caps.nzb_fetch,
                        redeem_claims = redeems.len(),
                        "gateway caps: fetched");
                    dir.record_gateway_caps(pid, caps.nzb_fetch, redeems);
                }
                Err(e) => debug!(peer_id = %pid, base_url = %base_url,
                    error = %e, "gateway caps: fetch failed"),
            }
        });
    }

    async fn on_swarm_event(
        &mut self,
        swarm: &mut Swarm<Behaviour>,
        event: SwarmEvent<BehaviourEvent>,
        kad_discovery_tick: &mut tokio::time::Interval,
    ) {
        // 0) Soft ceiling for inbound: when we're already at target,
        //    close inbound connections before they negotiate. Pre-handshake
        //    close — peer-id is not known yet, only the source address.
        //    Bootstrap dials and our own outgoing dials are unaffected
        //    (they go through the dial-gates in the mdns/kad branches
        //    below).
        if let SwarmEvent::IncomingConnection { connection_id, .. } = &event {
            let cid = *connection_id;
            let connected = swarm.connected_peers().count();
            if connected >= self.kad_target_peer_count {
                debug!(?cid, connected, target = self.kad_target_peer_count,
                    "rejecting inbound connection; at target");
                let _ = swarm.close_connection(cid);
            }
        }
        // 1) On every outgoing-dial connection, opportunistically populate
        //    bootstrap[].peer_id so future redial ticks can skip
        //    already-connected entries.
        if let SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } = &event {
            if let ConnectedPoint::Dialer { address, .. } = endpoint {
                // Always overwrite the cached peer-id on a fresh outgoing
                // dial, not just on first contact. Bootstrap targets that
                // lack a persistent peer-id (today: every meta-share peer
                // in the POC) rotate their identity on restart, and a
                // stale cached peer-id makes is_connected() return false
                // on the next tick — causing a redundant dial that
                // doubles the connection count.
                for entry in self.bootstrap.iter_mut() {
                    if addr_targets_match(&entry.addr, address)
                        && entry.peer_id != Some(*peer_id)
                    {
                        entry.peer_id = Some(*peer_id);
                        debug!(peer_id = %peer_id, addr = %entry.addr,
                            "auto-redial: bootstrap target peer-id learned/refreshed");
                    }
                }
            }
        }
        // 1b) On disconnect: if we drop below the connection floor, kick
        //     the kad discovery tick to fire immediately so a replacement
        //     peer is found quickly — but only if the last query was at
        //     least `fast_discovery_interval` ago, so a flapping peer
        //     can't trigger DHT queries faster than that floor.
        //     `reset_after(0)` makes the *next* tick fire now; if we're
        //     already mid-query the in-flight one continues.
        if let SwarmEvent::ConnectionClosed { peer_id, num_established, .. } = &event {
            // On the *last* connection to a peer closing, drop its gateway
            // state immediately — the fast complement to the read-side TTL
            // in PeerDirectory. A peer whose libp2p id rotates on restart
            // (the dev-stack norm) otherwise keeps advertising upstreams it
            // no longer serves, and the M7 fan-out burns a slot dialing the
            // dead id. `num_established` is the count remaining *after* this
            // close, so 0 means the peer is fully gone.
            if *num_established == 0 && self.peer_directory.forget_peer(peer_id) {
                debug!(peer_id = %peer_id, "peer fully disconnected — forgot gateway state");
            }
            let connected = swarm.connected_peers().count();
            if connected < self.kad_target_peer_count
                && self.last_kad_query_at.elapsed() >= self.kad_fast_discovery_interval
            {
                debug!(connected, target = self.kad_target_peer_count,
                    "kad: below connection floor — kicking discovery");
                kad_discovery_tick.reset_after(Duration::ZERO);
            }
        }
        // 2) When the identify protocol delivers a peer's listen
        //    addresses, feed them into kad's routing table and parse
        //    `baseUrl=` into the peer directory (the byte-fetch path
        //    resolves a peer's HTTP API URL from here).
        if let SwarmEvent::Behaviour(BehaviourEvent::Identify(
            identify::Event::Received { peer_id, info, .. }
        )) = &event {
            let pid = *peer_id;
            // Only what a remote peer could actually dial: a container behind
            // docker's bridge reports 0.0.0.0 / 127.0.0.1 listeners too, and
            // the keep-alive below would retry a pinned bad address forever.
            for addr in info.listen_addrs.iter().filter(|a| is_dialable_addr(a)) {
                swarm.behaviour_mut().kad.add_address(&pid, addr.clone());
            }
            let base_url = parse_base_url(&info.agent_version).map(str::to_string);
            let update = self.peer_directory.upsert_from_identify(pid, base_url);
            if let Some(url) = &update.base_url_changed {
                debug!(peer_id = %pid, base_url = %url,
                    "identify: learned/refreshed peer base URL");
            }
            // Pin every identified gateway for the keep-alive tick, refreshing
            // its addresses each time, so a dropped gateway gets re-dialed.
            if let Some(pin) = gateway_pin(
                &info.agent_version,
                &info.listen_addrs,
                self.peer_directory.base_url(&pid),
            ) {
                self.pinned_gateways.insert(pid, pin);
            }
            // Gateway discovery. A non-empty `gateways=` token is emitted by
            // meta-gateway and nobody else, so it's the "this peer is a
            // gateway" signal. Its *capabilities* aren't on the wire though —
            // libp2p 0.56 can't mutate agent_version after startup, so a
            // runtime plugin toggle would never reach us. We fetch them over
            // plain HTTP off the just-learned baseUrl instead (the reliable
            // source that replaced the flaky gossipsub heartbeat).
            //
            // Debounced by the directory so the identify burst on a
            // multi-connection peer doesn't fan out into redundant fetches.
            // The keep-alive tick re-stamps it when identify goes quiet.
            if advertises_gateways(&info.agent_version)
                && self
                    .peer_directory
                    .needs_cap_refresh(&pid, self.gateway_caps.refresh_after)
            {
                if let Some(base_url) = self.peer_directory.base_url(&pid) {
                    self.spawn_caps_fetch(pid, base_url);
                }
            }
        }
        // 2b) mDNS: register the address in kad's routing table (so
        //     subsequent lookups dedupe) and dial — unless at target.
        if let SwarmEvent::Behaviour(BehaviourEvent::Mdns(
            mdns::Event::Discovered(peers)
        )) = &event {
            for (pid, addr) in peers.iter() {
                if *pid == self.local_peer_id {
                    continue;
                }
                swarm.behaviour_mut().kad.add_address(pid, addr.clone());
                if swarm.is_connected(pid) {
                    trace!(peer_id = %pid, %addr, "mdns: peer already connected");
                    continue;
                }
                // LAN-local (mDNS) peers bypass the public-peer connection
                // ceiling and are always dialed — this is the local mesh (the
                // gateway + sibling peers) and it must never be starved by a
                // busy public DHT that has pushed `connected` past `target`.
                // mDNS is LAN-scoped, so the set stays small (no unbounded-dial
                // risk); remote/public peers still respect the ceiling below.
                match swarm.dial(*pid) {
                    Ok(()) => debug!(peer_id = %pid, %addr,
                        "mdns: dialing newly-discovered peer"),
                    Err(e) => debug!(peer_id = %pid, %addr, error = %e,
                        "mdns: dial failed"),
                }
            }
        }
        // 2c.5) Bitswap (M12) — fire the reply oneshot for an outbound
        //       `.get(cid)` when bitswap delivers the block or surfaces
        //       a query error. The same Behaviour also serves inbound
        //       WANT-HAVE/WANT-BLOCK from our local blockstore;
        //       those are intercepted by the Behaviour internally and
        //       never bubble up as `beetswap::Event` variants, so this
        //       arm only handles outbound results.
        if let SwarmEvent::Behaviour(BehaviourEvent::Bitswap(ev)) = &event {
            let fired = self.bitswap_inflight.on_event(ev);
            if fired {
                trace!("bitswap: inflight query resolved");
            }
        }
        // 2d) A queued announce finished (ok or timed out): free its slot and
        //     start the next. Only on the query's last step — until then the
        //     walk is still dialing.
        if let SwarmEvent::Behaviour(BehaviourEvent::Kad(
            kad::Event::OutboundQueryProgressed {
                id, result: QueryResult::StartProviding(_), step, ..
            }
        )) = &event {
            if step.last && self.provides.finished(*id) {
                self.pump_provides(swarm);
            }
        }
        // 3) kad providers — dial each new peer-id (subject to soft ceiling).
        if let SwarmEvent::Behaviour(BehaviourEvent::Kad(
            kad::Event::OutboundQueryProgressed {
                result: QueryResult::GetProviders(Ok(GetProvidersOk::FoundProviders {
                    providers, ..
                })),
                ..
            }
        )) = &event {
            for pid in providers.iter() {
                if *pid == self.local_peer_id {
                    continue; // ourselves
                }
                if swarm.is_connected(pid) {
                    trace!(peer_id = %pid, "kad: provider already connected");
                    continue;
                }
                let connected = swarm.connected_peers().count();
                if connected >= self.kad_target_peer_count {
                    trace!(peer_id = %pid,
                        connected, target = self.kad_target_peer_count,
                        "kad: at target — skipping dial of provider");
                    continue;
                }
                match swarm.dial(*pid) {
                    Ok(()) => debug!(peer_id = %pid,
                        "kad: dialing newly-discovered provider"),
                    Err(e) => debug!(peer_id = %pid, error = %e,
                        "kad: dial of discovered provider failed"),
                }
            }
        }

        default_log(event);
    }
}

/// Generic swarm-event logger — catches everything worth surfacing at
/// info/debug/trace level after `on_swarm_event`'s explicit branches.
fn default_log(event: SwarmEvent<BehaviourEvent>) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            info!(%address, "swarm listening");
        }
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            trace!(%peer_id, "connection established");
        }
        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
            trace!(%peer_id, ?cause, "connection closed");
        }
        SwarmEvent::IncomingConnectionError { error, .. } => {
            warn!(%error, "incoming connection error");
        }
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            warn!(?peer_id, %error, "outgoing connection error");
        }
        SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
            trace!(%peer_id, listen_addrs = info.listen_addrs.len(), "identify received");
        }
        SwarmEvent::Behaviour(BehaviourEvent::Identify(_)) => {
            // identify::Event::{Sent,Pushed,Error} — not interesting at info level
        }
        SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
            result: QueryResult::GetProviders(Ok(GetProvidersOk::FoundProviders { providers, .. })),
            ..
        })) => {
            debug!(provider_count = providers.len(), "kad: GetProviders ok");
        }
        SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
            result: QueryResult::StartProviding(res), ..
        })) => match res {
            Ok(_) => debug!("kad: StartProviding ok"),
            Err(e) => warn!(error = ?e, "kad: StartProviding error"),
        },
        SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
            result: QueryResult::Bootstrap(res), ..
        })) => match res {
            Ok(_) => trace!("kad: Bootstrap step ok"),
            Err(e) => debug!(error = ?e, "kad: Bootstrap step error"),
        },
        SwarmEvent::Behaviour(BehaviourEvent::Kad(_)) => {
            // RoutingUpdated, InboundRequest (won't happen in client mode),
            // ModeChanged, etc. — quiet at info.
        }
        SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {
            trace!(peer_count = peers.len(), "mdns: discovered local peers");
        }
        SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Expired(peers))) => {
            trace!(peer_count = peers.len(), "mdns: expired local peers");
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ma(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    #[test]
    fn only_a_gateway_is_pinned() {
        let addrs = [ma("/ip4/172.18.0.16/tcp/4002")];
        assert_eq!(gateway_pin("meta-share/2.3.0 baseUrl=http://x:3000", &addrs, None), None);
        assert!(gateway_pin("meta-gateway/1.0.41 gateways=usenet,tmdb", &addrs, None).is_some());
    }

    #[test]
    fn a_pin_keeps_only_dialable_addresses() {
        let addrs = [
            ma("/ip4/127.0.0.1/tcp/4002"),
            ma("/ip4/0.0.0.0/tcp/4002"),
            ma("/ip4/172.18.0.16/tcp/4002"),
            ma("/ip4/85.17.246.67/tcp/4002"),
        ];
        let pin = gateway_pin(
            "meta-gateway/1.0.41 gateways=usenet",
            &addrs,
            Some("https://metagateway-watch.nsl.sh".into()),
        )
        .unwrap();
        assert_eq!(pin.addrs, vec![addrs[2].clone(), addrs[3].clone()]);
        assert_eq!(pin.base_url.as_deref(), Some("https://metagateway-watch.nsl.sh"));
    }
}
