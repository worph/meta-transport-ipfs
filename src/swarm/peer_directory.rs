//! Per-peer state learned from libp2p identify exchanges. The directory
//! is shared between the swarm task (writer) and the HTTP layer (readers
//! — `/api/peers`, cross-peer file fetches).
//!
//! Held behind a `std::sync::RwLock` (not `tokio::sync::RwLock`) because
//! every access is a brief read/write of a `HashMap<PeerId, _>` —
//! contention is essentially nil at our scale and we don't want to await
//! across the lock.
//!
//! Since the gateway tier moved into its own service, the directory's job
//! is narrow: map a peer id to its HTTP API URL (parsed from identify's
//! `baseUrl=` token) so the cross-peer byte-fetch path can reach it.
//! [`PeerDirectory::forget_peer`] drops a peer's state on its last
//! `ConnectionClosed`.

// The freshness queries (`gateways_redeeming`, `nzb_fetch_gateways`, …) are
// answered by the hull's replica of this directory (`GET /ipfs-tier/directory`);
// they stay here, tested, as the reference the replica mirrors.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use libp2p::PeerId;

use crate::gateway_discovery::{RedeemClaim, REDEEM_NZB_RELEASE};

/// How long an identify-sourced fact stays fresh. Identify re-announces on
/// libp2p's default 5-minute cadence, so a live peer re-stamps its facts well
/// inside this window; a peer that goes quiet ages out rather than lingering as
/// a forever-stale routing target. (Disconnected peers are usually dropped
/// sooner, by `forget_peer` on the last `ConnectionClosed`.)
const IDENTIFY_TTL: Duration = Duration::from_secs(600);

/// Per-peer state learned from libp2p identify exchanges: the peer's HTTP API
/// URL (for cross-peer file fetches) plus, for meta-gateway peers, the
/// gateway capabilities fetched off that URL.
#[derive(Clone, Debug, Default)]
pub struct PeerInfo {
    /// HTTP API URL parsed from identify's `baseUrl=` token. `None` when
    /// the peer didn't advertise one (consumer-only, BASE_URL unset).
    pub base_url: Option<String>,
    /// When this peer last advertised `nzbFetch: true` on
    /// `/api/gateway/plugins` — i.e. it fronts a credentialed meta-share and
    /// can materialise + serve `nzb-release` bytes. `None` = never, or it
    /// stopped. Read accessors treat the capability as gone once older than
    /// [`IDENTIFY_TTL`]. Powers [`PeerDirectory::nzb_fetch_gateways`].
    nzb_fetch_at: Option<Instant>,
    /// The locator families this gateway's feeders can redeem, from the same
    /// capability fetch. Fresh while `caps_fetched_at` is. Powers
    /// [`PeerDirectory::gateways_redeeming`] and, with `nzb_fetch_at`,
    /// [`PeerDirectory::gateway_can_redeem`].
    redeems: Vec<RedeemClaim>,
    /// When we last *completed* a capability fetch against this peer, whatever
    /// the answer was.
    ///
    /// ⚠ This is deliberately separate from `nzb_fetch_at`. Debouncing off the
    /// capability stamp would mean a gateway answering `nzbFetch: false` (which
    /// leaves `nzb_fetch_at = None`) looks identical to one never fetched — so
    /// every single identify would re-fire the HTTP call, forever. The
    /// attempt stamp is what makes the debounce terminate.
    caps_fetched_at: Option<Instant>,
}

/// Shared, read-mostly directory of `peer_id → PeerInfo`. Populated by the
/// swarm task on every identify event and read by the HTTP API for
/// cross-peer fetches. Not behind tokio::sync::RwLock — locks are always
/// brief and identify events are infrequent.
#[derive(Clone, Default)]
pub struct PeerDirectory(Arc<RwLock<HashMap<PeerId, PeerInfo>>>);

impl PeerDirectory {
    /// Build a fresh, empty directory. Use this once at startup and clone
    /// the handle into both `spawn` and the AppState; the `Arc` inside
    /// shares the underlying map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Just the peer's API URL. `None` when the peer advertised no URL or
    /// hasn't been seen yet.
    pub fn base_url(&self, pid: &PeerId) -> Option<String> {
        self.0
            .read()
            .expect("peer directory poisoned")
            .get(pid)
            .and_then(|info| info.base_url.clone())
    }

    /// Atomically update a peer's info from an identify exchange.
    ///
    /// `base_url = Some(_)` replaces; `base_url = None` preserves any
    /// previously-learned URL — identify events from later peer versions
    /// may legitimately omit the token, and the previous URL is still
    /// valid until the peer reconnects with a different one.
    ///
    /// Returns a `PeerInfoUpdate` summarising what changed.
    pub fn upsert_from_identify(
        &self,
        peer_id: PeerId,
        base_url: Option<String>,
    ) -> PeerInfoUpdate {
        let mut map = self.0.write().expect("peer directory poisoned");
        let entry = map.entry(peer_id).or_default();
        let mut update = PeerInfoUpdate::default();
        if let Some(url) = base_url {
            if entry.base_url.as_deref() != Some(url.as_str()) {
                entry.base_url = Some(url.clone());
                update.base_url_changed = Some(url);
            }
        }
        update
    }

    /// Record the outcome of a `/api/gateway/plugins` capability fetch.
    /// `capable` stamps the `nzbFetch` liveness; `false` clears it (the gateway
    /// dropped its credentialed meta-share). `redeems` replaces the gateway's
    /// redeem claims, which don't depend on `nzbFetch` — redeeming a locator
    /// needs the gateway's feeder, not an NNTP pool. Either way the *attempt* is
    /// stamped, which is what [`Self::needs_cap_refresh`] debounces on.
    ///
    /// Only called after a fetch that actually answered — a failed fetch leaves
    /// every stamp alone, so the prior value ages out on its own TTL and the
    /// next identify retries.
    pub fn record_gateway_caps(
        &self,
        peer_id: PeerId,
        capable: bool,
        redeems: Vec<RedeemClaim>,
    ) {
        self.record_gateway_caps_at(peer_id, capable, redeems, Instant::now());
    }

    fn record_gateway_caps_at(
        &self,
        peer_id: PeerId,
        capable: bool,
        redeems: Vec<RedeemClaim>,
        now: Instant,
    ) {
        let mut map = self.0.write().expect("peer directory poisoned");
        let entry = map.entry(peer_id).or_default();
        entry.nzb_fetch_at = capable.then_some(now);
        entry.redeems = redeems;
        entry.caps_fetched_at = Some(now);
    }

    /// Base URLs of the gateways whose feeders can redeem `key` for `codec` right
    /// now — an `nzb-release` indexer host, or a `provider-file` source — from a
    /// fresh capability fetch, with a `base_url` to call. The targets for
    /// `crate::redeem`. Deduplicated; order unspecified.
    pub fn gateways_redeeming(&self, codec: &str, key: &str) -> Vec<String> {
        self.gateways_redeeming_at(codec, key, Instant::now())
    }

    fn gateways_redeeming_at(&self, codec: &str, key: &str, now: Instant) -> Vec<String> {
        let map = self.0.read().expect("peer directory poisoned");
        let mut out: Vec<String> = Vec::new();
        for info in map.values() {
            let fresh = info
                .caps_fetched_at
                .is_some_and(|t| now.saturating_duration_since(t) <= IDENTIFY_TTL);
            let Some(url) = info.base_url.as_deref() else {
                continue;
            };
            if fresh && info.redeems.iter().any(|c| c.covers(codec, key)) {
                let url = url.trim_end_matches('/').to_string();
                if !out.contains(&url) {
                    out.push(url);
                }
            }
        }
        out
    }

    /// Has a capability fetch against *any* reachable gateway completed recently?
    ///
    /// Tells "no gateway on this swarm redeems that" — a statement worth a `400`
    /// — apart from "we haven't found a gateway yet", which is a warming state
    /// worth a retryable `503`.
    pub fn knows_a_gateway(&self) -> bool {
        self.knows_a_gateway_at(Instant::now())
    }

    fn knows_a_gateway_at(&self, now: Instant) -> bool {
        let map = self.0.read().expect("peer directory poisoned");
        map.values().any(|info| {
            info.base_url.is_some()
                && info
                    .caps_fetched_at
                    .is_some_and(|t| now.saturating_duration_since(t) <= IDENTIFY_TTL)
        })
    }

    /// Can any gateway on this swarm redeem a release from `indexer_host` right
    /// now — a *fresh* `nzbFetch` capability on a gateway whose feeders claim
    /// that host?
    ///
    /// The availability predicate behind `/api/file/:cid/probe` for a Usenet cid.
    /// It costs nothing: the host comes out of the cid's own multihash and the
    /// claims come from the directory (refreshed on identify, 600 s TTL). Probing
    /// a Usenet title must never touch NNTP — `bridge::ensure` downloads the
    /// *whole* posting, so a "free" availability check used to start one full
    /// download per probed variant.
    pub fn gateway_can_redeem(&self, indexer_host: &str) -> bool {
        self.gateway_can_redeem_at(indexer_host, Instant::now())
    }

    fn gateway_can_redeem_at(&self, indexer_host: &str, now: Instant) -> bool {
        let map = self.0.read().expect("peer directory poisoned");
        map.values().any(|info| {
            let fresh = info
                .nzb_fetch_at
                .is_some_and(|t| now.saturating_duration_since(t) <= IDENTIFY_TTL);
            fresh
                && info.base_url.is_some()
                && info.redeems.iter().any(|c| c.covers(REDEEM_NZB_RELEASE, indexer_host))
        })
    }

    /// Can any gateway on this swarm fetch from Usenet **at all**, regardless of
    /// which indexers it holds keys for?
    ///
    /// This is [`gateway_can_redeem`](Self::gateway_can_redeem) minus the
    /// indexer-host match, and it is the right question for a **self-scanned
    /// `nzb-posting` (`0x1003`)** cid: that cid is a digest over the article
    /// Message-ID set and names no indexer, so a plain NNTP provider is the only
    /// thing needed to fetch it. Asking the host-scoped question about a posting
    /// would answer `false` for every gateway — including ones that can serve it
    /// perfectly well — and the title would grade `red` and never render.
    pub fn gateway_can_fetch_nzb(&self) -> bool {
        self.gateway_can_fetch_nzb_at(Instant::now())
    }

    fn gateway_can_fetch_nzb_at(&self, now: Instant) -> bool {
        let map = self.0.read().expect("peer directory poisoned");
        map.values().any(|info| {
            info.nzb_fetch_at
                .is_some_and(|t| now.saturating_duration_since(t) <= IDENTIFY_TTL)
                && info.base_url.is_some()
        })
    }

    /// Whether the swarm task should (re)fetch this peer's gateway capabilities.
    /// True when we've never completed a fetch, or the last one is older than
    /// `refresh_after`. Debounces the per-identify fetch so a burst of identify
    /// events (one per connection) doesn't spawn redundant HTTP calls.
    pub fn needs_cap_refresh(&self, peer_id: &PeerId, refresh_after: Duration) -> bool {
        self.needs_cap_refresh_at(peer_id, refresh_after, Instant::now())
    }

    fn needs_cap_refresh_at(&self, peer_id: &PeerId, refresh_after: Duration, now: Instant) -> bool {
        let map = self.0.read().expect("peer directory poisoned");
        match map.get(peer_id).and_then(|info| info.caps_fetched_at) {
            None => true,
            Some(at) => now.saturating_duration_since(at) > refresh_after,
        }
    }

    /// Gateways that can serve `nzb-release` bytes right now: peers with a
    /// *fresh* `nzbFetch` capability **and** an HTTP `base_url` to proxy to.
    /// Returns `(peer_id, base_url)` — the forward-target list for the Usenet
    /// byte path.
    pub fn nzb_fetch_gateways(&self) -> Vec<(PeerId, String)> {
        self.nzb_fetch_gateways_at(Instant::now())
    }

    fn nzb_fetch_gateways_at(&self, now: Instant) -> Vec<(PeerId, String)> {
        let map = self.0.read().expect("peer directory poisoned");
        map.iter()
            .filter_map(|(pid, info)| {
                let fresh = info
                    .nzb_fetch_at
                    .is_some_and(|t| now.saturating_duration_since(t) <= IDENTIFY_TTL);
                match (fresh, &info.base_url) {
                    (true, Some(url)) => Some((*pid, url.clone())),
                    _ => None,
                }
            })
            .collect()
    }

    /// Drop all state for `peer_id` (base URL + gateway capabilities). Called
    /// by the swarm task on the *last* `ConnectionClosed` for a peer. Returns
    /// `true` when an entry was actually present.
    /// The whole directory as the hull's replica wants it: freshness as ages,
    /// claims as the JSON the gateway served. `GET /ipfs-tier/directory`.
    pub fn snapshot(&self) -> Vec<meta_feeder_sdk::transport::ipfs::DirectoryPeer> {
        let now = Instant::now();
        let age = |t: Option<Instant>| t.map(|t| now.saturating_duration_since(t).as_millis() as u64);
        self.0
            .read()
            .expect("peer directory poisoned")
            .iter()
            .map(|(pid, info)| meta_feeder_sdk::transport::ipfs::DirectoryPeer {
                peer_id: pid.to_string(),
                base_url: info.base_url.clone(),
                nzb_fetch_age_ms: age(info.nzb_fetch_at),
                caps_age_ms: age(info.caps_fetched_at),
                redeems: info
                    .redeems
                    .iter()
                    .map(|c| {
                        serde_json::json!({
                            "codec": c.codec, "field": c.field,
                            "hosts": c.hosts, "sources": c.sources,
                        })
                    })
                    .collect(),
            })
            .collect()
    }

    pub fn forget_peer(&self, peer_id: &PeerId) -> bool {
        self.0
            .write()
            .expect("peer directory poisoned")
            .remove(peer_id)
            .is_some()
    }
}

/// What changed on a `PeerDirectory::upsert_from_identify` call. `None`
/// on a no-op refresh (peer re-identified with the same data). Used by
/// the swarm task to emit per-field debug logs only when something
/// actually moved.
#[derive(Default, Debug)]
pub struct PeerInfoUpdate {
    pub base_url_changed: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid_n(n: u8) -> PeerId {
        // Deterministic peer-ids from a seed keypair — we just need
        // distinct values, not real keypair material.
        let kp = libp2p::identity::Keypair::ed25519_from_bytes([n; 32]).expect("keypair");
        PeerId::from_public_key(&kp.public())
    }

    #[test]
    fn a_gateway_only_redeems_the_indexers_it_advertises() {
        // The Usenet availability predicate: an nzb-release cid names its indexer
        // host, and only a gateway holding a key for THAT host can play it. Answered
        // from the directory — no NNTP, no .nzb grab, no download.
        let dir = PeerDirectory::new();
        let gw = PeerId::random();
        dir.upsert_from_identify(gw, Some("http://gw:3000".into()));
        dir.record_gateway_caps(gw, true, vec![claim(REDEEM_NZB_RELEASE, &["api.nzb.life"], &[])]);

        assert!(dir.gateway_can_redeem("api.nzb.life"));
        // A release from an indexer nobody has a key for cannot play → red.
        assert!(!dir.gateway_can_redeem("api.other.example"));
    }

    #[test]
    fn a_gateway_that_lost_its_credentials_redeems_nothing() {
        // nzbFetch:false withdraws the capability, so a gateway whose meta-share
        // dropped its NNTP credentials stops grading releases playable — even
        // though its feeder still claims the host, no pool behind it can fetch
        // the articles.
        let dir = PeerDirectory::new();
        let gw = PeerId::random();
        dir.upsert_from_identify(gw, Some("http://gw:3000".into()));
        dir.record_gateway_caps(gw, true, vec![claim(REDEEM_NZB_RELEASE, &["api.nzb.life"], &[])]);
        assert!(dir.gateway_can_redeem("api.nzb.life"));

        dir.record_gateway_caps(gw, false, vec![claim(REDEEM_NZB_RELEASE, &["api.nzb.life"], &[])]);
        assert!(!dir.gateway_can_redeem("api.nzb.life"));
    }

    /// ⚠ THE SELF-SCANNED-POSTING PROBE. `gateway_can_fetch_nzb` must answer
    /// `true` for a gateway that advertises Usenet fetch capability with **no**
    /// indexer hosts at all — a self-hosted-scanner gateway has none to
    /// advertise, since a `0x1003` posting names no indexer. If this regresses
    /// to requiring an `nzb-release` redeem claim, self-scanned titles grade
    /// red and never render even though the gateway can serve them fine.
    #[test]
    fn any_gateway_with_nzb_capability_answers_the_posting_probe() {
        let dir = PeerDirectory::new();
        let gw = PeerId::random();
        dir.upsert_from_identify(gw, Some("http://gw:3000".into()));
        // Note: no redeem claims — this gateway holds no third-party keys,
        // exactly the shape a pure self-hosted-scanner gateway has.
        dir.record_gateway_caps(gw, true, vec![]);

        assert!(dir.gateway_can_fetch_nzb());
        // But it correctly still cannot redeem a HOST-BOUND locator it has no
        // key for — the two questions must stay distinct.
        assert!(!dir.gateway_can_redeem("api.nzb.life"));
    }

    #[test]
    fn no_gateway_advertising_nzb_capability_fails_the_posting_probe() {
        let dir = PeerDirectory::new();
        let gw = PeerId::random();
        dir.upsert_from_identify(gw, Some("http://gw:3000".into()));
        // Never called record_gateway_caps — no capability advertised at all.
        assert!(!dir.gateway_can_fetch_nzb());
    }

    #[test]
    fn a_gateway_that_lost_nzb_capability_fails_the_posting_probe_too() {
        let dir = PeerDirectory::new();
        let gw = PeerId::random();
        dir.upsert_from_identify(gw, Some("http://gw:3000".into()));
        dir.record_gateway_caps(gw, true, vec![]);
        assert!(dir.gateway_can_fetch_nzb());

        dir.record_gateway_caps(gw, false, vec![]);
        assert!(!dir.gateway_can_fetch_nzb());
    }

    fn claim(codec: &str, hosts: &[&str], sources: &[&str]) -> RedeemClaim {
        RedeemClaim {
            codec: codec.into(),
            field: "file".into(),
            hosts: hosts.iter().map(|s| s.to_string()).collect(),
            sources: sources.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Redeem targets come from claims, not from `nzbFetch`: redeeming a locator
    /// needs the gateway's feeder, and a gateway with no NNTP pool behind it can
    /// still grab a `.nzb` or download a subtitle.
    #[test]
    fn redeem_targets_are_the_gateways_whose_claims_cover_the_key() {
        use crate::gateway_discovery::{REDEEM_NZB_RELEASE, REDEEM_PROVIDER_FILE};
        let dir = PeerDirectory::new();
        let subs = pid_n(30);
        let usenet = pid_n(31);
        let no_url = pid_n(32);
        dir.upsert_from_identify(subs, Some("http://subs:3000/".into()));
        dir.upsert_from_identify(usenet, Some("http://usenet:3000".into()));
        dir.record_gateway_caps(subs, false, vec![claim(REDEEM_PROVIDER_FILE, &[], &["opensubtitles"])]);
        dir.record_gateway_caps(usenet, false, vec![claim(REDEEM_NZB_RELEASE, &["api.nzb.life"], &[])]);
        // Claims, but nowhere to POST to.
        dir.record_gateway_caps(no_url, false, vec![claim(REDEEM_PROVIDER_FILE, &[], &["opensubtitles"])]);

        assert_eq!(
            dir.gateways_redeeming(REDEEM_PROVIDER_FILE, "opensubtitles"),
            vec!["http://subs:3000".to_string()]
        );
        assert_eq!(
            dir.gateways_redeeming(REDEEM_NZB_RELEASE, "api.nzb.life"),
            vec!["http://usenet:3000".to_string()]
        );
        assert!(dir.gateways_redeeming(REDEEM_NZB_RELEASE, "api.other.example").is_empty());
        assert!(dir.gateways_redeeming(REDEEM_PROVIDER_FILE, "subscene").is_empty());
    }

    #[test]
    fn redeem_claims_and_gateway_knowledge_expire_with_the_caps_fetch() {
        use crate::gateway_discovery::REDEEM_PROVIDER_FILE;
        let dir = PeerDirectory::new();
        let p = pid_n(33);
        let t0 = Instant::now();
        assert!(!dir.knows_a_gateway_at(t0), "empty directory knows nothing");
        dir.upsert_from_identify(p, Some("http://gw:9".into()));
        dir.record_gateway_caps_at(p, false, vec![claim(REDEEM_PROVIDER_FILE, &[], &["opensubtitles"])], t0);

        assert!(dir.knows_a_gateway_at(t0 + IDENTIFY_TTL));
        assert_eq!(dir.gateways_redeeming_at(REDEEM_PROVIDER_FILE, "opensubtitles", t0 + IDENTIFY_TTL).len(), 1);
        let late = t0 + IDENTIFY_TTL + Duration::from_secs(1);
        assert!(!dir.knows_a_gateway_at(late));
        assert!(dir.gateways_redeeming_at(REDEEM_PROVIDER_FILE, "opensubtitles", late).is_empty());
    }

    #[test]
    fn upsert_records_base_url() {
        let dir = PeerDirectory::new();
        let p = pid_n(1);
        let u = dir.upsert_from_identify(p, Some("http://gateway-1:9".into()));
        assert_eq!(u.base_url_changed.as_deref(), Some("http://gateway-1:9"));
        assert_eq!(dir.base_url(&p).as_deref(), Some("http://gateway-1:9"));

        // No-op refresh.
        let u2 = dir.upsert_from_identify(p, Some("http://gateway-1:9".into()));
        assert!(u2.base_url_changed.is_none());
    }

    #[test]
    fn upsert_preserves_base_url_on_none() {
        let dir = PeerDirectory::new();
        let p = pid_n(2);
        dir.upsert_from_identify(p, Some("http://x:9".into()));
        // A later identify without a baseUrl token keeps the old URL.
        let u = dir.upsert_from_identify(p, None);
        assert!(u.base_url_changed.is_none());
        assert_eq!(dir.base_url(&p).as_deref(), Some("http://x:9"));
    }

    #[test]
    fn forget_peer_removes_all_state() {
        let dir = PeerDirectory::new();
        let p = pid_n(23);
        dir.upsert_from_identify(p, Some("http://g:9".into()));
        dir.record_gateway_caps(p, true, vec![claim(REDEEM_NZB_RELEASE, &["api.nzb.life"], &[])]);
        assert_eq!(dir.base_url(&p).as_deref(), Some("http://g:9"));
        assert_eq!(dir.nzb_fetch_gateways().len(), 1);

        assert!(dir.forget_peer(&p), "peer was present");
        assert_eq!(dir.base_url(&p), None);
        assert!(
            dir.nzb_fetch_gateways().is_empty(),
            "forget_peer must drop the gateway capability too"
        );

        assert!(!dir.forget_peer(&p), "second forget is a no-op");
    }

    #[test]
    fn nzb_gateway_listed_only_with_both_capability_and_base_url() {
        let dir = PeerDirectory::new();
        let with_url = pid_n(3);
        let no_url = pid_n(4);
        let not_capable = pid_n(5);

        dir.upsert_from_identify(with_url, Some("http://gw:9".into()));
        dir.record_gateway_caps(with_url, true, vec![]);

        // Capable, but advertised no baseUrl — there's nowhere to proxy to.
        dir.record_gateway_caps(no_url, true, vec![]);

        // Has a URL but declines nzb bytes (no credentialed meta-share behind it).
        dir.upsert_from_identify(not_capable, Some("http://plain:9".into()));
        dir.record_gateway_caps(not_capable, false, vec![]);

        assert_eq!(
            dir.nzb_fetch_gateways(),
            vec![(with_url, "http://gw:9".to_string())]
        );
    }

    #[test]
    fn nzb_capability_expires_after_identify_ttl() {
        let dir = PeerDirectory::new();
        let p = pid_n(6);
        let t0 = Instant::now();
        dir.upsert_from_identify(p, Some("http://gw:9".into()));
        dir.record_gateway_caps_at(p, true, vec![], t0);

        // Still fresh at the TTL boundary...
        assert_eq!(dir.nzb_fetch_gateways_at(t0 + IDENTIFY_TTL).len(), 1);
        // ...gone just past it. A gateway that stopped identifying must not
        // stay a forward target forever.
        assert!(dir
            .nzb_fetch_gateways_at(t0 + IDENTIFY_TTL + Duration::from_secs(1))
            .is_empty());
    }

    #[test]
    fn cap_refresh_debounces_even_when_gateway_reports_not_capable() {
        // The trap: `nzbFetch: false` leaves no capability stamp. If the
        // debounce keyed off that, every identify (one per connection, then
        // every ~5 min) would re-fire the HTTP fetch forever. It must key off
        // the *attempt* stamp instead.
        let dir = PeerDirectory::new();
        let p = pid_n(7);
        let refresh = Duration::from_secs(300);
        let t0 = Instant::now();

        assert!(
            dir.needs_cap_refresh_at(&p, refresh, t0),
            "never fetched → must fetch"
        );

        dir.record_gateway_caps_at(p, false, vec![], t0);
        assert!(
            !dir.needs_cap_refresh_at(&p, refresh, t0 + Duration::from_secs(1)),
            "a `false` answer must still debounce the next identify"
        );
        assert!(
            !dir.needs_cap_refresh_at(&p, refresh, t0 + refresh),
            "still inside the refresh window"
        );
        assert!(
            dir.needs_cap_refresh_at(&p, refresh, t0 + refresh + Duration::from_secs(1)),
            "past the refresh window → re-fetch"
        );
    }
}
