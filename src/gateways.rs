//! Which gateways can redeem a pointer, fastest first.
//!
//! Two sources, merged by base URL:
//!
//! - **Pinned** gateways from config (`gateway_urls`, seeded from
//!   `META_SHARE_GATEWAY_URLS`) — the local one. Their redeem claims come
//!   straight from `GET {url}/api/gateway/plugins`, so they never depend on the
//!   libp2p link (watch.nsl.sh 2026-10-04: a lost swarm link left every NZB
//!   "unredeemable" though the gateway sat on the same Docker network).
//! - **Swarm** gateways from the peer directory (identify `gateways=` + a caps
//!   fetch) — remote ones.
//!
//! Order is by the round-trip of the last caps fetch, which the refresh task
//! times for every known gateway. Nothing ranks the local gateway first by rule:
//! it is simply the closest, so it wins on latency.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tracing::debug;

use crate::api::AppState;
use crate::gateway_discovery::{fetch_gateway_caps, RedeemClaim};
use crate::swarm::PeerDirectory;

/// How often pinned gateways' claims and every gateway's latency are refreshed.
const REFRESH_EVERY: Duration = Duration::from_secs(30);
/// A pinned gateway's claims are trusted this long after the last fetch.
const CLAIMS_TTL: Duration = Duration::from_secs(600);
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Default)]
pub struct Gateways {
    pinned: Vec<String>,
    /// Pinned base URL → (claims, fetched at).
    pinned_claims: Mutex<HashMap<String, (Vec<RedeemClaim>, Instant)>>,
    /// Base URL → last caps-fetch round-trip.
    rtt: Mutex<HashMap<String, Duration>>,
}

fn norm(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

impl Gateways {
    pub fn new(pinned: impl IntoIterator<Item = String>) -> Self {
        let mut list: Vec<String> = Vec::new();
        for u in pinned.into_iter().map(|u| norm(&u)).filter(|u| !u.is_empty()) {
            if !list.contains(&u) {
                list.push(u);
            }
        }
        Self { pinned: list, ..Self::default() }
    }

    /// From `META_SHARE_GATEWAY_URLS` (comma-separated), which the config plane
    /// overlays at boot.
    pub fn from_env() -> Self {
        Self::new(
            std::env::var("META_SHARE_GATEWAY_URLS")
                .unwrap_or_default()
                .split(',')
                .map(str::to_string),
        )
    }

    pub fn pinned(&self) -> &[String] {
        &self.pinned
    }

    fn record(&self, url: &str, claims: Option<Vec<RedeemClaim>>, rtt: Duration) {
        self.rtt.lock().unwrap().insert(norm(url), rtt);
        if let Some(c) = claims {
            self.pinned_claims.lock().unwrap().insert(norm(url), (c, Instant::now()));
        }
    }

    /// Gateways whose claim covers (`codec`, `key`), fastest first. A gateway
    /// with no measured latency yet goes after every measured one.
    pub fn candidates(&self, dir: &PeerDirectory, codec: &str, key: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        {
            let claims = self.pinned_claims.lock().unwrap();
            for url in &self.pinned {
                let covered = claims.get(url).is_some_and(|(c, at)| {
                    at.elapsed() <= CLAIMS_TTL && c.iter().any(|c| c.covers(codec, key))
                });
                if covered {
                    out.push(url.clone());
                }
            }
        }
        for url in dir.gateways_redeeming(codec, key) {
            let url = norm(&url);
            if !out.contains(&url) {
                out.push(url);
            }
        }
        self.by_latency(out)
    }

    fn by_latency(&self, mut urls: Vec<String>) -> Vec<String> {
        let rtt = self.rtt.lock().unwrap();
        // Stable sort: unmeasured gateways keep their order (pinned first).
        urls.sort_by_key(|u| rtt.get(u).copied().unwrap_or(Duration::MAX));
        urls
    }

    /// Is any gateway known at all — a pinned one that answered, or a swarm one?
    /// Tells "nobody claims this" apart from "discovery hasn't finished".
    pub fn knows_any(&self, dir: &PeerDirectory) -> bool {
        let pinned_answered = self
            .pinned_claims
            .lock()
            .unwrap()
            .values()
            .any(|(_, at)| at.elapsed() <= CLAIMS_TTL);
        pinned_answered || dir.knows_a_gateway()
    }
}

/// Refresh pinned claims and every gateway's latency, now and every
/// [`REFRESH_EVERY`].
pub fn spawn_refresh(state: Arc<AppState>) {
    tokio::spawn(async move {
        loop {
            refresh(&state).await;
            tokio::time::sleep(REFRESH_EVERY).await;
        }
    });
}

async fn refresh(state: &AppState) {
    let gws = &state.gateways;
    let mut urls: Vec<(String, bool)> = gws.pinned().iter().map(|u| (u.clone(), true)).collect();
    for p in state.peer_directory.snapshot() {
        if p.redeems.is_empty() {
            continue;
        }
        if let Some(u) = p.base_url.as_deref().map(norm) {
            if !urls.iter().any(|(x, _)| *x == u) {
                urls.push((u, false));
            }
        }
    }
    for (url, pinned) in urls {
        let t0 = Instant::now();
        match fetch_gateway_caps(&state.http, &url, FETCH_TIMEOUT).await {
            Ok(caps) => gws.record(&url, pinned.then(|| caps.redeem_claims()), t0.elapsed()),
            Err(e) => debug!(gateway = %url, error = %e, "gateways: caps fetch failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway_discovery::REDEEM_NZB_RELEASE;

    fn claim(host: &str) -> RedeemClaim {
        serde_json::from_value(serde_json::json!({
            "codec": REDEEM_NZB_RELEASE, "field": "manifest", "hosts": [host], "sources": []
        }))
        .unwrap()
    }

    #[test]
    fn a_pinned_gateway_counts_only_for_what_it_claims() {
        let g = Gateways::new(["http://local:3000/".to_string()]);
        let dir = PeerDirectory::new();
        assert!(g.candidates(&dir, REDEEM_NZB_RELEASE, "api.nzbgeek.info").is_empty());
        assert!(!g.knows_any(&dir));
        g.record("http://local:3000", Some(vec![claim("api.nzbgeek.info")]), Duration::from_millis(3));
        assert_eq!(
            g.candidates(&dir, REDEEM_NZB_RELEASE, "api.nzbgeek.info"),
            vec!["http://local:3000".to_string()]
        );
        assert!(g.candidates(&dir, REDEEM_NZB_RELEASE, "api.nzb.life").is_empty());
        assert!(g.knows_any(&dir));
    }

    #[test]
    fn the_fastest_gateway_comes_first() {
        let g = Gateways::new(["http://a".to_string(), "http://b".to_string(), "http://c".to_string()]);
        g.record("http://a", Some(vec![claim("h")]), Duration::from_millis(80));
        g.record("http://b", Some(vec![claim("h")]), Duration::from_millis(2));
        // c claims but was never timed separately from its claims fetch: still timed.
        g.record("http://c", Some(vec![claim("h")]), Duration::from_millis(20));
        assert_eq!(
            g.candidates(&PeerDirectory::new(), REDEEM_NZB_RELEASE, "h"),
            vec!["http://b", "http://c", "http://a"]
        );
    }

    #[test]
    fn unmeasured_gateways_go_last_in_their_given_order() {
        let g = Gateways::new([]);
        g.rtt.lock().unwrap().insert("http://timed".into(), Duration::from_millis(500));
        assert_eq!(
            g.by_latency(vec!["http://x".into(), "http://timed".into(), "http://y".into()]),
            vec!["http://timed", "http://x", "http://y"]
        );
    }
}
