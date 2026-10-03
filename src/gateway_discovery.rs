//! The meta-gateway **discovery contract** — everything a peer needs to
//! recognise a gateway on the swarm and read back what it can serve.
//!
//! # Mirrored file — keep byte-identical
//!
//! This file exists twice, and the two copies must stay identical:
//!
//! - `packages/meta-share/crates/meta-share/src/gateway_discovery.rs`  (this file)
//! - `packages/meta-search/crates/meta-search/src/gateway_discovery.rs`
//!
//! `diff` between them must be empty. Duplicated rather than shared via a cargo
//! path-dep because both are independently-checked-out git submodules and a
//! `path = "../meta-search/..."` dep breaks when either is cloned alone. This is
//! the same convention meta-gateway's `protocol.rs` ↔ meta-search's
//! `gateway_wire.rs` already follow.
//!
//! # Drift contract
//!
//! The three things below are a wire contract with **meta-gateway**, and drift
//! is silent — a parser that stops recognising the token doesn't error, it just
//! quietly never finds a gateway. Any change must land in all three crates:
//!
//! 1. **The identify `gateways=` token.** meta-gateway advertises
//!    `meta-gateway/<ver> [gateways=<csv>] [baseUrl=<url>]` in its libp2p
//!    identify `agent_version` (`meta-gateway/src/swarm/mod.rs::build_agent_version`,
//!    pinned by its parser-compat test). Presence of a non-empty `gateways=`
//!    token is how a peer tells "this is a gateway" from "this is a sibling
//!    peer" — nothing else on the swarm sets it. The `baseUrl=` half is parsed
//!    by each crate's `swarm::identify_agent` (peer-level, not gateway-level).
//! 2. **The `metamesh-gateway` kad namespace.** Every meta-gateway peer
//!    `start_providing`s on `namespace_key(GATEWAY_NAMESPACE)`; a peer walking
//!    the DHT for gateways `get_providers` the same key. (Both crates already
//!    carry an identical `namespace_key` in `swarm::kad_discovery`.)
//! 3. **`GET {baseUrl}/api/gateway/plugins`.** The *reliable* capability source
//!    — it replaced a gossipsub heartbeat feed that dropped publishes often
//!    enough to leave the meta-watch home page empty. It is plain HTTP off the
//!    identify-learned `baseUrl`, deliberately **not** a libp2p protocol, so a
//!    transport-only peer can read it without adding a behaviour to its swarm.
//!
//! # Why a bare fetch, not a directory write
//!
//! [`fetch_gateway_caps`] returns the parsed response and writes nothing. The
//! two consumers want different halves of it and store them in differently-shaped
//! directories, so the *fetch* is common and the *recording* is not:
//!
//! - **meta-search** reads `plugins[]` (per-upstream file-type / content-kind
//!   facets) to route search fan-out.
//! - **meta-share** reads `nzbFetch` to find a gateway that can materialise and
//!   serve `nzb-release` bytes, then reverse-proxies `/api/file/:cid/raw` to it.
//!
//! That seam is what lets one file serve both crates.

use std::time::Duration;

use serde::Deserialize;

/// Single gateway namespace string. SHA-256 of this is the kad `RecordKey`
/// every meta-gateway peer `start_providing`s on, and the one a peer hunting
/// for gateways `get_providers` against. Mirrors meta-gateway's
/// `kad_helpers::GATEWAY_NAMESPACE` byte-for-byte — drift here means walking a
/// key the gateway never publishes on, which looks exactly like "no gateways
/// exist".
///
/// `allow(dead_code)`: **meta-search** walks this namespace; **meta-share**
/// currently does not. It doesn't need to — it meets gateways via mDNS on the
/// local mesh, or via an operator-configured `BOOTSTRAP_PEERS` across hosts. A
/// DHT walk would in fact be inert there today: a peer in local mode
/// (`PUBLIC_ADDR` unset) has no kad bootstrap peers, hence an empty routing
/// table and nothing to query. The constant stays here because it is part of
/// the gateway contract, and it's the key meta-share would walk if it ever
/// joins the public DHT.
#[allow(dead_code)]
pub const GATEWAY_NAMESPACE: &str = "metamesh-gateway";

/// Token prefix in a peer's identify `agent_version` carrying its served
/// gateway upstreams (CSV). Emitted by **meta-gateway only** — no meta-share or
/// meta-search peer ever sets it, which is what makes a non-empty value a
/// reliable "this peer is a gateway" signal.
pub const AGENT_GATEWAYS_TOKEN: &str = "gateways=";

/// Extract the gateway upstream list from a remote peer's `agent_version`.
/// Empty `Vec` when the token is absent (i.e. the peer is not a gateway) or
/// carries no value. Empty CSV entries are filtered out so `gateways=` and
/// `gateways=foo,,bar` both behave sensibly.
///
/// Keep the parse pattern (`split_ascii_whitespace` + `strip_prefix`) in step
/// with meta-gateway's `build_agent_version` parser-compat test.
pub fn parse_gateways(agent_version: &str) -> Vec<String> {
    agent_version
        .split_ascii_whitespace()
        .find_map(|tok| tok.strip_prefix(AGENT_GATEWAYS_TOKEN))
        .map(|csv| {
            csv.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Whether a peer's `agent_version` marks it as a meta-gateway. The predicate
/// behind "should I fetch this peer's capabilities?".
///
/// `allow(dead_code)`: used by meta-share. meta-search needs the upstream *list*
/// anyway (it stores it for search routing), so it calls [`parse_gateways`] and
/// tests the result for emptiness rather than parsing twice.
#[allow(dead_code)]
pub fn advertises_gateways(agent_version: &str) -> bool {
    !parse_gateways(agent_version).is_empty()
}

/// Shape of `GET {baseUrl}/api/gateway/plugins` on a meta-gateway peer. Only
/// the fields consumers read are declared; `#[serde(default)]` throughout
/// tolerates an older gateway that predates a field (it degrades to "no
/// capability" rather than failing the whole parse).
///
/// `allow(dead_code)`: each crate reads only *half* of this — meta-search wants
/// `plugins[]` for routing, meta-share wants `nzb_fetch` and the plugins' redeem
/// claims — so whichever half the compiling
/// crate ignores looks dead to it. That's inherent to a mirrored file, and
/// silencing it here (rather than at one crate's use site) is what keeps the two
/// copies byte-identical.
#[allow(dead_code)]
#[derive(Debug, Clone, Default, Deserialize)]
pub struct GatewayPluginsResponse {
    /// The gateway's per-upstream plugins. Consumed by meta-search for search
    /// fan-out routing; ignored by meta-share.
    #[serde(default)]
    pub plugins: Vec<GatewayPluginInfo>,
    /// Gateway-wide Usenet byte-serving capability: `true` when this gateway
    /// fronts a credentialed meta-share and can materialise + serve
    /// `nzb-release` bytes via `/api/file/:cid/raw`. Consumed by meta-share to
    /// pick a forward target; ignored by meta-search.
    #[serde(default, rename = "nzbFetch")]
    pub nzb_fetch: bool,
}

/// One upstream plugin on a gateway. `enabled: false` upstreams are served by
/// nobody — routing to one just bounces — so consumers skip them.
///
/// `allow(dead_code)`: read by meta-search (search fan-out routing), ignored by
/// meta-share. See [`GatewayPluginsResponse`].
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct GatewayPluginInfo {
    pub id: String,
    pub enabled: bool,
    #[serde(default)]
    pub file_types: Vec<String>,
    #[serde(default)]
    pub content_kinds: Vec<String>,
    /// The locator families this upstream's feeder can **redeem** — turn a
    /// metered locator cid into bytes through
    /// `POST {baseUrl}/api/file/:cid/redeem`. Read by meta-share to pick a redeem
    /// target; ignored by meta-search. Absent on a gateway that predates redeem.
    #[serde(default)]
    pub redeems: Vec<RedeemClaim>,
}

/// `RedeemClaim::codec` for the Newznab release locator (`0x1005`): the `.nzb`
/// behind it costs an indexer grab.
#[allow(dead_code)]
pub const REDEEM_NZB_RELEASE: &str = "nzb-release";
/// `RedeemClaim::codec` for the provider-file locator (`0x100A`): the file
/// behind it costs the provider's download quota.
#[allow(dead_code)]
pub const REDEEM_PROVIDER_FILE: &str = "provider-file";

/// One locator family a gateway plugin can redeem — the credential for it lives
/// on that plugin's feeder, never on the peer asking.
///
/// - `codec` — [`REDEEM_NZB_RELEASE`] or [`REDEEM_PROVIDER_FILE`].
/// - `field` — the pointer the gateway merges onto the locator's record once it
///   has redeemed it (`manifest` / `file`), naming the bytes' content cid.
/// - `hosts` — for `nzb-release`: the indexer hosts a key is configured for.
/// - `sources` — for `provider-file`: the provider tokens (`opensubtitles`).
///
/// `allow(dead_code)`: read by meta-share, ignored by meta-search.
#[allow(dead_code)]
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct RedeemClaim {
    #[serde(default)]
    pub codec: String,
    #[serde(default)]
    pub field: String,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub sources: Vec<String>,
}

#[allow(dead_code)]
impl RedeemClaim {
    /// Does this claim cover `key` for `codec` — an indexer host for
    /// `nzb-release`, a source token for `provider-file`?
    ///
    /// Hosts compare on the bare authority, case-insensitively, so a feeder that
    /// advertises `https://API.nzb.life/api` still matches the `api.nzb.life` a
    /// locator decodes to.
    pub fn covers(&self, codec: &str, key: &str) -> bool {
        if self.codec != codec {
            return false;
        }
        if codec == REDEEM_NZB_RELEASE {
            let want = bare_authority(key);
            self.hosts.iter().any(|h| bare_authority(h) == want)
        } else {
            self.sources.iter().any(|s| s.eq_ignore_ascii_case(key.trim()))
        }
    }
}

/// `https://Api.Example.com/api/` → `api.example.com`.
#[allow(dead_code)]
fn bare_authority(raw: &str) -> String {
    let t = raw.trim();
    let t = t.strip_prefix("https://").or_else(|| t.strip_prefix("http://")).unwrap_or(t);
    t.split('/').next().unwrap_or("").to_ascii_lowercase()
}

#[allow(dead_code)]
impl GatewayPluginsResponse {
    /// Every redeem claim of every **enabled** plugin. A disabled upstream is
    /// served by nobody, so its claims are too.
    pub fn redeem_claims(&self) -> Vec<RedeemClaim> {
        self.plugins
            .iter()
            .filter(|p| p.enabled)
            .flat_map(|p| p.redeems.iter().cloned())
            .collect()
    }
}

/// Fetch a gateway peer's served capabilities over HTTP, off the
/// identify-learned `base_url`. Pure: it returns the parsed response and
/// records nothing — the caller decides what to keep (see the module docs).
///
/// Callers treat this as best-effort. Every failure mode here (unreachable
/// peer, non-2xx, unparseable body) is a transient fact about one peer, so the
/// caller should log-and-continue, keep whatever it already held, and retry on
/// the next identify.
pub async fn fetch_gateway_caps(
    http: &reqwest::Client,
    base_url: &str,
    timeout: Duration,
) -> reqwest::Result<GatewayPluginsResponse> {
    let url = format!("{}/api/gateway/plugins", base_url.trim_end_matches('/'));
    http.get(&url)
        .timeout(timeout)
        .send()
        .await?
        .error_for_status()?
        .json::<GatewayPluginsResponse>()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_gateways_returns_empty_when_token_absent() {
        // A sibling meta-share/meta-search peer: baseUrl, but no gateways token.
        let av = "meta-share/0.1.0 baseUrl=http://x:9";
        assert!(parse_gateways(av).is_empty());
        assert!(!advertises_gateways(av));
    }

    #[test]
    fn parse_gateways_returns_full_csv() {
        // Matches the corpus meta-gateway's parser-compat test pins down.
        let av = "meta-gateway/0.1.0 gateways=arxiv,giphy,gutenberg,pubmed,wikicommons";
        assert_eq!(
            parse_gateways(av),
            vec!["arxiv", "giphy", "gutenberg", "pubmed", "wikicommons"],
        );
        assert!(advertises_gateways(av));
    }

    #[test]
    fn parse_gateways_handles_single_value() {
        assert_eq!(parse_gateways("meta-gateway/0.1.0 gateways=arxiv"), vec!["arxiv"]);
    }

    #[test]
    fn parse_gateways_filters_empty_csv_entries() {
        // Defensive: a malformed token shouldn't surface "" entries to callers
        // that index a map by upstream id.
        let av = "meta-gateway/0.1.0 gateways=arxiv,,gutenberg,";
        assert_eq!(parse_gateways(av), vec!["arxiv", "gutenberg"]);
    }

    #[test]
    fn parse_gateways_returns_empty_when_token_has_no_value() {
        let av = "meta-gateway/0.1.0 gateways=";
        assert!(parse_gateways(av).is_empty());
        // A gateway with every plugin disabled omits the token's value; it must
        // not be mistaken for a gateway we can route to.
        assert!(!advertises_gateways(av));
    }

    #[test]
    fn parse_gateways_coexists_with_base_url_token_in_either_order() {
        let a = "meta-gateway/0.1.0 baseUrl=http://x:9 gateways=arxiv";
        let b = "meta-gateway/0.1.0 gateways=arxiv baseUrl=http://x:9";
        assert_eq!(parse_gateways(a), vec!["arxiv"]);
        assert_eq!(parse_gateways(b), vec!["arxiv"]);
    }

    #[test]
    fn plugins_response_tolerates_gateway_predating_nzb_fetch() {
        // An older gateway sends neither `nzbFetch` nor the facet arrays.
        let r: GatewayPluginsResponse =
            serde_json::from_str(r#"{"plugins":[{"id":"arxiv","enabled":true}]}"#).unwrap();
        assert!(!r.nzb_fetch);
        assert_eq!(r.plugins.len(), 1);
        assert!(r.plugins[0].file_types.is_empty());
    }

    #[test]
    fn plugins_response_reads_nzb_fetch_and_facets() {
        let r: GatewayPluginsResponse = serde_json::from_str(
            r#"{"plugins":[{"id":"prowlarr","enabled":true,
                            "file_types":["video"],"content_kinds":["movie","episode"]}],
                "nzbFetch":true}"#,
        )
        .unwrap();
        assert!(r.nzb_fetch);
        assert_eq!(r.plugins[0].file_types, vec!["video"]);
        assert_eq!(r.plugins[0].content_kinds, vec!["movie", "episode"]);
    }

    #[test]
    fn plugins_response_reads_redeem_claims_of_enabled_plugins_only() {
        let r: GatewayPluginsResponse = serde_json::from_str(
            r#"{"plugins":[
                {"id":"usenet","enabled":true,"redeems":[
                    {"codec":"nzb-release","field":"manifest","hosts":["api.nzb.life"],"sources":[]}]},
                {"id":"opensubtitles","enabled":false,"redeems":[
                    {"codec":"provider-file","field":"file","hosts":[],"sources":["opensubtitles"]}]},
                {"id":"arxiv","enabled":true}],
                "nzbFetch":true}"#,
        )
        .unwrap();
        let claims = r.redeem_claims();
        assert_eq!(claims.len(), 1, "the disabled plugin's claim must not count");
        assert!(claims[0].covers(REDEEM_NZB_RELEASE, "api.nzb.life"));
        assert!(!claims[0].covers(REDEEM_PROVIDER_FILE, "api.nzb.life"));
        assert!(r.plugins[2].redeems.is_empty());
    }

    #[test]
    fn a_host_claim_matches_on_the_bare_authority() {
        let c = RedeemClaim {
            codec: REDEEM_NZB_RELEASE.into(),
            field: "manifest".into(),
            hosts: vec!["https://API.nzbgeek.info/api/".into()],
            sources: Vec::new(),
        };
        assert!(c.covers(REDEEM_NZB_RELEASE, "api.nzbgeek.info"));
        assert!(!c.covers(REDEEM_NZB_RELEASE, "api.nzb.life"));
    }

    #[test]
    fn plugins_response_tolerates_a_gateway_with_no_plugins_but_nzb_fetch() {
        // The shape that trips a naive debounce: nothing to route searches to,
        // but it CAN serve nzb bytes. Must parse, and must report the cap.
        let r: GatewayPluginsResponse = serde_json::from_str(r#"{"plugins":[],"nzbFetch":true}"#).unwrap();
        assert!(r.nzb_fetch);
        assert!(r.plugins.is_empty());
    }
}
