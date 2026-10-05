//! The plugin's own settings (config plane), edited from meta-share's dashboard
//! (Plugins → ipfs → configure) and stored in `<state dir>/config.json`.
//!
//! Every knob here was — and still is — an env var read by the module that uses
//! it (`config.rs`, `swarm/`, `ingress_commit.rs`). Rather than re-thread each
//! one, [`overlay_env`] writes the effective values onto those same env names
//! once at boot, before anything reads them: `config.json` wins, the env seeds
//! it. Infra stays env-only: `PUBLIC_ADDR` / `P2P_LISTEN` (bound to the port
//! compose publishes and the box's IP) and the data dirs.

use meta_feeder_sdk::transport::config::read;
use meta_feeder_sdk::{ConfigField, ConfigSchema};
use serde_json::{json, Value};

const GIB: u64 = 1024 * 1024 * 1024;
const DEFAULT_NAMESPACE: &str = "metamesh-share-default";

pub fn schema() -> ConfigSchema {
    ConfigSchema {
        fields: vec![
            ConfigField::text("kad_namespace", "Cohort namespace")
                .with_help("Peers only see others with the same namespace. Change it on every node of a private group."),
            ConfigField::list("kad_bootstrap_peers", "DHT bootstrap peers")
                .with_help("Multiaddrs used to join the public IPFS DHT. Empty = the app's default list. `none` disables the DHT."),
            ConfigField::list("bootstrap_peers", "Pinned peers")
                .with_help("Multiaddrs this node keeps dialled (e.g. a known gateway)."),
            ConfigField::list("gateway_urls", "Local gateways")
                .with_help("Base URLs of gateways reached over HTTP without the swarm (e.g. http://metagateway-app:3000). They resolve NZB and subtitle pointers even when the libp2p link is down."),
            ConfigField::bool("enable_mdns", "LAN discovery (mDNS)"),
            ConfigField::bool("seed_dht_provide", "Announce seeds on the DHT")
                .with_help("Publish provider records for what this node seeds, so remote peers can find it."),
            ConfigField::number("max_conns", "Max connections"),
            ConfigField::bool("ingress_commit", "Background completion")
                .with_help("Finish partially fetched IPFS content in the background."),
            ConfigField::number("ingress_commit_max_concurrent", "Concurrent completions"),
            ConfigField::number("ingress_commit_min_free_gib", "Disk floor (GiB)")
                .with_help("Background completion stands down below this much free disk."),
        ],
    }
}

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn env_list(key: &str) -> Vec<String> {
    env(key)
        .map(|s| s.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect())
        .unwrap_or_default()
}

fn env_flag(key: &str, default: bool) -> bool {
    match env(key) {
        Some(v) => !matches!(v.to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off"),
        None => default,
    }
}

fn env_u64(key: &str, default: u64) -> u64 {
    env(key).and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// The values a plugin with no `config.json` runs with. Booleans are explicit
/// (the page's checkbox always submits one), so each carries the default the
/// reading module would apply.
pub fn seed() -> Value {
    // `config.rs` defaults the seed announce to "public mode", i.e. a PUBLIC_ADDR.
    let public = env("PUBLIC_ADDR").or_else(|| env("P2P_ANNOUNCE")).is_some();
    json!({
        "kad_namespace": env("KAD_NAMESPACE").unwrap_or_else(|| DEFAULT_NAMESPACE.to_string()),
        "kad_bootstrap_peers": env_list("KAD_BOOTSTRAP_PEERS"),
        "bootstrap_peers": env_list("BOOTSTRAP_PEERS"),
        "gateway_urls": env_list("META_SHARE_GATEWAY_URLS"),
        "enable_mdns": env_flag("ENABLE_MDNS", true),
        "seed_dht_provide": env_flag("META_SHARE_SEED_DHT_PROVIDE", public),
        "max_conns": env_u64("META_SHARE_MAX_CONNS", 128),
        "ingress_commit": env_flag("META_SHARE_INGRESS_COMMIT", true),
        "ingress_commit_max_concurrent": env_u64("META_SHARE_INGRESS_COMMIT_MAX_CONCURRENT", 2),
        "ingress_commit_min_free_gib": env_u64("META_SHARE_INGRESS_COMMIT_MIN_FREE_BYTES", 5 * GIB) / GIB,
    })
}

/// `(env name, value)` pairs the effective config sets. An unset/blank value
/// is skipped, leaving the env (or the module's default) in force.
pub fn env_overrides(v: &Value) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    let bool_s = |b: bool| if b { "true".to_string() } else { "false".to_string() };
    if let Some(s) = read::text(v, "kad_namespace") {
        out.push(("KAD_NAMESPACE", s));
    }
    if let Some(l) = read::list(v, "kad_bootstrap_peers").filter(|l| !l.is_empty()) {
        // `none` is the documented "no DHT" spelling; config.rs reads set-but-empty that way.
        let joined = if l.iter().any(|p| p.eq_ignore_ascii_case("none")) { String::new() } else { l.join(",") };
        out.push(("KAD_BOOTSTRAP_PEERS", joined));
    }
    if let Some(l) = read::list(v, "bootstrap_peers").filter(|l| !l.is_empty()) {
        out.push(("BOOTSTRAP_PEERS", l.join(",")));
    }
    if let Some(l) = read::list(v, "gateway_urls").filter(|l| !l.is_empty()) {
        out.push(("META_SHARE_GATEWAY_URLS", l.join(",")));
    }
    if let Some(b) = read::flag(v, "enable_mdns") {
        out.push(("ENABLE_MDNS", bool_s(b)));
    }
    if let Some(b) = read::flag(v, "seed_dht_provide") {
        out.push(("META_SHARE_SEED_DHT_PROVIDE", bool_s(b)));
    }
    if let Some(n) = read::uint(v, "max_conns").filter(|n| *n > 0) {
        out.push(("META_SHARE_MAX_CONNS", n.to_string()));
    }
    if let Some(b) = read::flag(v, "ingress_commit") {
        out.push(("META_SHARE_INGRESS_COMMIT", bool_s(b)));
    }
    if let Some(n) = read::uint(v, "ingress_commit_max_concurrent").filter(|n| *n > 0) {
        out.push(("META_SHARE_INGRESS_COMMIT_MAX_CONCURRENT", n.to_string()));
    }
    if let Some(n) = read::uint(v, "ingress_commit_min_free_gib") {
        out.push(("META_SHARE_INGRESS_COMMIT_MIN_FREE_BYTES", n.saturating_mul(GIB).to_string()));
    }
    out
}

/// Apply [`env_overrides`] to this process's environment. Call once at the top
/// of `main`, before any config is read and before other tasks run.
pub fn overlay_env(v: &Value) {
    for (k, val) in env_overrides(v) {
        std::env::set_var(k, val);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get<'a>(o: &'a [(&'static str, String)], k: &str) -> Option<&'a str> {
        o.iter().find(|(n, _)| *n == k).map(|(_, v)| v.as_str())
    }

    #[test]
    fn page_values_map_onto_the_env_names_the_modules_read() {
        let o = env_overrides(&json!({
            "kad_namespace": "private-cohort",
            "kad_bootstrap_peers": ["/dns4/a/tcp/4001/p2p/X", "/dns4/b/tcp/4001/p2p/Y"],
            "bootstrap_peers": [],
            "enable_mdns": false,
            "seed_dht_provide": true,
            "max_conns": null,
            "ingress_commit": true,
            "ingress_commit_max_concurrent": 4,
            "ingress_commit_min_free_gib": 10,
        }));
        assert_eq!(get(&o, "KAD_NAMESPACE"), Some("private-cohort"));
        assert_eq!(get(&o, "KAD_BOOTSTRAP_PEERS"), Some("/dns4/a/tcp/4001/p2p/X,/dns4/b/tcp/4001/p2p/Y"));
        assert_eq!(get(&o, "BOOTSTRAP_PEERS"), None, "an empty list keeps the env");
        assert_eq!(get(&o, "ENABLE_MDNS"), Some("false"));
        assert_eq!(get(&o, "META_SHARE_MAX_CONNS"), None, "blank number keeps the env");
        assert_eq!(get(&o, "META_SHARE_INGRESS_COMMIT_MIN_FREE_BYTES"), Some("10737418240"));
    }

    #[test]
    fn none_disables_the_dht() {
        let o = env_overrides(&json!({ "kad_bootstrap_peers": ["none"] }));
        assert_eq!(get(&o, "KAD_BOOTSTRAP_PEERS"), Some(""));
    }

    #[test]
    fn every_seeded_key_is_in_the_schema() {
        let keys: Vec<String> = schema().fields.into_iter().map(|f| f.key).collect();
        for k in seed().as_object().unwrap().keys() {
            assert!(keys.contains(k), "{k} missing from schema");
        }
    }
}
