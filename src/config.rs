//! The ipfs plugin's configuration — the swarm/reachability half of what used to
//! be meta-share's `config.rs`, same variable names. The network *endpoints*
//! (`meta_core_url`, `peer_url`) are read from the hull's `settings.json`
//! (read-only), so identify keeps announcing the **hull's** `baseUrl`.
//!
//! Process-wide configuration assembled from environment variables.
//!
//! Every operator-visible knob is declared here as a typed field on
//! [`Config`]; `Config::from_env()` does all parsing in one place. The
//! repetitive `std::env::var("FOO").ok().and_then(|s| s.parse().ok())
//! .unwrap_or(default)` shape that was scattered through `main.rs` is
//! collapsed via [`env_parse_or`] / [`env_bool_or`].

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use libp2p::Multiaddr;

use crate::swarm::{self, GatewayCapsConfig, KadConfig};

/// Read a parseable env var; fall back to `default` on unset / parse
/// failure. Silently swallows parse errors — the original ladder did the
/// same; tightening is a separate, breaking-change conversation.
fn env_parse_or<T: FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

/// Read a boolean env var. `1/true/yes/on` (case-insensitive) → true;
/// `0/false/no/off` → false; missing → `default`. Anything else is
/// treated as truthy (matches the original `ENABLE_MDNS` semantics).
fn env_bool_or(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(s) => !matches!(s.trim().to_lowercase().as_str(), "0" | "false" | "no" | "off"),
        Err(_) => default,
    }
}


/// Read an env var, treating unset and blank as the same thing (absent).
/// Distinct from `env_multiaddrs`: callers need to tell "operator set this
/// explicitly" apart from "unset", because an explicit setting overrides the
/// mode-derived default.
fn env_opt(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Read a comma-separated env var into a `Vec<Multiaddr>`, propagating
/// the first parse error. Empty / unset → empty vec.
fn env_multiaddrs(name: &str) -> Result<Vec<Multiaddr>> {
    std::env::var(name)
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().parse::<Multiaddr>())
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("{name} must be comma-separated multiaddrs"))
}

/// Local-mode libp2p listen default. Unchanged from the historical default:
/// the port is stable so a sibling container can be pointed at it directly.
const DEFAULT_P2P_LISTEN: &str = "/ip4/0.0.0.0/tcp/4001";
/// Public-mode fallback port, used when `PUBLIC_ADDR` carries no port to
/// copy (a bare `/dns4/host`). Normally the port is lifted off the public
/// addr so the announced and bound ports can't drift.
const DEFAULT_P2P_PORT_PUBLIC: u16 = 4001;

/// Whether this peer is reachable from outside its own network.
///
/// The single switch operators flip. It decides whether the peer
/// *announces itself to the world*:
///
/// - [`NetworkMode::Local`] (default, `PUBLIC_ADDR` unset): mDNS / LAN only.
///   No public-DHT bootstrap, no provider records, no external address.
/// - [`NetworkMode::Public`]: the operator has told us a dialable address.
///   We register it as an external address (identify + kad then carry it),
///   bootstrap into the public DHT, and publish provider records.
///
/// The default matters: a container behind docker's bridge NAT observes only
/// `127.0.0.1` / `172.x` for itself, so a peer that publishes to the public
/// DHT from there advertises a presence it does not have — every peer that
/// finds it burns a dial that can never connect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkMode {
    Local,
    Public(Multiaddr),
}

impl NetworkMode {
    pub fn is_public(&self) -> bool {
        matches!(self, NetworkMode::Public(_))
    }

    pub fn public_addr(&self) -> Option<&Multiaddr> {
        match self {
            NetworkMode::Public(addr) => Some(addr),
            NetworkMode::Local => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            NetworkMode::Local => "local",
            NetworkMode::Public(_) => "public",
        }
    }
}

/// The networking decisions derived from the mode plus any explicit env
/// overrides. Produced by [`resolve_network`] — a pure function, so the whole
/// decision table is unit-testable without touching process env (which
/// matters here: `Config::from_env` also reads settings.json off disk).
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub mode: NetworkMode,
    pub listen_p2p: Multiaddr,
    pub kad_bootstrap_peers: Vec<Multiaddr>,
    pub kad_provide_enabled: bool,
}

/// The whole reachability decision table, as a pure function.
///
/// **An explicitly-set env var always wins over the mode-derived default** —
/// the mode only supplies defaults.
pub fn resolve_network(
    public_addr: Option<String>,
    listen: Option<String>,
    kad_bootstrap: Option<String>,
) -> Result<NetworkConfig> {
    let mode = match public_addr.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        Some(raw) => {
            let addr = raw
                .parse::<Multiaddr>()
                .with_context(|| format!("PUBLIC_ADDR is not a valid multiaddr: {raw}"))?;
            // Loud, not silent: an operator who sets a public address has
            // declared "peers can reach me here". If that can't possibly be
            // true (0.0.0.0, loopback, port 0), publishing it sends every
            // peer that finds us into a dial loop. Refuse to start.
            if !swarm::is_dialable_addr(&addr) {
                anyhow::bail!(
                    "PUBLIC_ADDR={addr} is not dialable by a remote peer \
                     (unspecified/loopback host, or port 0). Set it to the address peers \
                     actually reach this peer on, e.g. /ip4/1.2.3.4/tcp/4001, or leave it \
                     unset to run in local (mDNS-only) mode."
                );
            }
            NetworkMode::Public(addr)
        }
        None => NetworkMode::Local,
    };

    let listen_p2p = match listen.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        Some(raw) => raw
            .parse::<Multiaddr>()
            .with_context(|| format!("P2P_LISTEN must be a valid multiaddr: {raw}"))?,
        None => match &mode {
            NetworkMode::Local => DEFAULT_P2P_LISTEN.parse().expect("hardcoded listen addr"),
            // Bind the port we told the world to reach us on, so the two
            // can't drift.
            NetworkMode::Public(addr) => {
                let port = tcp_port_of(addr).unwrap_or(DEFAULT_P2P_PORT_PUBLIC);
                format!("/ip4/0.0.0.0/tcp/{port}")
                    .parse()
                    .expect("derived public listen addr")
            }
        },
    };

    if let (Some(pub_port), Some(listen_port)) = (
        mode.public_addr().and_then(tcp_port_of),
        tcp_port_of(&listen_p2p),
    ) {
        if pub_port != listen_port {
            tracing::warn!(
                announced_port = pub_port,
                listen_port,
                "PUBLIC_ADDR announces a different port than P2P_LISTEN binds. That is only \
                 correct if a port mapping translates between them."
            );
        }
    }

    // `KAD_BOOTSTRAP_PEERS` set explicitly (to anything, including the `none`
    // sentinel) wins. Unset, the mode decides: a local peer has no business
    // dialing the public IPFS bootstraps.
    let explicit_bootstrap = kad_bootstrap.is_some();
    let kad_bootstrap_peers = match kad_bootstrap {
        Some(raw) => parse_kad_bootstrap_peers(&raw)?,
        None if mode.is_public() => swarm::DEFAULT_KAD_BOOTSTRAPS
            .iter()
            .map(|s| s.parse::<Multiaddr>().expect("hardcoded multiaddr"))
            .collect(),
        None => Vec::new(),
    };

    // Publish provider records only when someone can act on them: we're
    // publicly dialable, OR the operator explicitly pointed us at a DHT (a
    // private/self-hosted one) and so clearly meant to publish. Either way
    // it's moot without a bootstrap peer to publish through.
    let kad_provide_enabled =
        !kad_bootstrap_peers.is_empty() && (mode.is_public() || explicit_bootstrap);

    Ok(NetworkConfig {
        mode,
        listen_p2p,
        kad_bootstrap_peers,
        kad_provide_enabled,
    })
}

/// The TCP port carried by a multiaddr, if any.
fn tcp_port_of(addr: &Multiaddr) -> Option<u16> {
    addr.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::Tcp(port) => Some(port),
        _ => None,
    })
}

/// Parse an explicitly-set `KAD_BOOTSTRAP_PEERS`. The `none`/`off`/`disabled`
/// sentinels mean "no DHT bootstrap at all" (parity with meta-gateway, which
/// has had them all along); a bare empty string means the same.
fn parse_kad_bootstrap_peers(raw: &str) -> Result<Vec<Multiaddr>> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("none")
        || trimmed.eq_ignore_ascii_case("off")
        || trimmed.eq_ignore_ascii_case("disabled")
    {
        return Ok(Vec::new());
    }
    trimmed
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().parse::<Multiaddr>())
        .collect::<Result<Vec<_>, _>>()
        .context("KAD_BOOTSTRAP_PEERS must be comma-separated multiaddrs")
}

/// The ipfs plugin's configuration.
pub struct Config {
    pub listen_p2p: Multiaddr,
    pub http_addr: SocketAddr,
    /// Reachability posture + everything derived from it. See [`NetworkMode`].
    pub network: NetworkConfig,
    pub bootstrap_peers: Vec<Multiaddr>,
    pub redial_interval: Duration,
    pub kad: KadConfig,
    pub enable_mdns: bool,
    pub gateway_caps: GatewayCapsConfig,
    /// The hull's API URL — announced in identify (`baseUrl=`), which is what
    /// peers and gateways call back on.
    pub peer_api_url: Option<String>,
    /// For reading library bytes (refs into meta-core files).
    pub meta_core_url: Option<String>,
    pub files_path_prefix: String,
    pub local_files_root: Option<PathBuf>,
    pub data_dir: PathBuf,
    /// Announce newly-seeded cids on the public DHT (`META_SHARE_SEED_DHT_PROVIDE`).
    pub seed_dht_provide: bool,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        // Reachability posture first — the listen addr, the kad bootstrap
        // list, and whether we publish provider records all fall out of it.
        // `P2P_ANNOUNCE` is the deprecated spelling of `PUBLIC_ADDR`.
        let network = resolve_network(
            env_opt("PUBLIC_ADDR").or_else(|| {
                env_opt("P2P_ANNOUNCE").inspect(|_| {
                    tracing::warn!(
                        "P2P_ANNOUNCE is deprecated; use PUBLIC_ADDR (same value — a \
                         dialable multiaddr)"
                    );
                })
            }),
            env_opt("P2P_LISTEN"),
            // NOT `env_opt`: `KAD_BOOTSTRAP_PEERS=` (set, but empty) is the
            // existing opt-out spelling and must stay an explicit "no
            // bootstraps", not decay into "unset → use the defaults".
            std::env::var("KAD_BOOTSTRAP_PEERS").ok(),
        )?;
        let listen_p2p = network.listen_p2p.clone();

        let http_addr: SocketAddr = std::env::var("HTTP_LISTEN")
            .unwrap_or_else(|_| "0.0.0.0:3000".to_string())
            .parse()
            .context("HTTP_LISTEN must be a valid socket addr (e.g. 0.0.0.0:3000)")?;

        let bootstrap_peers = env_multiaddrs("BOOTSTRAP_PEERS")?;

        // Auto-redial interval. Set to 0 to disable; v0.2 keeps bootstrap
        // multiaddrs alive across drops so a leaf doesn't silently
        // disconnect when its bootstrap target restarts.
        let redial_interval = Duration::from_secs(env_parse_or("BOOTSTRAP_REDIAL_SECS", 30));

        let kad = kad_config_from_env(&network)?;

        // mDNS local-network discovery. Default ON — purely additive.
        // Disable (`ENABLE_MDNS=false`) only on networks that block
        // multicast (some VPNs, some mDNS-isolating switches).
        let enable_mdns = env_bool_or("ENABLE_MDNS", true);

        // Gateway capability fetch. The refresh window is sized to identify's
        // ~5-minute re-announce cadence: a connected gateway is re-fetched
        // roughly once per identify, which keeps the capability inside the peer
        // directory's 600s freshness TTL without a dedicated keep-alive timer.
        let gateway_caps = swarm::GatewayCapsConfig {
            fetch_timeout: Duration::from_secs(env_parse_or(
                "META_SHARE_GATEWAY_CAP_FETCH_TIMEOUT_SECS",
                5,
            )),
            refresh_after: Duration::from_secs(env_parse_or(
                "META_SHARE_GATEWAY_CAP_REFRESH_SECS",
                300,
            )),
        };

        // The network endpoints are the hull's settings (`settings.json`,
        // seeded once from env by the hull). Read-only here; env fallback when
        // the file doesn't exist yet.
        let config_dir: PathBuf = std::env::var("META_SHARE_CONFIG_DIR")
            .unwrap_or_else(|_| "/config".to_string())
            .into();
        let net = crate::settings::NetworkSettings::load(&config_dir);
        let peer_api_url = net
            .peer_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.trim_end_matches('/').to_string());
        let meta_core_url = net
            .meta_core_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let files_path_prefix =
            std::env::var("META_SHARE_FILES_PATH").unwrap_or_else(|_| "/files".to_string());
        let local_files_root = std::env::var("META_SHARE_LOCAL_FILES_PATH")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);
        let data_dir: PathBuf = std::env::var("META_SHARE_DATA")
            .unwrap_or_else(|_| "/data/meta-share".to_string())
            .into();
        let seed_dht_provide = env_bool_or("META_SHARE_SEED_DHT_PROVIDE", network.mode.is_public());

        Ok(Config {
            listen_p2p,
            http_addr,
            network,
            bootstrap_peers,
            redial_interval,
            kad,
            enable_mdns,
            gateway_caps,
            peer_api_url,
            meta_core_url,
            files_path_prefix,
            local_files_root,
            data_dir,
            seed_dht_provide,
        })
    }
}

/// kad-DHT discovery config: namespace, cadences, connection floor.
///
/// The bootstrap list and the provide gate are NOT read here — they are
/// derived from the reachability mode by [`resolve_network`] and passed in,
/// so there is exactly one place that decides whether this peer talks to the
/// public DHT. Cohorts can still override `KAD_NAMESPACE` for isolation, and
/// prepend known cohort peers to `KAD_BOOTSTRAP_PEERS` to speed up cold-start.
fn kad_config_from_env(network: &NetworkConfig) -> Result<KadConfig> {
    let namespace =
        std::env::var("KAD_NAMESPACE").unwrap_or_else(|_| "metamesh-share-default".to_string());
    Ok(KadConfig {
        bootstrap_peers: network.kad_bootstrap_peers.clone(),
        provide_enabled: network.kad_provide_enabled,
        namespace,
        // Provider records expire on remote peers (~24h default); 6h is
        // the kubo default re-publish cadence.
        provide_interval: Duration::from_secs(env_parse_or("KAD_PROVIDE_SECS", 6 * 60 * 60)),
        // 5 min — steady-state topup when at floor.
        discovery_interval: Duration::from_secs(env_parse_or("KAD_DISCOVERY_SECS", 5 * 60)),
        // Faster cadence when we're below the connection floor. Also
        // acts as the rate-limit floor for reactive kicks on
        // `ConnectionClosed`.
        fast_discovery_interval: Duration::from_secs(env_parse_or("KAD_FAST_DISCOVERY_SECS", 60)),
        // Floor, not ceiling: extra connections beyond this aren't dropped.
        target_peer_count: env_parse_or("TARGET_PEER_COUNT", 10),
    })
}


/// The reachability decision table. These assert the *behaviour that keeps a
/// dev box off the public DHT*, so treat a failure here as a real regression,
/// not a stale expectation to update.
#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Option<String> {
        Some(v.to_string())
    }

    /// The headline: with nothing configured, we do NOT touch the public DHT.
    /// Before this change the same input dialed four public bootstrap nodes
    /// and published a provider record from behind docker's NAT.
    #[test]
    fn local_mode_is_the_default_and_publishes_nothing() {
        let n = resolve_network(None, None, None).unwrap();
        assert_eq!(n.mode, NetworkMode::Local);
        assert!(n.kad_bootstrap_peers.is_empty());
        assert!(!n.kad_provide_enabled);
        assert_eq!(n.listen_p2p.to_string(), "/ip4/0.0.0.0/tcp/4001");
    }

    #[test]
    fn public_addr_turns_on_the_dht_and_derives_the_listen_port() {
        let n = resolve_network(s("/ip4/1.2.3.4/tcp/4001"), None, None).unwrap();
        assert!(n.mode.is_public());
        assert_eq!(
            n.kad_bootstrap_peers.len(),
            swarm::DEFAULT_KAD_BOOTSTRAPS.len()
        );
        assert!(n.kad_provide_enabled);
        assert_eq!(n.listen_p2p.to_string(), "/ip4/0.0.0.0/tcp/4001");
    }

    /// Explicit config wins: an operator pointing us at a private DHT means
    /// to publish, even with no public address.
    #[test]
    fn explicit_bootstrap_peers_re_enable_publishing_in_local_mode() {
        let n = resolve_network(
            None,
            None,
            s("/ip4/10.0.0.1/tcp/4001/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN"),
        )
        .unwrap();
        assert_eq!(n.mode, NetworkMode::Local);
        assert_eq!(n.kad_bootstrap_peers.len(), 1);
        assert!(n.kad_provide_enabled);
    }

    /// `KAD_BOOTSTRAP_PEERS=` (set, but empty) was already the opt-out
    /// spelling before this change. It must stay explicit — not decay into
    /// "unset, so use the public defaults".
    #[test]
    fn empty_bootstrap_string_stays_an_explicit_opt_out() {
        let n = resolve_network(s("/ip4/1.2.3.4/tcp/4001"), None, s("")).unwrap();
        assert!(n.mode.is_public());
        assert!(n.kad_bootstrap_peers.is_empty());
        assert!(!n.kad_provide_enabled);
    }

    #[test]
    fn explicit_listen_overrides_the_derived_port() {
        let n = resolve_network(
            s("/ip4/1.2.3.4/tcp/4001"),
            s("/ip4/0.0.0.0/tcp/9999"),
            None,
        )
        .unwrap();
        assert_eq!(n.listen_p2p.to_string(), "/ip4/0.0.0.0/tcp/9999");
    }

    /// The failure this guards against is silent: publish 0.0.0.0 and every
    /// peer that finds you burns a dial forever. Fail startup instead.
    #[test]
    fn undialable_public_addr_is_a_hard_error() {
        for bad in [
            "/ip4/0.0.0.0/tcp/4001",
            "/ip4/127.0.0.1/tcp/4001",
            "/ip4/1.2.3.4/tcp/0",
        ] {
            let err = resolve_network(s(bad), None, None).unwrap_err();
            assert!(
                err.to_string().contains("not dialable"),
                "expected a dialability error for {bad}, got: {err}"
            );
        }
    }
}
