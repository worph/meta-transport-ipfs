//! libp2p kad-DHT discovery — peer discovery in `Mode::Client` against
//! the public IPFS DHT. Two responsibilities:
//!
//! 1. **Peer discovery** — periodic `start_providing` / `get_providers`
//!    under a namespace key lets every archivist find every other
//!    archivist without a designated bootstrap node.
//! 2. **CID → peer lookup** for the metadata fetch path (planned;
//!    not wired through the HTTP layer yet).
//!
//! See ADR 0001 §"Operational discovery in v0.2" and the package
//! `CLAUDE.md` "Load-bearing decisions" for the rationale.

use std::time::Duration;

use libp2p::kad::RecordKey;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use sha2::{Digest, Sha256};

/// kad protocol name. Using `/ipfs/kad/1.0.0` so we ride the same DHT as
/// IPFS / kubo and inherit the network-effect of its bootstrap nodes.
/// Cohort isolation is achieved via a unique namespace key, not a unique
/// protocol.
pub const IPFS_KAD_PROTOCOL: &str = "/ipfs/kad/1.0.0";

/// Default kad bootstrap multiaddrs, copied from kubo. Operators can
/// override (or prepend) via the `KAD_BOOTSTRAP_PEERS` env var.
pub const DEFAULT_KAD_BOOTSTRAPS: &[&str] = &[
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
];

/// Compute the kad provider key for a given namespace string.
/// SHA-256 gives uniformly-distributed 32-byte keys, so multiple cohorts
/// don't cluster on the same DHT nodes.
pub fn namespace_key(namespace: &str) -> RecordKey {
    let digest = Sha256::digest(namespace.as_bytes());
    RecordKey::new(&digest.as_slice().to_vec())
}

/// Configuration for the kad-based peer discovery loop.
pub struct KadConfig {
    /// Multiaddrs to seed kad's routing table. Each entry MUST include a
    /// trailing `/p2p/<peer_id>` segment so we can register the peer-id with
    /// the routing table without an extra dial round-trip.
    pub bootstrap_peers: Vec<Multiaddr>,
    /// Namespace string. Hashed to a `RecordKey`; cohort isolation knob.
    pub namespace: String,
    /// How often to (re)publish ourselves as a provider for the namespace
    /// key. Provider records expire on remote peers (default ~24 h), so this
    /// must be lower than that — 6 h is the kubo default.
    pub provide_interval: Duration,
    /// How often to query the DHT for other providers of the namespace key
    /// when the swarm is at or above `target_peer_count`. Steady-state topup
    /// rate; trades discovery latency for DHT-traffic load.
    pub discovery_interval: Duration,
    /// How often to query when the swarm is below `target_peer_count`. Should
    /// be substantially shorter than `discovery_interval` so a peer that
    /// joined cold can fan out quickly. Also acts as the rate-limit floor for
    /// reactive kicks on `ConnectionClosed`.
    pub fast_discovery_interval: Duration,
    /// Connection target — used as both a discovery floor and a soft
    /// ceiling for *new* discovery-driven connections (kadDHT k-bucket
    /// style):
    /// - **Below target**: tick at `fast_discovery_interval`; react to
    ///   `ConnectionClosed` by firing the next kad query immediately.
    /// - **At/above target**: tick at `discovery_interval`; mDNS- and
    ///   kad-discovered peers are added to the kad routing table for
    ///   later lookup but not actively dialled, and inbound
    ///   `IncomingConnection` events are immediately closed.
    ///
    /// "Soft" because it doesn't apply to bootstrap dials or auto-redial
    /// (those are intentional connections), and there's a small race
    /// window where two simultaneous inbounds can both pass the check
    /// before either is established. Also doesn't kick out existing
    /// connections that drift over the cap from outside causes — idle
    /// timeout handles that.
    pub target_peer_count: usize,
    /// Whether to publish the namespace provider record at all. False when
    /// this peer isn't publicly reachable (no `PUBLIC_ADDR`) — a provider
    /// record for an undialable peer is pure pollution: every peer that
    /// walks the DHT and finds us burns a dial that can never connect.
    /// Derived in `config::resolve_network`.
    pub provide_enabled: bool,
}

/// Extract the peer-id from a multiaddr's trailing `/p2p/<id>` segment.
/// Returns `None` if the multiaddr doesn't include one (kad's routing
/// table is keyed by peer-id, so address-only entries can't be registered
/// without a separate identify round-trip).
pub fn peer_id_from_multiaddr(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|p| match p {
        Protocol::P2p(id) => Some(id),
        _ => None,
    })
}

/// Whether a multiaddr is worth handing to a remote peer as somewhere we
/// can be reached.
///
/// A listener bound to `0.0.0.0` reports itself back as `/ip4/0.0.0.0/...`,
/// and an ephemeral bind reports `/tcp/0` — neither is dialable by anyone.
/// Loopback is only dialable by a peer already inside our netns. Publishing
/// any of them (in a kad provider record, in an identify payload) costs
/// every peer that receives it a dial that can never succeed.
///
/// RFC1918 / link-local addresses deliberately PASS: they're exactly what
/// mDNS discovery trades on, and a private cross-host mesh is a legitimate
/// deployment. The public/private distinction is the operator's to make via
/// `PUBLIC_ADDR` — this function only rejects addresses that are undialable
/// by *construction*.
///
/// Mirrors meta-gateway's `swarm::kad_helpers::is_dialable_addr` and
/// meta-search's copy. Duplicated by necessity (independent submodules).
pub fn is_dialable_addr(addr: &Multiaddr) -> bool {
    let mut has_host = false;
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) => {
                if ip.is_unspecified() || ip.is_loopback() {
                    return false;
                }
                has_host = true;
            }
            Protocol::Ip6(ip) => {
                if ip.is_unspecified() || ip.is_loopback() {
                    return false;
                }
                has_host = true;
            }
            Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dnsaddr(_) => {
                has_host = true;
            }
            Protocol::Tcp(0) | Protocol::Udp(0) => return false,
            _ => {}
        }
    }
    has_host
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ma(s: &str) -> Multiaddr {
        s.parse().expect("test multiaddr")
    }

    #[test]
    fn rejects_unspecified_loopback_and_port_zero() {
        assert!(!is_dialable_addr(&ma("/ip4/0.0.0.0/tcp/4001")));
        assert!(!is_dialable_addr(&ma("/ip4/127.0.0.1/tcp/4001")));
        assert!(!is_dialable_addr(&ma("/ip6/::/tcp/4001")));
        assert!(!is_dialable_addr(&ma("/ip6/::1/tcp/4001")));
        assert!(!is_dialable_addr(&ma("/ip4/1.2.3.4/tcp/0")));
    }

    #[test]
    fn accepts_private_and_public_hosts() {
        assert!(is_dialable_addr(&ma("/ip4/172.18.0.5/tcp/4001")));
        assert!(is_dialable_addr(&ma("/ip4/1.2.3.4/tcp/4001")));
        assert!(is_dialable_addr(&ma("/dns4/peer.example.com/tcp/4001")));
    }

    #[test]
    fn rejects_addr_without_a_host_component() {
        assert!(!is_dialable_addr(&ma(
            "/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN"
        )));
    }
}
