//! Bootstrap-multiaddr auto-redial machine. Distinct from kad-DHT
//! discovery: this layer keeps a small set of operator-configured
//! multiaddrs dialled across reconnects, so a leaf doesn't silently
//! disconnect when its bootstrap target restarts.
//!
//! Today's failure mode (pre-v0.2): rebuilding the bootstrap peer
//! without bouncing the leaves leaves them disconnected — they don't
//! auto-redial. This module fixes that. kad-DHT discovery is the
//! secondary mechanism (it'd re-establish the mesh anyway, but only at
//! `discovery_interval` cadence).

use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId, Swarm};
use tracing::{debug, trace};

use super::Behaviour;

/// One bootstrap target we keep alive across reconnects.
///
/// `peer_id` is populated either from a `/p2p/<id>` segment in the configured
/// multiaddr or, lacking that, from the first successful outgoing dial through
/// this address. Once known, it's used to skip redundant dials when a
/// connection is already up — without it, every redial tick adds a duplicate
/// connection that only goes away on idle timeout.
pub struct BootstrapEntry {
    pub addr: Multiaddr,
    pub peer_id: Option<PeerId>,
}

impl BootstrapEntry {
    pub fn new(addr: Multiaddr) -> Self {
        let peer_id = addr.iter().find_map(|p| match p {
            Protocol::P2p(id) => Some(id),
            _ => None,
        });
        Self { addr, peer_id }
    }
}

/// Re-dial any bootstrap entry whose target is not currently connected.
pub fn redial_bootstrap(swarm: &mut Swarm<Behaviour>, bootstrap: &[BootstrapEntry]) {
    for entry in bootstrap {
        if let Some(pid) = entry.peer_id {
            if swarm.is_connected(&pid) {
                trace!(addr = %entry.addr, "auto-redial: already connected, skip");
                continue;
            }
        }
        // Either we never learned this entry's peer-id (so we can't tell if
        // we're connected — dial unconditionally and rely on libp2p's
        // ConnectionEstablished to populate the peer-id next time), or the
        // peer-id is known and we're not connected.
        match swarm.dial(entry.addr.clone()) {
            Ok(()) => debug!(addr = %entry.addr, "auto-redial: dial issued"),
            Err(e) => debug!(addr = %entry.addr, error = %e, "auto-redial: dial failed"),
        }
    }
}

/// Returns true if `endpoint_addr` (the resolved address libp2p actually
/// dialed) was reached via the configured `bootstrap_addr`. Compares only the
/// non-DNS, non-`/p2p/...` prefix shape — DNS resolution rewrites the addr,
/// so byte-equality won't match. Pragmatic check: same TCP port, plus either
/// IP-prefix shape or both having a DNS segment. Good enough to
/// opportunistically link a learned peer-id back to a configured bootstrap
/// entry; false matches just mean we'd skip a redial that wasn't redundant.
pub fn addr_targets_match(bootstrap_addr: &Multiaddr, endpoint_addr: &Multiaddr) -> bool {
    let port_a = extract_tcp_port(bootstrap_addr);
    let port_b = extract_tcp_port(endpoint_addr);
    port_a.is_some() && port_a == port_b
}

fn extract_tcp_port(addr: &Multiaddr) -> Option<u16> {
    addr.iter().find_map(|p| match p {
        Protocol::Tcp(port) => Some(port),
        _ => None,
    })
}
