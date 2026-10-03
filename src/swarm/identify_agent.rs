//! libp2p `identify` protocol — how meta-share peers learn each other's
//! HTTP API URL.
//!
//! `identify::Behaviour` already exchanges peer-ids, listen addresses,
//! and an `agent_version` string. We overload `agent_version` with
//! whitespace-separated structured tokens:
//!
//! - `baseUrl=<url>` — the peer's HTTP API URL, used by cross-peer
//!   fetches (`/api/peer/:peer_id/file/:cid`) to dial server-to-server.
//!
//! Free-form-string-with-keys is the convention for `agent_version` in
//! libp2p; we'll graduate to a dedicated protocol if the shape starts
//! feeling cramped.

/// Identifier advertised on the identify protocol. Bumping this is harmless;
/// peers identify regardless of the protocol-version string.
pub const IDENTIFY_PROTOCOL: &str = "/meta-share/identify/1.0.0";

/// Token prefix in `identify.agent_version` carrying our HTTP API base URL.
/// Everything from this token to the next whitespace is the URL. Parsed by
/// other peers on `identify::Event::Received` and stored in the peer
/// directory so cross-peer fetches (`/api/peer/:peer_id/file/:cid`) can
/// dial without going through meta-core's filesystem registry.
const AGENT_BASE_URL_TOKEN: &str = "baseUrl=";

/// Construct the identify-protocol agent_version string. Format:
/// `meta-share/<version>` followed by `baseUrl=<url>` if set. Other peers
/// parse the URL via [`parse_base_url`].
pub fn build_agent_version(base_url: Option<&str>) -> String {
    let v = env!("CARGO_PKG_VERSION");
    let mut s = format!("meta-share/{v}");
    if let Some(url) = base_url {
        if !url.is_empty() {
            s.push(' ');
            s.push_str(AGENT_BASE_URL_TOKEN);
            s.push_str(url);
        }
    }
    s
}

/// Extract the HTTP API base URL from a remote peer's `agent_version`.
/// Returns `None` if the field doesn't carry one (consumer-only peer
/// with no `BASE_URL` set, or a non-meta-share peer).
pub fn parse_base_url(agent_version: &str) -> Option<&str> {
    agent_version
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix(AGENT_BASE_URL_TOKEN))
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_agent_version_includes_base_url() {
        let s = build_agent_version(Some("http://x:9"));
        assert!(s.starts_with("meta-share/"));
        assert!(s.contains("baseUrl=http://x:9"));
    }

    #[test]
    fn parse_base_url_extracts_token() {
        let av = "meta-share/0.1.0 baseUrl=http://x:9";
        assert_eq!(parse_base_url(av), Some("http://x:9"));
    }

    #[test]
    fn parse_base_url_returns_none_when_absent() {
        let av = "meta-share/0.1.0";
        assert_eq!(parse_base_url(av), None);
    }
}
