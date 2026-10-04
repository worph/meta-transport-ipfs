//! The hull's two endpoints this plugin needs: `peer_url` (announced in
//! identify as `baseUrl=`) and `meta_core_url` (library byte reads).
//!
//! `main` asks the hull (`GET /internal/network`) at boot; when it does not
//! answer, [`NetworkSettings::from_env`] recomputes the same env-derived values
//! the hull seeds its own settings from.

use serde::Deserialize;
use tracing::warn;

/// Same default the hull seeds (`settings::DEFAULT_PEER_URL`).
pub const DEFAULT_PEER_URL: &str = "http://metashare-app:3000";

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct NetworkSettings {
    pub meta_core_url: Option<String>,
    pub peer_url: Option<String>,
}

impl NetworkSettings {
    /// The hull's first-boot seed, recomputed: `META_CORE_URL`, and
    /// `INTERNAL_BASE_URL` → `BASE_URL` → [`DEFAULT_PEER_URL`].
    pub fn from_env() -> Self {
        Self {
            meta_core_url: env_nonempty("META_CORE_URL"),
            peer_url: internal_base_url()
                .or_else(|| env_nonempty("BASE_URL"))
                .map(|u| u.trim_end_matches('/').to_string())
                .or_else(|| Some(DEFAULT_PEER_URL.to_string())),
        }
    }
}

fn internal_base_url() -> Option<String> {
    env_nonempty("INTERNAL_BASE_URL").or_else(|| {
        let legacy = env_nonempty("META_SHARE_PEER_API_URL")?;
        warn!("META_SHARE_PEER_API_URL is deprecated; rename it to INTERNAL_BASE_URL");
        Some(legacy)
    })
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

impl From<meta_feeder_sdk::transport::NetworkInfo> for NetworkSettings {
    fn from(n: meta_feeder_sdk::transport::NetworkInfo) -> Self {
        Self {
            meta_core_url: n.meta_core_url,
            peer_url: n.peer_url,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_env_fallback_always_has_a_peer_url() {
        assert!(NetworkSettings::from_env().peer_url.is_some());
    }
}
