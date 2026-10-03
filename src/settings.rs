//! The `network` section of the hull's `settings.json`, read-only.
//!
//! The hull owns the file (it seeds it from the deprecated env vars on first
//! boot and edits it from the dashboard); this plugin only needs the two
//! endpoints, and falls back to the same env-derived defaults the hull would
//! seed when the file doesn't exist yet.

use std::path::Path;

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
    /// `<config_dir>/settings.json` → `network`, else [`Self::from_env`].
    pub fn load(config_dir: &Path) -> Self {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct File {
            network: Option<NetworkSettings>,
        }
        std::fs::read(config_dir.join("settings.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<File>(&b).ok())
            .and_then(|f| f.network)
            .unwrap_or_else(Self::from_env)
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_network_section_of_the_hulls_file() {
        let d = std::env::temp_dir().join(format!("ipfs-settings-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("settings.json"),
            r#"{"network":{"meta_core_url":"http://mc:9000","peer_url":"https://share.example"},"usenet":{"nntp_host":"x"}}"#,
        )
        .unwrap();
        let n = NetworkSettings::load(&d);
        assert_eq!(n.meta_core_url.as_deref(), Some("http://mc:9000"));
        assert_eq!(n.peer_url.as_deref(), Some("https://share.example"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
