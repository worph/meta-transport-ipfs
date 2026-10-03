//! WebDAV / meta-core path helpers used by `crate::api`. Two
//! responsibilities:
//!
//! - **WebDAV path construction** — percent-encoding, the canonical
//!   `plugin/share/<id>[.<ext>]` layout, and PUT URL building.
//! - **Meta-core `/urls` resolution** — the one-shot lookup that turns a
//!   meta-core base URL into the internal WebDAV URL, cached via
//!   `tokio::sync::OnceCell` for the lifetime of the process.

use anyhow::Context;
use tokio::sync::OnceCell;

/// Percent-encode unreserved-only per RFC 3986 §2.3. Single ASCII path
/// segment in, encoded segment out — callers split on `/` before invoking
/// so the separator survives intact.
pub fn urlencode_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char);
            }
            other => {
                out.push('%');
                out.push_str(&format!("{:02X}", other));
            }
        }
    }
    out
}





/// Lazily resolve meta-core's `webdavUrlInternal` from its `/urls` endpoint
/// and cache the result. `AppState` (in `crate::api`) holds an
/// `Arc<OnceCell<String>>` so a single PUT-time miss costs one round-trip
/// per process. Failures keep the cell empty so a transient meta-core blip
/// can be retried on the next call.
pub async fn resolve_webdav_url(
    http: &reqwest::Client,
    meta_core_url: &str,
    cache: &OnceCell<String>,
) -> anyhow::Result<String> {
    let meta_core_url = meta_core_url.trim_end_matches('/');
    let url = format!("{meta_core_url}/urls");
    cache
        .get_or_try_init(|| async {
            let body: serde_json::Value = http
                .get(&url)
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await
                .with_context(|| format!("GET {url}"))?
                .error_for_status()
                .with_context(|| format!("upstream {url}"))?
                .json()
                .await
                .with_context(|| format!("decode {url}"))?;
            let internal = body
                .get("webdavUrlInternal")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("{url} missing webdavUrlInternal"))?;
            Ok::<_, anyhow::Error>(internal.trim_end_matches('/').to_string())
        })
        .await
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencode_keeps_unreserved() {
        assert_eq!(urlencode_path_segment("Movie-2024_v1.mkv"), "Movie-2024_v1.mkv");
        assert_eq!(urlencode_path_segment("a b c"), "a%20b%20c");
        assert_eq!(urlencode_path_segment("[draft]"), "%5Bdraft%5D");
    }
}
