//! The two storage-model helpers bitswap ingress shares with the rest of the
//! `/data` volume. Moved from meta-share's `material.rs` (the material *index*
//! stays in the hull).

use std::path::{Path, PathBuf};

use tracing::debug;

/// `(tmp, cache)`: `META_SHARE_TMP_DIR` / `META_SHARE_CACHE_DIR`, defaulting to
/// `<data>/tmp` and `<data>/cache`. They must share a filesystem — and, in a
/// container, a bind mount — for [`promote_container`]'s `rename(2)`.
pub fn storage_dirs(data_dir: &Path) -> (PathBuf, PathBuf) {
    let tmp = std::env::var("META_SHARE_TMP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| data_dir.join("tmp"));
    let cache = std::env::var("META_SHARE_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| data_dir.join("cache"));
    (tmp, cache)
}

/// Publish `tmp/<cid>/` as `cache/<cid>/` with a single `rename(2)` — the one
/// "these bytes are complete; anyone may read them" transition. A destination
/// that already exists means a concurrent promote won: adopt it.
pub async fn promote_container(tmp_dir: &Path, cache_dir: &Path, cid: &str) -> std::io::Result<PathBuf> {
    let from = tmp_dir.join(cid);
    let to = cache_dir.join(cid);
    if tokio::fs::try_exists(&to).await.unwrap_or(false) {
        return Ok(to);
    }
    if let Some(parent) = to.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    match tokio::fs::rename(&from, &to).await {
        Ok(()) => debug!(cid, from = %from.display(), to = %to.display(), "material: promoted into the cache"),
        Err(e) if to.exists() => {
            debug!(cid, error = %e, "material: promote raced; adopting the existing cache dir")
        }
        Err(e) => return Err(e),
    }
    Ok(to)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn promote_renames_then_adopts() {
        let d = tempfile::tempdir().unwrap();
        let (tmp, cache) = (d.path().join("tmp"), d.path().join("cache"));
        std::fs::create_dir_all(tmp.join("c1")).unwrap();
        std::fs::write(tmp.join("c1/f"), b"x").unwrap();
        let to = promote_container(&tmp, &cache, "c1").await.unwrap();
        assert_eq!(to, cache.join("c1"));
        assert!(to.join("f").exists() && !tmp.join("c1").exists());
        // Second call: destination exists → adopted, no error.
        assert_eq!(promote_container(&tmp, &cache, "c1").await.unwrap(), to);
    }
}
