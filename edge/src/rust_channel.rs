//! Current stable rustc version from the Rust release channel manifest,
//! cached in the scheduler Durable Object so repeated human requests do
//! not re-fetch `channel-rust-stable.toml`.
//!
//! Manifest parsing is host-testable; the wasm fetcher and the one-row
//! `rust_stable_channel` cache follow the `github_app_token`
//! singleton-table shape.

use std::future::Future;

use skyzen_services::durable::DurableDb;
use stow_types::identity::WireRustcVersion;

use crate::errors::{QueueError, RustChannelError};

/// Manifest endpoint for the stable channel.
#[cfg(target_arch = "wasm32")]
const CHANNEL_MANIFEST_URL: &str = "https://static.rust-lang.org/dist/channel-rust-stable.toml";

/// How long a cached channel version is trusted — stable releases ship
/// roughly every six weeks, so an hour is ample.
const CHANNEL_CACHE_TTL_SQL: &str = "-60 minutes";

/// Fetches the stable channel manifest — `CfRustChannel` on wasm, stubs in
/// host tests.
pub trait RustChannelSource: Sync {
    /// GET `channel-rust-stable.toml` as text.
    fn fetch_manifest(&self) -> impl Future<Output = Result<String, RustChannelError>> + Send;
}

/// Parse `[pkg.rustc].version` out of `channel-rust-stable.toml`, reducing
/// the decorated string (`"1.98.1 (hash date)"`) to the semantic numeric
/// portion the queue's `rustc_version` identity column uses.
///
/// # Errors
/// [`RustChannelError::Parse`] when the manifest is not TOML, lacks
/// `pkg.rustc.version`, or the version fails wire validation.
pub fn parse_channel_rustc_version(manifest: &str) -> Result<WireRustcVersion, RustChannelError> {
    let document: toml::Table = toml::from_str(manifest)
        .map_err(|error| RustChannelError::Parse(format!("invalid channel TOML: {error}")))?;
    let raw = document
        .get("pkg")
        .and_then(|pkg| pkg.get("rustc"))
        .and_then(|rustc| rustc.get("version"))
        .and_then(toml::Value::as_str)
        .ok_or_else(|| RustChannelError::Parse("missing pkg.rustc.version".to_owned()))?;
    // The manifest decorates the version with build metadata:
    // `"1.98.1 (04b871bb4 2026-01-01)"` — only the leading semver matters.
    let numeric = raw
        .split_whitespace()
        .next()
        .ok_or_else(|| RustChannelError::Parse(format!("empty pkg.rustc.version `{raw}`")))?;
    let version = semver::Version::parse(numeric).map_err(|error| {
        RustChannelError::Parse(format!("invalid rustc semver `{numeric}`: {error}"))
    })?;
    WireRustcVersion::parse(version.to_string()).map_err(|error| {
        RustChannelError::Parse(format!("invalid rustc version `{numeric}`: {error}"))
    })
}

/// Read the cached stable rustc version, or `None` when no row is stored
/// or the row is older than the TTL.
pub async fn cached_stable_version(
    db: &DurableDb,
) -> Result<Option<WireRustcVersion>, RustChannelError> {
    crate::scheduler::queue::ensure_schema(db).await?;
    let version = db
        .query(
            "SELECT version FROM rust_stable_channel \
             WHERE id = 1 AND fetched_at >= datetime('now', ?)",
        )
        .bind(CHANNEL_CACHE_TTL_SQL.to_owned())
        .fetch_scalar_optional::<String>()
        .await
        .map_err(|error| QueueError::from(format!("load rust_stable_channel: {error}")))?;
    version
        .map(|raw| {
            WireRustcVersion::parse(&raw).map_err(|error| {
                QueueError::Invariant(format!("cached rust stable version `{raw}`: {error}"))
            })
        })
        .transpose()
        .map_err(RustChannelError::from)
}

/// Persist a freshly resolved stable version over the singleton cache row.
pub async fn store_stable_version(
    db: &DurableDb,
    version: &WireRustcVersion,
) -> Result<(), RustChannelError> {
    crate::scheduler::queue::ensure_schema(db).await?;
    db.query(
        "INSERT INTO rust_stable_channel (id, version, fetched_at) \
         VALUES (1, ?, datetime('now')) \
         ON CONFLICT(id) DO UPDATE \
         SET version = excluded.version, fetched_at = excluded.fetched_at",
    )
    .bind(version.as_str().to_owned())
    .execute()
    .await
    .map_err(|error| QueueError::from(format!("store rust_stable_channel: {error}")))?;
    Ok(())
}

/// Resolve the current stable rustc: serve the cached row while it is
/// fresh, otherwise fetch + parse the manifest and refresh the cache.
pub async fn stable_rustc_version(
    db: &DurableDb,
    source: &impl RustChannelSource,
) -> Result<WireRustcVersion, RustChannelError> {
    if let Some(cached) = cached_stable_version(db).await? {
        return Ok(cached);
    }
    let manifest = source.fetch_manifest().await?;
    let version = parse_channel_rustc_version(&manifest)?;
    store_stable_version(db, &version).await?;
    Ok(version)
}

/// Production manifest fetcher bound to `CfFetch`.
#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone, Copy, Default)]
pub struct CfRustChannel;

#[cfg(target_arch = "wasm32")]
impl RustChannelSource for CfRustChannel {
    async fn fetch_manifest(&self) -> Result<String, RustChannelError> {
        use skyzen_cloudflare::worker::send::{IntoSendFuture as _, SendWrapper};

        let request = SendWrapper::new(
            crate::cf_http::bare_request(
                skyzen_cloudflare::worker::Method::Get,
                CHANNEL_MANIFEST_URL,
                &[("User-Agent", "stow-edge/rust-channel")],
                None,
            )
            .map_err(|error| RustChannelError::Fetch(format!("build request: {error}")))?,
        );
        let mut response = SendWrapper::new(
            skyzen_cloudflare::CfFetch
                .request(&request)
                .await
                .map_err(|error| RustChannelError::Fetch(error.to_string()))?,
        );
        let status = response.status_code();
        let body = response
            .text()
            .into_send()
            .await
            .map_err(|error| RustChannelError::Fetch(format!("read body: {error}")))?;
        if !(200..300).contains(&status) {
            return Err(RustChannelError::Fetch(format!("HTTP {status}: {body}")));
        }
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::parse_channel_rustc_version;

    #[test]
    fn parses_rustc_version_from_channel_manifest() {
        let version =
            parse_channel_rustc_version(include_str!("../tests/fixtures/channel-rust-stable.toml"))
                .expect("parse manifest");
        assert_eq!(version.as_str(), "1.98.1");
    }

    #[test]
    fn rejects_manifest_without_rustc_version() {
        assert!(parse_channel_rustc_version("[pkg.cargo]\nversion = \"0.99.0\"\n").is_err());
        assert!(parse_channel_rustc_version("not toml = [").is_err());
        assert!(parse_channel_rustc_version("[pkg.rustc]\nversion = \"bad version!!\"\n").is_err());
    }

    #[test]
    fn rejects_empty_version_string() {
        assert!(
            parse_channel_rustc_version("[pkg.rustc]\nversion = \"\"\n").is_err(),
            "empty version must fail, not produce an empty rustc identity"
        );
    }
}

/// Cache tests: drive `stable_rustc_version` against a real in-memory
/// `SQLite` so the TTL window and the singleton upsert are exercised.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod sqlite_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use stow_types::identity::WireRustcVersion;

    use super::{
        RustChannelSource, cached_stable_version, stable_rustc_version, store_stable_version,
    };
    use crate::errors::RustChannelError;
    use crate::scheduler::test_db::memory_db;

    const MANIFEST: &str = include_str!("../tests/fixtures/channel-rust-stable.toml");

    struct StubRustChannel {
        manifest: &'static str,
        fetches: AtomicUsize,
    }

    impl RustChannelSource for StubRustChannel {
        fn fetch_manifest(
            &self,
        ) -> impl std::future::Future<Output = Result<String, RustChannelError>> + Send {
            self.fetches.fetch_add(1, Ordering::Relaxed);
            std::future::ready(Ok(self.manifest.to_owned()))
        }
    }

    #[tokio::test]
    async fn stable_version_fetches_once_then_serves_cache() {
        let db = memory_db().await.expect("memory db");
        let source = StubRustChannel {
            manifest: MANIFEST,
            fetches: AtomicUsize::new(0),
        };

        let first = stable_rustc_version(&db, &source).await.expect("resolve");
        let second = stable_rustc_version(&db, &source).await.expect("resolve");
        assert_eq!(first.as_str(), "1.98.1");
        assert_eq!(second.as_str(), "1.98.1");
        assert_eq!(
            source.fetches.load(Ordering::Relaxed),
            1,
            "second resolve must hit the cache, not re-fetch"
        );
    }

    #[tokio::test]
    async fn stale_cache_row_is_refreshed() {
        let db = memory_db().await.expect("memory db");
        store_stable_version(&db, &WireRustcVersion::parse("1.90.0").expect("version"))
            .await
            .expect("store");
        // Age the row beyond the 60-minute TTL.
        db.query("UPDATE rust_stable_channel SET fetched_at = datetime('now', '-61 minutes') WHERE id = 1")
            .execute()
            .await
            .expect("age row");
        assert!(
            cached_stable_version(&db).await.expect("cached").is_none(),
            "row past the TTL must not be served"
        );

        let source = StubRustChannel {
            manifest: MANIFEST,
            fetches: AtomicUsize::new(0),
        };
        let resolved = stable_rustc_version(&db, &source).await.expect("resolve");
        assert_eq!(resolved.as_str(), "1.98.1");
        assert_eq!(source.fetches.load(Ordering::Relaxed), 1);
    }
}
