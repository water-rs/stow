//! Current stable rustc version from the Rust release channel manifest,
//! resolved inside the Worker and cached in the Workers Cache API so a
//! site index view or request submission never wakes the scheduler
//! Durable Object.
//!
//! The cache holds the parsed version string rather than the ~900 KB
//! manifest, so a hit is one `WireRustcVersion::parse` over a dozen
//! bytes. Manifest parsing and the cache/fetch flow are host-testable
//! behind the [`RustChannelSource`] and [`ChannelCache`] seams;
//! `CfRustChannel` and the `CfCache` impl are the wasm production sides.

use std::future::Future;

use stow_types::identity::WireRustcVersion;

use crate::errors::RustChannelError;

/// Manifest endpoint for the stable channel.
const CHANNEL_MANIFEST_URL: &str = "https://static.rust-lang.org/dist/channel-rust-stable.toml";

/// Fetches the stable channel manifest — `CfRustChannel` on wasm, stubs in
/// host tests.
pub trait RustChannelSource: Sync {
    /// GET `channel-rust-stable.toml` as text.
    fn fetch_manifest(&self) -> impl Future<Output = Result<String, RustChannelError>> + Send;
}

/// Where [`stable_rustc_version`] keeps the resolved version string —
/// `CfCache` (the Workers Cache API) in production, a stub in tests. The
/// TTL rides on the stored response, so `get` serves only a still-fresh
/// value. Both directions fail loudly: a caller with a broken cache has
/// nothing safe to fall back to.
pub trait ChannelCache: Sync {
    /// The stored version string, or `None` when absent or expired.
    fn get(&self) -> impl Future<Output = Result<Option<Vec<u8>>, RustChannelError>> + Send;

    /// Store `version` under the fixed stable-rustc entry.
    fn put(&self, version: &str) -> impl Future<Output = Result<(), RustChannelError>> + Send;
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

/// Resolve the current stable rustc: serve the version string the cache
/// holds while it is fresh, otherwise fetch the manifest, parse it, and
/// store the version. The fetched manifest parses before it stores, so a
/// malformed manifest fails loudly and never poisons the cache; a stored
/// value that fails validation is itself an error — only validated
/// versions are ever written, so a bad entry means a bug, not a miss.
///
/// # Errors
/// [`RustChannelError::Fetch`] on transport failure,
/// [`RustChannelError::Parse`] when the manifest lacks a parseable
/// `pkg.rustc.version` or the stored value fails validation, and
/// [`RustChannelError::Cache`] (wasm) when the Cache API rejects a read
/// or write.
pub async fn stable_rustc_version(
    cache: &impl ChannelCache,
    source: &impl RustChannelSource,
) -> Result<WireRustcVersion, RustChannelError> {
    if let Some(bytes) = cache.get().await? {
        let text = String::from_utf8(bytes).map_err(|error| {
            RustChannelError::Parse(format!("cached stable rustc version is not UTF-8: {error}"))
        })?;
        return WireRustcVersion::parse(text).map_err(|error| {
            RustChannelError::Parse(format!(
                "cached stable rustc version failed validation: {error}"
            ))
        });
    }
    let manifest = source.fetch_manifest().await?;
    let version = parse_channel_rustc_version(&manifest)?;
    cache.put(version.as_str()).await?;
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
        if !(200..300).contains(&status) {
            return Err(RustChannelError::Fetch(format!("HTTP {status}")));
        }
        response
            .text()
            .into_send()
            .await
            .map_err(|error| RustChannelError::Fetch(format!("read body: {error}")))
    }
}

/// `ChannelCache` over the Workers Cache API — the version string lives
/// under the fixed `{CACHE_DOMAIN}/rustc/stable` entry via
/// `cache::get_stable_rustc`/`put_stable_rustc`, whose `s-maxage` carries
/// the TTL.
#[cfg(target_arch = "wasm32")]
impl ChannelCache for skyzen_cloudflare::CfCache {
    async fn get(&self) -> Result<Option<Vec<u8>>, RustChannelError> {
        crate::cache::get_stable_rustc(self)
            .await
            .map_err(RustChannelError::Cache)
    }

    async fn put(&self, version: &str) -> Result<(), RustChannelError> {
        crate::cache::put_stable_rustc(self, version)
            .await
            .map_err(RustChannelError::Cache)
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{
        ChannelCache, RustChannelError, RustChannelSource, parse_channel_rustc_version,
        stable_rustc_version,
    };

    const MANIFEST: &str = include_str!("../tests/fixtures/channel-rust-stable.toml");

    #[test]
    fn parses_rustc_version_from_channel_manifest() {
        let version = parse_channel_rustc_version(MANIFEST).expect("parse manifest");
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

    /// The version-string cache stub: `get` serves `stored`, `put`
    /// records every store, and the `fail_*` flags inject a failure so
    /// propagation is observable. The injected error stands in for the
    /// wasm-only `Cache` variant — any variant proves it is not
    /// swallowed.
    #[derive(Default)]
    struct StubCache {
        stored: Mutex<Option<Vec<u8>>>,
        gets: AtomicUsize,
        puts: Mutex<Vec<String>>,
        fail_get: bool,
        fail_put: bool,
    }

    impl StubCache {
        fn seeded(version: &str) -> Self {
            Self {
                stored: Mutex::new(Some(version.as_bytes().to_vec())),
                ..Self::default()
            }
        }

        fn broken_read() -> Self {
            Self {
                fail_get: true,
                ..Self::default()
            }
        }

        fn broken_write() -> Self {
            Self {
                fail_put: true,
                ..Self::default()
            }
        }

        fn injected(what: &str) -> RustChannelError {
            RustChannelError::Fetch(format!("injected cache {what} failure"))
        }
    }

    impl ChannelCache for StubCache {
        fn get(&self) -> impl Future<Output = Result<Option<Vec<u8>>, RustChannelError>> + Send {
            self.gets.fetch_add(1, Ordering::Relaxed);
            let out = if self.fail_get {
                Err(Self::injected("read"))
            } else {
                Ok(self.stored.lock().expect("stored").clone())
            };
            std::future::ready(out)
        }

        fn put(&self, version: &str) -> impl Future<Output = Result<(), RustChannelError>> + Send {
            if self.fail_put {
                return std::future::ready(Err(Self::injected("write")));
            }
            *self.stored.lock().expect("stored") = Some(version.as_bytes().to_vec());
            self.puts.lock().expect("puts").push(version.to_owned());
            std::future::ready(Ok(()))
        }
    }

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
    async fn cache_hit_serves_the_stored_version_without_fetching() {
        let cache = StubCache::seeded("1.98.1");
        let source = StubRustChannel {
            manifest: "unreachable",
            fetches: AtomicUsize::new(0),
        };

        let version = stable_rustc_version(&cache, &source)
            .await
            .expect("resolve");

        assert_eq!(version.as_str(), "1.98.1");
        assert_eq!(cache.gets.load(Ordering::Relaxed), 1);
        assert_eq!(
            source.fetches.load(Ordering::Relaxed),
            0,
            "a cache hit never fetches"
        );
        assert!(
            cache.puts.lock().expect("puts").is_empty(),
            "a hit does not re-store"
        );
    }

    #[tokio::test]
    async fn cache_miss_fetches_parses_then_stores_the_version_string() {
        let cache = StubCache::default();
        let source = StubRustChannel {
            manifest: MANIFEST,
            fetches: AtomicUsize::new(0),
        };

        let version = stable_rustc_version(&cache, &source)
            .await
            .expect("resolve");

        assert_eq!(version.as_str(), "1.98.1");
        assert_eq!(source.fetches.load(Ordering::Relaxed), 1);
        assert_eq!(
            cache.puts.lock().expect("puts").as_slice(),
            &["1.98.1"],
            "the cache stores the parsed version, not the manifest"
        );

        // A second resolve reads back what the miss stored.
        let again = stable_rustc_version(&cache, &source)
            .await
            .expect("resolve");
        assert_eq!(again.as_str(), "1.98.1");
        assert_eq!(
            source.fetches.load(Ordering::Relaxed),
            1,
            "the stored version serves the next resolve"
        );
    }

    #[tokio::test]
    async fn a_malformed_manifest_fails_loudly_and_never_stores() {
        let cache = StubCache::default();
        let source = StubRustChannel {
            manifest: "not toml = [",
            fetches: AtomicUsize::new(0),
        };

        let result = stable_rustc_version(&cache, &source).await;

        let Err(error) = result else {
            panic!("a malformed manifest must fail, not resolve");
        };
        assert!(
            matches!(error, RustChannelError::Parse(_)),
            "expected a parse failure, got {error}"
        );
        assert!(
            cache.puts.lock().expect("puts").is_empty(),
            "a malformed manifest never reaches the cache"
        );
        assert_eq!(source.fetches.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn a_stored_value_that_fails_validation_is_an_error() {
        let cache = StubCache::seeded("not a version");
        let source = StubRustChannel {
            manifest: MANIFEST,
            fetches: AtomicUsize::new(0),
        };

        let result = stable_rustc_version(&cache, &source).await;

        let Err(error) = result else {
            panic!("a corrupt cache entry must fail, not refetch");
        };
        assert!(
            matches!(error, RustChannelError::Parse(_)),
            "expected a parse failure, got {error}"
        );
        assert_eq!(
            source.fetches.load(Ordering::Relaxed),
            0,
            "only validated versions are stored, so a bad entry is a bug, never a miss"
        );
    }

    #[tokio::test]
    async fn a_cache_read_failure_propagates() {
        let cache = StubCache::broken_read();
        let source = StubRustChannel {
            manifest: MANIFEST,
            fetches: AtomicUsize::new(0),
        };

        assert!(
            stable_rustc_version(&cache, &source).await.is_err(),
            "a cache read failure is not a miss"
        );
        assert_eq!(source.fetches.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn a_cache_write_failure_propagates() {
        let cache = StubCache::broken_write();
        let source = StubRustChannel {
            manifest: MANIFEST,
            fetches: AtomicUsize::new(0),
        };

        assert!(
            stable_rustc_version(&cache, &source).await.is_err(),
            "a store failure fails the resolve"
        );
        assert_eq!(source.fetches.load(Ordering::Relaxed), 1);
    }
}
