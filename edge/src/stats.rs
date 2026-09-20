//! Privacy-preserving usage statistics: served cache hits and opt-in
//! `stow stats --share` contributions become Analytics Engine data points
//! in the `stow_events` dataset — never D1 rows.
//!
//! Hit points are written at a one-in-ten sample and carry the sample
//! weight as their first double, so published counts are scaled at query
//! time. A point carries artifact and toolchain dimensions only — never
//! an IP, a request id, a dependency graph, or a project name. The sole
//! index is a daily-salted install hash (`hex(HMAC-SHA256(HMAC-SHA256(
//! salt, YYYY-MM-DD), ip))[..16]`), unlinkable across days; the client IP
//! itself is never written anywhere.
//!
//! The pure helpers are host-compilable for unit tests; the request
//! extractors and the dataset writes are wasm-only.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// Header the CLI sets on every edge request when `STOW_NO_ANALYTICS=1`.
pub const NO_ANALYTICS_HEADER: &str = "x-stow-no-analytics";

/// Hit events are written with probability `1 / HIT_SAMPLE_WEIGHT`; the
/// weight itself is stored as the point's first double so aggregate
/// queries scale counts back up.
pub const HIT_SAMPLE_WEIGHT: f64 = 10.0;

/// The `event` blob discriminators.
const HIT_EVENT: &str = "hit";
const SHARE_EVENT: &str = "share";

/// Truncated install-hash length in hex characters.
const INSTALL_HASH_HEX_CHARS: usize = 16;

type InstallMac = Hmac<Sha256>;

/// Whether the request consented to usage analytics — `false` when the
/// client sent `x-stow-no-analytics: 1`. Every analytics write takes the
/// consent as an argument so the opt-out is honoured by construction
/// rather than by remembering a check at each call site.
#[derive(Debug, Clone, Copy)]
pub struct AnalyticsConsent(bool);

impl AnalyticsConsent {
    /// Unconditional consent, for tests that never saw a request.
    #[cfg(test)]
    pub const ALLOWED: Self = Self(true);

    /// Refused consent, for tests exercising the opt-out.
    #[cfg(test)]
    pub const DENIED: Self = Self(false);

    /// Whether analytics may be written for this request.
    pub const fn allowed(self) -> bool {
        self.0
    }
}

/// The serving surface a hit came through — the `surface` blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitSurface {
    /// `GET /api/v1/artifacts/{target}/{rustc_version}/{c_metadata}`.
    Exact,
    /// `POST /api/v1/artifacts/semantic`.
    Semantic,
    /// One `Present` entry of `POST /api/v1/artifacts/batch`.
    Batch,
}

impl HitSurface {
    /// The blob value for this surface.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Semantic => "semantic",
            Self::Batch => "batch",
        }
    }
}

/// One served cache hit — one Analytics Engine data point.
///
/// The blob tuple is `(event, target, rustc_version, crate_name, version,
/// size_bucket, cli_version, os_family, surface)` and the doubles tuple is
/// `(sample_weight, compile_millis, bundle_size)`.
#[derive(Debug)]
pub struct Hit<'a> {
    /// Compilation target triple.
    pub target: &'a str,
    /// Rustc version string.
    pub rustc_version: &'a str,
    /// Crate name of the served row.
    pub crate_name: &'a str,
    /// Crate version of the served row — possibly a semver-compatible
    /// upgrade of the requested version on the semantic surface.
    pub version: &'a str,
    /// Bundle size in bytes.
    pub bundle_size: u64,
    /// Compile milliseconds recorded at register time.
    pub compile_millis: u64,
    /// Serving surface.
    pub surface: HitSurface,
}

/// The blob tuple of one hit point, in dataset column order.
const fn hit_blobs<'a>(hit: &'a Hit<'a>, cli_version: &'a str, os_family: &'a str) -> [&'a str; 9] {
    [
        HIT_EVENT,
        hit.target,
        hit.rustc_version,
        hit.crate_name,
        hit.version,
        size_bucket(hit.bundle_size),
        cli_version,
        os_family,
        hit.surface.as_str(),
    ]
}

/// The doubles tuple of one hit point: sample weight, compile time, and
/// bundle size.
#[expect(
    clippy::cast_precision_loss,
    reason = "Analytics Engine doubles are f64; compile times and bundle sizes are far below 2^53"
)]
const fn hit_doubles(hit: &Hit<'_>) -> [f64; 3] {
    [
        HIT_SAMPLE_WEIGHT,
        hit.compile_millis as f64,
        hit.bundle_size as f64,
    ]
}

/// Coarse bundle-size bucket for the `size_bucket` blob.
pub const fn size_bucket(bytes: u64) -> &'static str {
    const MIB: u64 = 1024 * 1024;
    if bytes < MIB {
        "<1MB"
    } else if bytes < 10 * MIB {
        "1-10MB"
    } else if bytes < 100 * MIB {
        "10-100MB"
    } else {
        ">100MB"
    }
}

/// Parse the `stow-cli/<version> (<os>)` user agent the CLI sends into the
/// `(cli_version, os_family)` dimensions. Anything else — a browser, a
/// missing header — yields two empty strings so foreign traffic never
/// lands in the version leaderboard.
pub fn user_agent_dimensions(user_agent: Option<&str>) -> (&str, &str) {
    let Some(rest) = user_agent.and_then(|value| value.strip_prefix("stow-cli/")) else {
        return ("", "");
    };
    let (version, rest) = rest.split_once(' ').map_or((rest, ""), |(v, r)| (v, r));
    let os = rest
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
        .unwrap_or("");
    (version, os)
}

/// The daily-salted install hash: `hex(HMAC-SHA256(daily, ip))[..16]`
/// where `daily = HMAC-SHA256(salt_secret, day)` and `day` is the current
/// UTC date (`YYYY-MM-DD`). The salt secret never leaves the worker, the
/// derived daily key is never stored, and the IP is hashed inside the
/// worker and never written — so the index counts distinct installs per
/// day and cannot be joined across days.
#[must_use]
pub fn install_hash(salt_secret: &str, day: &str, client_ip: &str) -> String {
    let mut salt_mac = InstallMac::new_from_slice(salt_secret.as_bytes())
        .expect("HMAC accepts keys of any length");
    salt_mac.update(day.as_bytes());
    let daily_secret = salt_mac.finalize().into_bytes();
    let mut mac =
        InstallMac::new_from_slice(&daily_secret).expect("HMAC accepts keys of any length");
    mac.update(client_ip.as_bytes());
    let hash = mac.finalize().into_bytes();
    hex::encode(&hash[..INSTALL_HASH_HEX_CHARS / 2])
}

#[cfg(target_arch = "wasm32")]
mod worker {
    use skyzen::extract::Extractor;
    use skyzen::utils::State;
    use skyzen::{Request, header};
    use skyzen_cloudflare::worker::{AnalyticsEngineDataPointBuilder, AnalyticsEngineDataset};

    use super::{
        AnalyticsConsent, Hit, NO_ANALYTICS_HEADER, SHARE_EVENT, hit_blobs, hit_doubles,
        install_hash, user_agent_dimensions,
    };
    use crate::api::GetArtifactError;

    /// Everything the stats writer needs from one request: consent, the
    /// connecting IP for the install hash, and the `stow-cli` user agent.
    /// Extracted once per request so a handler cannot forget a piece.
    #[derive(Debug, Clone)]
    pub struct HitTelemetry {
        /// Whether analytics may be written for this request.
        pub consent: AnalyticsConsent,
        /// `CF-Connecting-IP`; hashed into the install index and dropped.
        pub client_ip: Option<String>,
        /// The `User-Agent` header, parsed into `cli_version`/`os_family`.
        pub user_agent: Option<String>,
    }

    impl Extractor for AnalyticsConsent {
        type Error = GetArtifactError;

        fn extract(
            request: &mut Request,
        ) -> impl std::future::Future<Output = Result<Self, Self::Error>> + Send {
            let opted_out = request
                .headers()
                .get(NO_ANALYTICS_HEADER)
                .and_then(|value| value.to_str().ok())
                == Some("1");
            std::future::ready(Ok(Self(!opted_out)))
        }
    }

    impl Extractor for HitTelemetry {
        type Error = GetArtifactError;

        fn extract(
            request: &mut Request,
        ) -> impl std::future::Future<Output = Result<Self, Self::Error>> + Send {
            let consent = request
                .headers()
                .get(NO_ANALYTICS_HEADER)
                .and_then(|value| value.to_str().ok())
                != Some("1");
            let client_ip = request
                .headers()
                .get("cf-connecting-ip")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let user_agent = request
                .headers()
                .get(header::USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            std::future::ready(Ok(Self {
                consent: AnalyticsConsent(consent),
                client_ip,
                user_agent,
            }))
        }
    }

    /// The `stow_events` dataset binding plus the salt secret the install
    /// hash is derived from.
    #[derive(Debug, Clone)]
    pub struct StatsContext {
        /// `STOW_STATS` Analytics Engine dataset binding.
        pub dataset: AnalyticsEngineDataset,
        /// `STOW_STATS_SALT_SECRET` Worker secret.
        pub salt_secret: String,
    }

    /// The `StatsContext` plus this request's [`HitTelemetry`] — one
    /// extractor gives every hit path the whole write side, so consent,
    /// identity, and dataset travel together.
    #[derive(Debug, Clone)]
    pub struct StatsSink {
        /// Dataset and salt.
        pub context: StatsContext,
        /// This request's consent, connecting IP, and user agent.
        pub telemetry: HitTelemetry,
    }

    impl Extractor for StatsSink {
        type Error = GetArtifactError;

        async fn extract(request: &mut Request) -> Result<Self, Self::Error> {
            let telemetry = HitTelemetry::extract(request).await?;
            let State(context) = State::<StatsContext>::extract(request)
                .await
                .map_err(|error| GetArtifactError::InternalWithMessage(error.to_string()))?;
            Ok(Self { context, telemetry })
        }
    }

    /// Today's date in UTC (`YYYY-MM-DD`) from `js_sys::Date` — the only
    /// clock the worker runtime exposes.
    fn current_utc_day() -> String {
        let iso = js_sys::Date::new_0()
            .to_iso_string()
            .as_string()
            .unwrap_or_default();
        iso.get(..10).unwrap_or(&iso).to_owned()
    }

    /// Write one hit point — sampled at `1/HIT_SAMPLE_WEIGHT`, indexed by
    /// the daily-salted install hash. Analytics failures never fail the
    /// request that observed the hit.
    pub fn record_hit(sink: &StatsSink, hit: &Hit<'_>) {
        if !sink.telemetry.consent.allowed()
            || js_sys::Math::random() >= 1.0 / super::HIT_SAMPLE_WEIGHT
        {
            return;
        }
        let (cli_version, os_family) = user_agent_dimensions(sink.telemetry.user_agent.as_deref());
        let install_index = sink
            .telemetry
            .client_ip
            .as_deref()
            .map(|ip| install_hash(&sink.context.salt_secret, &current_utc_day(), ip));
        let result = AnalyticsEngineDataPointBuilder::new()
            .indexes(install_index.as_deref().into_iter().collect::<Vec<_>>())
            .blobs(hit_blobs(hit, cli_version, os_family))
            .doubles(hit_doubles(hit))
            .write_to(&sink.context.dataset);
        if let Err(error) = result {
            tracing::warn!(%error, "failed to write hit to Analytics Engine");
        }
    }

    /// Write one `share` point — unsampled, carrying only the aggregate
    /// `cpu_millis_saved` the `stow stats --share` user opted into sending.
    #[expect(
        clippy::cast_precision_loss,
        reason = "Analytics Engine doubles are f64; shared CPU milliseconds are far below 2^53"
    )]
    pub fn record_share(context: &StatsContext, consent: AnalyticsConsent, cpu_millis: u64) {
        if !consent.allowed() {
            return;
        }
        let result = AnalyticsEngineDataPointBuilder::new()
            .blobs([SHARE_EVENT])
            .doubles([1.0, cpu_millis as f64])
            .write_to(&context.dataset);
        if let Err(error) = result {
            tracing::warn!(%error, "failed to write share to Analytics Engine");
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use worker::{StatsContext, StatsSink, record_hit, record_share};

#[cfg(test)]
mod tests {
    use super::{Hit, HitSurface, install_hash, size_bucket, user_agent_dimensions};

    #[test]
    fn size_buckets_partition_the_range() {
        const MIB: u64 = 1024 * 1024;
        assert_eq!(size_bucket(0), "<1MB");
        assert_eq!(size_bucket(MIB - 1), "<1MB");
        assert_eq!(size_bucket(MIB), "1-10MB");
        assert_eq!(size_bucket(10 * MIB - 1), "1-10MB");
        assert_eq!(size_bucket(10 * MIB), "10-100MB");
        assert_eq!(size_bucket(100 * MIB - 1), "10-100MB");
        assert_eq!(size_bucket(100 * MIB), ">100MB");
        assert_eq!(size_bucket(u64::MAX), ">100MB");
    }

    #[test]
    fn user_agent_dimensions_parses_the_cli_shape() {
        assert_eq!(
            user_agent_dimensions(Some("stow-cli/0.5.0 (macos)")),
            ("0.5.0", "macos")
        );
        assert_eq!(
            user_agent_dimensions(Some("stow-cli/0.5.0 (linux)")),
            ("0.5.0", "linux")
        );
        assert_eq!(user_agent_dimensions(Some("stow-cli/0.5.0")), ("0.5.0", ""));
        assert_eq!(user_agent_dimensions(Some("curl/8.0")), ("", ""));
        assert_eq!(user_agent_dimensions(None), ("", ""));
    }

    #[test]
    fn install_hash_is_stable_within_a_day() {
        let first = install_hash("salt", "2026-03-24", "203.0.113.7");
        let second = install_hash("salt", "2026-03-24", "203.0.113.7");
        assert_eq!(first, second);
        assert_eq!(first.len(), 16);
    }

    #[test]
    fn install_hash_rotates_with_the_day() {
        assert_ne!(
            install_hash("salt", "2026-03-24", "203.0.113.7"),
            install_hash("salt", "2026-03-25", "203.0.113.7")
        );
    }

    #[test]
    fn install_hash_differs_per_ip() {
        assert_ne!(
            install_hash("salt", "2026-03-24", "203.0.113.7"),
            install_hash("salt", "2026-03-24", "203.0.113.8")
        );
    }

    #[test]
    fn install_hash_never_contains_the_ip() {
        let ip = "203.0.113.7";
        let hash = install_hash("salt", "2026-03-24", ip);
        assert!(!hash.contains(ip));
        assert!(!ip.contains(&hash));
    }

    #[test]
    fn hit_point_shape_is_fixed() {
        let hit = Hit {
            target: "x86_64-unknown-linux-gnu",
            rustc_version: "1.85.0",
            crate_name: "serde",
            version: "1.0.5",
            bundle_size: 2 * 1024 * 1024,
            compile_millis: 4_200,
            surface: HitSurface::Semantic,
        };
        assert_eq!(
            super::hit_blobs(&hit, "0.5.0", "linux"),
            [
                "hit",
                "x86_64-unknown-linux-gnu",
                "1.85.0",
                "serde",
                "1.0.5",
                "1-10MB",
                "0.5.0",
                "linux",
                "semantic",
            ]
        );
        #[expect(
            clippy::float_cmp,
            reason = "the expected doubles are exact integer values"
        )]
        {
            assert_eq!(super::hit_doubles(&hit), [10.0, 4_200.0, 2_097_152.0]);
        }
    }
}
