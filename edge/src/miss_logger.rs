//! Cache-miss demand logging: every miss becomes one Analytics Engine
//! data point — never a D1 row — so anonymous traffic costs no billed
//! row writes.
//!
//! [`MissLog`] is the writer boundary: the worker implements it over the
//! `STOW_ANALYTICS` dataset binding, and host tests drive the call sites
//! with a recording stub. A point carries artifact identity only — never
//! an IP, a request id, a dependency graph, or a lockfile hash.

use stow_types::api::EnqueueRequest;
use stow_types::identity::CrateName;

use crate::stats::AnalyticsConsent;

/// The `event` blob every point carries — a fixed discriminator so the
/// dataset can grow other event kinds without changing its shape.
const MISS_EVENT: &str = "miss";

/// The lookup surface that observed the miss — the `path` blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissPath {
    /// `GET /api/v1/artifacts/{target}/{rustc_version}/{c_metadata}`: no
    /// row, or a row whose registry bundle turned out stale.
    Exact,
    /// One uncovered node of `POST /api/v1/admissions`.
    Graph,
}

impl MissPath {
    /// The blob value for this path.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Graph => "graph",
        }
    }
}

/// One cache miss — one Analytics Engine data point.
///
/// The blob tuple is fixed-width — `(event, crate_name, version,
/// features_json, target, rustc_version, kind, path)` — and a slot a
/// surface cannot observe stays empty rather than shifting positions.
#[derive(Debug)]
pub struct Miss {
    crate_name: String,
    version: String,
    features_json: String,
    target: String,
    rustc_version: String,
    kind: String,
    path: MissPath,
}

impl Miss {
    /// An exact-key miss: the request identifies the artifact by
    /// `c_metadata`, so the only demand fields it carries are the crate
    /// name (from `?crate=`), the target, and the toolchain.
    pub fn exact(crate_name: &CrateName, target: &str, rustc_version: &str) -> Self {
        Self {
            crate_name: crate_name.as_str().to_owned(),
            version: String::new(),
            features_json: String::new(),
            target: target.to_owned(),
            rustc_version: rustc_version.to_owned(),
            kind: String::new(),
            path: MissPath::Exact,
        }
    }

    /// An uncovered node of a dependency-graph analysis.
    pub fn graph(request: &EnqueueRequest) -> Self {
        Self {
            crate_name: request.crate_name.as_str().to_owned(),
            version: request.version.to_string(),
            features_json: request.features_json.raw(),
            target: request.target.as_str().to_owned(),
            rustc_version: request.rustc_version.as_str().to_owned(),
            kind: String::new(),
            path: MissPath::Graph,
        }
    }

    /// The data point's blob tuple, in the dataset's column order:
    /// `(event, crate_name, version, features_json, target,
    /// rustc_version, kind, path)`.
    pub fn blobs(&self) -> [&str; 8] {
        [
            MISS_EVENT,
            &self.crate_name,
            &self.version,
            &self.features_json,
            &self.target,
            &self.rustc_version,
            &self.kind,
            self.path.as_str(),
        ]
    }

    /// The data point's doubles tuple — every miss counts once.
    pub const DOUBLES: [f64; 1] = [1.0];
}

/// Where miss points go. The worker writes the bound Analytics Engine
/// dataset; host tests record the points they were handed.
pub trait MissLog: Sync {
    /// Record one miss. Infallible at the call site — analytics are a
    /// side channel that must never fail the request that observed the
    /// miss, so the writer reports its own failures. `consent` carries
    /// the request's `STOW_NO_ANALYTICS` opt-out; a refused consent writes
    /// nothing.
    fn write_miss(&self, consent: AnalyticsConsent, miss: &Miss);
}

/// Write one `graph`-path point per uncovered node — each enqueue
/// request the analysis produced is a miss the cache could not cover.
pub fn log_graph_misses(
    log: &impl MissLog,
    consent: AnalyticsConsent,
    requests: &[EnqueueRequest],
) {
    for request in requests {
        log.write_miss(consent, &Miss::graph(request));
    }
}

#[cfg(target_arch = "wasm32")]
impl MissLog for skyzen_cloudflare::worker::AnalyticsEngineDataset {
    fn write_miss(&self, consent: AnalyticsConsent, miss: &Miss) {
        use skyzen_cloudflare::worker::AnalyticsEngineDataPointBuilder;

        if !consent.allowed() {
            return;
        }
        if let Err(error) = AnalyticsEngineDataPointBuilder::new()
            .indexes([miss.crate_name.as_str()])
            .blobs(miss.blobs())
            .doubles(Miss::DOUBLES)
            .write_to(self)
        {
            tracing::warn!(%error, "failed to write miss to Analytics Engine");
        }
    }
}

/// Recording [`MissLog`] for host tests — stores each point's rendered
/// blob tuple so assertions see exactly what the dataset would store.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct RecordingMissLog {
    /// One rendered blob tuple per `write_miss` call.
    pub points: std::sync::Mutex<Vec<[String; 8]>>,
}

#[cfg(test)]
impl MissLog for RecordingMissLog {
    fn write_miss(&self, consent: AnalyticsConsent, miss: &Miss) {
        if !consent.allowed() {
            return;
        }
        self.points
            .lock()
            .expect("recording miss log mutex")
            .push(miss.blobs().map(str::to_owned));
    }
}

#[cfg(test)]
mod tests {
    use stow_types::api::EnqueueRequest;
    use stow_types::identity::{CrateName, CrateVersion, FeaturesJson};

    use super::{Miss, MissLog, RecordingMissLog};
    use crate::stats::AnalyticsConsent;

    const TARGET: &str = "x86_64-unknown-linux-gnu";
    const RUSTC: &str = "1.85.0";

    fn enqueue_request() -> EnqueueRequest {
        EnqueueRequest {
            crate_name: CrateName::parse("serde").expect("name"),
            version: CrateVersion::new(semver::Version::parse("1.0.5").expect("version")),
            features_json: FeaturesJson::canonicalize(vec!["derive".to_owned()]).expect("features"),
            target: TARGET.parse().expect("target"),
            rustc_version: RUSTC.parse().expect("rustc"),
            downloads: 0,
            source: stow_types::api::EnqueueSource::CacheMiss,
            depends_on: Vec::new(),
            preserve_lockfile: false,
        }
    }

    /// The exact surface knows only the crate name, target, and toolchain;
    /// the slots it cannot observe stay empty in the fixed tuple.
    #[test]
    fn exact_miss_point_shape() {
        let miss = Miss::exact(&CrateName::parse("serde").expect("name"), TARGET, RUSTC);
        assert_eq!(
            miss.blobs(),
            [
                "miss",
                "serde",
                "",
                "",
                "x86_64-unknown-linux-gnu",
                "1.85.0",
                "",
                "exact"
            ]
        );
    }

    /// A graph miss names the uncovered package node; the enqueue
    /// request carries no artifact kind, so the slot stays empty.
    #[test]
    fn graph_miss_point_shape() {
        let miss = Miss::graph(&enqueue_request());
        assert_eq!(
            miss.blobs(),
            [
                "miss",
                "serde",
                "1.0.5",
                "[\"derive\"]",
                "x86_64-unknown-linux-gnu",
                "1.85.0",
                "",
                "graph"
            ]
        );
    }

    #[test]
    fn recording_stub_captures_rendered_points() {
        let log = RecordingMissLog::default();
        log.write_miss(
            AnalyticsConsent::ALLOWED,
            &Miss::exact(&CrateName::parse("serde").expect("name"), TARGET, RUSTC),
        );
        log.write_miss(AnalyticsConsent::ALLOWED, &Miss::graph(&enqueue_request()));
        let points = log.points.lock().expect("points").clone();
        assert_eq!(points.len(), 2);
        assert_eq!(points[0][7], "exact");
        assert_eq!(points[1][7], "graph");
    }

    /// A request carrying `x-stow-no-analytics: 1` writes no point —
    /// the consent is checked inside `write_miss` so no call site can
    /// forget it.
    #[test]
    fn denied_consent_writes_nothing() {
        let log = RecordingMissLog::default();
        log.write_miss(
            AnalyticsConsent::DENIED,
            &Miss::exact(&CrateName::parse("serde").expect("name"), TARGET, RUSTC),
        );
        assert!(log.points.lock().expect("points").is_empty());
    }
}
