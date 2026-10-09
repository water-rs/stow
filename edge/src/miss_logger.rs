//! Cache-miss demand logging: every miss becomes one Analytics Engine
//! data point — never a D1 row — so anonymous traffic costs no billed
//! row writes.
//!
//! [`MissLog`] is the writer boundary: the worker implements it over the
//! `STOW_ANALYTICS` dataset binding, and host tests drive the call sites
//! with a recording stub. A point carries artifact identity only — never
//! an IP, a request id, a dependency graph, or a lockfile hash.

use stow_types::api::EnqueueRequest;

use crate::stats::AnalyticsConsent;

/// The `event` blob every point carries — a fixed discriminator so the
/// dataset can grow other event kinds without changing its shape.
const MISS_EVENT: &str = "miss";

/// The lookup surface that observed the miss — the `path` blob. Every
/// miss today is a graph miss: the byte path answers digest-addressed
/// blobs and observes no crate identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissPath {
    /// One uncovered node of `POST /api/v1/admissions`.
    Graph,
}

impl MissPath {
    /// The blob value for this path.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Graph => "graph",
        }
    }
}

/// One cache miss — one Analytics Engine data point.
///
/// The blob tuple is fixed-width — `(event, crate_name, version,
/// features_json, target, rustc_version, kind, path, depends_on_json,
/// dependency_identity, host_side, task_id)`
/// — and a slot a surface cannot observe stays empty rather than
/// shifting positions.
#[derive(Debug)]
pub struct Miss {
    crate_name: String,
    version: String,
    features_json: String,
    target: String,
    rustc_version: String,
    kind: String,
    path: MissPath,
    /// The edges the missed unit's compile observed, serialized as a
    /// `Vec<EnqueueDependency>` JSON array — what `preheat missed`
    /// re-mints `depends_on` from (stow#317). Empty when the lookup
    /// surface never saw the graph.
    depends_on_json: String,
    dependency_identity: String,
    host_side: bool,
    /// The missed unit's full contextual task id — `preheat missed`
    /// promotes by id through the submit-by-id route (stow#588). Empty
    /// when the lookup surface never re-derived one.
    task_id: String,
}

impl Miss {
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
            depends_on_json: serde_json::to_string(
                &request.depends_on().expect("subgraph resolves"),
            )
            .expect("enqueue dependencies serialize"),
            dependency_identity: request
                .dependency_identity()
                .expect("derived digest")
                .to_string(),
            host_side: request.host_side,
            task_id: request.task_id().expect("derived task id"),
        }
    }

    /// The data point's blob tuple, in the dataset's column order:
    /// `(event, crate_name, version, features_json, target,
    /// rustc_version, kind, path, depends_on_json, dependency_identity,
    /// host_side, task_id)`.
    pub fn blobs(&self) -> [&str; 12] {
        [
            MISS_EVENT,
            &self.crate_name,
            &self.version,
            &self.features_json,
            &self.target,
            &self.rustc_version,
            &self.kind,
            self.path.as_str(),
            &self.depends_on_json,
            &self.dependency_identity,
            if self.host_side { "true" } else { "false" },
            &self.task_id,
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
    pub points: std::sync::Mutex<Vec<[String; 12]>>,
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
            dependency_subgraph: stow_types::api::TaskSubgraph {
                root_deps: Vec::new(),
                nodes: Vec::new(),
            },
            preserve_lockfile: false,
            host_side: false,
        }
    }

    /// A graph miss names the uncovered package node; the enqueue
    /// request carries no artifact kind, so the slot stays empty.
    #[test]
    fn graph_miss_point_shape() {
        let request = enqueue_request();
        let miss = Miss::graph(&request);
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
                "graph",
                "[]",
                request.dependency_identity().expect("digest").as_str(),
                "false",
                request.task_id().expect("task id").as_str(),
            ]
        );
    }

    /// stow#317: a graph miss's final blob carries the edges the request
    /// minted with, serialized the way `preheat missed` parses them back.
    #[test]
    fn graph_miss_carries_dep_edges() {
        let mut request = enqueue_request();
        request.dependency_subgraph = stow_types::api::TaskSubgraph {
            root_deps: vec![0],
            nodes: vec![stow_types::api::SubgraphNode {
                crate_name: CrateName::parse("syn").expect("dep name"),
                version: CrateVersion::new(semver::Version::parse("3.0.6").expect("dep version")),
                features_json: FeaturesJson::canonicalize(vec!["derive".to_owned()])
                    .expect("dep features"),
                host_side: false,
                deps: Vec::new(),
            }],
        };
        let miss = Miss::graph(&request);
        let blobs = miss.blobs();
        let deps: Vec<stow_types::api::EnqueueDependency> =
            serde_json::from_str(blobs[8]).expect("depends_on blob parses");
        assert_eq!(deps, request.depends_on().expect("deps"));
    }

    #[test]
    fn recording_stub_captures_rendered_points() {
        let log = RecordingMissLog::default();
        log.write_miss(AnalyticsConsent::ALLOWED, &Miss::graph(&enqueue_request()));
        log.write_miss(AnalyticsConsent::ALLOWED, &Miss::graph(&enqueue_request()));
        let points = log.points.lock().expect("points").clone();
        assert_eq!(points.len(), 2);
        assert!(points.iter().all(|point| point[7] == "graph"));
    }

    /// A request carrying `x-stow-no-analytics: 1` writes no point —
    /// the consent is checked inside `write_miss` so no call site can
    /// forget it.
    #[test]
    fn denied_consent_writes_nothing() {
        let log = RecordingMissLog::default();
        log.write_miss(AnalyticsConsent::DENIED, &Miss::graph(&enqueue_request()));
        assert!(log.points.lock().expect("points").is_empty());
    }
}
