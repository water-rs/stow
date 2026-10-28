//! `stow-admin deploy …` — canary deploy verdicts for the edge Worker.
//!
//! `deploy verdict --phase canary` runs while traffic is split: worker
//! error rate and cpu/wall-time p50/p99 per `scriptVersion`, plus Durable
//! Object requests, errors and wall time per request — the fields
//! `durableObjectsInvocationsAdaptiveGroups` carries `scriptVersion` for.
//!
//! `deploy verdict --phase promoted` runs after promotion to 100%: the
//! metrics with no version dimension — DO cpu/rows from
//! `durableObjectsPeriodicGroups` per DO request from
//! `durableObjectsInvocationsAdaptiveGroups`, both summed over the same
//! bounds — compare two equal DO workload windows the workflow drives
//! (`scripts/deploy-do-workload.sh`): one on the baseline before the deploy,
//! one on the candidate after promotion, each past a warm-up that keeps the
//! reset object's cold first request out. Periodic cpu and rows include
//! work no request triggered (alarms) and organic work; the equal length
//! and equal synthetic schedule put that background into both windows
//! alike, amortised over a denominator the workload dominates. A window
//! under `--min-do-requests` is not compared and fails closed.
//!
//! Both phases read Cloudflare's GraphQL Analytics API with
//! `CLOUDFLARE_API_TOKEN` (Account Analytics read); they neither deploy nor
//! roll back — that is the workflow's job once it has each verdict.
//!
//! Durable Objects under a split deployment behave unlike Worker traffic
//! (developers.cloudflare.com/workers/versions-and-deployments/gradual-deployments/with-durable-objects):
//! every object is *assigned* one version per deployment config — stow's
//! `Scheduler` is a singleton (`idFromName("scheduler")`), so a canary
//! either leaves it on the baseline — candidate DO request count is zero
//! and the DO rows report `skipped`, not breach — or runs it on the
//! candidate outright (the object is reset on reassignment: in-memory
//! state is lost, its `SQLite` storage survives). Account-total DO health
//! is therefore the promoted phase's job.
//!
//! Every field a query selects is in `deploy/schema.rs`, the field lists
//! introspected against the production schema on 2026-09-27 (issue #436
//! review); the tests fail if a query names anything outside them. Still
//! not live-verified: the `scriptName`/`datetime_geq`/`datetime_leq`
//! *filter* arguments (dimension filters are standard across these
//! datasets). The `durableObjectsPeriodicGroups` query is an account
//! total, which assumes stow-edge is the account's only DO-bearing Worker
//! during a deploy window.

#[cfg(test)]
mod schema;

use std::fmt::Write as _;
use std::num::NonZeroU64;

use clap::{Args, Subcommand, ValueEnum};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use stow_types::stow_error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::cloudflare;
use crate::render::{self, Output, Table};

#[derive(Args)]
pub struct DeployArgs {
    #[command(subcommand)]
    pub command: DeployCommand,
}

#[derive(Subcommand)]
pub enum DeployCommand {
    /// Compare a deploy window's metrics against the pre-deploy baseline
    /// window and print a promote/rollback verdict.
    Verdict(VerdictArgs),
}

/// Which half of a split deployment the verdict is judging. The metrics
/// differ because only some datasets carry `scriptVersion`; see the module
/// docs.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum VerdictPhase {
    /// Traffic is split: per-`scriptVersion` worker metrics plus the
    /// versioned DO invocation metrics.
    Canary,
    /// Post-promotion: account-total DO periodic metrics, window
    /// over window.
    Promoted,
}

impl VerdictPhase {
    /// The name the report prints.
    const fn label(self) -> &'static str {
        match self {
            Self::Canary => "canary",
            Self::Promoted => "promoted",
        }
    }
}

#[derive(Args)]
pub struct VerdictArgs {
    /// Which window pair the verdict compares.
    #[arg(long)]
    phase: VerdictPhase,
    /// Cloudflare account tag the Worker lives under.
    #[arg(long)]
    account_tag: String,
    /// Worker script name (`stow-edge`).
    #[arg(long)]
    script: String,
    /// Version id the deploy would replace — the 100% version before upload.
    #[arg(long)]
    baseline_version: String,
    /// Version id under observation.
    #[arg(long)]
    candidate_version: String,
    /// Baseline window, RFC 3339 bounds (`--baseline-from`/`--baseline-to`)
    /// — the canary split for `canary` (split by version), the baseline DO
    /// workload window for `promoted`.
    #[arg(long, value_parser = parse_rfc3339)]
    baseline_from: OffsetDateTime,
    /// See `--baseline-from`.
    #[arg(long, value_parser = parse_rfc3339)]
    baseline_to: OffsetDateTime,
    /// Observation window, RFC 3339 bounds — the canary split for `canary`,
    /// the post-promotion DO workload window for `promoted`.
    #[arg(long, value_parser = parse_rfc3339)]
    candidate_from: OffsetDateTime,
    /// See `--candidate-from`.
    #[arg(long, value_parser = parse_rfc3339)]
    candidate_to: OffsetDateTime,
    /// Minimum worker requests EACH version must have served in its
    /// window — the workflow's synthetic suite pins this many requests to
    /// both sides via version overrides, so organic traffic is never
    /// required for signal. `0` disables the floor. Ignored by
    /// `--phase promoted`.
    #[arg(long, default_value_t = 0)]
    min_requests_per_version: u64,
    /// Minimum Durable Object requests EACH promoted window must carry —
    /// the workflow's DO workload (`scripts/deploy-do-workload.sh`)
    /// schedules more than this into both windows. A window below it
    /// fails closed as `insufficient sample`, so no promoted verdict is
    /// decided by a handful of requests. Required by `--phase promoted`,
    /// ignored by `--phase canary`.
    #[arg(long)]
    min_do_requests: Option<NonZeroU64>,
}

/// One window's bounds, formatted once for both the query variables and
/// the report.
#[derive(Debug, Clone, serde::Serialize)]
struct Window {
    /// RFC 3339 start, inclusive.
    from: String,
    /// RFC 3339 end, inclusive.
    to: String,
}

impl Window {
    fn new(from: OffsetDateTime, to: OffsetDateTime) -> stow_types::error::Result<Self> {
        Ok(Self {
            from: from
                .format(&Rfc3339)
                .map_err(|error| stow_error!("format window start: {error}"))?,
            to: to
                .format(&Rfc3339)
                .map_err(|error| stow_error!("format window end: {error}"))?,
        })
    }
}

/// The baseline and candidate windows a verdict compares.
#[derive(Debug)]
struct Windows {
    baseline: Window,
    candidate: Window,
}

fn parse_rfc3339(raw: &str) -> Result<OffsetDateTime, String> {
    OffsetDateTime::parse(raw, &Rfc3339)
        .map_err(|error| format!("invalid RFC 3339 time `{raw}`: {error}"))
}

/// What "worse" means, per metric: a breach is `candidate > baseline *
/// max_ratio + max_abs_delta`. The additive term keeps a noise-level
/// baseline from failing a deploy on epsilon — an error rate of one
/// failure in `10_000` requests reads infinite next to a baseline of zero.
#[derive(Debug, Clone, Copy)]
struct Threshold {
    /// Largest allowed `candidate / baseline` ratio.
    max_ratio: f64,
    /// Largest allowed `candidate - baseline`, in the metric's unit.
    max_abs_delta: f64,
}

/// One row of the verdict table: a metric, the unit both sides are printed
/// in, the threshold it is held to, and how to read it off a sample.
/// `extract` answers `None` when the window carried no data for the
/// metric — the caller decides whether that is a skip or a breach.
struct MetricSpec<S> {
    /// Table label.
    name: &'static str,
    /// Unit suffix on printed values.
    unit: &'static str,
    /// The breach bound.
    threshold: Threshold,
    /// Read the metric off one window's sample.
    extract: fn(&S) -> Option<f64>,
}

/// The canary verdict's typed threshold table — the deployment policy for
/// a split: a canary may be up to 25–50% slower or carry up to one extra
/// point of error rate before it is rolled back. Wall-time bounds are
/// looser than cpu-time ones because wall time folds in subrequest waits.
const CANARY_THRESHOLDS: &[MetricSpec<CanarySample>] = &[
    MetricSpec {
        name: "worker error rate",
        unit: "err/req",
        threshold: Threshold {
            max_ratio: 2.0,
            max_abs_delta: 0.01,
        },
        extract: |sample| {
            let worker = sample.worker?;
            (worker.requests > 0.0).then(|| worker.errors / worker.requests)
        },
    },
    MetricSpec {
        name: "worker cpu p50",
        unit: "µs",
        threshold: Threshold {
            max_ratio: 1.25,
            max_abs_delta: 50_000.0,
        },
        extract: |sample| Some(sample.worker?.cpu_p50_us),
    },
    MetricSpec {
        name: "worker cpu p99",
        unit: "µs",
        threshold: Threshold {
            max_ratio: 1.25,
            max_abs_delta: 250_000.0,
        },
        extract: |sample| Some(sample.worker?.cpu_p99_us),
    },
    MetricSpec {
        name: "worker wall p50",
        unit: "µs",
        threshold: Threshold {
            max_ratio: 1.5,
            max_abs_delta: 250_000.0,
        },
        extract: |sample| Some(sample.worker?.wall_p50_us),
    },
    MetricSpec {
        name: "worker wall p99",
        unit: "µs",
        threshold: Threshold {
            max_ratio: 1.5,
            max_abs_delta: 500_000.0,
        },
        extract: |sample| Some(sample.worker?.wall_p99_us),
    },
    // DO assignment is per-object, not per-request: the singleton
    // Scheduler either moved to the candidate (its rows exist) or did not
    // (zero candidate DO requests) — in which case these extract `None`
    // and the report marks them `skipped`.
    MetricSpec {
        name: "durable object error rate",
        unit: "err/req",
        threshold: Threshold {
            max_ratio: 2.0,
            max_abs_delta: 0.01,
        },
        extract: |sample| {
            let metrics = sample.do_invocations?;
            (metrics.requests > 0.0).then(|| metrics.errors / metrics.requests)
        },
    },
    MetricSpec {
        name: "durable object wall",
        unit: "µs/req",
        threshold: Threshold {
            max_ratio: 1.5,
            max_abs_delta: 100_000.0,
        },
        extract: |sample| {
            let metrics = sample.do_invocations?;
            (metrics.requests > 0.0).then(|| metrics.wall_us / metrics.requests)
        },
    },
];

/// The promoted verdict's threshold table — account totals, so nothing is
/// versioned and every metric divides by the window's request count.
const PROMOTED_THRESHOLDS: &[MetricSpec<PromotedSample>] = &[
    MetricSpec {
        name: "durable object cpu",
        unit: "µs/req",
        threshold: Threshold {
            max_ratio: 1.25,
            max_abs_delta: 50_000.0,
        },
        extract: |sample| (sample.do_requests > 0.0).then(|| sample.do_cpu_us / sample.do_requests),
    },
    MetricSpec {
        name: "durable object rows read",
        unit: "rows/req",
        threshold: Threshold {
            max_ratio: 1.25,
            max_abs_delta: 1.0,
        },
        extract: |sample| {
            (sample.do_requests > 0.0).then(|| sample.do_rows_read / sample.do_requests)
        },
    },
    MetricSpec {
        name: "durable object rows written",
        unit: "rows/req",
        threshold: Threshold {
            max_ratio: 1.25,
            max_abs_delta: 0.5,
        },
        extract: |sample| {
            (sample.do_requests > 0.0).then(|| sample.do_rows_written / sample.do_requests)
        },
    },
];

/// One metric's measured pair and how it landed against its threshold.
#[derive(Debug, serde::Serialize)]
struct MetricVerdict {
    /// Table label.
    name: &'static str,
    /// Unit suffix.
    unit: &'static str,
    /// The baseline window's value.
    baseline: f64,
    /// The observation window's value.
    candidate: f64,
    /// `baseline * max_ratio + max_abs_delta` — the bound `candidate` must not exceed.
    ceiling: f64,
    /// `pass`, `breach`, `skipped` (no data — only for canary DO metrics,
    /// which may legitimately be absent), `no signal` (fails closed) or
    /// `insufficient sample` (a window under its floor: not judged, and
    /// the verdict fails closed).
    verdict: &'static str,
}

/// Verdict of a row whose window is under its sample floor.
const INSUFFICIENT_SAMPLE: &str = "insufficient sample";

/// One total a window's judgement is computed from.
#[derive(Debug, serde::Serialize)]
struct WindowTotal {
    /// Column label.
    name: &'static str,
    /// Unit suffix.
    unit: &'static str,
    /// The window's total.
    value: f64,
}

/// One window as the report prints it: its bounds and the totals every
/// metric row of the phase is computed from.
#[derive(Debug, serde::Serialize)]
struct WindowSummary {
    /// `baseline` or `candidate`.
    window: &'static str,
    /// The queried bounds.
    #[serde(flatten)]
    bounds: Window,
    /// The totals, in the phase's fixed order.
    totals: Vec<WindowTotal>,
}

/// A phase sample's raw totals, printed beside the metric table so every
/// quotient's numerator and denominator is visible.
trait WindowTotals {
    fn totals(&self) -> Vec<WindowTotal>;
}

/// What `deploy verdict` reports: every metric's pair plus the bottom line.
#[derive(Debug, serde::Serialize)]
struct VerdictReport {
    /// Worker script name.
    script: String,
    /// Which phase ran.
    phase: &'static str,
    /// Version ids compared.
    baseline_version: String,
    /// See `baseline_version`.
    candidate_version: String,
    /// The baseline then the candidate window.
    windows: [WindowSummary; 2],
    /// One row per phase threshold entry.
    metrics: Vec<MetricVerdict>,
    /// Names of metrics that breached or carried no signal.
    breaches: Vec<String>,
    /// Whether the deploy may proceed.
    pass: bool,
}

/// The worker-side numbers one version accumulated over a window.
#[derive(Debug, Clone, Copy)]
struct VersionMetrics {
    /// `sum.requests`.
    requests: f64,
    /// `sum.errors`.
    errors: f64,
    /// `quantiles.cpuTimeP50`, microseconds.
    cpu_p50_us: f64,
    /// `quantiles.cpuTimeP99`, microseconds.
    cpu_p99_us: f64,
    /// `quantiles.wallTimeP50`, microseconds.
    wall_p50_us: f64,
    /// `quantiles.wallTimeP99`, microseconds.
    wall_p99_us: f64,
}

/// One version's DO invocation sums over a window.
#[derive(Debug, Clone, Copy)]
struct DoInvocationMetrics {
    /// `sum.requests`.
    requests: f64,
    /// `sum.errors`.
    errors: f64,
    /// `sum.wallTime`, microseconds total.
    wall_us: f64,
}

/// One canary window's samples, keyed to the version the window belongs to.
/// `worker: None` means the window carried no requests for that version —
/// a canary that served nothing proved nothing, so that breaches as
/// `no signal`.
#[derive(Debug)]
struct CanarySample {
    /// Worker metrics for the window's version.
    worker: Option<VersionMetrics>,
    /// DO invocation metrics for the window's version — `None` when the
    /// Scheduler object was assigned the other version for the whole
    /// window (see the module docs), which the report shows as `skipped`.
    do_invocations: Option<DoInvocationMetrics>,
}

/// One promoted-phase window's account totals — nothing is versioned, so
/// the window itself is the comparison axis.
#[derive(Debug)]
#[allow(clippy::struct_field_names)]
struct PromotedSample {
    /// `durableObjectsInvocationsAdaptiveGroups sum.requests` — the
    /// denominator the DO periodic metrics divide by.
    do_requests: f64,
    /// `durableObjectsPeriodicGroups sum.cpuTime`, microseconds.
    do_cpu_us: f64,
    /// `durableObjectsPeriodicGroups sum.rowsRead`.
    do_rows_read: f64,
    /// `durableObjectsPeriodicGroups sum.rowsWritten`.
    do_rows_written: f64,
}

impl CanarySample {
    /// The asked-for version's rows of one window's canary response.
    fn from_data(data: &CanaryData, version: &str) -> Self {
        Self {
            worker: worker_metrics(&data.workers, version),
            do_invocations: do_invocation_metrics(&data.do_invocations, version),
        }
    }
}

impl WindowTotals for CanarySample {
    /// The window's version only — a version with no row served nothing.
    fn totals(&self) -> Vec<WindowTotal> {
        let worker = |read: fn(&VersionMetrics) -> f64| self.worker.as_ref().map_or(0.0, read);
        let durable =
            |read: fn(&DoInvocationMetrics) -> f64| self.do_invocations.as_ref().map_or(0.0, read);
        vec![
            WindowTotal {
                name: "worker requests",
                unit: "req",
                value: worker(|metrics| metrics.requests),
            },
            WindowTotal {
                name: "worker errors",
                unit: "err",
                value: worker(|metrics| metrics.errors),
            },
            WindowTotal {
                name: "do requests",
                unit: "req",
                value: durable(|metrics| metrics.requests),
            },
            WindowTotal {
                name: "do errors",
                unit: "err",
                value: durable(|metrics| metrics.errors),
            },
            WindowTotal {
                name: "do wall",
                unit: "µs",
                value: durable(|metrics| metrics.wall_us),
            },
        ]
    }
}

impl PromotedSample {
    /// One window's account totals: every group of each dataset summed.
    fn from_data(data: &PromotedData) -> Self {
        let periodic = |read: fn(&DoPeriodicSum) -> f64| -> f64 {
            data.do_periodic.iter().map(|group| read(&group.sum)).sum()
        };
        Self {
            do_requests: data
                .do_requests
                .iter()
                .map(|group| group.sum.requests)
                .sum(),
            do_cpu_us: periodic(|sum| sum.cpu_us),
            do_rows_read: periodic(|sum| sum.rows_read),
            do_rows_written: periodic(|sum| sum.rows_written),
        }
    }
}

impl WindowTotals for PromotedSample {
    fn totals(&self) -> Vec<WindowTotal> {
        vec![
            WindowTotal {
                name: "do requests",
                unit: "req",
                value: self.do_requests,
            },
            WindowTotal {
                name: "do cpu",
                unit: "µs",
                value: self.do_cpu_us,
            },
            WindowTotal {
                name: "do rows read",
                unit: "rows",
                value: self.do_rows_read,
            },
            WindowTotal {
                name: "do rows written",
                unit: "rows",
                value: self.do_rows_written,
            },
        ]
    }
}

// ---- GraphQL wire shapes -------------------------------------------------

/// What the canary query returns.
#[derive(Debug, Deserialize)]
struct CanaryData {
    /// `workersInvocationsAdaptive`, one row per `scriptVersion`.
    #[serde(rename = "workersInvocationsAdaptive")]
    workers: Vec<WorkerGroup>,
    /// `durableObjectsInvocationsAdaptiveGroups`, one row per
    /// `scriptVersion`.
    #[serde(rename = "durableObjectsInvocationsAdaptiveGroups")]
    do_invocations: Vec<DoInvocationGroup>,
}

/// What the promoted query returns.
#[derive(Debug, Deserialize)]
struct PromotedData {
    /// `durableObjectsPeriodicGroups` — account totals, no version axis.
    #[serde(rename = "durableObjectsPeriodicGroups")]
    do_periodic: Vec<DoPeriodicGroup>,
    /// `durableObjectsInvocationsAdaptiveGroups` — used only for the
    /// request denominator.
    #[serde(rename = "durableObjectsInvocationsAdaptiveGroups")]
    do_requests: Vec<RequestsGroup>,
}

#[derive(Debug, Deserialize)]
struct WorkerGroup {
    /// The dimensions the query selected.
    dimensions: WorkerDimensions,
    /// Sums for the group.
    sum: WorkerSum,
    /// Quantiles for the group.
    quantiles: WorkerQuantiles,
}

#[derive(Debug, Deserialize)]
struct WorkerDimensions {
    /// The deployed version id.
    #[serde(rename = "scriptVersion")]
    script_version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WorkerSum {
    /// Requests served.
    requests: f64,
    /// Errored requests.
    errors: f64,
}

#[derive(Debug, Deserialize)]
struct WorkerQuantiles {
    /// Median cpu time, microseconds.
    #[serde(rename = "cpuTimeP50")]
    cpu_p50: f64,
    /// p99 cpu time, microseconds.
    #[serde(rename = "cpuTimeP99")]
    cpu_p99: f64,
    /// Median wall time, microseconds.
    #[serde(rename = "wallTimeP50")]
    wall_p50: f64,
    /// p99 wall time, microseconds.
    #[serde(rename = "wallTimeP99")]
    wall_p99: f64,
}

#[derive(Debug, Deserialize)]
struct DoInvocationGroup {
    /// The dimensions the query selected.
    dimensions: WorkerDimensions,
    /// Sums for the group.
    sum: DoInvocationSum,
}

#[derive(Debug, Deserialize)]
struct DoInvocationSum {
    /// DO requests served.
    requests: f64,
    /// Errored DO requests.
    errors: f64,
    /// Total wall time, microseconds.
    #[serde(rename = "wallTime")]
    wall_us: f64,
}

#[derive(Debug, Deserialize)]
struct DoPeriodicGroup {
    /// Sums for the group; no dimensions are selected, so each group is an
    /// account total over its grouping granularity.
    sum: DoPeriodicSum,
}

#[derive(Debug, Deserialize)]
struct DoPeriodicSum {
    /// Total cpu time, microseconds.
    #[serde(rename = "cpuTime")]
    cpu_us: f64,
    /// Storage rows read.
    #[serde(rename = "rowsRead")]
    rows_read: f64,
    /// Storage rows written.
    #[serde(rename = "rowsWritten")]
    rows_written: f64,
}

/// A group carrying only `sum.requests` — the denominator rows.
#[derive(Debug, Deserialize)]
struct RequestsGroup {
    /// Sums for the group.
    sum: RequestsSum,
}

#[derive(Debug, Deserialize)]
struct RequestsSum {
    /// Requests served.
    requests: f64,
}

/// The variables both verdict queries take.
#[derive(Debug, serde::Serialize)]
struct WindowVars<'a> {
    account: &'a str,
    script: &'a str,
    from: &'a str,
    to: &'a str,
}

/// The canary query: both versioned datasets, both bounds, one round trip.
/// Selecting only `dimensions { scriptVersion }` makes Cloudflare return
/// one row per deployed version. The DO dataset is filtered by datetime
/// alone — `scriptName` is not among its confirmed dimensions — so it is
/// an account total like every other DO dataset (see module docs).
const CANARY_QUERY: &str = include_str!("../queries/deploy-canary.graphql");

/// The promoted query: the unversioned datasets, account totals, one round
/// trip — `durableObjectsPeriodicGroups` for the numerators, the
/// invocation datasets for the request denominators.
const PROMOTED_QUERY: &str = include_str!("../queries/deploy-promoted.graphql");

pub async fn run(args: DeployArgs, output: Output) -> stow_types::error::Result<()> {
    match args.command {
        DeployCommand::Verdict(args) => verdict(args, output).await,
    }
}

async fn verdict(args: VerdictArgs, output: Output) -> stow_types::error::Result<()> {
    if args.baseline_from >= args.baseline_to || args.candidate_from >= args.candidate_to {
        return Err(stow_error!(
            "each window's --*-from must precede its --*-to"
        ));
    }
    let windows = Windows {
        baseline: Window::new(args.baseline_from, args.baseline_to)?,
        candidate: Window::new(args.candidate_from, args.candidate_to)?,
    };
    let token = cloudflare::api_token()?;

    let report = match args.phase {
        VerdictPhase::Canary => {
            let (baseline, candidate): (CanaryData, CanaryData) = futures_util::try_join!(
                fetch_window(&token, &args, CANARY_QUERY, &windows.baseline),
                fetch_window(&token, &args, CANARY_QUERY, &windows.candidate),
            )?;
            evaluate_canary(
                &args,
                &windows,
                &CanarySample::from_data(&baseline, &args.baseline_version),
                &CanarySample::from_data(&candidate, &args.candidate_version),
            )
        }
        VerdictPhase::Promoted => {
            let min_do_requests = args.min_do_requests.ok_or_else(|| {
                stow_error!(
                    "--phase promoted needs --min-do-requests: an unfloored window \
                     lets a single DO request decide the verdict"
                )
            })?;
            let (baseline, candidate): (PromotedData, PromotedData) = futures_util::try_join!(
                fetch_window(&token, &args, PROMOTED_QUERY, &windows.baseline),
                fetch_window(&token, &args, PROMOTED_QUERY, &windows.candidate),
            )?;
            evaluate_promoted(
                &args,
                &windows,
                min_do_requests,
                &PromotedSample::from_data(&baseline),
                &PromotedSample::from_data(&candidate),
            )
        }
    };
    emit(&report, output)?;
    if report.pass {
        Ok(())
    } else {
        Err(stow_error!(
            "deploy verdict FAIL — breached: {}",
            report.breaches.join(", ")
        ))
    }
}

/// POST one analytics query for one window and unwrap
/// `data.viewer.accounts[0]`.
async fn fetch_window<D: DeserializeOwned>(
    token: &str,
    args: &VerdictArgs,
    query: &'static str,
    window: &Window,
) -> stow_types::error::Result<D> {
    let variables = WindowVars {
        account: &args.account_tag,
        script: &args.script,
        from: &window.from,
        to: &window.to,
    };
    cloudflare::query_account(token, query, &variables)
        .await
        .map_err(|error| stow_error!("{error}"))
}

/// The worker row for `version`, or `None` when the window holds no row
/// for it (the version served no requests).
fn worker_metrics(groups: &[WorkerGroup], version: &str) -> Option<VersionMetrics> {
    groups
        .iter()
        .find(|group| group.dimensions.script_version.as_deref() == Some(version))
        .map(|group| VersionMetrics {
            requests: group.sum.requests,
            errors: group.sum.errors,
            cpu_p50_us: group.quantiles.cpu_p50,
            cpu_p99_us: group.quantiles.cpu_p99,
            wall_p50_us: group.quantiles.wall_p50,
            wall_p99_us: group.quantiles.wall_p99,
        })
}

/// The DO invocation row for `version`, or `None` — a per-object version
/// assignment means the Scheduler may not have run on `version` at all
/// during the window.
fn do_invocation_metrics(
    groups: &[DoInvocationGroup],
    version: &str,
) -> Option<DoInvocationMetrics> {
    groups
        .iter()
        .find(|group| group.dimensions.script_version.as_deref() == Some(version))
        .map(|group| DoInvocationMetrics {
            requests: group.sum.requests,
            errors: group.sum.errors,
            wall_us: group.sum.wall_us,
        })
}

/// Apply a phase's threshold table to a baseline/candidate pair. A metric
/// whose extract answers `None` — the DO not being assigned to a version
/// during a canary — reports `skipped`, not `breach`: the absent data is
/// expected, not an unproven gate. Each window's totals ride along so the
/// report shows what every quotient was computed from.
fn apply_thresholds<S: WindowTotals>(
    phase: VerdictPhase,
    specs: &[MetricSpec<S>],
    args: &VerdictArgs,
    windows: &Windows,
    baseline: &S,
    candidate: &S,
) -> VerdictReport {
    let mut metrics = Vec::new();
    let mut breaches = Vec::new();
    for spec in specs {
        let (Some(base), Some(cand)) = ((spec.extract)(baseline), (spec.extract)(candidate)) else {
            metrics.push(MetricVerdict {
                name: spec.name,
                unit: spec.unit,
                baseline: f64::NAN,
                candidate: f64::NAN,
                ceiling: f64::NAN,
                verdict: "skipped",
            });
            continue;
        };
        let ceiling = base.mul_add(spec.threshold.max_ratio, spec.threshold.max_abs_delta);
        let ok = cand <= ceiling;
        if !ok {
            breaches.push(spec.name.to_owned());
        }
        metrics.push(MetricVerdict {
            name: spec.name,
            unit: spec.unit,
            baseline: base,
            candidate: cand,
            ceiling,
            verdict: if ok { "pass" } else { "breach" },
        });
    }
    VerdictReport {
        script: args.script.clone(),
        phase: phase.label(),
        baseline_version: args.baseline_version.clone(),
        candidate_version: args.candidate_version.clone(),
        windows: [
            WindowSummary {
                window: "baseline",
                bounds: windows.baseline.clone(),
                totals: baseline.totals(),
            },
            WindowSummary {
                window: "candidate",
                bounds: windows.candidate.clone(),
                totals: candidate.totals(),
            },
        ],
        metrics,
        pass: breaches.is_empty(),
        breaches,
    }
}

/// A request floor as the `f64` the analytics counts are compared in.
fn floor_f64(floor: u64) -> f64 {
    f64::from(u32::try_from(floor).unwrap_or(u32::MAX))
}

/// The canary verdict. The worker row for the candidate must exist and
/// have served requests — a canary that produced no worker signal proved
/// nothing and fails closed. The DO rows may legitimately be absent (the
/// Scheduler stayed on the baseline) and report `skipped` instead.
fn evaluate_canary(
    args: &VerdictArgs,
    windows: &Windows,
    baseline: &CanarySample,
    candidate: &CanarySample,
) -> VerdictReport {
    let mut report = apply_thresholds(
        VerdictPhase::Canary,
        CANARY_THRESHOLDS,
        args,
        windows,
        baseline,
        candidate,
    );
    let no_worker_signal = candidate.worker.is_none_or(|worker| worker.requests <= 0.0)
        || baseline.worker.is_none_or(|worker| worker.requests <= 0.0);
    let min = floor_f64(args.min_requests_per_version);
    let insufficient_sample = !no_worker_signal
        && (candidate.worker.is_some_and(|worker| worker.requests < min)
            || baseline.worker.is_some_and(|worker| worker.requests < min));
    if no_worker_signal || insufficient_sample {
        let verdict = if no_worker_signal {
            "no signal"
        } else {
            INSUFFICIENT_SAMPLE
        };
        report.metrics.insert(
            0,
            MetricVerdict {
                name: "worker signal",
                unit: "req",
                baseline: baseline.worker.map_or(f64::NAN, |worker| worker.requests),
                candidate: candidate.worker.map_or(f64::NAN, |worker| worker.requests),
                ceiling: min,
                verdict,
            },
        );
        report
            .breaches
            .insert(0, format!("worker signal ({verdict})"));
        report.pass = false;
    }
    report
}

/// The promoted verdict: window-over-window comparison of account totals,
/// gated on both windows carrying at least `min_do_requests` DO requests.
/// The first row always reports both windows' DO request counts against
/// that floor. A window under it is not compared: every DO row reads
/// `insufficient sample` instead of a pass or breach its few requests
/// would decide, and the verdict fails closed — the workflow's DO
/// workload did not land, so nothing is known about the candidate.
fn evaluate_promoted(
    args: &VerdictArgs,
    windows: &Windows,
    min_do_requests: NonZeroU64,
    baseline: &PromotedSample,
    candidate: &PromotedSample,
) -> VerdictReport {
    let mut report = apply_thresholds(
        VerdictPhase::Promoted,
        PROMOTED_THRESHOLDS,
        args,
        windows,
        baseline,
        candidate,
    );
    let min = floor_f64(min_do_requests.get());
    let insufficient = baseline.do_requests < min || candidate.do_requests < min;
    if insufficient {
        for metric in &mut report.metrics {
            metric.verdict = INSUFFICIENT_SAMPLE;
        }
        report.breaches = vec![format!("durable object sample ({INSUFFICIENT_SAMPLE})")];
        report.pass = false;
    }
    report.metrics.insert(
        0,
        MetricVerdict {
            name: "durable object sample",
            unit: "req",
            baseline: baseline.do_requests,
            candidate: candidate.do_requests,
            ceiling: min,
            verdict: if insufficient {
                INSUFFICIENT_SAMPLE
            } else {
                "pass"
            },
        },
    );
    report
}

/// Emit the report: `--json` gets the structured verdict, the human output
/// prints each window's bounds and totals, then every metric's pair,
/// ceiling (a floor on the sample rows) and verdict.
fn emit(report: &VerdictReport, output: Output) -> stow_types::error::Result<()> {
    render::emit(output, report, render_report)
}

/// The human rendering `emit` prints.
fn render_report(report: &VerdictReport) -> String {
    let mut out = format!(
        "deploy verdict [{}] {}  {} -> {}\n",
        report.phase,
        if report.pass { "PASS" } else { "FAIL" },
        report.baseline_version,
        report.candidate_version,
    );
    let total_headers: Vec<String> = report.windows[0]
        .totals
        .iter()
        .map(|total| format!("{} ({})", total.name, total.unit))
        .collect();
    let mut headers = vec!["window", "from", "to"];
    headers.extend(total_headers.iter().map(String::as_str));
    let mut windows = Table::new(&headers);
    for window in &report.windows {
        windows.push(
            [
                window.window.to_owned(),
                window.bounds.from.clone(),
                window.bounds.to.clone(),
            ]
            .into_iter()
            .chain(
                window
                    .totals
                    .iter()
                    .map(|total| format!("{:.0}", total.value)),
            ),
        );
    }
    let _ = writeln!(out, "{}", windows.render());
    let mut table = Table::new(&["metric", "baseline", "candidate", "ceiling", "verdict"]);
    for metric in &report.metrics {
        table.push([
            metric.name.to_owned(),
            format!("{:.4} {}", metric.baseline, metric.unit),
            format!("{:.4} {}", metric.candidate, metric.unit),
            format!("{:.4}", metric.ceiling),
            metric.verdict.to_owned(),
        ]);
    }
    let _ = writeln!(out, "{}", table.render());
    out.trim_end().to_owned()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use std::num::NonZeroU64;

    use super::{
        CANARY_QUERY, CANARY_THRESHOLDS, CanaryData, CanarySample, INSUFFICIENT_SAMPLE,
        PROMOTED_QUERY, PROMOTED_THRESHOLDS, PromotedData, PromotedSample, VerdictPhase,
        VerdictReport, Window, Windows, apply_thresholds, evaluate_canary, evaluate_promoted,
        parse_rfc3339, render_report, schema,
    };
    use crate::deploy::VerdictArgs;

    /// The promoted floor the tests hold windows to — the workflow's
    /// `MIN_DO_SAMPLE_REQUESTS`.
    const MIN_DO_REQUESTS: NonZeroU64 = NonZeroU64::new(280).expect("non-zero");

    fn args() -> VerdictArgs {
        VerdictArgs {
            phase: VerdictPhase::Canary,
            account_tag: "acct".to_owned(),
            script: "stow-edge".to_owned(),
            baseline_version: "old".to_owned(),
            candidate_version: "new".to_owned(),
            baseline_from: parse_rfc3339("2026-09-28T00:00:00Z").expect("from"),
            baseline_to: parse_rfc3339("2026-09-28T00:15:00Z").expect("to"),
            candidate_from: parse_rfc3339("2026-09-28T00:15:00Z").expect("from"),
            candidate_to: parse_rfc3339("2026-09-28T00:30:00Z").expect("to"),
            min_requests_per_version: 0,
            min_do_requests: None,
        }
    }

    fn windows() -> Windows {
        let args = args();
        Windows {
            baseline: Window::new(args.baseline_from, args.baseline_to).expect("baseline"),
            candidate: Window::new(args.candidate_from, args.candidate_to).expect("candidate"),
        }
    }

    fn promoted_args() -> VerdictArgs {
        let mut args = args();
        args.phase = VerdictPhase::Promoted;
        args.min_do_requests = Some(MIN_DO_REQUESTS);
        args
    }

    fn canary(baseline: &CanarySample, candidate: &CanarySample) -> VerdictReport {
        evaluate_canary(&args(), &windows(), baseline, candidate)
    }

    fn promoted(baseline: &PromotedSample, candidate: &PromotedSample) -> VerdictReport {
        evaluate_promoted(
            &promoted_args(),
            &windows(),
            MIN_DO_REQUESTS,
            baseline,
            candidate,
        )
    }

    // ---- fixtures: real field names only (schema.rs is the source of truth)

    /// A `data.viewer.accounts[0]` document the way `CANARY_QUERY` returns
    /// it: worker and DO rows per `scriptVersion`.
    fn canary_data(
        worker_groups: &serde_json::Value,
        do_groups: &serde_json::Value,
    ) -> serde_json::Value {
        json!({
            "viewer": { "accounts": [{
                "workersInvocationsAdaptive": worker_groups.clone(),
                "durableObjectsInvocationsAdaptiveGroups": do_groups.clone(),
            }] }
        })
    }

    fn worker_group(
        version: &str,
        requests: f64,
        errors: f64,
        cpu_p50: f64,
        cpu_p99: f64,
        wall_p50: f64,
        wall_p99: f64,
    ) -> serde_json::Value {
        json!({
            "dimensions": { "scriptVersion": version },
            "sum": { "requests": requests, "errors": errors },
            "quantiles": {
                "cpuTimeP50": cpu_p50,
                "cpuTimeP99": cpu_p99,
                "wallTimeP50": wall_p50,
                "wallTimeP99": wall_p99,
            },
        })
    }

    /// `durableObjectsInvocationsAdaptiveGroups` rows: the introspected
    /// `sum` is `errors requests responseBodySize wallTime`.
    fn do_invocation_group(
        version: &str,
        requests: f64,
        errors: f64,
        wall: f64,
    ) -> serde_json::Value {
        json!({
            "dimensions": { "scriptVersion": version },
            "sum": {
                "requests": requests,
                "errors": errors,
                "responseBodySize": requests * 128.0,
                "wallTime": wall,
            },
        })
    }

    /// A `data.viewer.accounts[0]` document the way `PROMOTED_QUERY`
    /// returns it: account totals.
    fn promoted_data(periodic_sum: &serde_json::Value, do_requests: f64) -> serde_json::Value {
        json!({
            "viewer": { "accounts": [{
                "durableObjectsPeriodicGroups": [{ "sum": periodic_sum.clone() }],
                "durableObjectsInvocationsAdaptiveGroups": [{ "sum": { "requests": do_requests } }],
            }] }
        })
    }

    /// `durableObjectsPeriodicGroups` rows: the introspected `sum` fields
    /// include `cpuTime`, `rowsRead`, `rowsWritten` among many.
    fn periodic_sum(cpu: f64, read: f64, written: f64) -> serde_json::Value {
        json!({
            "cpuTime": cpu,
            "rowsRead": read,
            "rowsWritten": written,
            "activeTime": cpu * 2.0,
            "duration": cpu * 3.0,
            "exceededCpuErrors": 0.0,
            "exceededMemoryErrors": 0.0,
            "fatalInternalErrors": 0.0,
            "inboundWebsocketMsgCount": 0.0,
            "outboundWebsocketMsgCount": 0.0,
            "storageDeletes": 0.0,
            "storageReadUnits": read,
            "storageWriteUnits": written,
            "subrequests": 0.0,
        })
    }

    /// Decode a canary fixture through the real wire types — the same
    /// parse the live response takes.
    fn canary_sample(data: &serde_json::Value, version: &str) -> CanarySample {
        let data: CanaryData =
            serde_json::from_value(data["viewer"]["accounts"][0].clone()).expect("decode");
        CanarySample::from_data(&data, version)
    }

    /// Decode a promoted fixture into its account totals.
    fn promoted_sample(data: &serde_json::Value) -> PromotedSample {
        let data: PromotedData =
            serde_json::from_value(data["viewer"]["accounts"][0].clone()).expect("decode");
        PromotedSample::from_data(&data)
    }

    /// Healthy canary windows: candidate close to baseline everywhere.
    fn canary_samples() -> (CanarySample, CanarySample) {
        let baseline = canary_sample(
            &canary_data(
                &json!([worker_group(
                    "old", 100_000.0, 50.0, 400.0, 2_000.0, 20_000.0, 80_000.0
                )]),
                &json!([do_invocation_group("old", 10_000.0, 5.0, 500_000_000.0)]),
            ),
            "old",
        );
        let candidate = canary_sample(
            &canary_data(
                &json!([
                    worker_group("old", 95_000.0, 40.0, 410.0, 2_100.0, 21_000.0, 82_000.0),
                    worker_group("new", 5_000.0, 3.0, 420.0, 2_200.0, 22_000.0, 84_000.0),
                ]),
                &json!([do_invocation_group("new", 10_500.0, 6.0, 520_000_000.0)]),
            ),
            "new",
        );
        (baseline, candidate)
    }

    /// Healthy promoted windows: post-promotion totals close to pre-deploy.
    fn promoted_samples() -> (PromotedSample, PromotedSample) {
        let baseline = promoted_sample(&promoted_data(
            &periodic_sum(1_000_000_000.0, 5_000.0, 2_000.0),
            10_000.0,
        ));
        let candidate = promoted_sample(&promoted_data(
            &periodic_sum(1_050_000_000.0, 5_300.0, 2_100.0),
            10_200.0,
        ));
        (baseline, candidate)
    }

    // ---- field-list coverage ------------------------------------------------

    /// The fields a query selects inside `sum {}`/`quantiles {}`/
    /// `dimensions {}` of one dataset block.
    fn selected_fields<'a>(query: &'a str, dataset: &str, block: &str) -> Vec<&'a str> {
        let start = query
            .find(dataset)
            .unwrap_or_else(|| panic!("{dataset} is not in the query"));
        let rest = &query[start..];
        let block_start = rest
            .find(&format!("{block} {{"))
            .unwrap_or_else(|| panic!("{dataset} selects no `{block} {{}}`"));
        let body_start = start + block_start + block.len() + 2;
        let body_end = query[body_start..]
            .find('}')
            .map(|end| body_start + end)
            .expect("closing brace");
        query[body_start..body_end].split_whitespace().collect()
    }

    #[test]
    fn canary_query_names_only_introspected_fields() {
        for field in selected_fields(CANARY_QUERY, "workersInvocationsAdaptive", "sum") {
            assert!(
                schema::WORKERS_SUM.contains(&field),
                "{field} not in WORKERS_SUM"
            );
        }
        for field in selected_fields(CANARY_QUERY, "workersInvocationsAdaptive", "quantiles") {
            assert!(
                schema::WORKERS_QUANTILES.contains(&field),
                "{field} not in WORKERS_QUANTILES"
            );
        }
        for field in selected_fields(CANARY_QUERY, "workersInvocationsAdaptive", "dimensions") {
            assert!(
                schema::WORKERS_DIMENSIONS.contains(&field),
                "{field} not in WORKERS_DIMENSIONS"
            );
        }
        for field in selected_fields(
            CANARY_QUERY,
            "durableObjectsInvocationsAdaptiveGroups",
            "sum",
        ) {
            assert!(
                schema::DO_INVOCATIONS_SUM.contains(&field),
                "{field} not in DO_INVOCATIONS_SUM"
            );
        }
        for field in selected_fields(
            CANARY_QUERY,
            "durableObjectsInvocationsAdaptiveGroups",
            "dimensions",
        ) {
            assert!(
                schema::DO_INVOCATIONS_DIMENSIONS.contains(&field),
                "{field} not in DO_INVOCATIONS_DIMENSIONS"
            );
        }
    }

    #[test]
    fn promoted_query_names_only_introspected_fields() {
        for field in selected_fields(PROMOTED_QUERY, "durableObjectsPeriodicGroups", "sum") {
            assert!(
                schema::DO_PERIODIC_SUM.contains(&field),
                "{field} not in DO_PERIODIC_SUM"
            );
        }
        for field in selected_fields(
            PROMOTED_QUERY,
            "durableObjectsInvocationsAdaptiveGroups",
            "sum",
        ) {
            assert!(
                schema::DO_INVOCATIONS_SUM.contains(&field),
                "{field} not in DO_INVOCATIONS_SUM"
            );
        }
    }

    // ---- canary verdict ------------------------------------------------------

    #[test]
    fn a_canary_inside_the_thresholds_passes() {
        let (baseline, candidate) = canary_samples();
        let report = canary(&baseline, &candidate);
        assert!(report.pass, "{report:?}");
        assert_eq!(report.breaches, [] as [std::string::String; 0]);
        // 7 metric rows, no signal row.
        assert_eq!(report.metrics.len(), CANARY_THRESHOLDS.len());
    }

    #[test]
    fn an_error_rate_jump_breaches() {
        let (baseline, _) = canary_samples();
        let candidate = canary_sample(
            &canary_data(
                &json!([worker_group(
                    "new", 5_000.0, 300.0, 420.0, 2_200.0, 22_000.0, 84_000.0
                )]),
                &json!([do_invocation_group("new", 10_500.0, 6.0, 520_000_000.0)]),
            ),
            "new",
        );
        let report = canary(&baseline, &candidate);
        assert!(!report.pass);
        assert_eq!(report.breaches, ["worker error rate"]);
        let row = report
            .metrics
            .iter()
            .find(|metric| metric.name == "worker error rate")
            .expect("row");
        assert_eq!(row.verdict, "breach");
        assert!(row.candidate > row.baseline);
    }

    #[test]
    fn a_cpu_p99_regression_breaches_but_p50_does_not() {
        let (baseline, _) = canary_samples();
        let candidate = canary_sample(
            &canary_data(
                // p99 = 300_000 clears the 2_000*1.25+250_000 = 252_500 ceiling.
                &json!([worker_group(
                    "new", 5_000.0, 3.0, 430.0, 300_000.0, 22_000.0, 84_000.0
                )]),
                &json!([do_invocation_group("new", 10_500.0, 6.0, 520_000_000.0)]),
            ),
            "new",
        );
        let report = canary(&baseline, &candidate);
        assert!(!report.pass);
        assert_eq!(report.breaches, ["worker cpu p99"]);
    }

    #[test]
    fn a_durable_object_wall_regression_breaches() {
        let (baseline, _) = canary_samples();
        // Baseline DO wall/req = 50_000µs; candidate 200_000µs/req clears
        // the 1.5x + 100_000µs = 175_000µs ceiling.
        let candidate = canary_sample(
            &canary_data(
                &json!([worker_group(
                    "new", 5_000.0, 3.0, 420.0, 2_200.0, 22_000.0, 84_000.0
                )]),
                &json!([do_invocation_group("new", 10_500.0, 6.0, 2_100_000_000.0)]),
            ),
            "new",
        );
        let report = canary(&baseline, &candidate);
        assert!(!report.pass);
        assert_eq!(report.breaches, ["durable object wall"]);
    }

    #[test]
    fn a_do_that_stayed_on_the_baseline_reports_skipped() {
        // The Scheduler is a singleton: during the canary it kept its
        // baseline assignment, so the dataset carries no row for the
        // candidate version — the DO rows skip rather than breach.
        let (baseline, _) = canary_samples();
        let candidate = canary_sample(
            &canary_data(
                &json!([
                    worker_group("old", 95_000.0, 40.0, 410.0, 2_100.0, 21_000.0, 82_000.0),
                    worker_group("new", 5_000.0, 3.0, 420.0, 2_200.0, 22_000.0, 84_000.0),
                ]),
                &json!([do_invocation_group("old", 10_500.0, 6.0, 520_000_000.0)]),
            ),
            "new",
        );
        let report = canary(&baseline, &candidate);
        assert!(report.pass, "{report:?}");
        let skipped: Vec<_> = report
            .metrics
            .iter()
            .filter(|metric| metric.verdict == "skipped")
            .map(|metric| metric.name)
            .collect();
        assert_eq!(
            skipped,
            ["durable object error rate", "durable object wall"]
        );
    }

    #[test]
    fn a_canary_with_no_worker_signal_fails_closed() {
        let (baseline, _) = canary_samples();
        // The canary version served nothing: the dataset returns no worker
        // row for it at all.
        let candidate = canary_sample(
            &canary_data(
                &json!([worker_group(
                    "old", 100_000.0, 40.0, 410.0, 2_100.0, 21_000.0, 82_000.0
                )]),
                &json!([do_invocation_group("old", 10_500.0, 6.0, 520_000_000.0)]),
            ),
            "new",
        );
        let report = canary(&baseline, &candidate);
        assert!(!report.pass);
        assert_eq!(report.metrics[0].verdict, "no signal");
        assert_eq!(report.breaches, ["worker signal (no signal)"]);
    }

    #[test]
    fn a_side_below_the_minimum_sample_fails_closed() {
        // The suite guarantees 50 requests PER VERSION; a side that served
        // 3 breaches the floor even though it has signal, whichever side
        // it is.
        let mut min_args = args();
        min_args.min_requests_per_version = 50;
        let (baseline, _) = canary_samples();
        let thin_candidate = canary_sample(
            &canary_data(
                &json!([
                    worker_group("old", 95_000.0, 40.0, 410.0, 2_100.0, 21_000.0, 82_000.0),
                    worker_group("new", 3.0, 0.0, 420.0, 2_200.0, 22_000.0, 84_000.0),
                ]),
                &json!([do_invocation_group("old", 10_500.0, 6.0, 520_000_000.0)]),
            ),
            "new",
        );
        let report = evaluate_canary(&min_args, &windows(), &baseline, &thin_candidate);
        assert!(!report.pass);
        assert_eq!(report.metrics[0].verdict, INSUFFICIENT_SAMPLE);
        assert_eq!(report.breaches, ["worker signal (insufficient sample)"]);

        let thin_baseline = canary_sample(
            &canary_data(
                &json!([
                    worker_group("old", 4.0, 0.0, 410.0, 2_100.0, 21_000.0, 82_000.0),
                    worker_group("new", 500.0, 1.0, 420.0, 2_200.0, 22_000.0, 84_000.0),
                ]),
                &json!([do_invocation_group("new", 100.0, 0.0, 5_000_000.0)]),
            ),
            "old",
        );
        let (_, candidate) = canary_samples();
        let report = evaluate_canary(&min_args, &windows(), &thin_baseline, &candidate);
        assert!(!report.pass);
        assert_eq!(report.metrics[0].verdict, INSUFFICIENT_SAMPLE);
    }

    #[test]
    fn a_zero_request_baseline_still_reports_pairs() {
        // Baseline worker row exists but served nothing — every worker
        // metric needs a denominator, so the verdict reports no signal
        // rather than dividing by zero.
        let baseline = canary_sample(
            &canary_data(
                &json!([worker_group("old", 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)]),
                &json!([do_invocation_group("old", 10_000.0, 5.0, 500_000_000.0)]),
            ),
            "old",
        );
        let (_, candidate) = canary_samples();
        let report = canary(&baseline, &candidate);
        assert!(!report.pass);
        assert_eq!(report.metrics[0].verdict, "no signal");
    }

    // ---- promoted verdict ----------------------------------------------------

    #[test]
    fn a_promoted_window_inside_the_thresholds_passes() {
        let (baseline, candidate) = promoted_samples();
        let report = promoted(&baseline, &candidate);
        assert!(report.pass, "{report:?}");
        // The sample row, then one row per threshold entry.
        assert_eq!(report.metrics.len(), PROMOTED_THRESHOLDS.len() + 1);
        assert_eq!(report.metrics[0].name, "durable object sample");
        assert_eq!(report.metrics[0].verdict, "pass");
        assert!((report.metrics[0].baseline - 10_000.0).abs() < f64::EPSILON);
        assert!((report.metrics[0].candidate - 10_200.0).abs() < f64::EPSILON);
        assert_eq!(report.phase, "promoted");
    }

    #[test]
    fn a_do_cpu_regression_breaches_post_promotion() {
        let (baseline, _) = promoted_samples();
        // DO cpu/request doubled: 100_000µs -> 200_000µs vs ceiling
        // 100_000*1.25 + 50_000 = 175_000µs.
        let candidate = promoted_sample(&promoted_data(
            &periodic_sum(2_040_000_000.0, 5_300.0, 2_100.0),
            10_200.0,
        ));
        let report = promoted(&baseline, &candidate);
        assert!(!report.pass);
        assert_eq!(report.breaches, ["durable object cpu"]);
    }

    /// stow#1022's run: the baseline window carried 18 DO requests and the
    /// candidate window one — the first request after promotion, on the
    /// object the version change reset.
    fn one_cold_request_samples() -> (PromotedSample, PromotedSample) {
        let baseline = promoted_sample(&promoted_data(
            &periodic_sum(3_285_775.0, 95_732.0, 14.0),
            18.0,
        ));
        let cold_candidate =
            promoted_sample(&promoted_data(&periodic_sum(375_576.0, 6_838.0, 1.0), 1.0));
        (baseline, cold_candidate)
    }

    #[test]
    fn one_cold_do_request_cannot_breach_the_promoted_verdict() {
        // Compared unfloored, this pair breaches cpu and rows read (the
        // v0.8.2 rollback). Under the floor no DO row is judged: every row
        // reads `insufficient sample`, none `breach`.
        let (baseline, cold_candidate) = one_cold_request_samples();
        let report = promoted(&baseline, &cold_candidate);
        assert!(!report.pass, "an unproven window must not pass");
        assert!(
            report
                .metrics
                .iter()
                .all(|metric| metric.verdict == INSUFFICIENT_SAMPLE),
            "{report:?}"
        );
        assert_eq!(
            report.breaches,
            ["durable object sample (insufficient sample)"]
        );
        assert!((report.metrics[0].candidate - 1.0).abs() < f64::EPSILON);
        assert!((report.metrics[0].baseline - 18.0).abs() < f64::EPSILON);
    }

    #[test]
    fn one_cold_do_request_cannot_pass_the_promoted_verdict() {
        // The same single cold request, this time cheap enough to sit under
        // every ceiling: it still is not a pass.
        let (baseline, _) = one_cold_request_samples();
        let cheap_candidate =
            promoted_sample(&promoted_data(&periodic_sum(1_000.0, 1.0, 0.0), 1.0));
        let report = promoted(&baseline, &cheap_candidate);
        assert!(!report.pass);
        assert!(
            report
                .metrics
                .iter()
                .all(|metric| metric.verdict == INSUFFICIENT_SAMPLE)
        );
    }

    #[test]
    fn a_thin_baseline_window_is_not_compared_either() {
        let (_, candidate) = promoted_samples();
        let thin_baseline =
            promoted_sample(&promoted_data(&periodic_sum(1_000_000.0, 50.0, 2.0), 279.0));
        let report = promoted(&thin_baseline, &candidate);
        assert!(!report.pass);
        assert_eq!(report.metrics[0].verdict, INSUFFICIENT_SAMPLE);
    }

    #[test]
    fn an_empty_promoted_window_fails_closed_rather_than_passing() {
        // No DO traffic at all during the window: the workload did not
        // land, which is no evidence the candidate is healthy.
        let (baseline, _) = promoted_samples();
        let candidate = promoted_sample(&promoted_data(&periodic_sum(0.0, 0.0, 0.0), 0.0));
        let report = promoted(&baseline, &candidate);
        assert!(!report.pass, "{report:?}");
        assert!(
            report
                .metrics
                .iter()
                .all(|metric| metric.verdict == INSUFFICIENT_SAMPLE)
        );
    }

    #[test]
    fn a_window_at_the_floor_is_compared() {
        let (baseline, _) = promoted_samples();
        // 280 requests at the baseline's per-request cost.
        let candidate = promoted_sample(&promoted_data(
            &periodic_sum(28_000_000.0, 140.0, 56.0),
            280.0,
        ));
        let report = promoted(&baseline, &candidate);
        assert!(report.pass, "{report:?}");
        assert_eq!(report.metrics[0].verdict, "pass");
    }

    // ---- rendering ------------------------------------------------------------

    #[test]
    fn the_rendered_promoted_report_prints_each_windows_do_requests() {
        let (baseline, cold_candidate) = one_cold_request_samples();
        let rendered = render_report(&promoted(&baseline, &cold_candidate));
        let lines: Vec<&str> = rendered.lines().collect();
        assert!(lines[1].contains("do requests (req)"), "{rendered}");
        let baseline_row = lines
            .iter()
            .find(|line| line.starts_with("baseline "))
            .expect("baseline window row");
        assert!(baseline_row.contains("2026-09-28T00:00:00Z"), "{rendered}");
        assert!(
            baseline_row.split_whitespace().nth(3) == Some("18"),
            "{rendered}"
        );
        let candidate_row = lines
            .iter()
            .find(|line| line.starts_with("candidate "))
            .expect("candidate window row");
        assert!(
            candidate_row.split_whitespace().nth(3) == Some("1"),
            "{rendered}"
        );
        let sample_row = lines
            .iter()
            .find(|line| line.starts_with("durable object sample"))
            .expect("sample row");
        assert!(sample_row.contains("18.0000 req"), "{rendered}");
        assert!(sample_row.contains("1.0000 req"), "{rendered}");
        assert!(sample_row.contains("280.0000"), "{rendered}");
        assert!(sample_row.ends_with(INSUFFICIENT_SAMPLE), "{rendered}");
    }

    #[test]
    fn the_rendered_canary_report_prints_each_versions_requests() {
        let (baseline, candidate) = canary_samples();
        let rendered = render_report(&canary(&baseline, &candidate));
        assert!(rendered.contains("worker requests (req)"), "{rendered}");
        assert!(rendered.contains("do requests (req)"), "{rendered}");
        let candidate_row = rendered
            .lines()
            .find(|line| line.starts_with("candidate "))
            .expect("candidate window row");
        let cells: Vec<&str> = candidate_row.split_whitespace().collect();
        // window from to worker-requests worker-errors do-requests ...
        assert_eq!(cells[3], "5000", "{rendered}");
        assert_eq!(cells[5], "10500", "{rendered}");
    }

    // ---- misc -----------------------------------------------------------------

    #[test]
    fn threshold_tables_cover_every_phase() {
        // Keeps `apply_thresholds` honest if a spec list loses an entry.
        assert_eq!(CANARY_THRESHOLDS.len(), 7);
        assert_eq!(PROMOTED_THRESHOLDS.len(), 3);
    }

    #[test]
    fn rfc3339_bounds_parse() {
        assert!(parse_rfc3339("2026-09-28T00:00:00Z").is_ok());
        assert!(parse_rfc3339("not a time").is_err());
    }

    #[test]
    fn skipped_is_not_counted_as_a_breach() {
        let (baseline, candidate) = promoted_samples();
        let report = apply_thresholds(
            VerdictPhase::Promoted,
            PROMOTED_THRESHOLDS,
            &promoted_args(),
            &windows(),
            &baseline,
            &candidate,
        );
        assert!(report.pass);
        assert_eq!(report.breaches, [] as [std::string::String; 0]);
    }
}
