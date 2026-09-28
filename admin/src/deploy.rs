//! `stow-admin deploy …` — canary deploy verdicts for the edge Worker.
//!
//! `deploy verdict --phase canary` runs while traffic is split: worker
//! error rate and cpu/wall-time p50/p99 per `scriptVersion`, plus Durable
//! Object requests, errors and wall time per request — the fields
//! `durableObjectsInvocationsAdaptiveGroups` carries `scriptVersion` for.
//!
//! `deploy verdict --phase promoted` runs after promotion to 100%: the
//! metrics with no version dimension compare the post-promotion window
//! against the equal-length window that ended at the canary shift —
//! DO cpu/rows per DO request from `durableObjectsPeriodicGroups`, and D1
//! rows per worker request from `d1AnalyticsAdaptiveGroups`.
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
//! datasets), and `d1AnalyticsAdaptiveGroups` dimensions — the D1 query
//! selects none, so it is an account total like the DO periodic one, which
//! assumes stow-edge is the account's only DO/D1-bearing Worker during a
//! deploy window.

#[cfg(test)]
mod schema;

use std::fmt::Write as _;

use clap::{Args, Subcommand, ValueEnum};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use stow_types::stow_error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zenwave::{Client, ResponseExt};

use crate::render::{self, Output, Table};

const GRAPHQL_ENDPOINT: &str = "https://api.cloudflare.com/client/v4/graphql";
const CLOUDFLARE_API_TOKEN_ENV: &str = "CLOUDFLARE_API_TOKEN";

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
    /// Post-promotion: account-total DO periodic and D1 metrics, window
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
    /// Baseline window, RFC 3339 bounds: the equal-length window that ended
    /// at the canary traffic shift (`--baseline-from`/`--baseline-to`).
    #[arg(long, value_parser = parse_rfc3339)]
    baseline_from: OffsetDateTime,
    /// See `--baseline-from`.
    #[arg(long, value_parser = parse_rfc3339)]
    baseline_to: OffsetDateTime,
    /// Observation window, RFC 3339 bounds — the canary split for `canary`,
    /// the post-promotion window for `promoted`.
    #[arg(long, value_parser = parse_rfc3339)]
    candidate_from: OffsetDateTime,
    /// See `--candidate-from`.
    #[arg(long, value_parser = parse_rfc3339)]
    candidate_to: OffsetDateTime,
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
    MetricSpec {
        name: "d1 rows read",
        unit: "rows/req",
        threshold: Threshold {
            max_ratio: 1.25,
            max_abs_delta: 1.0,
        },
        extract: |sample| {
            (sample.worker_requests > 0.0).then(|| sample.d1_rows_read / sample.worker_requests)
        },
    },
    MetricSpec {
        name: "d1 rows written",
        unit: "rows/req",
        threshold: Threshold {
            max_ratio: 1.25,
            max_abs_delta: 0.5,
        },
        extract: |sample| {
            (sample.worker_requests > 0.0).then(|| sample.d1_rows_written / sample.worker_requests)
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
    /// `pass`, `breach`, `skipped` (no data — only for metrics that may
    /// legitimately be absent) or `no signal` (a breach).
    verdict: &'static str,
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
    /// `workersInvocationsAdaptive sum.requests` — the denominator the D1
    /// metrics divide by.
    worker_requests: f64,
    /// `d1AnalyticsAdaptiveGroups sum.rowsRead`.
    d1_rows_read: f64,
    /// `d1AnalyticsAdaptiveGroups sum.rowsWritten`.
    d1_rows_written: f64,
}

// ---- GraphQL wire shapes -------------------------------------------------

/// A `{"data": …, "errors": …}` envelope.
#[derive(Debug, Deserialize)]
struct GraphQlEnvelope<T> {
    /// Present on success.
    data: Option<T>,
    /// Present on failure — Cloudflare reports field errors here, sometimes
    /// alongside partial `data`.
    errors: Option<Vec<GraphQlError>>,
}

#[derive(Debug, Deserialize)]
struct GraphQlError {
    /// The API's message.
    message: String,
}

/// `viewer { accounts(...) { <T> } }` — the shape every analytics query shares.
#[derive(Debug, Deserialize)]
struct Viewer<T> {
    /// The viewer root.
    viewer: ViewerAccounts<T>,
}

#[derive(Debug, Deserialize)]
struct ViewerAccounts<T> {
    /// One entry per account the filter matched — the tag names exactly one.
    accounts: Vec<T>,
}

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
    /// `d1AnalyticsAdaptiveGroups`.
    #[serde(rename = "d1AnalyticsAdaptiveGroups")]
    d1: Vec<D1Group>,
    /// `workersInvocationsAdaptive` — used only for the request
    /// denominator, so no dimensions are selected.
    #[serde(rename = "workersInvocationsAdaptive")]
    worker_requests: Vec<RequestsGroup>,
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

#[derive(Debug, Deserialize)]
struct D1Group {
    /// Sums for the group.
    sum: D1Sum,
}

#[derive(Debug, Deserialize)]
struct D1Sum {
    /// Rows read.
    #[serde(rename = "rowsRead")]
    rows_read: f64,
    /// Rows written.
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

/// One GraphQL request body.
#[derive(Debug, serde::Serialize)]
struct GraphQlRequest {
    /// The query document.
    query: &'static str,
    /// The variables it references.
    variables: serde_json::Value,
}

/// The canary query: both versioned datasets, both bounds, one round trip.
/// Selecting only `dimensions { scriptVersion }` makes Cloudflare return
/// one row per deployed version. The DO dataset is filtered by datetime
/// alone — `scriptName` is not among its confirmed dimensions — so it is
/// an account total like every other DO/D1 dataset (see module docs).
const CANARY_QUERY: &str = r"query DeployVerdict($account: String!, $script: String!, $from: Time!, $to: Time!) {
  viewer {
    accounts(filter: { accountTag: $account }) {
      workersInvocationsAdaptive(
        filter: { scriptName: $script, datetime_geq: $from, datetime_leq: $to }
        limit: 500
      ) {
        dimensions { scriptVersion }
        sum { requests errors }
        quantiles { cpuTimeP50 cpuTimeP99 wallTimeP50 wallTimeP99 }
      }
      durableObjectsInvocationsAdaptiveGroups(
        filter: { datetime_geq: $from, datetime_leq: $to }
        limit: 500
      ) {
        dimensions { scriptVersion }
        sum { requests errors wallTime }
      }
    }
  }
}";

/// The promoted query: the unversioned datasets, account totals, one round
/// trip — `durableObjectsPeriodicGroups` and `d1AnalyticsAdaptiveGroups`
/// for the numerators, the invocation datasets for the request
/// denominators.
const PROMOTED_QUERY: &str = r"query DeployVerdict($account: String!, $script: String!, $from: Time!, $to: Time!) {
  viewer {
    accounts(filter: { accountTag: $account }) {
      durableObjectsPeriodicGroups(
        filter: { datetime_geq: $from, datetime_leq: $to }
        limit: 500
      ) {
        sum { cpuTime rowsRead rowsWritten }
      }
      durableObjectsInvocationsAdaptiveGroups(
        filter: { datetime_geq: $from, datetime_leq: $to }
        limit: 500
      ) {
        sum { requests }
      }
      d1AnalyticsAdaptiveGroups(
        filter: { datetime_geq: $from, datetime_leq: $to }
        limit: 500
      ) {
        sum { rowsRead rowsWritten }
      }
      workersInvocationsAdaptive(
        filter: { scriptName: $script, datetime_geq: $from, datetime_leq: $to }
        limit: 500
      ) {
        sum { requests }
      }
    }
  }
}";

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
    let token = std::env::var(CLOUDFLARE_API_TOKEN_ENV)
        .map_err(|_| stow_error!("missing {CLOUDFLARE_API_TOKEN_ENV}"))?;

    let report = match args.phase {
        VerdictPhase::Canary => {
            let baseline = canary_sample(&token, &args, true).await?;
            let candidate = canary_sample(&token, &args, false).await?;
            evaluate_canary(&args, &baseline, &candidate)
        }
        VerdictPhase::Promoted => {
            let baseline = promoted_sample(&token, &args, true).await?;
            let candidate = promoted_sample(&token, &args, false).await?;
            evaluate_promoted(&args, &baseline, &candidate)
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

/// POST one analytics query and unwrap `data.viewer.accounts[0]`.
async fn fetch_window<D: DeserializeOwned>(
    token: &str,
    args: &VerdictArgs,
    query: &'static str,
    baseline_window: bool,
) -> stow_types::error::Result<D> {
    let (from, to) = if baseline_window {
        (args.baseline_from, args.baseline_to)
    } else {
        (args.candidate_from, args.candidate_to)
    };
    let body = GraphQlRequest {
        query,
        variables: serde_json::json!({
            "account": args.account_tag,
            "script": args.script,
            "from": from.format(&Rfc3339).map_err(|error| stow_error!("format window start: {error}"))?,
            "to": to.format(&Rfc3339).map_err(|error| stow_error!("format window end: {error}"))?,
        }),
    };
    let mut client = zenwave::client();
    let response = client
        .post(GRAPHQL_ENDPOINT)
        .and_then(|request| request.header("Authorization", format!("Bearer {token}")))
        .and_then(|request| request.json_body(&body))
        .map_err(|error| stow_error!("POST {GRAPHQL_ENDPOINT}: {error}"))?
        .await
        .map_err(|error| stow_error!("POST {GRAPHQL_ENDPOINT}: {error}"))?;
    let envelope: GraphQlEnvelope<Viewer<D>> = response
        .error_for_status()
        .await
        .map_err(|error| stow_error!("POST {GRAPHQL_ENDPOINT}: {error}"))?
        .into_json()
        .await
        .map_err(|error| stow_error!("decode GraphQL response: {error}"))?;
    if let Some(errors) = envelope.errors.filter(|errors| !errors.is_empty()) {
        let messages = errors
            .iter()
            .map(|error| error.message.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(stow_error!("Cloudflare GraphQL errors: {messages}"));
    }
    envelope
        .data
        .and_then(|data| data.viewer.accounts.into_iter().next())
        .ok_or_else(|| stow_error!("GraphQL answer carried no account data"))
}

/// Run `CANARY_QUERY` for one window and pull the asked-for version's rows
/// out of it.
async fn canary_sample(
    token: &str,
    args: &VerdictArgs,
    baseline_window: bool,
) -> stow_types::error::Result<CanarySample> {
    let version = if baseline_window {
        &args.baseline_version
    } else {
        &args.candidate_version
    };
    let data: CanaryData = fetch_window(token, args, CANARY_QUERY, baseline_window).await?;
    Ok(CanarySample {
        worker: worker_metrics(&data.workers, version),
        do_invocations: do_invocation_metrics(&data.do_invocations, version),
    })
}

/// Run `PROMOTED_QUERY` for one window and sum each dataset's groups into
/// account totals.
async fn promoted_sample(
    token: &str,
    args: &VerdictArgs,
    baseline_window: bool,
) -> stow_types::error::Result<PromotedSample> {
    let data: PromotedData = fetch_window(token, args, PROMOTED_QUERY, baseline_window).await?;
    let requests = |groups: &[RequestsGroup]| groups.iter().map(|group| group.sum.requests).sum();
    Ok(PromotedSample {
        do_requests: requests(&data.do_requests),
        do_cpu_us: data.do_periodic.iter().map(|group| group.sum.cpu_us).sum(),
        do_rows_read: data
            .do_periodic
            .iter()
            .map(|group| group.sum.rows_read)
            .sum(),
        do_rows_written: data
            .do_periodic
            .iter()
            .map(|group| group.sum.rows_written)
            .sum(),
        worker_requests: requests(&data.worker_requests),
        d1_rows_read: data.d1.iter().map(|group| group.sum.rows_read).sum(),
        d1_rows_written: data.d1.iter().map(|group| group.sum.rows_written).sum(),
    })
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
/// whose extract answers `None` — the DO not being assigned to a version,
/// or a window with zero requests — reports `skipped`, not `breach`: the
/// absent data is expected, not an unproven gate.
fn apply_thresholds<S>(
    phase: VerdictPhase,
    specs: &[MetricSpec<S>],
    baseline: &S,
    candidate: &S,
    script: &str,
    baseline_version: &str,
    candidate_version: &str,
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
        script: script.to_owned(),
        phase: phase.label(),
        baseline_version: baseline_version.to_owned(),
        candidate_version: candidate_version.to_owned(),
        metrics,
        pass: breaches.is_empty(),
        breaches,
    }
}

/// The canary verdict. The worker row for the candidate must exist and
/// have served requests — a canary that produced no worker signal proved
/// nothing and fails closed. The DO rows may legitimately be absent (the
/// Scheduler stayed on the baseline) and report `skipped` instead.
fn evaluate_canary(
    args: &VerdictArgs,
    baseline: &CanarySample,
    candidate: &CanarySample,
) -> VerdictReport {
    let mut report = apply_thresholds(
        VerdictPhase::Canary,
        CANARY_THRESHOLDS,
        baseline,
        candidate,
        &args.script,
        &args.baseline_version,
        &args.candidate_version,
    );
    let no_worker_signal = candidate.worker.is_none_or(|worker| worker.requests <= 0.0)
        || baseline.worker.is_none_or(|worker| worker.requests <= 0.0);
    if no_worker_signal {
        report.metrics.insert(
            0,
            MetricVerdict {
                name: "worker signal",
                unit: "req",
                baseline: baseline.worker.map_or(f64::NAN, |worker| worker.requests),
                candidate: candidate.worker.map_or(f64::NAN, |worker| worker.requests),
                ceiling: f64::NAN,
                verdict: "no signal",
            },
        );
        report
            .breaches
            .insert(0, "worker signal (no signal)".to_owned());
        report.pass = false;
    }
    report
}

/// The promoted verdict: pure window-over-window comparison of account
/// totals; a metric with zero requests in a window reports `skipped`.
fn evaluate_promoted(
    args: &VerdictArgs,
    baseline: &PromotedSample,
    candidate: &PromotedSample,
) -> VerdictReport {
    apply_thresholds(
        VerdictPhase::Promoted,
        PROMOTED_THRESHOLDS,
        baseline,
        candidate,
        &args.script,
        &args.baseline_version,
        &args.candidate_version,
    )
}

/// Emit the report: `--json` gets the structured verdict, the human table
/// prints every metric's pair, ceiling and verdict.
fn emit(report: &VerdictReport, output: Output) -> stow_types::error::Result<()> {
    render::emit(output, report, |report| {
        let mut out = format!(
            "deploy verdict [{}] {}  {} -> {}\n",
            report.phase,
            if report.pass { "PASS" } else { "FAIL" },
            report.baseline_version,
            report.candidate_version,
        );
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
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        CANARY_QUERY, CANARY_THRESHOLDS, CanaryData, CanarySample, PROMOTED_QUERY,
        PROMOTED_THRESHOLDS, PromotedData, PromotedSample, VerdictPhase, apply_thresholds,
        do_invocation_metrics, evaluate_canary, evaluate_promoted, parse_rfc3339, schema,
        worker_metrics,
    };
    use crate::deploy::VerdictArgs;

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
        }
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
    fn promoted_data(
        periodic_sum: &serde_json::Value,
        do_requests: f64,
        d1_sum: &serde_json::Value,
        worker_requests: f64,
    ) -> serde_json::Value {
        json!({
            "viewer": { "accounts": [{
                "durableObjectsPeriodicGroups": [{ "sum": periodic_sum.clone() }],
                "durableObjectsInvocationsAdaptiveGroups": [{ "sum": { "requests": do_requests } }],
                "d1AnalyticsAdaptiveGroups": [{ "sum": d1_sum.clone() }],
                "workersInvocationsAdaptive": [{ "sum": { "requests": worker_requests } }],
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

    /// `d1AnalyticsAdaptiveGroups` rows.
    fn d1_sum(read: f64, written: f64) -> serde_json::Value {
        json!({
            "rowsRead": read,
            "rowsWritten": written,
            "readQueries": read,
            "writeQueries": written,
            "queryBatchResponseBytes": read * 64.0,
        })
    }

    /// Decode a canary fixture through the real wire types — the same
    /// parse the live response takes.
    fn canary_sample(data: &serde_json::Value, version: &str) -> CanarySample {
        let data: CanaryData =
            serde_json::from_value(data["viewer"]["accounts"][0].clone()).expect("decode");
        CanarySample {
            worker: worker_metrics(&data.workers, version),
            do_invocations: do_invocation_metrics(&data.do_invocations, version),
        }
    }

    /// Decode a promoted fixture into its account totals.
    fn promoted_sample(data: &serde_json::Value) -> PromotedSample {
        let data: PromotedData =
            serde_json::from_value(data["viewer"]["accounts"][0].clone()).expect("decode");
        let requests =
            |groups: &[super::RequestsGroup]| groups.iter().map(|group| group.sum.requests).sum();
        PromotedSample {
            do_requests: requests(&data.do_requests),
            do_cpu_us: data.do_periodic.iter().map(|group| group.sum.cpu_us).sum(),
            do_rows_read: data
                .do_periodic
                .iter()
                .map(|group| group.sum.rows_read)
                .sum(),
            do_rows_written: data
                .do_periodic
                .iter()
                .map(|group| group.sum.rows_written)
                .sum(),
            worker_requests: requests(&data.worker_requests),
            d1_rows_read: data.d1.iter().map(|group| group.sum.rows_read).sum(),
            d1_rows_written: data.d1.iter().map(|group| group.sum.rows_written).sum(),
        }
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
            &d1_sum(60_000.0, 8_000.0),
            100_000.0,
        ));
        let candidate = promoted_sample(&promoted_data(
            &periodic_sum(1_050_000_000.0, 5_300.0, 2_100.0),
            10_200.0,
            &d1_sum(62_000.0, 8_100.0),
            98_000.0,
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
        for field in selected_fields(PROMOTED_QUERY, "d1AnalyticsAdaptiveGroups", "sum") {
            assert!(schema::D1_SUM.contains(&field), "{field} not in D1_SUM");
        }
        for field in selected_fields(PROMOTED_QUERY, "workersInvocationsAdaptive", "sum") {
            assert!(
                schema::WORKERS_SUM.contains(&field),
                "{field} not in WORKERS_SUM"
            );
        }
    }

    // ---- canary verdict ------------------------------------------------------

    #[test]
    fn a_canary_inside_the_thresholds_passes() {
        let (baseline, candidate) = canary_samples();
        let report = evaluate_canary(&args(), &baseline, &candidate);
        assert!(report.pass, "{report:?}");
        assert!(report.breaches.is_empty());
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
        let report = evaluate_canary(&args(), &baseline, &candidate);
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
        let report = evaluate_canary(&args(), &baseline, &candidate);
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
        let report = evaluate_canary(&args(), &baseline, &candidate);
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
        let report = evaluate_canary(&args(), &baseline, &candidate);
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
        let report = evaluate_canary(&args(), &baseline, &candidate);
        assert!(!report.pass);
        assert_eq!(report.metrics[0].verdict, "no signal");
        assert_eq!(report.breaches, ["worker signal (no signal)"]);
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
        let report = evaluate_canary(&args(), &baseline, &candidate);
        assert!(!report.pass);
        assert_eq!(report.metrics[0].verdict, "no signal");
    }

    // ---- promoted verdict ----------------------------------------------------

    #[test]
    fn a_promoted_window_inside_the_thresholds_passes() {
        let (baseline, candidate) = promoted_samples();
        let mut promoted_args = args();
        promoted_args.phase = VerdictPhase::Promoted;
        let report = evaluate_promoted(&promoted_args, &baseline, &candidate);
        assert!(report.pass, "{report:?}");
        assert_eq!(report.metrics.len(), PROMOTED_THRESHOLDS.len());
        assert_eq!(report.phase, "promoted");
    }

    #[test]
    fn a_d1_rows_read_regression_breaches_post_promotion() {
        let (baseline, _) = promoted_samples();
        // D1 reads tripled per worker request: past the 1.25x + 1.0 ceiling.
        let candidate = promoted_sample(&promoted_data(
            &periodic_sum(1_050_000_000.0, 5_300.0, 2_100.0),
            10_200.0,
            &d1_sum(180_000.0, 8_100.0),
            98_000.0,
        ));
        let mut promoted_args = args();
        promoted_args.phase = VerdictPhase::Promoted;
        let report = evaluate_promoted(&promoted_args, &baseline, &candidate);
        assert!(!report.pass);
        assert_eq!(report.breaches, ["d1 rows read"]);
    }

    #[test]
    fn a_do_cpu_regression_breaches_post_promotion() {
        let (baseline, _) = promoted_samples();
        // DO cpu/request doubled: 100_000µs -> 200_000µs vs ceiling
        // 100_000*1.25 + 50_000 = 175_000µs.
        let candidate = promoted_sample(&promoted_data(
            &periodic_sum(2_040_000_000.0, 5_300.0, 2_100.0),
            10_200.0,
            &d1_sum(62_000.0, 8_100.0),
            98_000.0,
        ));
        let mut promoted_args = args();
        promoted_args.phase = VerdictPhase::Promoted;
        let report = evaluate_promoted(&promoted_args, &baseline, &candidate);
        assert!(!report.pass);
        assert_eq!(report.breaches, ["durable object cpu"]);
    }

    #[test]
    fn an_empty_promoted_window_skips_rather_than_breaches() {
        // No DO traffic at all during the window — nothing to compare.
        let (baseline, _) = promoted_samples();
        let candidate = promoted_sample(&promoted_data(
            &periodic_sum(0.0, 0.0, 0.0),
            0.0,
            &d1_sum(62_000.0, 8_100.0),
            98_000.0,
        ));
        let mut promoted_args = args();
        promoted_args.phase = VerdictPhase::Promoted;
        let report = evaluate_promoted(&promoted_args, &baseline, &candidate);
        assert!(report.pass, "{report:?}");
        assert!(
            report
                .metrics
                .iter()
                .all(|metric| metric.name.starts_with("durable object")
                    && metric.verdict == "skipped"
                    || !metric.name.starts_with("durable object"))
        );
    }

    // ---- misc -----------------------------------------------------------------

    #[test]
    fn threshold_tables_cover_every_phase() {
        // Keeps `apply_thresholds` honest if a spec list loses an entry.
        assert_eq!(CANARY_THRESHOLDS.len(), 7);
        assert_eq!(PROMOTED_THRESHOLDS.len(), 5);
    }

    #[test]
    fn rfc3339_bounds_parse() {
        assert!(parse_rfc3339("2026-09-28T00:00:00Z").is_ok());
        assert!(parse_rfc3339("not a time").is_err());
    }

    #[test]
    fn skipped_is_not_counted_as_a_breach() {
        let report = apply_thresholds(
            VerdictPhase::Promoted,
            PROMOTED_THRESHOLDS,
            &promoted_samples().0,
            &promoted_samples().1,
            "stow-edge",
            "old",
            "new",
        );
        assert!(report.pass);
        assert!(report.breaches.is_empty());
    }
}
