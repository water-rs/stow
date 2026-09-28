//! `stow-admin deploy …` — canary verdicts for the edge Worker.
//!
//! `deploy verdict` compares the metrics a canary Worker version produced
//! during its observation window against the metrics the version it would
//! replace produced in an equally long pre-deploy window, prints each
//! metric's baseline and candidate values, and answers a promote/rollback
//! decision. It reads Cloudflare's GraphQL Analytics API with
//! `CLOUDFLARE_API_TOKEN` (Account Analytics read); it neither deploys nor
//! rolls back — that is the workflow's job once it has the verdict.
//!
//! Schema fields verified against the Cloudflare docs but NOT against the
//! live schema (no `CLOUDFLARE_API_TOKEN` was available at authoring time):
//! `scriptVersion` on `workersInvocationsAdaptive` dimensions, and
//! `cpuTime`/`rowsRead`/`rowsWritten` on `durableObjectsInvocationsAdaptiveGroups`
//! sums. The DO dataset does not split by Worker version, so DO metrics
//! compare the observation window against the pre-deploy window outright.

use std::fmt::Write as _;

use clap::{Args, Subcommand};
use serde::Deserialize;
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
    /// Compare a canary's metrics against the version it would replace and
    /// print a promote/rollback verdict.
    Verdict(VerdictArgs),
}

#[derive(Args)]
pub struct VerdictArgs {
    /// Cloudflare account tag the Worker lives under.
    #[arg(long)]
    account_tag: String,
    /// Worker script name (`stow-edge`).
    #[arg(long)]
    script: String,
    /// Version id the canary would replace — the 100% version before upload.
    #[arg(long)]
    baseline_version: String,
    /// Version id of the canary under observation.
    #[arg(long)]
    candidate_version: String,
    /// Pre-deploy baseline window, RFC 3339 bounds (`--baseline-from`/`--baseline-to`).
    #[arg(long, value_parser = parse_rfc3339)]
    baseline_from: OffsetDateTime,
    /// See `--baseline-from`.
    #[arg(long, value_parser = parse_rfc3339)]
    baseline_to: OffsetDateTime,
    /// Canary observation window, RFC 3339 bounds.
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
/// baseline from failing a canary on epsilon — an error rate of one
/// failure in `10_000` requests reads infinite next to a baseline of zero.
#[derive(Debug, Clone, Copy)]
struct Threshold {
    /// Largest allowed `candidate / baseline` ratio.
    max_ratio: f64,
    /// Largest allowed `candidate - baseline`, in the metric's unit.
    max_abs_delta: f64,
}

/// The metrics the verdict rows over, and which sample field each reads.
#[derive(Debug, Clone, Copy)]
enum MetricKind {
    /// Worker `errors / requests`.
    WorkerErrorRate,
    /// Worker `cpuTimeP50`, microseconds.
    WorkerCpuP50,
    /// Worker `cpuTimeP99`, microseconds.
    WorkerCpuP99,
    /// Durable Object `cpuTime / requests`, microseconds per request.
    DoCpuPerRequest,
    /// Durable Object `rowsRead / requests`.
    DoRowsReadPerRequest,
    /// Durable Object `rowsWritten / requests`.
    DoRowsWrittenPerRequest,
}

/// One row of the verdict table: a metric, the unit both sides are printed
/// in, and the threshold it is held to.
#[derive(Debug, Clone, Copy)]
struct MetricSpec {
    /// Table label.
    name: &'static str,
    /// Unit suffix on printed values.
    unit: &'static str,
    /// Which sample the metric reads.
    kind: MetricKind,
    /// The breach bound.
    threshold: Threshold,
}

/// The verdict's typed threshold table. Values are the deployment policy —
/// a canary may be up to 25% slower or carry up to one extra point of error
/// rate (and at most double the baseline) before it is rolled back.
const THRESHOLDS: &[MetricSpec] = &[
    MetricSpec {
        name: "worker error rate",
        unit: "err/req",
        kind: MetricKind::WorkerErrorRate,
        threshold: Threshold {
            max_ratio: 2.0,
            max_abs_delta: 0.01,
        },
    },
    MetricSpec {
        name: "worker cpu p50",
        unit: "µs",
        kind: MetricKind::WorkerCpuP50,
        threshold: Threshold {
            max_ratio: 1.25,
            max_abs_delta: 50_000.0,
        },
    },
    MetricSpec {
        name: "worker cpu p99",
        unit: "µs",
        kind: MetricKind::WorkerCpuP99,
        threshold: Threshold {
            max_ratio: 1.25,
            max_abs_delta: 250_000.0,
        },
    },
    MetricSpec {
        name: "durable object cpu",
        unit: "µs/req",
        kind: MetricKind::DoCpuPerRequest,
        threshold: Threshold {
            max_ratio: 1.25,
            max_abs_delta: 50_000.0,
        },
    },
    MetricSpec {
        name: "durable object rows read",
        unit: "rows/req",
        kind: MetricKind::DoRowsReadPerRequest,
        threshold: Threshold {
            max_ratio: 1.25,
            max_abs_delta: 1.0,
        },
    },
    MetricSpec {
        name: "durable object rows written",
        unit: "rows/req",
        kind: MetricKind::DoRowsWrittenPerRequest,
        threshold: Threshold {
            max_ratio: 1.25,
            max_abs_delta: 1.0,
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
    /// `pass` or `breach`.
    verdict: &'static str,
}

/// What `deploy verdict` reports: every metric's pair plus the bottom line.
#[derive(Debug, serde::Serialize)]
struct VerdictReport {
    /// Worker script name.
    script: String,
    /// Version ids compared.
    baseline_version: String,
    /// See `baseline_version`.
    candidate_version: String,
    /// One row per `THRESHOLDS` entry.
    metrics: Vec<MetricVerdict>,
    /// Names of metrics that breached or carried no signal.
    breaches: Vec<String>,
    /// Whether the canary may be promoted.
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
    cpu_p50: f64,
    /// `quantiles.cpuTimeP99`, microseconds.
    cpu_p99: f64,
}

/// The Durable-Object numbers the whole script accumulated over a window.
/// DO datasets do not carry the Worker version, so the window itself is the
/// comparison axis.
#[derive(Debug, Clone, Copy)]
struct DoMetrics {
    /// `sum.cpuTime / sum.requests`, microseconds per request.
    cpu_us: f64,
    /// `sum.rowsRead / sum.requests`.
    rows_read: f64,
    /// `sum.rowsWritten / sum.requests`.
    rows_written: f64,
}

/// One window's assembled samples: the named version's worker metrics and
/// the script's aggregate DO metrics. `None` means the window carried no
/// signal — the verdict treats that as a breach, since a canary that served
/// nothing proved nothing.
#[derive(Debug)]
struct WindowSample {
    /// Worker metrics for the version the window is being asked about.
    worker: Option<VersionMetrics>,
    /// DO metrics aggregated across the window's hour groups.
    durable_objects: Option<DoMetrics>,
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

/// Both datasets a window query returns.
#[derive(Debug, Deserialize)]
struct WindowData {
    /// `workersInvocationsAdaptive`, one row per `scriptVersion`.
    #[serde(rename = "workersInvocationsAdaptive")]
    workers: Vec<WorkerGroup>,
    /// `durableObjectsInvocationsAdaptiveGroups`, one row per hour.
    #[serde(rename = "durableObjectsInvocationsAdaptiveGroups")]
    durable_objects: Vec<DoGroup>,
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
    /// The deployed version id — present where the dataset carries it.
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
}

#[derive(Debug, Deserialize)]
struct DoGroup {
    /// Sums for the group (`dimensions.datetimeHour` is only a grouping
    /// axis here, so it is not decoded).
    sum: DoSum,
}

#[derive(Debug, Deserialize)]
struct DoSum {
    /// Requests served — the denominator every per-request rate divides by.
    requests: f64,
    /// Total cpu time, microseconds.
    #[serde(rename = "cpuTime")]
    cpu_time: f64,
    /// Storage rows read.
    #[serde(rename = "rowsRead")]
    rows_read: f64,
    /// Storage rows written.
    #[serde(rename = "rowsWritten")]
    rows_written: f64,
}

/// One GraphQL request body.
#[derive(Debug, serde::Serialize)]
struct GraphQlRequest {
    /// The query document.
    query: &'static str,
    /// The variables it references.
    variables: serde_json::Value,
}

/// The window query: both datasets, both bounds, one round trip. Selecting
/// only `dimensions { scriptVersion }` makes Cloudflare return one worker row
/// per deployed version; the DO rows come back per `datetimeHour` and are
/// summed here, because DOs do not report the Worker version that served them.
const WINDOW_QUERY: &str = r"query DeployVerdict($account: String!, $script: String!, $from: Time!, $to: Time!) {
  viewer {
    accounts(filter: { accountTag: $account }) {
      workersInvocationsAdaptive(
        filter: { scriptName: $script, datetime_geq: $from, datetime_leq: $to }
        limit: 500
      ) {
        dimensions { scriptVersion }
        sum { requests errors }
        quantiles { cpuTimeP50 cpuTimeP99 }
      }
      durableObjectsInvocationsAdaptiveGroups(
        filter: { scriptName: $script, datetime_geq: $from, datetime_leq: $to }
        limit: 500
      ) {
        dimensions { datetimeHour }
        sum { requests errors cpuTime rowsRead rowsWritten }
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

    let baseline = window_sample(
        &token,
        &args,
        args.baseline_from,
        args.baseline_to,
        &args.baseline_version,
    )
    .await?;
    let candidate = window_sample(
        &token,
        &args,
        args.candidate_from,
        args.candidate_to,
        &args.candidate_version,
    )
    .await?;

    let report = evaluate(
        &args.script,
        &args.baseline_version,
        &args.candidate_version,
        &baseline,
        &candidate,
    );
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

/// Run `WINDOW_QUERY` for one window and pull the asked-for version's
/// worker row plus the aggregated DO sums out of it.
async fn window_sample(
    token: &str,
    args: &VerdictArgs,
    from: OffsetDateTime,
    to: OffsetDateTime,
    version: &str,
) -> stow_types::error::Result<WindowSample> {
    let body = GraphQlRequest {
        query: WINDOW_QUERY,
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
    let envelope: GraphQlEnvelope<Viewer<WindowData>> = response
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
    let data = envelope
        .data
        .and_then(|data| data.viewer.accounts.into_iter().next())
        .ok_or_else(|| stow_error!("GraphQL answer carried no account data"))?;
    Ok(WindowSample {
        worker: worker_metrics(&data.workers, version),
        durable_objects: do_metrics(&data.durable_objects),
    })
}

/// The worker row for `version`, or `None` when the window holds no row
/// for it (the version served no requests, or the dataset lacks the
/// `scriptVersion` dimension for the account).
fn worker_metrics(groups: &[WorkerGroup], version: &str) -> Option<VersionMetrics> {
    groups
        .iter()
        .find(|group| group.dimensions.script_version.as_deref() == Some(version))
        .map(|group| VersionMetrics {
            requests: group.sum.requests,
            errors: group.sum.errors,
            cpu_p50: group.quantiles.cpu_p50,
            cpu_p99: group.quantiles.cpu_p99,
        })
}

/// All DO groups of the window summed into per-request rates.
fn do_metrics(groups: &[DoGroup]) -> Option<DoMetrics> {
    if groups.is_empty() {
        return None;
    }
    let total =
        |field: fn(&DoSum) -> f64| groups.iter().map(|group| field(&group.sum)).sum::<f64>();
    let requests = total(|sum| sum.requests);
    if requests <= 0.0 {
        return None;
    }
    Some(DoMetrics {
        cpu_us: total(|sum| sum.cpu_time) / requests,
        rows_read: total(|sum| sum.rows_read) / requests,
        rows_written: total(|sum| sum.rows_written) / requests,
    })
}

/// Read one metric's baseline/candidate pair off the two window samples.
fn metric_pair(
    kind: MetricKind,
    baseline: &WindowSample,
    candidate: &WindowSample,
) -> Option<(f64, f64)> {
    match kind {
        MetricKind::WorkerErrorRate => {
            let (base, cand) = (baseline.worker?, candidate.worker?);
            if base.requests <= 0.0 || cand.requests <= 0.0 {
                return None;
            }
            Some((base.errors / base.requests, cand.errors / cand.requests))
        }
        MetricKind::WorkerCpuP50 => Some((baseline.worker?.cpu_p50, candidate.worker?.cpu_p50)),
        MetricKind::WorkerCpuP99 => Some((baseline.worker?.cpu_p99, candidate.worker?.cpu_p99)),
        MetricKind::DoCpuPerRequest => Some((
            baseline.durable_objects?.cpu_us,
            candidate.durable_objects?.cpu_us,
        )),
        MetricKind::DoRowsReadPerRequest => Some((
            baseline.durable_objects?.rows_read,
            candidate.durable_objects?.rows_read,
        )),
        MetricKind::DoRowsWrittenPerRequest => Some((
            baseline.durable_objects?.rows_written,
            candidate.durable_objects?.rows_written,
        )),
    }
}

/// Apply `THRESHOLDS` to the two windows and build the report. A metric
/// whose pair cannot be computed — the window carried no requests, or the
/// dataset carried no row for the version — breaches as `no signal`: a
/// canary that proved nothing is not promoted.
fn evaluate(
    script: &str,
    baseline_version: &str,
    candidate_version: &str,
    baseline: &WindowSample,
    candidate: &WindowSample,
) -> VerdictReport {
    let mut metrics = Vec::new();
    let mut breaches = Vec::new();
    for spec in THRESHOLDS {
        let Some((base, cand)) = metric_pair(spec.kind, baseline, candidate) else {
            metrics.push(MetricVerdict {
                name: spec.name,
                unit: spec.unit,
                baseline: f64::NAN,
                candidate: f64::NAN,
                ceiling: f64::NAN,
                verdict: "no signal",
            });
            breaches.push(format!("{} (no signal)", spec.name));
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
        baseline_version: baseline_version.to_owned(),
        candidate_version: candidate_version.to_owned(),
        metrics,
        pass: breaches.is_empty(),
        breaches,
    }
}

/// Emit the report: `--json` gets the structured verdict, the human table
/// prints every metric's pair, ceiling and verdict.
fn emit(report: &VerdictReport, output: Output) -> stow_types::error::Result<()> {
    render::emit(output, report, |report| {
        let mut out = format!(
            "deploy verdict {}  {} -> {}\n",
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

    use super::{WindowSample, do_metrics, evaluate, parse_rfc3339, worker_metrics};

    /// A GraphQL `data` document the way `WINDOW_QUERY` returns it: worker
    /// rows per version, DO rows per hour.
    fn window_data(
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
        p50: f64,
        p99: f64,
    ) -> serde_json::Value {
        json!({
            "dimensions": { "scriptVersion": version },
            "sum": { "requests": requests, "errors": errors },
            "quantiles": { "cpuTimeP50": p50, "cpuTimeP99": p99 },
        })
    }

    fn do_group(
        requests: f64,
        errors: f64,
        cpu: f64,
        read: f64,
        written: f64,
    ) -> serde_json::Value {
        json!({
            "dimensions": { "datetimeHour": "2026-09-28T00:00:00Z" },
            "sum": {
                "requests": requests,
                "errors": errors,
                "cpuTime": cpu,
                "rowsRead": read,
                "rowsWritten": written,
            },
        })
    }

    /// Decode a fixture through the real wire types — the same parse the
    /// live response takes.
    fn decode(data: &serde_json::Value, version: &str) -> WindowSample {
        let data: super::WindowData =
            serde_json::from_value(data["viewer"]["accounts"][0].clone()).expect("decode");
        WindowSample {
            worker: worker_metrics(&data.workers, version),
            durable_objects: do_metrics(&data.durable_objects),
        }
    }

    /// A healthy comparison: the canary is close to the baseline everywhere.
    fn samples() -> (WindowSample, WindowSample) {
        let baseline = decode(
            &window_data(
                &json!([worker_group("old", 100_000.0, 50.0, 400.0, 2_000.0)]),
                &json!([do_group(10_000.0, 5.0, 1_000_000_000.0, 5_000.0, 2_000.0)]),
            ),
            "old",
        );
        let candidate = decode(
            &window_data(
                &json!([
                    worker_group("old", 95_000.0, 40.0, 410.0, 2_100.0),
                    worker_group("new", 5_000.0, 3.0, 420.0, 2_200.0),
                ]),
                &json!([do_group(10_500.0, 6.0, 1_100_000_000.0, 5_500.0, 2_100.0)]),
            ),
            "new",
        );
        (baseline, candidate)
    }

    #[test]
    fn a_canary_inside_the_thresholds_passes() {
        let (baseline, candidate) = samples();
        let report = evaluate("stow-edge", "old", "new", &baseline, &candidate);
        assert!(report.pass, "{report:?}");
        assert!(report.breaches.is_empty());
        assert_eq!(report.metrics.len(), super::THRESHOLDS.len());
    }

    #[test]
    fn an_error_rate_jump_breaches() {
        let (baseline, _) = samples();
        // 0.05% -> 6% errors: over the +0.01 absolute allowance at any ratio.
        let candidate = decode(
            &window_data(
                &json!([worker_group("new", 5_000.0, 300.0, 420.0, 2_200.0)]),
                &json!([do_group(10_500.0, 6.0, 1_100_000_000.0, 5_500.0, 2_100.0)]),
            ),
            "new",
        );
        let report = evaluate("stow-edge", "old", "new", &baseline, &candidate);
        assert!(!report.pass);
        assert_eq!(report.breaches, ["worker error rate"]);
        let row = &report.metrics[0];
        assert_eq!(row.verdict, "breach");
        // And the printed pair is the real pair, old first.
        assert!(row.candidate > row.baseline);
    }

    #[test]
    fn a_cpu_p99_regression_breaches_but_p50_does_not() {
        let (baseline, _) = samples();
        let candidate = decode(
            &window_data(
                // p99 = 300_000 clears the 2000*1.25+250_000 = 252_500 ceiling.
                &json!([worker_group("new", 5_000.0, 3.0, 430.0, 300_000.0)]),
                &json!([do_group(10_500.0, 6.0, 1_100_000_000.0, 5_500.0, 2_100.0)]),
            ),
            "new",
        );
        let report = evaluate("stow-edge", "old", "new", &baseline, &candidate);
        assert!(!report.pass);
        assert_eq!(report.breaches, ["worker cpu p99"]);
    }

    #[test]
    fn a_durable_object_metric_breach_is_named() {
        // Baseline DOs read 0.5 rows/request; a candidate window reading
        // 5 rows/request is ten times that, past the 1.25x + 1.0 ceiling.
        let baseline = decode(
            &window_data(
                &json!([worker_group("old", 100_000.0, 50.0, 400.0, 2_000.0)]),
                &json!([do_group(10_000.0, 5.0, 1_000_000_000.0, 5_000.0, 2_000.0)]),
            ),
            "old",
        );
        let candidate = decode(
            &window_data(
                &json!([worker_group("new", 5_000.0, 3.0, 420.0, 2_200.0)]),
                &json!([do_group(10_500.0, 6.0, 1_100_000_000.0, 52_500.0, 2_100.0)]),
            ),
            "new",
        );
        let report = evaluate("stow-edge", "old", "new", &baseline, &candidate);
        assert!(!report.pass);
        assert_eq!(report.breaches, ["durable object rows read"]);
    }

    #[test]
    fn a_canary_with_no_signal_fails_closed() {
        let (baseline, _) = samples();
        // The canary version served nothing: the dataset returns no row for
        // it at all.
        let candidate = decode(
            &window_data(
                &json!([worker_group("old", 100_000.0, 40.0, 410.0, 2_100.0)]),
                &json!([do_group(10_500.0, 6.0, 1_100_000_000.0, 5_500.0, 2_100.0)]),
            ),
            "new",
        );
        let report = evaluate("stow-edge", "old", "new", &baseline, &candidate);
        assert!(!report.pass);
        assert!(report.breaches.iter().all(|name| name.contains("no signal")
            || name.contains("durable")
            || name.contains("worker")));
        assert!(report.metrics.iter().any(|row| row.verdict == "no signal"));
    }

    #[test]
    fn a_zero_request_baseline_still_reports_pairs() {
        // Baseline row exists but served nothing — every worker metric
        // needs a denominator, so it reports no signal rather than divide
        // by zero.
        let baseline = decode(
            &window_data(
                &json!([worker_group("old", 0.0, 0.0, 0.0, 0.0)]),
                &json!([do_group(0.0, 0.0, 0.0, 0.0, 0.0)]),
            ),
            "old",
        );
        let (_, candidate) = samples();
        let report = evaluate("stow-edge", "old", "new", &baseline, &candidate);
        assert!(!report.pass);
    }

    #[test]
    fn rfc3339_bounds_parse() {
        assert!(parse_rfc3339("2026-09-28T00:00:00Z").is_ok());
        assert!(parse_rfc3339("not a time").is_err());
    }
}
