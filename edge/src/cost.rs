//! The cost trip: the edge's scheduled handler meters the account
//! through the Cloudflare GraphQL Analytics API every ten minutes and
//! the freeze trips when any metered dimension crosses its daily
//! budget — the monthly Workers Paid included allowance divided by 30,
//! scaled by `STOW_COST_BUDGET_MULTIPLIER`.
//!
//! The allowances the budgets are built from:
//! <https://developers.cloudflare.com/workers/platform/pricing/> —
//! Workers Paid includes 10M requests/month, 30M ms CPU/month.
//! <https://developers.cloudflare.com/durable-objects/platform/pricing/>
//! — DO Paid includes 1M requests/month, 400k GB-s duration/month,
//! 25G rows read/month, 50M rows written/month (SQLite storage).
//! <https://developers.cloudflare.com/d1/platform/pricing/> —
//! D1 Paid includes 25G rows read/month, 50M rows written/month.
//!
//! Budgets are account-scoped because the allowances are: billing sees
//! the whole account, so the DO and D1 queries filter only on
//! `accountTag` and the day. The Workers query additionally filters on
//! `scriptName = "stow-edge"` — its `scriptName` dimension doubles as
//! the trip email's "top routes" (no per-path dimension exists on
//! `workersInvocationsAdaptive`).

use askama::Template;
use stow_types::api::{
    CostMetric, DispatchFreezeCost, DispatchFreezeCostEntry, DispatchFreezeTrigger, TopRouteCount,
    UsageCheck,
};

/// `STOW_COST_BUDGET_MULTIPLIER` default — 1.0 means the service is
/// designed to live inside the included allowance; a multiplier loosens
/// or tightens every budget at once (e.g. 0.5 trips at half the
/// allowance for a shared account).
pub const DEFAULT_COST_BUDGET_MULTIPLIER: f64 = 1.0;

/// The Worker script name the Workers metrics filter on — must match
/// `cloudflare.name` in `Skyzen.toml`.
pub const WORKER_SCRIPT_NAME: &str = "stow-edge";

/// One metered dimension's monthly included allowance, in the unit
/// [`CostMetric`] names (requests/rows are counts, duration is GB-s,
/// CPU is milliseconds).
const MONTHLY_ALLOWANCE: &[(CostMetric, f64)] = &[
    (CostMetric::DurableObjectRowsRead, 25e9),
    (CostMetric::DurableObjectRowsWritten, 50e6),
    (CostMetric::DurableObjectRequests, 1e6),
    (CostMetric::DurableObjectDurationGbS, 400e3),
    (CostMetric::WorkerRequests, 10e6),
    (CostMetric::WorkerCpuMs, 30e6),
    (CostMetric::D1RowsRead, 25e9),
    (CostMetric::D1RowsWritten, 50e6),
];

/// Days per monthly allowance — the daily budget the check compares
/// usage-since-00:00-UTC against. Thirty days trips a sustained burn
/// early in the month rather than letting one bad day spend it.
const DAYS_PER_MONTH: f64 = 30.0;

/// Every metric's daily budget under `multiplier`.
#[must_use]
pub fn daily_budgets(multiplier: f64) -> Vec<(CostMetric, f64)> {
    MONTHLY_ALLOWANCE
        .iter()
        .map(|(metric, monthly)| (*metric, monthly / DAYS_PER_MONTH * multiplier))
        .collect()
}

/// Today's usage per metered dimension — one field per budget line,
/// `f64` so GB-s duration and µs→ms CPU conversions stay exact.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct UsageSnapshot {
    /// `durableObjectsPeriodicGroups.sum.rowsRead`.
    pub durable_object_rows_read: f64,
    /// `durableObjectsPeriodicGroups.sum.rowsWritten`.
    pub durable_object_rows_written: f64,
    /// `durableObjectsInvocationsAdaptiveGroups.sum.requests`.
    pub durable_object_requests: f64,
    /// `durableObjectsPeriodicGroups.sum.duration` — reported in GB-s,
    /// the billed unit.
    pub durable_object_duration_gb_s: f64,
    /// `workersInvocationsAdaptive.sum.requests` for `stow-edge`.
    pub worker_requests: f64,
    /// `workersInvocationsAdaptive.sum.cpuTimeUs` for `stow-edge`,
    /// divided by 1000 into milliseconds.
    pub worker_cpu_ms: f64,
    /// `d1AnalyticsAdaptiveGroups.sum.rowsRead`.
    pub d1_rows_read: f64,
    /// `d1AnalyticsAdaptiveGroups.sum.rowsWritten`.
    pub d1_rows_written: f64,
}

impl UsageSnapshot {
    /// The observed value for one metric.
    #[must_use]
    pub const fn of(&self, metric: CostMetric) -> f64 {
        match metric {
            CostMetric::DurableObjectRowsRead => self.durable_object_rows_read,
            CostMetric::DurableObjectRowsWritten => self.durable_object_rows_written,
            CostMetric::DurableObjectRequests => self.durable_object_requests,
            CostMetric::DurableObjectDurationGbS => self.durable_object_duration_gb_s,
            CostMetric::WorkerRequests => self.worker_requests,
            CostMetric::WorkerCpuMs => self.worker_cpu_ms,
            CostMetric::D1RowsRead => self.d1_rows_read,
            CostMetric::D1RowsWritten => self.d1_rows_written,
        }
    }
}

/// Fold a usage snapshot into the check verdict posted to the DO:
/// `over` lists every metric past its daily budget (worst ratio first),
/// `top_routes` is the day's request groups. The DO trips the freeze
/// when `over` is non-empty.
#[must_use]
pub fn evaluate_usage(
    usage: &UsageSnapshot,
    mut top_routes: Vec<TopRouteCount>,
    multiplier: f64,
) -> UsageCheck {
    top_routes.sort_by(|a, b| {
        b.requests
            .partial_cmp(&a.requests)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    top_routes.truncate(5);
    let mut over: Vec<DispatchFreezeCostEntry> = daily_budgets(multiplier)
        .into_iter()
        .filter(|(metric, budget)| usage.of(*metric) > *budget)
        .map(|(metric, budget)| DispatchFreezeCostEntry {
            metric,
            used: usage.of(metric),
            budget,
        })
        .collect();
    over.sort_by(|a, b| {
        (b.used / b.budget)
            .partial_cmp(&(a.used / a.budget))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    UsageCheck { over, top_routes }
}

/// The trigger a trip verdict becomes — the worst offender in `metric`,
/// every over-budget line in `over`.
#[must_use]
pub fn cost_trigger(check: &UsageCheck) -> Option<DispatchFreezeTrigger> {
    let first = check.over.first()?;
    Some(DispatchFreezeTrigger::Cost(DispatchFreezeCost {
        metric: first.metric,
        used: first.used,
        budget: first.budget,
        over: check.over.clone(),
        top_routes: check.top_routes.clone(),
    }))
}

/// Subject of the ops email a broken usage check sends — a hard error
/// the spec says is "logged and emailed", not skipped.
pub const USAGE_CHECK_ERROR_SUBJECT: &str = "[stow] usage check failed";

/// The incident-issue dedup key for usage-check failures.
pub const USAGE_CHECK_INCIDENT_KEY: &str = "usage-check";

/// Askama context for `templates/usage_check_error.txt` — the issue
/// post and the email's `text` part.
#[derive(askama::Template)]
#[template(path = "usage_check_error.txt")]
struct UsageCheckErrorTemplate<'a> {
    error: &'a str,
}

/// Askama context for `templates/usage_check_error.html`.
#[derive(askama::Template)]
#[template(path = "usage_check_error.html")]
struct UsageCheckErrorHtmlTemplate<'a> {
    error: &'a str,
}

/// Render the check-failure alert — the draft the "logged and emailed"
/// rule fans out to both channels.
#[allow(clippy::missing_errors_doc)]
pub fn render_usage_check_error(error: &str) -> Result<crate::freeze::AlertDraft, askama::Error> {
    let body = UsageCheckErrorTemplate { error }.render()?;
    let html = UsageCheckErrorHtmlTemplate { error }.render()?;
    let title = crate::freeze::incident_title(USAGE_CHECK_INCIDENT_KEY, "analytics probe failed")?;
    Ok(crate::freeze::AlertDraft {
        key: USAGE_CHECK_INCIDENT_KEY,
        subject: USAGE_CHECK_ERROR_SUBJECT.to_owned(),
        title,
        body,
        html,
    })
}

// ===== GraphQL wire shape =====

/// The GraphQL Analytics API endpoint — one POST serves all four
/// datasets' usage.
pub const GRAPHQL_URL: &str = "https://api.cloudflare.com/client/v4/graphql";

/// One query covers the whole budget table: Workers invocations for
/// `stow-edge`, both Durable Object datasets, and D1's
/// `d1AnalyticsAdaptiveGroups` — each filtered to today (UTC) on the
/// account tag. `date_geq` granularity is a day, which is exactly the
/// budget granularity.
pub const USAGE_QUERY: &str = r"query StowCostCheck($accountTag: String!, $since: Date!, $scriptName: String!) {
  viewer {
    accounts(filter: {accountTag: $accountTag}) {
      workersInvocationsAdaptive(filter: {date_geq: $since, scriptName: $scriptName}, limit: 500) {
        dimensions { scriptName }
        sum { requests cpuTimeUs subrequests }
      }
      durableObjectsInvocationsAdaptiveGroups(filter: {date_geq: $since}, limit: 100) {
        sum { requests }
      }
      durableObjectsPeriodicGroups(filter: {date_geq: $since}, limit: 100) {
        sum { activeTime cpuTime duration rowsRead rowsWritten }
      }
      d1AnalyticsAdaptiveGroups(filter: {date_geq: $since}, limit: 100) {
        sum { rowsRead rowsWritten }
      }
    }
  }
}";

/// The POST body the scheduled handler sends.
#[derive(Debug, serde::Serialize)]
pub struct UsageQuery {
    pub query: &'static str,
    pub variables: UsageQueryVars,
}

/// Query variables — the account, today's date (UTC `YYYY-MM-DD`), and
/// the Worker script name.
#[derive(Debug, serde::Serialize)]
pub struct UsageQueryVars {
    #[serde(rename = "accountTag")]
    pub account_tag: String,
    pub since: String,
    #[serde(rename = "scriptName")]
    pub script_name: String,
}

// Response decoding — the datasets answer a list of groups, each with
// optional `dimensions` and a `sum` object; absent groups deserialize
// as empty vecs and absent sums as zeros.

#[derive(Debug, serde::Deserialize)]
struct GraphqlResponse {
    data: Option<UsageData>,
    errors: Option<Vec<GraphqlError>>,
}

#[derive(Debug, serde::Deserialize)]
struct GraphqlError {
    message: String,
}

#[derive(Debug, serde::Deserialize)]
struct UsageData {
    viewer: UsageViewer,
}

#[derive(Debug, serde::Deserialize)]
struct UsageViewer {
    accounts: Vec<UsageAccount>,
}

#[derive(Debug, serde::Deserialize)]
struct UsageAccount {
    #[serde(rename = "workersInvocationsAdaptive", default)]
    workers_invocations: Vec<WorkerInvocationGroup>,
    #[serde(rename = "durableObjectsInvocationsAdaptiveGroups", default)]
    do_invocations: Vec<DoInvocationGroup>,
    #[serde(rename = "durableObjectsPeriodicGroups", default)]
    do_periodic: Vec<DoPeriodicGroup>,
    #[serde(rename = "d1AnalyticsAdaptiveGroups", default)]
    d1_analytics: Vec<D1AnalyticsGroup>,
}

#[derive(Debug, serde::Deserialize)]
struct WorkerInvocationGroup {
    dimensions: Option<WorkerDimensions>,
    sum: Option<WorkerSum>,
}

#[derive(Debug, serde::Deserialize)]
struct WorkerDimensions {
    #[serde(rename = "scriptName")]
    script_name: Option<String>,
}

#[derive(Debug, serde::Deserialize, Default)]
struct WorkerSum {
    #[serde(default)]
    requests: f64,
    #[serde(rename = "cpuTimeUs", default)]
    cpu_time_us: f64,
}

#[derive(Debug, serde::Deserialize)]
struct DoInvocationGroup {
    sum: Option<DoInvocationSum>,
}

#[derive(Debug, serde::Deserialize, Default)]
struct DoInvocationSum {
    #[serde(default)]
    requests: f64,
}

#[derive(Debug, serde::Deserialize)]
struct DoPeriodicGroup {
    sum: Option<DoPeriodicSum>,
}

#[derive(Debug, serde::Deserialize, Default)]
struct DoPeriodicSum {
    #[serde(default)]
    duration: f64,
    #[serde(rename = "rowsRead", default)]
    rows_read: f64,
    #[serde(rename = "rowsWritten", default)]
    rows_written: f64,
}

#[derive(Debug, serde::Deserialize)]
struct D1AnalyticsGroup {
    sum: Option<D1Sum>,
}

#[derive(Debug, serde::Deserialize, Default)]
struct D1Sum {
    #[serde(rename = "rowsRead", default)]
    rows_read: f64,
    #[serde(rename = "rowsWritten", default)]
    rows_written: f64,
}

/// Decode a GraphQL response into the usage snapshot plus the day's
/// request groups by `scriptName`. A non-empty `errors` array is a hard
/// error — the check is broken, not quiet — and the caller reports it
/// rather than evaluating a partial snapshot.
pub fn parse_usage_response(body: &str) -> Result<(UsageSnapshot, Vec<TopRouteCount>), String> {
    let response: GraphqlResponse =
        serde_json::from_str(body).map_err(|error| format!("decode GraphQL response: {error}"))?;
    if let Some(errors) = response.errors
        && !errors.is_empty()
    {
        let messages: Vec<String> = errors.into_iter().map(|error| error.message).collect();
        return Err(format!("GraphQL errors: {}", messages.join("; ")));
    }
    let Some(data) = response.data else {
        return Err("GraphQL response carried no data".to_owned());
    };
    let mut snapshot = UsageSnapshot::default();
    let mut route_counts: std::collections::BTreeMap<String, f64> =
        std::collections::BTreeMap::new();
    for account in data.viewer.accounts {
        for group in account.workers_invocations {
            if let Some(sum) = group.sum {
                snapshot.worker_requests += sum.requests;
                snapshot.worker_cpu_ms += sum.cpu_time_us / 1000.0;
                if let Some(dimensions) = group.dimensions
                    && let Some(script) = dimensions.script_name
                {
                    *route_counts.entry(script).or_default() += sum.requests;
                }
            }
        }
        for group in account.do_invocations {
            if let Some(sum) = group.sum {
                snapshot.durable_object_requests += sum.requests;
            }
        }
        for group in account.do_periodic {
            if let Some(sum) = group.sum {
                snapshot.durable_object_duration_gb_s += sum.duration;
                snapshot.durable_object_rows_read += sum.rows_read;
                snapshot.durable_object_rows_written += sum.rows_written;
            }
        }
        for group in account.d1_analytics {
            if let Some(sum) = group.sum {
                snapshot.d1_rows_read += sum.rows_read;
                snapshot.d1_rows_written += sum.rows_written;
            }
        }
    }
    let mut top_routes: Vec<TopRouteCount> = route_counts
        .into_iter()
        .map(|(label, requests)| TopRouteCount { label, requests })
        .collect();
    top_routes.sort_by(|a, b| {
        b.requests
            .partial_cmp(&a.requests)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    top_routes.truncate(5);
    Ok((snapshot, top_routes))
}

/// Today's UTC date (`YYYY-MM-DD`) — the `date_geq` argument. Wasm-only
/// because the only clock in the Worker runtime is `js_sys::Date`.
#[cfg(target_arch = "wasm32")]
#[must_use]
pub fn today_utc() -> String {
    let iso = js_sys::Date::new_0()
        .to_iso_string()
        .as_string()
        .unwrap_or_default();
    iso.get(..10).unwrap_or(&iso).to_owned()
}

/// Run one usage check: POST the query, decode, evaluate the budgets,
/// and post the verdict to the scheduler DO, which owns the freeze
/// transition and the email. Query/HTTP errors are reported up — the
/// caller logs and mails them (a blind check is itself a fault).
#[cfg(target_arch = "wasm32")]
pub async fn run_usage_check(
    account_id: &str,
    analytics_token: &str,
    scheduler: &skyzen_cloudflare::CfDurableNamespace,
    multiplier: f64,
) -> Result<(), String> {
    use skyzen_cloudflare::worker::send::{IntoSendFuture as _, SendWrapper};

    let body = serde_json::to_vec(&UsageQuery {
        query: USAGE_QUERY,
        variables: UsageQueryVars {
            account_tag: account_id.to_owned(),
            since: today_utc(),
            script_name: WORKER_SCRIPT_NAME.to_owned(),
        },
    })
    .map_err(|error| format!("encode usage query: {error}"))?;
    let authorization = format!("Bearer {analytics_token}");
    let request = SendWrapper::new(
        crate::cf_http::bare_request(
            skyzen_cloudflare::worker::Method::Post,
            GRAPHQL_URL,
            &[
                ("Authorization", authorization.as_str()),
                ("Content-Type", "application/json"),
            ],
            Some(body.as_slice()),
        )
        .map_err(|error| format!("build usage query request: {error}"))?,
    );
    let mut response = SendWrapper::new(
        skyzen_cloudflare::CfFetch
            .request(&request)
            .await
            .map_err(|error| format!("usage query fetch: {error}"))?,
    );
    let status = response.status_code();
    let text = response
        .text()
        .into_send()
        .await
        .map_err(|error| format!("read usage response body: {error}"))?;
    if !(200..300).contains(&status) {
        return Err(format!("usage query HTTP {status}: {text}"));
    }
    let (snapshot, top_routes) = parse_usage_response(&text)?;
    let check = evaluate_usage(&snapshot, top_routes, multiplier);
    crate::scheduler_client::report_usage_check(scheduler, &check)
        .await
        .map_err(|error| format!("post usage check to scheduler: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_COST_BUDGET_MULTIPLIER, UsageSnapshot, cost_trigger, daily_budgets, evaluate_usage,
        parse_usage_response,
    };
    use stow_types::api::{CostMetric, DispatchFreezeTrigger, TopRouteCount};

    /// The response shape `durableObjectsPeriodicGroups` answers with —
    /// one group per day/namespace cell.
    const FIXTURE_UNDER_BUDGET: &str = r#"{
        "data": {"viewer": {"accounts": [{
            "workersInvocationsAdaptive": [
                {"dimensions": {"scriptName": "stow-edge"}, "sum": {"requests": 12000, "cpuTimeUs": 500000000}},
                {"dimensions": {"scriptName": "stow-edge"}, "sum": {"requests": 8000, "cpuTimeUs": 300000000}}
            ],
            "durableObjectsInvocationsAdaptiveGroups": [{"sum": {"requests": 5000}}],
            "durableObjectsPeriodicGroups": [{"sum": {"activeTime": 1000, "cpuTime": 500, "duration": 1000.5, "rowsRead": 1000000, "rowsWritten": 200000}}],
            "d1AnalyticsAdaptiveGroups": [{"sum": {"rowsRead": 500000, "rowsWritten": 80000}}]
        }]}}
    }"#;

    const FIXTURE_OVER_BUDGET: &str = r#"{
        "data": {"viewer": {"accounts": [{
            "workersInvocationsAdaptive": [
                {"dimensions": {"scriptName": "stow-edge"}, "sum": {"requests": 900000, "cpuTimeUs": 900000000000}},
                {"dimensions": {"scriptName": "other-script"}, "sum": {"requests": 4000, "cpuTimeUs": 1000000000}}
            ],
            "durableObjectsInvocationsAdaptiveGroups": [{"sum": {"requests": 40000}}],
            "durableObjectsPeriodicGroups": [{"sum": {"activeTime": 1000, "cpuTime": 500, "duration": 200000, "rowsRead": 900000000000, "rowsWritten": 2000000}}],
            "d1AnalyticsAdaptiveGroups": [{"sum": {"rowsRead": 100000, "rowsWritten": 10000}}]
        }]}}
    }"#;

    const FIXTURE_ERRORS: &str = r#"{
        "data": null,
        "errors": [{"message": "unknown field 'rowsRead' on dataset"}]
    }"#;

    #[test]
    fn fixture_under_budget_never_trips() {
        let (snapshot, routes) = parse_usage_response(FIXTURE_UNDER_BUDGET).expect("parses");
        assert!((snapshot.durable_object_rows_read - 1_000_000.0).abs() < f64::EPSILON);
        assert!((snapshot.worker_cpu_ms - 800_000.0).abs() < f64::EPSILON);
        let check = evaluate_usage(&snapshot, routes, DEFAULT_COST_BUDGET_MULTIPLIER);
        assert!(check.over.is_empty());
        assert!(cost_trigger(&check).is_none());
    }

    #[test]
    fn fixture_over_budget_trips_on_do_rows_read_and_names_routes() {
        let (snapshot, routes) = parse_usage_response(FIXTURE_OVER_BUDGET).expect("parses");
        // 900e9 rows read > 25e9/30 ≈ 833e6 daily budget.
        let check = evaluate_usage(&snapshot, routes, DEFAULT_COST_BUDGET_MULTIPLIER);
        assert!(!check.over.is_empty());
        assert_eq!(
            check.over[0].metric,
            CostMetric::DurableObjectRowsRead,
            "the worst ratio leads the over-budget list"
        );
        let metrics: Vec<CostMetric> = check.over.iter().map(|entry| entry.metric).collect();
        // 200e3 GB-s duration > 400e3/30 ≈ 13.3e3; 900e3 worker requests >
        // 10e6/30 ≈ 333e3; 900e9 µs = 900e6 ms > 1e6 ms CPU budget.
        for expected in [
            CostMetric::DurableObjectRowsRead,
            CostMetric::DurableObjectDurationGbS,
            CostMetric::WorkerRequests,
            CostMetric::WorkerCpuMs,
        ] {
            assert!(metrics.contains(&expected), "missing {expected:?}");
        }
        assert_eq!(check.top_routes[0].label, "stow-edge");
        let Some(DispatchFreezeTrigger::Cost(cost)) = cost_trigger(&check) else {
            panic!("expected a cost trigger");
        };
        assert_eq!(cost.metric, CostMetric::DurableObjectRowsRead);
        assert!((cost.used - 900_000_000_000.0).abs() < f64::EPSILON);
        assert!(cost.budget > 800_000_000.0 && cost.budget < 900_000_000.0);
    }

    #[test]
    fn graphql_errors_are_a_hard_error_not_a_quiet_skip() {
        let error = parse_usage_response(FIXTURE_ERRORS).expect_err("errors array is fatal");
        assert!(error.contains("unknown field"));
    }

    #[test]
    fn multiplier_scales_every_budget() {
        let budgets = daily_budgets(2.0);
        let do_rows_read = budgets
            .iter()
            .find(|(metric, _)| *metric == CostMetric::DurableObjectRowsRead)
            .map(|(_, budget)| *budget)
            .expect("rows read budget exists");
        // 25e9/30 * 2 = 1.66e9.
        assert!(do_rows_read > 1.6e9 && do_rows_read < 1.7e9);

        let usage = UsageSnapshot {
            durable_object_rows_read: 1.0e9,
            ..UsageSnapshot::default()
        };
        let check = evaluate_usage(&usage, Vec::new(), 1.0);
        assert!(!check.over.is_empty());
        let check = evaluate_usage(&usage, Vec::new(), 2.0);
        assert!(check.over.is_empty(), "2x budget absorbs the same usage");
    }

    #[test]
    fn exactly_at_budget_does_not_trip() {
        let budgets = daily_budgets(1.0);
        let mut usage = UsageSnapshot::default();
        for (metric, budget) in &budgets {
            if metric == &CostMetric::WorkerRequests {
                usage.worker_requests = *budget;
            }
        }
        // The trip is strictly over budget — equality is not a trip.
        let check = evaluate_usage(&usage, Vec::new(), 1.0);
        assert!(check.over.is_empty());
        usage.worker_requests *= 1.000_000_1;
        let check = evaluate_usage(&usage, Vec::new(), 1.0);
        assert_eq!(check.over.len(), 1);
    }

    #[test]
    fn top_routes_group_by_script_name() {
        let routes = vec![
            TopRouteCount {
                label: "a".to_owned(),
                requests: 5.0,
            },
            TopRouteCount {
                label: "b".to_owned(),
                requests: 50.0,
            },
        ];
        let check = evaluate_usage(&UsageSnapshot::default(), routes, 1.0);
        assert_eq!(check.top_routes[0].label, "b");
    }
}
