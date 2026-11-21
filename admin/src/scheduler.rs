//! `stow-admin scheduler …` — the scheduler Durable Object's operations
//! surface. The reset lives here because it is operations work, not
//! request work: an operator runs `scheduler reset --yes` to create the
//! store's schema (or destroy and recreate it after a schema change),
//! and the route it posts to is the only code that may issue DDL on
//! the queue database.

use clap::{Args, Subcommand};
use stow_types::api::{
    DispatchCapSet, DispatchCaps, DispatchRate, DispatchRateSet, MemoryLineSet, MemoryLines,
    MinCliVersion, MinCliVersionSet, ReleasePriority, ReleasePrioritySet, SchedulerBudgetReport,
    SchedulerBudgetRequest, SchedulerResetReport, SchedulerSeedReport,
};

use crate::Edge;
use crate::render::{self, Output};

/// The fixture seed builds the graph and the budget pass replays every
/// scheduler drive on it, each inside one Durable Object request, so
/// both legitimately outlive the 45 s default edge bound — sized ~10× over the measured pass duration
/// at the 100k fixture.
const BUDGET_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(15);

#[derive(Args)]
pub struct SchedulerArgs {
    #[command(subcommand)]
    pub command: SchedulerCommand,
}

#[derive(Subcommand)]
pub enum SchedulerCommand {
    /// Reset the scheduler store: drop every table, index and trigger
    /// and re-execute `schema.sql`. This destroys the queue and every
    /// recorded slice, so the command refuses to run without `--yes`.
    /// `operations.yml` refills both once the reset succeeds: it
    /// dispatches `index-publish.yml` with `report=true` for every
    /// published rustc and a forced `preheat-cron.yml` wave, and a
    /// failed dispatch fails the run. It is also how a store that was
    /// never initialized gets its schema.
    Reset {
        /// Confirm the destructive reset.
        #[arg(long)]
        yes: bool,
    },
    /// The workerd cost probe — drives every scheduler route and the
    /// alarm pass on a seeded fixture and reports the real
    /// `rowsRead`/`rowsWritten` the Durable Object bills. The route
    /// answers only on deploys carrying `STOW_SCHEDULER_BUDGET=1`
    /// (the mock stack); use `seed` to load the fixture first.
    Budget {
        /// Queue rows to seed before measuring; seeding wipes the
        /// store first, so a store holding an earlier fixture is fine.
        #[arg(long)]
        queue_rows: Option<u32>,
        /// Do not seed; measure the fixture the store was last seeded
        /// with (the probe reseeds it to its canonical state).
        #[arg(long)]
        no_seed: bool,
        /// Override the deploy's dispatch cap for the alarm-pass drives.
        /// The mock deploys a tiny cap (`STOW_MAX_CONCURRENT_JOBS=3`)
        /// for its own stability — a pass run under it claims nothing
        /// and prices a claim at zero, so the harness passes the
        /// production cap from `edge/Skyzen.toml` here.
        #[arg(long)]
        dispatch_limit: Option<u32>,
    },
    /// The hourly demand feed's native leg (stow#523): resume the
    /// durable cursor's unfinished hour — frozen pages deliver without
    /// a new Analytics Engine query — or materialize the next closed
    /// hour, freeze it on the page manifest and deliver it to
    /// `delivered`. The hourly GitHub job is the intended caller.
    DemandFeed {
        /// Materialize this specific closed hour (`YYYY-MM-DDTHH`, UTC)
        /// instead of following the durable cursor — the operator's
        /// recovery path.
        #[arg(long)]
        hour: Option<String>,
    },
}

/// Dispatch one `scheduler` subcommand against the edge connection.
pub async fn run(
    edge: &Edge,
    args: SchedulerArgs,
    output: Output,
) -> stow_types::error::Result<()> {
    match args.command {
        SchedulerCommand::Reset { yes } => reset(edge, yes, output).await,
        SchedulerCommand::Budget {
            queue_rows,
            no_seed,
            dispatch_limit,
        } => budget(edge, queue_rows, no_seed, dispatch_limit, output).await,
        SchedulerCommand::DemandFeed { hour } => {
            crate::demand_feed::run(edge, crate::demand_feed::DemandFeedArgs { hour }, output).await
        }
    }
}

/// Runtime operator settings captured before a `scheduler reset` and
/// re-applied immediately after `schema.sql` recreates the store,
/// before `operations.yml` dispatches refill workflows.
#[derive(Debug, Default, PartialEq, Eq)]
struct PreservedSettings {
    memory_line: Option<MemoryLineSet>,
    dispatch_rate: Option<DispatchRateSet>,
    dispatch_cap: Option<DispatchCapSet>,
    release_priority: Option<ReleasePrioritySet>,
    min_cli_version: Option<MinCliVersionSet>,
}

impl PreservedSettings {
    async fn capture(edge: &Edge) -> Self {
        // `memory-line` lives outside the graph: if this read fails the
        // store is uninitialized (first deploy), so skip the four
        // graph-backed probes; if it succeeds, preserve `memory_line`
        // even when the graph itself cannot wake.
        let Ok(memory) = edge
            .get_json::<MemoryLines>("/api/v1/admin/memory-line")
            .await
        else {
            return Self::default();
        };
        let (rate, cap, release, min_cli) = futures_util::join!(
            edge.get_json::<DispatchRate>("/api/v1/admin/dispatch-rate"),
            edge.get_json::<DispatchCaps>("/api/v1/admin/dispatch-cap"),
            edge.get_json::<ReleasePriority>("/api/v1/admin/release-priority"),
            edge.get_json::<MinCliVersion>("/api/v1/admin/min-cli-version"),
        );
        Self {
            memory_line: memory.setting.map(|s| s.lines),
            dispatch_rate: rate.ok().and_then(|v| v.setting).map(|s| DispatchRateSet {
                max_runs_per_minute: s.max_runs_per_minute,
            }),
            dispatch_cap: cap.ok().and_then(|v| v.setting).map(|s| DispatchCapSet {
                max_concurrent_jobs: s.max_concurrent_jobs,
                max_concurrent_macos_jobs: s.max_concurrent_macos_jobs,
            }),
            release_priority: release
                .ok()
                .and_then(|v| v.setting)
                .map(|s| ReleasePrioritySet { percent: s.percent }),
            min_cli_version: min_cli
                .ok()
                .and_then(|v| v.setting)
                .map(|s| MinCliVersionSet { version: s.version }),
        }
    }

    async fn restore(self, edge: &Edge) -> stow_types::error::Result<()> {
        if let Some(plan) = &self.memory_line {
            let _: MemoryLines = edge.post_json("/api/v1/admin/memory-line", plan).await?;
        }
        // Restore `dispatch-rate` strictly ahead of `dispatch-cap` so a
        // subsequent refill never sees a raised concurrency ceiling
        // without its per-minute start bound.
        if let Some(plan) = &self.dispatch_rate {
            let _: DispatchRate = edge.post_json("/api/v1/admin/dispatch-rate", plan).await?;
        }
        if let Some(plan) = &self.dispatch_cap {
            let _: DispatchCaps = edge.post_json("/api/v1/admin/dispatch-cap", plan).await?;
        }
        if let Some(plan) = &self.release_priority {
            let _: ReleasePriority = edge
                .post_json("/api/v1/admin/release-priority", plan)
                .await?;
        }
        if let Some(plan) = &self.min_cli_version {
            let _: MinCliVersion = edge
                .post_json("/api/v1/admin/min-cli-version", plan)
                .await?;
        }
        Ok(())
    }
}

async fn reset(edge: &Edge, yes: bool, output: Output) -> stow_types::error::Result<()> {
    if !yes {
        return Err(stow_types::error::Error::msg(
            "scheduler reset drops every table, index and trigger in the store \
             and recreates `schema.sql` — the queue and recorded slices are \
             destroyed, and the operations run refills them once the reset \
             succeeds; re-run with --yes",
        ));
    }
    let preserved = PreservedSettings::capture(edge).await;
    let report: SchedulerResetReport = edge
        .post_json("/api/v1/admin/scheduler/reset", &serde_json::json!({}))
        .await?;
    preserved.restore(edge).await?;
    render::emit(output, &report, |report| {
        format!("scheduler store reset — {} objects dropped", report.dropped)
    })
}

/// Run `call`, repeating it up to three more times after a failure: the
/// dev runtime drops the Durable Object stub connection after a long
/// request, and the same call succeeds on a fresh one.
async fn retry_dropped_stub<T, Fut: std::future::Future<Output = stow_types::error::Result<T>>>(
    what: &str,
    mut call: impl FnMut() -> Fut,
) -> stow_types::error::Result<T> {
    let mut attempts = 0u8;
    loop {
        match call().await {
            Ok(value) => return Ok(value),
            Err(error) if attempts < 3 => {
                attempts += 1;
                eprintln!("[budget] {what} call failed, retrying: {error}");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn budget(
    edge: &Edge,
    queue_rows: Option<u32>,
    no_seed: bool,
    dispatch_limit: Option<u32>,
    output: Output,
) -> stow_types::error::Result<()> {
    if !no_seed {
        // One call wipes the store and seeds the whole fixture, so a
        // transient workerd failure (a dropped dev-runtime stub
        // connection) retries the same call rather than resuming.
        let body = serde_json::json!({ "queue_rows": queue_rows });
        let seed: SchedulerSeedReport = retry_dropped_stub("seed", || {
            edge.post_json_with_timeout(
                "/api/v1/admin/scheduler/budget/seed",
                &body,
                BUDGET_PROBE_TIMEOUT,
            )
        })
        .await?;
        eprintln!(
            "[budget] seeded: nodes={} edges={} published={}",
            seed.nodes, seed.edges, seed.published
        );
    }
    // The first call after a long seed meets the same dropped stub, and
    // the probe reseeds the fixture itself, so the retry is the same call.
    let request = SchedulerBudgetRequest { dispatch_limit };
    let report: SchedulerBudgetReport = retry_dropped_stub("probe", || {
        edge.post_json_with_timeout(
            "/api/v1/admin/scheduler/budget",
            &request,
            BUDGET_PROBE_TIMEOUT,
        )
    })
    .await?;
    let over = report.over_budget;
    render::emit(output, &report, render_budget_table)?;
    if over {
        return Err(stow_types::error::Error::msg("scheduler budget exceeded"));
    }
    Ok(())
}

/// The budget table as a terminal row set — one line per drive with its
/// four measurements against budget, the `OVER` marker on a gated
/// breach, and `SLOW` on a wall-budget breach — reported, never gated
/// (stow#567).
fn render_budget_table(report: &SchedulerBudgetReport) -> String {
    let mut out = format!("scheduler budget (queue rows {}):\n", report.queue_rows);
    for row in &report.rows {
        let marker = format!(
            "{}{}",
            if row.over_budget { " OVER" } else { "" },
            if row.over_wall { " SLOW" } else { "" },
        );
        let _ = std::fmt::Write::write_fmt(
            &mut out,
            format_args!(
                "  {:<34} stmts={:<3}/{:<3} rows_read={:<7}/{:<7} rows_written={:<6}/{:<6} wall_ms={:<5}/{:<5}{}\n",
                row.name,
                row.statements,
                row.statement_budget,
                row.rows_read,
                row.read_budget,
                row.rows_written,
                row.write_budget,
                row.wall_ms,
                row.wall_budget,
                marker,
            ),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use axum::http::StatusCode;
    use axum::response::IntoResponse as _;
    use serde_json::{Value, json};
    use tokio::sync::mpsc;

    use super::{Output, reset};
    use crate::Edge;

    type RouteMap = BTreeMap<&'static str, (StatusCode, Value)>;

    struct StubShared {
        routes: RouteMap,
        calls: mpsc::Sender<(String, Value)>,
    }

    struct StubEdge {
        edge: Edge,
        calls: mpsc::Receiver<(String, Value)>,
    }

    async fn stub_handler(
        axum::extract::State(shared): axum::extract::State<Arc<StubShared>>,
        request: axum::extract::Request,
    ) -> axum::response::Response {
        let key = format!("{} {}", request.method(), request.uri().path());
        let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024)
            .await
            .expect("body");
        let body = serde_json::from_slice::<Value>(&bytes).unwrap_or_default();
        shared.calls.try_send((key.clone(), body)).expect("record");
        let (status, payload) = shared
            .routes
            .get(key.as_str())
            .cloned()
            .unwrap_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": key})));
        (status, axum::Json(payload)).into_response()
    }

    async fn spawn_stub(routes: RouteMap) -> StubEdge {
        let (calls, rx) = mpsc::channel(32);
        let app = axum::Router::new()
            .fallback(axum::routing::any(stub_handler))
            .with_state(Arc::new(StubShared { routes, calls }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        StubEdge {
            edge: Edge::for_test(format!("http://{addr}")),
            calls: rx,
        }
    }

    fn drain_posts(calls: &mut mpsc::Receiver<(String, Value)>) -> Vec<(String, Value)> {
        let mut posts = Vec::new();
        while let Ok((key, body)) = calls.try_recv() {
            if key.starts_with("POST ") {
                posts.push((key, body));
            }
        }
        posts
    }

    fn configured_gets() -> RouteMap {
        BTreeMap::from([
            (
                "GET /api/v1/admin/memory-line",
                (
                    StatusCode::OK,
                    json!({
                        "setting": {
                            "normal_line_bytes": 75_000_000,
                            "small_line_bytes": 85_000_000,
                            "small_increment_bytes": 65_536,
                            "set_at": "2026-11-21T00:00:00Z",
                            "actor": "lexoliu"
                        },
                        "normal_line_bytes": 75_000_000,
                        "small_line_bytes": 85_000_000,
                        "small_increment_bytes": 65_536
                    }),
                ),
            ),
            (
                "GET /api/v1/admin/dispatch-rate",
                (
                    StatusCode::OK,
                    json!({
                        "setting": {
                            "max_runs_per_minute": 150,
                            "set_at": "2026-11-21T00:00:00Z",
                            "actor": "lexoliu"
                        },
                        "max_runs_per_minute": 150,
                        "started_last_minute": 12
                    }),
                ),
            ),
            (
                "GET /api/v1/admin/dispatch-cap",
                (
                    StatusCode::OK,
                    json!({
                        "setting": {
                            "max_concurrent_jobs": 500,
                            "max_concurrent_macos_jobs": 60,
                            "set_at": "2026-11-21T00:00:00Z",
                            "actor": "lexoliu"
                        },
                        "max_concurrent_jobs": 500,
                        "max_concurrent_macos_jobs": 60
                    }),
                ),
            ),
            (
                "GET /api/v1/admin/release-priority",
                (StatusCode::OK, json!({ "percent": 10 })),
            ),
            (
                "GET /api/v1/admin/min-cli-version",
                (
                    StatusCode::OK,
                    json!({
                        "setting": {
                            "version": "0.21.8",
                            "set_at": "2026-11-21T00:00:00Z",
                            "actor": "lexoliu"
                        },
                        "version": "0.21.8"
                    }),
                ),
            ),
        ])
    }

    fn configured_routes() -> RouteMap {
        let mut routes = configured_gets();
        routes.extend([
            (
                "POST /api/v1/admin/scheduler/reset",
                (StatusCode::OK, json!({ "dropped": 8 })),
            ),
            (
                "POST /api/v1/admin/memory-line",
                (
                    StatusCode::OK,
                    json!({
                        "normal_line_bytes": 75_000_000,
                        "small_line_bytes": 85_000_000,
                        "small_increment_bytes": 65_536
                    }),
                ),
            ),
            (
                "POST /api/v1/admin/dispatch-rate",
                (
                    StatusCode::OK,
                    json!({ "max_runs_per_minute": 150, "started_last_minute": 0 }),
                ),
            ),
            (
                "POST /api/v1/admin/dispatch-cap",
                (
                    StatusCode::OK,
                    json!({ "max_concurrent_jobs": 500, "max_concurrent_macos_jobs": 60 }),
                ),
            ),
            (
                "POST /api/v1/admin/min-cli-version",
                (StatusCode::OK, json!({ "version": "0.21.8" })),
            ),
        ]);
        routes
    }

    #[tokio::test]
    async fn reset_preserves_operator_settings_and_restores_rate_before_cap() {
        let mut stub = spawn_stub(configured_routes()).await;
        reset(&stub.edge, true, Output::Json).await.expect("reset");
        let posts = drain_posts(&mut stub.calls);
        let keys: Vec<&str> = posts.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "POST /api/v1/admin/scheduler/reset",
                "POST /api/v1/admin/memory-line",
                "POST /api/v1/admin/dispatch-rate",
                "POST /api/v1/admin/dispatch-cap",
                "POST /api/v1/admin/min-cli-version",
            ]
        );
        assert_eq!(
            posts[2].1,
            json!({ "max_runs_per_minute": 150 }),
            "dispatch-rate restores ahead of dispatch-cap"
        );
        assert_eq!(
            posts[3].1,
            json!({ "max_concurrent_jobs": 500, "max_concurrent_macos_jobs": 60 })
        );
    }

    #[tokio::test]
    async fn reset_preserves_memory_line_on_unwakeable_graph_and_skips_uninitialized_store() {
        let mut torn = BTreeMap::from([
            configured_routes()
                .remove_entry("GET /api/v1/admin/memory-line")
                .expect("memory-line get"),
            (
                "POST /api/v1/admin/scheduler/reset",
                (StatusCode::OK, json!({ "dropped": 8 })),
            ),
            configured_routes()
                .remove_entry("POST /api/v1/admin/memory-line")
                .expect("memory-line post"),
        ]);
        let mut stub = spawn_stub(torn.clone()).await;
        reset(&stub.edge, true, Output::Json)
            .await
            .expect("reset over torn graph");
        let posts = drain_posts(&mut stub.calls);
        assert_eq!(posts.len(), 2);
        assert_eq!(posts[0].0, "POST /api/v1/admin/scheduler/reset");
        assert_eq!(posts[1].0, "POST /api/v1/admin/memory-line");

        torn.remove("GET /api/v1/admin/memory-line");
        let mut fresh = spawn_stub(torn).await;
        reset(&fresh.edge, true, Output::Json)
            .await
            .expect("first-deploy reset");
        let mut all = Vec::new();
        while let Ok((key, _)) = fresh.calls.try_recv() {
            all.push(key);
        }
        assert_eq!(
            all,
            vec![
                "GET /api/v1/admin/memory-line",
                "POST /api/v1/admin/scheduler/reset",
            ]
        );
    }
}
