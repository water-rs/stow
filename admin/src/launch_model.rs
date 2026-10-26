//! `stow-admin launch-model export` — regenerates the checked-in
//! `launch-model.toml` from production's own events (stow#452).
//!
//! Two production surfaces feed the window snapshot:
//!
//! - **Analytics Engine** (`stow_events`, `stow_cache_misses`) — the
//!   install count, the byte-path fetch count (sampled points carry
//!   their weight in `double1`, so `sum(double1)` restores the true
//!   count) and the miss-node count. These are the only counters the
//!   edge writes to AE.
//! - **Zone HTTP analytics** (`httpRequestsAdaptiveGroups` grouped by
//!   method and path) — the only production record of index pulls,
//!   admissions, enqueues, human requests, status reads, site views,
//!   index publishes and operator work: the edge writes no AE point for
//!   any of them. Webhook deliveries, request outcomes, trusted submits
//!   and health probes are priced from their fixed shapes instead, so
//!   the window does not count them.
//!
//! - **Rust's release notes** (`RELEASES.md` in rust-lang/rust, one
//!   `Version X.Y.Z (YYYY-MM-DD)` heading per stable release, point
//!   releases included) — the stable-release cadence: how many stable
//!   rustc releases landed in the [`RELEASE_HISTORY_DAYS`] before the
//!   window's end. Each one brings a full preheat wave.
//!
//! The window's rates divide each count by `days × install_days`. The
//! launch gate multiplies them back up at `installs × days_per_month`,
//! so the file holds only what the window measured, not the projection.
//!
//! `--from-snapshot` reads a captured window snapshot instead of
//! Cloudflare — the fixture-driven path the CI test exercises while the
//! account is frozen. `--write-snapshot` records what a live export
//! read, so the model diff and its inputs review together.

use std::collections::BTreeMap;
use std::path::PathBuf;

use askama::Template as _;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use stow_types::launch_model::{
    LaunchCadence, LaunchModel, LaunchRates, LaunchRatios, LaunchScale, LaunchWindow,
};
use stow_types::stow_error;

use crate::cloudflare;
use crate::maintenance::CF_ZONE_ID_ENV;
use crate::render::{self, Output};

/// The checked-in file's location and default output.
const DEFAULT_OUT: &str = "launch-model.toml";

/// `CF_ACCOUNT_ID` — the account the AE SQL and zone analytics read.
const CF_ACCOUNT_ID_ENV: &str = "CF_ACCOUNT_ID";

/// `YYYY-MM-DD` calendar bounds every launch-model Analytics Engine
/// query shares — the one typed value the three askama templates
/// render into `toDateTime` literals; no marker replace, no
/// hand-built SQL text.
#[derive(Debug)]
struct QueryWindow {
    /// Inclusive first day of the window.
    since: String,
    /// Exclusive day after the window's end.
    until: String,
}

/// The Analytics Engine SQL API posts one query and answers
/// `{"data": [...]}` — the same `FORMAT JSON` envelope the edge's stats
/// surface decodes.
/// `launch_model/install_days.sql` — distinct install-days over the
/// window.
#[derive(Debug, askama::Template)]
#[template(path = "launch_model/install_days.sql", escape = "txt")]
struct InstallDaysQuery<'a> {
    /// The shared window bounds.
    window: &'a QueryWindow,
}

/// `launch_model/cli_fetches.sql` — sampled fetch weight over the
/// window (the `Float64` estimate).
#[derive(Debug, askama::Template)]
#[template(path = "launch_model/cli_fetches.sql", escape = "txt")]
struct CliFetchesQuery<'a> {
    /// The shared window bounds.
    window: &'a QueryWindow,
}

/// `launch_model/miss_nodes.sql` — miss points over the window (the
/// `Float64` estimate).
#[derive(Debug, askama::Template)]
#[template(path = "launch_model/miss_nodes.sql", escape = "txt")]
struct MissNodesQuery<'a> {
    /// The shared window bounds.
    window: &'a QueryWindow,
}

/// One `count(DISTINCT)` row [`InstallDaysQuery`] returns — `FORMAT
/// JSON` quotes `UInt64`, so `de_u64` decodes it.
#[derive(Debug, Deserialize)]
struct AeCountRow {
    /// The queried aggregate — the query selects it as `value`.
    #[serde(deserialize_with = "stow_types::analytics::de_u64")]
    value: u64,
}

/// One `sum(_sample_interval * double1)` row — the additive estimate
/// is `Float64`, decoded with `de_f64` and validated losslessly
/// before its u64 use rather than clamped.
#[derive(Debug, Deserialize)]
struct AeSumRow {
    /// The queried aggregate — the query selects it as `value`.
    #[serde(deserialize_with = "stow_types::analytics::de_f64")]
    value: f64,
}

/// `launch-model.graphql` — the zone's HTTP request counts by method
/// and path over the window.
const PATH_COUNTS_QUERY: &str = include_str!("../queries/launch-model.graphql");

/// One request family the path classifier buckets a zone row into.
/// String form is the snapshot's `"METHOD family"` key prefix — the
/// family suffix keeps the raw-path detail the classifier discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RouteKind {
    /// `GET /api/v1/index/…` — pointer and slice fetches (a pull is two).
    IndexRequest,
    /// `POST /api/v1/admissions`.
    Admission,
    /// `POST /api/v1/enqueue`.
    EnqueueRedemption,
    /// `POST /api/v1/requests`.
    HumanRequest,
    /// `GET /api/v1/requests/{task_id}`.
    RequestStatusRead,
    /// `/`, `/install.sh`, `/install.ps1`, `/requests/{id}` pages.
    SiteView,
    /// `/stats` and `/api/v1/stats`.
    StatsView,
    /// `POST /api/v1/admin/index/…` — index slice publishes.
    IndexPublish,
    /// The rest of the trusted surface — status reads and queue
    /// mutations.
    AdminOperation,
}

impl RouteKind {
    /// The snapshot's stable key prefix for the kind.
    const fn key(self) -> &'static str {
        match self {
            Self::IndexRequest => "GET /api/v1/index/*",
            Self::Admission => "POST /api/v1/admissions",
            Self::EnqueueRedemption => "POST /api/v1/enqueue",
            Self::HumanRequest => "POST /api/v1/requests",
            Self::RequestStatusRead => "GET /api/v1/requests/*",
            Self::SiteView => "GET /site/*",
            Self::StatsView => "GET /stats",
            Self::IndexPublish => "POST /api/v1/admin/index/*",
            Self::AdminOperation => "* /api/v1/(admin|scheduler)/*",
        }
    }
}

/// Which route family one `(method, path)` pair belongs to, or `None`
/// for traffic the launch model does not count.
fn classify_path(method: &str, path: &str) -> Option<RouteKind> {
    match (method, path) {
        ("POST", "/api/v1/admissions") => Some(RouteKind::Admission),
        ("POST", "/api/v1/enqueue") => Some(RouteKind::EnqueueRedemption),
        ("POST", "/api/v1/requests") => Some(RouteKind::HumanRequest),
        // Priced from fixed shapes, never from the window: a build
        // run's and a resolve run's webhook deliveries and a request's
        // outcome post by their lifecycle (`stow_types::forwards`), a
        // trusted submit by the preheat side, the health probe at its
        // stated cadence. Counting them here too would book them a
        // second time as operator work under the catch-all below.
        ("POST", "/api/v1/github/workflow-run" | "/api/v1/scheduler/tasks/submit")
        | ("GET", "/api/v1/scheduler/health") => None,
        ("POST", p) if p.starts_with("/api/v1/scheduler/requests/") => None,
        ("GET", "/" | "/install.sh" | "/install.ps1") => Some(RouteKind::SiteView),
        ("GET", "/stats" | "/api/v1/stats") => Some(RouteKind::StatsView),
        ("POST", p) if p.starts_with("/api/v1/admin/index/") => Some(RouteKind::IndexPublish),
        ("GET", p) if p.starts_with("/api/v1/requests/") => Some(RouteKind::RequestStatusRead),
        ("GET", p) if p.starts_with("/api/v1/index/") => Some(RouteKind::IndexRequest),
        ("GET", p) if p.starts_with("/requests/") => Some(RouteKind::SiteView),
        (_, p) if p.starts_with("/api/v1/admin/") || p.starts_with("/api/v1/scheduler/") => {
            Some(RouteKind::AdminOperation)
        }
        _ => None,
    }
}

/// Days of Rust release history the cadence counts, ending at the
/// window's end (exclusive, like the window itself).
const RELEASE_HISTORY_DAYS: u32 = 365;

/// One stable rustc release from the published release notes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StableRelease {
    /// `MAJOR.MINOR.PATCH`.
    pub version: String,
    /// Release day — `YYYY-MM-DD`.
    pub date: String,
}

/// Every stable release `RELEASES.md` lists, in file order. A heading
/// is `Version <version> (<date>)`; the pre-1.0 headings (`Version 0.10`)
/// and 1.0's alphas are not `MAJOR.MINOR.PATCH` releases and are not
/// stable, so they are left out.
///
/// # Errors
/// A stable release heading whose date is not a calendar day.
fn parse_stable_releases(notes: &str) -> stow_types::error::Result<Vec<StableRelease>> {
    notes
        .lines()
        .filter_map(|line| {
            let heading = line.strip_prefix("Version ")?;
            let (version, date) = heading.split_once(" (")?;
            let stable =
                semver::Version::parse(version.trim()).is_ok_and(|parsed| parsed.pre.is_empty());
            stable.then(|| (version.trim(), date.trim_end().trim_end_matches(')')))
        })
        .map(|(version, date)| {
            time::Date::parse(date, &time::format_description::well_known::Iso8601::DATE)
                .map_err(|error| stow_error!("release {version} date {date:?}: {error}"))?;
            Ok(StableRelease {
                version: version.to_owned(),
                date: date.to_owned(),
            })
        })
        .collect()
}

/// The `[since, until)` days the cadence counts for a window ending at
/// `window_end`.
fn release_period(window_end: &str) -> stow_types::error::Result<(String, String)> {
    Ok((
        shift_day(window_end, -i64::from(RELEASE_HISTORY_DAYS))?,
        window_end.to_owned(),
    ))
}

/// The releases published inside the cadence period before `window_end`.
fn releases_in_period(
    releases: Vec<StableRelease>,
    window_end: &str,
) -> stow_types::error::Result<Vec<StableRelease>> {
    let (since, until) = release_period(window_end)?;
    Ok(releases
        .into_iter()
        .filter(|release| since <= release.date && release.date < until)
        .collect())
}

/// What the export measured for the window — the raw counts the model
/// derivation divides by install-days. `--from-snapshot` accepts this
/// shape; `--write-snapshot` emits it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowSnapshot {
    /// Window length in days.
    pub window_days: u32,
    /// Window end — `YYYY-MM-DD`, exclusive of its own day (the window
    /// covers `[end - days, end)`).
    pub window_end: String,
    /// Distinct installs the window saw (`stow_events.index1`).
    pub install_days: u64,
    /// Sample-weighted byte-path fetches (`sum(stow_events.double1)`).
    pub cli_fetches: u64,
    /// Uncovered nodes admitted (`count(stow_cache_misses)`).
    pub miss_nodes: u64,
    /// Zone HTTP requests per route family — keys are
    /// [`RouteKind::key`] values after the classifier collapsed raw
    /// paths.
    pub requests: BTreeMap<String, u64>,
    /// The stable rustc releases published in the [`RELEASE_HISTORY_DAYS`]
    /// before `window_end` — the cadence's count, kept as the releases
    /// themselves so the model diff and its inputs review together.
    pub stable_releases: Vec<StableRelease>,
}

#[derive(Args)]
pub struct LaunchModelArgs {
    #[command(subcommand)]
    pub command: LaunchModelCommand,
}

#[derive(Subcommand)]
pub enum LaunchModelCommand {
    /// Regenerate `launch-model.toml` from production's analytics. The
    /// account must be live; while it is frozen, `--from-snapshot`
    /// reruns the derivation on a captured window.
    Export {
        /// Output path.
        #[arg(long, default_value = DEFAULT_OUT)]
        out: PathBuf,
        /// Window end `YYYY-MM-DD` — defaults to the freeze day's
        /// recorded end in the checked-in model.
        #[arg(long)]
        end: Option<String>,
        /// Window length in days.
        #[arg(long, default_value_t = 7)]
        window_days: u32,
        /// Read this captured window snapshot instead of Cloudflare —
        /// the fixture-driven path the export test uses.
        #[arg(long)]
        from_snapshot: Option<PathBuf>,
        /// Also write the raw window snapshot to this path.
        #[arg(long)]
        write_snapshot: Option<PathBuf>,
    },
}

/// The launch-scale constants stow#452 decided — they are not measured,
/// they are the assumption the gate and load test are built on.
const LAUNCH_INSTALLS: u64 = 10_000;
const PEAK_FACTOR: f64 = 10.0;
const DAYS_PER_MONTH: u32 = 30;

/// Tasks a human request enqueues — the request's uncovered closure.
/// Not measurable from HTTP or AE (the batch rides inside one submit
/// call), so it is a stated constant: the window's callbacks minus its
/// redeemed-miss builds, divided by its human requests — the extra
/// builds a request wave caused beyond the misses it redeemed.
const TASKS_PER_HUMAN_REQUEST: f64 = 5.0;

/// The external uptime monitor's `GET /api/v1/scheduler/health`
/// cadence: once a minute, the operator's decision (stow#940), not a
/// window measurement.
const HEALTH_PROBES_PER_DAY: f64 = 24.0 * 60.0;

/// Run one `launch-model` subcommand.
pub async fn run(args: LaunchModelArgs, output: Output) -> stow_types::error::Result<()> {
    match args.command {
        LaunchModelCommand::Export {
            out,
            end,
            window_days,
            from_snapshot,
            write_snapshot,
        } => export(out, end, window_days, from_snapshot, write_snapshot, output).await,
    }
}

async fn export(
    out: PathBuf,
    end: Option<String>,
    window_days: u32,
    from_snapshot: Option<PathBuf>,
    write_snapshot: Option<PathBuf>,
    output: Output,
) -> stow_types::error::Result<()> {
    let snapshot = match from_snapshot {
        Some(path) => {
            let text = tokio::fs::read_to_string(&path)
                .await
                .map_err(|error| stow_error!("read snapshot {}: {error}", path.display()))?;
            serde_json::from_str::<WindowSnapshot>(&text)
                .map_err(|error| stow_error!("parse snapshot {}: {error}", path.display()))?
        }
        None => gather_snapshot(end.as_deref(), window_days).await?,
    };
    let model = derive_model(&snapshot)?;
    let document = render_toml(&model)?;
    tokio::fs::write(&out, &document)
        .await
        .map_err(|error| stow_error!("write {}: {error}", out.display()))?;
    if let Some(path) = write_snapshot {
        let json = serde_json::to_string_pretty(&snapshot)
            .map_err(|error| stow_error!("serialize snapshot: {error}"))?;
        tokio::fs::write(&path, format!("{json}\n"))
            .await
            .map_err(|error| stow_error!("write {}: {error}", path.display()))?;
    }
    render::emit(output, &model, render_model)
}

/// The snapshot the live export assembles — three Analytics Engine
/// queries plus the zone's per-path HTTP counts.
async fn gather_snapshot(
    end: Option<&str>,
    window_days: u32,
) -> stow_types::error::Result<WindowSnapshot> {
    let token = cloudflare::api_token()?;
    let account =
        std::env::var(CF_ACCOUNT_ID_ENV).map_err(|_| stow_error!("missing {CF_ACCOUNT_ID_ENV}"))?;
    let zone =
        std::env::var(CF_ZONE_ID_ENV).map_err(|_| stow_error!("missing {CF_ZONE_ID_ENV}"))?;
    let window_end = end.map_or_else(default_window_end, str::to_owned);
    let since = shift_day(&window_end, -i64::from(window_days))?;

    let window = QueryWindow {
        since,
        until: window_end.clone(),
    };
    let install_days_sql = InstallDaysQuery { window: &window }
        .render()
        .map_err(|error| stow_error!("render launch-model query: {error}"))?;
    let cli_fetches_sql = CliFetchesQuery { window: &window }
        .render()
        .map_err(|error| stow_error!("render launch-model query: {error}"))?;
    let miss_nodes_sql = MissNodesQuery { window: &window }
        .render()
        .map_err(|error| stow_error!("render launch-model query: {error}"))?;
    let sql_base = cloudflare::analytics_sql_base()?;
    let (install_days, cli_fetches, miss_nodes, requests, release_notes) = futures_util::try_join!(
        async {
            cloudflare::analytics_engine_sql::<AeCountRow>(
                &sql_base,
                &token,
                &account,
                &install_days_sql,
            )
            .await
            .map_err(|error| stow_error!("analytics engine: {error}"))?
            .first()
            .map(|row| row.value)
            .ok_or_else(|| stow_error!("install-days query returned no row"))
        },
        analytic_sum(&sql_base, &token, &account, &cli_fetches_sql, "fetch"),
        analytic_sum(&sql_base, &token, &account, &miss_nodes_sql, "miss"),
        zone_path_counts(&token, &zone, &window.since, &window.until),
        crate::rust_channel::release_notes(),
    )?;
    let stable_releases = releases_in_period(parse_stable_releases(&release_notes)?, &window_end)?;
    Ok(WindowSnapshot {
        window_days,
        window_end,
        install_days,
        cli_fetches,
        miss_nodes,
        requests,
        stable_releases,
    })
}

/// One `Float64` aggregate row — the additive sampled-weight
/// estimate — decoded at the actual column type and validated
/// losslessly before its u64 use rather than clamped.
async fn analytic_sum(
    sql_base: &str,
    token: &str,
    account: &str,
    sql: &str,
    what: &'static str,
) -> stow_types::error::Result<u64> {
    cloudflare::analytics_engine_sql::<AeSumRow>(sql_base, token, account, sql)
        .await
        .map_err(|error| stow_error!("analytics engine: {error}"))?
        .first()
        .map(|row| row.value)
        .ok_or_else(|| stow_error!("{what} query returned no row"))
        .and_then(|value| {
            stow_types::analytics::f64_to_u64_exact(value, what)
                .map_err(stow_types::error::Error::msg)
        })
}

/// The freeze day's recorded end — the window the checked-in model was
/// built on. A live export overrides it with `--end`.
fn default_window_end() -> String {
    "2026-09-27".to_owned()
}

/// `YYYY-MM-DD` shifted by `days` (negative shifts backward).
fn shift_day(day: &str, days: i64) -> stow_types::error::Result<String> {
    let time = time::Date::parse(day, &time::format_description::well_known::Iso8601::DATE)
        .map_err(|error| stow_error!("parse window day {day:?}: {error}"))?;
    (time + time::Duration::days(days))
        .format(&time::format_description::well_known::Iso8601::DATE)
        .map_err(|error| stow_error!("format shifted day: {error}"))
}

/// Zone HTTP request counts over the window, folded into route
/// families by [`classify_path`].
async fn zone_path_counts(
    token: &str,
    zone: &str,
    since: &str,
    until: &str,
) -> stow_types::error::Result<BTreeMap<String, u64>> {
    #[derive(Deserialize)]
    struct ZoneData {
        groups: Vec<PathGroup>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct PathGroup {
        count: u64,
        dimensions: PathDimensions,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct PathDimensions {
        client_request_http_method_name: String,
        client_request_path: String,
    }
    let groups: Vec<PathGroup> = cloudflare::query_zone::<serde_json::Value, ZoneData>(
        token,
        PATH_COUNTS_QUERY,
        &serde_json::json!({
            "zoneTag": zone,
            "since": format!("{since}T00:00:00Z"),
            "until": format!("{until}T00:00:00Z"),
        }),
    )
    .await
    .map_err(stow_types::error::Error::msg)?
    .groups;
    let mut requests: BTreeMap<String, u64> = BTreeMap::new();
    for group in groups {
        let Some(kind) = classify_path(
            &group.dimensions.client_request_http_method_name,
            &group.dimensions.client_request_path,
        ) else {
            continue;
        };
        *requests.entry(kind.key().to_owned()).or_default() += group.count;
    }
    Ok(requests)
}

/// The checked-in `launch-model.toml` — the generation banner plus the
/// typed model serialized in its fixed section order.
fn render_toml(model: &LaunchModel) -> stow_types::error::Result<String> {
    let body = model.to_toml().map_err(stow_types::error::Error::msg)?;
    Ok(format!(
        "# Regenerated by `stow-admin launch-model export` — hand edits\n\
         # are lost. `stow-admin traffic-cost project`, `verdict` and `peak`\n\
         # read this file; every rate is events per active install per\n\
         # day in `window`, or a flat daily cadence where the lane does\n\
         # not scale with installs. `cadence` counts the stable rustc\n\
         # releases (minor and point) Rust published in the\n\
         # `period_days` before the window's end; each one invalidates\n\
         # the public cache and brings a full preheat wave, which the\n\
         # projection prices once per release.\n\n{body}"
    ))
}

/// Turn the window's raw counts into the launch model: every
/// install-scaled rate divides by `days × install_days`, and flat
/// cadences divide by `days`.
#[expect(
    clippy::cast_precision_loss,
    reason = "window counts fit f64 exactly far past any launch traffic"
)]
pub fn derive_model(snapshot: &WindowSnapshot) -> stow_types::error::Result<LaunchModel> {
    if snapshot.install_days == 0 {
        return Err(stow_error!(
            "snapshot window {} saw no installs — rates need a nonzero denominator",
            snapshot.window_end
        ));
    }
    let per_install_day = |count: u64| {
        count as f64 / (f64::from(snapshot.window_days) * snapshot.install_days as f64)
    };
    let per_day = |count: u64| count as f64 / f64::from(snapshot.window_days);
    let (period_start, period_end) = release_period(&snapshot.window_end)?;
    if let Some(stray) = snapshot
        .stable_releases
        .iter()
        .find(|release| release.date < period_start || period_end <= release.date)
    {
        return Err(stow_error!(
            "snapshot release {} ({}) is outside the cadence period [{period_start}, {period_end})",
            stray.version,
            stray.date
        ));
    }
    let requests = &snapshot.requests;
    let count = |kind: RouteKind| requests.get(kind.key()).copied().unwrap_or(0);

    let index_requests = count(RouteKind::IndexRequest);
    let enqueues = count(RouteKind::EnqueueRedemption);
    let human_requests = count(RouteKind::HumanRequest);
    let admin_operations = count(RouteKind::AdminOperation);
    let index_publishes = count(RouteKind::IndexPublish);

    Ok(LaunchModel {
        scale: LaunchScale {
            installs: LAUNCH_INSTALLS,
            peak_factor: PEAK_FACTOR,
            days_per_month: DAYS_PER_MONTH,
        },
        window: LaunchWindow {
            days: snapshot.window_days,
            end: snapshot.window_end.clone(),
            install_days: snapshot.install_days,
        },
        cadence: LaunchCadence {
            stable_releases: u32::try_from(snapshot.stable_releases.len())
                .map_err(|error| stow_error!("stable release count: {error}"))?,
            period_days: RELEASE_HISTORY_DAYS,
        },
        rates: LaunchRates {
            cli_byte_path_fetch: round4(per_install_day(snapshot.cli_fetches)),
            // One pull is the pointer GET plus the slice GET — two
            // requests per pull.
            index_pull: round4(per_install_day(index_requests.div_ceil(2))),
            admission: round4(per_install_day(count(RouteKind::Admission))),
            enqueue_redemption: round4(per_install_day(enqueues)),
            human_request: round4(per_install_day(human_requests)),
            request_status_read: round4(per_install_day(count(RouteKind::RequestStatusRead))),
            site_view: round4(per_install_day(count(RouteKind::SiteView))),
            stats_view: round4(per_install_day(count(RouteKind::StatsView))),
            miss_node: round4(per_install_day(snapshot.miss_nodes)),
            admin_operations_per_day: round4(per_day(admin_operations)),
            index_publishes_per_day: round4(per_day(index_publishes)),
            health_probes_per_day: HEALTH_PROBES_PER_DAY,
        },
        ratios: LaunchRatios {
            // A redeemed ticket is exactly one queue row, so this ratio
            // is the miss-to-build share — capped at 1, a miss can
            // never build twice.
            builds_per_miss: round4((enqueues as f64 / snapshot.miss_nodes.max(1) as f64).min(1.0)),
            tasks_per_human_request: TASKS_PER_HUMAN_REQUEST,
        },
    })
}

/// Four decimals keeps the checked-in file stable and readable without
/// hiding window noise.
fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

/// The human table: the model's rates plus what each kind projects
/// monthly at launch scale.
fn render_model(model: &LaunchModel) -> String {
    use stow_types::launch_model::EventKind;
    let mut out = format!(
        "launch model — {} installs, {}x peak, {}d month (window {} days ending {}, {} install-days)\n",
        model.scale.installs,
        model.scale.peak_factor,
        model.scale.days_per_month,
        model.window.days,
        model.window.end,
        model.window.install_days,
    );
    let _ = std::fmt::Write::write_fmt(
        &mut out,
        format_args!(
            "cadence — {} stable releases in {} days ({:.2}/month)\n",
            model.cadence.stable_releases,
            model.cadence.period_days,
            model.monthly_stable_releases()
        ),
    );
    let mut table = crate::render::Table::new(&["kind", "events/month"]);
    for (label, kind) in [
        ("cli byte-path fetch", EventKind::CliBytePathFetch),
        ("index pull", EventKind::IndexPull),
        ("admission", EventKind::Admission),
        ("enqueue redemption", EventKind::EnqueueRedemption),
        ("human request", EventKind::HumanRequest),
        ("status read", EventKind::RequestStatusRead),
        ("site view", EventKind::SiteView),
        ("stats view", EventKind::StatsView),
        ("miss node", EventKind::MissNode),
        ("admin op", EventKind::AdminOperation),
        ("index publish", EventKind::IndexPublish),
        ("build", EventKind::Build),
        ("build callback", EventKind::BuildCallback),
        ("health probe", EventKind::HealthProbe),
        ("alarm pass", EventKind::AlarmPass),
    ] {
        table.push([
            label.to_owned(),
            format!("{:.0}", model.monthly_events(kind)),
        ]);
    }
    let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{}\n", table.render()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixture the export test drives while the account is frozen —
    /// the window snapshot's shape, not Cloudflare's wire format.
    const SNAPSHOT: &str = include_str!("../tests/fixtures/launch-snapshot.json");

    #[test]
    fn fixture_derives_the_checked_in_model() {
        let snapshot: WindowSnapshot =
            serde_json::from_str(SNAPSHOT).expect("fixture snapshot parses");
        let model = derive_model(&snapshot).expect("fixture derives a model");
        let checked_in = LaunchModel::from_toml(
            &std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../launch-model.toml"))
                .expect("read launch-model.toml"),
        )
        .expect("launch-model.toml parses");
        assert_eq!(
            model, checked_in,
            "launch-model.toml is stale — regenerate it: \
             stow-admin launch-model export --from-snapshot admin/tests/fixtures/launch-snapshot.json"
        );
    }

    #[test]
    fn export_writes_parseable_toml() {
        let snapshot: WindowSnapshot =
            serde_json::from_str(SNAPSHOT).expect("fixture snapshot parses");
        let model = derive_model(&snapshot).expect("fixture derives a model");
        let document = render_toml(&model).expect("model serializes");
        let reparsed = LaunchModel::from_toml(&document).expect("rendered document reparses");
        assert_eq!(model, reparsed);
    }

    /// The three Analytics templates substitute only the typed
    /// [`QueryWindow`] bounds — no marker strings survive a render and
    /// each query keeps its own dataset.
    #[test]
    fn analytics_templates_render_the_typed_window() {
        let window = QueryWindow {
            since: "2026-09-20".to_owned(),
            until: "2026-09-27".to_owned(),
        };
        let queries = [
            (InstallDaysQuery { window: &window }.render(), "stow_events"),
            (CliFetchesQuery { window: &window }.render(), "stow_events"),
            (
                MissNodesQuery { window: &window }.render(),
                "stow_cache_misses",
            ),
        ];
        for (query, dataset) in queries {
            let sql = query.expect("template renders");
            assert!(sql.contains("toDateTime('2026-09-20 00:00:00')"), "{sql}");
            assert!(sql.contains("toDateTime('2026-09-27 00:00:00')"), "{sql}");
            assert!(sql.contains(dataset), "{sql}");
            assert!(!sql.contains("{{"), "{sql}");
            assert!(!sql.contains('$'), "{sql}");
        }
    }

    /// An excerpt of the release notes' shape: a point release, a
    /// minor, a 1.0 alpha and the pre-1.0 headings.
    const NOTES: &str = "\
Version 1.98.1 (2026-09-03)
==========================

* [fix a thing](https://example.invalid/1)

Version 1.98.0 (2026-08-20)
==========================

Version 1.0.0-alpha.2 (2015-02-20)
==================================

Version 0.10 (2014-04-03)
=========================

Version 0.3  (2012-07-12)
=========================
";

    #[test]
    fn release_notes_yield_stable_releases_only() {
        let releases = parse_stable_releases(NOTES).expect("parse");
        let found: Vec<(&str, &str)> = releases
            .iter()
            .map(|release| (release.version.as_str(), release.date.as_str()))
            .collect();
        assert_eq!(found, [("1.98.1", "2026-09-03"), ("1.98.0", "2026-08-20")]);
    }

    #[test]
    fn a_stable_heading_with_a_bad_date_is_refused() {
        let error = parse_stable_releases("Version 1.98.1 (2026-13-40)\n").expect_err("bad date");
        assert!(error.to_string().contains("1.98.1"), "{error}");
    }

    #[test]
    fn the_cadence_counts_the_year_before_the_window_end() {
        let release = |version: &str, date: &str| StableRelease {
            version: version.to_owned(),
            date: date.to_owned(),
        };
        let kept = releases_in_period(
            vec![
                // The window's own end day is outside the period ...
                release("1.99.0", "2026-09-27"),
                release("1.98.1", "2026-09-26"),
                // ... its first day, 365 days earlier, is inside.
                release("1.90.0", "2025-09-27"),
                release("1.89.0", "2025-09-26"),
            ],
            "2026-09-27",
        )
        .expect("period");
        let versions: Vec<&str> = kept
            .iter()
            .map(|release| release.version.as_str())
            .collect();
        assert_eq!(versions, ["1.98.1", "1.90.0"]);
    }

    #[test]
    fn a_snapshot_release_outside_the_period_is_refused() {
        let mut snapshot: WindowSnapshot =
            serde_json::from_str(SNAPSHOT).expect("fixture snapshot parses");
        snapshot.stable_releases.push(StableRelease {
            version: "1.89.0".to_owned(),
            date: "2025-08-07".to_owned(),
        });
        let error = derive_model(&snapshot).expect_err("stale release must refuse");
        assert!(error.to_string().contains("1.89.0"), "{error}");
    }

    #[test]
    fn the_fixture_cadence_is_its_release_count() {
        let snapshot: WindowSnapshot =
            serde_json::from_str(SNAPSHOT).expect("fixture snapshot parses");
        let model = derive_model(&snapshot).expect("fixture derives a model");
        assert_eq!(
            usize::try_from(model.cadence.stable_releases).expect("count fits"),
            snapshot.stable_releases.len()
        );
        assert_eq!(model.cadence.period_days, RELEASE_HISTORY_DAYS);
    }

    #[test]
    fn empty_window_refuses() {
        let snapshot = WindowSnapshot {
            window_days: 7,
            window_end: "2026-09-27".to_owned(),
            install_days: 0,
            cli_fetches: 0,
            miss_nodes: 0,
            requests: BTreeMap::new(),
            stable_releases: Vec::new(),
        };
        assert!(derive_model(&snapshot).is_err());
    }
}
