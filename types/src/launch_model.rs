//! The checked-in launch traffic model (`launch-model.toml`) — stow#452.
//!
//! `stow-admin launch-model export` regenerates the file from production's
//! own events; the launch gate (stow-edge's `launch_gate` test) and the
//! mock load test read it back through this module. Every rate is events
//! per active install per day over the measurement window, or an explicit
//! flat daily cadence for the lanes that do not scale with installs
//! (operator work and index publishes). The file is reviewed like code:
//! each field names what it counts and the provenance is the window the
//! export measured.

use serde::{Deserialize, Serialize};

/// The launch assumption stow#452 fixes: ten thousand active installs
/// (about 35× the 289 measured the week before the freeze), and a peak
/// hour ten times the average hour.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct LaunchScale {
    /// Active installs at launch.
    pub installs: u64,
    /// Peak-hour multiplier over the average hour.
    pub peak_factor: f64,
    /// Days in the monthly window every allowance is quoted for.
    pub days_per_month: u32,
}

/// The production window the rates were measured in. `install_days`
/// counts distinct installs seen in `stow_events.index1` — the
/// per-install denominators every rate divides by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchWindow {
    /// Window length in days (the last week before the account froze).
    pub days: u32,
    /// The window's last day — the freeze day — `YYYY-MM-DD`.
    pub end: String,
    /// Distinct installs the window saw.
    pub install_days: u64,
}

/// The per-install traffic kinds, each in events per install-day, plus
/// the flat daily cadences that do not scale with installs.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct LaunchRates {
    /// `GET /api/v1/bundles/{digest}` — one per covered unit an install's
    /// builds consume. Analytics Engine `stow_events`, `sum(double1)`
    /// where `blob1 = 'hit'` (the 1/10 sample's weight restores the true
    /// count).
    pub cli_byte_path_fetch: f64,
    /// Index pulls: one pull is the pointer GET plus the folded-slice
    /// GET, so each pull is two worker requests. Zone
    /// `httpRequestsAdaptiveGroups` on `/api/v1/index/*` — Analytics
    /// Engine has no event for the index path.
    pub index_pull: f64,
    /// `POST /api/v1/admissions` — miss admissions minted.
    pub admission: f64,
    /// `POST /api/v1/enqueue` — admission tickets redeemed.
    pub enqueue_redemption: f64,
    /// `POST /api/v1/requests` — Turnstile-verified human requests.
    pub human_request: f64,
    /// `GET /api/v1/requests/{id}` — status reads (the `/requests/{id}`
    /// page polls this route). Not in the issue's rate list by name; it
    /// is a distinct route hitting the scheduler, so it carries its own
    /// measured rate — zone `httpRequestsAdaptiveGroups`.
    pub request_status_read: f64,
    /// `/`, `/install.sh`, `/install.ps1`, `/requests/{id}` page loads.
    pub site_view: f64,
    /// `/stats` and `GET /api/v1/stats` — hourly-cached, so each view
    /// is cheap but they still bill a worker request.
    pub stats_view: f64,
    /// `dependency_graph_misses` nodes admitted per install-day —
    /// Analytics Engine `stow_cache_misses`, one point per uncovered
    /// node. This is the denominator of [`LaunchRatios::builds_per_miss`].
    pub miss_node: f64,
    /// Operator work (`stow-admin` reads, queue mutations, migrations,
    /// trusted submits) — a flat daily cadence, not install-scaled. The
    /// window's own operations show a handful a day; fifty leaves the
    /// launch fleet room and stays well under any allowance line.
    pub admin_operations_per_day: f64,
    /// Index slice publishes (full or delta) — fleet cadence, not
    /// install-scaled. Slices republish as coverage lands; four a day
    /// is the recorded pre-freeze cadence.
    pub index_publishes_per_day: f64,
}

/// Ratios the event chain needs rather than per-install rates.
///
/// A miss only builds once its ticket is redeemed and dispatched, and
/// each build reports through the `workflow_run` webhook (retries and
/// redeliveries push the callback count above the build count).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct LaunchRatios {
    /// Builds dispatched per miss node minted. Bounded at 1 by
    /// construction — a node can enqueue one task — and realistically
    /// lower: missed nodes are deduplicated upstream and not every
    /// admission is redeemed.
    pub builds_per_miss: f64,
    /// `POST /api/v1/github/workflow-run` deliveries per build — one
    /// per `completed` run plus retried deliveries.
    pub callbacks_per_build: f64,
    /// Queue rows a single human request submits — the request's whole
    /// dependency closure. The submit itself is one scheduler call; the
    /// row count sets how many builds the human lane causes.
    pub tasks_per_human_request: f64,
}

/// The typed `launch-model.toml`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LaunchModel {
    /// The launch-scale assumptions.
    pub scale: LaunchScale,
    /// The measurement window the rates came from.
    pub window: LaunchWindow,
    /// Per-install-day rates and flat daily cadences.
    pub rates: LaunchRates,
    /// Event-chain ratios.
    pub ratios: LaunchRatios,
}

/// A traffic kind the model projects. Each worker route and scheduler
/// lane sums a few of these to get its monthly event count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// [`LaunchRates::cli_byte_path_fetch`]
    CliBytePathFetch,
    /// [`LaunchRates::index_pull`] — one pull; routes billed per pull's
    /// two requests multiply it themselves.
    IndexPull,
    /// [`LaunchRates::admission`]
    Admission,
    /// [`LaunchRates::enqueue_redemption`]
    EnqueueRedemption,
    /// [`LaunchRates::human_request`]
    HumanRequest,
    /// [`LaunchRates::request_status_read`]
    RequestStatusRead,
    /// [`LaunchRates::site_view`]
    SiteView,
    /// [`LaunchRates::stats_view`]
    StatsView,
    /// [`LaunchRates::miss_node`]
    MissNode,
    /// [`LaunchRates::admin_operations_per_day`]
    AdminOperation,
    /// [`LaunchRates::index_publishes_per_day`]
    IndexPublish,
    /// Queue rows the human lane submits —
    /// `human_request × tasks_per_human_request`.
    HumanTask,
    /// Dispatched builds — `miss_node × builds_per_miss + HumanTask`.
    Build,
    /// `workflow_run` webhook deliveries — `Build × callbacks_per_build`.
    BuildCallback,
    /// Scheduler alarm passes. One armed event causes one pass; passes
    /// coalesce while the alarm is already armed, so this is an upper
    /// bound: submit calls + completions + index publishes.
    AlarmPass,
}

impl LaunchModel {
    /// Parse a `launch-model.toml` document.
    ///
    /// # Errors
    /// TOML syntax or schema errors, as text.
    pub fn from_toml(document: &str) -> Result<Self, String> {
        toml::from_str(document).map_err(|error| format!("parse launch model: {error}"))
    }

    /// Serialize the model in the fixed section order
    /// `launch-model.toml` is checked in under — the export emits this.
    ///
    /// # Errors
    /// TOML serialization failure, as text.
    pub fn to_toml(&self) -> Result<String, String> {
        toml::to_string_pretty(self).map_err(|error| format!("serialize launch model: {error}"))
    }

    /// Events of `kind` in an average day at launch scale.
    #[expect(
        clippy::cast_precision_loss,
        reason = "event counts fit f64 exactly far past any launch traffic"
    )]
    #[must_use]
    pub fn daily_events(&self, kind: EventKind) -> f64 {
        match kind {
            EventKind::CliBytePathFetch => {
                self.rates.cli_byte_path_fetch * self.scale.installs as f64
            }
            EventKind::IndexPull => self.rates.index_pull * self.scale.installs as f64,
            EventKind::Admission => self.rates.admission * self.scale.installs as f64,
            EventKind::EnqueueRedemption => {
                self.rates.enqueue_redemption * self.scale.installs as f64
            }
            EventKind::HumanRequest => self.rates.human_request * self.scale.installs as f64,
            EventKind::RequestStatusRead => {
                self.rates.request_status_read * self.scale.installs as f64
            }
            EventKind::SiteView => self.rates.site_view * self.scale.installs as f64,
            EventKind::StatsView => self.rates.stats_view * self.scale.installs as f64,
            EventKind::MissNode => self.rates.miss_node * self.scale.installs as f64,
            EventKind::AdminOperation => self.rates.admin_operations_per_day,
            EventKind::IndexPublish => self.rates.index_publishes_per_day,
            EventKind::HumanTask => {
                self.daily_events(EventKind::HumanRequest) * self.ratios.tasks_per_human_request
            }
            EventKind::Build => self.daily_events(EventKind::MissNode).mul_add(
                self.ratios.builds_per_miss,
                self.daily_events(EventKind::HumanTask),
            ),
            EventKind::BuildCallback => {
                self.daily_events(EventKind::Build) * self.ratios.callbacks_per_build
            }
            EventKind::AlarmPass => {
                // One arming event causes one pass: enqueues, human
                // submits and completions arm the dispatch alarm, and
                // an index publish schedules one. Passes that coalesce
                // inside an already-armed alarm only lower this.
                self.daily_events(EventKind::EnqueueRedemption)
                    + self.daily_events(EventKind::HumanRequest)
                    + self.daily_events(EventKind::BuildCallback)
                    + self.daily_events(EventKind::IndexPublish)
            }
        }
    }

    /// Events of `kind` over one monthly window at launch scale.
    #[must_use]
    pub fn monthly_events(&self, kind: EventKind) -> f64 {
        self.daily_events(kind) * f64::from(self.scale.days_per_month)
    }

    /// Events of `kind` in one peak hour: the monthly count spread over
    /// the window's hours and multiplied by the peak factor.
    #[must_use]
    pub fn peak_hourly_events(&self, kind: EventKind) -> f64 {
        self.monthly_events(kind) * self.scale.peak_factor
            / (f64::from(self.scale.days_per_month) * 24.0)
    }

    /// Events of `kind` per second at peak-hour rate.
    #[must_use]
    pub fn peak_events_per_second(&self, kind: EventKind) -> f64 {
        self.peak_hourly_events(kind) / 3600.0
    }
}
