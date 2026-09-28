//! The dispatch freeze: the scheduler's "this is going badly" circuit
//! breaker.
//!
//! Where the zone's WAF maintenance rules (`stow maintenance:*`, toggled
//! by `stow-admin maintenance`) shed anonymous edge traffic to protect
//! the worker, the freeze gates dispatch inside the scheduler Durable Object
//! so a systematic CI breakage or an over-budget day cannot keep burning
//! the org's allowance. Untrusted enqueues are never gated — misses
//! arriving during a freeze are exactly the work that should dispatch
//! first once it lifts, so the freeze is worth nothing if it blinds the
//! queue.
//!
//! The failure-rate trip never fires on a bare count or a bare ratio: a
//! stream must reach the minimum sample inside the window *and* cross
//! the failure ratio over that sample. Two failures out of two builds
//! is not a signal, and a fleet that rarely builds cannot accumulate
//! the sample — both are silent by design. The condition is evaluated
//! over two kinds of streams: the fleet-wide aggregate (a slow,
//! widely-dispersed breakage still burns the shared runner allowance)
//! and each individual target (a linker/SDK breakage is almost always
//! concentrated on one family, where per-target sampling catches it
//! without being diluted by healthy legs). The sample is the
//! `attempt_outcome_buckets` counters — every completion upserts one
//! five-minute bucket per target — so a task's retried attempts keep
//! counting; the queue row alone cannot carry that history (a
//! re-request flips it back to `pending`).
//!
//! The cost trip is the same freeze from a different instrument: the
//! scheduler Durable Object meters its own SQL work (`rowsRead` /
//! `rowsWritten` off every statement's result) into a per-UTC-day
//! meter row, and engages the flag the moment the day's meter crosses
//! the prorated budget — no poll, no scheduled handler.
//!
//! Recovery is manual only: an automatic unfreeze would burn another
//! wave against the same broken `main` and turn the alert into hourly
//! noise. One alert goes out per state transition — freeze and clear —
//! fanned out to two channels that never block each other: an Email
//! Sending notify (`send_email` binding) and a GitHub `incident` issue
//! record (opened, commented hourly, closed on resolve). A channel that
//! fails is recorded on the freeze record rather than retried, so a
//! silent alert is visible to whoever eventually reads
//! `stow-admin dispatch-freeze status`.
//!
//! Everything here is platform-free: the trip decisions, the alert-body
//! rendering, and the outcome interpretation are unit-testable on the
//! host without a Worker. The wasm glue lives in `scheduler/object.rs`
//! (gate + evaluation points) and `email.rs` (the `send_email` binding
//! call the alert sink lives on); the usage fetch lives in `cost.rs`.
//!
//! Alerting is email-only on the edge: the edge's GitHub App token
//! deliberately carries no `issues` grant (untrusted serving
//! infrastructure), so the `incident`-issue record is the #450
//! watchdog's job — it reads the freeze state and its transition log
//! over the admin route.

use askama::Template;
use stow_types::api::{
    ChannelOutcome, DispatchFreezeCost, DispatchFreezeRecord, DispatchFreezeTarget,
    DispatchFreezeTrigger, DispatchFreezeTrip,
};
use stow_types::identity::TargetTriple;

use crate::errors::QueueError;

/// Default for `STOW_FREEZE_WINDOW_MINUTES` — the trailing window
/// terminal outcomes are counted over. The motivating incident burned
/// 308 failed runs in four hours (~77/hour on the failing legs), so a
/// one-hour window sees a decisive sample well before the allowance is
/// gone while staying too short for a stale failure burst to haunt the
/// next day.
pub const DEFAULT_FREEZE_WINDOW_MINUTES: u32 = 60;
/// Default for `STOW_FREEZE_MIN_OUTCOMES` — the sample floor below which
/// no stream can trip however bad its ratio. Small enough that the
/// incident's ~120 outcomes/hour/target trips inside the first hour,
/// large enough that "2 of 2" noise and low-volume queues stay silent:
/// a queue that cannot produce 50 outcomes in an hour cannot be burning
/// the allowance fast either.
pub const DEFAULT_FREEZE_MIN_OUTCOMES: u32 = 50;
/// Default for `STOW_FREEZE_FAIL_PERCENT` — the failure ratio (percent)
/// a sufficiently-sampled stream must reach to trip. Half of a target's
/// builds failing is unambiguous systematic breakage; ordinary flake
/// tails and a couple of bad crates stay under it.
pub const DEFAULT_FREEZE_FAIL_PERCENT: u32 = 50;

/// Default for `STOW_ALERT_FROM` — the sender address, which must live
/// on a domain onboarded under Compute → Email Service → Email Sending.
pub const DEFAULT_ALERT_FROM: &str = "alerts@stow.waterui.dev";
/// Default for `STOW_ALERT_TO` — where freeze/clear alerts go.
pub const DEFAULT_ALERT_TO: &str = "me@lexo.cool";

/// The operator-facing name of the clear command — the alert emails and
/// the stored-record summaries point at it.
pub const CLEAR_COMMAND: &str = "stow-admin dispatch-freeze clear --yes";
/// The operator-facing name of the status command.
pub const STATUS_COMMAND: &str = "stow-admin dispatch-freeze status";

/// Runtime-tunable freeze knobs, read from Worker env bindings by the
/// Durable Object glue (`STOW_FREEZE_WINDOW_MINUTES`,
/// `STOW_FREEZE_MIN_OUTCOMES`, `STOW_FREEZE_FAIL_PERCENT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreezeSettings {
    /// Trailing window in minutes terminal outcomes are counted over.
    pub window_minutes: u32,
    /// Minimum sample: a stream needs this many terminal outcomes in
    /// the window before its ratio is even read.
    pub min_outcomes: u32,
    /// Failure ratio (percent) over the sample that trips the freeze.
    pub fail_percent: u32,
}

impl Default for FreezeSettings {
    fn default() -> Self {
        Self {
            window_minutes: DEFAULT_FREEZE_WINDOW_MINUTES,
            min_outcomes: DEFAULT_FREEZE_MIN_OUTCOMES,
            fail_percent: DEFAULT_FREEZE_FAIL_PERCENT,
        }
    }
}

/// One target's terminal-outcome tally inside the freeze window, as the
/// SQL window query produces it (target string, completed+failed count,
/// failed count). Stringly-typed because the parse into `TargetTriple`
/// happens when the caller assembles the wire type — the pure decision
/// below does not depend on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeTally {
    /// Compilation target these outcomes landed on.
    pub target: String,
    /// Terminal outcomes (completed + failed) in the window.
    pub outcomes: u32,
    /// Of those, the ones that failed.
    pub failures: u32,
}

/// One failing target's contribution to the trip decision — the per-
/// target line the freeze alert prints and the wire record stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetTrip {
    /// Compilation target.
    pub target: String,
    /// Terminal outcomes for this target in the window.
    pub outcomes: u32,
    /// Failed outcomes for this target in the window.
    pub failures: u32,
    /// Whether this target alone met the sample-and-ratio condition.
    pub tripped: bool,
}

/// The trip decision over one window: the fleet-wide tally plus a line
/// per target that recorded any failure. Present only when at least one
/// stream tripped — `evaluate` returns `None` otherwise, so the value's
/// existence is the verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TripEval {
    /// Fleet-wide terminal outcomes in the window.
    pub outcomes: u32,
    /// Fleet-wide failed outcomes in the window.
    pub failures: u32,
    /// Whether the fleet aggregate itself met the condition.
    pub fleet_tripped: bool,
    /// Every target that recorded a failure in the window.
    pub targets: Vec<TargetTrip>,
}

/// `failures/outcomes` as a whole percent — integer math so the host
/// tests and the DO agree exactly.
fn percent(failures: u32, outcomes: u32) -> u32 {
    if outcomes == 0 {
        return 0;
    }
    let value = u64::from(failures) * 100 / u64::from(outcomes);
    // `failures` is a subset of `outcomes` so the value cannot exceed
    // 100; the `.min` only guards a corrupt hand-built tally.
    u32::try_from(value.min(100)).expect("a percentage fits u32")
}

/// The sample-and-ratio rule applied to one stream. A zero-outcome
/// stream never trips regardless of configuration: the ratio is
/// undefined at an empty sample, and nothing failing cannot be a
/// systematic failure.
fn trips(outcomes: u32, failures: u32, settings: &FreezeSettings) -> bool {
    outcomes > 0
        && outcomes >= settings.min_outcomes
        && u64::from(failures) * 100 >= u64::from(outcomes) * u64::from(settings.fail_percent)
}

/// The pure trip decision: `Some` when the fleet aggregate or any one
/// target met the sample-and-ratio condition, `None` otherwise.
#[must_use]
pub fn evaluate(tallies: &[OutcomeTally], settings: &FreezeSettings) -> Option<TripEval> {
    let mut outcomes = 0_u32;
    let mut failures = 0_u32;
    let mut targets = Vec::new();
    let mut target_tripped = false;
    for tally in tallies {
        outcomes = outcomes.saturating_add(tally.outcomes);
        failures = failures.saturating_add(tally.failures);
        if tally.failures > 0 {
            let tripped = trips(tally.outcomes, tally.failures, settings);
            target_tripped |= tripped;
            targets.push(TargetTrip {
                target: tally.target.clone(),
                outcomes: tally.outcomes,
                failures: tally.failures,
                tripped,
            });
        }
    }
    let fleet_tripped = trips(outcomes, failures, settings);
    (fleet_tripped || target_tripped).then_some(TripEval {
        outcomes,
        failures,
        fleet_tripped,
        targets,
    })
}

/// `failures/outcomes` percent for the wire record — same integer
/// rounding the alert prints.
#[must_use]
pub fn observed_percent(eval: &TripEval) -> u32 {
    percent(eval.failures, eval.outcomes)
}

impl TripEval {
    /// The wire evidence stored on the freeze record. Each stored
    /// target string parses into `TargetTriple` — queue rows only ever
    /// hold valid triples, so a parse failure is a stored-data
    /// invariant the caller surfaces as `Err`.
    pub fn into_wire(
        self,
        settings: &FreezeSettings,
        classes: Vec<stow_types::api::DispatchFreezeClass>,
        example_run_urls: Vec<String>,
    ) -> Result<DispatchFreezeTrip, String> {
        let failure_percent = observed_percent(&self);
        let mut targets = Vec::with_capacity(self.targets.len());
        for target in self.targets {
            targets.push(DispatchFreezeTarget {
                target: TargetTriple::parse(target.target.as_str())
                    .map_err(|error| format!("stored queue target `{}`: {error}", target.target))?,
                outcomes: target.outcomes,
                failures: target.failures,
                tripped: target.tripped,
            });
        }
        Ok(DispatchFreezeTrip {
            window_minutes: settings.window_minutes,
            min_outcomes: settings.min_outcomes,
            fail_percent: settings.fail_percent,
            outcomes: self.outcomes,
            failures: self.failures,
            failure_percent,
            fleet_tripped: self.fleet_tripped,
            targets,
            classes,
            example_run_urls,
        })
    }
}

/// One-line description of a metered dimension for alert text — the
/// label the cost-trip email and `summarize_trigger` print.
#[must_use]
pub const fn metric_label(metric: stow_types::api::CostMetric) -> &'static str {
    use stow_types::api::CostMetric;
    match metric {
        CostMetric::DurableObjectRowsRead => "durable object rows read",
        CostMetric::DurableObjectRowsWritten => "durable object rows written",
        CostMetric::DurableObjectRequests => "durable object requests",
        CostMetric::DurableObjectDurationGbS => "durable object duration (GB-s)",
        CostMetric::WorkerRequests => "worker requests",
        CostMetric::WorkerCpuMs => "worker CPU (ms)",
        CostMetric::D1RowsRead => "d1 rows read",
        CostMetric::D1RowsWritten => "d1 rows written",
    }
}

/// A usage figure for human readers — whole numbers stay whole, big
/// ones get a unit suffix (`833M`, `1.2G`).
#[must_use]
pub fn human_count(value: f64) -> String {
    if value >= 1e9 {
        format!("{:.1}G", value / 1e9)
    } else if value >= 1e6 {
        format!("{:.1}M", value / 1e6)
    } else if value >= 1e3 {
        format!("{:.1}K", value / 1e3)
    } else {
        format!("{value:.0}")
    }
}

/// Subject per transition — one email per state change, so the
/// subject line alone says which change arrived.
#[must_use]
pub fn freeze_subject(trigger: &DispatchFreezeTrigger) -> String {
    match trigger {
        DispatchFreezeTrigger::Manual => "[stow] dispatch frozen — manual".to_owned(),
        DispatchFreezeTrigger::Tripped(_) => {
            "[stow] dispatch frozen — systematic failures".to_owned()
        }
        DispatchFreezeTrigger::Cost(cost) => format!(
            "[stow] dispatch frozen — {} over daily budget",
            metric_label(cost.metric)
        ),
    }
}

/// The clear-transition subject.
pub const FREEZE_CLEARED_SUBJECT: &str = "[stow] dispatch freeze cleared";

/// The actionable hint a known `send_email` error code gets — the
/// failure modes a configuration can actually cause, each naming the
/// setting or console surface that owns it.
#[must_use]
pub fn notify_hint(code: &str) -> Option<String> {
    match code {
        "E_RECIPIENT_NOT_ALLOWED" => Some(
            "the recipient is not allowed for this deployment: check the Email Sending \
             per-domain allowlist for the sender domain (Compute → Email Service → Email \
             Sending), `allowed_destination_addresses` on the send_email binding, and \
             STOW_ALERT_TO"
                .to_owned(),
        ),
        "E_RECIPIENT_SUPPRESSED" => Some(
            "the recipient address is on Cloudflare's suppression list — clear it there \
             or change STOW_ALERT_TO"
                .to_owned(),
        ),
        "E_SENDER_NOT_VERIFIED" | "E_SENDER_DOMAIN_NOT_AVAILABLE" => Some(
            "STOW_ALERT_FROM must be an address on a domain onboarded and Enabled under \
             Compute → Email Service → Email Sending"
                .to_owned(),
        ),
        "E_DAILY_LIMIT_EXCEEDED" => Some(
            "the account's daily Email Service quota is spent — the alert resumes once \
             the quota rolls over"
                .to_owned(),
        ),
        _ => None,
    }
}

/// Build the recorded channel outcome for a send the binding accepted.
#[must_use]
pub const fn notify_sent(message_id: Option<String>) -> ChannelOutcome {
    ChannelOutcome::Sent { message_id }
}

/// Build the recorded channel outcome for a rejected send, attaching
/// the known-code hint when there is one.
#[must_use]
pub fn notify_failed(code: Option<String>, message: String) -> ChannelOutcome {
    let hint = code.as_deref().and_then(notify_hint);
    let message = match code {
        Some(code) => format!("{code}: {message}"),
        None => message,
    };
    ChannelOutcome::Failed { message, hint }
}

/// Build the recorded channel outcome when no send was attempted.
#[must_use]
pub const fn notify_disabled(reason: String) -> ChannelOutcome {
    ChannelOutcome::Disabled { reason }
}

/// One-line summary of one channel outcome.
#[must_use]
pub fn summarize_channel(outcome: &ChannelOutcome) -> String {
    match outcome {
        ChannelOutcome::Sent { message_id } => message_id
            .as_ref()
            .map_or_else(|| "sent".to_owned(), |id| format!("sent (messageId {id})")),
        ChannelOutcome::Opened { url } => format!("issue opened: {url}"),
        ChannelOutcome::Commented { url } => format!("issue commented: {url}"),
        ChannelOutcome::Resolved { url } => format!("issue resolved: {url}"),
        ChannelOutcome::Failed { message, hint } => hint.as_ref().map_or_else(
            || format!("FAILED: {message}"),
            |hint| format!("FAILED: {message} — {hint}"),
        ),
        ChannelOutcome::Disabled { reason } => format!("disabled: {reason}"),
    }
}

/// One-line summary of a stored notify outcome — for the cleared
/// alert and `stow-admin dispatch-freeze status`.
#[must_use]
pub fn summarize_notify(notify: &ChannelOutcome) -> String {
    format!("email {}", summarize_channel(notify))
}

/// Whether the channel actually reached a human-readable surface.
#[must_use]
pub const fn notify_reached(notify: &ChannelOutcome) -> bool {
    matches!(notify, ChannelOutcome::Sent { .. })
}

/// One-line summary of a stored trigger, for the cleared alert and
/// `stow-admin dispatch-freeze status`.
#[must_use]
pub fn summarize_trigger(trigger: &DispatchFreezeTrigger) -> String {
    match trigger {
        DispatchFreezeTrigger::Manual => "manual (POST /api/v1/admin/dispatch-freeze)".to_owned(),
        DispatchFreezeTrigger::Tripped(trip) => {
            let tripped: Vec<&str> = trip
                .targets
                .iter()
                .filter(|target| target.tripped)
                .map(|target| target.target.as_str())
                .collect();
            let streams = if trip.fleet_tripped {
                if tripped.is_empty() {
                    "fleet".to_owned()
                } else {
                    format!("fleet + {}", tripped.join(", "))
                }
            } else {
                tripped.join(", ")
            };
            format!(
                "tripped: {}/{} attempts failed ({}%) over {}m — {}",
                trip.failures, trip.outcomes, trip.failure_percent, trip.window_minutes, streams
            )
        }
        DispatchFreezeTrigger::Cost(cost) => format!(
            "cost trip: {} used {} of {} daily budget",
            metric_label(cost.metric),
            human_count(cost.used),
            human_count(cost.budget),
        ),
    }
}

/// The plain-text template context — one struct the alert fills
/// differently per trigger kind.
struct TripContext<'a> {
    window_minutes: u32,
    min_outcomes: u32,
    fail_percent: u32,
    outcomes: u32,
    failures: u32,
    failure_percent: u32,
    fleet_tripped: bool,
    targets: &'a [DispatchFreezeTarget],
    classes: &'a [stow_types::api::DispatchFreezeClass],
    example_run_urls: &'a [String],
}

/// The cost-trip fields both templates share.
struct CostContext<'a> {
    metric_label: &'a str,
    used: String,
    budget: String,
    over: Vec<CostOverLine>,
    top_routes: &'a [stow_types::api::TopRouteCount],
}

/// One over-budget metric line rendered in the cost trip alert.
struct CostOverLine {
    metric_label: &'static str,
    used: String,
    budget: String,
}

fn cost_context(cost: &DispatchFreezeCost) -> CostContext<'_> {
    CostContext {
        metric_label: metric_label(cost.metric),
        used: human_count(cost.used),
        budget: human_count(cost.budget),
        over: cost
            .over
            .iter()
            .map(|entry| CostOverLine {
                metric_label: metric_label(entry.metric),
                used: human_count(entry.used),
                budget: human_count(entry.budget),
            })
            .collect(),
        top_routes: &cost.top_routes,
    }
}

/// Askama context for `templates/freeze_alert.txt` — the markdown
/// body that doubles as the incident issue's opening post and the
/// email's `text` part.
#[derive(Template)]
#[template(path = "freeze_alert.txt")]
struct FreezeAlertTemplate<'a> {
    frozen_at: &'a str,
    manual: bool,
    trip: Option<TripContext<'a>>,
    cost: Option<CostContext<'a>>,
    clear_command: &'a str,
    status_command: &'a str,
}

/// Askama context for `templates/freeze_alert.html` — the email's
/// `html` part.
#[derive(Template)]
#[template(path = "freeze_alert.html")]
struct FreezeAlertHtmlTemplate<'a> {
    frozen_at: &'a str,
    manual: bool,
    trip: Option<TripContext<'a>>,
    cost: Option<CostContext<'a>>,
    clear_command: &'a str,
    status_command: &'a str,
}

/// The incident key the freeze's alert and record live under — shared
/// with the watchdog's `incident` issue (`[incident] dispatch-freeze:`
/// on the title), which is the watchdog's to write, not the edge's.
pub const FREEZE_INCIDENT_KEY: &str = stow_types::api::DISPATCH_FREEZE_INCIDENT_KEY;

/// One rendered alert — the email takes `subject`/`body`/`html`; the
/// watchdog composes its own issue title from `key` plus the freeze
/// state it reads over the admin route.
#[derive(Debug, Clone)]
pub struct AlertDraft {
    /// The incident key — the watchdog's dedup anchor and the log's
    /// signal identity.
    #[allow(dead_code)] // the fault-signal sinks (#438) dedupe on it
    pub key: &'static str,
    /// Email subject.
    pub subject: String,
    /// Markdown body — the email's `text` part.
    pub body: String,
    /// HTML body — the email's `html` part.
    pub html: String,
}

fn trip_context(trip: &DispatchFreezeTrip) -> TripContext<'_> {
    TripContext {
        window_minutes: trip.window_minutes,
        min_outcomes: trip.min_outcomes,
        fail_percent: trip.fail_percent,
        outcomes: trip.outcomes,
        failures: trip.failures,
        failure_percent: trip.failure_percent,
        fleet_tripped: trip.fleet_tripped,
        targets: &trip.targets,
        classes: &trip.classes,
        example_run_urls: &trip.example_run_urls,
    }
}

/// Render the freeze-transition alert — subject, incident title and
/// both bodies. Never fails on data grounds (a stored record is
/// already validated); the `askama` error return exists so the
/// caller's log names the template.
pub fn render_freeze_alert(
    frozen_at: &str,
    trigger: &DispatchFreezeTrigger,
) -> Result<AlertDraft, askama::Error> {
    let render_bodies =
        |trigger: &DispatchFreezeTrigger| -> Result<(String, String), askama::Error> {
            let (manual, trip, cost) = match trigger {
                DispatchFreezeTrigger::Manual => (true, None, None),
                DispatchFreezeTrigger::Tripped(trip) => (false, Some(trip_context(trip)), None),
                DispatchFreezeTrigger::Cost(cost) => (false, None, Some(cost_context(cost))),
            };
            let body = FreezeAlertTemplate {
                frozen_at,
                manual,
                trip,
                cost,
                clear_command: CLEAR_COMMAND,
                status_command: STATUS_COMMAND,
            }
            .render()?;
            let (manual, trip, cost) = match trigger {
                DispatchFreezeTrigger::Manual => (true, None, None),
                DispatchFreezeTrigger::Tripped(trip) => (false, Some(trip_context(trip)), None),
                DispatchFreezeTrigger::Cost(cost) => (false, None, Some(cost_context(cost))),
            };
            let html = FreezeAlertHtmlTemplate {
                frozen_at,
                manual,
                trip,
                cost,
                clear_command: CLEAR_COMMAND,
                status_command: STATUS_COMMAND,
            }
            .render()?;
            Ok((body, html))
        };
    let (body, html) = render_bodies(trigger)?;
    Ok(AlertDraft {
        key: FREEZE_INCIDENT_KEY,
        subject: freeze_subject(trigger),
        body,
        html,
    })
}

/// Askama context for `templates/freeze_cleared.txt` — the resolve
/// comment's markdown body and the email's `text` part.
#[derive(Template)]
#[template(path = "freeze_cleared.txt")]
struct FreezeClearedTemplate<'a> {
    frozen_at: &'a str,
    cleared_at: &'a str,
    trigger_summary: &'a str,
    notify_summary: &'a str,
}

/// Askama context for `templates/freeze_cleared.html`.
#[derive(Template)]
#[template(path = "freeze_cleared.html")]
struct FreezeClearedHtmlTemplate<'a> {
    frozen_at: &'a str,
    cleared_at: &'a str,
    trigger_summary: &'a str,
    notify_summary: &'a str,
}

/// Render the cleared-transition alert — the resolve comment closes
/// the issue the engage opened, summarizing the record the freeze
/// held while it was engaged.
pub fn render_freeze_cleared(
    frozen_at: &str,
    cleared_at: &str,
    trigger: &DispatchFreezeTrigger,
    notify: &ChannelOutcome,
) -> Result<AlertDraft, askama::Error> {
    let trigger_summary = summarize_trigger(trigger);
    let notify_summary = summarize_notify(notify);
    let body = FreezeClearedTemplate {
        frozen_at,
        cleared_at,
        trigger_summary: &trigger_summary,
        notify_summary: &notify_summary,
    }
    .render()?;
    let html = FreezeClearedHtmlTemplate {
        frozen_at,
        cleared_at,
        trigger_summary: &trigger_summary,
        notify_summary: &notify_summary,
    }
    .render()?;
    Ok(AlertDraft {
        key: FREEZE_INCIDENT_KEY,
        subject: FREEZE_CLEARED_SUBJECT.to_owned(),
        body,
        html,
    })
}

/// Storage seam for the transition coordinator: the Durable Object
/// implements it over `settings` in wasm; host tests fake it. All three
/// calls touch the freeze row only.
pub trait FreezeStore {
    /// Read the stored record, if the freeze is engaged.
    fn record(
        &self,
    ) -> impl Future<Output = Result<Option<DispatchFreezeRecord>, QueueError>> + Send;
    /// Persist `record` — its presence is the engaged flag.
    fn set(
        &self,
        record: &DispatchFreezeRecord,
    ) -> impl Future<Output = Result<(), QueueError>> + Send;
    /// Drop the record — clears the flag.
    fn delete(&self) -> impl Future<Output = Result<(), QueueError>> + Send;
}

/// Alert seam for the transition coordinator: the wasm impl sends the
/// draft through Email Sending. Host tests count calls.
///
/// Every call reports a [`ChannelOutcome`], never an error: a missing
/// binding or a failed API call comes back inside the outcome so
/// alerting can never wedge a transition (the outcome lands on the
/// freeze record). The `incident` issue record is not this sink's job
/// — the #450 watchdog records it from the freeze status and its
/// transition log; the edge's App token has no `issues` grant.
pub trait AlertSink {
    /// An incident opened — email the draft.
    fn opened(&self, draft: &AlertDraft) -> impl Future<Output = ChannelOutcome> + Send;
    /// The incident is still open — a digest/update send. The freeze's
    /// digest is the watchdog's (#450); fault signals (#438) still use
    /// this verb edge-side.
    #[allow(dead_code)]
    fn updated(&self, draft: &AlertDraft) -> impl Future<Output = ChannelOutcome> + Send;
    /// The incident cleared — email the summary.
    fn resolved(&self, draft: &AlertDraft) -> impl Future<Output = ChannelOutcome> + Send;
}

/// What an operator/command asks the freeze to do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreezeAction {
    /// Engage the flag under `trigger`.
    Freeze,
    /// Clear the flag, whatever trigger engaged it.
    Clear,
}

/// The state change a [`apply_transition`] call made — and therefore
/// the single email it sent. `Engaged` carries the stored record
/// (notify outcome included); `Cleared` carries the record the freeze
/// held.
#[derive(Clone, Debug, PartialEq)]
pub enum FreezeTransition {
    /// Not frozen → frozen: the record was stored and one alert sent.
    Engaged(DispatchFreezeRecord),
    /// Frozen → not frozen: the record was dropped and one cleared
    /// alert sent.
    Cleared(DispatchFreezeRecord),
    /// The flag already held the requested state — no write, no email.
    Unchanged,
}

/// One transition, one alert — the whole "never per failure" rule lives
/// here: an already-engaged freeze (a repeated trip, a doubled admin
/// `freeze`) returns `Unchanged` without notifying, and a clear on a
/// clear store likewise. `now` stamps `frozen_at`/`cleared_at`;
/// `trigger` is what the freeze will attribute itself to (`Manual` for
/// the admin command, `Tripped`/`Cost` for the automatic paths).
#[allow(clippy::future_not_send)]
pub async fn apply_transition(
    store: &impl FreezeStore,
    sink: &impl AlertSink,
    action: FreezeAction,
    trigger: DispatchFreezeTrigger,
    now: &str,
) -> Result<FreezeTransition, QueueError> {
    match action {
        FreezeAction::Freeze => {
            if store.record().await?.is_some() {
                return Ok(FreezeTransition::Unchanged);
            }
            let mut record = DispatchFreezeRecord {
                frozen_at: now.to_owned(),
                trigger,
                notify: ChannelOutcome::Disabled {
                    reason: "alert render failed".to_owned(),
                },
            };
            match render_freeze_alert(now, &record.trigger) {
                Ok(draft) => {
                    record.notify = sink.opened(&draft).await;
                }
                Err(error) => {
                    record.notify = ChannelOutcome::Failed {
                        message: format!("alert template: {error}"),
                        hint: None,
                    };
                }
            }
            store.set(&record).await?;
            Ok(FreezeTransition::Engaged(record))
        }
        FreezeAction::Clear => {
            let Some(record) = store.record().await? else {
                return Ok(FreezeTransition::Unchanged);
            };
            store.delete().await?;
            if let Ok(draft) =
                render_freeze_cleared(&record.frozen_at, now, &record.trigger, &record.notify)
            {
                let outcome = sink.resolved(&draft).await;
                if !notify_reached(&outcome) {
                    tracing::warn!(?outcome, "freeze-cleared alert reached nobody");
                }
            }
            Ok(FreezeTransition::Cleared(record))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_FREEZE_FAIL_PERCENT, DEFAULT_FREEZE_MIN_OUTCOMES, DEFAULT_FREEZE_WINDOW_MINUTES,
        FreezeSettings, FreezeStore, OutcomeTally, evaluate, notify_failed, notify_hint,
        observed_percent, render_freeze_alert, render_freeze_cleared, summarize_notify,
        summarize_trigger,
    };
    use stow_types::api::{
        ChannelOutcome, CostMetric, DispatchFreezeClass, DispatchFreezeCost,
        DispatchFreezeCostEntry, DispatchFreezeRecord, DispatchFreezeTarget, DispatchFreezeTrigger,
        DispatchFreezeTrip, TopRouteCount,
    };
    use stow_types::identity::TargetTriple;

    use crate::errors::QueueError;

    fn settings() -> FreezeSettings {
        FreezeSettings {
            window_minutes: DEFAULT_FREEZE_WINDOW_MINUTES,
            min_outcomes: DEFAULT_FREEZE_MIN_OUTCOMES,
            fail_percent: DEFAULT_FREEZE_FAIL_PERCENT,
        }
    }

    fn tally(target: &str, outcomes: u32, failures: u32) -> OutcomeTally {
        OutcomeTally {
            target: target.to_owned(),
            outcomes,
            failures,
        }
    }

    #[test]
    fn nothing_trips_below_the_sample_floor_however_bad_the_ratio() {
        // 2 failures out of 2 is not a signal.
        assert!(evaluate(&[tally("t-linux", 2, 2)], &settings()).is_none());
        assert!(evaluate(&[tally("t-win", 49, 49)], &settings()).is_none());
    }

    #[test]
    fn nothing_trips_below_the_ratio_however_large_the_sample() {
        assert!(evaluate(&[tally("t-linux", 1000, 400)], &settings()).is_none());
        // Exactly at the ratio trips — the threshold is inclusive.
        assert!(evaluate(&[tally("t-linux", 100, 50)], &settings()).is_some());
        assert!(evaluate(&[tally("t-linux", 100, 49)], &settings()).is_none());
    }

    #[test]
    fn a_concentrated_breakage_trips_on_one_target() {
        // The measured incident shape: the Windows legs fail ~100% while
        // other targets stay healthy.
        let eval = evaluate(
            &[
                tally("x86_64-pc-windows-msvc", 60, 60),
                tally("x86_64-unknown-linux-gnu", 200, 2),
            ],
            &settings(),
        )
        .expect("60/60 failures on one target trips");
        assert!(!eval.fleet_tripped);
        let tripped: Vec<&str> = eval
            .targets
            .iter()
            .filter(|target| target.tripped)
            .map(|target| target.target.as_str())
            .collect();
        assert_eq!(tripped, ["x86_64-pc-windows-msvc"]);
    }

    #[test]
    fn a_dispersed_breakage_trips_on_the_fleet_stream() {
        // No single target reaches the floor, but the fleet does —
        // a fleet-wide breakage (bad rustc, poisoned tarball) is the
        // same burn against the shared allowance.
        let eval = evaluate(&[tally("t-a", 30, 28), tally("t-b", 30, 29)], &settings())
            .expect("the fleet aggregate trips even when no target does");
        assert!(eval.fleet_tripped);
        assert_eq!(eval.outcomes, 60);
        assert_eq!(eval.failures, 57);
        assert!(eval.targets.iter().all(|target| !target.tripped));
    }

    #[test]
    fn an_empty_window_never_trips() {
        // Even a zeroed min-outcomes floor cannot make "nothing failed"
        // a systematic failure.
        let zero_floor = FreezeSettings {
            min_outcomes: 0,
            ..settings()
        };
        assert!(evaluate(&[], &zero_floor).is_none());
        assert!(evaluate(&[tally("t-a", 0, 0)], &zero_floor).is_none());
    }

    #[test]
    fn observed_percent_is_the_fleet_ratio() {
        let eval = evaluate(&[tally("t-a", 100, 67)], &settings()).expect("trips");
        assert_eq!(observed_percent(&eval), 67);
    }

    #[test]
    fn only_failing_targets_are_listed() {
        let eval = evaluate(
            &[tally("t-ok", 500, 0), tally("t-bad", 60, 55)],
            &settings(),
        )
        .expect("trips");
        assert_eq!(eval.targets.len(), 1);
        assert_eq!(eval.targets[0].target, "t-bad");
    }

    #[test]
    fn recipient_denial_names_the_allowlist_setting() {
        let notify = notify_failed(
            Some("E_RECIPIENT_NOT_ALLOWED".to_owned()),
            "recipient not allowed".to_owned(),
        );
        let ChannelOutcome::Failed { message, hint } = &notify else {
            panic!("expected a failed outcome");
        };
        assert!(message.contains("E_RECIPIENT_NOT_ALLOWED"));
        let hint = hint.as_ref().expect("a known code carries a hint");
        assert!(hint.contains("allowed_destination_addresses"));
        assert!(hint.contains("STOW_ALERT_TO"));
        assert_eq!(
            notify_hint("E_RECIPIENT_NOT_ALLOWED").as_deref(),
            Some(hint.as_str())
        );
        assert!(notify_hint("E_SOMETHING_ELSE").is_none());
    }

    fn trip() -> DispatchFreezeTrip {
        DispatchFreezeTrip {
            window_minutes: 60,
            min_outcomes: 50,
            fail_percent: 50,
            outcomes: 512,
            failures: 480,
            failure_percent: 93,
            fleet_tripped: true,
            targets: vec![
                DispatchFreezeTarget {
                    target: TargetTriple::parse("x86_64-pc-windows-msvc").expect("target"),
                    outcomes: 312,
                    failures: 312,
                    tripped: true,
                },
                DispatchFreezeTarget {
                    target: TargetTriple::parse("aarch64-pc-windows-msvc").expect("target"),
                    outcomes: 168,
                    failures: 168,
                    tripped: true,
                },
            ],
            classes: vec![
                DispatchFreezeClass {
                    class: "register: POST /api/v1/admin/artifacts/register -> 500".to_owned(),
                    count: 240,
                },
                DispatchFreezeClass {
                    class: "build: cargo exited 101".to_owned(),
                    count: 173,
                },
            ],
            example_run_urls: vec![
                "https://github.com/water-rs/stow/actions/runs/123456".to_owned(),
                "https://github.com/water-rs/stow/actions/runs/123450".to_owned(),
            ],
        }
    }

    #[test]
    fn freeze_alert_names_counts_window_ratio_targets_classes_and_runs() {
        let draft = render_freeze_alert(
            "2026-09-22T03:51:00Z",
            &DispatchFreezeTrigger::Tripped(trip()),
        )
        .expect("template renders");
        assert_eq!(draft.key, "dispatch-freeze");
        for needle in [
            "480",
            "512",
            "93%",
            "60m",
            "x86_64-pc-windows-msvc",
            "aarch64-pc-windows-msvc",
            "register: POST /api/v1/admin/artifacts/register -> 500",
            "https://github.com/water-rs/stow/actions/runs/123456",
            "https://github.com/water-rs/stow/actions/runs/123450",
            "stow-admin dispatch-freeze clear --yes",
        ] {
            assert!(
                draft.body.contains(needle) || draft.html.contains(needle),
                "alert is missing `{needle}`:\ntext:\n{}\nhtml:\n{}",
                draft.body,
                draft.html
            );
        }
        assert!(!draft.html.is_empty());
    }

    #[test]
    fn manual_freeze_alert_renders_without_trip_stats() {
        let draft = render_freeze_alert("2026-09-22T03:51:00Z", &DispatchFreezeTrigger::Manual)
            .expect("template renders");
        assert_eq!(draft.key, "dispatch-freeze");
        assert!(draft.body.contains("manual"));
        assert!(
            draft
                .body
                .contains("stow-admin dispatch-freeze clear --yes")
        );
    }

    #[test]
    fn cost_freeze_alert_names_metric_used_budget_and_top_routes() {
        let cost = DispatchFreezeCost {
            metric: CostMetric::DurableObjectRowsRead,
            used: 900_000_000.0,
            budget: 833_333_333.0,
            over: vec![
                DispatchFreezeCostEntry {
                    metric: CostMetric::DurableObjectRowsRead,
                    used: 900_000_000.0,
                    budget: 833_333_333.0,
                },
                DispatchFreezeCostEntry {
                    metric: CostMetric::D1RowsWritten,
                    used: 1_900_000.0,
                    budget: 1_666_667.0,
                },
            ],
            top_routes: vec![TopRouteCount {
                label: "stow-edge".to_owned(),
                requests: 45_000.0,
            }],
        };
        let draft = render_freeze_alert("2026-09-27T04:00:00Z", &DispatchFreezeTrigger::Cost(cost))
            .expect("template renders");
        assert!(
            draft
                .subject
                .contains("durable object rows read over daily budget")
        );
        for needle in [
            "durable object rows read",
            "900.0M",
            "833.3M",
            "d1 rows written",
            "stow-edge",
        ] {
            assert!(
                draft.body.contains(needle),
                "cost alert body is missing `{needle}`:\n{}",
                draft.body
            );
        }
        assert!(draft.html.contains("durable object rows read"));
    }

    #[test]
    fn cost_subject_names_the_metric() {
        let subject = super::freeze_subject(&DispatchFreezeTrigger::Cost(DispatchFreezeCost {
            metric: CostMetric::WorkerCpuMs,
            used: 1.0,
            budget: 1.0,
            over: Vec::new(),
            top_routes: Vec::new(),
        }));
        assert!(subject.contains("worker CPU (ms)"));
    }

    #[test]
    fn cleared_alert_replays_what_the_freeze_record_held() {
        let draft = render_freeze_cleared(
            "2026-09-22T03:51:00Z",
            "2026-09-22T05:10:00Z",
            &DispatchFreezeTrigger::Tripped(trip()),
            &ChannelOutcome::Failed {
                message: "E_RECIPIENT_NOT_ALLOWED: recipient not allowed".to_owned(),
                hint: Some("check the allowlist".to_owned()),
            },
        )
        .expect("template renders");
        assert_eq!(draft.key, "dispatch-freeze");
        assert!(draft.body.contains("2026-09-22T03:51:00Z"));
        assert!(draft.body.contains("2026-09-22T05:10:00Z"));
        assert!(draft.body.contains("480/512"));
        assert!(draft.body.contains("E_RECIPIENT_NOT_ALLOWED"));
    }

    #[test]
    fn cost_trigger_summarizes_metric_used_and_budget() {
        let summary = summarize_trigger(&DispatchFreezeTrigger::Cost(DispatchFreezeCost {
            metric: CostMetric::D1RowsWritten,
            used: 2_000_000.0,
            budget: 1_666_667.0,
            over: Vec::new(),
            top_routes: Vec::new(),
        }));
        assert!(summary.contains("d1 rows written"));
        assert!(summary.contains("2.0M"));
    }

    #[test]
    fn notify_summary_marks_a_failed_send_loudly() {
        let notify = ChannelOutcome::Failed {
            message: "E_DAILY_LIMIT_EXCEEDED: quota".to_owned(),
            hint: None,
        };
        let summary = summarize_notify(&notify);
        assert!(summary.contains("FAILED"), "{summary}");
        assert!(summary.contains("E_DAILY_LIMIT_EXCEEDED"), "{summary}");
        let sent = ChannelOutcome::Sent {
            message_id: Some("abc".to_owned()),
        };
        let summary = summarize_notify(&sent);
        assert!(summary.contains("abc"), "{summary}");
        assert!(super::notify_reached(&sent));
        let silent = ChannelOutcome::Disabled {
            reason: "no binding".to_owned(),
        };
        assert!(!super::notify_reached(&silent));
    }

    // ===== One alert per transition (issue #279) =====

    /// In-memory [`FreezeStore`]: the row's presence is the flag.
    struct FakeStore(std::sync::Mutex<Option<DispatchFreezeRecord>>);

    impl super::FreezeStore for FakeStore {
        fn record(
            &self,
        ) -> impl Future<Output = Result<Option<DispatchFreezeRecord>, QueueError>> + Send {
            std::future::ready(Ok(self.0.lock().expect("store").clone()))
        }
        fn set(
            &self,
            record: &DispatchFreezeRecord,
        ) -> impl Future<Output = Result<(), QueueError>> + Send {
            *self.0.lock().expect("store") = Some(record.clone());
            std::future::ready(Ok(()))
        }
        fn delete(&self) -> impl Future<Output = Result<(), QueueError>> + Send {
            *self.0.lock().expect("store") = None;
            std::future::ready(Ok(()))
        }
    }

    /// Counting [`AlertSink`]: every call appends `(kind, subject)`.
    struct FakeSink(std::sync::Mutex<Vec<(&'static str, String)>>);

    impl super::AlertSink for FakeSink {
        fn opened(&self, draft: &super::AlertDraft) -> impl Future<Output = ChannelOutcome> + Send {
            self.0
                .lock()
                .expect("sent")
                .push(("opened", draft.subject.clone()));
            std::future::ready(ChannelOutcome::Sent {
                message_id: Some("fake".to_owned()),
            })
        }
        fn updated(
            &self,
            draft: &super::AlertDraft,
        ) -> impl Future<Output = ChannelOutcome> + Send {
            self.0
                .lock()
                .expect("sent")
                .push(("updated", draft.subject.clone()));
            std::future::ready(ChannelOutcome::Sent { message_id: None })
        }
        fn resolved(
            &self,
            draft: &super::AlertDraft,
        ) -> impl Future<Output = ChannelOutcome> + Send {
            self.0
                .lock()
                .expect("sent")
                .push(("resolved", draft.subject.clone()));
            std::future::ready(ChannelOutcome::Sent {
                message_id: Some("fake".to_owned()),
            })
        }
    }

    impl FakeSink {
        fn sent(&self) -> Vec<(&'static str, String)> {
            self.0.lock().expect("sent").clone()
        }
    }

    /// Freeze → freeze again → clear → clear again issues exactly two
    /// alerts: one per *transition*. The repeated calls return
    /// `Unchanged` and never reach the sink — this is why a trip
    /// storm under sustained failures cannot spam the operator.
    #[tokio::test]
    async fn one_alert_per_transition() {
        let store = FakeStore(std::sync::Mutex::new(None));
        let sink = FakeSink(std::sync::Mutex::new(Vec::new()));
        let trigger = || DispatchFreezeTrigger::Tripped(trip());

        assert!(matches!(
            super::apply_transition(
                &store,
                &sink,
                super::FreezeAction::Freeze,
                trigger(),
                "2026-09-22T03:51:00Z",
            )
            .await
            .expect("freeze"),
            super::FreezeTransition::Engaged(_)
        ));
        assert_eq!(
            super::apply_transition(
                &store,
                &sink,
                super::FreezeAction::Freeze,
                trigger(),
                "2026-09-22T03:52:00Z",
            )
            .await
            .expect("re-freeze"),
            super::FreezeTransition::Unchanged,
            "a second trip while frozen sends nothing"
        );
        assert_eq!(sink.sent().len(), 1);
        let record = store.record().await.expect("record").expect("engaged");
        assert!(matches!(record.notify, ChannelOutcome::Sent { .. }));
        assert!(super::notify_reached(&record.notify));

        assert!(matches!(
            super::apply_transition(
                &store,
                &sink,
                super::FreezeAction::Clear,
                DispatchFreezeTrigger::Manual,
                "2026-09-22T05:10:00Z",
            )
            .await
            .expect("clear"),
            super::FreezeTransition::Cleared(_)
        ));
        assert_eq!(
            super::apply_transition(
                &store,
                &sink,
                super::FreezeAction::Clear,
                DispatchFreezeTrigger::Manual,
                "2026-09-22T05:11:00Z",
            )
            .await
            .expect("re-clear"),
            super::FreezeTransition::Unchanged,
            "clearing an un-frozen store sends nothing"
        );
        assert_eq!(
            sink.sent(),
            [
                (
                    "opened",
                    "[stow] dispatch frozen — systematic failures".to_owned()
                ),
                ("resolved", "[stow] dispatch freeze cleared".to_owned()),
            ],
            "exactly one alert per state transition"
        );
        assert!(store.record().await.expect("record").is_none());
    }
}
