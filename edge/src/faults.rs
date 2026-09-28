//! Fault signals — #438, split by where the fact lives.
//!
//! Object-side signals are evaluated on the events that change them,
//! never on a timer: build failures when a completion report lands,
//! queue health on enqueue and on each dispatch pass. Edge-side
//! signals (Worker 5xx rate, DO resource failures, usage) are the #450
//! watchdog's — the edge only *writes* the Analytics Engine events the
//! watchdog reads ([`record_worker_5xx`], [`record_do_overloaded`]),
//! per event, not idle.
//!
//! Each signal's threshold is a minimum sample combined with a rate
//! (or count/age), so a quiet window never opens a signal and a single
//! bad row never resolves one. One mail goes out when a signal opens,
//! one when it resolves, and a digest summarises each still-open
//! signal at most hourly — and only when an evaluation actually runs:
//! no events means nothing new to say.
//!
//! State (opened/last-digest times plus the stored observation) lives in
//! the scheduler object's `fault_signals` table behind [`SignalStore`];
//! the alert transport reuses the #279 [`crate::freeze::AlertSink`]
//! seam (email notify; the `incident` issue record is the watchdog's,
//! which reads freeze state over `dispatch-freeze status`) so host
//! tests fake it. Each signal is its own incident keyed `fault-{snake}`.
use std::fmt::Write as _;

use stow_types::api::{FaultObservation, FaultOffender, FaultSignal};

/// The evaluation window — each event evaluates its signal over the
/// trailing ten minutes.
pub const FAULT_WINDOW_MINUTES: u32 = 10;

/// Open-signal digest cadence — a still-open signal is summarised at
/// most this often.
pub const DIGEST_INTERVAL_MINUTES: u64 = 60;

/// Build failures: needs ten terminal attempts in the window and a
/// twenty-percent failure share before it opens — a lone failed retry
/// of one crate is ordinary queue traffic, not a fault.
pub const BUILD_FAILURE_MIN_OUTCOMES: f64 = 10.0;
/// Build failure rate threshold, percent.
pub const BUILD_FAILURE_PERCENT: f64 = 20.0;
/// Tasks at or above this attempt count are offenders on their own —
/// the incident that prompted #438 retried to attempt 12.
pub const BUILD_FAILURE_ATTEMPT_THRESHOLD: u32 = 4;

/// Queue health: the oldest pending task is older than this (minutes).
/// Dispatch deliberately ages misses `STOW_DISPATCH_MIN_AGE_MINUTES`;
/// an hour pending means nothing has claimed it.
pub const QUEUE_AGE_MINUTES: f64 = 60.0;
/// A dispatch stall needs pending work in the queue…
pub const QUEUE_STALL_MIN_PENDING: f64 = 1.0;

/// Offenders a mail lists at most.
pub const MAX_OFFENDERS: usize = 10;

/// The signal's current persisted state — the row's presence means open.
#[derive(Debug, Clone, PartialEq)]
pub struct SignalState {
    /// ISO 8601 timestamp the signal opened.
    pub opened_at: String,
    /// ISO 8601 timestamp of the last digest mail naming it.
    pub last_digest_at: String,
    /// The observation stored at open time (what the resolve mail can
    /// still name after the window drains).
    pub observation: FaultObservation,
}

/// Storage seam for fault-signal state — the object implements it over
/// its `fault_signals` table; host tests fake it.
pub trait SignalStore {
    /// Every currently-open signal's stored state.
    fn open_signals(
        &self,
    ) -> impl std::future::Future<
        Output = Result<Vec<(FaultSignal, SignalState)>, crate::errors::QueueError>,
    > + Send;
    /// Mark `signal` open with this state, or update a still-open row.
    fn open(
        &self,
        signal: FaultSignal,
        state: &SignalState,
    ) -> impl std::future::Future<Output = Result<(), crate::errors::QueueError>> + Send;
    /// Mark `signal` resolved — drops its row.
    fn resolve(
        &self,
        signal: FaultSignal,
    ) -> impl std::future::Future<Output = Result<(), crate::errors::QueueError>> + Send;
}

/// Whether an observation's min-sample floor is met and its rate/count
/// threshold crossed — the shared gate every signal runs through.
pub fn opens(sample: f64, min_sample: f64, observed: f64, threshold: f64) -> bool {
    sample >= min_sample && observed > threshold
}

/// The incident-issue dedup key one signal alerts under — `[incident]
/// fault-{key}:` on the issue title. Snake-cases the signal name.
pub const fn signal_key(signal: FaultSignal) -> &'static str {
    match signal {
        FaultSignal::ErrorRate => "fault-error-rate",
        FaultSignal::ResourceFailures => "fault-resource-failures",
        FaultSignal::BuildFailures => "fault-build-failures",
        FaultSignal::QueueHealth => "fault-queue-health",
        FaultSignal::UsageWarn => "fault-usage-warn",
        FaultSignal::UsageHigh => "fault-usage-high",
    }
}

/// Route family for a request path — the label 5xx events and alert
/// offenders group on (`public`, `admin`, `scheduler`, `build-callbacks`).
pub fn route_family(path: &str) -> &'static str {
    if path.starts_with("/api/v1/admin/artifacts/register")
        || path.starts_with("/api/v1/scheduler/complete")
    {
        "build-callbacks"
    } else if path.starts_with("/api/v1/scheduler/") {
        "scheduler"
    } else if path.starts_with("/api/v1/admin/") {
        "admin"
    } else {
        "public"
    }
}

/// The `index1` value every fault event carries — `#` can never collide
/// with the crate-name indexes the miss points use.
pub const FAULT_INDEX: &str = "#fault";
/// Worker 5xx event kind.
pub const FAULT_KIND_5XX: &str = "worker_5xx";
/// DO overloaded event kind.
pub const FAULT_KIND_OVERLOADED: &str = "do_overloaded";

// ---- Worker-side machinery (wasm only): the Analytics Engine write,
// the SQL read, the 5xx-observing middleware, and the thread-local
// dataset scheduler_client records `overloaded` errors through. ----

#[cfg(target_arch = "wasm32")]
mod worker {
    use skyzen_cloudflare::worker::{AnalyticsEngineDataPointBuilder, AnalyticsEngineDataset};

    // The `STOW_ANALYTICS` dataset installed per-isolate at worker
    // startup — `scheduler_client` has no env handle where it catches
    // DO `overloaded`, so the binding lives in a thread-local (the
    // runtime is single-threaded).
    thread_local! {
        static DATASET: std::cell::RefCell<Option<AnalyticsEngineDataset>> =
            const { std::cell::RefCell::new(None) };
    }

    /// Install the dataset this isolate records fault events into —
    /// called once from `entry::worker` alongside the other binding
    /// reads.
    pub fn install_dataset(dataset: AnalyticsEngineDataset) {
        DATASET.with(|slot| *slot.borrow_mut() = Some(dataset));
    }

    /// Record one fault event — `index1 = '#fault'` partitions it from
    /// the miss points sharing `stow_cache_misses`, `blob1` the kind,
    /// `blob2` the family/label, `double1` the status or count. A
    /// failed write logs and drops: observability must never fail the
    /// request it observed.
    fn write_fault(kind: &'static str, label: &str, code: f64) {
        DATASET.with(|slot| {
            if let Some(dataset) = slot.borrow().as_ref() {
                let result = AnalyticsEngineDataPointBuilder::new()
                    .indexes([super::FAULT_INDEX])
                    .blobs([kind, label])
                    .doubles([code])
                    .write_to(dataset);
                if let Err(error) = result {
                    tracing::warn!(%error, kind, "failed to write fault event");
                }
            }
        });
    }

    /// Record a Worker 5xx — the route family is the offender label,
    /// the status the double.
    pub fn record_worker_5xx(family: &'static str, status: u16) {
        write_fault(super::FAULT_KIND_5XX, family, f64::from(status));
    }

    /// Record a DO `overloaded` catch — `label` is the scheduler path
    /// that was being called.
    pub fn record_do_overloaded(label: &str) {
        write_fault(super::FAULT_KIND_OVERLOADED, label, 1.0);
    }

    /// Skyzen middleware `entry.rs` wraps every route in: the 5xx share
    /// of served responses is the `ErrorRate` signal's numerator, and
    /// the route family its offender label. Panic-gate sheds count too —
    /// a shed is still a 503 the caller received.
    pub struct FaultWatch;

    impl skyzen::middleware::Middleware for FaultWatch {
        async fn handle(
            &self,
            request: &mut skyzen::Request,
            next: skyzen::middleware::Next<'_>,
        ) -> Result<skyzen::Response, skyzen::Error> {
            let family = super::route_family(request.uri().path());
            match next.run(request).await {
                Ok(response) => {
                    let status = response.status().as_u16();
                    if (500..600).contains(&status) {
                        record_worker_5xx(family, status);
                    }
                    Ok(response)
                }
                Err(error) => {
                    let status = error.status().as_u16();
                    if (500..600).contains(&status) {
                        record_worker_5xx(family, status);
                    }
                    Err(error)
                }
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use worker::{FaultWatch, install_dataset, record_do_overloaded};

/// What one event-driven evaluation did — the transitions it mailed.
/// Logs and tests read it; the signals themselves live in
/// `fault_signals`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FaultTransitionReport {
    /// Signals that opened this evaluation (each mailed once).
    pub opened: Vec<FaultSignal>,
    /// Signals that resolved this evaluation (each mailed once).
    pub resolved: Vec<FaultSignal>,
    /// Whether a still-open digest mail went out.
    pub digested: bool,
}

/// A fault alert's kind — which sink verb the draft feeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailKind {
    /// A signal just opened.
    Opened,
    /// A signal just resolved.
    Resolved,
    /// A still-open signal summarised.
    Digest,
}

/// The alert subject line — one signal per mail, so the verb + signal
/// title carry it.
pub fn mail_subject(kind: MailKind, signal: FaultSignal) -> String {
    match kind {
        MailKind::Opened => format!("stow fault opened: {}", signal.title()),
        MailKind::Resolved => format!("stow fault resolved: {}", signal.title()),
        MailKind::Digest => format!("stow fault digest: {} still open", signal.title()),
    }
}

/// One rendered signal block in the mail.
#[derive(Clone)]
struct SignalLine<'a> {
    title: &'static str,
    window_minutes: u32,
    observed: String,
    threshold: String,
    unit: &'a str,
    sample: String,
    offenders: &'a [FaultOffender],
}

impl<'a> From<&'a SignalState> for SignalLine<'a> {
    fn from(state: &'a SignalState) -> Self {
        let observation = &state.observation;
        Self {
            title: observation.signal.title(),
            window_minutes: FAULT_WINDOW_MINUTES,
            observed: human_count(observation.observed),
            threshold: human_count(observation.threshold),
            unit: &observation.unit,
            sample: human_count(observation.sample),
            offenders: &observation.offenders,
        }
    }
}

/// Compact number for a mail line — integers print bare, rates keep one
/// decimal.
fn human_count(value: f64) -> String {
    if value.fract() == 0.0 {
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "callers only pass non-negative counts/rates; a value past u64::MAX prints rounded"
        )]
        let as_int = value as u64;
        as_int.to_string()
    } else {
        format!("{value:.1}")
    }
}

#[derive(askama::Template)]
#[template(path = "fault_alert.txt")]
struct FaultText<'a> {
    kind: &'a str,
    lines: Vec<SignalLine<'a>>,
}

#[derive(askama::Template)]
#[template(path = "fault_alert.html")]
struct FaultHtml<'a> {
    kind: &'a str,
    lines: Vec<SignalLine<'a>>,
}

/// Render one signal's fault alert — opened, resolved, or digest —
/// into the shared [`crate::freeze::AlertDraft`] both channels send
/// from: `subject` for the email, `title` for the incident issue,
/// `body`/`html` for both.
pub fn render_fault_mail(
    kind: MailKind,
    state: &SignalState,
) -> Result<crate::freeze::AlertDraft, crate::errors::QueueError> {
    use askama::Template as _;
    let signal = state.observation.signal;
    let subject = mail_subject(kind, signal);
    let kind_label = match kind {
        MailKind::Opened => "opened",
        MailKind::Resolved => "resolved",
        MailKind::Digest => "digest",
    };
    let lines = vec![SignalLine::from(state)];
    let text = FaultText {
        kind: kind_label,
        lines: lines.clone(),
    }
    .render()
    .map_err(|error| crate::errors::QueueError::Sql(format!("fault text template: {error}")))?;
    let html = FaultHtml {
        kind: kind_label,
        lines,
    }
    .render()
    .map_err(|error| crate::errors::QueueError::Sql(format!("fault html template: {error}")))?;
    Ok(crate::freeze::AlertDraft {
        key: signal_key(signal),
        subject,
        body: text,
        html,
    })
}

/// Diff one tick's observations against the stored open signals and
/// send the mail each transition earns: one per opened signal, one per
/// resolved signal, and one digest for everything still open once the
/// digest interval has elapsed.
///
/// `digest_due` is the caller's decision that the interval has passed
/// (the store answers `opened_at`/`last_digest_at` strings; comparing
/// them as lexicographic ISO 8601 works because every writer stamps
/// `strftime`-shaped UTC).
#[allow(clippy::future_not_send)]
pub async fn apply_fault_transitions(
    store: &impl SignalStore,
    sink: &impl crate::freeze::AlertSink,
    observations: Vec<FaultObservation>,
    now: &str,
    digest_after: &str,
) -> Result<FaultTransitionReport, crate::errors::QueueError> {
    let mut report = FaultTransitionReport::default();
    let mut known: std::collections::BTreeMap<FaultSignal, SignalState> =
        store.open_signals().await?.into_iter().collect();

    for observation in observations {
        let signal = observation.signal;
        match (observation.open, known.get(&signal)) {
            (true, None) => {
                let state = SignalState {
                    opened_at: now.to_owned(),
                    last_digest_at: now.to_owned(),
                    observation,
                };
                let draft = render_fault_mail(MailKind::Opened, &state)?;
                let notify = sink.opened(&draft).await;
                if !crate::freeze::notify_reached(&notify) {
                    tracing::error!(?notify, ?signal, "fault opened alert reached nobody");
                }
                store.open(signal, &state).await?;
                known.insert(signal, state);
                report.opened.push(signal);
            }
            (false, Some(state)) => {
                let state = state.clone();
                let draft = render_fault_mail(MailKind::Resolved, &state)?;
                let notify = sink.resolved(&draft).await;
                if !crate::freeze::notify_reached(&notify) {
                    tracing::error!(?notify, ?signal, "fault resolved alert reached nobody");
                }
                store.resolve(signal).await?;
                known.remove(&signal);
                report.resolved.push(signal);
            }
            (true, Some(state)) => {
                // Still open — refresh the stored observation so the
                // digest reads current numbers, keep the opened time.
                let mut state = state.clone();
                state.observation = observation;
                store.open(signal, &state).await?;
                known.insert(signal, state);
            }
            (false, None) => {}
        }
    }

    // One digest per still-open signal, at most hourly — each signal
    // is its own incident issue, so its digest comment lands there
    // (the email rides the same draft). The digest uses the freshest
    // stored observation.
    for (signal, state) in &mut known {
        if state.last_digest_at.as_str() > digest_after {
            continue;
        }
        let draft = render_fault_mail(MailKind::Digest, state)?;
        let notify = sink.updated(&draft).await;
        if !crate::freeze::notify_reached(&notify) {
            tracing::error!(?notify, ?signal, "fault digest alert reached nobody");
        }
        now.clone_into(&mut state.last_digest_at);
        store.open(*signal, state).await?;
        report.digested = true;
    }

    let mut summary = String::new();
    for signal in &report.opened {
        let _ = write!(summary, " opened={signal:?}");
    }
    for signal in &report.resolved {
        let _ = write!(summary, " resolved={signal:?}");
    }
    if !summary.is_empty() || report.digested {
        tracing::warn!(digested = report.digested, "fault transitions:{summary}");
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::{
        BUILD_FAILURE_MIN_OUTCOMES, BUILD_FAILURE_PERCENT, FAULT_WINDOW_MINUTES, MailKind,
        SignalState, SignalStore, apply_fault_transitions, mail_subject, render_fault_mail,
        route_family,
    };
    use crate::errors::QueueError;
    use crate::freeze::{AlertDraft, AlertSink};
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use stow_types::api::{ChannelOutcome, FaultObservation, FaultOffender, FaultSignal};

    struct FakeStore(Mutex<BTreeMap<FaultSignal, SignalState>>);

    impl FakeStore {
        fn new() -> Self {
            Self(Mutex::new(BTreeMap::new()))
        }
    }

    impl SignalStore for FakeStore {
        fn open_signals(
            &self,
        ) -> impl std::future::Future<Output = Result<Vec<(FaultSignal, SignalState)>, QueueError>> + Send
        {
            let rows = self
                .0
                .lock()
                .expect("store")
                .iter()
                .map(|(signal, state)| (*signal, state.clone()))
                .collect();
            std::future::ready(Ok(rows))
        }
        fn open(
            &self,
            signal: FaultSignal,
            state: &SignalState,
        ) -> impl std::future::Future<Output = Result<(), QueueError>> + Send {
            self.0.lock().expect("store").insert(signal, state.clone());
            std::future::ready(Ok(()))
        }
        fn resolve(
            &self,
            signal: FaultSignal,
        ) -> impl std::future::Future<Output = Result<(), QueueError>> + Send {
            self.0.lock().expect("store").remove(&signal);
            std::future::ready(Ok(()))
        }
    }

    /// Counting [`AlertSink`]: each call appends `(verb, subject)` and
    /// answers `Sent` — the edge's one channel is email.
    struct FakeSink(Mutex<Vec<(&'static str, String)>>);

    impl AlertSink for FakeSink {
        fn opened(
            &self,
            draft: &AlertDraft,
        ) -> impl std::future::Future<Output = ChannelOutcome> + Send {
            self.0
                .lock()
                .expect("sent")
                .push(("opened", draft.subject.clone()));
            std::future::ready(ChannelOutcome::Sent { message_id: None })
        }
        fn updated(
            &self,
            draft: &AlertDraft,
        ) -> impl std::future::Future<Output = ChannelOutcome> + Send {
            self.0
                .lock()
                .expect("sent")
                .push(("updated", draft.subject.clone()));
            std::future::ready(ChannelOutcome::Sent { message_id: None })
        }
        fn resolved(
            &self,
            draft: &AlertDraft,
        ) -> impl std::future::Future<Output = ChannelOutcome> + Send {
            self.0
                .lock()
                .expect("sent")
                .push(("resolved", draft.subject.clone()));
            std::future::ready(ChannelOutcome::Sent { message_id: None })
        }
    }

    impl FakeSink {
        fn sent(&self) -> Vec<(&'static str, String)> {
            self.0.lock().expect("sent").clone()
        }
    }

    /// A BuildFailures-shaped observation fixture — `open` answers the
    /// verdict the DO-side measurement would have produced.
    fn fixture_observation(open: bool, offenders: Vec<FaultOffender>) -> FaultObservation {
        FaultObservation {
            signal: FaultSignal::BuildFailures,
            open,
            observed: if open { 40.0 } else { 0.0 },
            threshold: BUILD_FAILURE_PERCENT,
            unit: "% failed".to_owned(),
            sample: 30.0,
            min_sample: BUILD_FAILURE_MIN_OUTCOMES,
            offenders,
        }
    }

    fn offender(label: &str, count: f64) -> FaultOffender {
        FaultOffender {
            label: label.to_owned(),
            count,
            url: None,
        }
    }

    #[test]
    fn route_family_buckets_the_named_paths() {
        assert_eq!(
            route_family("/api/v1/admin/artifacts/register"),
            "build-callbacks"
        );
        assert_eq!(
            route_family("/api/v1/scheduler/complete"),
            "build-callbacks"
        );
        assert_eq!(route_family("/api/v1/scheduler/status"), "scheduler");
        assert_eq!(route_family("/api/v1/admin/status"), "admin");
        assert_eq!(route_family("/api/v1/enqueue"), "public");
        assert_eq!(route_family("/"), "public");
    }

    #[tokio::test]
    async fn open_resolve_and_digest_send_one_alert_each() {
        let store = FakeStore::new();
        let sink = FakeSink(Mutex::new(Vec::new()));
        let open = fixture_observation(true, vec![offender("register: POST -> 500", 16.0)]);
        let closed = fixture_observation(false, vec![]);

        // Tick 1: opens — one alert.
        let report = apply_fault_transitions(
            &store,
            &sink,
            vec![open.clone()],
            "2026-09-28T00:10:00Z",
            "2026-09-27T23:10:00Z",
        )
        .await
        .expect("transitions");
        assert_eq!(report.opened, vec![FaultSignal::BuildFailures]);
        assert_eq!(
            sink.sent(),
            [("opened", "stow fault opened: build failures".to_owned())]
        );

        // Tick 2: still open, digest interval not elapsed — silence.
        let report = apply_fault_transitions(
            &store,
            &sink,
            vec![open.clone()],
            "2026-09-28T00:20:00Z",
            "2026-09-27T23:40:00Z",
        )
        .await
        .expect("transitions");
        assert!(report.opened.is_empty() && !report.digested);
        assert_eq!(sink.sent().len(), 1);

        // Tick 3: digest interval elapsed — one digest alert.
        let report = apply_fault_transitions(
            &store,
            &sink,
            vec![open.clone()],
            "2026-09-28T01:20:00Z",
            "2026-09-28T00:15:00Z",
        )
        .await
        .expect("transitions");
        assert!(report.digested);
        assert_eq!(sink.sent().len(), 2);
        assert_eq!(
            sink.sent()[1],
            (
                "updated",
                "stow fault digest: build failures still open".to_owned()
            )
        );

        // Tick 4: resolved — one alert, and the digest deadline is gone.
        let report = apply_fault_transitions(
            &store,
            &sink,
            vec![closed.clone()],
            "2026-09-28T01:30:00Z",
            "2026-09-28T00:25:00Z",
        )
        .await
        .expect("transitions");
        assert_eq!(report.resolved, vec![FaultSignal::BuildFailures]);
        assert_eq!(sink.sent().len(), 3);
        assert_eq!(
            sink.sent()[2],
            ("resolved", "stow fault resolved: build failures".to_owned())
        );

        // Tick 5: quiet — nothing more.
        let report = apply_fault_transitions(
            &store,
            &sink,
            vec![closed],
            "2026-09-28T01:40:00Z",
            "2026-09-28T00:35:00Z",
        )
        .await
        .expect("transitions");
        assert!(report.opened.is_empty() && report.resolved.is_empty() && !report.digested);
        assert_eq!(sink.sent().len(), 3);
    }

    #[test]
    fn fault_mail_names_signal_window_observed_threshold_and_offenders() {
        let mut obs = fixture_observation(true, vec![offender("register: POST -> 500", 16.0)]);
        obs.offenders.push(FaultOffender {
            label: "serde 1.0.228 (a1b2c3d4e5f6)".to_owned(),
            count: 6.0,
            url: Some("https://github.com/water-rs/stow/actions/runs/777".to_owned()),
        });
        let state = SignalState {
            opened_at: "2026-09-28T00:10:00Z".to_owned(),
            last_digest_at: "2026-09-28T00:10:00Z".to_owned(),
            observation: obs,
        };
        let draft = render_fault_mail(MailKind::Opened, &state).expect("render");
        assert_eq!(draft.subject, "stow fault opened: build failures");
        assert_eq!(draft.key, "fault-build-failures");
        let (text, html) = (draft.body, draft.html);
        for needle in [
            "build failures",
            "40 % failed",
            "threshold 20",
            "register: POST -> 500",
            "actions/runs/777",
        ] {
            assert!(
                text.contains(needle) || html.contains(needle),
                "mail missing `{needle}`:\n{text}\n{html}"
            );
        }
    }

    #[test]
    fn every_signal_subject_names_it() {
        for signal in [
            FaultSignal::ErrorRate,
            FaultSignal::ResourceFailures,
            FaultSignal::BuildFailures,
            FaultSignal::QueueHealth,
            FaultSignal::UsageWarn,
            FaultSignal::UsageHigh,
        ] {
            assert!(mail_subject(MailKind::Opened, signal).contains(signal.title()));
        }
    }

    #[test]
    fn constants_match_the_motivating_incident() {
        // The incident shape: 16 register-500s among 30 recent failures —
        // under these defaults that wave opens BuildFailures (30 >= 10
        // sample, 53% > 20%) in one tick.
        assert_eq!(FAULT_WINDOW_MINUTES, 10);
        const {
            assert!(BUILD_FAILURE_MIN_OUTCOMES >= 5.0);
            assert!(BUILD_FAILURE_PERCENT < 53.0);
        }
    }
}
