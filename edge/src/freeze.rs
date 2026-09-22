//! The dispatch freeze: the scheduler's "this is going badly" circuit
//! breaker.
//!
//! Where [`crate::panic`] sheds anonymous edge traffic to protect the
//! worker, the freeze gates `dispatch_pending` inside the scheduler
//! Durable Object so a systematic CI breakage cannot keep burning the
//! org's Actions allowance. Enqueues are never gated — misses arriving
//! during a freeze are exactly the work that should dispatch first once
//! it lifts, so the freeze is worth nothing if it blinds the queue.
//!
//! The trip condition never fires on a bare count or a bare ratio: a
//! stream must reach the minimum sample inside the window *and* cross
//! the failure ratio over that sample. Two failures out of two builds
//! is not a signal, and a fleet that rarely builds cannot accumulate
//! the sample — both are silent by design. The condition is evaluated
//! over two kinds of streams: the fleet-wide aggregate (a slow,
//! widely-dispersed breakage still burns the shared runner allowance)
//! and each individual target (a linker/SDK breakage is almost always
//! concentrated on one family, where per-target sampling catches it
//! without being diluted by healthy legs).
//!
//! Recovery is manual only: an automatic unfreeze would burn another
//! wave against the same broken `main` and turn the alert into hourly
//! noise. One email goes out per state transition — freeze and clear —
//! through the `send_email` binding; a send that fails is recorded on
//! the freeze record rather than retried, so a silent alert is visible
//! to whoever eventually reads `stow-admin freeze status`.
//!
//! Everything here is platform-free: the trip decision, the alert-body
//! rendering, and the notify-outcome interpretation are unit-testable
//! on the host without a Worker. The wasm glue lives in
//! `scheduler/object.rs` (gate + evaluation points) and `email.rs`
//! (the `send_email` binding call).

use askama::Template;
use stow_types::api::{
    DispatchFreezeNotify, DispatchFreezeTarget, DispatchFreezeTrigger, DispatchFreezeTrip,
};
use stow_types::identity::TargetTriple;

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
        example_run_url: Option<String>,
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
            example_run_url,
        })
    }
}

/// Subject per transition — one email per state change, so the
/// subject line alone says which change arrived.
#[must_use]
pub const fn freeze_subject(trigger: &DispatchFreezeTrigger) -> &'static str {
    match trigger {
        DispatchFreezeTrigger::Manual => "[stow] dispatch frozen — manual",
        DispatchFreezeTrigger::Tripped(_) => "[stow] dispatch frozen — systematic failures",
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

/// Build the recorded notify outcome for a send the binding accepted.
#[must_use]
pub const fn notify_sent(message_id: Option<String>) -> DispatchFreezeNotify {
    DispatchFreezeNotify::Sent { message_id }
}

/// Build the recorded notify outcome for a rejected send, attaching the
/// known-code hint when there is one.
#[must_use]
pub fn notify_failed(code: Option<String>, message: String) -> DispatchFreezeNotify {
    let hint = code.as_deref().and_then(notify_hint);
    DispatchFreezeNotify::Failed {
        code,
        message,
        hint,
    }
}

/// Build the recorded notify outcome when no send was attempted.
#[must_use]
pub const fn notify_disabled(reason: String) -> DispatchFreezeNotify {
    DispatchFreezeNotify::Disabled { reason }
}

/// One-line summary of a stored notify outcome, for the cleared alert
/// and for `stow-admin freeze status`.
#[must_use]
pub fn summarize_notify(notify: &DispatchFreezeNotify) -> String {
    match notify {
        DispatchFreezeNotify::Sent { message_id } => message_id
            .as_ref()
            .map_or_else(|| "sent".to_owned(), |id| format!("sent (messageId {id})")),
        DispatchFreezeNotify::Failed {
            code,
            message,
            hint,
        } => {
            let code = code.as_deref().unwrap_or("E_UNKNOWN");
            hint.as_ref().map_or_else(
                || format!("FAILED {code}: {message}"),
                |hint| format!("FAILED {code}: {message} — {hint}"),
            )
        }
        DispatchFreezeNotify::Disabled { reason } => format!("disabled: {reason}"),
    }
}

/// One-line summary of a stored trigger, for the cleared alert and
/// `stow-admin freeze status`.
#[must_use]
pub fn summarize_trigger(trigger: &DispatchFreezeTrigger) -> String {
    match trigger {
        DispatchFreezeTrigger::Manual => "manual (stow-admin freeze on)".to_owned(),
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
                "tripped: {}/{} outcomes failed ({}%) over {}m — {}",
                trip.failures, trip.outcomes, trip.failure_percent, trip.window_minutes, streams
            )
        }
    }
}

struct TripContext<'a> {
    window_minutes: u32,
    min_outcomes: u32,
    fail_percent: u32,
    outcomes: u32,
    failures: u32,
    failure_percent: u32,
    fleet_tripped: bool,
    targets: &'a [stow_types::api::DispatchFreezeTarget],
    example_run_url: &'a Option<String>,
}

/// Askama context for `templates/freeze_alert.txt`.
#[derive(Template)]
#[template(path = "freeze_alert.txt")]
struct FreezeAlertTemplate<'a> {
    frozen_at: &'a str,
    manual: bool,
    trip: Option<TripContext<'a>>,
    to: &'a str,
    from: &'a str,
}

/// Render the freeze-transition alert body. Never fails on data grounds
/// (a stored record is already validated); the `askama` error return
/// exists so the caller's `expect` names the template.
pub fn render_freeze_alert(
    frozen_at: &str,
    trigger: &DispatchFreezeTrigger,
    to: &str,
    from: &str,
) -> Result<String, askama::Error> {
    let (manual, trip) = match trigger {
        DispatchFreezeTrigger::Manual => (true, None),
        DispatchFreezeTrigger::Tripped(trip) => (
            false,
            Some(TripContext {
                window_minutes: trip.window_minutes,
                min_outcomes: trip.min_outcomes,
                fail_percent: trip.fail_percent,
                outcomes: trip.outcomes,
                failures: trip.failures,
                failure_percent: trip.failure_percent,
                fleet_tripped: trip.fleet_tripped,
                targets: &trip.targets,
                example_run_url: &trip.example_run_url,
            }),
        ),
    };
    FreezeAlertTemplate {
        frozen_at,
        manual,
        trip,
        to,
        from,
    }
    .render()
}

/// Askama context for `templates/freeze_cleared.txt`.
#[derive(Template)]
#[template(path = "freeze_cleared.txt")]
struct FreezeClearedTemplate<'a> {
    frozen_at: &'a str,
    cleared_at: &'a str,
    trigger_summary: &'a str,
    notify_summary: &'a str,
    to: &'a str,
    from: &'a str,
}

/// Render the cleared-transition alert body, summarizing the record the
/// freeze held while it was engaged.
pub fn render_freeze_cleared(
    frozen_at: &str,
    cleared_at: &str,
    trigger: &DispatchFreezeTrigger,
    notify: &DispatchFreezeNotify,
    to: &str,
    from: &str,
) -> Result<String, askama::Error> {
    let trigger_summary = summarize_trigger(trigger);
    let notify_summary = summarize_notify(notify);
    FreezeClearedTemplate {
        frozen_at,
        cleared_at,
        trigger_summary: &trigger_summary,
        notify_summary: &notify_summary,
        to,
        from,
    }
    .render()
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_FREEZE_FAIL_PERCENT, DEFAULT_FREEZE_MIN_OUTCOMES, DEFAULT_FREEZE_WINDOW_MINUTES,
        FreezeSettings, OutcomeTally, evaluate, notify_failed, notify_hint, observed_percent,
        render_freeze_alert, render_freeze_cleared, summarize_notify,
    };
    use stow_types::api::{
        DispatchFreezeNotify, DispatchFreezeTarget, DispatchFreezeTrigger, DispatchFreezeTrip,
    };
    use stow_types::identity::TargetTriple;

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
        let settings = FreezeSettings {
            min_outcomes: 0,
            ..settings()
        };
        assert!(evaluate(&[], &settings).is_none());
        assert!(evaluate(&[tally("t-a", 0, 0)], &settings).is_none());
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
        let DispatchFreezeNotify::Failed { hint, .. } = &notify else {
            panic!("expected a failed outcome");
        };
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
            example_run_url: Some(
                "https://github.com/water-rs/stow/actions/runs/123456".to_owned(),
            ),
        }
    }

    #[test]
    fn freeze_alert_names_counts_window_ratio_targets_and_a_run() {
        let body = render_freeze_alert(
            "2026-09-22T03:51:00Z",
            &DispatchFreezeTrigger::Tripped(trip()),
            "me@lexo.cool",
            "alerts@stow.waterui.dev",
        )
        .expect("template renders");
        for needle in [
            "480",
            "512",
            "93%",
            "60m",
            "x86_64-pc-windows-msvc",
            "aarch64-pc-windows-msvc",
            "https://github.com/water-rs/stow/actions/runs/123456",
            "stow-admin freeze off --yes",
        ] {
            assert!(
                body.contains(needle),
                "alert body is missing `{needle}`:\n{body}"
            );
        }
    }

    #[test]
    fn manual_freeze_alert_renders_without_trip_stats() {
        let body = render_freeze_alert(
            "2026-09-22T03:51:00Z",
            &DispatchFreezeTrigger::Manual,
            "me@lexo.cool",
            "alerts@stow.waterui.dev",
        )
        .expect("template renders");
        assert!(body.contains("manual"));
        assert!(body.contains("stow-admin freeze off --yes"));
    }

    #[test]
    fn cleared_alert_replays_what_the_freeze_record_held() {
        let body = render_freeze_cleared(
            "2026-09-22T03:51:00Z",
            "2026-09-22T05:10:00Z",
            &DispatchFreezeTrigger::Tripped(trip()),
            &DispatchFreezeNotify::Failed {
                code: Some("E_RECIPIENT_NOT_ALLOWED".to_owned()),
                message: "recipient not allowed".to_owned(),
                hint: Some("check the allowlist".to_owned()),
            },
            "me@lexo.cool",
            "alerts@stow.waterui.dev",
        )
        .expect("template renders");
        assert!(body.contains("2026-09-22T03:51:00Z"));
        assert!(body.contains("2026-09-22T05:10:00Z"));
        assert!(body.contains("480/512"));
        assert!(body.contains("E_RECIPIENT_NOT_ALLOWED"));
        assert!(body.contains("check the allowlist"));
    }

    #[test]
    fn notify_summary_marks_a_failed_send_loudly() {
        let failed = DispatchFreezeNotify::Failed {
            code: Some("E_DAILY_LIMIT_EXCEEDED".to_owned()),
            message: "quota".to_owned(),
            hint: None,
        };
        assert!(summarize_notify(&failed).contains("FAILED E_DAILY_LIMIT_EXCEEDED"));
        let sent = DispatchFreezeNotify::Sent {
            message_id: Some("abc".to_owned()),
        };
        assert!(summarize_notify(&sent).contains("abc"));
        let disabled = DispatchFreezeNotify::Disabled {
            reason: "no binding".to_owned(),
        };
        assert!(summarize_notify(&disabled).contains("disabled"));
    }
}
