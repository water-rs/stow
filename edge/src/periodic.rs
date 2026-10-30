//! The Worker's scheduled handler core (stow#1100): the Cloudflare Cron
//! Trigger fires an event carrying the cron expression that fired, the
//! deployed [`PeriodicSchedule`] names the workflows due on it, and each
//! is dispatched on `main` through the scheduler Durable Object (which
//! holds the GitHub App token cache). The handler creates, alters and
//! backfills nothing; its cost is one Durable Object request and one
//! outbound `workflow_dispatch` per due workflow, independent of stored
//! data.
//!
//! A failed dispatch is logged, mailed through the `send_email` alert
//! channel the freeze alerts use, and returned as the invocation's
//! error so it shows as failed in Workers Logs. The `incident` issue is
//! the watchdog's to keep: the edge's App token has no `issues` grant by
//! design.

use std::future::Future;

use askama::Template;
use futures_util::StreamExt as _;
use stow_types::periodic::{PeriodicSchedule, WorkflowFile};

use crate::freeze::{AlertDraft, AlertSink, summarize_channel};

/// How many due workflows one tick dispatches at once. A cron names a
/// handful of workflows, so the bound only has to stay far under
/// Workers' six simultaneous outbound connections.
pub const DISPATCH_CONCURRENCY: usize = 4;

/// The incident key the alert carries.
pub const PERIODIC_INCIDENT_KEY: &str = "periodic-dispatch";

/// Where a due workflow is dispatched.
pub trait Dispatcher: Sync {
    /// Dispatch `workflow` on the trusted builder's branch (`main`).
    fn dispatch(&self, workflow: &WorkflowFile) -> impl Future<Output = Result<(), String>> + Send;
}

/// One workflow that was not dispatched, or the tick itself when
/// `workflow` is `-`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// The workflow file, or `-` for a tick that named none.
    pub workflow: String,
    /// Why it was not dispatched.
    pub error: String,
}

/// A tick that left at least one workflow undispatched.
#[derive(Debug, thiserror::Error)]
#[error("periodic dispatch failed on cron {cron:?}: {}", .failures.iter().map(|failure| format!("{}: {}", failure.workflow, failure.error)).collect::<Vec<_>>().join("; "))]
pub struct TickFailed {
    /// The cron expression that fired.
    pub cron: String,
    /// Every failure of the tick.
    pub failures: Vec<Failure>,
}

#[derive(Template)]
#[template(path = "periodic_alert.txt")]
struct PeriodicAlertTemplate<'a> {
    cron: &'a str,
    failures: &'a [Failure],
}

#[derive(Template)]
#[template(path = "periodic_alert.html")]
struct PeriodicAlertHtmlTemplate<'a> {
    cron: &'a str,
    failures: &'a [Failure],
}

fn render_alert(cron: &str, failures: &[Failure]) -> Result<AlertDraft, askama::Error> {
    let workflows = failures
        .iter()
        .map(|failure| failure.workflow.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    Ok(AlertDraft {
        key: PERIODIC_INCIDENT_KEY,
        subject: format!("[stow] periodic dispatch failed: {workflows}"),
        body: PeriodicAlertTemplate { cron, failures }.render()?,
        html: PeriodicAlertHtmlTemplate { cron, failures }.render()?,
    })
}

/// Run one scheduled tick: dispatch exactly the workflows due on `cron`,
/// at most [`DISPATCH_CONCURRENCY`] at a time, and mail a failure.
///
/// # Errors
///
/// [`TickFailed`] when `cron` names no workflow or any dispatch failed.
pub async fn run_tick<D: Dispatcher, S: AlertSink + Sync>(
    schedule: &PeriodicSchedule,
    cron: &str,
    dispatcher: &D,
    sink: &S,
) -> Result<(), TickFailed> {
    let failures = match schedule.due(cron) {
        Ok(due) => {
            futures_util::stream::iter(due)
                .map(|workflow| async move {
                    dispatcher
                        .dispatch(workflow)
                        .await
                        .err()
                        .map(|error| Failure {
                            workflow: workflow.as_str().to_owned(),
                            error,
                        })
                })
                .buffer_unordered(DISPATCH_CONCURRENCY)
                .filter_map(std::future::ready)
                .collect::<Vec<_>>()
                .await
        }
        Err(error) => vec![Failure {
            workflow: "-".to_owned(),
            error: error.to_string(),
        }],
    };
    if failures.is_empty() {
        return Ok(());
    }
    for failure in &failures {
        tracing::error!(cron, workflow = %failure.workflow, error = %failure.error, "periodic dispatch failed");
    }
    match render_alert(cron, &failures) {
        Ok(draft) => {
            let outcome = sink.opened(&draft).await;
            tracing::error!(notify = %summarize_channel(&outcome), "periodic dispatch alert");
        }
        Err(error) => tracing::error!(%error, "render periodic dispatch alert"),
    }
    Err(TickFailed {
        cron: cron.to_owned(),
        failures,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use stow_types::api::ChannelOutcome;

    use super::*;

    const SCHEDULE: &str =
        r#"{"*/15 * * * *":["watchdog.yml"],"17 0 * * *":["preheat-cron.yml","other.yml"]}"#;

    /// Records dispatch order and in-flight overlap; fails the named
    /// workflows.
    struct Recorder {
        failing: &'static [&'static str],
        started: Mutex<Vec<String>>,
        in_flight: Mutex<(usize, usize)>,
    }

    impl Recorder {
        fn new(failing: &'static [&'static str]) -> Self {
            Self {
                failing,
                started: Mutex::new(Vec::new()),
                in_flight: Mutex::new((0, 0)),
            }
        }
    }

    /// Yields once so a sequential driver and a concurrent one differ.
    struct YieldOnce(bool);

    impl Future for YieldOnce {
        type Output = ();
        fn poll(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            if self.0 {
                return std::task::Poll::Ready(());
            }
            self.0 = true;
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    }

    impl Dispatcher for Recorder {
        fn dispatch(
            &self,
            workflow: &WorkflowFile,
        ) -> impl Future<Output = Result<(), String>> + Send {
            self.record(workflow)
        }
    }

    impl Recorder {
        async fn record(&self, workflow: &WorkflowFile) -> Result<(), String> {
            self.started
                .lock()
                .unwrap()
                .push(workflow.as_str().to_owned());
            {
                let mut gauge = self.in_flight.lock().unwrap();
                gauge.0 += 1;
                gauge.1 = gauge.1.max(gauge.0);
            }
            YieldOnce(false).await;
            self.in_flight.lock().unwrap().0 -= 1;
            if self.failing.contains(&workflow.as_str()) {
                Err("HTTP 422".to_owned())
            } else {
                Ok(())
            }
        }
    }

    struct Mailbox(Mutex<Vec<AlertDraft>>);

    impl AlertSink for Mailbox {
        fn opened(&self, draft: &AlertDraft) -> impl Future<Output = ChannelOutcome> + Send {
            self.0.lock().unwrap().push(draft.clone());
            std::future::ready(ChannelOutcome::Sent { message_id: None })
        }
        fn updated(&self, draft: &AlertDraft) -> impl Future<Output = ChannelOutcome> + Send {
            self.opened(draft)
        }
        fn resolved(&self, draft: &AlertDraft) -> impl Future<Output = ChannelOutcome> + Send {
            self.opened(draft)
        }
    }

    fn schedule() -> PeriodicSchedule {
        SCHEDULE.parse().expect("schedule")
    }

    #[tokio::test]
    async fn a_tick_dispatches_exactly_the_workflows_due_concurrently() {
        let recorder = Recorder::new(&[]);
        let mailbox = Mailbox(Mutex::new(Vec::new()));
        run_tick(&schedule(), "17 0 * * *", &recorder, &mailbox)
            .await
            .expect("tick");
        let mut started = recorder.started.lock().unwrap().clone();
        started.sort();
        assert_eq!(started, ["other.yml", "preheat-cron.yml"]);
        assert_eq!(
            recorder.in_flight.lock().unwrap().1,
            2,
            "dispatches overlap"
        );
        assert!(
            mailbox.0.lock().unwrap().is_empty(),
            "a clean tick mails nothing"
        );

        let recorder = Recorder::new(&[]);
        run_tick(&schedule(), "*/15 * * * *", &recorder, &mailbox)
            .await
            .expect("tick");
        assert_eq!(*recorder.started.lock().unwrap(), ["watchdog.yml"]);
    }

    #[tokio::test]
    async fn a_failed_dispatch_is_mailed_and_fails_the_tick() {
        let recorder = Recorder::new(&["other.yml"]);
        let mailbox = Mailbox(Mutex::new(Vec::new()));
        let error = run_tick(&schedule(), "17 0 * * *", &recorder, &mailbox)
            .await
            .expect_err("one dispatch failed");
        assert_eq!(
            error.failures,
            [Failure {
                workflow: "other.yml".to_owned(),
                error: "HTTP 422".to_owned()
            }]
        );
        // The healthy workflow still went out.
        assert!(
            recorder
                .started
                .lock()
                .unwrap()
                .contains(&"preheat-cron.yml".to_owned())
        );
        let sent = mailbox.0.lock().unwrap().clone();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].subject,
            "[stow] periodic dispatch failed: other.yml"
        );
        assert!(sent[0].body.contains("other.yml: HTTP 422"));
        assert!(sent[0].html.contains("17 0 * * *"));
    }

    #[tokio::test]
    async fn an_unnamed_cron_dispatches_nothing_and_is_mailed() {
        let recorder = Recorder::new(&[]);
        let mailbox = Mailbox(Mutex::new(Vec::new()));
        let error = run_tick(&schedule(), "0 0 * * *", &recorder, &mailbox)
            .await
            .expect_err("unknown cron");
        assert!(recorder.started.lock().unwrap().is_empty());
        assert_eq!(error.failures[0].workflow, "-");
        assert_eq!(mailbox.0.lock().unwrap().len(), 1);
    }
}
