//! `stow-admin status --watch`'s live-queue model — the fleet's
//! state and the frame it renders (stow#853).
//!
//! The model is pure: the watch's I/O drives `apply_listing` with the
//! two listings a tick reads, `apply_jobs` with each in-flight run's
//! jobs page and `retire` with a completed run's final row and page,
//! and renders what `frame` yields. Nothing here fetches.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;

use futures_util::StreamExt;
use stow_types::api::{BatchId, SchedulerStatus};
use stow_types::records::parse_batch_run_title;
use stow_types::runs::{LegFailure, RunFailure, RunJobRow, RunJobsPage};
use stow_types::stow_error;
use stow_types::transient::Backoff;
use stow_types::trusted_builder::{BATCH_WORKFLOW_FILE, BATCH_WORKFLOW_NAME};
use time::OffsetDateTime;

use crate::Edge;
use crate::github::{self, ConditionalPages, RunsPage, WorkflowRunRow};
use crate::render::Screen;
use crate::runs::{self, FailureClass, LegProgress, LiveLeg};

/// The session's in-memory fleet — every in-flight batch run, every
/// `(run, leg)`'s latest live state, the session's failures and the
/// log classes it classified.
pub struct Fleet {
    /// Watch start — `frame`'s `since`.
    since: OffsetDateTime,
    /// In-flight runs, keyed by run id.
    runs: BTreeMap<u64, RunTrack>,
    /// `(run_id, leg)` → the latest `LiveLeg` — a rerun's page
    /// overwrites the same key, so a leg that failed attempt 1 and
    /// succeeded on attempt 2 counts once (§2.1).
    legs: BTreeMap<(u64, u32), LiveLeg>,
    /// Completed runs frozen this session — run id to the attempt it
    /// completed at. A reappearance with a later `run_attempt` is a
    /// rerun and re-enters; one at the same attempt is a stale
    /// listing row and stays frozen.
    finished: BTreeMap<u64, u64>,
    /// `(run_id, leg)` → the leg's failure track — present exactly
    /// while the leg's latest outcome is `Failed`.
    failures: BTreeMap<(u64, u32), FailureTrack>,
    /// The next failure's discovery order — the frame lists failures
    /// newest first.
    next_failure_seq: u64,
    /// The session's log classes per failed job id — the memo the
    /// `actions/jobs/{id}/logs` reads fill once each (§2.3).
    log_class: HashMap<u64, FailureClass>,
}

/// One in-flight run's display state — the row's own fields and the
/// title parsed once.
#[derive(Debug)]
struct RunTrack {
    /// The parsed title's rustc — `1.99.0`.
    rustc: String,
    /// The parsed title's batch id.
    batch_id: BatchId,
    /// `actor.login` — the account the run dispatched under.
    actor: String,
    /// The listing status — `queued` or `in_progress`.
    status: String,
    /// The attempt the listing row reported.
    run_attempt: u64,
    /// The run's Actions URL.
    url: String,
    /// `created_at` — a `RunView`'s `age_seconds` is `now` minus it.
    created_at: OffsetDateTime,
}

/// What a failed leg's `FailureView` needs and the `LiveLeg` does not
/// carry — captured at `apply_jobs` while the jobs page is in hand.
#[derive(Debug)]
struct FailureTrack {
    /// Discovery order — failures list newest first.
    seq: u64,
    /// The failed job's id — the `log_class` memo's key; `None` for
    /// an invariant failure, which has no log.
    job_id: Option<u64>,
    /// The failed job's Actions URL.
    job_url: Option<String>,
}

impl Fleet {
    /// An empty fleet — `since` is the watch's start.
    pub fn new(since: OffsetDateTime) -> Self {
        Self {
            since,
            runs: BTreeMap::new(),
            legs: BTreeMap::new(),
            finished: BTreeMap::new(),
            failures: BTreeMap::new(),
            next_failure_seq: 0,
            log_class: HashMap::new(),
        }
    }

    /// Record one failed job's classified log — keyed by job id, so a
    /// run read across ticks never fetches the same log twice.
    pub fn record_log_class(&mut self, job_id: u64, class: FailureClass) {
        self.log_class.insert(job_id, class);
    }

    /// Fold one tick's listings — the union of the `queued` and
    /// `in_progress` workflow-run pages. Returns the run ids that
    /// left the in-flight set: the caller re-reads each one's row and
    /// final attempt page and hands both to [`Fleet::retire`].
    ///
    /// A `finished` run reappearing with a later `run_attempt` is a
    /// rerun — it un-freezes and tracks again (§2.1).
    ///
    /// # Errors
    /// A batch-workflow row whose title is neither
    /// `BATCH_WORKFLOW_NAME` nor a parsable `<rustc>-b<batch_id>` — a
    /// schema surprise, never ignored.
    pub fn apply_listing(
        &mut self,
        rows: impl IntoIterator<Item = WorkflowRunRow>,
    ) -> stow_types::error::Result<Vec<u64>> {
        let mut present = BTreeSet::new();
        for row in rows {
            if let Some(&attempt) = self.finished.get(&row.id) {
                if row.run_attempt <= attempt {
                    // A stale listing row of a frozen run.
                    continue;
                }
                self.finished.remove(&row.id);
            }
            let Some((rustc, batch_id)) = row_batch(&row)? else {
                continue;
            };
            present.insert(row.id);
            self.runs.insert(
                row.id,
                RunTrack {
                    rustc,
                    batch_id,
                    actor: row.actor.login,
                    status: row.status,
                    run_attempt: row.run_attempt,
                    url: row.html_url,
                    created_at: row.created_at,
                },
            );
        }
        let dropped: Vec<u64> = self
            .runs
            .keys()
            .copied()
            .filter(|id| !present.contains(id))
            .collect();
        for id in &dropped {
            self.runs.remove(id);
        }
        Ok(dropped)
    }

    /// Fold one run's jobs page — `live_legs` under `run_conclusion`
    /// (`""` while the run flies; only a completed run's own
    /// conclusion settles its legs). Each present leg's latest
    /// `LiveLeg` overwrites its `(run, leg)` entry and its failure
    /// track; legs absent from the page keep their last outcome.
    ///
    /// # Errors
    /// `live_legs`'s — a non-leg job, an unrendered name outside a
    /// skipped job, or an unsettled leg in a shape the live table
    /// does not name.
    pub fn apply_jobs(
        &mut self,
        run_id: u64,
        run_conclusion: &str,
        jobs: &[RunJobRow],
        now: OffsetDateTime,
    ) -> stow_types::error::Result<()> {
        for leg in runs::live_legs(jobs, run_conclusion, now)? {
            match &leg.progress {
                LegProgress::Failed(failure) => {
                    let log_job = runs::leg_log_job(failure, jobs);
                    // A failure keeps the place it took when first seen:
                    // re-reading the same page every tick must not
                    // reorder the newest-first list.
                    let seq = if let Some(track) = self.failures.get(&(run_id, leg.leg)) {
                        track.seq
                    } else {
                        self.next_failure_seq += 1;
                        self.next_failure_seq
                    };
                    self.failures.insert(
                        (run_id, leg.leg),
                        FailureTrack {
                            seq,
                            job_id: log_job.map(|row| row.id),
                            job_url: log_job.map(|row| row.html_url.clone()),
                        },
                    );
                }
                _ => {
                    self.failures.remove(&(run_id, leg.leg));
                }
            }
            self.legs.insert((run_id, leg.leg), leg);
        }
        Ok(())
    }

    /// Freeze a run that left the listings, given the row the
    /// `actions/runs/{id}` re-read returned and its final attempt's
    /// jobs page. A `completed` run folds its settled legs once and
    /// is never read again; a row still reading `queued`/
    /// `in_progress` is the run having left the two listings
    /// mid-transition — the row is the truth, so it tracks again.
    ///
    /// # Errors
    /// `apply_jobs`'s, and [`row_batch`]'s title rule on the
    /// re-tracked path.
    pub fn retire(
        &mut self,
        row: &WorkflowRunRow,
        jobs: &[RunJobRow],
        now: OffsetDateTime,
    ) -> stow_types::error::Result<()> {
        if row.status == "completed" {
            self.apply_jobs(row.id, row.conclusion.as_deref().unwrap_or(""), jobs, now)?;
            self.finished.insert(row.id, row.run_attempt);
            return Ok(());
        }
        if let Some((rustc, batch_id)) = row_batch(row)? {
            self.runs.insert(
                row.id,
                RunTrack {
                    rustc,
                    batch_id,
                    actor: row.actor.login.clone(),
                    status: row.status.clone(),
                    run_attempt: row.run_attempt,
                    url: row.html_url.clone(),
                    created_at: row.created_at,
                },
            );
        }
        Ok(())
    }

    /// `(run_id, run_attempt)` of each run the listing reports
    /// `in_progress` — the jobs reads the next tick owes. A `queued`
    /// run has no jobs and is not read (§2.2).
    pub fn in_progress(&self) -> Vec<(u64, u64)> {
        self.runs
            .iter()
            .filter(|(_, track)| track.status == "in_progress")
            .map(|(&run_id, track)| (run_id, track.run_attempt))
            .collect()
    }

    /// The failed jobs whose log class is still unset — the reads the
    /// next tick owes, bounded by failures, not by ticks (§2.3).
    pub fn unclassified_jobs(&self) -> Vec<u64> {
        self.failures
            .values()
            .filter_map(|track| track.job_id)
            .filter(|job_id| !self.log_class.contains_key(job_id))
            .collect()
    }

    /// One render's worth of state — the scheduler counts the caller
    /// already read, the in-flight runs with their leg buckets, the
    /// per-target roll-up and the session's failures newest first.
    pub fn frame(&self, now: OffsetDateTime, scheduler: &SchedulerStatus) -> WatchFrame {
        let mut runs: Vec<RunView> = self
            .runs
            .iter()
            .map(|(&run_id, track)| RunView {
                run_id,
                batch_id: track.batch_id.clone(),
                rustc: track.rustc.clone(),
                actor: track.actor.clone(),
                status: track.status.clone(),
                run_attempt: track.run_attempt,
                age_seconds: (now - track.created_at).whole_seconds().max(0),
                url: track.url.clone(),
                legs: self.leg_counts(run_id),
            })
            .collect();
        runs.sort_by(|a, b| {
            rank(a)
                .cmp(&rank(b))
                .then(b.age_seconds.cmp(&a.age_seconds))
        });

        let mut targets: BTreeMap<String, LegCounts> = BTreeMap::new();
        for leg in self.legs.values() {
            let Some(label) = &leg.label else {
                // An all-unrendered leg lands in no target bucket —
                // it still counts toward its run.
                continue;
            };
            targets
                .entry(label.target.clone())
                .or_default()
                .count(&leg.progress);
        }

        let mut failures: Vec<((u64, u32), &FailureTrack)> = self
            .failures
            .iter()
            .map(|(&key, track)| (key, track))
            .collect();
        failures.sort_by_key(|(_, track)| std::cmp::Reverse(track.seq));
        let failures = failures
            .into_iter()
            .map(|(key, track)| {
                let leg = &self.legs[&key];
                let LegProgress::Failed(failure) = &leg.progress else {
                    unreachable!("a failure track keys a leg whose latest outcome is Failed")
                };
                FailureView {
                    target: leg.label.as_ref().map(|label| label.target.clone()),
                    crate_name: leg.label.as_ref().map(|label| label.crate_name.clone()),
                    version: leg.label.as_ref().map(|label| label.version.clone()),
                    coarse_class: coarse_class(failure),
                    log_class: track
                        .job_id
                        .and_then(|job_id| self.log_class.get(&job_id).copied()),
                    job_url: track.job_url.clone(),
                }
            })
            .collect();

        WatchFrame {
            at: now,
            since: self.since,
            scheduler: SchedulerView {
                pending_miss: scheduler.pending.saturating_sub(scheduler.human_pending),
                pending_human: scheduler.human_pending,
                blocked: scheduler.blocked,
                dispatched: scheduler.dispatched,
                running: scheduler.running,
            },
            runs,
            targets: targets
                .into_iter()
                .map(|(target, legs)| TargetView { target, legs })
                .collect(),
            failures,
        }
    }

    /// One run's legs in the §2.3 buckets.
    fn leg_counts(&self, run_id: u64) -> LegCounts {
        let mut counts = LegCounts::default();
        for ((_, _), leg) in self.legs.range((run_id, 0)..=(run_id, u32::MAX)) {
            counts.count(&leg.progress);
        }
        counts
    }
}

/// A listing row's `(rustc, batch_id)` — `parse_batch_run_title`
/// under `manual::bound_run_state`'s rule (§2.4): a title still
/// reading `BATCH_WORKFLOW_NAME` is `run-name` not rendered yet, and
/// anything else unparseable fails fast.
fn row_batch(row: &WorkflowRunRow) -> stow_types::error::Result<Option<(String, BatchId)>> {
    if row.display_title == BATCH_WORKFLOW_NAME {
        return Ok(None);
    }
    let Some((rustc, batch_id)) = parse_batch_run_title(&row.display_title) else {
        return Err(stow_error!(
            "batch run {} carries an unparseable title {:?}",
            row.id,
            row.display_title
        ));
    };
    Ok(Some((rustc.to_owned(), batch_id)))
}

/// `RunView` order — runs with failed legs first, then in-progress,
/// then queued; `frame` sorts oldest first inside each group (§3).
fn rank(view: &RunView) -> u8 {
    if view.legs.failed > 0 {
        0
    } else if view.status == "in_progress" {
        1
    } else {
        2
    }
}

/// The page-free failure class — `verdict:<step>` for a
/// `RunFailure::Verdict`, `infrastructure[:<step>]` for
/// `Infrastructure`, the conclusion for a `Concluded` leg and
/// `invariant` for an `Invariant` (§2.3).
fn coarse_class(failure: &LegFailure) -> String {
    match failure {
        LegFailure::Run(RunFailure::Verdict { step, .. }) => format!("verdict:{step}"),
        LegFailure::Run(RunFailure::Infrastructure { step, .. }) => step.as_ref().map_or_else(
            || "infrastructure".to_owned(),
            |step| format!("infrastructure:{step}"),
        ),
        LegFailure::Concluded { conclusion, .. } => conclusion.clone(),
        LegFailure::Invariant(_) => "invariant".to_owned(),
    }
}

/// One render of the live queue — what `--json` emits per tick and
/// the table renderer reads (§3).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WatchFrame {
    /// Render time, rfc3339.
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    /// Watch start — failures listed are this session's.
    #[serde(with = "time::serde::rfc3339")]
    pub since: OffsetDateTime,
    /// The scheduler queue's counts at this render.
    pub scheduler: SchedulerView,
    /// In-flight runs — failed legs first, then in-progress, then
    /// queued, oldest first inside each group.
    pub runs: Vec<RunView>,
    /// Per-target roll-up — the same legs as `runs`, by target.
    pub targets: Vec<TargetView>,
    /// The session's failed legs, newest first.
    pub failures: Vec<FailureView>,
}

/// The scheduler half of the header — `pending` split into
/// cache-miss and human lanes (§1).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SchedulerView {
    /// `pending` minus `human_pending` — the cache-miss lane.
    pub pending_miss: u32,
    /// The human-requested lane — a subset of `pending`.
    pub pending_human: u32,
    /// Pending tasks parked behind a terminally failed dependency.
    pub blocked: u32,
    /// Dispatches sent, not yet picked up.
    pub dispatched: u32,
    /// Runs claimed, not yet reported.
    pub running: u32,
}

/// One leg bucket — `runs` and `targets` add up over the same legs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LegCounts {
    /// Legs waiting on a runner.
    pub queued: u32,
    /// Legs building, publishing or still settling a failure.
    pub building: u32,
    /// Legs done.
    pub done: u32,
    /// Legs failed.
    pub failed: u32,
}

impl LegCounts {
    /// Fold one leg's progress into its §2.3 column — `Queued` is
    /// queued, the three still-moving progresses building, `Done`
    /// done and `Failed` failed.
    const fn count(&mut self, progress: &LegProgress) {
        match progress {
            LegProgress::Queued => self.queued += 1,
            LegProgress::Building | LegProgress::Publishing | LegProgress::Settling => {
                self.building += 1;
            }
            LegProgress::Done => self.done += 1,
            LegProgress::Failed(_) => self.failed += 1,
        }
    }
}

/// One in-flight run's frame row.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RunView {
    /// The run's id.
    pub run_id: u64,
    /// The batch the run builds.
    pub batch_id: BatchId,
    /// The rustc the batch compiles.
    pub rustc: String,
    /// `actor.login` — who dispatched.
    pub actor: String,
    /// The listing status — `queued` or `in_progress`.
    pub status: String,
    /// The attempt the listing row reported.
    pub run_attempt: u64,
    /// `now - created_at`, floored at 0 — GitHub and local clocks
    /// skew.
    pub age_seconds: i64,
    /// The run's Actions URL.
    pub url: String,
    /// The run's legs, bucketed.
    pub legs: LegCounts,
}

/// One target's roll-up — the same legs as `runs`, grouped by
/// `label.target`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TargetView {
    /// The target triple.
    pub target: String,
    /// The target's legs, bucketed — serialized flat next to
    /// `target`.
    #[serde(flatten)]
    pub legs: LegCounts,
}

/// One failed leg — the session's failures, newest first (§2.3: the
/// coarse class off the page, the log class once read).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FailureView {
    /// The leg's target — `None` on an unrendered leg (stow#839).
    pub target: Option<String>,
    /// The leg's crate — `None` on an unrendered leg.
    pub crate_name: Option<String>,
    /// The leg's version — `None` on an unrendered leg.
    pub version: Option<String>,
    /// The page-free class — `verdict:<step>`,
    /// `infrastructure[:<step>]`, the conclusion, or `invariant`.
    pub coarse_class: String,
    /// The log class once the log read landed — `None` until then.
    pub log_class: Option<FailureClass>,
    /// The failed job's Actions URL — `None` for an invariant
    /// failure, which names no job.
    pub job_url: Option<String>,
}
// ===== The watch loop (stow#853 §3) =====

/// One tick every [`TICK_INTERVAL`] — the same 30 s cadence
/// `manual::RUN_POLL_SECONDS` and the cost model hold.
const TICK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// The scheduler half of each tick — the queue's own status route.
const SCHEDULER_STATUS_PATH: &str = "/api/v1/scheduler/status";

/// The session's watch — the `Fleet` plus the conditional caches that
/// make every repeated read an `If-None-Match` (§2.4).
pub struct Watch {
    /// The model — runs, legs, failures, the log-class memo.
    fleet: Fleet,
    /// The `queued` listing's per-URL page cache.
    queued: ConditionalPages<RunsPage<WorkflowRunRow>>,
    /// The `in_progress` listing's per-URL page cache.
    in_progress: ConditionalPages<RunsPage<WorkflowRunRow>>,
    /// Each in-flight run's jobs-page cache — dropped at `retire`.
    run_pages: HashMap<u64, ConditionalPages<RunJobsPage>>,
}

impl Watch {
    /// A watch starting now — `since` anchors the frame header.
    pub fn new(since: OffsetDateTime) -> Self {
        Self {
            fleet: Fleet::new(since),
            queued: ConditionalPages::new(),
            in_progress: ConditionalPages::new(),
            run_pages: HashMap::new(),
        }
    }

    /// The loop: a `30 s` interval (first tick immediate,
    /// `MissedTickBehavior::Delay` so a slow tick slides rather than
    /// stacks) driving tick-plus-render, raced against Ctrl-C — a won
    /// signal drops the in-flight tick and exits 0 (§3). A broken
    /// stdout exits 0 too (`--json --watch | head -1`); any read
    /// error exits non-zero, naming the read.
    ///
    /// # Errors
    /// Any read's `Err` — retries exhausted, a refusal, a title or job
    /// the schema can't read — and a stdout write that is not
    /// `BrokenPipe`.
    pub async fn run<W: Write>(
        &mut self,
        edge: &Edge,
        token: &str,
        base: &str,
        screen: &mut Screen<W>,
    ) -> stow_types::error::Result<()> {
        let mut interval = tokio::time::interval(TICK_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let work = async {
                interval.tick().await;
                self.tick(edge, token, base, OffsetDateTime::now_utc())
                    .await
            };
            tokio::select! {
                result = work => {
                    let frame = result?;
                    match screen.render(&frame) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {
                            return Ok(());
                        }
                        Err(error) => {
                            return Err(stow_error!("render frame: {error}"));
                        }
                    }
                }
                signal = tokio::signal::ctrl_c() => {
                    signal.map_err(|error| stow_error!("ctrl_c handler: {error}"))?;
                    return Ok(());
                }
            }
        }
    }

    /// One tick — `join!` of the scheduler read and the GitHub
    /// refresh, then the failure logs, then the frame. Any read's
    /// `Err` exits the watch: it never renders a frame built on a
    /// failed read.
    ///
    /// # Errors
    /// The scheduler read's, any listing's, any jobs page's or final
    /// read's — the first one, as the exit's message.
    pub async fn tick(
        &mut self,
        edge: &Edge,
        token: &str,
        base: &str,
        now: OffsetDateTime,
    ) -> stow_types::error::Result<WatchFrame> {
        let (scheduler, refresh) = tokio::join!(
            edge.get_json_retried::<SchedulerStatus>(SCHEDULER_STATUS_PATH, Backoff::new()),
            self.github_refresh(token, base, now),
        );
        let scheduler = scheduler?;
        refresh?;
        self.read_logs(token, base).await;
        Ok(self.fleet.frame(now, &scheduler))
    }

    /// The GitHub half of a tick: the two listings concurrently,
    /// every `in_progress` run's jobs page at the read bound, then
    /// the dropped runs' one-time final reads.
    async fn github_refresh(
        &mut self,
        token: &str,
        base: &str,
        now: OffsetDateTime,
    ) -> stow_types::error::Result<()> {
        let (queued, in_progress) = tokio::join!(
            fetch_listing(token, base, "queued", &mut self.queued),
            fetch_listing(token, base, "in_progress", &mut self.in_progress),
        );
        let rows = queued?.into_iter().chain(in_progress?).collect::<Vec<_>>();
        let dropped = self.fleet.apply_listing(rows)?;

        let in_flight = self.fleet.in_progress();
        let reads = futures_util::stream::iter(in_flight)
            .map(|(run_id, attempt)| {
                let mut pages = self
                    .run_pages
                    .remove(&run_id)
                    .unwrap_or_else(ConditionalPages::new);
                async move {
                    let result = runs::fetch_attempt_jobs(
                        Some(token),
                        base,
                        run_id,
                        attempt,
                        Some(&mut pages),
                        Backoff::new,
                    )
                    .await;
                    (run_id, pages, result)
                }
            })
            .buffered(github::RANGE_READ_CONCURRENCY)
            .collect::<Vec<_>>()
            .await;
        for (run_id, pages, result) in reads {
            self.run_pages.insert(run_id, pages);
            self.fleet.apply_jobs(run_id, "", &result?, now)?;
        }

        let completions = futures_util::stream::iter(dropped)
            .map(|run_id| async move {
                let row = github::get_url_json::<WorkflowRunRow>(
                    &format!("{base}/repos/{}/actions/runs/{run_id}", github::REPO),
                    Some(token),
                    Backoff::new(),
                )
                .await?;
                let jobs = runs::fetch_attempt_jobs(
                    Some(token),
                    base,
                    run_id,
                    row.run_attempt,
                    None,
                    Backoff::new,
                )
                .await?;
                stow_types::error::Result::Ok((row, jobs))
            })
            .buffered(github::RANGE_READ_CONCURRENCY)
            .collect::<Vec<_>>()
            .await;
        for completion in completions {
            let (row, jobs) = completion?;
            self.run_pages.remove(&row.id);
            self.fleet.retire(&row, &jobs, now)?;
        }
        Ok(())
    }

    /// Each unclassified failed job's log, at the read bound — the
    /// memo keys the class on the job id, so a log is fetched once
    /// per failure, never once per tick. A failed read warns and
    /// stays unclassified for the next tick: a dead token fails the
    /// listings first, so a log failure is the log's own — late
    /// publication or retention, not the watch's.
    async fn read_logs(&mut self, token: &str, base: &str) {
        let pending = self.fleet.unclassified_jobs();
        let results = futures_util::stream::iter(pending)
            .map(|job_id| async move {
                let url = format!("{base}/repos/{}/actions/jobs/{job_id}/logs", github::REPO);
                (job_id, github::get_text(token, &url, Backoff::new()).await)
            })
            .buffered(github::RANGE_READ_CONCURRENCY)
            .collect::<Vec<_>>()
            .await;
        for (job_id, result) in results {
            match result {
                Ok(log) => {
                    let (class, _) = runs::classify_log(&log);
                    self.fleet.record_log_class(job_id, class);
                }
                Err(error) => {
                    tracing::warn!(job_id, %error, "job log unavailable; classifying next tick");
                }
            }
        }
    }
}

/// One listing's rows — the `runs?status=<s>&per_page=100` walk
/// through `pages`, following `Link: rel="next"` until
/// `total_count` is in hand (§2.1). Fails past
/// `github::RUNS_LISTING_CAP` and on a `Link` off `base`, same as the
/// jobs pager.
async fn fetch_listing(
    token: &str,
    base: &str,
    status: &str,
    pages: &mut ConditionalPages<RunsPage<WorkflowRunRow>>,
) -> stow_types::error::Result<Vec<WorkflowRunRow>> {
    let mut url = format!(
        "{base}/repos/{}/actions/workflows/{BATCH_WORKFLOW_FILE}/runs?status={status}&per_page=100",
        github::REPO
    );
    let mut rows = Vec::new();
    loop {
        let (page, next) = pages
            .get(Some(token), &url, Backoff::new())
            .await
            .map_err(|error| stow_error!("GET {url}: {error}"))?;
        rows.extend(page.workflow_runs.iter().cloned());
        if u64::try_from(rows.len()).unwrap_or(u64::MAX) >= page.total_count {
            break;
        }
        if rows.len() > github::RUNS_LISTING_CAP {
            return Err(stow_error!(
                "runs listing passed {} rows — the cap is {}",
                rows.len(),
                github::RUNS_LISTING_CAP
            ));
        }
        let Some(next) = next else { break };
        let next = next.to_owned();
        if !next.starts_with(&format!("{base}/")) {
            return Err(stow_error!(
                "listing page link {next} leaves the read's base {base}"
            ));
        }
        url = next;
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::Actor;
    use stow_types::runs::{RunJobRow, RunStepRow};

    /// A wall-clock timestamp for the fixtures.
    fn at(unix: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(unix).expect("timestamp")
    }

    /// The title every batch run renders — `<rustc>-b<batch_id>`.
    const TITLE: &str = "1.99.0-b0123456789abcdef0123456789abcdef";

    /// A listing row — `display_title` defaults to [`TITLE`] because
    /// `run-name` only ever fails to render as `BATCH_WORKFLOW_NAME`.
    fn run_row(
        id: u64,
        status: &str,
        conclusion: Option<&str>,
        run_attempt: u64,
        created_at: i64,
        display_title: &str,
    ) -> WorkflowRunRow {
        WorkflowRunRow {
            id,
            display_title: display_title.to_owned(),
            head_sha: "sha".to_owned(),
            status: status.to_owned(),
            conclusion: conclusion.map(str::to_owned),
            html_url: format!("https://github.com/water-rs/stow/actions/runs/{id}"),
            run_attempt,
            created_at: at(created_at),
            actor: Actor {
                login: "stow-bot".to_owned(),
            },
        }
    }

    /// One step row.
    fn step(name: &str, status: &str, conclusion: Option<&str>) -> RunStepRow {
        RunStepRow {
            name: name.to_owned(),
            status: status.to_owned(),
            conclusion: conclusion.map(str::to_owned),
        }
    }

    /// A leg's job row — every field `live_legs` reads is scriptable.
    fn leg_job(
        id: u64,
        name: String,
        status: &str,
        conclusion: Option<&str>,
        started_at: Option<i64>,
        completed_at: Option<i64>,
        steps: Vec<RunStepRow>,
    ) -> RunJobRow {
        RunJobRow {
            id,
            name,
            status: status.to_owned(),
            conclusion: conclusion.map(str::to_owned),
            started_at: started_at.map(at),
            completed_at: completed_at.map(at),
            run_attempt: 1,
            html_url: format!("https://github.com/water-rs/stow/actions/runs/1/job/{id}"),
            steps,
        }
    }

    /// `leg N / build #N <crate> <version> (<target>) <16-hex hash>`.
    fn build(leg: u32) -> String {
        format!("leg {leg} / build #{leg} serde 1.0.0 (x86_64-unknown-linux-gnu) 0123456789abcdef")
    }

    /// `leg N / publish #N <16-hex hash>`.
    fn publish(leg: u32) -> String {
        format!("leg {leg} / publish #{leg} 0123456789abcdef")
    }

    /// Both jobs of a leg reading `completed`/`success`.
    fn settled_jobs(leg: u32) -> Vec<RunJobRow> {
        vec![
            leg_job(
                10 + u64::from(leg),
                build(leg),
                "completed",
                Some("success"),
                Some(900),
                Some(950),
                vec![],
            ),
            leg_job(
                20 + u64::from(leg),
                publish(leg),
                "completed",
                Some("success"),
                Some(960),
                Some(990),
                vec![],
            ),
        ]
    }

    /// A leg's build job failed its verdict step with every row
    /// settled — a `RunFailure::Verdict`.
    fn failed_jobs(leg: u32) -> Vec<RunJobRow> {
        vec![
            leg_job(
                30 + u64::from(leg),
                build(leg),
                "completed",
                Some("failure"),
                Some(900),
                Some(950),
                vec![step(
                    "Run the untrusted build stage",
                    "completed",
                    Some("failure"),
                )],
            ),
            leg_job(
                40 + u64::from(leg),
                publish(leg),
                "completed",
                Some("skipped"),
                Some(960),
                Some(990),
                vec![],
            ),
        ]
    }

    /// A `SchedulerStatus` fixture.
    fn scheduler(pending: u32, human_pending: u32) -> SchedulerStatus {
        SchedulerStatus {
            pending,
            human_pending,
            blocked: 2,
            dispatched: 3,
            running: 4,
            completed: 100,
            failed: 5,
        }
    }

    /// `queued` → `in_progress` → `completed` — a run's full
    /// lifecycle through the model (§2.1).
    #[test]
    fn a_run_lifecycle_queued_to_completed() {
        let mut fleet = Fleet::new(at(500));
        let dropped = fleet
            .apply_listing([run_row(7, "queued", None, 1, 400, TITLE)])
            .expect("listing");
        assert_eq!(dropped, [] as [u64; 0]);
        let dropped = fleet
            .apply_listing([run_row(7, "in_progress", None, 1, 400, TITLE)])
            .expect("listing");
        assert_eq!(dropped, [] as [u64; 0]);
        fleet
            .apply_jobs(
                7,
                "",
                &[leg_job(30, build(0), "queued", None, None, None, vec![])],
                at(1_000),
            )
            .expect("jobs");
        let frame = fleet.frame(at(1_000), &scheduler(10, 3));
        assert_eq!(frame.runs.len(), 1);
        assert_eq!(frame.runs[0].status, "in_progress");
        assert_eq!(frame.runs[0].legs.queued, 1);
        assert_eq!(frame.runs[0].age_seconds, 600);
        assert_eq!(frame.since, at(500));
        assert_eq!(frame.scheduler.pending_miss, 7);
        assert_eq!(frame.scheduler.pending_human, 3);

        let dropped = fleet.apply_listing([]).expect("listing");
        assert_eq!(dropped, vec![7]);
        fleet
            .retire(
                &run_row(7, "completed", Some("success"), 1, 400, TITLE),
                &settled_jobs(0),
                at(1_100),
            )
            .expect("retire");
        let frame = fleet.frame(at(1_100), &scheduler(0, 0));
        assert_eq!(frame.runs, [] as [RunView; 0]);
        assert_eq!(frame.targets[0].legs.done, 1);
    }

    /// A rerun re-enters at `run_attempt + 1`; a leg that failed
    /// attempt 1 and succeeded on attempt 2 counts once, as done —
    /// and a same-attempt reappearance stays frozen (§2.1).
    #[test]
    fn a_rerun_reenters_and_a_flipped_leg_counts_once() {
        let mut fleet = Fleet::new(at(0));
        fleet
            .apply_listing([run_row(7, "in_progress", None, 1, 0, TITLE)])
            .expect("listing");
        fleet
            .apply_jobs(7, "", &failed_jobs(0), at(1_000))
            .expect("jobs");
        let dropped = fleet.apply_listing([]).expect("listing");
        assert_eq!(dropped, vec![7]);
        fleet
            .retire(
                &run_row(7, "completed", Some("failure"), 1, 0, TITLE),
                &failed_jobs(0),
                at(1_100),
            )
            .expect("retire");
        let frame = fleet.frame(at(1_100), &scheduler(0, 0));
        assert_eq!(frame.failures.len(), 1);

        // A rerun — the same run id at `run_attempt + 1` re-enters.
        let dropped = fleet
            .apply_listing([run_row(7, "in_progress", None, 2, 0, TITLE)])
            .expect("listing");
        assert_eq!(dropped, [] as [u64; 0]);
        let frame = fleet.frame(at(1_200), &scheduler(0, 0));
        assert_eq!(frame.runs.len(), 1);
        assert_eq!(frame.runs[0].run_attempt, 2);
        // The leg's attempt-1 outcome stands until the new page lands.
        assert_eq!(frame.failures.len(), 1);

        fleet
            .apply_jobs(7, "", &settled_jobs(0), at(1_300))
            .expect("jobs");
        let frame = fleet.frame(at(1_300), &scheduler(0, 0));
        assert_eq!(frame.targets[0].legs.done, 1);
        assert_eq!(frame.targets[0].legs.failed, 0);
        assert_eq!(frame.failures, [] as [FailureView; 0]);

        // Completed again — and a stale listing row at the old
        // attempt cannot resurrect it.
        fleet.apply_listing([]).expect("listing");
        fleet
            .retire(
                &run_row(7, "completed", Some("success"), 2, 0, TITLE),
                &settled_jobs(0),
                at(1_400),
            )
            .expect("retire");
        let dropped = fleet
            .apply_listing([run_row(7, "in_progress", None, 1, 0, TITLE)])
            .expect("listing");
        assert_eq!(dropped, [] as [u64; 0]);
        let frame = fleet.frame(at(1_500), &scheduler(0, 0));
        assert_eq!(frame.runs, [] as [RunView; 0]);
        assert_eq!(frame.targets[0].legs.done, 1);
    }

    /// The per-target roll-up and the per-run buckets add up over the
    /// same legs — the frame's own cross-check (§3).
    #[test]
    fn per_target_sums_equal_per_run_sums() {
        let mut fleet = Fleet::new(at(0));
        fleet
            .apply_listing([
                run_row(1, "in_progress", None, 1, 0, TITLE),
                run_row(2, "in_progress", None, 1, 0, TITLE),
            ])
            .expect("listing");
        fleet
            .apply_jobs(1, "", &settled_jobs(0), at(1_000))
            .expect("jobs");
        fleet
            .apply_jobs(
                2,
                "",
                &[
                    leg_job(30, build(0), "in_progress", None, Some(900), None, vec![]),
                    leg_job(31, build(1), "queued", None, None, None, vec![]),
                ],
                at(1_000),
            )
            .expect("jobs");
        let frame = fleet.frame(at(1_000), &scheduler(0, 0));
        let run_totals: u32 = frame
            .runs
            .iter()
            .map(|run| run.legs.queued + run.legs.building + run.legs.done + run.legs.failed)
            .sum();
        let target_totals: u32 = frame
            .targets
            .iter()
            .map(|target| {
                target.legs.queued + target.legs.building + target.legs.done + target.legs.failed
            })
            .sum();
        assert_eq!(run_totals, 3);
        assert_eq!(run_totals, target_totals);
        let target = &frame.targets[0];
        assert_eq!(target.target, "x86_64-unknown-linux-gnu");
        assert_eq!(target.legs.done, 1);
        assert_eq!(target.legs.building, 1);
        assert_eq!(target.legs.queued, 1);
    }

    /// An all-unrendered leg (stow#839) counts toward its run but
    /// lands in no target bucket.
    #[test]
    fn an_unrendered_leg_counts_under_no_target() {
        let mut fleet = Fleet::new(at(0));
        fleet
            .apply_listing([run_row(1, "in_progress", None, 1, 0, TITLE)])
            .expect("listing");
        fleet
            .apply_jobs(
                1,
                "cancelled",
                &[leg_job(
                    30,
                    "leg 0 / build #${{ inputs.leg }} ${{ inputs.label }} (${{ inputs.target }}) ${{ inputs.task_hash }}"
                        .to_owned(),
                    "completed",
                    Some("skipped"),
                    Some(900),
                    Some(950),
                    vec![],
                )],
                at(1_000),
            )
            .expect("jobs");
        let frame = fleet.frame(at(1_000), &scheduler(0, 0));
        assert_eq!(frame.runs[0].legs.failed, 1);
        assert_eq!(frame.targets, [] as [TargetView; 0]);
        let failure = &frame.failures[0];
        assert_eq!(failure.coarse_class, "skipped");
        assert_eq!(failure.target, None);
        assert_eq!(failure.crate_name, None);
    }

    /// A title still reading `BATCH_WORKFLOW_NAME` is `run-name` not
    /// rendered yet — ignored, not tracked, not an error (§2.4).
    #[test]
    fn an_unrendered_title_is_ignored() {
        let mut fleet = Fleet::new(at(0));
        let dropped = fleet
            .apply_listing([run_row(9, "queued", None, 1, 0, BATCH_WORKFLOW_NAME)])
            .expect("listing");
        assert_eq!(dropped, [] as [u64; 0]);
        assert_eq!(
            fleet.frame(at(100), &scheduler(0, 0)).runs,
            [] as [RunView; 0]
        );
    }

    /// Any other unparseable title on this workflow is a schema
    /// surprise — the run is ours, so the title must read a batch.
    #[test]
    fn an_unparseable_title_fails() {
        let mut fleet = Fleet::new(at(0));
        assert!(
            fleet
                .apply_listing([run_row(9, "queued", None, 1, 0, "some-hand-run")])
                .is_err()
        );
    }

    /// A run that left the two listings mid-transition — the re-read
    /// row still says `in_progress` — tracks again rather than
    /// freeze.
    #[test]
    fn retire_retracks_a_still_in_flight_run() {
        let mut fleet = Fleet::new(at(0));
        fleet
            .apply_listing([run_row(7, "in_progress", None, 1, 0, TITLE)])
            .expect("listing");
        let dropped = fleet.apply_listing([]).expect("listing");
        assert_eq!(dropped, vec![7]);
        fleet
            .retire(
                &run_row(7, "in_progress", None, 1, 0, TITLE),
                &[],
                at(1_000),
            )
            .expect("retire");
        let frame = fleet.frame(at(1_000), &scheduler(0, 0));
        assert_eq!(frame.runs.len(), 1);
        assert_eq!(frame.runs[0].status, "in_progress");
    }

    /// The failure list orders newest first and joins `log_class`
    /// once the memo has it.
    #[test]
    fn failures_list_newest_first_with_the_log_class() {
        let mut fleet = Fleet::new(at(0));
        fleet
            .apply_listing([run_row(1, "in_progress", None, 1, 0, TITLE)])
            .expect("listing");
        fleet
            .apply_jobs(1, "", &[failed_jobs(0), failed_jobs(1)].concat(), at(1_000))
            .expect("jobs");
        fleet.record_log_class(30, FailureClass::LinkerUnusable);
        assert_eq!(fleet.unclassified_jobs(), [31]);
        let frame = fleet.frame(at(1_000), &scheduler(0, 0));
        assert_eq!(frame.failures.len(), 2);
        // Newest first — leg 1 failed second, and its job's log has
        // not been read, so it lists no class.
        assert_eq!(
            frame.failures[0].coarse_class,
            "verdict:Run the untrusted build stage"
        );
        assert_eq!(frame.failures[0].crate_name.as_deref(), Some("serde"));
        assert_eq!(frame.failures[0].log_class, None);
        // The memo keyed on leg 0's failed job id joined its class.
        let leg_zero = frame
            .failures
            .iter()
            .find(|failure| {
                failure
                    .job_url
                    .as_deref()
                    .is_some_and(|url| url.ends_with("/30"))
            })
            .expect("leg 0's failure");
        assert_eq!(leg_zero.log_class, Some(FailureClass::LinkerUnusable));
    }

    // ----- The I/O loop (stow#853 §3) -----

    use crate::test_server::{Loopback, Step};

    /// A `RunsPage` body carrying `rows` run ids.
    fn listing(rows: &[String]) -> &'static str {
        let count = rows.len();
        let rows = rows.join(",");
        Box::leak(
            format!("{{\"total_count\":{count},\"workflow_runs\":[{rows}]}}").into_boxed_str(),
        )
    }

    /// One `WorkflowRunRow` JSON object.
    fn run_json(id: u64, status: &str, conclusion: Option<&str>, attempt: u64) -> String {
        let conclusion = conclusion.map_or_else(|| "null".to_owned(), |c| format!("\"{c}\""));
        format!(
            "{{\"id\":{id},\"display_title\":\"{TITLE}\",\"head_sha\":\"s\",\"status\":\"{status}\",\"conclusion\":{conclusion},\"html_url\":\"u\",\"run_attempt\":{attempt},\"created_at\":\"1970-01-01T00:00:00Z\",\"actor\":{{\"login\":\"stow-bot\"}}}}"
        )
    }

    /// A `RunJobsPage` body — one settled build+publish pair per leg.
    fn jobs_json() -> &'static str {
        "{\"jobs\":[{\"id\":30,\"name\":\"leg 0 / build #0 serde 1.0.0 (x86_64-unknown-linux-gnu) 0123456789abcdef\",\"status\":\"completed\",\"conclusion\":\"success\",\"started_at\":\"1970-01-01T00:15:00Z\",\"completed_at\":\"1970-01-01T00:15:50Z\",\"run_attempt\":1,\"html_url\":\"j\",\"steps\":[]},{\"id\":40,\"name\":\"leg 0 / publish #0 0123456789abcdef\",\"status\":\"completed\",\"conclusion\":\"success\",\"started_at\":\"1970-01-01T00:16:00Z\",\"completed_at\":\"1970-01-01T00:16:30Z\",\"run_attempt\":1,\"html_url\":\"j\",\"steps\":[]}]}"
    }

    /// The queue status the scheduler endpoint answers.
    const STATUS_JSON: &str = "{\"pending\":10,\"human_pending\":3,\"blocked\":2,\"dispatched\":1,\"running\":4,\"completed\":9,\"failed\":0}";

    /// A 200 step carrying an `ETag`.
    fn ok_etag(etag: &str, body: &'static str) -> Step {
        Step::RespondWith {
            status: 200,
            retry_after: None,
            headers: vec![("etag".to_owned(), format!("\"{etag}\""))],
            body,
        }
    }

    /// Two ticks: every repeated read — listings and the in-flight
    /// run's jobs page — goes out `If-None-Match` and the 304s render
    /// the same frame (§2.1, §2.4).
    #[tokio::test]
    async fn two_ticks_revalidate_and_render_the_same_frame() {
        let github = Loopback::start(vec![
            // tick 1 — both listings 200 with etags, the run's page 200.
            ok_etag("lq", listing(&[run_json(7, "in_progress", None, 1)])),
            ok_etag("li", listing(&[])),
            ok_etag("lj", jobs_json()),
            // tick 2 — every URL revalidates, all 304.
            Step::Respond {
                status: 304,
                retry_after: None,
                body: "",
            },
            Step::Respond {
                status: 304,
                retry_after: None,
                body: "",
            },
            Step::Respond {
                status: 304,
                retry_after: None,
                body: "",
            },
        ])
        .await;
        let edge_server = Loopback::start(vec![
            Step::Respond {
                status: 200,
                retry_after: None,
                body: STATUS_JSON,
            },
            Step::Respond {
                status: 200,
                retry_after: None,
                body: STATUS_JSON,
            },
        ])
        .await;
        let edge = crate::Edge::for_test(edge_server.url.clone());
        let mut watch = Watch::new(at(0));
        let first = watch
            .tick(&edge, "tok", &github.url, at(1_000))
            .await
            .expect("tick");
        let second = watch
            .tick(&edge, "tok", &github.url, at(1_000))
            .await
            .expect("tick");
        assert_eq!(first, second);
        assert_eq!(first.targets[0].legs.done, 1);
        let heads = github.join().await;
        let etags: Vec<Option<String>> = heads
            .iter()
            .map(|head| {
                head.head
                    .headers
                    .get("if-none-match")
                    .map(|value| value.to_str().expect("ascii").to_owned())
            })
            .collect();
        // The first tick sent no validator; the second tick sent each
        // page's own ETag — the listings race, so compare the set.
        assert_eq!(etags[0], None);
        assert_eq!(etags[1], None);
        let mut second: Vec<_> = etags[3..].iter().flatten().cloned().collect();
        second.sort();
        assert_eq!(second, vec!["\"li\"", "\"lj\"", "\"lq\""]);
        let _ = edge_server.join().await;
    }

    /// A run that leaves both listings is read once — row plus its
    /// final attempt's page — then frozen (§2.1).
    #[tokio::test]
    async fn a_dropped_run_gets_one_final_read() {
        let github = Loopback::start(vec![
            // tick 1: run 7 in flight.
            ok_etag("lq", listing(&[run_json(7, "in_progress", None, 1)])),
            ok_etag("li", listing(&[])),
            ok_etag("lj", jobs_json()),
            // tick 2: gone from both listings — a completion changes
            // the listing, so the revalidation is a 200 with the run
            // absent — then its row + final page, read once.
            ok_etag("lq2", listing(&[])),
            ok_etag("li2", listing(&[])),
            Step::Respond {
                status: 200,
                retry_after: None,
                body: Box::leak(run_json(7, "completed", Some("success"), 1).into_boxed_str()),
            },
            ok_etag("lf", jobs_json()),
        ])
        .await;
        let edge_server = Loopback::start(vec![
            Step::Respond {
                status: 200,
                retry_after: None,
                body: STATUS_JSON,
            },
            Step::Respond {
                status: 200,
                retry_after: None,
                body: STATUS_JSON,
            },
        ])
        .await;
        let edge = crate::Edge::for_test(edge_server.url.clone());
        let mut watch = Watch::new(at(0));
        watch
            .tick(&edge, "tok", &github.url, at(1_000))
            .await
            .expect("tick");
        let frame = watch
            .tick(&edge, "tok", &github.url, at(1_100))
            .await
            .expect("tick");
        assert_eq!(frame.runs, [] as [RunView; 0]);
        assert_eq!(frame.targets[0].legs.done, 1);
        let _ = github.join().await;
        let _ = edge_server.join().await;
    }

    /// A 401 on either read — scheduler or GitHub — exits `Err`; the
    /// watch never renders a frame built on a failed read (§3).
    #[tokio::test]
    async fn a_401_from_either_source_exits_err() {
        for (github_steps, edge_steps) in [
            (
                vec![Step::Respond {
                    status: 401,
                    retry_after: None,
                    body: "no",
                }],
                vec![Step::Respond {
                    status: 200,
                    retry_after: None,
                    body: STATUS_JSON,
                }],
            ),
            (
                vec![ok_etag("lq", listing(&[])), ok_etag("li", listing(&[]))],
                vec![Step::Respond {
                    status: 401,
                    retry_after: None,
                    body: "no",
                }],
            ),
        ] {
            let github = Loopback::start(github_steps).await;
            let edge_server = Loopback::start(edge_steps).await;
            let edge = crate::Edge::for_test(edge_server.url.clone());
            let mut watch = Watch::new(at(0));
            assert!(
                watch
                    .tick(&edge, "tok", &github.url, at(1_000))
                    .await
                    .is_err()
            );
            let _ = github.join().await;
            let _ = edge_server.join().await;
        }
    }

    /// A scheduler 503 then 200 retries under `Backoff` and the tick
    /// still renders (§1).
    #[tokio::test]
    async fn a_scheduler_503_retries_and_renders() {
        let github = Loopback::start(vec![
            ok_etag("lq", listing(&[])),
            ok_etag("li", listing(&[])),
        ])
        .await;
        let edge_server = Loopback::start(vec![
            Step::Respond {
                status: 503,
                retry_after: None,
                body: "down",
            },
            Step::Respond {
                status: 200,
                retry_after: None,
                body: STATUS_JSON,
            },
        ])
        .await;
        let edge = crate::Edge::for_test(edge_server.url.clone());
        let mut watch = Watch::new(at(0));
        let frame = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            watch.tick(&edge, "tok", &github.url, at(1_000)),
        )
        .await
        .expect("the retry lands inside the bound")
        .expect("tick");
        assert_eq!(frame.scheduler.pending_miss, 7);
        let _ = github.join().await;
        let _ = edge_server.join().await;
    }

    /// `--json` emits exactly one compact `WatchFrame` line per
    /// render — the NDJSON contract (§3).
    #[test]
    fn json_mode_emits_one_ndjson_line_per_frame() {
        let mut fleet = Fleet::new(at(500));
        fleet
            .apply_listing([run_row(1, "in_progress", None, 1, 400, TITLE)])
            .expect("listing");
        let frame = fleet.frame(at(1_000), &scheduler(10, 3));
        let mut out = Vec::new();
        let mut screen = crate::render::Screen::for_test(
            &mut out,
            crate::render::Output::Json,
            false,
            jiff::tz::TimeZone::UTC,
        );
        screen.render(&frame).expect("render");
        screen.render(&frame).expect("render");
        let text = String::from_utf8(out).expect("utf8");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let parsed: WatchFrame = serde_json::from_str(lines[0]).expect("ndjson round-trips");
        assert_eq!(parsed, frame);
    }

    /// The frame serializes — `at`/`since` as rfc3339, `batch_id` as
    /// its hex string, `TargetView`'s legs flat next to `target` —
    /// and round-trips.
    #[test]
    fn a_frame_serializes_and_round_trips() {
        let mut fleet = Fleet::new(at(500));
        fleet
            .apply_listing([run_row(1, "in_progress", None, 1, 400, TITLE)])
            .expect("listing");
        fleet
            .apply_jobs(1, "", &settled_jobs(0), at(1_000))
            .expect("jobs");
        let frame = fleet.frame(at(1_000), &scheduler(10, 3));
        let json = serde_json::to_value(&frame).expect("serialize");
        assert_eq!(json["at"], "1970-01-01T00:16:40Z");
        assert_eq!(json["since"], "1970-01-01T00:08:20Z");
        assert_eq!(
            json["runs"][0]["batch_id"],
            "0123456789abcdef0123456789abcdef"
        );
        assert_eq!(json["targets"][0]["target"], "x86_64-unknown-linux-gnu");
        assert_eq!(json["targets"][0]["done"], 1);
        assert!(json["targets"][0].get("legs").is_none());
        let round_trip: WatchFrame = serde_json::from_value(json).expect("deserialize");
        assert_eq!(round_trip, frame);
    }
}
