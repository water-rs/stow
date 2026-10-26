//! The `Preheat cost` lane's report (stow#773).
//!
//! What one preheat wave and one daily resubmit cost the scheduler
//! Durable Object, in the rows Cloudflare bills, and whether the wave
//! ran the graph the way the model says it must.
//!
//! `scripts/preheat-cost.sh` drives the wave on the mock stack and
//! leaves its observations in a work directory; `stow-admin preheat
//! cost report` reads them into [`WaveObservations`] and
//! [`analyse`] turns them into a [`PreheatCostReport`]. The analysis is
//! pure, so every check is unit-tested here rather than in the shell.
//!
//! The production wave's size ([`ProductionWave`]) is a separate
//! document: `scripts/production-wave.sh` resolves the production
//! preheat lanes plan-only, and the distinct task identities across them
//! ([`count_production`]) are the node count the monthly projection
//! scales the measured per-node costs to.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::api::{SchedulerLedger, SchedulerLedgerOp};
use crate::do_budgets::{DO_BUDGETS, LEDGER_OP_ALARM, LEDGER_OP_TASK_COMPLETE, grew};
use crate::local_ci::LocalCiRun;

/// The event kinds a wave is made of, each one scheduler operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A preheat lane's trusted task submit.
    Submit,
    /// The alarm's dispatch pass.
    Dispatch,
    /// A build run's `workflow_run` completion — one per
    /// `build-crate.yml` run, so one per task.
    Completion,
    /// An `index-publish` slice report, which also dispatches the
    /// dependents it releases.
    SliceReport,
}

impl EventKind {
    /// Every kind, in the order a wave meets them.
    pub const ALL: [Self; 4] = [
        Self::Submit,
        Self::Dispatch,
        Self::Completion,
        Self::SliceReport,
    ];

    /// The probe-ledger operation this kind books under.
    #[must_use]
    pub const fn ledger_op(self) -> &'static str {
        match self {
            Self::Submit => "POST /tasks/submit/trusted",
            Self::Dispatch => LEDGER_OP_ALARM,
            Self::Completion => LEDGER_OP_TASK_COMPLETE,
            Self::SliceReport => "POST /index/published",
        }
    }

    /// The stow#433 drive whose budget one event of this kind must fit,
    /// for the kinds whose event has a fixed size: one alarm pass claims
    /// at most the dispatch cap. A submit, a completion and a
    /// slice report scale with what they carry, so their fixture drives
    /// do not bound a wave's events.
    #[must_use]
    pub const fn drive(self) -> Option<&'static str> {
        match self {
            Self::Dispatch => Some("alarm pass"),
            Self::Submit | Self::Completion | Self::SliceReport => None,
        }
    }
}

/// Operations the harness itself issues to watch the run — readiness
/// and progress polls, ledger reads, the operator reset. Production pays
/// none of them for a wave, so the totals leave them out.
pub const OBSERVER_OPS: &[&str] = &["GET /status", "GET /budget/ledger", "POST /reset"];

/// One ledger read and when it was taken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerSnapshot {
    /// Unix milliseconds when the read returned.
    pub taken_at_ms: u64,
    /// The object's per-operation totals at that moment.
    pub ledger: SchedulerLedger,
}

/// One publish round of the wave: export → publish → report.
#[derive(Debug, Clone)]
pub struct Round {
    /// The ledger read right before the round's first slice report —
    /// its timestamp is the earliest a dependent the round releases may
    /// be dispatched.
    pub before_report: LedgerSnapshot,
    /// The ledger read once every slice of the round was reported.
    pub end: LedgerSnapshot,
    /// Task ids whose records the round's export carried.
    pub published: BTreeSet<String>,
}

/// One preheat lane's run: its submit and the ledger around it.
#[derive(Debug, Clone)]
pub struct LaneRun {
    /// `top-binaries` or `projects`.
    pub lane: String,
    /// Tasks the lane posted.
    pub submitted: u64,
    /// Queue rows the lane's submit inserted; the rest of `submitted`
    /// deduplicated away.
    pub inserted: u64,
    /// `queue_dependencies` rows the lane's submit wrote — the direct
    /// dependency edges of its inserted tasks.
    pub inserted_edges: u64,
    /// Lanes whose submit failed — a repository whose POST failed, or
    /// the whole lane's.
    pub submit_failures: Vec<String>,
    /// The ledger before the lane started.
    pub before: LedgerSnapshot,
    /// The ledger after the lane exited.
    pub after: LedgerSnapshot,
}

/// One restart of the dev edge the harness made mid-run.
///
/// The probe ledger lives on the scheduler graph and persists only
/// through its snapshot, so a restarted edge answers the ledger of its
/// last snapshot: every booking since then is gone. The harness reads
/// the ledger right before it stops the edge and right after the new
/// one answers; [`analyse`] carries every later read across the
/// restart as `before + (read − after)`. Nothing but those two reads
/// and the readiness polls may reach the scheduler in between — a build
/// dispatched there is a booking neither read holds, and the report
/// fails on it.
#[derive(Debug, Clone)]
pub struct EdgeRestart {
    /// The ledger read right before the edge stopped.
    pub before: LedgerSnapshot,
    /// The ledger read once the restarted edge answered.
    pub after: LedgerSnapshot,
}

/// One submitted node.
#[derive(Debug, Clone)]
pub struct Node {
    /// The target its task mints on.
    pub target: String,
    /// Its direct dependencies' task ids.
    pub dependencies: Vec<String>,
}

/// One phase — the wave, or the resubmit after it.
#[derive(Debug, Clone)]
pub struct PhaseObservations {
    /// The ledger when the phase began.
    pub start: LedgerSnapshot,
    /// The phase's publish rounds, in order. The last round's end is the
    /// phase's end.
    pub rounds: Vec<Round>,
    /// The phase's lanes, in the order they ran.
    pub lanes: Vec<LaneRun>,
    /// The ledger when the phase ended (equal to the last round's end
    /// when the phase published anything).
    pub end: LedgerSnapshot,
}

/// One task a production lane planned, reduced to what the count needs.
#[derive(Debug, Clone)]
pub struct ProductionTask {
    /// The scheduler's task identity (`task_id` of the enqueue request).
    pub task_id: String,
    /// The target the task mints on.
    pub target: String,
}

/// One production preheat lane's plan-only output.
#[derive(Debug, Clone)]
pub struct ProductionLane {
    /// `top-binaries` or `projects`.
    pub lane: String,
    /// Every task the lane planned, duplicates included.
    pub tasks: Vec<ProductionTask>,
}

/// One production lane's share of the count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionLaneCount {
    /// The lane.
    pub lane: String,
    /// Tasks the lane planned.
    pub planned: u64,
    /// Distinct task ids the lane added that no earlier lane had.
    pub new_nodes: u64,
}

/// The production wave's size.
///
/// The distinct task identities the production preheat lanes would
/// submit — the scheduler deduplicates on `task_id`, so a node two lanes
/// (or two targets' resolves) name is one queue row and one build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionWave {
    /// Distinct nodes across every lane.
    pub nodes: u64,
    /// Nodes per target triple.
    pub nodes_per_target: BTreeMap<String, u64>,
    /// Each lane's planned and first-seen counts, in lane order.
    pub lanes: Vec<ProductionLaneCount>,
}

impl ProductionWave {
    /// Every production lane must have planned something: a lane that
    /// resolved nothing would undercount the production wave the monthly
    /// projection scales to.
    ///
    /// # Errors
    /// No lane ran, or a lane planned no task.
    pub fn require_planned(&self) -> crate::error::Result<()> {
        if self.lanes.is_empty() {
            return Err(crate::stow_error!("no production lane ran"));
        }
        let empty: Vec<&str> = self
            .lanes
            .iter()
            .filter(|lane| lane.planned == 0)
            .map(|lane| lane.lane.as_str())
            .collect();
        if empty.is_empty() {
            Ok(())
        } else {
            Err(crate::stow_error!(
                "production lane(s) planned nothing: {}",
                empty.join(", ")
            ))
        }
    }
}

/// Count the distinct nodes across the production lanes, dedup'd by
/// task id exactly as the scheduler's queue would.
#[must_use]
pub fn count_production(lanes: &[ProductionLane]) -> ProductionWave {
    let mut seen = BTreeSet::<&str>::new();
    let mut nodes_per_target = BTreeMap::<String, u64>::new();
    let counts = lanes
        .iter()
        .map(|lane| {
            let mut new_nodes = 0_u64;
            for task in &lane.tasks {
                if seen.insert(task.task_id.as_str()) {
                    new_nodes += 1;
                    *nodes_per_target.entry(task.target.clone()).or_default() += 1;
                }
            }
            ProductionLaneCount {
                lane: lane.lane.clone(),
                planned: lane.tasks.len() as u64,
                new_nodes,
            }
        })
        .collect();
    ProductionWave {
        nodes: seen.len() as u64,
        nodes_per_target,
        lanes: counts,
    }
}

/// Everything the harness observed.
#[derive(Debug, Clone)]
pub struct WaveObservations {
    /// The rustc the wave built for.
    pub rustc_version: String,
    /// Every node the wave's lanes submitted, by task id.
    pub nodes: BTreeMap<String, Node>,
    /// The first wave.
    pub wave: PhaseObservations,
    /// The daily resubmit of the same lists.
    pub resubmit: PhaseObservations,
    /// Every edge restart across both phases, in the order they ran.
    pub restarts: Vec<EdgeRestart>,
    /// Every run the local CI was dispatched, both phases.
    pub runs: Vec<LocalCiRun>,
    /// Task ids the final published slices serve — the gate's own
    /// coverage rule.
    pub covered: BTreeSet<String>,
    /// Every place an `overloaded` answer surfaced, one line each.
    pub overload_sightings: Vec<String>,
}

/// One kind's cost over a span.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KindCost {
    /// The kind.
    pub kind: EventKind,
    /// Events of the kind.
    pub events: u64,
    /// `rowsRead` the events were billed.
    pub rows_read: u64,
    /// `rowsWritten` the events were billed.
    pub rows_written: u64,
}

impl KindCost {
    /// `(rowsRead, rowsWritten)` per event, `None` without events.
    #[must_use]
    #[allow(
        clippy::cast_precision_loss,
        reason = "row counts stay far below f64's exact-integer range"
    )]
    pub fn per_event(&self) -> Option<(f64, f64)> {
        (self.events > 0).then(|| {
            (
                self.rows_read as f64 / self.events as f64,
                self.rows_written as f64 / self.events as f64,
            )
        })
    }
}

/// One phase's cost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseCost {
    /// Per event kind.
    pub kinds: Vec<KindCost>,
    /// Every other operation the phase ran (observers excluded).
    pub other_ops: Vec<SchedulerLedgerOp>,
    /// `rowsRead` over every counted operation.
    pub rows_read: u64,
    /// `rowsWritten` over every counted operation.
    pub rows_written: u64,
    /// `build-crate.yml` runs the local CI was dispatched during the
    /// phase — one per task — the completions the phase must have
    /// paid.
    pub tasks: u64,
    /// Wall milliseconds from the phase's first to its last ledger read.
    pub wall_ms: u64,
}

impl PhaseCost {
    /// Scheduler calls the phase was billed: every counted operation's
    /// events, the four kinds and the rest alike. Observers are already
    /// out of both.
    #[must_use]
    pub fn requests(&self) -> u64 {
        self.kinds.iter().map(|kind| kind.events).sum::<u64>()
            + self.other_ops.iter().map(|op| op.events).sum::<u64>()
    }
}

/// One layer of the wave: the builds one publish round released, their
/// completions, and the round's report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerCost {
    /// 1-based layer number.
    pub layer: usize,
    /// Task ids the layer's round first published.
    pub published: u64,
    /// `build-crate.yml` runs dispatched during the layer — one per
    /// task.
    pub tasks: u64,
    /// Per event kind.
    pub kinds: Vec<KindCost>,
}

/// One lane's submit cost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneCost {
    /// Which lane, and in which phase.
    pub lane: String,
    /// `wave` or `resubmit`.
    pub phase: String,
    /// Tasks posted.
    pub submitted: u64,
    /// Queue rows the lane's submit inserted.
    pub inserted: u64,
    /// `queue_dependencies` rows the lane's submit wrote.
    pub inserted_edges: u64,
    /// The submit kind's cost while the lane ran.
    pub submit: KindCost,
    /// Wall milliseconds the lane took.
    pub wall_ms: u64,
}

/// One gate outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    /// What was checked.
    pub name: String,
    /// Whether it held.
    pub passed: bool,
    /// The measured numbers, or why it failed.
    pub detail: String,
}

/// `preheat-cost-report.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreheatCostReport {
    /// The rustc the wave built for.
    pub rustc_version: String,
    /// Distinct nodes the wave submitted.
    pub nodes: u64,
    /// Nodes per target triple.
    pub nodes_per_target: BTreeMap<String, u64>,
    /// The wave's totals.
    pub wave: PhaseCost,
    /// The resubmit's totals.
    pub resubmit: PhaseCost,
    /// The wave, layer by layer.
    pub layers: Vec<LayerCost>,
    /// Each lane's submit, both phases.
    pub lanes: Vec<LaneCost>,
    /// Every gate, passed or not.
    pub checks: Vec<Check>,
}

impl PreheatCostReport {
    /// The checks that failed.
    pub fn failures(&self) -> impl Iterator<Item = &Check> {
        self.checks.iter().filter(|check| !check.passed)
    }
}

/// `later − earlier`, per operation. An operation missing from either
/// side is at zero there.
///
/// # Errors
/// An operation's counters went backwards — the ledger was reset under
/// the run, and every difference after that is meaningless.
pub fn ledger_delta(
    earlier: &SchedulerLedger,
    later: &SchedulerLedger,
) -> crate::error::Result<Vec<SchedulerLedgerOp>> {
    if earlier.woken_at_ms != later.woken_at_ms {
        return Err(crate::stow_error!(
            "probe ledger reloaded between two reads (graph woken at {} ms, then at {} ms) \
             with no edge restart recorded around it: every booking since its last snapshot \
             was dropped — the ledger was reset mid-run",
            earlier.woken_at_ms,
            later.woken_at_ms
        ));
    }
    let before: BTreeMap<&str, &SchedulerLedgerOp> =
        earlier.ops.iter().map(|op| (op.op.as_str(), op)).collect();
    if let Some(lost) = earlier
        .ops
        .iter()
        .find(|op| op.events > 0 && !later.ops.iter().any(|later| later.op == op.op))
    {
        return Err(crate::stow_error!(
            "probe ledger {} went from {} events to none: the ledger was reset mid-run",
            lost.op,
            lost.events
        ));
    }
    later
        .ops
        .iter()
        .map(|op| {
            let (events, read, written) = before
                .get(op.op.as_str())
                .map_or((0, 0, 0), |b| (b.events, b.rows_read, b.rows_written));
            let delta = |now: u64, then: u64, what: &str| {
                now.checked_sub(then).ok_or_else(|| {
                    crate::stow_error!(
                        "probe ledger {} {what} went from {then} to {now}: the ledger was reset mid-run",
                        op.op
                    )
                })
            };
            Ok(SchedulerLedgerOp {
                op: op.op.clone(),
                events: delta(op.events, events, "events")?,
                rows_read: delta(op.rows_read, read, "rowsRead")?,
                rows_written: delta(op.rows_written, written, "rowsWritten")?,
            })
        })
        .filter(|op| op.as_ref().map_or(true, |op| op.events > 0))
        .collect()
}

/// `base + delta`, per operation.
fn ledger_sum(base: &SchedulerLedger, delta: &[SchedulerLedgerOp]) -> SchedulerLedger {
    let mut ops: BTreeMap<&str, SchedulerLedgerOp> = base
        .ops
        .iter()
        .map(|op| (op.op.as_str(), op.clone()))
        .collect();
    for op in delta {
        let sum = ops
            .entry(op.op.as_str())
            .or_insert_with(|| SchedulerLedgerOp {
                op: op.op.clone(),
                events: 0,
                rows_read: 0,
                rows_written: 0,
            });
        sum.events += op.events;
        sum.rows_read += op.rows_read;
        sum.rows_written += op.rows_written;
    }
    SchedulerLedger {
        woken_at_ms: base.woken_at_ms,
        ops: ops.into_values().collect(),
    }
}

/// The run's ledger reads on one continuous timeline: each read after
/// an [`EdgeRestart`] is carried across it, so the run reports the
/// totals it would have without the restart. A carried read answers the
/// first graph's `woken_at_ms`, so [`ledger_delta`] still refuses any
/// pair of reads a reload separates that no recorded restart explains.
struct Timeline<'a> {
    restarts: &'a [EdgeRestart],
    /// Per restart, its `before` read already carried across every
    /// earlier restart — what the edge had booked when it stopped.
    carried: Vec<SchedulerLedger>,
}

impl<'a> Timeline<'a> {
    /// # Errors
    /// The restarts are out of order or overlap, or a restart's `before`
    /// read went backwards against an earlier restart's `after`.
    fn new(restarts: &'a [EdgeRestart]) -> crate::error::Result<Self> {
        let mut timeline = Self {
            restarts,
            carried: Vec::with_capacity(restarts.len()),
        };
        for (index, restart) in restarts.iter().enumerate() {
            if restart.after.taken_at_ms <= restart.before.taken_at_ms {
                return Err(crate::stow_error!(
                    "edge restart {}: its after read ({} ms) does not follow its before read ({} ms)",
                    index + 1,
                    restart.after.taken_at_ms,
                    restart.before.taken_at_ms
                ));
            }
            if let Some(previous) = index.checked_sub(1).map(|previous| &restarts[previous])
                && restart.before.taken_at_ms <= previous.after.taken_at_ms
            {
                return Err(crate::stow_error!(
                    "edge restart {} began ({} ms) before restart {index} ended ({} ms)",
                    index + 1,
                    restart.before.taken_at_ms,
                    previous.after.taken_at_ms
                ));
            }
            let carried = timeline.carry(&restart.before, index)?;
            timeline.carried.push(carried);
        }
        Ok(timeline)
    }

    /// `snapshot`'s ledger carried across the first `restarts` restarts.
    fn carry(
        &self,
        snapshot: &LedgerSnapshot,
        restarts: usize,
    ) -> crate::error::Result<SchedulerLedger> {
        let at = snapshot.taken_at_ms;
        let last = self.restarts[..restarts]
            .iter()
            .rposition(|restart| restart.before.taken_at_ms < at);
        let Some(last) = last else {
            return Ok(snapshot.ledger.clone());
        };
        let restart = &self.restarts[last];
        if at < restart.after.taken_at_ms {
            return Err(crate::stow_error!(
                "a ledger read at {at} ms fell inside edge restart {} ({} → {} ms)",
                last + 1,
                restart.before.taken_at_ms,
                restart.after.taken_at_ms
            ));
        }
        Ok(ledger_sum(
            &self.carried[last],
            &ledger_delta(&restart.after.ledger, &snapshot.ledger)?,
        ))
    }

    /// `snapshot` on the continuous timeline.
    fn snapshot(&self, snapshot: &LedgerSnapshot) -> crate::error::Result<LedgerSnapshot> {
        Ok(LedgerSnapshot {
            taken_at_ms: snapshot.taken_at_ms,
            ledger: self.carry(snapshot, self.restarts.len())?,
        })
    }

    /// Every ledger read of `phase` on the continuous timeline.
    fn phase(&self, phase: &PhaseObservations) -> crate::error::Result<PhaseObservations> {
        Ok(PhaseObservations {
            start: self.snapshot(&phase.start)?,
            rounds: phase
                .rounds
                .iter()
                .map(|round| {
                    Ok(Round {
                        before_report: self.snapshot(&round.before_report)?,
                        end: self.snapshot(&round.end)?,
                        published: round.published.clone(),
                    })
                })
                .collect::<crate::error::Result<_>>()?,
            lanes: phase
                .lanes
                .iter()
                .map(|lane| {
                    Ok(LaneRun {
                        before: self.snapshot(&lane.before)?,
                        after: self.snapshot(&lane.after)?,
                        ..lane.clone()
                    })
                })
                .collect::<crate::error::Result<_>>()?,
            end: self.snapshot(&phase.end)?,
        })
    }
}

/// No build was dispatched while the edge restarted: the dispatch's
/// alarm booked into a ledger neither of the restart's reads holds.
fn restart_check(observed: &WaveObservations) -> Check {
    let dispatched: Vec<String> = observed
        .restarts
        .iter()
        .enumerate()
        .filter_map(|(index, restart)| {
            let builds = build_tasks_between(
                &observed.runs,
                restart.before.taken_at_ms,
                restart.after.taken_at_ms,
            );
            (builds > 0).then(|| format!("restart {}: {builds} build runs", index + 1))
        })
        .collect();
    check(
        "No build dispatched during an edge restart",
        dispatched.is_empty(),
        if dispatched.is_empty() {
            format!(
                "{} edge restarts, each with nothing dispatched",
                observed.restarts.len()
            )
        } else {
            dispatched.join("; ")
        },
    )
}

fn kind_costs(ops: &[SchedulerLedgerOp]) -> Vec<KindCost> {
    EventKind::ALL
        .iter()
        .map(|&kind| {
            let op = ops.iter().find(|op| op.op == kind.ledger_op());
            KindCost {
                kind,
                events: op.map_or(0, |op| op.events),
                rows_read: op.map_or(0, |op| op.rows_read),
                rows_written: op.map_or(0, |op| op.rows_written),
            }
        })
        .collect()
}

fn kind(costs: &[KindCost], kind: EventKind) -> &KindCost {
    costs
        .iter()
        .find(|cost| cost.kind == kind)
        .expect("kind_costs yields every EventKind")
}

/// The `build-crate.yml` runs dispatched in `(from_ms, to_ms]` — one
/// per task. Other workflows the local CI ran (a request's resolve)
/// are not builds.
fn build_tasks_between(runs: &[LocalCiRun], from_ms: u64, to_ms: u64) -> u64 {
    let path = format!(
        ".github/workflows/{}",
        crate::trusted_builder::WORKFLOW_FILE
    );
    runs.iter()
        .filter(|run| {
            run.path == path && run.dispatched_at_ms > from_ms && run.dispatched_at_ms <= to_ms
        })
        .count() as u64
}

fn phase_cost(phase: &PhaseObservations, runs: &[LocalCiRun]) -> crate::error::Result<PhaseCost> {
    let ops = ledger_delta(&phase.start.ledger, &phase.end.ledger)?;
    let counted: Vec<&SchedulerLedgerOp> = ops
        .iter()
        .filter(|op| !OBSERVER_OPS.contains(&op.op.as_str()))
        .collect();
    let other_ops = counted
        .iter()
        .filter(|op| !EventKind::ALL.iter().any(|kind| kind.ledger_op() == op.op))
        .map(|op| (*op).clone())
        .collect();
    let tasks = build_tasks_between(runs, phase.start.taken_at_ms, phase.end.taken_at_ms);
    Ok(PhaseCost {
        kinds: kind_costs(&ops),
        other_ops,
        rows_read: counted.iter().map(|op| op.rows_read).sum(),
        rows_written: counted.iter().map(|op| op.rows_written).sum(),
        tasks,
        wall_ms: phase
            .end
            .taken_at_ms
            .saturating_sub(phase.start.taken_at_ms),
    })
}

fn layers(phase: &PhaseObservations, runs: &[LocalCiRun]) -> crate::error::Result<Vec<LayerCost>> {
    let mut previous = &phase.start;
    let mut out = Vec::with_capacity(phase.rounds.len());
    for (index, round) in phase.rounds.iter().enumerate() {
        let ops = ledger_delta(&previous.ledger, &round.end.ledger)?;
        out.push(LayerCost {
            layer: index + 1,
            published: round.published.len() as u64,
            tasks: build_tasks_between(runs, previous.taken_at_ms, round.end.taken_at_ms),
            kinds: kind_costs(&ops),
        });
        previous = &round.end;
    }
    Ok(out)
}

fn lane_costs(phase_name: &str, phase: &PhaseObservations) -> crate::error::Result<Vec<LaneCost>> {
    phase
        .lanes
        .iter()
        .map(|lane| {
            let ops = ledger_delta(&lane.before.ledger, &lane.after.ledger)?;
            Ok(LaneCost {
                lane: lane.lane.clone(),
                phase: phase_name.to_owned(),
                submitted: lane.submitted,
                inserted: lane.inserted,
                inserted_edges: lane.inserted_edges,
                submit: kind(&kind_costs(&ops), EventKind::Submit).clone(),
                wall_ms: lane
                    .after
                    .taken_at_ms
                    .saturating_sub(lane.before.taken_at_ms),
            })
        })
        .collect()
}

fn check(name: impl Into<String>, passed: bool, detail: impl Into<String>) -> Check {
    Check {
        name: name.into(),
        passed,
        detail: detail.into(),
    }
}

/// Every build run a phase dispatched completes through exactly one
/// `POST /tasks/complete-run`, and nothing else books one —
/// the count the projection prices completions at. Fewer means a
/// completion never reached the scheduler or was booked under another
/// ledger key; more means a run's completion was paid twice.
fn completions_check(name: &str, cost: &PhaseCost) -> Check {
    let completions = kind(&cost.kinds, EventKind::Completion).events;
    check(
        name,
        completions == cost.tasks,
        format!(
            "{completions} completions booked under `{}`, {} build runs dispatched",
            EventKind::Completion.ledger_op(),
            cost.tasks
        ),
    )
}

/// Per-event growth first → last layer for the kinds whose events
/// scale with what they carry: completions and slice reports. The
/// alarm pass is fixed-size and held to its drive budget in every layer
/// instead ([`drive_checks`]); since the in-memory scheduler a slice
/// report dispatches the dependents it releases in its own turn
/// (stow#878), so the alarm may dispatch in the first layer alone.
fn growth_checks(layers: &[LayerCost]) -> Vec<Check> {
    [EventKind::Completion, EventKind::SliceReport]
        .iter()
        .map(|&event| {
            let measured: Vec<(usize, (f64, f64))> = layers
                .iter()
                .filter_map(|layer| {
                    kind(&layer.kinds, event)
                        .per_event()
                        .map(|rate| (layer.layer, rate))
                })
                .collect();
            let name = format!("{event:?} per-event cost flat across layers");
            match (measured.first(), measured.last()) {
                (Some(&(first, (r0, w0))), Some(&(last, (r1, w1)))) if first != last => {
                    let passed = !grew(r0, r1) && !grew(w0, w1);
                    check(
                        name,
                        passed,
                        format!(
                            "layer {first}: {r0:.1} read / {w0:.1} written per event; \
                         layer {last}: {r1:.1} read / {w1:.1} written (tolerance 10% + 50 rows)"
                        ),
                    )
                }
                _ => check(
                    name,
                    false,
                    format!(
                        "{event:?} events landed in {} layer(s); flatness needs two",
                        measured.len()
                    ),
                ),
            }
        })
        .collect()
}

/// Submit cost per inserted unit — a queue row or a dependency edge —
/// first lane → last lane. A deduplicated submission moves nothing, so
/// the posted count cannot normalize a submit: lanes whose insert shares
/// differ would read as different per-row costs while paying the same
/// per row (stow#773). The tolerance's fixed rows apply per submit
/// event, spread over the units the lane inserted.
#[allow(
    clippy::cast_precision_loss,
    reason = "row and task counts stay far below f64's exact-integer range"
)]
fn submit_growth_check(lanes: &[LaneCost]) -> Check {
    let measured: Vec<&LaneCost> = lanes
        .iter()
        .filter(|lane| lane.phase == "wave" && lane.inserted > 0 && lane.submit.events > 0)
        .collect();
    let name = "Submit per-inserted-unit cost flat across lanes";
    let (Some(first), Some(last)) = (measured.first(), measured.last()) else {
        return check(name, false, "no wave lane inserted a task");
    };
    let units = |lane: &LaneCost| (lane.inserted + lane.inserted_edges) as f64;
    let per_unit = |lane: &LaneCost| {
        (
            lane.submit.rows_read as f64 / units(lane),
            lane.submit.rows_written as f64 / units(lane),
        )
    };
    let (r0, w0) = per_unit(first);
    let (r1, w1) = per_unit(last);
    let slack = crate::do_budgets::GROWTH_TOLERANCE_ROWS * last.submit.events as f64 / units(last);
    let over = |earlier: f64, later: f64| {
        later > earlier.mul_add(1.0 + crate::do_budgets::GROWTH_TOLERANCE_FRACTION, slack)
    };
    check(
        name,
        !over(r0, r1) && !over(w0, w1),
        format!(
            "{}: {r0:.2} read / {w0:.2} written per inserted unit; \
             {}: {r1:.2} read / {w1:.2} written \
             (tolerance 10% + {slack:.2} rows per unit)",
            first.lane, last.lane
        ),
    )
}

/// The fixed-size kinds' per-event average in every layer against their
/// stow#433 drive budget.
fn drive_checks(layers: &[LayerCost]) -> Vec<Check> {
    EventKind::ALL
        .iter()
        .filter_map(|&event| event.drive().map(|drive| (event, drive)))
        .map(|(event, drive)| {
            let budget = DO_BUDGETS
                .iter()
                .find(|budget| budget.name == drive)
                .expect("EventKind::drive names a DO_BUDGETS row");
            let breaches: Vec<String> = layers
                .iter()
                .filter_map(|layer| {
                    let (read, written) = kind(&layer.kinds, event).per_event()?;
                    #[allow(
                        clippy::cast_precision_loss,
                        reason = "budget rows stay far below f64's exact-integer range"
                    )]
                    let over =
                        read > budget.rows_read as f64 || written > budget.rows_written as f64;
                    over.then(|| {
                        format!(
                            "layer {}: {read:.0} read / {written:.0} written per event",
                            layer.layer
                        )
                    })
                })
                .collect();
            check(
                format!("{event:?} per-event cost within the `{drive}` drive budget"),
                breaches.is_empty(),
                if breaches.is_empty() {
                    format!(
                        "every layer within {} read / {} written",
                        budget.rows_read, budget.rows_written
                    )
                } else {
                    format!(
                        "budget {} read / {} written; {}",
                        budget.rows_read,
                        budget.rows_written,
                        breaches.join("; ")
                    )
                },
            )
        })
        .collect()
}

/// The marker the build stage's foreign-unit refusal prints — a build
/// that had to compile a dependency because it was not served.
const FOREIGN_UNIT_MARKER: &str = "not the task's own crate";

/// No node may be dispatched before every dependency is in a published
/// slice: a dispatch at `t` sees exactly the task ids rounds published
/// whose report began at or before `t`.
fn order_check(observed: &WaveObservations) -> Check {
    let rounds: Vec<&Round> = observed
        .wave
        .rounds
        .iter()
        .chain(&observed.resubmit.rounds)
        .collect();
    let mut violations = Vec::new();
    for run in &observed.runs {
        let available: BTreeSet<&String> = rounds
            .iter()
            .filter(|round| round.before_report.taken_at_ms <= run.dispatched_at_ms)
            .flat_map(|round| &round.published)
            .collect();
        let Some(task_id) = run.task_id.as_deref() else {
            continue;
        };
        let Some(node) = observed.nodes.get(task_id) else {
            continue;
        };
        let missing: Vec<&String> = node
            .dependencies
            .iter()
            .filter(|dep| !available.contains(dep))
            .collect();
        if !missing.is_empty() {
            violations.push(format!(
                "{task_id} dispatched at {} before {} of its dependencies were published (first: {})",
                run.dispatched_at_ms,
                missing.len(),
                missing[0]
            ));
        }
        if let Some(error) = run
            .error
            .as_deref()
            .filter(|error| error.contains(FOREIGN_UNIT_MARKER))
        {
            violations.push(format!("{task_id} compiled a dependency itself: {error}"));
        }
    }
    check(
        "No node dispatched before its dependencies were published",
        violations.is_empty(),
        if violations.is_empty() {
            format!(
                "{} tasks checked",
                observed
                    .runs
                    .iter()
                    .filter(|run| run.task_id.is_some())
                    .count()
            )
        } else {
            summarise(&violations)
        },
    )
}

fn published_check(observed: &WaveObservations) -> Check {
    let missing: Vec<String> = observed
        .nodes
        .keys()
        .filter(|task_id| !observed.covered.contains(*task_id))
        .map(|task_id| {
            // The run's own error — the build's, the dispatch's or a
            // webhook delivery's — names why the task never published.
            let last_error = observed
                .runs
                .iter()
                .filter(|run| run.task_id.as_deref() == Some(task_id.as_str()))
                .filter_map(|run| run.error.as_deref())
                .next_back();
            last_error.map_or_else(
                || format!("{task_id}: never published"),
                |error| format!("{task_id}: {error}"),
            )
        })
        .collect();
    check(
        "Every submitted node published",
        missing.is_empty(),
        if missing.is_empty() {
            format!("{} nodes served by the final slices", observed.nodes.len())
        } else {
            format!(
                "{} of {} unpublished: {}",
                missing.len(),
                observed.nodes.len(),
                summarise(&missing)
            )
        },
    )
}

fn overload_check(observed: &WaveObservations) -> Check {
    let mut sightings = observed.overload_sightings.clone();
    for run in &observed.runs {
        sightings.extend(
            run.delivery_errors
                .iter()
                .filter(|error| error.to_ascii_lowercase().contains("overload"))
                .map(|error| format!("{} webhook: {error}", run.display_title)),
        );
    }
    for lane in observed.wave.lanes.iter().chain(&observed.resubmit.lanes) {
        sightings.extend(
            lane.submit_failures
                .iter()
                .filter(|failure| failure.to_ascii_lowercase().contains("overload"))
                .map(|failure| format!("{} submit: {failure}", lane.lane)),
        );
    }
    check(
        "The Durable Object never answered overloaded",
        sightings.is_empty(),
        if sightings.is_empty() {
            "none".to_owned()
        } else {
            summarise(&sightings)
        },
    )
}

fn submit_failure_check(observed: &WaveObservations) -> Check {
    let failures: Vec<String> = observed
        .wave
        .lanes
        .iter()
        .chain(&observed.resubmit.lanes)
        .flat_map(|lane| {
            lane.submit_failures
                .iter()
                .map(move |failure| format!("{}: {failure}", lane.lane))
        })
        .collect();
    check(
        "Every lane's submit landed",
        failures.is_empty(),
        if failures.is_empty() {
            "none failed".to_owned()
        } else {
            summarise(&failures)
        },
    )
}

/// The first few lines of a long list, and how many were left out.
fn summarise(lines: &[String]) -> String {
    const SHOWN: usize = 10;
    let shown = lines
        .iter()
        .take(SHOWN)
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");
    if lines.len() > SHOWN {
        format!("{shown}; … and {} more", lines.len() - SHOWN)
    } else {
        shown
    }
}

/// Build the report and run every check.
///
/// # Errors
/// A ledger snapshot went backwards between two reads.
pub fn analyse(observed: &WaveObservations) -> crate::error::Result<PreheatCostReport> {
    let nodes = observed.nodes.len() as u64;
    let mut nodes_per_target = BTreeMap::<String, u64>::new();
    for node in observed.nodes.values() {
        *nodes_per_target.entry(node.target.clone()).or_default() += 1;
    }
    let timeline = Timeline::new(&observed.restarts)?;
    let wave_reads = timeline.phase(&observed.wave)?;
    let resubmit_reads = timeline.phase(&observed.resubmit)?;
    let wave = phase_cost(&wave_reads, &observed.runs)?;
    let resubmit = phase_cost(&resubmit_reads, &observed.runs)?;
    let layers = layers(&wave_reads, &observed.runs)?;
    let mut lanes = lane_costs("wave", &wave_reads)?;
    lanes.extend(lane_costs("resubmit", &resubmit_reads)?);

    let mut checks = vec![
        check(
            "Resubmit rebuilt nothing",
            resubmit.tasks == 0,
            format!("{} build runs dispatched by the resubmit", resubmit.tasks),
        ),
        completions_check("Wave completions equal its build runs", &wave),
        completions_check("Resubmit completions equal its build runs", &resubmit),
        check(
            "Wave ran in at least three layers",
            layers.len() >= 3,
            format!("{} layers", layers.len()),
        ),
    ];
    checks.extend(growth_checks(&layers));
    checks.push(submit_growth_check(&lanes));
    checks.extend(drive_checks(&layers));
    checks.push(restart_check(observed));
    checks.push(order_check(observed));
    checks.push(published_check(observed));
    checks.push(overload_check(observed));
    checks.push(submit_failure_check(observed));

    Ok(PreheatCostReport {
        rustc_version: observed.rustc_version.clone(),
        nodes,
        nodes_per_target,
        wave,
        resubmit,
        layers,
        lanes,
        checks,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{
        EventKind, LaneRun, LedgerSnapshot, Node, PhaseObservations, ProductionLane,
        ProductionTask, Round, WaveObservations, analyse, count_production, ledger_delta,
    };
    use crate::api::{SchedulerLedger, SchedulerLedgerOp};
    use crate::local_ci::LocalCiRun;

    /// A ledger whose kinds each ran `events` times — completions
    /// `completions` times, one per build run — at `rate` rows read and
    /// one written per event, plus `completion_extra` reads on
    /// completions.
    fn ledger(events: u64, completions: u64, rate: u64, completion_extra: u64) -> SchedulerLedger {
        SchedulerLedger {
            woken_at_ms: 0,
            ops: EventKind::ALL
                .iter()
                .map(|kind| {
                    let (events, extra) = if *kind == EventKind::Completion {
                        (completions, completion_extra)
                    } else {
                        (events, 0)
                    };
                    SchedulerLedgerOp {
                        op: kind.ledger_op().to_owned(),
                        events,
                        rows_read: events * rate + extra,
                        rows_written: events,
                    }
                })
                .collect(),
        }
    }

    fn snapshot(at: u64, ledger: SchedulerLedger) -> LedgerSnapshot {
        LedgerSnapshot {
            taken_at_ms: at,
            ledger,
        }
    }

    fn run(task_id: &str, dispatched_at_ms: u64) -> LocalCiRun {
        LocalCiRun {
            workflow_run_id: dispatched_at_ms,
            // A real build run's title — `<rustc>-<task_id>`.
            display_title: format!("1.99.1-{task_id}"),
            status: "completed".to_owned(),
            conclusion: Some("success".to_owned()),
            built: true,
            html_url: String::new(),
            path: ".github/workflows/build-crate.yml".to_owned(),
            dispatched_at_ms,
            completed_at_ms: Some(dispatched_at_ms + 1),
            error: None,
            delivery_errors: Vec::new(),
            task_id: Some(task_id.to_owned()),
            triggering_actor_login: crate::local_ci::SEEDED_RUN_OPERATOR_LOGIN.to_owned(),
        }
    }

    /// A three-layer chain a → b → c, one build run per node:
    /// each layer runs 10 events per kind and one completion at 2 rows
    /// each; `completion_growth` adds that many reads to each later
    /// layer's completion in total.
    fn chain(completion_growth: u64) -> WaveObservations {
        let nodes = BTreeMap::from([
            (
                "a".to_owned(),
                Node {
                    target: "x86_64-unknown-linux-gnu".to_owned(),
                    dependencies: vec![],
                },
            ),
            (
                "b".to_owned(),
                Node {
                    target: "x86_64-unknown-linux-gnu".to_owned(),
                    dependencies: vec!["a".to_owned()],
                },
            ),
            (
                "c".to_owned(),
                Node {
                    target: "x86_64-unknown-linux-gnu".to_owned(),
                    dependencies: vec!["b".to_owned()],
                },
            ),
        ]);
        let start = snapshot(0, SchedulerLedger::default());
        let rounds: Vec<Round> = (1..=3u64)
            .map(|layer| Round {
                before_report: snapshot(layer * 100 - 10, ledger(layer * 10, layer - 1, 2, 0)),
                end: snapshot(
                    layer * 100,
                    ledger(
                        layer * 10,
                        layer,
                        2,
                        completion_growth * (layer - 1) * layer / 2,
                    ),
                ),
                published: BTreeSet::from([
                    ["a", "b", "c"][usize::try_from(layer - 1).unwrap()].to_owned()
                ]),
            })
            .collect();
        let end = rounds.last().unwrap().end.clone();
        let lane = LaneRun {
            lane: "top-binaries".to_owned(),
            submitted: 3,
            inserted: 3,
            inserted_edges: 2,
            submit_failures: vec![],
            before: start.clone(),
            after: snapshot(5, ledger(1, 0, 2, 0)),
        };
        WaveObservations {
            rustc_version: "1.99.1".to_owned(),
            nodes,
            wave: PhaseObservations {
                start,
                rounds,
                lanes: vec![lane.clone(), lane],
                end: end.clone(),
            },
            resubmit: PhaseObservations {
                start: end.clone(),
                rounds: vec![],
                lanes: vec![],
                end: snapshot(400, end.ledger),
            },
            // a dispatches before round 1; b after round 1's report
            // began; c after round 2's.
            restarts: vec![],
            runs: vec![run("a", 10), run("b", 95), run("c", 195)],
            covered: BTreeSet::from(["a".to_owned(), "b".to_owned(), "c".to_owned()]),
            overload_sightings: vec![],
        }
    }

    /// One edge restart a test replays: it stops right after `stop_at`,
    /// when the never-restarted ledger stood at `truth`, and the new
    /// edge's first ledger read, at `after_at`, answers `reloaded` — its
    /// last snapshot plus the readiness poll that woke it.
    struct Replayed {
        stop_at: u64,
        after_at: u64,
        truth: SchedulerLedger,
        reloaded: SchedulerLedger,
    }

    /// What the restarted edge answers at `at` for the never-restarted
    /// `truth`: the last restart's reloaded ledger plus everything
    /// booked since it stopped.
    fn answered(truth: &SchedulerLedger, at: u64, restarts: &[Replayed]) -> SchedulerLedger {
        restarts
            .iter()
            .rev()
            .find(|restart| restart.after_at <= at)
            .map_or_else(
                || truth.clone(),
                |restart| {
                    super::ledger_sum(
                        &restart.reloaded,
                        &ledger_delta(&restart.truth, truth).expect("truth only grows"),
                    )
                },
            )
    }

    /// `observed` as the restarted edge would have answered it, with the
    /// restarts recorded the way `scripts/preheat-cost.sh` records them.
    fn restarted(mut observed: WaveObservations, restarts: &[Replayed]) -> WaveObservations {
        let answer = |read: &mut LedgerSnapshot| {
            read.ledger = answered(&read.ledger, read.taken_at_ms, restarts);
        };
        for phase in [&mut observed.wave, &mut observed.resubmit] {
            answer(&mut phase.start);
            answer(&mut phase.end);
            for round in &mut phase.rounds {
                answer(&mut round.before_report);
                answer(&mut round.end);
            }
            for lane in &mut phase.lanes {
                answer(&mut lane.before);
                answer(&mut lane.after);
            }
        }
        observed.restarts = restarts
            .iter()
            .map(|restart| super::EdgeRestart {
                before: snapshot(
                    restart.stop_at,
                    answered(&restart.truth, restart.stop_at, restarts),
                ),
                after: snapshot(restart.after_at, restart.reloaded.clone()),
            })
            .collect();
        observed
    }

    /// The edge's last snapshot `ledger` as the graph woken at
    /// `woken_at_ms` holds it, plus the readiness poll and the ledger
    /// read that woke it.
    fn reloaded(mut ledger: SchedulerLedger, woken_at_ms: i64) -> SchedulerLedger {
        ledger.woken_at_ms = woken_at_ms;
        for op in ["GET /budget/ledger", "GET /status"] {
            ledger.ops.push(SchedulerLedgerOp {
                op: op.to_owned(),
                events: 1,
                rows_read: 500,
                rows_written: 0,
            });
        }
        ledger.ops.sort_by(|a, b| a.op.cmp(&b.op));
        ledger
    }

    /// Two restarts — one mid-wave, after layer 1; one between the
    /// wave's end and the resubmit's — each reloading a snapshot older
    /// than the ledger it stopped with.
    fn two_restarts(observed: &WaveObservations) -> Vec<Replayed> {
        vec![
            Replayed {
                stop_at: 150,
                after_at: 160,
                truth: observed.wave.rounds[0].end.ledger.clone(),
                reloaded: reloaded(ledger(4, 0, 2, 0), 158),
            },
            Replayed {
                stop_at: 330,
                after_at: 340,
                truth: observed.wave.end.ledger.clone(),
                reloaded: reloaded(ledger(25, 1, 2, 0), 338),
            },
        ]
    }

    fn production_lane(lane: &str, tasks: &[(&str, &str)]) -> ProductionLane {
        ProductionLane {
            lane: lane.to_owned(),
            tasks: tasks
                .iter()
                .map(|(task_id, target)| ProductionTask {
                    task_id: (*task_id).to_owned(),
                    target: (*target).to_owned(),
                })
                .collect(),
        }
    }

    fn failed(report: &super::PreheatCostReport) -> Vec<&str> {
        report.failures().map(|check| check.name.as_str()).collect()
    }

    #[test]
    fn a_flat_ordered_wave_passes() {
        let report = analyse(&chain(0)).expect("analyse");
        assert_eq!(report.layers.len(), 3);
        // The submit lane names one lane twice; only the lane-growth
        // check reads it, and equal lanes are flat.
        assert!(failed(&report).is_empty(), "{:?}", report.checks);
    }

    #[test]
    fn a_completion_that_scans_the_queue_fails_growth() {
        // Each later layer's 10 completions read 100 more rows each.
        let report = analyse(&chain(1_000)).expect("analyse");
        assert!(
            failed(&report).contains(&"Completion per-event cost flat across layers"),
            "{:?}",
            report.checks
        );
    }

    #[test]
    fn a_premature_dispatch_fails_the_order_check() {
        let mut observed = chain(0);
        // c dispatched before round 2 published b.
        observed.runs[2].dispatched_at_ms = 150;
        let report = analyse(&observed).expect("analyse");
        assert_eq!(
            failed(&report),
            ["No node dispatched before its dependencies were published"]
        );
    }

    #[test]
    fn a_foreign_unit_failure_names_only_its_own_task() {
        let mut observed = chain(0);
        // Two failed runs: only a's carries the foreign-unit marker —
        // attribution reads the run's own error.
        let mut a = run("a", 10);
        a.conclusion = Some("failure".to_owned());
        a.error = Some("Error: unit of b is not the task's own crate".to_owned());
        let mut b = run("b", 95);
        b.conclusion = Some("failure".to_owned());
        b.error = Some("Error: rustc failed".to_owned());
        observed.runs[0] = a;
        observed.runs[1] = b;
        let report = analyse(&observed).expect("analyse");
        let order = report
            .checks
            .iter()
            .find(|check| check.name == "No node dispatched before its dependencies were published")
            .expect("the order check ran");
        assert!(!order.passed, "{order:?}");
        assert!(
            order.detail.contains("a compiled a dependency itself"),
            "{order:?}"
        );
        assert!(!order.detail.contains("b compiled"), "{order:?}");
    }

    #[test]
    fn an_unpublished_node_and_an_overload_fail() {
        let mut observed = chain(0);
        observed.covered.remove("c");
        observed.runs[1]
            .delivery_errors
            .push("503: Durable Object is overloaded".to_owned());
        let report = analyse(&observed).expect("analyse");
        let failed = failed(&report);
        assert!(failed.contains(&"Every submitted node published"));
        assert!(failed.contains(&"The Durable Object never answered overloaded"));
    }

    #[test]
    fn a_resubmit_that_rebuilds_fails() {
        let mut observed = chain(0);
        observed.runs.push(run("a", 350));
        let report = analyse(&observed).expect("analyse");
        assert!(failed(&report).contains(&"Resubmit rebuilt nothing"));
    }

    #[test]
    fn a_ledger_that_went_backwards_is_refused() {
        assert!(ledger_delta(&ledger(10, 1, 2, 0), &ledger(5, 1, 2, 0)).is_err());
        // An operation that vanished went back to zero.
        let mut vanished = ledger(10, 1, 2, 0);
        vanished
            .ops
            .retain(|op| op.op != EventKind::SliceReport.ledger_op());
        let error = ledger_delta(&ledger(10, 1, 2, 0), &vanished).unwrap_err();
        assert!(error.to_string().contains("reset mid-run"), "{error}");
        // A reload whose counters all grew past the earlier read's is
        // still a reset: the graph's wake tells it.
        let mut reloaded = ledger(20, 2, 2, 0);
        reloaded.woken_at_ms = 7;
        let error = ledger_delta(&ledger(10, 1, 2, 0), &reloaded).unwrap_err();
        assert!(error.to_string().contains("reset mid-run"), "{error}");
    }

    /// stow#928: a run whose edge restarted reports exactly the totals,
    /// layers and lanes of the same run without the restarts.
    #[test]
    fn edge_restarts_report_the_totals_of_a_run_without_them() {
        let baseline = chain(0);
        let restarts = two_restarts(&baseline);
        let observed = restarted(baseline.clone(), &restarts);
        assert_ne!(
            observed.wave.end.ledger, baseline.wave.end.ledger,
            "the restarted edge answers a different ledger"
        );
        let expected = analyse(&baseline).expect("baseline");
        let report = analyse(&observed).expect("restarted");
        assert_eq!(report.wave, expected.wave);
        assert_eq!(report.resubmit, expected.resubmit);
        assert_eq!(report.layers, expected.layers);
        assert_eq!(report.lanes, expected.lanes);
        let restart_check = report
            .checks
            .iter()
            .find(|check| check.name == "No build dispatched during an edge restart")
            .expect("the restart check");
        assert!(restart_check.passed, "{}", restart_check.detail);
        assert!(
            restart_check.detail.starts_with("2 edge restarts"),
            "{}",
            restart_check.detail
        );
    }

    /// A reset no recorded restart accounts for still fails the report.
    #[test]
    fn a_reset_no_restart_accounts_for_is_refused() {
        let baseline = chain(0);
        let mut observed = restarted(baseline.clone(), &two_restarts(&baseline));
        observed.restarts.remove(0);
        let error = analyse(&observed).unwrap_err();
        assert!(error.to_string().contains("reset mid-run"), "{error}");
        // Nor does a recorded restart excuse a second reset after it.
        let mut observed = restarted(baseline.clone(), &two_restarts(&baseline));
        observed.wave.rounds[2].end.ledger = ledger(1, 0, 2, 0);
        assert!(analyse(&observed).is_err());
    }

    /// A build dispatched while the edge restarted booked an alarm pass
    /// neither restart read holds: the report fails on it.
    #[test]
    fn a_build_dispatched_during_a_restart_fails_the_report() {
        let baseline = chain(0);
        let mut observed = restarted(baseline.clone(), &two_restarts(&baseline));
        observed.runs.push(run("c", 155));
        let report = analyse(&observed).expect("analysed");
        let restart_check = report
            .checks
            .iter()
            .find(|check| check.name == "No build dispatched during an edge restart")
            .expect("the restart check");
        assert!(!restart_check.passed);
        assert_eq!(restart_check.detail, "restart 1: 1 build runs");
    }

    /// Restart records that overlap or run backwards, and a ledger read
    /// taken inside a restart, are refused.
    #[test]
    fn malformed_restart_records_are_refused() {
        let baseline = chain(0);
        let restarts = two_restarts(&baseline);

        let mut observed = restarted(baseline.clone(), &restarts);
        observed.restarts[0].after.taken_at_ms = 150;
        assert!(analyse(&observed).is_err(), "after not following before");

        let mut observed = restarted(baseline.clone(), &restarts);
        observed.restarts[1].before.taken_at_ms = 155;
        assert!(analyse(&observed).is_err(), "overlapping restarts");

        let mut observed = restarted(baseline, &restarts);
        observed.wave.rounds[1].before_report.taken_at_ms = 155;
        let error = analyse(&observed).unwrap_err();
        assert!(
            error.to_string().contains("inside edge restart 1"),
            "{error}"
        );
    }

    #[test]
    fn production_nodes_dedupe_by_task_id_across_lanes() {
        let wave = count_production(&[
            // `a` twice inside the lane: two targets' resolves of the
            // same shared node land on one task id.
            production_lane("top-binaries", &[("a", "t1"), ("b", "t1"), ("a", "t1")]),
            production_lane("projects", &[("a", "t1"), ("b", "t1"), ("c", "t2")]),
        ]);
        assert_eq!(wave.nodes, 3);
        assert_eq!(wave.nodes_per_target["t1"], 2);
        assert_eq!(wave.nodes_per_target["t2"], 1);
        let counts: Vec<(&str, u64, u64)> = wave
            .lanes
            .iter()
            .map(|lane| (lane.lane.as_str(), lane.planned, lane.new_nodes))
            .collect();
        assert_eq!(counts, [("top-binaries", 3, 2), ("projects", 3, 1)]);
    }

    #[test]
    fn a_lane_that_planned_nothing_is_refused() {
        let planned = count_production(&[production_lane("top-binaries", &[("a", "t1")])]);
        planned.require_planned().expect("every lane planned");
        let empty = count_production(&[
            production_lane("top-binaries", &[("a", "t1")]),
            production_lane("projects", &[]),
        ]);
        let error = empty.require_planned().expect_err("an empty lane");
        assert!(error.to_string().contains("projects"), "{error}");
        assert!(count_production(&[]).require_planned().is_err());
    }

    #[test]
    fn a_phase_bills_every_counted_operation_as_a_request() {
        let report = analyse(&chain(0)).expect("analyse");
        // Three kinds at 30 events each over the three layers, and one
        // completion per build run.
        assert_eq!(report.wave.requests(), 3 * 30 + 3);
    }

    #[test]
    fn a_phase_counts_its_build_runs() {
        let mut observed = chain(0);
        // A resolve run is no build.
        let mut resolve = run("x", 96);
        resolve.path = ".github/workflows/resolve-request.yml".to_owned();
        resolve.task_id = None;
        observed.runs.push(resolve);
        let report = analyse(&observed).expect("analyse");
        assert_eq!(report.wave.tasks, 3);
        let layers: Vec<u64> = report.layers.iter().map(|layer| layer.tasks).collect();
        assert_eq!(layers, [2, 1, 0]);
        assert!(failed(&report).is_empty(), "{:?}", report.checks);
    }

    #[test]
    fn a_completion_count_off_the_build_runs_fails() {
        // A fourth build run whose completion never booked.
        let mut observed = chain(0);
        observed.runs.push(run("c", 196));
        let report = analyse(&observed).expect("analyse");
        assert_eq!(failed(&report), ["Wave completions equal its build runs"]);

        // Completions booked under a different op name, as a ledger
        // that keys completions elsewhere books them.
        let mut observed = chain(0);
        for round in &mut observed.wave.rounds {
            for snapshot in [&mut round.before_report, &mut round.end] {
                for op in &mut snapshot.ledger.ops {
                    if op.op == EventKind::Completion.ledger_op() {
                        op.op = "POST /tasks/7/complete-run".to_owned();
                    }
                }
            }
        }
        observed.wave.end = observed.wave.rounds.last().unwrap().end.clone();
        observed.resubmit.start = observed.wave.end.clone();
        observed.resubmit.end.ledger = observed.wave.end.ledger.clone();
        let report = analyse(&observed).expect("analyse");
        assert!(
            failed(&report).contains(&"Wave completions equal its build runs"),
            "{:?}",
            report.checks
        );
    }
}
