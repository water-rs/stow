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

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::api::{SchedulerLedger, SchedulerLedgerOp};
use crate::do_budgets::{DO_BUDGETS, LEDGER_OP_ALARM, PREHEAT_BUDGET, grew};
use crate::local_ci::LocalCiRun;

/// The event kinds a wave is made of, each one scheduler operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A preheat lane's trusted batch submit.
    Submit,
    /// The alarm's dispatch pass.
    Dispatch,
    /// A build's `workflow_run` completion.
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
            Self::Completion => "POST /tasks/complete-run",
            Self::SliceReport => "POST /index/published",
        }
    }

    /// The stow#433 drive whose budget one event of this kind must fit,
    /// for the kinds whose event has a fixed size: one completion is one
    /// task, one alarm pass claims at most the dispatch cap. A submit
    /// batch and a slice report scale with what they carry, so their
    /// fixture drives do not bound a wave's events.
    #[must_use]
    pub const fn drive(self) -> Option<&'static str> {
        match self {
            Self::Completion => Some("POST /tasks/complete-run"),
            Self::Dispatch => Some("alarm pass"),
            Self::Submit | Self::SliceReport => None,
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
    /// `top`, `top-binaries` or `projects`.
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhaseCost {
    /// Per event kind.
    pub kinds: Vec<KindCost>,
    /// Every other operation the phase ran (observers excluded).
    pub other_ops: Vec<SchedulerLedgerOp>,
    /// `rowsRead` over every counted operation.
    pub rows_read: u64,
    /// `rowsWritten` over every counted operation.
    pub rows_written: u64,
    /// The budget's `rowsRead` for this phase at this node count.
    pub budget_rows_read: f64,
    /// The budget's `rowsWritten` for this phase at this node count.
    pub budget_rows_written: f64,
    /// Runs the local CI was dispatched during the phase.
    pub dispatched_runs: u64,
    /// Wall milliseconds from the phase's first to its last ledger read.
    pub wall_ms: u64,
}

/// One layer of the wave: the builds one publish round released, their
/// completions, and the round's report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerCost {
    /// 1-based layer number.
    pub layer: usize,
    /// Task ids the layer's round first published.
    pub published: u64,
    /// Runs dispatched during the layer.
    pub dispatched_runs: u64,
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// `later − earlier`, per operation. An operation missing from
/// `earlier` started at zero.
///
/// # Errors
/// An operation's counters went backwards — the ledger was reset under
/// the run, and every difference after that is meaningless.
pub fn ledger_delta(
    earlier: &SchedulerLedger,
    later: &SchedulerLedger,
) -> crate::error::Result<Vec<SchedulerLedgerOp>> {
    let before: BTreeMap<&str, &SchedulerLedgerOp> =
        earlier.ops.iter().map(|op| (op.op.as_str(), op)).collect();
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

fn runs_between(runs: &[LocalCiRun], from_ms: u64, to_ms: u64) -> u64 {
    runs.iter()
        .filter(|run| run.dispatched_at_ms > from_ms && run.dispatched_at_ms <= to_ms)
        .count() as u64
}

fn phase_cost(
    phase: &PhaseObservations,
    runs: &[LocalCiRun],
    budget: (f64, f64),
) -> crate::error::Result<PhaseCost> {
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
    Ok(PhaseCost {
        kinds: kind_costs(&ops),
        other_ops,
        rows_read: counted.iter().map(|op| op.rows_read).sum(),
        rows_written: counted.iter().map(|op| op.rows_written).sum(),
        budget_rows_read: budget.0,
        budget_rows_written: budget.1,
        dispatched_runs: runs_between(runs, phase.start.taken_at_ms, phase.end.taken_at_ms),
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
            dispatched_runs: runs_between(runs, previous.taken_at_ms, round.end.taken_at_ms),
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

#[allow(
    clippy::cast_precision_loss,
    reason = "row counts stay far below f64's exact-integer range"
)]
fn totals_check(name: &str, cost: &PhaseCost) -> Check {
    let passed = (cost.rows_read as f64) <= cost.budget_rows_read
        && (cost.rows_written as f64) <= cost.budget_rows_written;
    check(
        name,
        passed,
        format!(
            "rowsRead {} of {:.0}, rowsWritten {} of {:.0}",
            cost.rows_read, cost.budget_rows_read, cost.rows_written, cost.budget_rows_written
        ),
    )
}

/// Per-event growth first → last layer for the kinds a layer
/// normalises: alarm passes, completions and slice reports.
fn growth_checks(layers: &[LayerCost]) -> Vec<Check> {
    [
        EventKind::Dispatch,
        EventKind::Completion,
        EventKind::SliceReport,
    ]
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
        let Some((_, task_id)) = crate::records::parse_run_title(&run.display_title) else {
            continue;
        };
        let Some(node) = observed.nodes.get(task_id) else {
            continue;
        };
        let available: BTreeSet<&String> = rounds
            .iter()
            .filter(|round| round.before_report.taken_at_ms <= run.dispatched_at_ms)
            .flat_map(|round| &round.published)
            .collect();
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
        if run
            .error
            .as_deref()
            .is_some_and(|error| error.contains(FOREIGN_UNIT_MARKER))
        {
            violations.push(format!(
                "{task_id} compiled a dependency itself: {}",
                run.error.as_deref().unwrap_or_default()
            ));
        }
    }
    check(
        "No node dispatched before its dependencies were published",
        violations.is_empty(),
        if violations.is_empty() {
            format!("{} runs checked", observed.runs.len())
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
            let last_error = observed
                .runs
                .iter()
                .filter(|run| {
                    crate::records::parse_run_title(&run.display_title)
                        .is_some_and(|(_, id)| id == task_id)
                })
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
    let wave = phase_cost(&observed.wave, &observed.runs, PREHEAT_BUDGET.wave(nodes))?;
    let resubmit = phase_cost(
        &observed.resubmit,
        &observed.runs,
        PREHEAT_BUDGET.resubmit(nodes),
    )?;
    let layers = layers(&observed.wave, &observed.runs)?;
    let mut lanes = lane_costs("wave", &observed.wave)?;
    lanes.extend(lane_costs("resubmit", &observed.resubmit)?);

    let mut checks = vec![
        totals_check("Wave total within the preheat budget", &wave),
        totals_check("Resubmit total within the preheat budget", &resubmit),
        check(
            "Resubmit rebuilt nothing",
            resubmit.dispatched_runs == 0,
            format!(
                "{} runs dispatched by the resubmit",
                resubmit.dispatched_runs
            ),
        ),
        check(
            "Wave ran in at least three layers",
            layers.len() >= 3,
            format!("{} layers", layers.len()),
        ),
    ];
    checks.extend(growth_checks(&layers));
    checks.push(submit_growth_check(&lanes));
    checks.extend(drive_checks(&layers));
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
        EventKind, LaneRun, LedgerSnapshot, Node, PhaseObservations, Round, WaveObservations,
        analyse, ledger_delta,
    };
    use crate::api::{SchedulerLedger, SchedulerLedgerOp};
    use crate::local_ci::LocalCiRun;

    /// A ledger whose four kinds each ran `events` times at `rate` rows
    /// read and one written per event, plus `completion_extra` reads on
    /// completions.
    fn ledger(events: u64, rate: u64, completion_extra: u64) -> SchedulerLedger {
        SchedulerLedger {
            ops: EventKind::ALL
                .iter()
                .map(|kind| {
                    let extra = if *kind == EventKind::Completion {
                        completion_extra
                    } else {
                        0
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
            display_title: format!("1.99.1-{task_id}"),
            status: "completed".to_owned(),
            conclusion: Some("success".to_owned()),
            html_url: String::new(),
            path: ".github/workflows/build-crate.yml".to_owned(),
            dispatched_at_ms,
            completed_at_ms: Some(dispatched_at_ms + 1),
            error: None,
            delivery_errors: Vec::new(),
        }
    }

    /// A three-layer chain a → b → c: each layer runs 10 events per kind
    /// at 20 rows each; `completion_growth` adds that many reads to each
    /// later layer's completions in total.
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
                before_report: snapshot(layer * 100 - 10, ledger(layer * 10, 20, 0)),
                end: snapshot(
                    layer * 100,
                    ledger(layer * 10, 20, completion_growth * (layer - 1) * layer / 2),
                ),
                published: BTreeSet::from([
                    ["a", "b", "c"][usize::try_from(layer - 1).unwrap()].to_owned()
                ]),
            })
            .collect();
        let end = rounds.last().unwrap().end.clone();
        let lane = LaneRun {
            lane: "top".to_owned(),
            submitted: 3,
            inserted: 3,
            inserted_edges: 2,
            submit_failures: vec![],
            before: start.clone(),
            after: snapshot(5, ledger(1, 20, 0)),
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
            runs: vec![run("a", 10), run("b", 95), run("c", 195)],
            covered: BTreeSet::from(["a".to_owned(), "b".to_owned(), "c".to_owned()]),
            overload_sightings: vec![],
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
        assert!(ledger_delta(&ledger(10, 20, 0), &ledger(5, 20, 0)).is_err());
    }
}
