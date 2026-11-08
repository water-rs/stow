//! The preheat share of the monthly projection (stow#775).
//!
//! A stable rustc release invalidates the whole public cache, so each
//! one brings a full preheat wave, and `preheat-cron.yml` resubmits the
//! whole list every day. The Preheat cost job measures both on a
//! reduced wave; the Production wave job resolves the production lanes
//! plan-only for the production node count. This module scales one to
//! the other:
//!
//! ```text
//! monthly = releases/month × (wave cost per node × production nodes + wave trigger)
//!         + days/month    × (resubmit cost per node × production nodes + daily trigger)
//! ```
//!
//! The per-node costs are the report's measured phase totals over the
//! reduced wave's node count. That scaling is valid because the same
//! report proves per-event cost does not grow across layers.
//!
//! A run's completion is paid once per task — one task is one
//! `build-crate.yml` run — so the measured per-node cost already
//! carries the completion its node pays.
//!
//! Scheduler calls and rows are measured. Worker requests follow the
//! production delivery contract, including workflows the local mock
//! does not deliver. Trigger costs are fixed per wave, not per node.
//! Covered phase CPU includes scheduler and observer CPU. Missing build
//! and index lifecycle deliveries use their separately measured lanes.
//! Fixed trigger CPU and Durable Object duration remain unmeasured.

use crate::preheat_cost::MeasuredReport;
use stow_types::forwards::RunForwards;
use stow_types::launch_model::LaunchModel;
use stow_types::preheat_cost::{EventKind, PhaseCost, ProductionWave};

use super::cpu::WorkerCpuReport;

/// CPU of the lifecycle deliveries absent from the captured mock phase.
#[derive(Debug)]
struct LifecycleCpu {
    measured_ms: f64,
    budget_ms: f64,
}

#[expect(
    clippy::cast_precision_loss,
    reason = "phase event counts fit f64 exactly"
)]
fn lifecycle_cpu(phase: &PhaseCost, cpu: &WorkerCpuReport) -> Result<LifecycleCpu, String> {
    let mut result = LifecycleCpu {
        measured_ms: 0.0,
        budget_ms: 0.0,
    };
    for cost in &phase.kinds {
        let lanes: &[&str] = match cost.kind {
            EventKind::Completion => &["build-requested"],
            EventKind::SliceReport => &["index-requested", "index-in-progress", "index-completed"],
            EventKind::Submit | EventKind::Dispatch | EventKind::ExternalRunUpdate => &[],
        };
        for lane in lanes {
            result.measured_ms =
                (cost.events as f64).mul_add(cpu.lane_cpu_ms(lane)?, result.measured_ms);
            result.budget_ms =
                (cost.events as f64).mul_add(cpu.lane_budget_ms(lane)?, result.budget_ms);
        }
    }
    Ok(result)
}

/// A phase's measured cost per node of the wave that measured it.
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct PerNode {
    /// Worker requests, including each build and index run's deliveries.
    pub worker_requests: f64,
    /// Covered isolate CPU, including scheduler and observer work.
    pub worker_cpu_ms: f64,
    /// Captured phase CPU plus missing lifecycle CPU at lane budgets.
    pub worker_cpu_ms_at_lifecycle_budget: f64,
    /// Durable Object calls the phase was billed.
    pub requests: f64,
    /// Durable Object `rowsRead`.
    pub rows_read: f64,
    /// Durable Object `rowsWritten`.
    pub rows_written: f64,
}

impl PerNode {
    /// `phase`'s totals over the `nodes` the wave submitted.
    #[expect(
        clippy::cast_precision_loss,
        reason = "measured counters fit f64 exactly past any wave"
    )]
    fn of(
        phase: &PhaseCost,
        nodes: u64,
        cpu_ms: f64,
        cpu: &WorkerCpuReport,
    ) -> Result<Self, String> {
        if !phase.other_ops.is_empty() {
            return Err(format!(
                "preheat Worker request count has unsupported operations: {:?}",
                phase.other_ops
            ));
        }
        let deliveries = f64::from(RunForwards::DELIVERIES);
        let worker_requests: f64 = phase
            .kinds
            .iter()
            .map(|cost| {
                let requests = match cost.kind {
                    EventKind::Submit => 1.0,
                    EventKind::Completion => deliveries,
                    EventKind::SliceReport => 1.0 + deliveries,
                    // Alarms invoke the object directly. An external
                    // in_progress delivery is already in its completed
                    // build run's lifecycle, not another lifecycle.
                    EventKind::Dispatch | EventKind::ExternalRunUpdate => 0.0,
                };
                cost.events as f64 * requests
            })
            .sum();
        let nodes = nodes as f64;
        let lifecycle = lifecycle_cpu(phase, cpu)?;
        Ok(Self {
            worker_requests: worker_requests / nodes,
            worker_cpu_ms: (cpu_ms + lifecycle.measured_ms) / nodes,
            worker_cpu_ms_at_lifecycle_budget: (cpu_ms + lifecycle.budget_ms) / nodes,
            requests: phase.requests() as f64 / nodes,
            rows_read: phase.rows_read as f64 / nodes,
            rows_written: phase.rows_written as f64 / nodes,
        })
    }
}

/// What preheat adds to a month.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct PreheatMonthly {
    /// Scheduler dispatch call made by the new-release webhook.
    pub wave_trigger_do_requests: f64,
    /// Scheduler dispatch call made by the daily scheduled tick.
    pub resubmit_trigger_do_requests: f64,
    /// New-release webhook plus the preheat-admin run's deliveries.
    pub wave_trigger_worker_requests: f64,
    /// Scheduled tick plus preheat-cron and preheat-admin deliveries.
    pub resubmit_trigger_worker_requests: f64,
    /// Nodes the reduced wave submitted — the denominator of the
    /// per-node costs.
    pub measured_nodes: u64,
    /// Distinct nodes the production lanes plan.
    pub production_nodes: u64,
    /// Stable rustc releases per month, from the launch model's cadence.
    pub releases_per_month: f64,
    /// Daily resubmits per month.
    pub resubmits_per_month: f64,
    /// One wave's cost per node.
    pub wave: PerNode,
    /// One resubmit's cost per node.
    pub resubmit: PerNode,
    /// `build-crate.yml` runs the measured wave dispatched — one per
    /// task.
    pub wave_tasks: u64,
    /// `build-crate.yml` runs the measured resubmit dispatched.
    pub resubmit_tasks: u64,
}

impl PreheatMonthly {
    /// Scale the report's measured costs to the production wave and the
    /// model's cadence.
    ///
    /// # Errors
    /// The report measured no nodes, or the production lanes planned none
    /// — either leaves nothing to scale — or a phase contains an
    /// operation without a production Worker-request mapping.
    pub fn new(
        model: &LaunchModel,
        measured: &MeasuredReport,
        production: &ProductionWave,
        cpu: &WorkerCpuReport,
    ) -> Result<Self, String> {
        let report = &measured.report;
        if report.nodes == 0 {
            return Err(
                "preheat cost report measured 0 nodes — no per-node cost to scale".to_owned(),
            );
        }
        if production.nodes == 0 {
            return Err("production wave planned 0 nodes".to_owned());
        }
        Ok(Self {
            wave_trigger_do_requests: 1.0,
            resubmit_trigger_do_requests: 1.0,
            wave_trigger_worker_requests: 1.0 + f64::from(RunForwards::DELIVERIES),
            resubmit_trigger_worker_requests: 2.0_f64
                .mul_add(f64::from(RunForwards::DELIVERIES), 1.0),
            measured_nodes: report.nodes,
            production_nodes: production.nodes,
            releases_per_month: model.monthly_stable_releases(),
            resubmits_per_month: model.monthly_resubmits(),
            wave: PerNode::of(
                &report.wave,
                report.nodes,
                measured.cpu.wave.total_ms(),
                cpu,
            )?,
            resubmit: PerNode::of(
                &report.resubmit,
                report.nodes,
                measured.cpu.resubmit.total_ms(),
                cpu,
            )?,
            wave_tasks: report.wave.tasks,
            resubmit_tasks: report.resubmit.tasks,
        })
    }

    /// The month's preheat usage of one product dimension, or `None`
    /// when the report does not measure it.
    #[expect(
        clippy::cast_precision_loss,
        reason = "node counts fit f64 exactly past any wave"
    )]
    pub fn monthly(&self, product: &str, dimension: &str) -> Option<f64> {
        let (pick, wave_fixed, resubmit_fixed): (fn(&PerNode) -> f64, f64, f64) =
            match (product, dimension) {
                ("workers", "requests") => (
                    |cost| cost.worker_requests,
                    self.wave_trigger_worker_requests,
                    self.resubmit_trigger_worker_requests,
                ),
                ("workers", "cpu_ms") => (|cost| cost.worker_cpu_ms, 0.0, 0.0),
                ("workers", "cpu_ms_at_lifecycle_budget") => {
                    (|cost| cost.worker_cpu_ms_at_lifecycle_budget, 0.0, 0.0)
                }
                ("durable_objects", "requests") => (
                    |cost| cost.requests,
                    self.wave_trigger_do_requests,
                    self.resubmit_trigger_do_requests,
                ),
                ("durable_objects", "rows_read") => (|cost| cost.rows_read, 0.0, 0.0),
                ("durable_objects", "rows_written") => (|cost| cost.rows_written, 0.0, 0.0),
                _ => return None,
            };
        let nodes = self.production_nodes as f64;
        Some(self.resubmits_per_month.mul_add(
            pick(&self.resubmit).mul_add(nodes, resubmit_fixed),
            self.releases_per_month * pick(&self.wave).mul_add(nodes, wave_fixed),
        ))
    }

    /// Fixed trigger events whose CPU is not measured. These do not
    /// scale with the production node count.
    pub fn unmeasured_worker_events(&self) -> f64 {
        self.resubmits_per_month.mul_add(
            self.resubmit_trigger_worker_requests,
            self.releases_per_month * self.wave_trigger_worker_requests,
        )
    }
}

/// Why the Preheat cost report carries no preheat usage for a product
/// dimension.
pub fn not_measured(product: &str, dimension: &str) -> &'static str {
    match (product, dimension) {
        ("durable_objects", "duration_gb_s") => {
            "the report carries the harness's phase wall, not Durable Object duration"
        }
        _ => "the preheat report does not measure this dimension",
    }
}

/// A production wave of `nodes` distinct nodes.
#[cfg(test)]
pub(super) const fn test_production(nodes: u64) -> ProductionWave {
    ProductionWave {
        nodes,
        nodes_per_target: std::collections::BTreeMap::new(),
        lanes: Vec::new(),
    }
}

/// A report of `nodes` measured nodes whose wave and resubmit each cost
/// 100 calls, 1000 rows read and 500 rows written per phase, over 100
/// `build-crate.yml` runs — one per task.
#[cfg(test)]
pub(super) fn test_report(nodes: u64) -> MeasuredReport {
    use std::collections::BTreeMap;

    use stow_types::preheat_cost::{EventKind, KindCost, PreheatCostReport};

    let phase = PhaseCost {
        kinds: vec![KindCost {
            kind: EventKind::Completion,
            events: 100,
            rows_read: 1_000,
            rows_written: 500,
        }],
        other_ops: Vec::new(),
        rows_read: 1_000,
        rows_written: 500,
        tasks: 100,
        wall_ms: 0,
    };
    MeasuredReport {
        report: PreheatCostReport {
            rustc_version: "1.99.1".to_owned(),
            nodes,
            nodes_per_target: BTreeMap::new(),
            wave: phase.clone(),
            resubmit: phase,
            layers: Vec::new(),
            lanes: Vec::new(),
            checks: Vec::new(),
        },
        cpu: crate::preheat_cost::cpu::test_cpu(100.0, 20.0),
    }
}

#[cfg(test)]
mod tests {
    use super::{PreheatMonthly, not_measured, test_production, test_report};
    use crate::traffic_cost::test_support::{fixture_cpu, model};

    fn monthly(nodes: u64, production: u64) -> PreheatMonthly {
        PreheatMonthly::new(
            &model(),
            &test_report(nodes),
            &test_production(production),
            &fixture_cpu(|_| 0.0),
        )
        .expect("scale")
    }

    #[test]
    fn missing_lifecycle_cpu_prices_only_deliveries_absent_from_the_phase() {
        use stow_types::preheat_cost::{EventKind, KindCost};

        let mut report = test_report(10);
        report.report.wave.kinds = [
            (EventKind::Completion, 10),
            (EventKind::SliceReport, 3),
            (EventKind::Submit, 7),
            (EventKind::ExternalRunUpdate, 4),
            (EventKind::Dispatch, 5),
        ]
        .into_iter()
        .map(|(kind, events)| KindCost {
            kind,
            events,
            rows_read: 0,
            rows_written: 0,
        })
        .collect();
        let mut cpu = crate::traffic_cost::test_support::fixture_cpu(|_| 0.0);
        for row in &mut cpu.rows {
            row.cpu_ms = match row.lane.as_str() {
                "build-requested" => 2.0,
                "index-requested" => 3.0,
                "index-in-progress" => 5.0,
                "index-completed" => 7.0,
                _ => 1_000.0,
            };
            row.budget_ms = row.cpu_ms * 2.0;
        }
        let extra = super::lifecycle_cpu(&report.report.wave, &cpu).expect("lifecycle cost");
        assert_eq!(extra.measured_ms, 65.0);
        assert_eq!(extra.budget_ms, 130.0);
        let preheat = PreheatMonthly::new(&model(), &report, &test_production(1_000), &cpu)
            .expect("priced phases");
        assert_eq!(preheat.wave.worker_cpu_ms, 16.5);
        assert_eq!(preheat.resubmit.worker_cpu_ms, 22.0);
        let expected = preheat
            .releases_per_month
            .mul_add(16_500.0, preheat.resubmits_per_month * 22_000.0);
        assert!((preheat.monthly("workers", "cpu_ms").expect("CPU") - expected).abs() < 1e-6);
        let expected_budget = preheat
            .releases_per_month
            .mul_add(23_000.0, preheat.resubmits_per_month * 42_000.0);
        assert!(
            (preheat
                .monthly("workers", "cpu_ms_at_lifecycle_budget")
                .expect("budget")
                - expected_budget)
                .abs()
                < 1e-6
        );
        cpu.rows.retain(|row| row.lane != "index-completed");
        assert!(
            super::lifecycle_cpu(&report.report.wave, &cpu)
                .expect_err("missing price")
                .contains("index-completed")
        );
        assert!(
            PreheatMonthly::new(&model(), &report, &test_production(1_000), &cpu)
                .expect_err("projection needs all lifecycle prices")
                .contains("index-completed")
        );
    }

    /// Per-node cost is the phase total over the measured wave's nodes.
    #[test]
    fn per_node_cost_is_the_phase_total_over_the_measured_nodes() {
        let preheat = monthly(50, 50);
        assert!((preheat.wave.requests - 2.0).abs() < 1e-12);
        assert!((preheat.wave.rows_read - 20.0).abs() < 1e-12);
        assert!((preheat.resubmit.rows_written - 10.0).abs() < 1e-12);
        assert_eq!(preheat.wave_tasks, 100);
        assert_eq!(preheat.resubmit_tasks, 100);
        assert_eq!(preheat.wave.worker_cpu_ms, 2.0);
        assert_eq!(preheat.resubmit.worker_cpu_ms, 0.4);
    }

    #[test]
    fn covered_cpu_scales_wave_and_resubmit_with_their_own_cadence() {
        let preheat = monthly(50, 5_000);
        let expected = preheat
            .releases_per_month
            .mul_add(10_000.0, preheat.resubmits_per_month * 2_000.0);
        let actual = preheat.monthly("workers", "cpu_ms").expect("covered CPU");
        assert!((actual - expected).abs() < 1e-6, "{actual}");
        let missing = preheat
            .releases_per_month
            .mul_add(4.0, preheat.resubmits_per_month * 7.0);
        assert!((preheat.unmeasured_worker_events() - missing).abs() < 1e-6);
    }

    #[test]
    fn a_cost_report_without_cpu_cannot_be_read_as_measured() {
        let mut value = serde_json::to_value(test_report(50)).expect("report JSON");
        value.as_object_mut().expect("object").remove("cpu");
        let error = serde_json::from_value::<crate::preheat_cost::MeasuredReport>(value)
            .expect_err("CPU is mandatory");
        assert!(error.to_string().contains("cpu"), "{error}");
    }

    /// The monthly usage is releases × wave + days × resubmit, each at
    /// per-node cost × production nodes.
    #[test]
    fn the_month_is_waves_per_release_plus_a_resubmit_per_day() {
        let model = model();
        let preheat = monthly(50, 5_000);
        let rows_read = preheat
            .monthly("durable_objects", "rows_read")
            .expect("measured");
        // 20 rows read per node in each phase, 5000 production nodes.
        let wave = model.monthly_stable_releases() * 20.0 * 5_000.0;
        let resubmits = f64::from(model.scale.days_per_month) * 20.0 * 5_000.0;
        assert!((rows_read - (wave + resubmits)).abs() < 1e-6, "{rows_read}");
        // 10 rows written per node, 2 calls per node.
        let rows_written = preheat
            .monthly("durable_objects", "rows_written")
            .expect("measured");
        let expected = (model.monthly_stable_releases() + 30.0) * 10.0 * 5_000.0;
        assert!((rows_written - expected).abs() < 1e-6, "{rows_written}");
        let requests = preheat
            .monthly("durable_objects", "requests")
            .expect("measured");
        let expected = (model.monthly_stable_releases() + 30.0) * 10_001.0;
        assert!((requests - expected).abs() < 1e-6, "{requests}");
    }

    /// Scaling by production nodes is linear: ten times the nodes at
    /// the same measured per-node cost is ten times the month.
    #[test]
    fn production_scale_is_linear_in_nodes() {
        let small = monthly(50, 1_000).monthly("durable_objects", "rows_written");
        let large = monthly(50, 10_000).monthly("durable_objects", "rows_written");
        assert!((large.unwrap() / small.unwrap() - 10.0).abs() < 1e-9);
    }

    #[test]
    fn worker_requests_follow_production_lifecycles() {
        use stow_types::preheat_cost::{EventKind, KindCost};

        let mut report = test_report(10);
        report.report.wave.kinds = [
            (EventKind::Submit, 2),
            (EventKind::Dispatch, 500),
            (EventKind::Completion, 10),
            (EventKind::SliceReport, 3),
            (EventKind::ExternalRunUpdate, 4),
        ]
        .into_iter()
        .map(|(kind, events)| KindCost {
            kind,
            events,
            rows_read: 0,
            rows_written: 0,
        })
        .collect();
        report.report.resubmit.kinds.clear();
        let preheat = PreheatMonthly::new(
            &model(),
            &report,
            &test_production(1_000),
            &fixture_cpu(|_| 0.0),
        )
        .expect("scale");
        // Two submits, ten complete build lifecycles, three report +
        // index-run lifecycles. Neither alarms nor in_progress adds
        // another Worker lifecycle.
        assert!((preheat.wave.worker_requests - 4.4).abs() < 1e-12);
        assert_eq!(preheat.resubmit.worker_requests, 0.0);
        let expected = preheat
            .resubmits_per_month
            .mul_add(7.0, preheat.releases_per_month * 4_404.0);
        let requests = preheat.monthly("workers", "requests").expect("counted");
        assert!((requests - expected).abs() < 1e-6);
    }

    #[test]
    fn trigger_requests_do_not_scale_with_nodes() {
        let mut report = test_report(10);
        report.report.wave.kinds.clear();
        report.report.resubmit.kinds.clear();
        let small = PreheatMonthly::new(
            &model(),
            &report,
            &test_production(10),
            &fixture_cpu(|_| 0.0),
        )
        .expect("small");
        let large = PreheatMonthly::new(
            &model(),
            &report,
            &test_production(10_000),
            &fixture_cpu(|_| 0.0),
        )
        .expect("large");
        assert_eq!(
            small.monthly("workers", "requests"),
            large.monthly("workers", "requests")
        );
        assert!(small.monthly("workers", "requests").unwrap() > 0.0);
        let scheduler_requests = small.monthly("durable_objects", "requests");
        assert_eq!(
            scheduler_requests,
            large.monthly("durable_objects", "requests")
        );
        assert_eq!(
            scheduler_requests,
            Some(small.releases_per_month + small.resubmits_per_month)
        );
    }

    #[test]
    fn unknown_phase_operations_refuse_projection() {
        let mut report = test_report(10);
        report
            .report
            .resubmit
            .other_ops
            .push(stow_types::api::SchedulerLedgerOp {
                op: "POST /unknown".to_owned(),
                events: 1,
                rows_read: 0,
                rows_written: 0,
            });
        let error = PreheatMonthly::new(
            &model(),
            &report,
            &test_production(10),
            &fixture_cpu(|_| 0.0),
        )
        .expect_err("unknown operation");
        assert!(error.contains("POST /unknown"), "{error}");
    }

    /// DO active duration remains absent, never phase wall time.
    #[test]
    fn unmeasured_products_have_no_preheat_usage() {
        let preheat = monthly(50, 50);
        assert_eq!(preheat.monthly("durable_objects", "duration_gb_s"), None);
        assert_ne!(not_measured("durable_objects", "duration_gb_s"), "");
    }

    #[test]
    fn nothing_to_scale_is_refused() {
        let unmeasured = PreheatMonthly::new(
            &model(),
            &test_report(0),
            &test_production(10),
            &fixture_cpu(|_| 0.0),
        )
        .expect_err("0 nodes");
        assert!(unmeasured.contains("0 nodes"), "{unmeasured}");
        let unplanned = PreheatMonthly::new(
            &model(),
            &test_report(10),
            &test_production(0),
            &fixture_cpu(|_| 0.0),
        )
        .expect_err("0 plan");
        assert!(unplanned.contains("0 nodes"), "{unplanned}");
    }
}
