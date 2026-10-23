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
//! monthly = releases/month × (wave cost per node × production nodes)
//!         + days/month    × (resubmit cost per node × production nodes)
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
//! Only the scheduler Durable Object is measured: its billed calls and
//! rows. Every other product dimension is reported as not measured and
//! never priced at zero.

use stow_types::launch_model::LaunchModel;
use stow_types::preheat_cost::{PhaseCost, PreheatCostReport, ProductionWave};

/// A phase's measured cost per node of the wave that measured it.
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct PerNode {
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
    fn of(phase: &PhaseCost, nodes: u64) -> Self {
        let nodes = nodes as f64;
        Self {
            requests: phase.requests() as f64 / nodes,
            rows_read: phase.rows_read as f64 / nodes,
            rows_written: phase.rows_written as f64 / nodes,
        }
    }
}

/// What preheat adds to a month.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct PreheatMonthly {
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
    /// — either leaves nothing to scale.
    pub fn new(
        model: &LaunchModel,
        report: &PreheatCostReport,
        production: &ProductionWave,
    ) -> Result<Self, String> {
        if report.nodes == 0 {
            return Err(
                "preheat cost report measured 0 nodes — no per-node cost to scale".to_owned(),
            );
        }
        if production.nodes == 0 {
            return Err("production wave planned 0 nodes".to_owned());
        }
        Ok(Self {
            measured_nodes: report.nodes,
            production_nodes: production.nodes,
            releases_per_month: model.monthly_stable_releases(),
            resubmits_per_month: model.monthly_resubmits(),
            wave: PerNode::of(&report.wave, report.nodes),
            resubmit: PerNode::of(&report.resubmit, report.nodes),
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
        let pick: fn(&PerNode) -> f64 = match (product, dimension) {
            ("durable_objects", "requests") => |cost| cost.requests,
            ("durable_objects", "rows_read") => |cost| cost.rows_read,
            ("durable_objects", "rows_written") => |cost| cost.rows_written,
            _ => return None,
        };
        let nodes = self.production_nodes as f64;
        Some(self.resubmits_per_month.mul_add(
            pick(&self.resubmit) * nodes,
            self.releases_per_month * (pick(&self.wave) * nodes),
        ))
    }
}

/// Why the Preheat cost report carries no preheat usage for a product
/// dimension.
pub fn not_measured(product: &str, dimension: &str) -> &'static str {
    match (product, dimension) {
        ("durable_objects", "duration_gb_s") => {
            "the report carries the harness's phase wall, not Durable Object duration"
        }
        _ => "the report prices the scheduler Durable Object only",
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
pub(super) fn test_report(nodes: u64) -> PreheatCostReport {
    use std::collections::BTreeMap;

    use stow_types::preheat_cost::{EventKind, KindCost};

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
        budget_rows_read: f64::INFINITY,
        budget_rows_written: f64::INFINITY,
        tasks: 100,
        wall_ms: 0,
    };
    PreheatCostReport {
        rustc_version: "1.99.1".to_owned(),
        nodes,
        nodes_per_target: BTreeMap::new(),
        wave: phase.clone(),
        resubmit: phase,
        layers: Vec::new(),
        lanes: Vec::new(),
        checks: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::{PreheatMonthly, not_measured, test_production, test_report};
    use crate::traffic_cost::test_support::model;

    fn monthly(nodes: u64, production: u64) -> PreheatMonthly {
        PreheatMonthly::new(&model(), &test_report(nodes), &test_production(production))
            .expect("scale")
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
        let expected = (model.monthly_stable_releases() + 30.0) * 2.0 * 5_000.0;
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

    /// A dimension the report does not measure is absent, never zero.
    #[test]
    fn unmeasured_products_have_no_preheat_usage() {
        let preheat = monthly(50, 50);
        for (product, dimension) in [
            ("durable_objects", "duration_gb_s"),
            ("workers", "requests"),
            ("workers", "cpu_ms"),
            ("d1", "rows_read"),
            ("d1", "rows_written"),
        ] {
            assert_eq!(preheat.monthly(product, dimension), None);
            assert_ne!(not_measured(product, dimension), "");
        }
    }

    #[test]
    fn nothing_to_scale_is_refused() {
        let unmeasured = PreheatMonthly::new(&model(), &test_report(0), &test_production(10))
            .expect_err("0 nodes");
        assert!(unmeasured.contains("0 nodes"), "{unmeasured}");
        let unplanned = PreheatMonthly::new(&model(), &test_report(10), &test_production(0))
            .expect_err("0 plan");
        assert!(unplanned.contains("0 nodes"), "{unplanned}");
    }
}
