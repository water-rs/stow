//! What one traffic event's handlers send: the Worker requests a
//! lifecycle is billed and the scheduler requests it forwards (stow#937,
//! stow#940).
//!
//! `stow-admin traffic-cost project` prices each event from these
//! tables. The webhook's tables are not declarations the handler can
//! drift from: the edge's tests drive every `workflow_run` action of
//! each lifecycle through the real delivery handler and fail when what
//! it forwards stops matching the row here. The two counts that live in
//! wasm-only route handlers ([`HUMAN_REQUEST_ADMIT`],
//! [`HUMAN_REQUEST_OUTCOME`]) name the handler they come from.

/// The `workflow_run` actions GitHub delivers for one run, in order.
///
/// GitHub's `workflow_run` webhook event documents
/// `requested`, `in_progress` and `completed`, plus `waiting` for a job
/// held by a deployment protection rule. No stow workflow names an
/// `environment`, so none of their runs waits.
pub const WORKFLOW_RUN_ACTIONS: [&str; 3] = ["requested", "in_progress", "completed"];

/// Scheduler requests the `workflow_run` webhook forwards for each
/// delivery of one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunForwards {
    /// Forwards on the `requested` delivery.
    pub requested: u32,
    /// Forwards on the `in_progress` delivery.
    pub in_progress: u32,
    /// Forwards on the `completed` delivery.
    pub completed: u32,
}

impl RunForwards {
    /// Worker requests one run's deliveries are billed: one per
    /// [`WORKFLOW_RUN_ACTIONS`] entry, whatever the handler forwards.
    #[expect(clippy::cast_possible_truncation, reason = "three actions fit u32")]
    pub const DELIVERIES: u32 = WORKFLOW_RUN_ACTIONS.len() as u32;

    /// Forwards on the delivery of `action`, `None` for an action GitHub
    /// does not send for a stow run.
    #[must_use]
    pub fn on(self, action: &str) -> Option<u32> {
        match action {
            "requested" => Some(self.requested),
            "in_progress" => Some(self.in_progress),
            "completed" => Some(self.completed),
            _ => None,
        }
    }

    /// Scheduler requests the whole run forwards.
    #[must_use]
    pub const fn total(self) -> u32 {
        self.requested + self.in_progress + self.completed
    }
}

/// A `build-crate.yml` run the scheduler dispatched (its
/// `triggering_actor` is the App's bot): only `completed` reaches the
/// object, since the CI listing's reconcile reports its running state.
pub const OWN_BUILD_RUN: RunForwards = RunForwards {
    requested: 0,
    in_progress: 0,
    completed: 1,
};

/// A `build-crate.yml` run the scheduler did not dispatch: its
/// `in_progress` records the external occupancy and its `completed`
/// releases it.
pub const EXTERNAL_BUILD_RUN: RunForwards = RunForwards {
    requested: 0,
    in_progress: 1,
    completed: 1,
};

/// A `resolve-request.yml` run that concluded `success`: `in_progress`
/// moves the record to `resolving`, and the run already posted its
/// outcome, so `completed` forwards nothing.
pub const SUCCESSFUL_RESOLVE_RUN: RunForwards = RunForwards {
    requested: 0,
    in_progress: 1,
    completed: 0,
};

/// A `resolve-request.yml` run with any other conclusion: `completed`
/// is the backstop that fails a run which finished without an outcome.
pub const FAILED_RESOLVE_RUN: RunForwards = RunForwards {
    requested: 0,
    in_progress: 1,
    completed: 1,
};

/// An `index-publish.yml` run, like every other workflow's.
///
/// GitHub delivers its actions to the Worker and the webhook consumes them
/// without a forward — its slices reach the scheduler through the
/// run's own report instead.
pub const INDEX_PUBLISH_RUN: RunForwards = RunForwards {
    requested: 0,
    in_progress: 0,
    completed: 0,
};

/// `POST /api/v1/requests` makes one scheduler request, the admit
/// (`api::submit_crate_request` → `scheduler_client::submit_request`).
pub const HUMAN_REQUEST_ADMIT: u32 = 1;

/// The resolve job's outcome post makes one scheduler request.
///
/// `POST /api/v1/scheduler/requests/{id}/outcome` is
/// `api::scheduler_request_outcome` →
/// `scheduler_client::send_request_outcome`. Only a successful run
/// posts it: the workflow fails the posting step, and so the run, when
/// the post does not land.
pub const HUMAN_REQUEST_OUTCOME: u32 = 1;

/// Scheduler requests one human request's lifecycle makes: the admit,
/// the resolve run's forwards, and the outcome when the run succeeded.
#[must_use]
pub const fn human_request_forwards(success: bool) -> u32 {
    if success {
        HUMAN_REQUEST_ADMIT + SUCCESSFUL_RESOLVE_RUN.total() + HUMAN_REQUEST_OUTCOME
    } else {
        HUMAN_REQUEST_ADMIT + FAILED_RESOLVE_RUN.total()
    }
}

/// Worker requests one human request's lifecycle is billed: the
/// `POST /api/v1/requests`, the resolve run's deliveries, and the
/// outcome post when the run succeeded.
#[must_use]
pub const fn human_request_worker_requests(success: bool) -> u32 {
    if success {
        1 + RunForwards::DELIVERIES + 1
    } else {
        1 + RunForwards::DELIVERIES
    }
}

#[cfg(test)]
mod tests {
    use super::{RunForwards, WORKFLOW_RUN_ACTIONS, human_request_forwards};

    /// Every lifecycle answers every action GitHub sends, and none
    /// forwards on `requested` — the scheduler has no route for it.
    #[test]
    fn every_lifecycle_prices_every_action_and_none_forwards_requested() {
        for forwards in [
            super::OWN_BUILD_RUN,
            super::EXTERNAL_BUILD_RUN,
            super::SUCCESSFUL_RESOLVE_RUN,
            super::FAILED_RESOLVE_RUN,
            super::INDEX_PUBLISH_RUN,
        ] {
            let summed: u32 = WORKFLOW_RUN_ACTIONS
                .iter()
                .map(|action| forwards.on(action).expect("a delivered action"))
                .sum();
            assert_eq!(summed, forwards.total());
            assert_eq!(forwards.requested, 0);
        }
        assert_eq!(RunForwards::DELIVERIES, 3);
    }

    /// A human request costs the scheduler the same either way it ends:
    /// a failed run trades the outcome for the `completed` backstop. The
    /// projection therefore needs no failure rate to price it.
    #[test]
    fn a_human_request_costs_three_scheduler_requests_whether_it_succeeds_or_fails() {
        assert_eq!(human_request_forwards(true), 3);
        assert_eq!(human_request_forwards(false), 3);
    }
}
