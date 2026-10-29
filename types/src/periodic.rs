//! The edge's periodic workflow dispatches (stow#1100).
//!
//! GitHub's own `schedule` trigger is best-effort and was observed to
//! skip most ticks, so the edge Worker's Cloudflare Cron Trigger fires
//! the periodic workflows instead. The operator declares the cadences
//! once, in the manifest's `[cloudflare.triggers] crons`, and names the
//! workflows each cron string drives in `STOW_PERIODIC_WORKFLOWS`: a
//! JSON object from cron expression to the workflow files due on that
//! tick. A scheduled event carries the expression that fired it, so the
//! Worker looks the due workflows up by that string.

use std::collections::BTreeMap;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The environment binding that carries the cron-to-workflows map.
pub const SCHEDULE_BINDING: &str = "STOW_PERIODIC_WORKFLOWS";

/// A workflow file under `.github/workflows/`, validated to be a bare
/// `*.yml` / `*.yaml` file name so it can never reshape the dispatch
/// URL it is spliced into.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, ToSchema)]
#[serde(transparent)]
#[schema(value_type = String)]
pub struct WorkflowFile(String);

/// A [`WorkflowFile`] or [`PeriodicSchedule`] that does not parse.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PeriodicError {
    /// The workflow file name is not a bare `*.yml` / `*.yaml` name.
    #[error("workflow file {0:?} is not a bare `*.yml` or `*.yaml` file name")]
    BadWorkflowFile(String),
    /// The schedule is not a JSON object of cron to workflow lists.
    #[error("{SCHEDULE_BINDING} is not a JSON object of cron expression to workflow files: {0}")]
    BadSchedule(String),
    /// The schedule drives no workflow at all.
    #[error("{SCHEDULE_BINDING} names no cron expression")]
    EmptySchedule,
    /// A cron expression maps to no workflow.
    #[error("{SCHEDULE_BINDING} maps cron {0:?} to no workflow")]
    NoWorkflows(String),
    /// A scheduled event fired on a cron the schedule does not name.
    #[error("no workflow is configured for cron {0:?}")]
    UnknownCron(String),
}

impl WorkflowFile {
    /// The file name, e.g. `watchdog.yml`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The file name without its extension — the local CI stack's
    /// `event_type` for the workflow.
    #[must_use]
    pub fn stem(&self) -> &str {
        self.0
            .rsplit_once('.')
            .map_or(self.0.as_str(), |(stem, _)| stem)
    }
}

impl FromStr for WorkflowFile {
    type Err = PeriodicError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        let stem = name
            .strip_suffix(".yml")
            .or_else(|| name.strip_suffix(".yaml"));
        match stem {
            Some(stem)
                if !stem.is_empty()
                    && stem.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
                    }) =>
            {
                Ok(Self(name.to_owned()))
            }
            _ => Err(PeriodicError::BadWorkflowFile(name.to_owned())),
        }
    }
}

impl<'de> Deserialize<'de> for WorkflowFile {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        name.parse().map_err(serde::de::Error::custom)
    }
}

/// The scheduler route's body: one periodic workflow to dispatch on the
/// default branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PeriodicDispatchRequest {
    /// The workflow to dispatch.
    pub workflow: WorkflowFile,
}

/// Cron expression to the workflows due when it fires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeriodicSchedule(BTreeMap<String, Vec<WorkflowFile>>);

impl FromStr for PeriodicSchedule {
    type Err = PeriodicError;

    fn from_str(json: &str) -> Result<Self, Self::Err> {
        let map: BTreeMap<String, Vec<WorkflowFile>> = serde_json::from_str(json)
            .map_err(|error| PeriodicError::BadSchedule(error.to_string()))?;
        if map.is_empty() {
            return Err(PeriodicError::EmptySchedule);
        }
        if let Some((cron, _)) = map.iter().find(|(_, workflows)| workflows.is_empty()) {
            return Err(PeriodicError::NoWorkflows(cron.clone()));
        }
        Ok(Self(map))
    }
}

impl PeriodicSchedule {
    /// The workflows due on the tick that `cron` fired.
    ///
    /// # Errors
    ///
    /// [`PeriodicError::UnknownCron`] when the schedule does not name
    /// `cron` — a manifest whose triggers and schedule disagree fails
    /// the tick instead of silently dispatching nothing.
    pub fn due(&self, cron: &str) -> Result<&[WorkflowFile], PeriodicError> {
        self.0
            .get(cron)
            .map(Vec::as_slice)
            .ok_or_else(|| PeriodicError::UnknownCron(cron.to_owned()))
    }

    /// Every cron expression the schedule names, sorted.
    pub fn crons(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEDULE: &str =
        r#"{"*/15 * * * *":["watchdog.yml"],"17 */4 * * *":["preheat-cron.yml"]}"#;

    #[test]
    fn a_cron_maps_to_exactly_its_workflows() {
        let schedule: PeriodicSchedule = SCHEDULE.parse().expect("schedule parses");
        let due = schedule.due("*/15 * * * *").expect("known cron");
        assert_eq!(
            due.iter().map(WorkflowFile::as_str).collect::<Vec<_>>(),
            ["watchdog.yml"]
        );
        let due = schedule.due("17 */4 * * *").expect("known cron");
        assert_eq!(
            due.iter().map(WorkflowFile::as_str).collect::<Vec<_>>(),
            ["preheat-cron.yml"]
        );
    }

    #[test]
    fn an_unnamed_cron_fails_the_tick() {
        let schedule: PeriodicSchedule = SCHEDULE.parse().expect("schedule parses");
        assert_eq!(
            schedule.due("0 0 * * *"),
            Err(PeriodicError::UnknownCron("0 0 * * *".to_owned()))
        );
    }

    #[test]
    fn a_workflow_name_cannot_reshape_the_dispatch_path() {
        for bad in [
            "",
            ".yml",
            "../x.yml",
            "a/b.yml",
            "a b.yml",
            "watchdog",
            "a.yml?x=1",
        ] {
            assert!(
                bad.parse::<WorkflowFile>().is_err(),
                "{bad:?} must be refused"
            );
        }
        assert_eq!(
            "preheat-cron.yml".parse::<WorkflowFile>().unwrap().stem(),
            "preheat-cron"
        );
    }

    #[test]
    fn a_malformed_schedule_is_refused() {
        assert!(matches!(
            "[]".parse::<PeriodicSchedule>(),
            Err(PeriodicError::BadSchedule(_))
        ));
        assert_eq!(
            "{}".parse::<PeriodicSchedule>(),
            Err(PeriodicError::EmptySchedule)
        );
        assert_eq!(
            r#"{"* * * * *":[]}"#.parse::<PeriodicSchedule>(),
            Err(PeriodicError::NoWorkflows("* * * * *".to_owned()))
        );
        assert!(r#"{"* * * * *":["../x.yml"]}"#.parse::<PeriodicSchedule>().is_err());
    }
}
