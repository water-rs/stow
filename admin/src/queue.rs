//! `stow-admin queue …` — inspect and mutate scheduler queue rows.

use std::fmt::Write as _;

use clap::{Args, Subcommand};
use stow_types::api::{QueueMutationResult, QueueSelector, QueueTask, QueueTaskStatus};
use stow_types::stow_error;

use crate::Edge;
use crate::render::{self, Output, Table};

#[derive(Args)]
pub struct QueueArgs {
    #[command(subcommand)]
    pub command: QueueCommand,
}

#[derive(Subcommand)]
pub enum QueueCommand {
    /// List queue rows, newest transition first.
    List(ListArgs),
    /// Move `failed` rows back to `pending`, clearing the dispatch
    /// backoff.
    Retry(MutationArgs),
    /// Mark `pending`/`dispatched` rows `failed` as `cancelled by
    /// operator`.
    Cancel(MutationArgs),
    /// Move `pending` rows from the miss lane into the human lane.
    Promote(MutationArgs),
    /// Delete `completed`/`failed` rows. Requires `--older-than` (or
    /// explicit `--task-id`s) so live work can never be swept.
    Purge(MutationArgs),
}

/// Shared row selector for `queue list` and every mutation: explicit
/// `--task-id`s when given, otherwise the filter flags.
#[derive(Args)]
pub struct SelectorArgs {
    /// Act on these task ids exactly; repeatable. When empty the filter
    /// flags below select the rows.
    #[arg(long = "task-id")]
    task_ids: Vec<String>,
    /// Lifecycle status to match.
    #[arg(long, value_parser = parse_status)]
    status: Option<QueueTaskStatus>,
    /// Compilation target to match.
    #[arg(long)]
    target: Option<String>,
    /// Crate name to match.
    #[arg(long = "crate")]
    crate_name: Option<String>,
    /// Only rows whose last transition is at least this old (`30m`,
    /// `24h`, `7d`).
    #[arg(long, value_parser = parse_duration_secs)]
    older_than: Option<u64>,
}

#[derive(Args)]
pub struct ListArgs {
    #[command(flatten)]
    selector: SelectorArgs,
    /// Most rows to print (the server caps at 500).
    #[arg(long)]
    limit: Option<u32>,
}

#[derive(Args)]
pub struct MutationArgs {
    #[command(flatten)]
    selector: SelectorArgs,
    /// Apply the transition. Without it the command prints the plan and
    /// exits 0 without touching the queue.
    #[arg(long)]
    yes: bool,
}

fn parse_status(raw: &str) -> Result<QueueTaskStatus, String> {
    QueueTaskStatus::parse(raw).ok_or_else(|| {
        format!(
            "unknown status `{raw}` (pending|blocked|dispatched|running|completed|partial|failed)"
        )
    })
}

fn parse_duration_secs(raw: &str) -> Result<u64, String> {
    humantime::parse_duration(raw)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("invalid duration `{raw}`: {error}"))
}

impl SelectorArgs {
    fn selector(&self, limit: Option<u32>) -> stow_types::error::Result<QueueSelector> {
        Ok(QueueSelector {
            task_ids: self.task_ids.clone(),
            status: self.status,
            target: self
                .target
                .as_deref()
                .map(|raw| {
                    raw.parse::<stow_types::identity::TargetTriple>()
                        .map_err(|error| stow_error!("--target: {error}"))
                })
                .transpose()?,
            crate_name: self
                .crate_name
                .as_deref()
                .map(|raw| {
                    stow_types::identity::CrateName::parse(raw)
                        .map_err(|error| stow_error!("--crate: {error}"))
                })
                .transpose()?,
            older_than_secs: self.older_than,
            limit,
        })
    }
}

pub async fn run(edge: &Edge, args: QueueArgs, output: Output) -> stow_types::error::Result<()> {
    match args.command {
        QueueCommand::List(args) => list(edge, args, output).await,
        QueueCommand::Retry(args) => mutate(edge, "retry", args, output).await,
        QueueCommand::Cancel(args) => mutate(edge, "cancel", args, output).await,
        QueueCommand::Promote(args) => mutate(edge, "promote", args, output).await,
        QueueCommand::Purge(args) => mutate(edge, "purge", args, output).await,
    }
}

async fn list(edge: &Edge, args: ListArgs, output: Output) -> stow_types::error::Result<()> {
    let selector = args.selector.selector(args.limit)?;
    let tasks: Vec<QueueTask> = edge.get_json(&selector_path(&selector)?).await?;
    render::emit(output, &tasks, |tasks| {
        let mut table = Table::new(&[
            "task",
            "crate",
            "version",
            "target",
            "lane",
            "status",
            "blocked by",
            "attempt",
            "updated",
        ]);
        for task in tasks {
            table.push([
                short_id(&task.task_id),
                task.crate_name.as_str().to_owned(),
                task.version.to_string(),
                task.target.as_str().to_owned(),
                task.lane.as_str().to_owned(),
                task.status.as_str().to_owned(),
                task.blocked_by
                    .as_deref()
                    .map_or_else(|| "—".to_owned(), short_id),
                task.attempt.to_string(),
                task.updated_at.clone(),
            ]);
        }
        if table.is_empty() {
            "no queue rows match".to_owned()
        } else {
            table.render()
        }
    })
}

/// One queue mutation: preview the rows the selector names, and only on
/// `--yes` POST the transition.
async fn mutate(
    edge: &Edge,
    verb: &'static str,
    args: MutationArgs,
    output: Output,
) -> stow_types::error::Result<()> {
    let selector = args.selector.selector(None)?;
    if verb == "purge" && selector.task_ids.is_empty() && selector.older_than_secs.is_none() {
        return Err(stow_error!(
            "queue purge needs --older-than (or explicit --task-id) so live work cannot be swept"
        ));
    }
    // The preview asks the same selector — `GET /admin/queue` honors
    // `task_ids` — so the rendered rows are the exact set the POST will
    // see. The verb's own domain predicates apply on top at the DO.
    let matching: Vec<QueueTask> = edge.get_json(&selector_path(&selector)?).await?;
    let affected = matching.iter().filter(|task| in_domain(verb, task)).count();
    let plan = QueueMutationPlan {
        verb,
        matching,
        affected,
    };
    render::mutation(
        output,
        args.yes,
        plan,
        |envelope: &render::Planned<QueueMutationPlan, QueueMutationResult>| {
            let plan = &envelope.plan;
            let mut out = format!(
                "{}: {} rows match the selector, {} in the transition domain\n",
                plan.verb,
                plan.matching.len(),
                plan.affected
            );
            let mut table = Table::new(&[
                "task",
                "crate",
                "status",
                "blocked by",
                "lane",
                "target",
                "applies",
            ]);
            for task in &plan.matching {
                table.push([
                    short_id(&task.task_id),
                    task.crate_name.as_str().to_owned(),
                    task.status.as_str().to_owned(),
                    task.blocked_by
                        .as_deref()
                        .map_or_else(|| "—".to_owned(), short_id),
                    task.lane.as_str().to_owned(),
                    task.target.as_str().to_owned(),
                    if in_domain(plan.verb, task) {
                        "yes".to_owned()
                    } else {
                        "no".to_owned()
                    },
                ]);
            }
            let _ = write!(out, "{}", table.render());
            if let Some(result) = &envelope.result {
                let _ = write!(out, "\n{} row(s) affected", result.affected);
            }
            let _ = write!(out, "\n{}", render::plan_footer(envelope.dry_run));
            out
        },
        async move |_| {
            edge.post_json(&format!("/api/v1/admin/queue/{verb}"), &selector)
                .await
        },
    )
    .await
}

/// Whether `verb`'s transition domain covers `task` — the same predicates
/// the Durable Object ANDs into its WHERE clause, mirrored so the plan's
/// `affected` count is honest.
fn in_domain(verb: &str, task: &QueueTask) -> bool {
    match verb {
        "retry" => matches!(
            task.status,
            QueueTaskStatus::Failed | QueueTaskStatus::Partial
        ),
        // `blocked` is a derived label on a stored `pending` row, so it
        // inherits every stored-pending domain: cancel stops it, promote
        // moves a miss-lane one.
        "cancel" => matches!(
            task.status,
            QueueTaskStatus::Pending | QueueTaskStatus::Blocked | QueueTaskStatus::Dispatched
        ),
        "promote" => {
            matches!(
                task.status,
                QueueTaskStatus::Pending | QueueTaskStatus::Blocked
            ) && task.lane == stow_types::api::TaskLane::Miss
        }
        "purge" => matches!(
            task.status,
            QueueTaskStatus::Completed | QueueTaskStatus::Failed | QueueTaskStatus::Partial
        ),
        _ => false,
    }
}

/// The plan a `queue` mutation prints: every row the selector matched,
/// plus how many of them the verb's transition domain covers.
#[derive(Debug, serde::Serialize)]
struct QueueMutationPlan {
    /// The verb being applied (`retry`/`cancel`/`promote`/`purge`).
    verb: &'static str,
    /// Rows the selector matched.
    matching: Vec<QueueTask>,
    /// How many of `matching` the verb's transition will touch.
    affected: usize,
}

/// `GET /api/v1/admin/queue?<flattened selector>` — the selector fields
/// serialize flat (`task_ids=a&task_ids=b&status=…`).
fn selector_path(selector: &QueueSelector) -> stow_types::error::Result<String> {
    let query = serde_html_form::to_string(selector)
        .map_err(|error| stow_error!("serialize queue selector: {error}"))?;
    Ok(if query.is_empty() {
        "/api/v1/admin/queue".to_owned()
    } else {
        format!("/api/v1/admin/queue?{query}")
    })
}

/// The queue display name of a task id: its leading 12 hex chars.
fn short_id(task_id: &str) -> String {
    task_id.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use stow_types::api::{QueueSelector, QueueTaskStatus};

    use super::selector_path;

    /// The selector must decode identically from a JSON body and from the
    /// query string `selector_path` emits — the edge's `Query` extractor
    /// and `serde_html_form` are the same contract.
    #[test]
    fn selector_round_trips_between_json_and_query() {
        let selector = QueueSelector {
            task_ids: vec!["abc".to_owned(), "def".to_owned()],
            status: Some(QueueTaskStatus::Failed),
            crate_name: Some("serde".parse().expect("crate name")),
            // The numeric predicates are the reason this struct is flat:
            // a `#[serde(flatten)]`ed half makes serde buffer every query
            // value as a string, which `u32`/`u64` cannot decode from, and
            // the whole selector then fails to parse.
            older_than_secs: Some(3_600),
            limit: Some(5),
            ..Default::default()
        };
        let path = selector_path(&selector).expect("selector path");
        let query = path.split_once('?').expect("query").1;
        let from_query: QueueSelector = serde_html_form::from_str(query).expect("decode query");
        let from_json: QueueSelector =
            serde_json::from_str(&serde_json::to_string(&selector).expect("to json"))
                .expect("decode json");
        assert_eq!(from_query, selector);
        assert_eq!(from_json, selector);
    }

    #[test]
    fn empty_selector_serializes_to_no_query() {
        let path = selector_path(&QueueSelector::default()).expect("selector path");
        assert_eq!(path, "/api/v1/admin/queue");
    }

    #[test]
    fn age_filter_uses_the_wire_name() {
        let selector = QueueSelector {
            task_ids: Vec::new(),
            older_than_secs: Some(3_600),
            ..Default::default()
        };
        let path = selector_path(&selector).expect("selector path");
        assert!(path.contains("older_than=3600"), "{path}");
    }
}
