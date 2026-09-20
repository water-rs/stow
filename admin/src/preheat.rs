//! `stow-admin preheat …` — the cache-warming submission lanes plus
//! `preheat plan`, the edge's dry-run expansion.

use std::fmt::Write as _;

use clap::{Args, Subcommand};
use stow_types::api::{
    CI_TARGET_TRIPLES, EnqueueRequest, EnqueueSource, PreheatPlanRequest, PreheatPlanResponse,
    ProjectSource, SchedulerSubmitResponse, is_ci_target,
};
use stow_types::identity::{
    CrateName, CrateVersion as TypedCrateVersion, FeaturesJson, TargetTriple, WireRustcVersion,
};
use stow_types::stow_error;
use zenwave::{Client, ResponseExt};

use crate::render::{self, Output, Table};
use crate::{Edge, submit};

const CRATES_IO_API_BASE: &str = "https://crates.io/api/v1/crates";
const CRATES_IO_USER_AGENT: &str = "stow-admin";
const CRATES_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const CF_ACCOUNT_ID_ENV: &str = "CF_ACCOUNT_ID";
const CF_ANALYTICS_TOKEN_ENV: &str = "CF_ANALYTICS_TOKEN";
const CF_ANALYTICS_SQL_BASE: &str = "https://api.cloudflare.com/client/v4";
// The SQL API itself times queries out at 30 s; the client bound sits just
// above that so a slow query reports the server's error, not a local cutoff.
const CF_ANALYTICS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);

#[derive(Args)]
pub struct PreheatArgs {
    #[command(subcommand)]
    pub command: PreheatCommand,
}

#[derive(Subcommand)]
pub enum PreheatCommand {
    /// Submit tasks for the top-N most-downloaded crates — every selected
    /// version line on the target, each with the default feature set.
    Top(TopArgs),
    /// Submit one task per top-N most-downloaded *binary* crate, marked
    /// `preserve_lockfile` so the trusted runner resolves transitive deps
    /// against the binary's published `Cargo.lock`. `--manifest-path`
    /// switches to project seeding: one task whose source is the
    /// checkout's repository pinned to an immutable commit.
    BinaryOverlay(BinaryOverlayArgs),
    /// Submit one project-source task per entry of a checked-in showcase
    /// list (`preheat/projects.toml`).
    Projects(ProjectsArgs),
    /// Promote the most-missed `(crate, version, features)` identities in
    /// the Analytics Engine dataset into scheduler tasks.
    Missed(MissedArgs),
    /// Dry run of the edge's closure expansion and dominance pruning for
    /// one crate request — the tasks a dispatch wave would enqueue per
    /// target. Nothing is enqueued.
    Plan(PlanArgs),
}

#[derive(Args)]
pub struct TopArgs {
    #[arg(long)]
    target: String,
    #[arg(long)]
    rustc_version: String,
    #[arg(long, default_value_t = 100)]
    limit: usize,
    /// Submit the batch. Without it the command prints the plan and exits
    /// 0 without enqueuing.
    #[arg(long)]
    yes: bool,
}

#[derive(Args)]
pub struct BinaryOverlayArgs {
    #[arg(long)]
    target: String,
    #[arg(long)]
    rustc_version: String,
    #[arg(long, default_value_t = 100)]
    limit: usize,
    /// Path to a `Cargo.toml` inside the project checkout to seed from.
    /// The repository URL and commit are read from the checkout's git
    /// remote and HEAD; `--repo`/`--commit` override either when the
    /// checkout is not the tree the runner should clone.
    #[arg(long)]
    manifest_path: Option<std::path::PathBuf>,
    /// Git URL the runner clones. Defaults to the checkout's `origin`
    /// remote.
    #[arg(long, requires = "manifest_path")]
    repo: Option<String>,
    /// Full commit SHA the runner checks out. Defaults to the checkout's
    /// `HEAD`.
    #[arg(long, requires = "manifest_path")]
    commit: Option<String>,
    /// Submit the batch. Without it the command prints the plan and exits
    /// 0 without enqueuing.
    #[arg(long)]
    yes: bool,
}

#[derive(Args)]
pub struct ProjectsArgs {
    /// Path to the projects TOML (see `preheat/projects.toml` for the
    /// schema).
    #[arg(long)]
    file: std::path::PathBuf,
    #[arg(long)]
    target: String,
    #[arg(long)]
    rustc_version: String,
    /// Submit the batch. Without it the command prints the plan and exits
    /// 0 without enqueuing.
    #[arg(long)]
    yes: bool,
}

#[derive(Args)]
pub struct MissedArgs {
    /// Stable rustc version the promoted tasks build for.
    #[arg(long)]
    rustc_version: String,
    /// Comma-separated CI target triples to promote misses for. Defaults
    /// to every triple `stow_types::api::CI_TARGET_TRIPLES` covers.
    #[arg(long, value_delimiter = ',')]
    targets: Option<Vec<String>>,
    /// How many missed identities to promote per target.
    #[arg(long, default_value_t = 50)]
    limit: usize,
    /// How many days of miss history to rank over.
    #[arg(long, default_value_t = 7)]
    since_days: u32,
    /// Submit the batch. Without it the command prints the plan and exits
    /// 0 without enqueuing.
    #[arg(long)]
    yes: bool,
}

#[derive(Args)]
pub struct PlanArgs {
    /// Crate name, optionally `name@version`.
    pub crate_spec: String,
    /// Seed features as a JSON array (`[]` = `--no-default-features`
    /// semantics). Defaults to `["default"]`.
    #[arg(long)]
    features_json: Option<String>,
    /// Plan for one CI target instead of the whole fleet.
    #[arg(long)]
    target: Option<String>,
    /// Rustc version to plan against; absent resolves the scheduler's
    /// stable channel version.
    #[arg(long)]
    rustc_version: Option<String>,
}

pub async fn run(edge: &Edge, args: PreheatArgs, output: Output) -> stow_types::error::Result<()> {
    match args.command {
        PreheatCommand::Top(args) => top(edge, args, output).await,
        PreheatCommand::BinaryOverlay(args) => binary_overlay(edge, args, output).await,
        PreheatCommand::Projects(args) => projects(edge, args, output).await,
        PreheatCommand::Missed(args) => missed(edge, args, output).await,
        PreheatCommand::Plan(args) => plan(edge, args, output).await,
    }
}

/// The human table for a batch of enqueue requests — the plan every
/// `preheat` submit previews.
fn requests_table(requests: &[EnqueueRequest]) -> String {
    let mut table = Table::new(&[
        "crate", "version", "target", "features", "rustc", "source", "lockfile",
    ]);
    for request in requests {
        table.push([
            request.crate_name.as_str().to_owned(),
            request.version.to_string(),
            request.target.as_str().to_owned(),
            request.features_json.raw(),
            request.rustc_version.as_str().to_owned(),
            format!("{:?}", request.source),
            if request.uses_source_lockfile() {
                "source".to_owned()
            } else {
                "latest".to_owned()
            },
        ]);
    }
    table.render()
}

/// Submit `requests` as one batch after rendering the plan — the shared
/// tail of every `preheat` submit lane.
async fn submit_plan(
    edge: &Edge,
    requests: Vec<EnqueueRequest>,
    yes: bool,
    output: Output,
) -> stow_types::error::Result<()> {
    render::mutation(
        output,
        yes,
        requests,
        |envelope: &render::Planned<Vec<EnqueueRequest>, SchedulerSubmitResponse>| {
            let mut out = format!("{} task(s)\n", envelope.plan.len());
            if !envelope.plan.is_empty() {
                let _ = write!(out, "{}", requests_table(&envelope.plan));
            }
            if let Some(result) = &envelope.result {
                let _ = write!(
                    out,
                    "\nsubmitted {}, inserted {}, dropped {}",
                    result.submitted, result.inserted, result.dropped
                );
            }
            let _ = write!(out, "\n{}", render::plan_footer(envelope.dry_run));
            out
        },
        async move |requests: &Vec<EnqueueRequest>| submit(edge, requests).await,
    )
    .await
}

async fn top(edge: &Edge, args: TopArgs, output: Output) -> stow_types::error::Result<()> {
    let target = TargetTriple::parse(args.target.clone())
        .map_err(|error| stow_error!("preheat target: {error}"))?;
    let rustc_version = WireRustcVersion::parse(args.rustc_version.clone())
        .map_err(|error| stow_error!("preheat rustc_version: {error}"))?;
    let default_only = FeaturesJson::canonicalize(vec!["default".to_owned()])
        .map_err(|error| stow_error!("canonicalize default features: {error}"))?;
    let empty_features = FeaturesJson::default();

    let crates = fetch_top_crates(args.limit).await?;
    let mut requests = Vec::new();
    for krate in crates {
        let crate_name = CrateName::parse(krate.id.as_str())
            .map_err(|error| stow_error!("crate_name from crates.io `{}`: {error}", krate.id))?;
        let versions = fetch_versions(&krate.id).await?;
        let selected = select_version_lines(&versions)?;
        for version in selected {
            let has_default = versions
                .iter()
                .find(|candidate| candidate.num == version)
                .ok_or_else(|| {
                    stow_error!(
                        "selected version {} missing from crates.io response for {}",
                        version,
                        krate.id
                    )
                })?
                .features
                .contains_key("default");
            let typed_version =
                TypedCrateVersion::new(semver::Version::parse(&version).map_err(|error| {
                    stow_error!(
                        "parse crates.io version `{version}` for `{}`: {error}",
                        krate.id
                    )
                })?);
            requests.push(EnqueueRequest {
                crate_name: crate_name.clone(),
                version: typed_version,
                features_json: if has_default {
                    default_only.clone()
                } else {
                    empty_features.clone()
                },
                target: target.clone(),
                rustc_version: rustc_version.clone(),
                downloads: krate.downloads,
                source: EnqueueSource::CrateUpdate,
                depends_on: Vec::new(),
                preserve_lockfile: false,
                project_source: None,
            });
        }
    }
    submit_plan(edge, requests, args.yes, output).await
}

async fn binary_overlay(
    edge: &Edge,
    args: BinaryOverlayArgs,
    output: Output,
) -> stow_types::error::Result<()> {
    let target = TargetTriple::parse(args.target.clone())
        .map_err(|error| stow_error!("preheat target: {error}"))?;
    let rustc_version = WireRustcVersion::parse(args.rustc_version.clone())
        .map_err(|error| stow_error!("preheat rustc_version: {error}"))?;

    if let Some(manifest_path) = &args.manifest_path {
        let request = project_source_request(
            manifest_path,
            args.repo.as_deref(),
            args.commit.as_deref(),
            target,
            rustc_version,
        )
        .await?;
        return submit_plan(edge, vec![request], args.yes, output).await;
    }

    let default_only = FeaturesJson::canonicalize(vec!["default".to_owned()])
        .map_err(|error| stow_error!("canonicalize default features: {error}"))?;
    let empty_features = FeaturesJson::default();

    let candidates = fetch_top_binary_crates(args.limit).await?;
    if candidates.is_empty() {
        return Err(stow_error!(
            "no binary crates discovered from crates.io top-{} download list",
            args.limit
        ));
    }

    let mut requests = Vec::with_capacity(candidates.len());
    for binary in &candidates {
        let crate_name = CrateName::parse(binary.id.as_str())
            .map_err(|error| stow_error!("crate_name from crates.io `{}`: {error}", binary.id))?;
        let typed_version = TypedCrateVersion::new(
            semver::Version::parse(&binary.latest_version).map_err(|error| {
                stow_error!(
                    "parse crates.io version `{}` for `{}`: {error}",
                    binary.latest_version,
                    binary.id
                )
            })?,
        );
        requests.push(EnqueueRequest {
            crate_name,
            version: typed_version,
            features_json: if binary.has_default_feature {
                default_only.clone()
            } else {
                empty_features.clone()
            },
            target: target.clone(),
            rustc_version: rustc_version.clone(),
            downloads: binary.downloads,
            source: EnqueueSource::CrateUpdate,
            depends_on: Vec::new(),
            preserve_lockfile: true,
            project_source: None,
        });
    }

    tracing::info!(
        binaries = requests.len(),
        target = %args.target,
        rustc_version = %args.rustc_version,
        "planned binary-overlay preheat tasks"
    );
    submit_plan(edge, requests, args.yes, output).await
}

/// Build the project-source enqueue request for one pinned checkout —
/// the single task shape both `preheat binary-overlay --manifest-path`
/// seeding and the `preheat projects` showcase list submit.
async fn project_source_request(
    manifest_path: &std::path::Path,
    repo: Option<&str>,
    commit: Option<&str>,
    target: TargetTriple,
    rustc_version: WireRustcVersion,
) -> stow_types::error::Result<EnqueueRequest> {
    let (crate_name, version, project_source) =
        project_source_from_checkout(manifest_path, repo, commit).await?;
    tracing::info!(
        crate_name = %crate_name,
        version = %version,
        url = %project_source.url,
        commit = %project_source.commit,
        manifest_path = %project_source.manifest_path,
        %target,
        %rustc_version,
        "planned project-source preheat task"
    );
    // Feature flags are meaningless for a project task: the runner builds
    // the checkout's workspace with each member's own default set, and
    // `project_source` already implies `--locked`.
    Ok(EnqueueRequest {
        crate_name,
        version,
        features_json: FeaturesJson::default(),
        target,
        rustc_version,
        downloads: 0,
        source: EnqueueSource::CrateUpdate,
        depends_on: Vec::new(),
        preserve_lockfile: false,
        project_source: Some(project_source),
    })
}

async fn projects(
    edge: &Edge,
    args: ProjectsArgs,
    output: Output,
) -> stow_types::error::Result<()> {
    let target = TargetTriple::parse(args.target.clone())
        .map_err(|error| stow_error!("preheat target: {error}"))?;
    let rustc_version = WireRustcVersion::parse(args.rustc_version.clone())
        .map_err(|error| stow_error!("preheat rustc_version: {error}"))?;

    let bytes = smol::fs::read(&args.file)
        .await
        .map_err(|error| stow_error!("read projects file {}: {error}", args.file.display()))?;
    let file: ProjectsFile = toml::from_slice(&bytes)
        .map_err(|error| stow_error!("parse projects file {}: {error}", args.file.display()))?;
    if file.project.is_empty() {
        return Err(stow_error!(
            "projects file {} lists no [[project]] entries",
            args.file.display()
        ));
    }

    // The clones exist only to read package identity out of the manifest
    // at the pinned commit; one scratch dir per invocation keeps them out
    // of the repository.
    let scratch = std::env::temp_dir().join(format!("stow-admin-preheat-{}", std::process::id()));
    let mut requests = Vec::with_capacity(file.project.len());
    for (index, entry) in file.project.iter().enumerate() {
        let commit = resolve_project_commit(entry).await?;
        let dir = scratch.join(index.to_string());
        fetch_commit_checkout(&entry.repo, &commit, &dir).await?;
        requests.push(
            project_source_request(
                &dir.join(&entry.manifest_path),
                Some(&entry.repo),
                Some(&commit),
                target.clone(),
                rustc_version.clone(),
            )
            .await?,
        );
    }
    if let Err(error) = smol::fs::remove_dir_all(&scratch).await {
        tracing::warn!(dir = %scratch.display(), %error, "failed to remove preheat scratch dir");
    }
    submit_plan(edge, requests, args.yes, output).await
}

/// The Analytics Engine query template; `__LIMIT__`, `__SINCE_DAYS__`,
/// and `__TARGETS__` are the only substitution points (see the file's own
/// comment for why that is safe).
const TOP_MISSED_SQL: &str = include_str!("../sql/top_missed.sql");

/// Render the top-missed query for a dispatch run. `targets` must already
/// be validated by [`missed_targets`] — the literals land in the SQL text
/// unescaped because the SQL API has no bound parameters.
fn top_missed_query(limit: usize, since_days: u32, targets: &[String]) -> String {
    TOP_MISSED_SQL
        .replace("__LIMIT__", &limit.to_string())
        .replace("__SINCE_DAYS__", &since_days.to_string())
        .replace(
            "__TARGETS__",
            &targets
                .iter()
                .map(|target| format!("'{target}'"))
                .collect::<Vec<_>>()
                .join(", "),
        )
}

/// Resolve the `--targets` list to the triples the query covers; absent
/// means every target the CI fleet builds. Anything outside
/// [`CI_TARGET_TRIPLES`] is rejected outright — it would produce a task
/// the runner map in `build-crate.yml` cannot dispatch.
fn missed_targets(targets: Option<Vec<String>>) -> stow_types::error::Result<Vec<String>> {
    let targets = match targets {
        Some(targets) if !targets.is_empty() => targets,
        Some(_) => {
            return Err(stow_error!(
                "--targets must name at least one target triple"
            ));
        }
        None => CI_TARGET_TRIPLES
            .iter()
            .map(|target| (*target).to_owned())
            .collect(),
    };
    for target in &targets {
        if !is_ci_target(target) {
            return Err(stow_error!(
                "--targets `{target}` is not a CI target (stow_types::api::CI_TARGET_TRIPLES)"
            ));
        }
    }
    Ok(targets)
}

/// One row of the Analytics Engine response: a target and the
/// `crate;version;features_json;misses` identities `topKWeighted` ranked
/// for it.
#[derive(Debug, serde::Deserialize)]
struct TopMissedRow {
    target: String,
    top_missed: Vec<String>,
}

/// The `FORMAT JSON` envelope the SQL API wraps result rows in.
#[derive(Debug, serde::Deserialize)]
struct AnalyticsResponse {
    data: Vec<TopMissedRow>,
}

/// Run the top-missed query against the Analytics Engine SQL API.
/// `CF_ACCOUNT_ID` and `CF_ANALYTICS_TOKEN` (an API token with
/// `Account Analytics: Read`) are both required.
async fn fetch_top_missed(query: &str) -> stow_types::error::Result<Vec<TopMissedRow>> {
    let account_id =
        std::env::var(CF_ACCOUNT_ID_ENV).map_err(|_| stow_error!("missing {CF_ACCOUNT_ID_ENV}"))?;
    let token = std::env::var(CF_ANALYTICS_TOKEN_ENV)
        .map_err(|_| stow_error!("missing {CF_ANALYTICS_TOKEN_ENV}"))?;
    let url = format!("{CF_ANALYTICS_SQL_BASE}/accounts/{account_id}/analytics_engine/sql");
    let mut client = zenwave::client().timeout(CF_ANALYTICS_TIMEOUT);
    let response = client
        .post(&url)
        .and_then(|request| request.header("Authorization", format!("Bearer {token}")))
        .map(|request| request.bytes_body(query.as_bytes().to_vec()))
        .map_err(|error| stow_error!("query Analytics Engine: {error}"))?
        .await
        .map_err(|error| stow_error!("query Analytics Engine: {error}"))?
        .error_for_status()
        .await
        .map_err(|error| stow_error!("query Analytics Engine: {error}"))?;
    let envelope: AnalyticsResponse = response
        .into_json()
        .await
        .map_err(|error| stow_error!("parse Analytics Engine response: {error}"))?;
    Ok(envelope.data)
}

/// Map one `crate;version;features_json;misses` element of a
/// [`TopMissedRow::top_missed`] array to the task it promotes. Every field
/// came from a validated `EnqueueRequest`/`SemanticArtifactRequest` on the
/// write path, so a parse failure here means the dataset diverged from
/// `miss_logger`'s layout — a bug to fail on, not a row to skip.
fn missed_enqueue_request(
    target: &str,
    entry: &str,
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<EnqueueRequest> {
    let [crate_name, version, features_json, misses]: [&str; 4] = entry
        .split(';')
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| {
            stow_error!(
                "malformed top_missed entry {entry:?} — expected `crate;version;features_json;misses`"
            )
        })?;
    let features: Vec<String> = serde_json::from_str(features_json)
        .map_err(|error| stow_error!("top_missed features_json {features_json:?}: {error}"))?;
    Ok(EnqueueRequest {
        crate_name: CrateName::parse(crate_name)
            .map_err(|error| stow_error!("top_missed crate_name: {error}"))?,
        version: TypedCrateVersion::new(semver::Version::parse(version)?),
        features_json: FeaturesJson::canonicalize(features)
            .map_err(|error| stow_error!("top_missed features_json: {error}"))?,
        target: TargetTriple::parse(target)
            .map_err(|error| stow_error!("top_missed target: {error}"))?,
        rustc_version: rustc_version.clone(),
        downloads: misses
            .parse()
            .map_err(|error| stow_error!("top_missed misses `{misses}`: {error}"))?,
        source: EnqueueSource::CacheMiss,
        depends_on: Vec::new(),
        preserve_lockfile: false,
        project_source: None,
    })
}

async fn missed(edge: &Edge, args: MissedArgs, output: Output) -> stow_types::error::Result<()> {
    let rustc_version = WireRustcVersion::parse(args.rustc_version)
        .map_err(|error| stow_error!("preheat rustc_version: {error}"))?;
    let targets = missed_targets(args.targets)?;
    if args.limit == 0 {
        return Err(stow_error!("--limit must be at least 1"));
    }
    if args.since_days == 0 {
        return Err(stow_error!("--since-days must be at least 1"));
    }
    let query = top_missed_query(args.limit, args.since_days, &targets);
    let rows = fetch_top_missed(&query).await?;

    let mut requests = Vec::new();
    for row in &rows {
        for entry in &row.top_missed {
            requests.push(missed_enqueue_request(&row.target, entry, &rustc_version)?);
        }
    }
    if requests.is_empty() {
        tracing::info!("no missed identities in the window; nothing to submit");
    }
    submit_plan(edge, requests, args.yes, output).await
}

async fn plan(edge: &Edge, args: PlanArgs, output: Output) -> stow_types::error::Result<()> {
    let (crate_name, version) = crate::coverage::parse_crate_spec(&args.crate_spec)?;
    let features_json = match &args.features_json {
        Some(raw) => {
            let features: Vec<String> = serde_json::from_str(raw)
                .map_err(|error| stow_error!("--features-json: {error}"))?;
            FeaturesJson::canonicalize(features)
                .map_err(|error| stow_error!("--features-json: {error}"))?
        }
        None => FeaturesJson::canonicalize(vec!["default".to_owned()])
            .map_err(|error| stow_error!("canonicalize default features: {error}"))?,
    };
    let request = PreheatPlanRequest {
        crate_name,
        version,
        features_json,
        target: args
            .target
            .as_deref()
            .map(|raw| TargetTriple::parse(raw).map_err(|error| stow_error!("--target: {error}")))
            .transpose()?,
        rustc_version: args
            .rustc_version
            .as_deref()
            .map(|raw| {
                WireRustcVersion::parse(raw)
                    .map_err(|error| stow_error!("--rustc-version: {error}"))
            })
            .transpose()?,
    };
    let plan: PreheatPlanResponse = edge
        .post_json("/api/v1/admin/preheat/plan", &request)
        .await?;
    render::emit(output, &plan, |plan| {
        let mut out = format!(
            "{} {} (rustc {})\n",
            plan.crate_name, plan.version, plan.rustc_version
        );
        for target in &plan.targets {
            let _ = writeln!(
                out,
                "{}: {} task(s){}",
                target.target,
                target.tasks.len(),
                if target.root_cached {
                    ", root cached"
                } else {
                    ""
                }
            );
            let mut table = Table::new(&["crate", "version", "features", "deps", "lockfile"]);
            for task in &target.tasks {
                table.push([
                    task.crate_name.as_str().to_owned(),
                    task.version.to_string(),
                    task.features_json.raw(),
                    task.depends_on.len().to_string(),
                    if task.uses_source_lockfile() {
                        "source".to_owned()
                    } else {
                        "latest".to_owned()
                    },
                ]);
            }
            if !table.is_empty() {
                let _ = writeln!(out, "{}", table.render());
            }
        }
        out.trim_end().to_owned()
    })
}

// ===== crates.io discovery =====

/// Parsed `preheat/projects.toml`: the checked-in showcase list.
#[derive(Debug, serde::Deserialize)]
struct ProjectsFile {
    #[serde(default)]
    project: Vec<ProjectsFileEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct ProjectsFileEntry {
    /// Git URL the runner clones.
    repo: String,
    /// Which ref the entry tracks.
    ref_policy: RefPolicy,
    /// Manifest path relative to the repository root.
    #[serde(default = "default_manifest_path")]
    manifest_path: String,
}

#[derive(Debug, Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RefPolicy {
    /// The newest tag whose name parses as semver (leading `v` allowed).
    LatestTag,
    /// The remote's `HEAD`.
    DefaultBranch,
}

fn default_manifest_path() -> String {
    "Cargo.toml".to_owned()
}

#[derive(Debug, serde::Deserialize)]
struct CratesResponse {
    crates: Vec<CrateSummary>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct CrateSummary {
    id: String,
    downloads: u64,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct CrateVersion {
    num: String,
    #[serde(default)]
    features: std::collections::BTreeMap<String, Vec<String>>,
    yanked: bool,
}

/// Resolve a projects-file entry to the immutable commit its ref policy
/// tracks, without a working tree.
async fn resolve_project_commit(entry: &ProjectsFileEntry) -> stow_types::error::Result<String> {
    match entry.ref_policy {
        RefPolicy::DefaultBranch => {
            let output = git_standalone(&["ls-remote", &entry.repo, "HEAD"]).await?;
            output
                .split_whitespace()
                .next()
                .map(str::to_owned)
                .ok_or_else(|| stow_error!("git ls-remote {} HEAD printed nothing", entry.repo))
        }
        RefPolicy::LatestTag => latest_tag_commit(&entry.repo).await,
    }
}

/// Pick the newest semver tag a repository publishes and return the
/// commit it points at. Tag names parse with or without a leading `v`;
/// annotated tags resolve to their peeled `^{}` commit.
async fn latest_tag_commit(repo: &str) -> stow_types::error::Result<String> {
    let output = git_standalone(&["ls-remote", "--tags", repo]).await?;
    let mut direct = std::collections::HashMap::new();
    let mut peeled = std::collections::HashMap::new();
    for line in output.lines() {
        let Some((sha, reference)) = line.split_once('\t') else {
            return Err(stow_error!(
                "git ls-remote --tags {repo} returned a malformed line: {line:?}"
            ));
        };
        let Some(name) = reference.strip_prefix("refs/tags/") else {
            continue;
        };
        if let Some(base) = name.strip_suffix("^{}") {
            peeled.insert(base.to_owned(), sha.to_owned());
        } else {
            direct.insert(name.to_owned(), sha.to_owned());
        }
    }
    let mut best: Option<(semver::Version, &str)> = None;
    for (name, sha) in &direct {
        let Ok(version) = semver::Version::parse(name.strip_prefix('v').unwrap_or(name)) else {
            continue;
        };
        if best.as_ref().is_none_or(|(current, _)| version > *current) {
            best = Some((
                version,
                peeled.get(name).map_or(sha.as_str(), String::as_str),
            ));
        }
    }
    best.map(|(_, commit)| commit.to_owned())
        .ok_or_else(|| stow_error!("{repo} publishes no semver tags"))
}

/// Fetch a single commit into `dir` as a depth-1 checkout of `FETCH_HEAD`.
async fn fetch_commit_checkout(
    repo: &str,
    commit: &str,
    dir: &std::path::Path,
) -> stow_types::error::Result<()> {
    smol::fs::create_dir_all(dir)
        .await
        .map_err(|error| stow_error!("create checkout dir {}: {error}", dir.display()))?;
    git(dir, &["init", "--quiet"]).await?;
    git(dir, &["remote", "add", "origin", repo]).await?;
    git(dir, &["fetch", "--quiet", "--depth", "1", "origin", commit]).await?;
    git(dir, &["checkout", "--quiet", "FETCH_HEAD"]).await?;
    Ok(())
}

/// Read the project identity for a source-seeded task from a checkout.
///
/// The manifest supplies `package.name`/`package.version` — the root package
/// the task is named after, which the publisher asserts the pinned checkout
/// actually contains — and the repo URL/commit pin the tree the runner
/// clones. A virtual workspace root has no `[package]` table and is
/// rejected: the task must be anchored on the package the consumer's
/// manifest resolves to (for waterui, the workspace-root facade crate).
async fn project_source_from_checkout(
    manifest_path: &std::path::Path,
    repo_override: Option<&str>,
    commit_override: Option<&str>,
) -> stow_types::error::Result<(CrateName, TypedCrateVersion, ProjectSource)> {
    let manifest_path = smol::fs::canonicalize(manifest_path)
        .await
        .map_err(|error| {
            stow_error!("canonicalize manifest {}: {error}", manifest_path.display())
        })?;
    if manifest_path.file_name().and_then(|name| name.to_str()) != Some("Cargo.toml") {
        return Err(stow_error!(
            "--manifest-path must point at a Cargo.toml (got {})",
            manifest_path.display()
        ));
    }
    let manifest_dir = manifest_path
        .parent()
        .ok_or_else(|| stow_error!("manifest {} has no parent", manifest_path.display()))?;
    let checkout_root =
        smol::fs::canonicalize(git(manifest_dir, &["rev-parse", "--show-toplevel"]).await?)
            .await
            .map_err(|error| stow_error!("canonicalize checkout root: {error}"))?;
    let manifest_rel = manifest_path
        .strip_prefix(&checkout_root)
        .map_err(|_| {
            stow_error!(
                "manifest {} is outside checkout root {}",
                manifest_path.display(),
                checkout_root.display()
            )
        })?
        .to_string_lossy()
        .into_owned();

    let commit = match commit_override {
        Some(commit) => commit.to_owned(),
        None => git(manifest_dir, &["rev-parse", "HEAD"]).await?,
    };
    if commit.len() != 40 || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(stow_error!("commit is not a full SHA-1: {commit:?}"));
    }
    let url = match repo_override {
        Some(url) => url.to_owned(),
        None => git(manifest_dir, &["remote", "get-url", "origin"]).await?,
    };
    if url.is_empty() {
        return Err(stow_error!(
            "checkout has no `origin` remote — pass --repo explicitly"
        ));
    }

    let manifest_bytes = smol::fs::read(&manifest_path)
        .await
        .map_err(|error| stow_error!("read manifest {}: {error}", manifest_path.display()))?;
    let manifest: toml::Value = toml::from_slice(&manifest_bytes)
        .map_err(|error| stow_error!("parse manifest {}: {error}", manifest_path.display()))?;
    let package = manifest.get("package").ok_or_else(|| {
        stow_error!(
            "{} has no [package] table — point --manifest-path at the workspace's root package",
            manifest_path.display()
        )
    })?;
    let name = package
        .get("name")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| stow_error!("manifest [package] has no `name`"))?;
    let version = package
        .get("version")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| stow_error!("manifest [package] has no `version`"))?;

    Ok((
        CrateName::parse(name).map_err(|error| stow_error!("crate name: {error}"))?,
        TypedCrateVersion::new(
            semver::Version::parse(version)
                .map_err(|error| stow_error!("crate version: {error}"))?,
        ),
        ProjectSource {
            url,
            commit,
            manifest_path: manifest_rel,
        },
    ))
}

/// Run `git` in `dir` and return trimmed stdout; any failure is fatal.
async fn git(dir: &std::path::Path, args: &[&str]) -> stow_types::error::Result<String> {
    let output = smol::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .await
        .map_err(|error| stow_error!("run git {}: {error}", args.join(" ")))?;
    git_output(
        output,
        &format!("git {} in {}", args.join(" "), dir.display()),
    )
}

/// Run `git` outside a working tree (`ls-remote`); any failure is fatal.
async fn git_standalone(args: &[&str]) -> stow_types::error::Result<String> {
    let output = smol::process::Command::new("git")
        .args(args)
        .output()
        .await
        .map_err(|error| stow_error!("run git {}: {error}", args.join(" ")))?;
    git_output(output, &format!("git {}", args.join(" ")))
}

/// Turn a finished `git` invocation into trimmed stdout; failure is fatal.
fn git_output(output: std::process::Output, command: &str) -> stow_types::error::Result<String> {
    if !output.status.success() {
        return Err(stow_error!(
            "{command} failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout)
        .map(|stdout| stdout.trim().to_owned())
        .map_err(|error| stow_error!("{command} output is not UTF-8: {error}"))
}

#[derive(Debug, Clone)]
struct BinaryCandidate {
    id: String,
    latest_version: String,
    downloads: u64,
    has_default_feature: bool,
}

async fn fetch_top_binary_crates(limit: usize) -> stow_types::error::Result<Vec<BinaryCandidate>> {
    // crates.io's `binaries` field on the per-crate detail endpoint is not
    // reliably populated, so we use the `command-line-utilities` category as
    // the canonical "this crate is a binary" signal — every crate registered
    // in that category ships at least one [[bin]] target. We still call
    // fetch_crate_detail to grab the latest non-yanked version + features.
    let mut binaries = Vec::with_capacity(limit);
    let mut page: u32 = 1;
    let scan_per_page: usize = 100;
    let max_scan_pages: u32 = 20;
    while binaries.len() < limit && page <= max_scan_pages {
        let url = format!(
            "{CRATES_IO_API_BASE}?category=command-line-utilities&page={page}&per_page={scan_per_page}&sort=downloads"
        );
        let response: CratesResponse = get_json_with_retries(&url).await?;
        if response.crates.is_empty() {
            break;
        }
        for summary in response.crates {
            let detail = match fetch_crate_detail(&summary.id).await {
                Ok(detail) => detail,
                Err(error) => {
                    tracing::warn!(
                        crate = %summary.id,
                        %error,
                        "skipping candidate; failed to fetch detail"
                    );
                    continue;
                }
            };
            let Some(latest_version) = detail.latest_version else {
                continue;
            };
            binaries.push(BinaryCandidate {
                id: summary.id.clone(),
                latest_version: latest_version.num.clone(),
                downloads: summary.downloads,
                has_default_feature: latest_version.features.contains_key("default"),
            });
            if binaries.len() >= limit {
                break;
            }
        }
        page += 1;
    }
    binaries.truncate(limit);
    Ok(binaries)
}

#[derive(Debug, Clone)]
struct CrateDetail {
    latest_version: Option<CrateVersion>,
}

#[derive(Debug, serde::Deserialize)]
struct CrateDetailResponse {
    #[serde(rename = "crate")]
    krate: CrateDetailNode,
    versions: Vec<CrateVersion>,
}

#[derive(Debug, serde::Deserialize)]
struct CrateDetailNode {
    #[serde(default)]
    max_stable_version: Option<String>,
    #[serde(default)]
    max_version: Option<String>,
}

async fn fetch_crate_detail(crate_name: &str) -> stow_types::error::Result<CrateDetail> {
    let url = format!("{CRATES_IO_API_BASE}/{crate_name}");
    let response: CrateDetailResponse = get_json_with_retries(&url).await?;
    let preferred_num = response
        .krate
        .max_stable_version
        .clone()
        .or_else(|| response.krate.max_version.clone());
    let latest_version = match preferred_num {
        Some(num) => response
            .versions
            .iter()
            .find(|candidate| candidate.num == num && !candidate.yanked)
            .cloned()
            .or_else(|| {
                response
                    .versions
                    .iter()
                    .find(|candidate| !candidate.yanked)
                    .cloned()
            }),
        None => response
            .versions
            .iter()
            .find(|candidate| !candidate.yanked)
            .cloned(),
    };
    Ok(CrateDetail { latest_version })
}

async fn fetch_top_crates(limit: usize) -> stow_types::error::Result<Vec<CrateSummary>> {
    let per_page = limit.min(100);
    let url = format!("{CRATES_IO_API_BASE}?page=1&per_page={per_page}&sort=downloads");
    let response = get_json_with_retries::<CratesResponse>(&url).await?;
    Ok(response.crates.into_iter().take(limit).collect())
}

async fn fetch_versions(crate_name: &str) -> stow_types::error::Result<Vec<CrateVersion>> {
    let url = format!("{CRATES_IO_API_BASE}/{crate_name}");
    let response = get_json_with_retries::<serde_json::Value>(&url).await?;
    let versions = serde_json::from_value::<Vec<CrateVersion>>(response["versions"].clone())?;
    Ok(versions
        .into_iter()
        .filter(|version| !version.yanked)
        .collect())
}

async fn get_json_with_retries<T>(url: &str) -> stow_types::error::Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let mut client = zenwave::client().timeout(CRATES_IO_TIMEOUT).retry(2);
    let response = client
        .get(url)
        .and_then(|request| request.header("User-Agent", CRATES_IO_USER_AGENT))
        .map_err(|error| stow_error!("fetch crates.io JSON from {url}: {error}"))?
        .await
        .map_err(|error| stow_error!("fetch crates.io JSON from {url}: {error}"))?;
    response
        .into_json()
        .await
        .map_err(|error| stow_error!("parse crates.io JSON from {url}: {error}"))
}

fn select_version_lines(versions: &[CrateVersion]) -> stow_types::error::Result<Vec<String>> {
    let mut chosen = std::collections::BTreeMap::<(u64, u64), String>::new();
    for version in versions {
        let parsed = semver::Version::parse(&version.num)?;
        let key = if parsed.major >= 1 {
            (parsed.major, u64::MAX)
        } else {
            (0, parsed.minor)
        };
        chosen
            .entry(key)
            .and_modify(|existing| {
                if semver::Version::parse(existing).is_ok_and(|current| parsed > current) {
                    existing.clone_from(&version.num);
                }
            })
            .or_insert_with(|| version.num.clone());
    }
    let mut parsed_values = chosen
        .into_values()
        .map(|version| {
            let parsed = semver::Version::parse(&version).map_err(|error| {
                stow_error!("invalid version in chosen set: {version}: {error}")
            })?;
            Ok((parsed, version))
        })
        .collect::<stow_types::error::Result<Vec<_>>>()?;
    parsed_values.sort_by(|a, b| b.0.cmp(&a.0));
    parsed_values.truncate(3);
    Ok(parsed_values
        .into_iter()
        .map(|(_, version)| version)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::{missed_enqueue_request, missed_targets, top_missed_query};
    use stow_types::api::EnqueueSource;
    use stow_types::identity::WireRustcVersion;

    /// The rendered query substitutes the three validated values into the
    /// template and nothing else — the golden text is the whole contract.
    #[test]
    fn top_missed_query_renders_golden() {
        let targets = vec![
            "x86_64-unknown-linux-gnu".to_owned(),
            "aarch64-apple-darwin".to_owned(),
        ];
        let sql = top_missed_query(50, 7, &targets);
        let expected = include_str!("../sql/top_missed.sql")
            .replace("__LIMIT__", "50")
            .replace("__SINCE_DAYS__", "7")
            .replace(
                "__TARGETS__",
                "'x86_64-unknown-linux-gnu', 'aarch64-apple-darwin'",
            );
        assert_eq!(sql, expected);
    }

    /// A triple outside `CI_TARGET_TRIPLES` is rejected before it can
    /// reach the query text; an absent list covers the whole CI matrix.
    #[test]
    fn missed_targets_validates_against_ci_set() {
        assert!(
            missed_targets(Some(vec!["wasm32-wasip1".to_owned()])).is_err(),
            "non-CI target must be rejected"
        );
        assert_eq!(
            missed_targets(None).expect("default targets").len(),
            stow_types::api::CI_TARGET_TRIPLES.len()
        );
    }

    /// A `top_missed` element maps to the task the scheduler expects:
    /// miss-sourced, miss count as the priority signal, no lockfile pin.
    #[test]
    fn missed_entry_maps_to_enqueue_request() {
        let rustc_version = WireRustcVersion::parse("1.91.1").expect("rustc version");
        let request = missed_enqueue_request(
            "x86_64-unknown-linux-gnu",
            "serde;1.2.3;[\"derive\",\"std\"];42",
            &rustc_version,
        )
        .expect("entry maps to a request");
        assert_eq!(request.crate_name.as_str(), "serde");
        assert_eq!(request.version.to_string(), "1.2.3");
        assert_eq!(request.features_json.raw(), "[\"derive\",\"std\"]");
        assert_eq!(request.target.as_str(), "x86_64-unknown-linux-gnu");
        assert_eq!(request.rustc_version.as_str(), "1.91.1");
        assert_eq!(request.downloads, 42);
        assert_eq!(request.source, EnqueueSource::CacheMiss);
        assert!(!request.preserve_lockfile);
        assert!(request.project_source.is_none());
        assert!(request.depends_on.is_empty());
    }

    /// A malformed element fails loudly rather than submitting a
    /// half-parsed identity.
    #[test]
    fn missed_entry_rejects_bad_shape() {
        let rustc_version = WireRustcVersion::parse("1.91.1").expect("rustc version");
        assert!(
            missed_enqueue_request("x86_64-unknown-linux-gnu", "serde;1.2.3", &rustc_version)
                .is_err()
        );
        assert!(
            missed_enqueue_request(
                "x86_64-unknown-linux-gnu",
                "serde;1.2.3;[\"derive\"];not-a-number",
                &rustc_version,
            )
            .is_err()
        );
    }
}
