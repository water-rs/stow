//! `stow-admin preheat …` — the cache-warming submission lanes plus
//! `preheat plan`, the edge's dry-run expansion.

use std::fmt::Write as _;

use clap::{Args, Subcommand};
use stow_types::api::{
    CI_TARGET_TRIPLES, EnqueueRequest, EnqueueSource, PreheatPlanResponse, PreheatPlanTarget,
    is_ci_target,
};
use stow_types::identity::{
    CrateVersion as TypedCrateVersion, FeaturesJson, TargetTriple, WireRustcVersion,
};
use stow_types::stow_error;
use zenwave::{Client, ResponseExt};

use crate::Edge;
use crate::crates_io;
use crate::render::{self, Output, Table};

const CF_ACCOUNT_ID_ENV: &str = "CF_ACCOUNT_ID";
const CF_ANALYTICS_TOKEN_ENV: &str = "CF_ANALYTICS_TOKEN";
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
    /// Preheat one named crates.io binary crate's dependency graph: its
    /// `.crate` tarball is fetched and resolved once
    /// runs once per CI target — every crates.io node an ordinary crate
    /// task at its resolved feature set, with its crates.io deps as
    /// `depends_on`. The binary's own package is a name source, never a
    /// task. A release that ships `Cargo.lock` has it dropped before
    /// the resolve like every other lane's — the resolve lands on the
    /// latest semver-compatible versions, and `preserve_lockfile` stays
    /// `false`: on the runner it names the task crate's own lockfile,
    /// not the source binary's.
    Binary(BinaryArgs),
    /// The top-binary lane (stow#891): the top-N crates whose default
    /// version ships a binary target and no library (stow#918), ranked
    /// by the last 90 days of `version_downloads`, all read from the
    /// crates.io daily database dump in a single fetch. Each candidate
    /// resolves exactly the way `preheat binary` resolves one — name
    /// sources, never tasks of their own.
    TopBinaries(TopBinariesArgs),
    /// Promote the most-missed `(crate, version, features)` identities in
    /// the Analytics Engine dataset into scheduler tasks.
    Missed(MissedArgs),
    /// Dry run of the edge's closure expansion and dominance pruning for
    /// one crate request — the tasks a dispatch wave would enqueue per
    /// target. Nothing is enqueued.
    Plan(PlanArgs),
    /// Resolve a wave on the operator's machine and submit one
    /// dependency tree per source to the scheduler's operations entry
    /// point at the caller's `--priority` (stow#880). The scheduler
    /// owns dispatch from there — no second dispatcher remains.
    Manual(crate::manual::ManualArgs),
    /// The stars-ranked lane: `generate` rebuilds the reviewed
    /// `preheat/projects.toml` list from GitHub, `submit` resolves every
    /// listed repository and enqueues its crates.io graph as ordinary
    /// crate tasks.
    Projects(crate::projects::ProjectsArgs),
    /// The `Preheat cost` lane's ledger snapshots and report (stow#773)
    /// — mock-stack only: the ledger exists on budget-probe deploys.
    Cost(crate::preheat_cost::CostArgs),
}

#[derive(Args)]
pub struct TopBinariesArgs {
    /// Rustc version the tasks build for.
    #[arg(long)]
    rustc_version: String,
    /// Comma-separated CI target triples to resolve and enqueue for.
    /// Defaults to every triple `stow_types::api::CI_TARGET_TRIPLES`
    /// covers — the list never grows for one binary.
    #[arg(long, value_delimiter = ',')]
    targets: Option<Vec<String>>,
    /// How many top-downloaded binary crates to resolve.
    #[arg(long, default_value_t = 100)]
    limit: usize,
    /// Submit the batch. Without it the command prints the plan and exits
    /// 0 without enqueuing.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Args)]
pub struct BinaryArgs {
    /// Crate name, optionally `name@version`. Without a version the
    /// newest non-yanked release on crates.io is submitted.
    pub crate_spec: String,
    /// Comma-separated CI target triples to preheat for. Defaults to
    /// every triple `stow_types::api::CI_TARGET_TRIPLES` covers.
    #[arg(long, value_delimiter = ',')]
    targets: Option<Vec<String>>,
    /// Rustc version the tasks build for. Absent resolves the
    /// scheduler's current stable channel version.
    #[arg(long)]
    rustc_version: Option<String>,
    /// Submit the batch. Without it the command prints the plan and exits
    /// 0 without enqueuing.
    #[arg(long)]
    pub yes: bool,
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
    pub yes: bool,
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

/// Command entry point.
///
/// A lane reaches the edge only to submit: its plan — crates.io,
/// the resolver, the signed slices — is computed without one, so the
/// edge is connected up front under `--yes` (a missing `STOW_EDGE_URL`
/// fails before the resolve spends its minutes) and never otherwise.
/// Each lane gets its own crates.io client: its pace gate serializes the
/// lane's API calls and it counts them for the dry-run report.
pub async fn run(args: PreheatArgs, output: Output) -> stow_types::error::Result<()> {
    match args.command {
        PreheatCommand::Manual(manual) => crate::manual::run(manual, output).await,
        PreheatCommand::Projects(args) => crate::projects::run(args, output).await,
        PreheatCommand::Cost(args) => crate::preheat_cost::run(args, output).await,
        PreheatCommand::Binary(args) => {
            let edge = Edge::connect_to_submit(args.yes)?;
            binary(edge.as_ref(), &mut crates_io::CratesIo::new(), args, output).await
        }
        PreheatCommand::TopBinaries(args) => {
            let edge = Edge::connect_to_submit(args.yes)?;
            top_binaries(edge.as_ref(), args, output).await
        }
        PreheatCommand::Missed(args) => {
            let edge = Edge::connect_to_submit(args.yes)?;
            missed(edge.as_ref(), args, output).await
        }
        PreheatCommand::Plan(args) => plan(&mut crates_io::CratesIo::new(), args, output).await,
    }
}

/// The human table for a batch of enqueue requests — the plan every
/// `preheat` submit previews.
fn requests_table(trees: &[stow_types::api::SubmissionTree]) -> String {
    let mut table = Table::new(&[
        "crate", "version", "target", "features", "rustc", "source", "lockfile",
    ]);
    for tree in trees {
        for node in &tree.nodes {
            table.push([
                node.crate_name.as_str().to_owned(),
                node.version.to_string(),
                node.target.as_str().to_owned(),
                node.features_json.raw(),
                node.rustc_version.as_str().to_owned(),
                format!("{:?}", tree.source),
                if node.preserve_lockfile {
                    "source".to_owned()
                } else {
                    "latest".to_owned()
                },
            ]);
        }
    }
    table.render()
}

/// Submit `requests` after rendering the plan — the shared tail of every
/// `preheat` submit lane. Batches post in chunks under the edge's
/// expanded-task bound.
async fn submit_plan(
    edge: Option<&Edge>,
    crates_io: &crates_io::CratesIo,
    mut trees: Vec<stow_types::api::SubmissionTree>,
    output: Output,
) -> stow_types::error::Result<()> {
    // Contained feature sets are served from their smallest containing
    // set rather than built (stow#881): substitute across the lane's
    // whole batch before the plan renders and before anything submits —
    // the plan-only output is the production wave count's input, so it
    // must carry the substituted task ids.
    crate::manual::substitute_against_published(&mut trees).await?;
    // The fetch phase ended before this call — the count cannot change.
    let api_requests = crates_io.api_requests();
    render::mutation(
        output,
        trees,
        move |envelope: &render::Planned<
            Vec<stow_types::api::SubmissionTree>,
            crate::projects::SubmitOutcome,
        >| {
            let nodes: usize = envelope.plan.iter().map(|tree| tree.nodes.len()).sum();
            let mut out = format!("{nodes} task(s)\n");
            if !envelope.plan.is_empty() {
                let _ = write!(out, "{}", requests_table(&envelope.plan));
            }
            if api_requests > 0 {
                let _ = write!(out, "\ncrates.io API requests: {api_requests}");
            }
            if let Some(result) = &envelope.result {
                let _ = write!(
                    out,
                    "\nsubmitted {}, inserted {}, dropped {} in {} batch(es)",
                    result.submitted, result.inserted, result.dropped, result.batches
                );
            }
            let _ = write!(out, "\n{}", render::plan_footer(envelope.dry_run));
            out
        },
        edge.map(|edge| {
            async move |trees: &Vec<stow_types::api::SubmissionTree>| {
                crate::projects::submit_chunked(edge, trees).await
            }
        }),
    )
    .await
}

/// One crate resolve the `top-binaries` lane queues — a ranked
/// binary's default version, resolved for its crates.io graph and
/// never enqueued itself.
struct CrateJob {
    /// crates.io name.
    name: String,
    /// The selected release.
    version: semver::Version,
    /// The crate's 90-day download count — the scheduler's queue
    /// ordering.
    downloads: u64,
}

/// A resolved lane batch's flat task list — per-target batches
/// concatenated in `CI_TARGET_TRIPLES` order.
fn flatten_source(resolved: stow_resolver::SourceResolve) -> Vec<EnqueueRequest> {
    resolved
        .targets
        .into_iter()
        .flat_map(|(_target, tasks)| tasks)
        .collect()
}

/// One submission tree per resolved source (stow#878): every
/// `flatten_source` output folds into the tree the scheduler merges by
/// task id — the per-task embedded subgraph shape is gone.
fn source_tree(resolved: stow_resolver::SourceResolve) -> stow_types::api::SubmissionTree {
    stow_types::api::SubmissionTree::from_enqueue_requests(
        stow_types::api::SubmissionSource::Preheat,
        &flatten_source(resolved),
    )
    .expect("resolved source converts to a submission tree")
}

/// `preheat binary <crate>[@version]` — cache the whole dependency
/// graph of one named crates.io binary.
///
/// The published tarball decides the resolution rather than a guess,
/// but its bundled `Cargo.lock` is dropped like every other lane's —
/// the resolve lands on the latest semver-compatible versions. The
/// dropped lockfile's registry pins still admit the yanked versions
/// they name. `preserve_lockfile` stays `false` on every derived task
/// — on the runner it names the task crate's own lockfile, not the
/// source binary's. The binary's own package is a path member in this
/// resolve — a name source, never a task (`ArtifactKind` has no
/// `Bin`).
async fn binary(
    edge: Option<&Edge>,
    crates_io: &mut crates_io::CratesIo,
    args: BinaryArgs,
    output: Output,
) -> stow_types::error::Result<()> {
    let (crate_name, pinned) = crate::coverage::parse_crate_spec(&args.crate_spec)?;
    let targets = typed_targets(args.targets)?;
    let release = resolve_named_release(crates_io, crate_name.as_str(), pinned.as_ref()).await?;
    let rustc_version = match &args.rustc_version {
        Some(raw) => WireRustcVersion::parse(raw.clone())
            .map_err(|error| stow_error!("--rustc-version: {error}"))?,
        None => crate::rust_channel::stable_rustc_version().await?,
    };

    let version = release.version.as_semver().clone();
    let resolved = tokio::task::spawn_blocking({
        let crate_name = crate_name.clone();
        let targets = targets.clone();
        let rustc_version = rustc_version.clone();
        move || {
            let pool = crate::resolve::ResolvePool::new(&rustc_version)?;
            Ok::<_, stow_types::error::Error>(resolve_binary_crate(
                pool.resolver(),
                pool.runtime(),
                crate_name.as_str(),
                &version,
                release.downloads,
                &targets,
                &rustc_version,
            ))
        }
    })
    .await
    .expect("resolve pool panicked")?;
    let requests = match resolved.map_err(|error| stow_error!("{error}"))? {
        BinaryResolve::Tasks { trees } => {
            let node_count: usize = trees.iter().map(|tree| tree.nodes.len()).sum();
            tracing::info!(
                %crate_name,
                version = %release.version,
                targets = targets.len(),
                tasks = node_count,
                %rustc_version,
                "planned named-binary preheat tasks"
            );
            trees
        }
        BinaryResolve::NoBinary => {
            return Err(stow_error!(
                "{crate_name} {} ships no binary target — the lane only applies to crates with one",
                release.version
            ));
        }
    };
    submit_plan(edge, crates_io, requests, output).await
}

/// The `--targets` option as validated triples — `ci_targets` admits
/// only `CI_TARGET_TRIPLES` members, the parse cannot fail after it.
fn typed_targets(targets: Option<Vec<String>>) -> stow_types::error::Result<Vec<TargetTriple>> {
    ci_targets(targets)?
        .iter()
        .map(|target| {
            TargetTriple::parse(target.clone())
                .map_err(|error| stow_error!("--targets `{target}`: {error}"))
        })
        .collect()
}

/// What resolving one binary crate produced: the task batch its
/// dependency graph yields, or the answer that this lane does not
/// apply — the crate ships no binary target.
enum BinaryResolve {
    /// The crates.io graph resolved into one submission tree.
    Tasks {
        /// The tree the resolve produced (stow#878).
        trees: Vec<stow_types::api::SubmissionTree>,
    },
    /// The crate has no `[[bin]]` — a name source this lane skips.
    NoBinary,
}

/// Resolve one binary crate's published `.crate` in-process — cargo's
/// own resolver once per target — every crates.io node an ordinary
/// crate task at its resolved feature set with its deps as
/// `depends_on`. The binary's own package is a path member in the
/// resolve — a name source, never a task.
///
/// The lockfile treatment is every lane's one: a bundled `Cargo.lock`
/// is dropped before the resolve, so the resolve lands on the latest
/// semver-compatible versions and those land in each task's `version`
/// and `features_json`; the dropped pins survive only as the
/// `dropped_lockfile` admission (yanked versions, git shas).
/// `preserve_lockfile` stays `false` on every derived task — on the
/// runner it names the task crate's own lockfile, not the source
/// binary's.
fn resolve_binary_crate(
    resolver: &stow_resolver::Resolver,
    runtime: &tokio::runtime::Handle,
    crate_name: &str,
    version: &semver::Version,
    downloads: u64,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
) -> Result<BinaryResolve, String> {
    let source = crate::resolve::resolve_crate(
        resolver,
        runtime,
        crate_name,
        version,
        targets,
        rustc_version,
        downloads,
    )?;
    if !source.has_binary {
        return Ok(BinaryResolve::NoBinary);
    }
    Ok(BinaryResolve::Tasks {
        trees: vec![source_tree(source)],
    })
}

/// The release `preheat binary` submits: version, seed features and the
/// download count the scheduler orders the queue by.
#[derive(Debug, Clone)]
struct NamedRelease {
    version: TypedCrateVersion,
    downloads: u64,
}

/// Resolve the crate spec against crates.io.
///
/// A pinned spec must name a published, non-yanked release — silently
/// submitting a neighbouring version would cache an identity nobody
/// asked for.
async fn resolve_named_release(
    crates_io: &mut crates_io::CratesIo,
    crate_name: &str,
    pinned: Option<&TypedCrateVersion>,
) -> stow_types::error::Result<NamedRelease> {
    let detail = crates_io.fetch_crate_detail(crate_name).await?;
    let release = match pinned {
        Some(pinned) => {
            let wanted = pinned.to_string();
            detail
                .versions
                .iter()
                .find(|candidate| candidate.num == wanted && !candidate.yanked)
                .cloned()
                .ok_or_else(|| stow_error!("crates.io lists no non-yanked {crate_name} {wanted}"))?
        }
        None => detail
            .latest_version
            .ok_or_else(|| stow_error!("crates.io lists no non-yanked release of {crate_name}"))?,
    };
    Ok(NamedRelease {
        version: TypedCrateVersion::new(semver::Version::parse(&release.num)?),
        downloads: detail.downloads,
    })
}

/// `preheat top-binaries` — every top-downloaded binary resolved the
/// way `preheat binary` resolves one: cargo's resolver per target,
/// crates.io nodes as ordinary crate tasks. The candidates come from
/// the crates.io database dump, fetched once — the 100 crates whose
/// default version ships a binary target and no library (stow#918),
/// ranked by 90-day downloads.
/// One binary that fails to resolve is reported and skipped — the
/// rest of the wave still lands.
async fn top_binaries(
    edge: Option<&Edge>,
    args: TopBinariesArgs,
    output: Output,
) -> stow_types::error::Result<()> {
    let rustc_version = WireRustcVersion::parse(args.rustc_version.clone())
        .map_err(|error| stow_error!("preheat rustc_version: {error}"))?;
    let targets = typed_targets(args.targets)?;

    let candidates = crate::dump::top_binary_crates(args.limit).await?;
    if candidates.is_empty() {
        return Err(stow_error!(
            "the db-dump ranks no binary crates in its top-{} window",
            args.limit
        ));
    }
    tracing::info!(
        binaries = candidates.len(),
        "db-dump top binary crates: {}",
        candidates
            .iter()
            .map(|candidate| candidate.id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let plan = tokio::task::spawn_blocking({
        let targets = targets.clone();
        let rustc_version = rustc_version.clone();
        move || resolve_binaries(&candidates, &targets, &rustc_version)
    })
    .await
    .expect("resolve pool panicked")?;
    tracing::info!(
        binaries = plan.per_binary.len(),
        tasks = plan.trees.iter().map(|tree| tree.nodes.len()).sum::<usize>(),
        skipped = plan.skipped.len(),
        targets = targets.len(),
        %rustc_version,
        "planned top-binaries preheat tasks"
    );
    render::mutation(
        output,
        plan,
        move |envelope: &render::Planned<BinariesPlan, crate::projects::SubmitOutcome>| {
            let plan = &envelope.plan;
            let mut out = format!(
                "{} task(s) from {} binaries\n",
                plan.trees
                    .iter()
                    .map(|tree| tree.nodes.len())
                    .sum::<usize>(),
                plan.per_binary.len()
            );
            if !plan.per_binary.is_empty() {
                let mut table = Table::new(&["binary", "tasks"]);
                for contribution in &plan.per_binary {
                    table.push([contribution.binary.clone(), contribution.tasks.to_string()]);
                }
                let _ = write!(out, "{}", table.render());
            }
            if !plan.skipped.is_empty() {
                let mut table = Table::new(&["binary", "reason"]);
                for skipped in &plan.skipped {
                    table.push([skipped.binary.clone(), skipped.reason.clone()]);
                }
                let _ = write!(out, "\nskipped\n{}", table.render());
            }
            if let Some(result) = &envelope.result {
                let _ = write!(
                    out,
                    "\nsubmitted {}, inserted {}, dropped {} in {} batch(es)",
                    result.submitted, result.inserted, result.dropped, result.batches
                );
            }
            let _ = write!(out, "\n{}", render::plan_footer(envelope.dry_run));
            out
        },
        edge.map(|edge| {
            async move |plan: &BinariesPlan| {
                crate::projects::submit_chunked(edge, &plan.trees).await
            }
        }),
    )
    .await
}

/// Resolve every candidate binary into the shared plan — one task batch
/// per crates.io node across the targets, computed in-process on the
/// resolve pool. A binary that fails to resolve (download, unpack,
/// resolution, or simply ships no binary) is recorded in `skipped` and
/// the rest of the wave proceeds.
fn resolve_binaries(
    candidates: &[crate::dump::BinaryCandidate],
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<BinariesPlan> {
    let mut jobs = Vec::with_capacity(candidates.len());
    for binary in candidates {
        jobs.push(CrateJob {
            name: binary.id.clone(),
            version: semver::Version::parse(&binary.version).map_err(|error| {
                stow_error!(
                    "parse crates.io version `{}` for `{}`: {error}",
                    binary.version,
                    binary.id
                )
            })?,
            downloads: binary.downloads,
        });
    }
    let pool = crate::resolve::ResolvePool::new(rustc_version)?;
    let mut slots: Vec<Option<Result<BinaryResolve, String>>> = jobs.iter().map(|_| None).collect();
    pool.run(
        &jobs,
        |resolver, runtime, job| {
            resolve_binary_crate(
                resolver,
                runtime,
                &job.name,
                &job.version,
                job.downloads,
                targets,
                rustc_version,
            )
        },
        |index, _job, result| slots[index] = Some(result),
    )?;
    let mut plan = BinariesPlan {
        trees: Vec::new(),
        per_binary: Vec::with_capacity(candidates.len()),
        skipped: Vec::new(),
    };
    for (job, slot) in jobs.iter().zip(slots) {
        match slot.expect("the pool produces one result per job") {
            Ok(BinaryResolve::Tasks { trees }) => {
                let node_count: usize = trees.iter().map(|tree| tree.nodes.len()).sum();
                tracing::info!(binary = %job.name, tasks = node_count, "resolved");
                plan.per_binary.push(BinaryContribution {
                    binary: job.name.clone(),
                    tasks: node_count,
                });
                plan.trees.extend(trees);
            }
            Ok(BinaryResolve::NoBinary) => {
                let reason = format!("{} {} ships no binary target", job.name, job.version);
                tracing::warn!(binary = %job.name, %reason, "skipped");
                plan.skipped.push(SkippedBinary {
                    binary: job.name.clone(),
                    reason,
                });
            }
            Err(error) => {
                tracing::warn!(binary = %job.name, reason = %error, "skipped");
                plan.skipped.push(SkippedBinary {
                    binary: job.name.clone(),
                    reason: error,
                });
            }
        }
    }
    Ok(plan)
}

/// One resolved binary's contribution to the plan: its task count.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BinaryContribution {
    /// The binary crate's crates.io name.
    pub binary: String,
    /// How many enqueue requests its resolve graphs produced.
    pub tasks: usize,
}

/// A binary that failed to resolve, with its reason.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SkippedBinary {
    /// The binary crate's crates.io name.
    pub binary: String,
    /// Why resolution failed — fetch or resolver.
    pub reason: String,
}

/// The plan `top-binaries` previews and applies: every task every
/// binary produced, plus per-binary outcomes.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BinariesPlan {
    /// Every submission tree across every binary and target (stow#878).
    pub trees: Vec<stow_types::api::SubmissionTree>,
    /// How many requests each binary produced.
    pub per_binary: Vec<BinaryContribution>,
    /// Binaries resolution failed on, with their reasons.
    pub skipped: Vec<SkippedBinary>,
}

/// The Analytics Engine query template; `__LIMIT__`, `__SINCE_DAYS__`,
/// `__TARGETS__` and `__RUSTC_VERSION__` are the substitution points (see the file's own
/// comment for why that is safe).
const TOP_MISSED_SQL: &str = include_str!("../sql/top_missed.sql");

/// Render the top-missed query for a dispatch run. `targets` must already
/// be validated by [`ci_targets`] — the literals land in the SQL text
/// unescaped because the SQL API has no bound parameters.
fn top_missed_query(
    limit: usize,
    since_days: u32,
    targets: &[String],
    rustc_version: &WireRustcVersion,
) -> String {
    TOP_MISSED_SQL
        .replace("__LIMIT__", &limit.to_string())
        .replace("__SINCE_DAYS__", &since_days.to_string())
        .replace("__RUSTC_VERSION__", rustc_version.as_str())
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
pub fn ci_targets(targets: Option<Vec<String>>) -> stow_types::error::Result<Vec<String>> {
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
/// Contextual task identities `topKWeighted` ranked
/// for it.
#[derive(Debug, serde::Deserialize)]
struct TopMissedRow {
    /// The row's target — carried in the query answer but unused here:
    /// the task id embeds it (stow#588).
    #[expect(dead_code)]
    target: String,
    top_missed: Vec<String>,
}

/// Run the top-missed query against the Analytics Engine SQL API.
/// `CF_ACCOUNT_ID` and `CF_ANALYTICS_TOKEN` (an API token with
/// `Account Analytics: Read`) are both required.
async fn fetch_top_missed(query: &str) -> stow_types::error::Result<Vec<TopMissedRow>> {
    let account_id =
        std::env::var(CF_ACCOUNT_ID_ENV).map_err(|_| stow_error!("missing {CF_ACCOUNT_ID_ENV}"))?;
    let token = std::env::var(CF_ANALYTICS_TOKEN_ENV)
        .map_err(|_| stow_error!("missing {CF_ANALYTICS_TOKEN_ENV}"))?;
    let base = crate::cloudflare::analytics_sql_base()?;
    let url = format!("{base}/accounts/{account_id}/analytics_engine/sql");
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
    let envelope: stow_types::analytics::Envelope<TopMissedRow> = response
        .into_json()
        .await
        .map_err(|error| stow_error!("parse Analytics Engine response: {error}"))?;
    Ok(envelope.data)
}

/// Map one `task_id;misses` element of a [`TopMissedRow::top_missed`]
/// array to the promote-by-id entry it submits (stow#588). The miss
/// row's task id is the whole identity — the scheduler re-derives the
/// subgraph from its node store, so nothing more travels on this lane;
/// an id the store does not hold comes back as `unknown`, never
/// re-minted. A parse failure means the dataset diverged from
/// `miss_logger`'s layout — a bug to fail on, not a row to skip.
fn missed_task_id_entry(
    entry: &str,
) -> stow_types::error::Result<stow_types::api::SubmitTaskIdEntry> {
    let [task_id, misses]: [&str; 2] =
        entry
            .split(';')
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| {
                stow_error!(
                    "malformed top_missed entry {entry:?} - expected a `task_id;misses` pair"
                )
            })?;
    Ok(stow_types::api::SubmitTaskIdEntry {
        task_id: task_id.to_owned(),
        downloads: misses
            .parse()
            .map_err(|error| stow_error!("top_missed misses `{misses}`: {error}"))?,
    })
}

async fn missed(
    edge: Option<&Edge>,
    args: MissedArgs,
    output: Output,
) -> stow_types::error::Result<()> {
    let rustc_version = WireRustcVersion::parse(args.rustc_version)
        .map_err(|error| stow_error!("preheat rustc_version: {error}"))?;
    let targets = ci_targets(args.targets)?;
    if args.limit == 0 {
        return Err(stow_error!("--limit must be at least 1"));
    }
    if args.since_days == 0 {
        return Err(stow_error!("--since-days must be at least 1"));
    }
    let query = top_missed_query(args.limit, args.since_days, &targets, &rustc_version);
    let rows = fetch_top_missed(&query).await?;

    let mut entries = Vec::new();
    for row in &rows {
        for entry in &row.top_missed {
            entries.push(missed_task_id_entry(entry)?);
        }
    }
    if entries.is_empty() {
        tracing::info!("no missed task ids in the window; nothing to submit");
    }
    submit_ids_plan(edge, entries, output).await
}

/// The promote-by-id submit: same dry-run/`--yes` envelope as the
/// request lanes, applied through the trusted submit-ids route — the
/// scheduler resolves each id's subgraph from its node store and
/// reports the ids it does not hold as `unknown` (stow#588).
async fn submit_ids_plan(
    edge: Option<&Edge>,
    entries: Vec<stow_types::api::SubmitTaskIdEntry>,
    output: Output,
) -> stow_types::error::Result<()> {
    render::mutation(
        output,
        entries,
        move |envelope: &render::Planned<
            Vec<stow_types::api::SubmitTaskIdEntry>,
            crate::projects::SubmitIdsOutcome,
        >| {
            let mut out = format!(
                "{} task id(s)
",
                envelope.plan.len()
            );
            if let Some(result) = &envelope.result {
                let _ = write!(
                    out,
                    "submitted {}, inserted {}, unknown {} in {} batch(es)",
                    result.submitted,
                    result.inserted,
                    result.unknown.len(),
                    result.batches
                );
                for id in &result.unknown {
                    let _ = write!(out, "\n  unknown: {id}");
                }
            }
            let _ = write!(out, "\n{}", render::plan_footer(envelope.dry_run));
            out
        },
        edge.map(|edge| {
            async move |entries: &Vec<stow_types::api::SubmitTaskIdEntry>| {
                crate::projects::submit_ids_chunked(edge, entries).await
            }
        }),
    )
    .await
}

/// `preheat plan` — the dry run of a crate request's closure expansion
/// and coverage pruning, computed in-process on the same resolver the
/// submit lanes use. Coverage comes from verified signed slices and
/// requires the exact dependency context and complete unit shapes.
#[allow(clippy::too_many_lines)] // one lane end to end: fetch → resolve → coverage → enqueue
async fn plan(
    crates_io: &mut crates_io::CratesIo,
    args: PlanArgs,
    output: Output,
) -> stow_types::error::Result<()> {
    let (crate_name, pinned) = crate::coverage::parse_crate_spec(&args.crate_spec)?;
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
    let release = resolve_named_release(crates_io, crate_name.as_str(), pinned.as_ref()).await?;
    let rustc_version = match &args.rustc_version {
        Some(raw) => WireRustcVersion::parse(raw.clone())
            .map_err(|error| stow_error!("--rustc-version: {error}"))?,
        None => crate::rust_channel::stable_rustc_version().await?,
    };
    let targets: Vec<String> = match &args.target {
        Some(raw) => {
            TargetTriple::parse(raw.clone()).map_err(|error| stow_error!("--target: {error}"))?;
            vec![raw.clone()]
        }
        None => CI_TARGET_TRIPLES.iter().map(|t| (*t).to_owned()).collect(),
    };
    let seed = features_json.features().to_vec();
    let version = release.version.as_semver().clone();
    let crate_name_string = crate_name.to_string();
    let outputs = tokio::task::spawn_blocking({
        let rustc_version = rustc_version.clone();
        let version = version.clone();
        move || {
            let pool = crate::resolve::ResolvePool::new(&rustc_version)?;
            let resolver = pool.shared();
            let no_default_features = !seed.iter().any(|feature| feature == "default");
            pool.runtime()
                .block_on(resolver.resolve_crate_units(
                    &crate_name_string,
                    &version,
                    &stow_resolver::ResolveOptions {
                        features: seed,
                        no_default_features,
                        ..stow_resolver::ResolveOptions::default()
                    },
                    &targets,
                ))
                .map_err(|error| stow_error!("resolve {crate_name_string} {version}: {error:#}"))
        }
    })
    .await
    .expect("resolve pool panicked")?;

    let mut parts = Vec::with_capacity(outputs.len());
    for (target, output) in &outputs {
        let target_parts =
            stow_resolver::request_plan_parts(&output.units, &output.roots, target, &rustc_version)
                .map_err(|error| {
                    stow_error!("plan {crate_name} {version} for {target}: {error:#}")
                })?;
        parts.push((target, target_parts));
    }
    let target_triples = outputs
        .iter()
        .map(|(target, _)| TargetTriple::parse(target.clone()).map_err(Into::into))
        .collect::<stow_types::error::Result<Vec<_>>>()?;
    let mut spellings = std::collections::BTreeMap::new();
    for (_, target_parts) in &parts {
        for (index, node) in target_parts.graph.nodes().iter().enumerate() {
            let task_id = target_parts
                .graph
                .task_id(index)
                .ok_or_else(|| stow_error!("resolved graph has no task id for node {index}"))?
                .to_owned();
            spellings.insert(task_id, node.explicit_spelling);
        }
    }
    let covered =
        crate::manual::contextual_coverage(&target_triples, &rustc_version, &spellings).await?;
    let mut planned = Vec::with_capacity(parts.len());
    for (target, target_parts) in parts {
        let (tasks, _uncovered) = stow_resolver::enqueue_requests_inner(
            &target_parts.graph,
            &covered,
            EnqueueSource::HumanRequest,
            0,
        )
        .map_err(|error| stow_error!("plan {target} requests: {error:#}"))?;
        let root_cached = target_parts
            .root_task_id
            .as_ref()
            .is_some_and(|key| covered.contains(key));
        planned.push(PreheatPlanTarget {
            target: TargetTriple::parse(target.clone())
                .map_err(|error| stow_error!("plan target `{target}`: {error}"))?,
            root_cached,
            tasks,
        });
    }
    let plan = PreheatPlanResponse {
        crate_name,
        version: release.version,
        rustc_version,
        targets: planned,
    };
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
                    task.depends_on()
                        .expect("planned task subgraph resolves")
                        .len()
                        .to_string(),
                    if task.preserve_lockfile {
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

#[cfg(test)]
mod tests {
    use super::{ci_targets, missed_task_id_entry, top_missed_query};

    use stow_types::identity::WireRustcVersion;

    /// The rendered query substitutes the three validated values into the
    /// template and nothing else — the golden text is the whole contract.
    #[test]
    fn top_missed_query_renders_golden() {
        let targets = vec![
            "x86_64-unknown-linux-gnu".to_owned(),
            "aarch64-apple-darwin".to_owned(),
        ];
        let rustc_version = WireRustcVersion::parse("1.91.1").expect("rustc");
        let sql = top_missed_query(50, 7, &targets, &rustc_version);
        let expected = include_str!("../sql/top_missed.sql")
            .replace("__LIMIT__", "50")
            .replace("__SINCE_DAYS__", "7")
            .replace("__RUSTC_VERSION__", "1.91.1")
            .replace(
                "__TARGETS__",
                "'x86_64-unknown-linux-gnu', 'aarch64-apple-darwin'",
            );
        assert_eq!(sql, expected);
        assert!(sql.contains("AND blob6 = '1.91.1'"));
        assert!(sql.contains("AND blob12 <> ''"));
        assert!(sql.contains("GROUP BY\n        target,\n        task_id"));
    }

    /// A triple outside `CI_TARGET_TRIPLES` is rejected before it can
    /// reach the query text; an absent list covers the whole CI matrix.
    #[test]
    fn requested_targets_validate_against_ci_set() {
        assert!(
            ci_targets(Some(vec!["wasm32-wasip1".to_owned()])).is_err(),
            "non-CI target must be rejected"
        );
        assert_eq!(
            ci_targets(None).expect("default targets").len(),
            stow_types::api::CI_TARGET_TRIPLES.len()
        );
    }

    /// A `top_missed` element maps to the promote-by-id entry the
    /// submit-ids lane posts; a malformed element fails loudly rather
    /// than submitting a half-parsed id (stow#588).
    #[test]
    fn missed_entry_maps_to_task_id_entry() {
        let entry = missed_task_id_entry(
            "serde-1.0.228--x86_64-unknown-linux-gnu-r1.91.1-d4bc91f87c0a1f0e;42",
        )
        .expect("entry");
        assert_eq!(
            entry.task_id,
            "serde-1.0.228--x86_64-unknown-linux-gnu-r1.91.1-d4bc91f87c0a1f0e"
        );
        assert_eq!(entry.downloads, 42);
    }

    /// A malformed element fails loudly rather than submitting a
    /// half-parsed identity.
    #[test]
    fn missed_entry_rejects_bad_shape() {
        assert!(
            missed_task_id_entry("serde;1.2.3").is_err(),
            "three-field entry must fail"
        );
        assert!(
            missed_task_id_entry("some-task-id;not-a-count").is_err(),
            "non-numeric misses must fail"
        );
    }
}
