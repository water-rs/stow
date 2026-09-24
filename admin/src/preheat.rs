//! `stow-admin preheat …` — the cache-warming submission lanes plus
//! `preheat plan`, the edge's dry-run expansion.

use std::fmt::Write as _;

use clap::{Args, Subcommand};
use stow_types::api::{
    CI_TARGET_TRIPLES, EnqueueDependency, EnqueueRequest, EnqueueSource, PreheatPlanRequest,
    PreheatPlanResponse, is_ci_target,
};
use stow_types::identity::{
    CrateName, CrateVersion as TypedCrateVersion, FeaturesJson, TargetTriple, WireRustcVersion,
};
use stow_types::stow_error;
use zenwave::{Client, ResponseExt};

use crate::Edge;
use crate::crates_io::{self, CrateVersion};
use crate::render::{self, Output, Table};

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
    /// version line on the target, each with the default feature set. A
    /// ranked crate whose newest release ships no library target is a
    /// name source like any binary: its dependency graph resolves
    /// through cargo's resolver in the edge and its crates.io
    /// nodes are enqueued in its place.
    Top(TopArgs),
    /// Preheat one named crates.io binary crate's dependency graph: its
    /// `.crate` tarball is fetched and resolved once
    /// runs once per CI target — every crates.io node an ordinary crate
    /// task at its resolved feature set, with its crates.io deps as
    /// `depends_on`. The binary's own package is a name source, never a
    /// task. A release that ships `Cargo.lock` unpacks with it in
    /// place, so the resolve lands on the pins `cargo install --locked`
    /// reproduces — the pins bake into each task's `version` and
    /// `features_json`, and `preserve_lockfile` stays `false`: on the
    /// runner it names the task crate's own lockfile, not the source
    /// binary's.
    Binary(BinaryArgs),
    /// The download-ranked binary lane: resolve each of the top-N
    /// most-downloaded *binary* crates exactly the way `preheat binary`
    /// resolves one — name sources, never tasks of their own.
    TopBinaries(TopBinariesArgs),
    /// Promote the most-missed `(crate, version, features)` identities in
    /// the Analytics Engine dataset into scheduler tasks.
    Missed(MissedArgs),
    /// Dry run of the edge's closure expansion and dominance pruning for
    /// one crate request — the tasks a dispatch wave would enqueue per
    /// target. Nothing is enqueued.
    Plan(PlanArgs),
    /// The stars-ranked lane: `generate` rebuilds the reviewed
    /// `preheat/projects.toml` list from GitHub, `submit` resolves every
    /// listed repository and enqueues its crates.io graph as ordinary
    /// crate tasks.
    Projects(crate::projects::ProjectsArgs),
}

#[derive(Args)]
pub struct TopArgs {
    /// Comma-separated CI target triples to enqueue for. Defaults to
    /// every triple `stow_types::api::CI_TARGET_TRIPLES` covers — the
    /// ranked crates.io list is walked once and the same resolve serves
    /// every target, so the lane is one invocation rather than nine.
    #[arg(long, value_delimiter = ',')]
    targets: Option<Vec<String>>,
    /// Rustc version the tasks build for.
    #[arg(long)]
    rustc_version: String,
    /// How many top-downloaded crates to enqueue per target.
    #[arg(long, default_value_t = 100)]
    limit: usize,
    /// Submit the batch. Without it the command prints the plan and exits
    /// 0 without enqueuing.
    #[arg(long)]
    yes: bool,
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
    yes: bool,
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

/// Command entry point — sync like `index::run` because the executor is
/// per-lane: `projects generate` runs against GitHub only, and every
/// lane that posts to the scheduler connects the edge itself.
pub fn run(args: PreheatArgs, output: Output) -> stow_types::error::Result<()> {
    smol::block_on(async move {
        match args.command {
            PreheatCommand::Projects(args) => crate::projects::run(args, output).await,
            command => {
                let edge = crate::Edge::connect().await?;
                run_on_edge(&edge, command, output).await
            }
        }
    })
}

async fn run_on_edge(
    edge: &Edge,
    command: PreheatCommand,
    output: Output,
) -> stow_types::error::Result<()> {
    // One crates.io client per invocation: its pace gate serializes the
    // lane's API calls and it counts them for the dry-run report.
    let mut crates_io = crates_io::CratesIo::new();
    match command {
        PreheatCommand::Top(args) => top(edge, &mut crates_io, args, output).await,
        PreheatCommand::Binary(args) => binary(edge, &mut crates_io, args, output).await,
        PreheatCommand::TopBinaries(args) => top_binaries(edge, &mut crates_io, args, output).await,
        PreheatCommand::Missed(args) => missed(edge, &crates_io, args, output).await,
        PreheatCommand::Plan(args) => plan(edge, args, output).await,
        PreheatCommand::Projects(_) => {
            unreachable!("projects commands dispatch before the edge connect")
        }
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
            if request.preserve_lockfile {
                "source".to_owned()
            } else {
                "latest".to_owned()
            },
        ]);
    }
    table.render()
}

/// Submit `requests` after rendering the plan — the shared tail of every
/// `preheat` submit lane. Batches post in chunks under the edge's
/// expanded-task bound.
async fn submit_plan(
    edge: &Edge,
    crates_io: &crates_io::CratesIo,
    requests: Vec<EnqueueRequest>,
    yes: bool,
    output: Output,
) -> stow_types::error::Result<()> {
    // The fetch phase ended before this call — the count cannot change.
    let api_requests = crates_io.api_requests();
    render::mutation(
        output,
        yes,
        requests,
        move |envelope: &render::Planned<Vec<EnqueueRequest>, crate::projects::SubmitOutcome>| {
            let mut out = format!("{} task(s)\n", envelope.plan.len());
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
        async move |requests: &Vec<EnqueueRequest>| {
            crate::projects::submit_chunked(edge, requests).await
        },
    )
    .await
}

async fn top(
    edge: &Edge,
    crates_io: &mut crates_io::CratesIo,
    args: TopArgs,
    output: Output,
) -> stow_types::error::Result<()> {
    let targets = typed_targets(args.targets)?;
    let rustc_version = WireRustcVersion::parse(args.rustc_version.clone())
        .map_err(|error| stow_error!("preheat rustc_version: {error}"))?;

    // The ranking and the per-crate metadata are walked once — every
    // target draws from the same answers, so the lane spends one
    // crates.io pass total rather than one per target.
    let crates = crates_io.fetch_top_crates(args.limit).await?;
    let mut requests = Vec::new();
    for krate in crates {
        // The newest published release's `has_lib` decides which lane
        // the ranked crate takes — the publish shape is a property of
        // the release, not of the ranking, and crates.io's version
        // record already carries it, so no tarball is fetched to find
        // out. A library resolves its version lines through the edge —
        // proc-macro crates land on the runner-family host and every
        // node carries its dependency edges; a crate with no library
        // target is a name source like any binary, resolved through the
        // same lane, never enqueued itself.
        let detail = crates_io.fetch_crate_detail(&krate.id).await?;
        let Some(latest) = detail.latest_version else {
            tracing::warn!(krate = %krate.id, "no published release; skipped");
            continue;
        };
        if !latest.has_lib.unwrap_or(true) {
            let tasks = resolve_bin_only_ranked(
                edge,
                &krate.id,
                &latest.num,
                krate.downloads,
                &targets,
                &rustc_version,
            )
            .await?;
            requests.extend(tasks);
            continue;
        }
        let selected = select_version_lines(&detail.versions)?;
        for version in selected {
            let typed_version =
                TypedCrateVersion::new(semver::Version::parse(&version).map_err(|error| {
                    stow_error!(
                        "parse crates.io version `{version}` for `{}`: {error}",
                        krate.id
                    )
                })?);
            let resolved = resolve_crate_edge(
                edge,
                &krate.id,
                &typed_version,
                &targets,
                &rustc_version,
                krate.downloads,
            )
            .await?;
            requests.extend(resolved.tasks);
        }
    }
    tracing::info!(
        api_requests = crates_io.api_requests(),
        tasks = requests.len(),
        targets = targets.len(),
        "planned top preheat tasks"
    );
    submit_plan(edge, crates_io, requests, args.yes, output).await
}

/// The bin-only half of `top`'s per-crate branch: the ranked crate's
/// newest release reports no library target, so it is a name source like
/// any binary. The tarball is fetched only on this branch — a library
/// never pays for it — unpacked under `scratch`, and resolved through
/// the edge's crate resolve. Its crates.io graph becomes the task batch;
/// the crate itself is never enqueued.
async fn resolve_bin_only_ranked(
    edge: &Edge,
    crate_name: &str,
    version: &str,
    downloads: u64,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<Vec<EnqueueRequest>> {
    let typed_version =
        TypedCrateVersion::new(semver::Version::parse(version).map_err(|error| {
            stow_error!("parse crates.io version `{version}` for `{crate_name}`: {error}")
        })?);
    let resolved = resolve_crate_edge(
        edge,
        crate_name,
        &typed_version,
        targets,
        rustc_version,
        downloads,
    )
    .await?;
    if resolved.has_library {
        tracing::warn!(
            krate = %crate_name,
            version = %typed_version,
            "crates.io reports has_lib=false but the tarball declares a library"
        );
    }
    let tasks = resolved.tasks;
    tracing::info!(
        krate = %crate_name,
        version = %typed_version,
        tasks = tasks.len(),
        ships_lockfile = resolved.ships_lockfile,
        "ranked crate ships no library — resolved as a name source"
    );
    Ok(tasks)
}

/// `preheat binary <crate>[@version]` — cache the whole dependency
/// graph of one named crates.io binary.
///
/// The published tarball decides the resolution rather than a guess: a
/// release that ships a `Cargo.lock` unpacks with it in place, so
/// a resolve lands on the pins `cargo install --locked`
/// reproduces and those pins bake into each task's `version` and
/// `features_json`; one that ships none resolves fresh, which is what
/// plain `cargo install` does for it. `preserve_lockfile` stays `false`
/// on every derived task — on the runner it names the task crate's own
/// lockfile, not the source binary's. The binary's own package is a
/// path member in this resolve — a name source, never a task
/// (`ArtifactKind` has no `Bin`).
async fn binary(
    edge: &Edge,
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
        None => stable_rustc_version(edge, &crate_name, &release, targets[0].as_str()).await?,
    };

    let resolved = resolve_binary_crate(
        edge,
        crate_name.as_str(),
        &release.version,
        release.downloads,
        &targets,
        &rustc_version,
    )
    .await;
    let requests = match resolved? {
        BinaryResolve::Tasks { tasks, published } => {
            tracing::info!(
                %crate_name,
                version = %release.version,
                targets = targets.len(),
                tasks = tasks.len(),
                %rustc_version,
                ships_lockfile = published.ships_lockfile,
                "planned named-binary preheat tasks"
            );
            tasks
        }
        BinaryResolve::NoBinary => {
            return Err(stow_error!(
                "{crate_name} {} ships no binary target — `preheat top` is the library lane",
                release.version
            ));
        }
    };
    submit_plan(edge, crates_io, requests, args.yes, output).await
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

/// What the published `.crate` says about a release — the flags the
/// edge's crate resolve reports back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PublishedCrate {
    /// The package declares or auto-discovers at least one `[[bin]]`.
    has_binary: bool,
    /// The package declares a `[lib]` or auto-discovers `src/lib.rs`.
    has_library: bool,
    /// The package ships the `Cargo.lock` `cargo install --locked`
    /// resolves against.
    ships_lockfile: bool,
}

/// What resolving one binary crate produced: the task batch its
/// dependency graph yields, or the answer that this lane does not
/// apply — the crate ships no binary target.
enum BinaryResolve {
    /// The crates.io graph resolved into tasks.
    Tasks {
        /// Every enqueue request the resolve produced.
        tasks: Vec<EnqueueRequest>,
        /// What the published tarball declared, kept for the log line.
        published: PublishedCrate,
    },
    /// The crate has no `[[bin]]` — a name source this lane skips.
    NoBinary,
}

/// Download one binary crate's published `.crate`, unpack it under
/// — `POST /api/v1/admin/resolve/crate`, cargo's own resolver on the
/// worker once per target — every crates.io node an ordinary crate task
/// at its resolved feature set with its deps as `depends_on`. The
/// binary's own package is a path member in the resolve — a name source,
/// never a task.
///
/// The lockfile treatment is the lane's existing one: a release that
/// ships a `Cargo.lock` unpacks with it in place, so the resolve lands
/// on the pins `cargo install --locked` reproduces and those pins bake
/// into each task's `version` and `features_json`; one that ships none
/// resolves fresh, the plain-`cargo install` resolve. `preserve_lockfile`
/// stays `false` on every derived task — on the runner it names the
/// task crate's own lockfile, not the source binary's.
async fn resolve_binary_crate(
    edge: &Edge,
    crate_name: &str,
    version: &TypedCrateVersion,
    downloads: u64,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<BinaryResolve> {
    let resolved =
        resolve_crate_edge(edge, crate_name, version, targets, rustc_version, downloads).await?;
    if !resolved.has_binary {
        return Ok(BinaryResolve::NoBinary);
    }
    Ok(BinaryResolve::Tasks {
        tasks: resolved.tasks,
        published: PublishedCrate {
            has_binary: resolved.has_binary,
            has_library: resolved.has_library,
            ships_lockfile: resolved.ships_lockfile,
        },
    })
}

/// One published `.crate` resolved on the edge: `POST
/// /api/v1/admin/resolve/crate` — the worker downloads the tarball and
/// runs cargo's own resolver on it, so no local cargo or filesystem is
/// involved. The returned tasks cover every requested target; this
/// helper flattens them into the lane's single batch.
async fn resolve_crate_edge(
    edge: &Edge,
    crate_name: &str,
    version: &TypedCrateVersion,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
    downloads: u64,
) -> stow_types::error::Result<EdgeCrateResolve> {
    let request = stow_types::api::AdminResolveCrateRequest {
        crate_name: CrateName::parse(crate_name)
            .map_err(|error| stow_error!("crate name `{crate_name}`: {error}"))?,
        version: version.clone(),
        targets: targets.to_vec(),
        rustc_version: rustc_version.clone(),
        downloads,
    };
    let resolved: stow_types::api::AdminResolveResponse = edge
        .post_json("/api/v1/admin/resolve/crate", &request)
        .await?;
    let tasks = resolved
        .targets
        .into_iter()
        .flat_map(|batch| batch.tasks)
        .collect();
    Ok(EdgeCrateResolve {
        tasks,
        has_binary: resolved.has_binary,
        has_library: resolved.has_library,
        ships_lockfile: resolved.ships_lockfile,
    })
}

/// The flat task batch one edge crate resolve returned plus its
/// publish-shape flags.
struct EdgeCrateResolve {
    /// Every enqueue request across the requested targets.
    tasks: Vec<EnqueueRequest>,
    /// Whether the package ships a `[[bin]]`.
    has_binary: bool,
    /// Whether the package ships a library target.
    has_library: bool,
    /// Whether the `.crate` carried a `Cargo.lock`.
    ships_lockfile: bool,
}

/// The release `preheat binary` submits: version, seed features and the
/// download count the scheduler orders the queue by.
#[derive(Debug, Clone)]
struct NamedRelease {
    version: TypedCrateVersion,
    features_json: FeaturesJson,
    downloads: u64,
}

/// Resolve the crate spec against crates.io.
///
/// A pinned spec must name a published, non-yanked release — silently
/// submitting a neighbouring version would cache an identity nobody
/// asked for. The seed feature set follows the same rule as the top-N
/// lanes: `["default"]` when the release declares a `default` feature,
/// `[]` otherwise.
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
    let features_json = if release.features.contains_key("default") {
        FeaturesJson::canonicalize(vec!["default".to_owned()])
            .map_err(|error| stow_error!("canonicalize default features: {error}"))?
    } else {
        FeaturesJson::default()
    };
    Ok(NamedRelease {
        version: TypedCrateVersion::new(semver::Version::parse(&release.num)?),
        features_json,
        downloads: detail.downloads,
    })
}

/// The stable `rustc` the scheduler is currently building for.
///
/// `POST /api/v1/admin/preheat/plan` resolves it from the DO-cached
/// channel manifest, so the operator does not have to name a version the
/// pool would not match anyway. The plan is asked for one target, since
/// only its `rustc_version` is read.
async fn stable_rustc_version(
    edge: &Edge,
    crate_name: &CrateName,
    release: &NamedRelease,
    target: &str,
) -> stow_types::error::Result<WireRustcVersion> {
    let request = PreheatPlanRequest {
        crate_name: crate_name.clone(),
        version: Some(release.version.clone()),
        features_json: release.features_json.clone(),
        target: Some(
            TargetTriple::parse(target.to_owned())
                .map_err(|error| stow_error!("--targets `{target}`: {error}"))?,
        ),
        rustc_version: None,
    };
    let plan: PreheatPlanResponse = edge
        .post_json("/api/v1/admin/preheat/plan", &request)
        .await?;
    Ok(plan.rustc_version)
}

/// `preheat top-binaries` — every top-downloaded binary resolved the
/// way `preheat binary` resolves one: the edge unpacks the tarball and
/// runs cargo's resolver per target, crates.io nodes as ordinary crate
/// tasks. One binary that fails to resolve is reported and skipped —
/// the rest of the wave still lands.
async fn top_binaries(
    edge: &Edge,
    crates_io: &mut crates_io::CratesIo,
    args: TopBinariesArgs,
    output: Output,
) -> stow_types::error::Result<()> {
    let rustc_version = WireRustcVersion::parse(args.rustc_version.clone())
        .map_err(|error| stow_error!("preheat rustc_version: {error}"))?;
    let targets = typed_targets(args.targets)?;

    let candidates = crates_io.fetch_top_binary_crates(args.limit).await?;
    if candidates.is_empty() {
        return Err(stow_error!(
            "no binary crates discovered from crates.io top-{} download list",
            args.limit
        ));
    }

    let plan = resolve_binaries(edge, &candidates, &targets, &rustc_version).await?;
    tracing::info!(
        binaries = plan.per_binary.len(),
        tasks = plan.tasks.len(),
        skipped = plan.skipped.len(),
        targets = targets.len(),
        %rustc_version,
        "planned top-binaries preheat tasks"
    );
    let api_requests = crates_io.api_requests();
    render::mutation(
        output,
        args.yes,
        plan,
        move |envelope: &render::Planned<BinariesPlan, crate::projects::SubmitOutcome>| {
            let plan = &envelope.plan;
            let mut out = format!(
                "{} task(s) from {} binaries\n",
                plan.tasks.len(),
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
        async move |plan: &BinariesPlan| crate::projects::submit_chunked(edge, &plan.tasks).await,
    )
    .await
}

/// Resolve every candidate binary into the shared plan — one task batch
/// per crates.io node across the targets, computed on the edge. A binary
/// that fails to resolve (download, unpack, resolution, or simply ships
/// no binary) is recorded in `skipped` and the rest of the wave proceeds.
async fn resolve_binaries(
    edge: &Edge,
    candidates: &[crates_io::BinaryCandidate],
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<BinariesPlan> {
    let mut plan = BinariesPlan {
        tasks: Vec::new(),
        per_binary: Vec::with_capacity(candidates.len()),
        skipped: Vec::new(),
    };
    for binary in candidates {
        let version = TypedCrateVersion::new(
            semver::Version::parse(&binary.latest_version).map_err(|error| {
                stow_error!(
                    "parse crates.io version `{}` for `{}`: {error}",
                    binary.latest_version,
                    binary.id
                )
            })?,
        );
        match resolve_binary_crate(
            edge,
            &binary.id,
            &version,
            binary.downloads,
            targets,
            rustc_version,
        )
        .await
        {
            Ok(BinaryResolve::Tasks { tasks, .. }) => {
                tracing::info!(binary = %binary.id, tasks = tasks.len(), "resolved");
                plan.per_binary.push(BinaryContribution {
                    binary: binary.id.clone(),
                    tasks: tasks.len(),
                });
                plan.tasks.extend(tasks);
            }
            Ok(BinaryResolve::NoBinary) => {
                let reason = format!("{} {version} ships no binary target", binary.id);
                tracing::warn!(binary = %binary.id, %reason, "skipped");
                plan.skipped.push(SkippedBinary {
                    binary: binary.id.clone(),
                    reason,
                });
            }
            Err(error) => {
                tracing::warn!(binary = %binary.id, reason = %error, "skipped");
                plan.skipped.push(SkippedBinary {
                    binary: binary.id.clone(),
                    reason: error.to_string(),
                });
            }
        }
    }
    Ok(plan)
}

/// One resolved binary's contribution to the plan: its task count.
#[derive(Debug, serde::Serialize)]
struct BinaryContribution {
    /// The binary crate's crates.io name.
    binary: String,
    /// How many enqueue requests its resolve graphs produced.
    tasks: usize,
}

/// A binary that failed to resolve, with its reason.
#[derive(Debug, serde::Serialize)]
struct SkippedBinary {
    /// The binary crate's crates.io name.
    binary: String,
    /// Why resolution failed — fetch or resolver.
    reason: String,
}

/// The plan `top-binaries` previews and applies: every task every
/// binary produced, plus per-binary outcomes.
#[derive(Debug, serde::Serialize)]
struct BinariesPlan {
    /// Every enqueue request across every binary and target.
    tasks: Vec<EnqueueRequest>,
    /// How many requests each binary produced.
    per_binary: Vec<BinaryContribution>,
    /// Binaries resolution failed on, with their reasons.
    skipped: Vec<SkippedBinary>,
}

/// The Analytics Engine query template; `__LIMIT__`, `__SINCE_DAYS__`,
/// and `__TARGETS__` are the only substitution points (see the file's own
/// comment for why that is safe).
const TOP_MISSED_SQL: &str = include_str!("../sql/top_missed.sql");

/// Render the top-missed query for a dispatch run. `targets` must already
/// be validated by [`ci_targets`] — the literals land in the SQL text
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

/// Map one `crate;version;features_json;depends_on_json;misses` element
/// of a [`TopMissedRow::top_missed`] array to the task it promotes. Every
/// field came from a validated `EnqueueRequest` on the write path, so a
/// parse failure here means the dataset diverged from `miss_logger`'s
/// layout — a bug to fail on, not a row to skip.
fn missed_enqueue_request(
    target: &str,
    entry: &str,
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<EnqueueRequest> {
    let [crate_name, version, features_json, depends_on_json, misses]: [&str; 5] = entry
        .split(';')
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| {
            stow_error!(
                "malformed top_missed entry {entry:?} — expected `crate;version;features_json;depends_on_json;misses`"
            )
        })?;
    let features: Vec<String> = serde_json::from_str(features_json)
        .map_err(|error| stow_error!("top_missed features_json {features_json:?}: {error}"))?;
    let depends_on: Vec<EnqueueDependency> = if depends_on_json.is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(depends_on_json).map_err(|error| {
            stow_error!("top_missed depends_on_json {depends_on_json:?}: {error}")
        })?
    };
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
        depends_on,
        preserve_lockfile: false,
        host_side: false,
    })
}

async fn missed(
    edge: &Edge,
    crates_io: &crates_io::CratesIo,
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
    submit_plan(edge, crates_io, requests, args.yes, output).await
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

/// How many semver-compatible lines of one crate a wave preheats.
const MAX_VERSION_LINES: usize = 3;

/// The smallest share of a crate's downloads a version line must hold to be
/// worth a build, in percent.
const MIN_LINE_DOWNLOAD_PERCENT: u128 = 1;

/// A semver-compatible line: everything a `^` requirement would unify.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
struct VersionLine(u64, u64);

impl VersionLine {
    const fn of(version: &semver::Version) -> Self {
        if version.major >= 1 {
            Self(version.major, u64::MAX)
        } else {
            Self(0, version.minor)
        }
    }
}

/// The version lines of one crate worth preheating, most-used first.
///
/// Lines are ranked by how much they are actually downloaded, never by
/// version number. `rand`'s three most-used lines are 0.8, 0.9 and 0.7
/// (46%, 25%, 12% of its downloads) while its three highest-numbered are
/// 0.10, 0.9 and 0.8 — ranking by number spends a build wave on 0.10, which
/// holds 8%, and never builds 0.7, which holds more.
///
/// A line under [`MIN_LINE_DOWNLOAD_PERCENT`] is dropped even when the cap
/// would have room for it. Abandoned early lines — `errno` 0.1 at 0.11% of
/// downloads, `ppv-lite86` 0.1 at less than 0.005% — do not compile under a
/// current rustc and never will again, so each one enqueued is a build that
/// fails, a failure row that is retried, and a queue slot taken from a line
/// somebody uses.
///
/// Within a line the newest release is the one built, since that is what a
/// `^` requirement resolves to.
fn select_version_lines(versions: &[CrateVersion]) -> stow_types::error::Result<Vec<String>> {
    let mut newest = std::collections::BTreeMap::<VersionLine, (semver::Version, String)>::new();
    let mut downloads = std::collections::BTreeMap::<VersionLine, u128>::new();
    for version in versions {
        let parsed = semver::Version::parse(&version.num)?;
        let line = VersionLine::of(&parsed);
        *downloads.entry(line).or_default() += u128::from(version.downloads);
        match newest.get(&line) {
            Some((current, _)) if *current >= parsed => {}
            _ => {
                newest.insert(line, (parsed, version.num.clone()));
            }
        }
    }

    let total: u128 = downloads.values().sum();
    let mut ranked: Vec<(u128, VersionLine, String)> = newest
        .into_iter()
        .map(|(line, (_, num))| (downloads.get(&line).copied().unwrap_or_default(), line, num))
        .collect();
    // Downloads descending; the line itself breaks a tie so the answer does
    // not depend on map iteration order, and so a crate whose versions
    // report no downloads at all still yields its newest lines.
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    ranked.retain(|(line_downloads, _, _)| {
        total == 0 || line_downloads * 100 >= total * MIN_LINE_DOWNLOAD_PERCENT
    });
    ranked.truncate(MAX_VERSION_LINES);
    Ok(ranked.into_iter().map(|(_, _, num)| num).collect())
}

#[cfg(test)]
mod tests {
    use super::{ci_targets, missed_enqueue_request, top_missed_query};
    use stow_types::api::EnqueueSource;
    use stow_types::identity::WireRustcVersion;

    fn version(num: &str, downloads: u64) -> super::CrateVersion {
        super::CrateVersion {
            num: num.to_owned(),
            features: std::collections::BTreeMap::new(),
            yanked: false,
            downloads,
            has_lib: Some(true),
        }
    }

    fn lines(versions: &[super::CrateVersion]) -> Vec<String> {
        super::select_version_lines(versions).expect("select version lines")
    }

    /// `rand`'s real shape on crates.io: the three most-downloaded lines are
    /// 0.8, 0.9 and 0.7, while the three highest-numbered are 0.10, 0.9 and
    /// 0.8. Ranking by number builds 0.10 and never builds 0.7, which more
    /// people use.
    #[test]
    fn version_lines_rank_by_downloads_not_by_version_number() {
        let versions = [
            version("0.10.3", 8_000),
            version("0.9.5", 24_000),
            version("0.8.8", 46_000),
            version("0.7.3", 12_000),
            version("0.4.6", 4_000),
        ];
        assert_eq!(lines(&versions), ["0.8.8", "0.9.5", "0.7.3"]);
    }

    /// `errno`'s real shape: 0.3 holds 95%, 0.2 holds 4.9%, 0.1 holds 0.11%.
    /// The cap alone would have taken all three; the 0.1 line does not build
    /// on a current rustc, so it is dropped on its share instead.
    #[test]
    fn an_abandoned_line_is_dropped_even_when_the_cap_has_room() {
        let versions = [
            version("0.3.14", 94_980),
            version("0.2.8", 4_910),
            version("0.1.8", 110),
        ];
        assert_eq!(lines(&versions), ["0.3.14", "0.2.8"]);
    }

    /// Within a line the newest release is what a `^` requirement resolves
    /// to, and so what is worth building — whatever order they arrive in.
    #[test]
    fn the_newest_release_of_a_line_is_the_one_selected() {
        let versions = [
            version("1.2.0", 10),
            version("1.10.0", 10),
            version("1.3.0", 10),
        ];
        assert_eq!(lines(&versions), ["1.10.0"]);
    }

    /// A major line is one line however many minors it has, and 0.x minors
    /// are lines of their own — the split a `^` requirement makes.
    #[test]
    fn major_releases_share_a_line_and_zero_minors_do_not() {
        let versions = [
            version("2.1.0", 50),
            version("2.0.0", 50),
            version("0.9.1", 30),
            version("0.8.0", 20),
        ];
        assert_eq!(lines(&versions), ["2.1.0", "0.9.1", "0.8.0"]);
    }

    /// A crate whose versions report no downloads at all still yields its
    /// newest lines rather than nothing.
    #[test]
    fn lines_without_download_counts_fall_back_to_the_newest() {
        let versions = [
            version("0.3.1", 0),
            version("0.2.0", 0),
            version("0.1.0", 0),
        ];
        assert_eq!(lines(&versions), ["0.3.1", "0.2.0", "0.1.0"]);
    }

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

    /// A `top_missed` element maps to the task the scheduler expects:
    /// miss-sourced, miss count as the priority signal, no lockfile pin,
    /// and the recorded dep edges back in `depends_on` (stow#317).
    #[test]
    fn missed_entry_maps_to_enqueue_request() {
        let rustc_version = WireRustcVersion::parse("1.91.1").expect("rustc version");
        let depends_on_json = concat!(
            "[{\"crate_name\":\"syn\",\"version\":\"3.0.6\",",
            "\"features_json\":\"[\\\"derive\\\"]\",",
            "\"target\":\"x86_64-unknown-linux-gnu\",\"rustc_version\":\"1.91.1\"}]"
        );
        let request = missed_enqueue_request(
            "x86_64-unknown-linux-gnu",
            &format!("serde;1.2.3;[\"derive\",\"std\"];{depends_on_json};42"),
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
        assert_eq!(request.depends_on.len(), 1);
        assert_eq!(request.depends_on[0].crate_name.as_str(), "syn");
        assert_eq!(
            request.depends_on[0].target.as_str(),
            "x86_64-unknown-linux-gnu"
        );

        // Points recorded before the edges blob existed carry an empty
        // slot and re-mint edge-less.
        let request = missed_enqueue_request(
            "x86_64-unknown-linux-gnu",
            "serde;1.2.3;[\"derive\"];[];42",
            &rustc_version,
        )
        .expect("edge-less entry maps");
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
                "serde;1.2.3;[\"derive\"];[];not-a-number",
                &rustc_version,
            )
            .is_err()
        );
    }
}
