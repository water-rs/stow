//! `stow-admin preheat …` — the cache-warming submission lanes plus
//! `preheat plan`, the edge's dry-run expansion.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use stow_types::api::{
    CI_TARGET_TRIPLES, EnqueueRequest, EnqueueSource, PreheatPlanRequest, PreheatPlanResponse,
    is_ci_target,
};
use stow_types::identity::{
    CrateName, CrateVersion as TypedCrateVersion, FeaturesJson, TargetTriple, WireRustcVersion,
};
use stow_types::stow_error;
use zenwave::{Client, ResponseExt};

use crate::Edge;
use crate::render::{self, Output, Table};

const CRATES_IO_API_BASE: &str = "https://crates.io/api/v1/crates";
const CRATES_IO_USER_AGENT: &str = "stow-admin";
const CRATES_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
// A `.crate` tarball is a download rather than a metadata call; the big
// ones (binaries vendoring assets) run to a few megabytes.
const CRATES_IO_DOWNLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(1);
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
    /// through `cargo metadata --filter-platform` and its crates.io
    /// nodes are enqueued in its place.
    Top(TopArgs),
    /// Preheat one named crates.io binary crate's dependency graph: its
    /// `.crate` tarball is unpacked and `cargo metadata --filter-platform`
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
    match command {
        PreheatCommand::Top(args) => top(edge, args, output).await,
        PreheatCommand::Binary(args) => binary(edge, args, output).await,
        PreheatCommand::TopBinaries(args) => top_binaries(edge, args, output).await,
        PreheatCommand::Missed(args) => missed(edge, args, output).await,
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
    requests: Vec<EnqueueRequest>,
    yes: bool,
    output: Output,
) -> stow_types::error::Result<()> {
    render::mutation(
        output,
        yes,
        requests,
        |envelope: &render::Planned<Vec<EnqueueRequest>, crate::projects::SubmitOutcome>| {
            let mut out = format!("{} task(s)\n", envelope.plan.len());
            if !envelope.plan.is_empty() {
                let _ = write!(out, "{}", requests_table(&envelope.plan));
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

async fn top(edge: &Edge, args: TopArgs, output: Output) -> stow_types::error::Result<()> {
    let target = TargetTriple::parse(args.target.clone())
        .map_err(|error| stow_error!("preheat target: {error}"))?;
    let rustc_version = WireRustcVersion::parse(args.rustc_version.clone())
        .map_err(|error| stow_error!("preheat rustc_version: {error}"))?;
    let default_only = FeaturesJson::canonicalize(vec!["default".to_owned()])
        .map_err(|error| stow_error!("canonicalize default features: {error}"))?;
    let empty_features = FeaturesJson::default();

    let crates = fetch_top_crates(args.limit).await?;
    let scratch = std::env::temp_dir().join(format!("stow-admin-top-{}", std::process::id()));
    let mut requests = Vec::new();
    for krate in crates {
        let crate_name = CrateName::parse(krate.id.as_str())
            .map_err(|error| stow_error!("crate_name from crates.io `{}`: {error}", krate.id))?;
        // The newest published release's `has_lib` decides which lane
        // the ranked crate takes — the publish shape is a property of
        // the release, not of the ranking, and crates.io's version
        // record already carries it, so no tarball is fetched to find
        // out. A library keeps its version-line tasks; a crate with no
        // library target is a name source like any binary, resolved
        // through `tasks_for_manifest`, never enqueued itself.
        let detail = fetch_crate_detail(&krate.id).await?;
        let Some(latest) = detail.latest_version else {
            tracing::warn!(krate = %krate.id, "no published release; skipped");
            continue;
        };
        if !latest.has_lib.unwrap_or(true) {
            let tasks = resolve_bin_only_ranked(
                &krate.id,
                &latest.num,
                krate.downloads,
                &scratch,
                &target,
                &rustc_version,
            )
            .await?;
            requests.extend(tasks);
            continue;
        }
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
            });
        }
    }
    let _ = std::fs::remove_dir_all(&scratch);
    submit_plan(edge, requests, args.yes, output).await
}

/// The bin-only half of `top`'s per-crate branch: the ranked crate's
/// newest release reports no library target, so it is a name source like
/// any binary. The tarball is fetched only on this branch — a library
/// never pays for it — unpacked under `scratch`, and resolved through
/// `tasks_for_manifest`. Its crates.io graph becomes the task batch; the
/// crate itself is never enqueued.
async fn resolve_bin_only_ranked(
    crate_name: &str,
    version: &str,
    downloads: u64,
    scratch: &Path,
    target: &TargetTriple,
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<Vec<EnqueueRequest>> {
    let typed_version =
        TypedCrateVersion::new(semver::Version::parse(version).map_err(|error| {
            stow_error!("parse crates.io version `{version}` for `{crate_name}`: {error}")
        })?);
    let archive = download_crate_archive(crate_name, &typed_version).await?;
    let package_dir = format!("{crate_name}-{typed_version}");
    let published = inspect_crate_archive(&archive, &package_dir)?;
    if published.has_library {
        tracing::warn!(
            krate = %crate_name,
            version = %typed_version,
            "crates.io reports has_lib=false but the tarball declares a library"
        );
    }
    let workdir = scratch.join(crate_name);
    let resolved = async {
        let manifest_path = extract_crate_archive(&archive, &workdir, &package_dir)?;
        crate::projects::tasks_for_manifest(
            &manifest_path,
            std::slice::from_ref(target),
            rustc_version,
            downloads,
        )
        .await
    }
    .await;
    let _ = std::fs::remove_dir_all(&workdir);
    let tasks = resolved?;
    tracing::info!(
        krate = %crate_name,
        version = %typed_version,
        tasks = tasks.len(),
        ships_lockfile = published.ships_lockfile,
        "ranked crate ships no library — resolved as a name source"
    );
    Ok(tasks)
}

/// `preheat binary <crate>[@version]` — cache the whole dependency
/// graph of one named crates.io binary.
///
/// The published tarball decides the resolution rather than a guess: a
/// release that ships a `Cargo.lock` unpacks with it in place, so
/// `cargo metadata` lands on the pins `cargo install --locked`
/// reproduces and those pins bake into each task's `version` and
/// `features_json`; one that ships none resolves fresh, which is what
/// plain `cargo install` does for it. `preserve_lockfile` stays `false`
/// on every derived task — on the runner it names the task crate's own
/// lockfile, not the source binary's. The binary's own package is a
/// path member in this resolve — a name source, never a task
/// (`ArtifactKind` has no `Bin`).
async fn binary(edge: &Edge, args: BinaryArgs, output: Output) -> stow_types::error::Result<()> {
    let (crate_name, pinned) = crate::coverage::parse_crate_spec(&args.crate_spec)?;
    let targets = typed_targets(args.targets)?;
    let release = resolve_named_release(crate_name.as_str(), pinned.as_ref()).await?;
    let rustc_version = match &args.rustc_version {
        Some(raw) => WireRustcVersion::parse(raw.clone())
            .map_err(|error| stow_error!("--rustc-version: {error}"))?,
        None => stable_rustc_version(edge, &crate_name, &release, targets[0].as_str()).await?,
    };

    let scratch = std::env::temp_dir().join(format!("stow-admin-binary-{}", std::process::id()));
    let resolved = resolve_binary_crate(
        crate_name.as_str(),
        &release.version,
        release.downloads,
        &scratch,
        &targets,
        &rustc_version,
    )
    .await;
    let _ = std::fs::remove_dir_all(&scratch);
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
    submit_plan(edge, requests, args.yes, output).await
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
/// `workdir`, and run the same resolve the projects lane runs on a
/// clone: `cargo metadata --filter-platform` once per target, every
/// crates.io node an ordinary crate task at its resolved feature set
/// with its crates.io deps as `depends_on`. The binary's own package is
/// a path member in this resolve — a name source, never a task.
///
/// The lockfile treatment is the lane's existing one: a release that
/// ships a `Cargo.lock` unpacks with it in place, so the resolve lands
/// on the pins `cargo install --locked` reproduces and those pins bake
/// into each task's `version` and `features_json`; one that ships none
/// resolves fresh, the plain-`cargo install` resolve. `preserve_lockfile`
/// stays `false` on every derived task — on the runner it names the
/// task crate's own lockfile, not the source binary's.
async fn resolve_binary_crate(
    crate_name: &str,
    version: &TypedCrateVersion,
    downloads: u64,
    workdir: &Path,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<BinaryResolve> {
    let archive = download_crate_archive(crate_name, version).await?;
    let package_dir = format!("{crate_name}-{version}");
    let published = inspect_crate_archive(&archive, &package_dir)?;
    if !published.has_binary {
        return Ok(BinaryResolve::NoBinary);
    }
    let manifest_path = extract_crate_archive(&archive, workdir, &package_dir)?;
    let tasks =
        crate::projects::tasks_for_manifest(&manifest_path, targets, rustc_version, downloads)
            .await?;
    Ok(BinaryResolve::Tasks { tasks, published })
}

/// Unpack the `.crate` tarball into `workdir` and return the manifest —
/// `<workdir>/<name>-<version>/Cargo.toml`, the layout cargo packs.
/// `unpack_in` refuses path traversal inside the archive.
fn extract_crate_archive(
    compressed: &[u8],
    workdir: &Path,
    package_dir: &str,
) -> stow_types::error::Result<PathBuf> {
    std::fs::create_dir_all(workdir)
        .map_err(|error| stow_error!("create {}: {error}", workdir.display()))?;
    let decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(compressed));
    let mut archive = tar::Archive::new(decoder);
    for entry in archive
        .entries()
        .map_err(|error| stow_error!("read {package_dir}.crate entries: {error}"))?
    {
        entry
            .map_err(|error| stow_error!("read {package_dir}.crate entry: {error}"))?
            .unpack_in(workdir)
            .map_err(|error| {
                stow_error!(
                    "unpack {package_dir}.crate into {}: {error}",
                    workdir.display()
                )
            })?;
    }
    let manifest_path = workdir.join(package_dir).join("Cargo.toml");
    if !manifest_path.exists() {
        return Err(stow_error!(
            "{package_dir}.crate unpacked without a Cargo.toml"
        ));
    }
    Ok(manifest_path)
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
    crate_name: &str,
    pinned: Option<&TypedCrateVersion>,
) -> stow_types::error::Result<NamedRelease> {
    let detail = fetch_crate_detail(crate_name).await?;
    let release = match pinned {
        Some(pinned) => {
            let wanted = pinned.to_string();
            fetch_versions(crate_name)
                .await?
                .into_iter()
                .find(|candidate| candidate.num == wanted)
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

/// What the published `.crate` tarball says about a release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PublishedCrate {
    /// The package declares or auto-discovers at least one `[[bin]]`.
    has_binary: bool,
    /// The package declares a `[lib]` or auto-discovers `src/lib.rs` —
    /// whether it compiles to anything `ArtifactKind` covers.
    has_library: bool,
    /// The package ships the `Cargo.lock` `cargo install --locked`
    /// resolves against.
    ships_lockfile: bool,
}

/// Read the published tarball's manifest and file list.
///
/// Binary detection follows cargo's own rules: an explicit `[[bin]]`
/// table, or the auto-discovered `src/main.rs`, `src/bin/*.rs` and
/// `src/bin/*/main.rs`. A library target is the explicit `[lib]` table
/// or the auto-discovered `src/lib.rs`. Entries outside the
/// `<name>-<version>/` prefix cargo packs everything under are ignored.
fn inspect_crate_archive(
    compressed: &[u8],
    root: &str,
) -> stow_types::error::Result<PublishedCrate> {
    use std::io::Read as _;

    let decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(compressed));
    let mut archive = tar::Archive::new(decoder);
    let mut published = PublishedCrate {
        has_binary: false,
        has_library: false,
        ships_lockfile: false,
    };
    for entry in archive
        .entries()
        .map_err(|error| stow_error!("read {root}.crate entries: {error}"))?
    {
        let mut entry = entry.map_err(|error| stow_error!("read {root}.crate entry: {error}"))?;
        let path = entry
            .path()
            .map_err(|error| stow_error!("read {root}.crate entry path: {error}"))?
            .into_owned();
        let Ok(relative) = path.strip_prefix(root) else {
            continue;
        };
        let components: Vec<_> = relative
            .components()
            .map(|component| component.as_os_str().to_string_lossy().into_owned())
            .collect();
        match components
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice()
        {
            ["Cargo.lock"] => published.ships_lockfile = true,
            ["src", "lib.rs"] => published.has_library = true,
            ["src", "main.rs"] | ["src", "bin", _, "main.rs"] => published.has_binary = true,
            ["src", "bin", name]
                if std::path::Path::new(name).extension() == Some("rs".as_ref()) =>
            {
                published.has_binary = true;
            }
            ["Cargo.toml"] => {
                let mut manifest = String::new();
                entry
                    .read_to_string(&mut manifest)
                    .map_err(|error| stow_error!("read {root}/Cargo.toml: {error}"))?;
                let manifest: toml::Table = toml::from_str(&manifest)
                    .map_err(|error| stow_error!("parse {root}/Cargo.toml: {error}"))?;
                if manifest
                    .get("bin")
                    .and_then(toml::Value::as_array)
                    .is_some_and(|bins| !bins.is_empty())
                {
                    published.has_binary = true;
                }
                if manifest.get("lib").is_some_and(toml::Value::is_table) {
                    published.has_library = true;
                }
            }
            _ => {}
        }
    }
    Ok(published)
}

/// The published `.crate` tarball bytes — the same crates.io download
/// endpoint the trusted runner fetches, so what is inspected here is what
/// the build unpacks.
async fn download_crate_archive(
    crate_name: &str,
    version: &TypedCrateVersion,
) -> stow_types::error::Result<Vec<u8>> {
    let url = format!("{CRATES_IO_API_BASE}/{crate_name}/{version}/download");
    let mut client = zenwave::client()
        .timeout(CRATES_IO_DOWNLOAD_TIMEOUT)
        .follow_redirect()
        .retry(2);
    let response = client
        .get(&url)
        .and_then(|request| request.header("User-Agent", CRATES_IO_USER_AGENT))
        .map_err(|error| stow_error!("download {url}: {error}"))?
        .await
        .map_err(|error| stow_error!("download {url}: {error}"))?
        .error_for_status()
        .await
        .map_err(|error| stow_error!("download {url}: {error}"))?;
    let body = response
        .into_body()
        .into_bytes()
        .await
        .map_err(|error| stow_error!("read {url} body: {error}"))?;
    Ok(body.to_vec())
}

/// `preheat top-binaries` — every top-downloaded binary resolved the
/// way `preheat binary` resolves one: tarball unpacked, `cargo metadata
/// --filter-platform` per target, crates.io nodes as ordinary crate
/// tasks. One binary that fails to resolve is reported and skipped —
/// the rest of the wave still lands.
async fn top_binaries(
    edge: &Edge,
    args: TopBinariesArgs,
    output: Output,
) -> stow_types::error::Result<()> {
    let rustc_version = WireRustcVersion::parse(args.rustc_version.clone())
        .map_err(|error| stow_error!("preheat rustc_version: {error}"))?;
    let targets = typed_targets(args.targets)?;

    let candidates = fetch_top_binary_crates(args.limit).await?;
    if candidates.is_empty() {
        return Err(stow_error!(
            "no binary crates discovered from crates.io top-{} download list",
            args.limit
        ));
    }

    let plan = resolve_binaries(&candidates, &targets, &rustc_version).await?;
    tracing::info!(
        binaries = plan.per_binary.len(),
        tasks = plan.tasks.len(),
        skipped = plan.skipped.len(),
        targets = targets.len(),
        %rustc_version,
        "planned top-binaries preheat tasks"
    );
    render::mutation(
        output,
        args.yes,
        plan,
        |envelope: &render::Planned<BinariesPlan, crate::projects::SubmitOutcome>| {
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

/// Resolve every candidate binary into the shared plan — one scratch
/// workdir each, one task batch per crates.io node across the targets.
/// A binary that fails to resolve (download, unpack, `cargo metadata`,
/// or simply ships no binary) is recorded in `skipped` and the rest of
/// the wave proceeds.
async fn resolve_binaries(
    candidates: &[BinaryCandidate],
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<BinariesPlan> {
    let scratch =
        std::env::temp_dir().join(format!("stow-admin-top-binaries-{}", std::process::id()));
    let mut plan = BinariesPlan {
        tasks: Vec::new(),
        per_binary: Vec::with_capacity(candidates.len()),
        skipped: Vec::new(),
    };
    for (index, binary) in candidates.iter().enumerate() {
        let version = TypedCrateVersion::new(
            semver::Version::parse(&binary.latest_version).map_err(|error| {
                stow_error!(
                    "parse crates.io version `{}` for `{}`: {error}",
                    binary.latest_version,
                    binary.id
                )
            })?,
        );
        let workdir = scratch.join(index.to_string());
        match resolve_binary_crate(
            &binary.id,
            &version,
            binary.downloads,
            &workdir,
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
        // The unpacked tarball is consumed into tasks already — drop the
        // bytes before the next binary lands.
        let _ = std::fs::remove_dir_all(&workdir);
    }
    let _ = std::fs::remove_dir_all(&scratch);
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
    /// Why resolution failed — download, unpack, or `cargo metadata`.
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

/// Map one `crate;version;features_json;misses` element of a
/// [`TopMissedRow::top_missed`] array to the task it promotes. Every field
/// came from a validated `EnqueueRequest` on the write path, so a parse
/// failure here means the dataset diverged from `miss_logger`'s layout — a
/// bug to fail on, not a row to skip.
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
    })
}

async fn missed(edge: &Edge, args: MissedArgs, output: Output) -> stow_types::error::Result<()> {
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

// ===== crates.io discovery =====

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
    /// All-time downloads of this exact version, which is how a version
    /// line's share of the crate's use is measured.
    #[serde(default)]
    downloads: u64,
    /// Whether the release publishes a library target, as crates.io's
    /// version record reports it. `None` on records that predate the
    /// field — an absent field is an old record, not a bin-only crate.
    #[serde(default)]
    has_lib: Option<bool>,
}

#[derive(Debug, Clone)]
struct BinaryCandidate {
    id: String,
    latest_version: String,
    downloads: u64,
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
    /// All-time download count, which the scheduler orders its queue by.
    downloads: u64,
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
    #[serde(default)]
    downloads: u64,
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
    Ok(CrateDetail {
        latest_version,
        downloads: response.krate.downloads,
    })
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

/// How many times one crates.io GET is attempted before the command fails.
///
/// A wave walks a few hundred crates.io endpoints per target, so a single
/// transient answer is likely somewhere in every run — on 2026-09-21 one
/// `Invalid redirect URL` on `lock_api` ended a whole target's lane. The
/// client's own `retry` does not cover a failure raised while building the
/// request, so the attempt is repeated here, and every refused attempt is
/// logged verbatim rather than summarised away.
const CRATES_IO_ATTEMPTS: u32 = 3;

/// Delay before the second attempt; doubles for each one after it.
const CRATES_IO_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(500);

async fn get_json_with_retries<T>(url: &str) -> stow_types::error::Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let mut delay = CRATES_IO_RETRY_DELAY;
    for attempt in 1..CRATES_IO_ATTEMPTS {
        match get_json(url).await {
            Ok(value) => return Ok(value),
            Err(error) => {
                tracing::warn!(url, attempt, %error, "crates.io request failed; retrying");
                smol::Timer::after(delay).await;
                delay = delay.saturating_mul(2);
            }
        }
    }
    get_json(url).await
}

async fn get_json<T>(url: &str) -> stow_types::error::Result<T>
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
    use super::{
        PublishedCrate, ci_targets, extract_crate_archive, inspect_crate_archive,
        missed_enqueue_request, top_missed_query,
    };
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
    /// Build a `.crate`-shaped tarball: every file under the
    /// `<name>-<version>/` prefix cargo packs into.
    fn crate_archive(root: &str, files: &[(&str, &str)]) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut builder = tar::Builder::new(encoder);
        for (path, contents) in files {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_size(u64::try_from(contents.len()).expect("test file fits"));
            builder
                .append_data(&mut header, format!("{root}/{path}"), contents.as_bytes())
                .expect("append test file");
        }
        builder
            .into_inner()
            .expect("finish tar")
            .finish()
            .expect("finish gzip")
    }

    /// The shape `preheat binary` is for: a binary that ships the
    /// lockfile `cargo install --locked` resolves against.
    #[test]
    fn a_published_binary_with_a_lockfile_is_detected() {
        let archive = crate_archive(
            "ripgrep-14.1.1",
            &[
                ("Cargo.toml", "[package]\nname = \"ripgrep\"\n"),
                ("Cargo.lock", "version = 3\n"),
                ("src/main.rs", "fn main() {}\n"),
            ],
        );
        assert_eq!(
            inspect_crate_archive(&archive, "ripgrep-14.1.1").expect("inspect"),
            PublishedCrate {
                has_binary: true,
                has_library: false,
                ships_lockfile: true,
            }
        );
    }

    /// An explicit `[[bin]]` counts even when its path is nowhere cargo
    /// would auto-discover one, and a crate may ship no lockfile.
    #[test]
    fn an_explicit_bin_table_counts_without_a_lockfile() {
        let archive = crate_archive(
            "tool-0.3.0",
            &[
                (
                    "Cargo.toml",
                    "[package]\nname = \"tool\"\n\n[[bin]]\nname = \"tool\"\npath = \"cmd/tool.rs\"\n",
                ),
                ("cmd/tool.rs", "fn main() {}\n"),
                ("src/lib.rs", ""),
            ],
        );
        assert_eq!(
            inspect_crate_archive(&archive, "tool-0.3.0").expect("inspect"),
            PublishedCrate {
                has_binary: true,
                has_library: true,
                ships_lockfile: false,
            }
        );
    }

    /// A library is refused by the command, so detection must not read a
    /// bin target into one: `src/bin` and `src/main.rs` are the only
    /// auto-discovered paths.
    #[test]
    fn a_library_ships_no_binary_target() {
        let archive = crate_archive(
            "serde-1.0.219",
            &[
                ("Cargo.toml", "[package]\nname = \"serde\"\n"),
                ("src/lib.rs", ""),
                ("src/de/mod.rs", ""),
            ],
        );
        assert_eq!(
            inspect_crate_archive(&archive, "serde-1.0.219").expect("inspect"),
            PublishedCrate {
                has_binary: false,
                has_library: true,
                ships_lockfile: false,
            }
        );
    }

    /// Extracting a `.crate` lays out `<name>-<version>/…` under the
    /// workdir and hands back the manifest path the resolve runs
    /// against — lockfile included when the tarball ships one.
    #[test]
    fn extract_crate_archive_lays_out_the_package() {
        let archive = crate_archive(
            "ripgrep-14.1.1",
            &[
                ("Cargo.toml", "[package]\nname = \"ripgrep\"\n"),
                ("Cargo.lock", "version = 3\n"),
                ("src/main.rs", "fn main() {}\n"),
            ],
        );
        let workdir =
            std::env::temp_dir().join(format!("stow-admin-test-extract-{}", std::process::id()));
        let manifest =
            extract_crate_archive(&archive, &workdir, "ripgrep-14.1.1").expect("extract");
        assert_eq!(manifest, workdir.join("ripgrep-14.1.1").join("Cargo.toml"));
        assert!(workdir.join("ripgrep-14.1.1").join("Cargo.lock").exists());
        assert!(workdir.join("ripgrep-14.1.1").join("src/main.rs").exists());
        let _ = std::fs::remove_dir_all(&workdir);
    }

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
