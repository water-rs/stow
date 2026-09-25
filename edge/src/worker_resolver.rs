//! Worker-side graph resolution through `stow-resolve`.
//!
//! Every lane that expands a name into build tasks — the human request
//! lane, the preheat lanes (crates.io binaries and GitHub projects), and
//! the register-scope closure check — resolves the published manifest
//! itself rather than walking crates.io metadata by hand. The resolver is
//! cargo's own code carried into `stow-resolve`; the worker supplies the
//! three things a real `cargo` invocation would have read from the machine:
//!
//! - the manifest source: the `.crate` tarball from `static.crates.io`,
//!   or the GitHub repo tree for the projects lane — a codeload tarball
//!   plus each submodule's own tarball at the commit the parent tree
//!   pins, unpacked into a [`MemoryVfs`]. A `Cargo.lock` a `.crate` ships
//!   stays in place, so the resolve lands on the pins `cargo install
//!   --locked` reproduces — the projects lane drops the committed
//!   lockfile so its resolve lands on the latest semver-compatible
//!   versions, as it did when the admin CLI ran `cargo metadata` locally;
//! - the registry: cargo's sparse-index machinery over a [`worker::Fetch`]
//!   transport, with the index `.cache` files persisting under the shared
//!   in-memory cargo home for the whole request;
//! - the toolchain truth: `rustc -vV` and `rustc --print cfg` vendored per
//!   rustc release in [`stow_resolve::rustc_data`], keyed by the task's
//!   `rustc_version`. A resolve for an unvendored version is a truthful
//!   error.
//!
//! One `cargo metadata --filter-platform` invocation resolves exactly one
//! requested platform — host-dep features unify across that build's edges
//! alone — so a multi-target request resolves once per target. Index
//! fetches are shared through the request's single [`MemoryVfs`], so the
//! per-target cost is the graph walk, not the network.

// Resolve futures are `!Send` by construction — `Rc` HTTP clients and the
// thread-local ambient VFS — and every caller wraps them in
// `IntoSendFuture`, which is safe on the single-threaded isolate.
#![allow(clippy::future_not_send)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::dependency_resolver::{
    PackageKey, load_cached_artifacts_for_keys, serialize_feature_set,
};
use crate::errors::ResolverError;
use crate::fetch_guard::OutboundPool;
use semver::Version;
use skyzen_services::Db;
use stow_resolve::api::{self, StowResolveInput, StowUnit, StowUnitKey, StowUnitKind};
use stow_resolve::github_tree;
use stow_resolve::rustc_data;
use stow_resolve::util::context::{Env, GlobalContext};
use stow_resolve::util::fs::{MemoryVfs, Vfs, poll_scoped};
use stow_resolve::util::network::http_async::{BodyStream, Client, HttpClient};
use stow_resolve::util::shell::Shell;
use stow_resolve::util::tarball::{self, TarPrefix};
use stow_types::api::{EnqueueDependency, EnqueueRequest, EnqueueSource, runner_family};
use stow_types::identity::{CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion};

/// The fetch transport the resolve machinery drives.
pub type ResolveHttp = Rc<dyn HttpClient>;

/// The HTTP client for production resolves: [`worker::Fetch`] on wasm32,
/// threaded through the private helpers as their `http` parameter.
/// `pool` is the invoking request's [`OutboundPool`], so the resolve's
/// fetch fan-out stays inside that invocation's connection budget.
///
/// On the host the edge runs only unit tests, which inject
/// [`stow_resolve::testing::RecordedHttp`] through the same parameter.
#[cfg(target_family = "wasm")]
#[must_use]
pub fn fetch_http(pool: &OutboundPool) -> ResolveHttp {
    Rc::new(WorkerFetchHttp { pool: pool.clone() })
}

/// The host-side transport. The edge runs production resolves only on
/// wasm; on the host — where `stow-edge` compiles for tests — fetching
/// through the worker transport cannot exist, and callers inject
/// [`stow_resolve::testing::RecordedHttp`] for anything a test needs.
/// This client answers with a truthful error rather than an implicit
/// fallback.
#[cfg(not(target_family = "wasm"))]
#[must_use]
pub fn fetch_http(_pool: &OutboundPool) -> ResolveHttp {
    struct HostUnavailable;
    impl HttpClient for HostUnavailable {
        fn request<'a>(
            &'a self,
            request: http::Request<Vec<u8>>,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = stow_resolve::util::errors::CargoResult<http::Response<Vec<u8>>>,
                    > + 'a,
            >,
        > {
            Box::pin(async move {
                Err(anyhow::format_err!(
                    "the worker fetch transport is unavailable on the host;                      inject a fixture client ({}) for tests",
                    request.uri()
                ))
            })
        }
    }
    Rc::new(HostUnavailable)
}

/// A node in the per-platform task graph — the full identity a scheduler
/// task carries minus `rustc_version` (shared by the wave): crate,
/// version, resolved feature set, the triple the unit compiles on, and
/// the cargo side the unit lives on. Host-side units (proc-macros, build
/// dependencies) key at the runner family's host triple, not the
/// consumer's target — and carry `host_side` so they stay distinct from
/// a target-side node at the same triple.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TaskNode {
    /// Crate name.
    crate_name: CrateName,
    /// Crate version.
    version: CrateVersion,
    /// Canonical features JSON (sorted array).
    features_json: String,
    /// Compilation target triple the unit keys on.
    target: String,
    /// Whether the unit lives on the host side of the build graph.
    host_side: bool,
}

/// What one target's resolve produced for the request lane: the enqueue
/// batch plus the root's outcome inputs. Shape matches the old
/// `CrateRequestPlan` so `api.rs` call sites keep their fields.
pub struct CrateRequestPlan {
    /// One task per uncovered node in the resolved closure.
    pub enqueue_requests: Vec<EnqueueRequest>,
    /// Whether the root's artifact already exists in the catalog.
    pub root_cached: bool,
    /// Whether the requested package publishes a library target.
    pub root_has_library: bool,
    /// The root task's canonical features JSON.
    pub root_features_json: String,
    /// The triple the root task keys on — the requested target for a
    /// normal lib root, the runner-family host triple for a proc-macro
    /// root, whose lib compiles on the host.
    pub root_target: String,
    /// Whether the root task is a host-side node — true exactly when
    /// `root_target` is the host triple because the root is a proc-macro.
    pub root_host_side: bool,
}

/// `no_default_features` from a request's complete feature set:
/// `features_json` is the resolved set the request asked for, so defaults
/// are on iff it carries `"default"`. An empty set means exactly
/// `--no-default-features`.
fn no_default_features_for(seed_features: &BTreeSet<String>) -> bool {
    !seed_features.contains("default")
}

/// One workspace (a `.crate` package or a repo checkout) held in memory
/// for the request's whole per-target fan-out: `vfs` carries the source
/// tree and doubles as the cargo home root so index `.cache` files live
/// across the resolves.
struct SourceWorkspace {
    /// The shared filesystem — a [`MemoryVfs`] in production; tests may
    /// swap in an overlay so the cargo-home prefix lands on the real fs
    /// (the tarball unpack path is `std::fs` on host).
    vfs: Rc<dyn Vfs>,
    /// Root manifest the resolves read.
    manifest_path: PathBuf,
    /// The cargo home the resolves download and unpack into. On wasm the
    /// ambient VFS makes the whole tree virtual; on host the package
    /// source unpack path is the real filesystem, so tests point this at
    /// a real directory.
    cargo_home: PathBuf,
    /// Whether the members of this tree are crates.io packages — a
    /// `.crate` tarball's member *is* the published package, so its units
    /// may become tasks; a project checkout's members are sources only
    /// (`StowResolveInput::members_are_crates_io`).
    members_are_crates_io: bool,
    /// Whether the tree carried a `Cargo.lock` into the resolve.
    ships_lockfile: bool,
}

/// The in-memory tree every resolve in this request shares. The
/// vendored resolver insists manifest paths be absolute, and on
/// Windows `/ws` is not — the worker itself always runs the Unix root,
/// so a drive-prefixed root exists only for host-compiled tests.
#[cfg(windows)]
const WORKSPACE_DIR: &str = r"C:\ws";
/// The in-memory tree every resolve in this request shares.
#[cfg(not(windows))]
const WORKSPACE_DIR: &str = "/ws";

/// The cargo-home root every production resolve shares — `/cargo-home`
/// inside the ambient VFS.
#[cfg(windows)]
const CARGO_HOME_DIR: &str = r"C:\cargo-home";
/// The cargo-home root every production resolve shares.
#[cfg(not(windows))]
const CARGO_HOME_DIR: &str = "/cargo-home";

/// Expand one crate request into a per-target task plan — the request
/// lane's expansion. The `.crate` tarball is fetched once for the whole
/// fan-out; each target gets its own resolve because cargo unifies
/// host-dep features per requested platform.
///
/// # Errors
/// [`ResolverError`] on fetch, parse, or resolution failures.
#[expect(
    clippy::too_many_arguments,
    reason = "the expansion needs the request's fields plus the invocation's outbound pool"
)]
pub async fn expand_crate_request_on_targets(
    db: &Db,
    crate_name: &CrateName,
    version: &Version,
    seed_features: &BTreeSet<String>,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
    rustc_data_base_url: Option<&str>,
    pool: &OutboundPool,
) -> Result<Vec<(TargetTriple, CrateRequestPlan)>, ResolverError> {
    let http = fetch_http(pool);
    let source = crate_workspace(&http, crate_name, version, /* keep lockfile */ true).await?;
    let mut plans = Vec::with_capacity(targets.len());
    for target in targets {
        let output = resolve_workspace(
            &http,
            &source,
            seed_features,
            no_default_features_for(seed_features),
            target,
            rustc_version,
            rustc_data_base_url,
        )
        .await?;
        plans.push((
            target.clone(),
            plan_from_output(db, &output, crate_name, version, target, rustc_version).await?,
        ));
    }
    Ok(plans)
}

/// The name/version closure a dispatched task may publish — every package
/// the resolve pulls into the unit graph is inside it. Register-scope
/// check for `task_binding`, replacing the old crates.io closure walk.
///
/// # Errors
/// [`ResolverError`] on fetch, parse, or resolution failures.
pub async fn expand_task_closure(
    crate_name: &CrateName,
    version: &Version,
    seed_features: &BTreeSet<String>,
    target: &TargetTriple,
    rustc_version: &WireRustcVersion,
    rustc_data_base_url: Option<&str>,
    pool: &OutboundPool,
) -> Result<BTreeSet<(CrateName, CrateVersion)>, ResolverError> {
    let http = fetch_http(pool);
    let source = crate_workspace(&http, crate_name, version, /* keep lockfile */ true).await?;
    let output = resolve_workspace(
        &http,
        &source,
        seed_features,
        no_default_features_for(seed_features),
        target,
        rustc_version,
        rustc_data_base_url,
    )
    .await?;
    output
        .units
        .iter()
        .filter(|unit| unit.is_crates_io)
        .map(|unit| {
            Ok((
                CrateName::parse(unit.name.clone()).map_err(ResolverError::Identity)?,
                CrateVersion::new(
                    semver::Version::parse(&unit.version).expect("resolver emits semver versions"),
                ),
            ))
        })
        .collect::<Result<_, ResolverError>>()
}

/// What an admin resolve lane learns about the source: publish-shape
/// flags plus the per-target task batch.
pub struct SourceResolve {
    /// Whether the source ships a `[[bin]]` — the binaries lane's skip
    /// condition, taken from cargo's own target knowledge.
    pub has_binary: bool,
    /// Whether the root package ships a library target.
    pub has_library: bool,
    /// Whether the source shipped a `Cargo.lock` the resolve honored —
    /// a `.crate`'s bundled lockfile; a project's committed one is
    /// dropped before the resolve, so the flag reads `false` there.
    pub ships_lockfile: bool,
    /// One task batch per requested target, in request order.
    pub targets: Vec<(TargetTriple, Vec<EnqueueRequest>)>,
}

/// The admin crate lane: resolve one published `.crate` into tasks. The
/// tarball's bundled `Cargo.lock` stays in place — the `cargo install
/// --locked` resolve — and the emitted tasks carry
/// `preserve_lockfile: false` since the flag names the task crate's own
/// lockfile, not the source's.
///
/// # Errors
/// [`ResolverError`] on fetch, parse, or resolution failures.
pub async fn resolve_crate(
    crate_name: &CrateName,
    version: &Version,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
    downloads: u64,
    rustc_data_base_url: Option<&str>,
    pool: &OutboundPool,
) -> Result<SourceResolve, ResolverError> {
    tracing::info!(
        crate = %crate_name,
        %version,
        targets = targets.len(),
        "resolve: crate lane begin"
    );
    let http = fetch_http(pool);
    let source = crate_workspace(&http, crate_name, version, true).await?;
    source_resolve(
        &http,
        &source,
        targets,
        rustc_version,
        downloads,
        rustc_data_base_url,
    )
    .await
}

/// The projects lane: resolve a GitHub repository's workspace into crate
/// tasks. The tarball is fetched from codeload and the committed
/// `Cargo.lock` is dropped — a project contributes names and feature
/// sets, never version pins.
///
/// # Errors
/// [`ResolverError`] on fetch, parse, or resolution failures.
pub async fn resolve_github_project(
    repo: &str,
    git_ref: &str,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
    downloads: u64,
    rustc_data_base_url: Option<&str>,
    pool: &OutboundPool,
) -> Result<SourceResolve, ResolverError> {
    tracing::info!(
        repo,
        git_ref,
        targets = targets.len(),
        "resolve: project lane begin"
    );
    let http = fetch_http(pool);
    let source = github_workspace(&http, repo, git_ref).await?;
    source_resolve(
        &http,
        &source,
        targets,
        rustc_version,
        downloads,
        rustc_data_base_url,
    )
    .await
}

/// Resolve a prepared workspace once per target into tasks + flags.
async fn source_resolve(
    http: &ResolveHttp,
    source: &SourceWorkspace,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
    downloads: u64,
    rustc_data_base_url: Option<&str>,
) -> Result<SourceResolve, ResolverError> {
    let seed_features = BTreeSet::new();
    let mut has_binary = false;
    let mut has_library = false;
    let mut batches = Vec::with_capacity(targets.len());
    for target in targets {
        tracing::info!(target = %target, "resolve: target begin");
        let output = resolve_workspace(
            http,
            source,
            &seed_features,
            false,
            target,
            rustc_version,
            rustc_data_base_url,
        )
        .await?;
        if output.roots.iter().any(|key| key.kind == StowUnitKind::Lib) {
            has_library = true;
        }
        has_binary |= output.has_binary;
        let (requests, _) = enqueue_requests_from_output(
            &output.units,
            rustc_version,
            EnqueueSource::CrateUpdate,
            downloads,
        )?;
        batches.push((target.clone(), requests));
    }
    Ok(SourceResolve {
        has_binary,
        has_library,
        ships_lockfile: source.ships_lockfile,
        targets: batches,
    })
}

/// Download and unpack one published `.crate` into memory. The body
/// streams through the gzip/tar reader — the isolate never holds more
/// than [`tarball::MAX_RESOLVE_TREE_BYTES`] of content.
async fn crate_workspace(
    http: &ResolveHttp,
    crate_name: &CrateName,
    version: &Version,
    keep_lockfile: bool,
) -> Result<SourceWorkspace, ResolverError> {
    let url = format!("https://static.crates.io/crates/{crate_name}/{crate_name}-{version}.crate");
    tracing::info!(crate = %crate_name, %version, "resolve: source fetch begin");
    let (body, len) = get_stream(http, &url).await?;
    let files = tarball::collect_tar_gz(
        body,
        TarPrefix::FirstComponent,
        tarball::unpack_size_bound(len),
        tarball::MAX_RESOLVE_TREE_BYTES,
    )
    .await
    .map_err(|error| {
        ResolverError::CratesIo(format!("unpack {crate_name}-{version}.crate: {error}"))
    })?;
    tracing::info!(crate = %crate_name, %version, files = files.len(), "resolve: source workspace built");
    build_workspace(files, keep_lockfile, true)
}

/// Download and unpack one GitHub repo tree — the codeload tarball
/// streams through [`tarball::collect_tar_gz`], and `.gitmodules`
/// submodules arrive as their own tarballs at the gitlink commits
/// ([`github_tree::fetch_github_tree`]).
async fn github_workspace(
    http: &ResolveHttp,
    repo: &str,
    git_ref: &str,
) -> Result<SourceWorkspace, ResolverError> {
    tracing::info!(repo, git_ref, "resolve: source fetch begin");
    let tree = github_tree::fetch_github_tree(&Client::new(http.clone()), repo, git_ref)
        .await
        .map_err(|error| {
            ResolverError::CratesIo(format!("fetch {repo}@{git_ref} tree: {error:#}"))
        })?;
    tracing::info!(
        repo,
        files = tree.files.len(),
        "resolve: source workspace built"
    );
    for note in &tree.notes {
        tracing::warn!(repo, %note, "github tree fetch note");
    }
    build_workspace(tree.files, false, false)
}

/// Lay the unpacked tree into a fresh [`MemoryVfs`], find the root
/// manifest, and record the workspace's provenance.
fn build_workspace(
    files: BTreeMap<PathBuf, Vec<u8>>,
    keep_lockfile: bool,
    members_are_crates_io: bool,
) -> Result<SourceWorkspace, ResolverError> {
    let vfs = MemoryVfs::new();
    let root = PathBuf::from(WORKSPACE_DIR);
    // The manifest the lane's admission picked: the shallowest
    // `Cargo.lock` whose directory also carries `Cargo.toml` — a
    // lockfile roots the workspace it pins. Repos the admission let
    // through always have one; for a tarball without any lock (or a
    // `.crate`, whose package is the root) the root manifest answers.
    let manifest_rel = github_tree::select_manifest(&files)
        .ok_or_else(|| ResolverError::BadRequest("tarball contains no Cargo.toml".to_owned()))?;
    let manifest_path = root.join(&manifest_rel);
    let ws_root = manifest_rel
        .parent()
        .map_or_else(PathBuf::new, Path::to_path_buf);
    let ships_lockfile = keep_lockfile && files.contains_key(&ws_root.join("Cargo.lock"));
    for (path, data) in files {
        // Every `Cargo.lock` under the selected workspace is dropped
        // unless the lane asked to keep it — a lockfile nested in a
        // member dir pins versions just as the root one does.
        let is_ws_lockfile = !keep_lockfile
            && path.file_name().and_then(|n| n.to_str()) == Some("Cargo.lock")
            && path.starts_with(&ws_root);
        if !is_ws_lockfile {
            vfs.insert(root.join(path), data);
        }
    }
    Ok(SourceWorkspace {
        vfs: Rc::new(vfs),
        manifest_path,
        cargo_home: PathBuf::from(CARGO_HOME_DIR),
        members_are_crates_io,
        ships_lockfile,
    })
}

/// One request's resolved units for one target assembled into the
/// request-lane plan: enqueue batch plus the root's cached/library flags.
async fn plan_from_output(
    db: &Db,
    output: &api::StowResolveOutput,
    crate_name: &CrateName,
    version: &Version,
    target: &TargetTriple,
    rustc_version: &WireRustcVersion,
) -> Result<CrateRequestPlan, ResolverError> {
    tracing::info!(crate = %crate_name, %version, target = %target, "resolve: plan begin");
    let parts = request_plan_parts(&output.units, &output.roots, crate_name, version, target)?;
    let covered = covered_nodes(db, &parts.nodes, rustc_version).await?;
    tracing::info!(
        crate = %crate_name,
        %version,
        target = %target,
        covered = covered.len(),
        "resolve: plan covered"
    );
    let (enqueue_requests, _) = enqueue_requests_inner(
        &parts.nodes,
        &parts.edges,
        &covered,
        rustc_version,
        EnqueueSource::HumanRequest,
        0,
    );
    let root_cached = parts
        .root_key
        .as_ref()
        .is_some_and(|key| covered.contains(key));
    Ok(CrateRequestPlan {
        enqueue_requests,
        root_cached,
        root_has_library: parts.root_key.is_some(),
        root_features_json: parts
            .root_key
            .as_ref()
            .map_or_else(|| "[]".to_owned(), |key| key.features_json.clone()),
        root_target: parts.root_target,
        root_host_side: parts.root_host_side,
    })
}

/// The db-independent half of [`plan_from_output`]: task graph, the
/// root's task key, and the triple the root task keys on — the requested
/// target for a normal lib root, or the runner-family host triple when
/// the only lib root is a proc-macro (its key carries the host platform).
struct RequestPlanParts {
    /// Every task node in the resolved closure.
    nodes: BTreeSet<TaskNode>,
    /// Task-level dependency edges between nodes.
    edges: BTreeMap<TaskNode, BTreeSet<TaskNode>>,
    /// The requested crate's lib-unit task key, at the platform its
    /// `roots` entry carries.
    root_key: Option<TaskNode>,
    /// `root_key`'s triple, or the requested target when there is no lib
    /// root.
    root_target: String,
    /// `root_key`'s cargo side — true only for a proc-macro root, whose
    /// lib unit lives on the host side of its own resolve.
    root_host_side: bool,
}

fn request_plan_parts(
    units: &[StowUnit],
    roots: &[StowUnitKey],
    crate_name: &CrateName,
    version: &Version,
    target: &TargetTriple,
) -> Result<RequestPlanParts, ResolverError> {
    let (nodes, edges) = task_graph(units)?;
    let root_key = roots
        .iter()
        .find(|key| key.kind == StowUnitKind::Lib)
        .map(|key| TaskNode {
            crate_name: crate_name.clone(),
            version: CrateVersion::new(version.clone()),
            features_json: unit_features(units, key).unwrap_or_default(),
            target: key.platform.clone(),
            host_side: key.side == stow_resolve::api::StowSide::Host,
        });
    let (root_target, root_host_side) = root_key.as_ref().map_or_else(
        || (target.as_str().to_owned(), false),
        |key| (key.target.clone(), key.host_side),
    );
    Ok(RequestPlanParts {
        nodes,
        edges,
        root_key,
        root_target,
        root_host_side,
    })
}

/// Assemble the enqueue batch for a resolve output: `(requests, nodes)`.
fn enqueue_requests_from_output(
    units: &[StowUnit],
    rustc_version: &WireRustcVersion,
    source: EnqueueSource,
    downloads: u64,
) -> Result<(Vec<EnqueueRequest>, BTreeSet<TaskNode>), ResolverError> {
    let (nodes, edges) = task_graph(units)?;
    Ok(enqueue_requests_inner(
        &nodes,
        &edges,
        &BTreeSet::new(),
        rustc_version,
        source,
        downloads,
    ))
}

/// The lib-unit graph the wave machinery works on: every task node and
/// its task-level dependency edges.
///
/// Every task node and its task-level edges.
type TaskGraph = (BTreeSet<TaskNode>, BTreeMap<TaskNode, BTreeSet<TaskNode>>);

/// A node's task deps are the lib units its own build must find in the
/// cache: its normal-dependency lib units (the lib unit's `deps` of kind
/// `Lib`), plus the build-dependency lib units its build script links
/// (the compile unit's `deps` of kind `Lib`). Run and compile units are
/// interior — they happen inside the owning lib's task and mint no task
/// of their own.
fn task_graph(units: &[StowUnit]) -> Result<TaskGraph, ResolverError> {
    // Index once — dep and build-script lookups used to re-scan `units`
    // inside per-unit loops, which is quadratic on a zed-sized resolve.
    let mut libs: HashMap<(&str, &str, &str, stow_resolve::api::StowSide), &StowUnit> =
        HashMap::with_capacity(units.len());
    let mut scripts: HashMap<(&str, &str, &[String]), &StowUnit> =
        HashMap::with_capacity(units.len());
    for unit in units {
        match unit.key.kind {
            StowUnitKind::Lib => {
                libs.entry((
                    unit.name.as_str(),
                    unit.version.as_str(),
                    unit.key.platform.as_str(),
                    unit.key.side,
                ))
                .or_insert(unit);
            }
            StowUnitKind::BuildScript => {
                scripts
                    .entry((unit.name.as_str(), unit.version.as_str(), &unit.features))
                    .or_insert(unit);
            }
            StowUnitKind::RunBuildScript => {}
        }
    }
    let by_key = |name: &str, version: &str, platform: &str, side| {
        libs.get(&(name, version, platform, side)).copied()
    };
    let node_of = |unit: &StowUnit| -> Result<TaskNode, ResolverError> {
        Ok(TaskNode {
            crate_name: CrateName::parse(unit.name.clone()).map_err(ResolverError::Identity)?,
            version: CrateVersion::new(
                semver::Version::parse(&unit.version).expect("resolver emits semver versions"),
            ),
            features_json: serialize_feature_set(
                &unit.features.iter().cloned().collect::<BTreeSet<_>>(),
            )?,
            target: unit.key.platform.clone(),
            host_side: unit.key.side == stow_resolve::api::StowSide::Host,
        })
    };
    // One unit's direct lib edges: its normal-dep libs plus the build-dep
    // libs its build-script compile unit links (dedup'd by feature set as
    // `emit_units` produced it).
    let raw_deps = |unit: &StowUnit| -> Vec<&StowUnit> {
        let mut direct: Vec<&StowUnit> = unit
            .deps
            .iter()
            .filter(|dep| dep.key.kind == StowUnitKind::Lib)
            .filter_map(|dep| by_key(&dep.name, &dep.version, &dep.key.platform, dep.key.side))
            .collect();
        let compile = scripts.get(&(&unit.name, &unit.version, &unit.features));
        if let Some(compile) = compile {
            direct.extend(
                compile
                    .deps
                    .iter()
                    .filter(|dep| dep.key.kind == StowUnitKind::Lib)
                    .filter_map(|dep| {
                        by_key(&dep.name, &dep.version, &dep.key.platform, dep.key.side)
                    }),
            );
        }
        direct
    };
    let mut nodes = BTreeSet::new();
    let mut edges = BTreeMap::<TaskNode, BTreeSet<TaskNode>>::new();
    for unit in units {
        if unit.key.kind != StowUnitKind::Lib || !unit.is_crates_io {
            continue;
        }
        let node = node_of(unit)?;
        nodes.insert(node.clone());
        let entry = edges.entry(node.clone()).or_default();
        // Non-crates.io units (project members, path deps, git packages)
        // carry the resolve's edges but mint no task — a project's own
        // crates are the way into the crates.io graph. Walk through them
        // so a node's deps are the crates.io libs on the far side.
        let mut seen = BTreeSet::new();
        let mut stack = raw_deps(unit);
        while let Some(dep_unit) = stack.pop() {
            if !seen.insert(&dep_unit.key) {
                continue;
            }
            if dep_unit.is_crates_io {
                entry.insert(node_of(dep_unit)?);
            } else {
                stack.extend(raw_deps(dep_unit));
            }
        }
        entry.remove(&node);
    }
    Ok((nodes, edges))
}

/// Decode a canonical features JSON string back into the typed form.
fn features_json(raw: &str) -> FeaturesJson {
    let features: Vec<String> = serde_json::from_str(raw).expect("canonical features json");
    FeaturesJson::from_sorted(features).expect("serialize_feature_set sorted")
}

/// The feature set of the unit `key` points at.
fn unit_features(units: &[StowUnit], key: &StowUnitKey) -> Option<String> {
    let unit = units.iter().find(|unit| &unit.key == key)?;
    serialize_feature_set(&unit.features.iter().cloned().collect::<BTreeSet<_>>()).ok()
}

/// Nodes the artifact catalog already covers, per platform and cargo
/// side: each node's `target` is the triple its artifacts are keyed
/// under — host units resolve against the host triple's rows — and a
/// node is covered only when those rows serve every unit shape its side
/// requires (a host-side node needs both the native-shape and the
/// `--target`-shape host units its consumers' builds look up).
async fn covered_nodes(
    db: &Db,
    nodes: &BTreeSet<TaskNode>,
    rustc_version: &WireRustcVersion,
) -> Result<BTreeSet<TaskNode>, ResolverError> {
    let mut covered = BTreeSet::new();
    let mut by_slice: BTreeMap<(&str, bool), BTreeSet<(PackageKey, String)>> = BTreeMap::new();
    for node in nodes {
        by_slice
            .entry((node.target.as_str(), node.host_side))
            .or_default()
            .insert((
                PackageKey {
                    crate_name: node.crate_name.clone(),
                    version: node.version.as_semver().clone(),
                },
                node.features_json.clone(),
            ));
    }
    for ((platform, host_side), key_pairs) in by_slice {
        let semantic = load_cached_artifacts_for_keys(
            db,
            platform,
            rustc_version.as_str(),
            &key_pairs,
            host_side,
        )
        .await?;
        let semantic: BTreeSet<(CrateName, semver::Version, String)> = semantic
            .into_iter()
            .map(|(key, features)| (key.crate_name, key.version, features))
            .collect();
        covered.extend(
            nodes
                .iter()
                .filter(|node| {
                    node.target == platform
                        && node.host_side == host_side
                        && semantic.contains(&(
                            node.crate_name.clone(),
                            node.version.as_semver().clone(),
                            node.features_json.clone(),
                        ))
                })
                .cloned(),
        );
    }
    Ok(covered)
}

/// Emit one [`EnqueueRequest`] per uncovered node. `depends_on` carries
/// the node's own task deps — the lib units its build links — so a
/// dependent dispatches only once its dependencies are servable, which
/// is the queue gate's release signal. Each dep names the dep's own
/// platform: the runner family's host triple for host-side units.
fn enqueue_requests_inner(
    nodes: &BTreeSet<TaskNode>,
    edges: &BTreeMap<TaskNode, BTreeSet<TaskNode>>,
    covered: &BTreeSet<TaskNode>,
    rustc_version: &WireRustcVersion,
    source: EnqueueSource,
    downloads: u64,
) -> (Vec<EnqueueRequest>, BTreeSet<TaskNode>) {
    let uncovered: BTreeSet<TaskNode> = nodes
        .iter()
        .filter(|n| !covered.contains(*n))
        .cloned()
        .collect();
    let mut requests = Vec::new();
    for node in &uncovered {
        let depends_on = edges
            .get(node)
            .into_iter()
            .flatten()
            .map(|dep| EnqueueDependency {
                crate_name: dep.crate_name.clone(),
                version: dep.version.clone(),
                features_json: features_json(&dep.features_json),
                target: TargetTriple::parse(&dep.target)
                    .expect("resolver emits CI or host triples"),
                rustc_version: rustc_version.clone(),
                host_side: dep.host_side,
            })
            .collect::<Vec<_>>();
        requests.push(EnqueueRequest {
            crate_name: node.crate_name.clone(),
            version: node.version.clone(),
            features_json: features_json(&node.features_json),
            target: TargetTriple::parse(&node.target).expect("resolver emits CI or host triples"),
            rustc_version: rustc_version.clone(),
            downloads,
            source,
            depends_on,
            preserve_lockfile: false,
            host_side: node.host_side,
        });
    }
    (requests, uncovered)
}

/// `GET` the URL body — one fetch, no retry: the index machinery retries
/// on its own machinery's `Retry` policy; tarballs and one-shot GETs pass
/// through the same transport.
async fn get_bytes(client: &ResolveHttp, url: &str) -> Result<Vec<u8>, ResolverError> {
    let request = http::Request::get(url)
        .body(Vec::new())
        .map_err(|error| ResolverError::CratesIo(format!("build request {url}: {error}")))?;
    let response = client
        .request(request)
        .await
        .map_err(|error| ResolverError::CratesIo(format!("fetch {url}: {error}")))?;
    let (parts, body) = response.into_parts();
    if !(200..300).contains(&parts.status.as_u16()) {
        return Err(ResolverError::CratesIo(format!(
            "{url} returned HTTP {}",
            parts.status
        )));
    }
    Ok(body)
}

/// `GET` the URL as a streaming body — the tarball lane, where the
/// response may far exceed the isolate's memory budget. Returns the body
/// and the Content-Length when the server sent one (the decompression
/// bound's compression-ratio input).
async fn get_stream(
    client: &ResolveHttp,
    url: &str,
) -> Result<(BodyStream, Option<u64>), ResolverError> {
    let request = http::Request::get(url)
        .body(Vec::new())
        .map_err(|error| ResolverError::CratesIo(format!("build request {url}: {error}")))?;
    let response = client
        .request_stream(request)
        .await
        .map_err(|error| ResolverError::CratesIo(format!("fetch {url}: {error}")))?;
    let (parts, body) = response.into_parts();
    if !(200..300).contains(&parts.status.as_u16()) {
        return Err(ResolverError::CratesIo(format!(
            "{url} returned HTTP {}",
            parts.status
        )));
    }
    let len = parts
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok());
    Ok((body, len))
}

/// Fetch one generated rustc-data file: `{base}/{version}/verbose/{host}.txt`
/// or `{base}/{version}/cfg/{triple}.txt`.
async fn fetch_rustc_data(
    http: &ResolveHttp,
    base_url: Option<&str>,
    path: &str,
) -> Result<String, ResolverError> {
    let Some(base) = base_url else {
        return Err(ResolverError::BadRequest(format!(
            "no vendored rustc data for `{path}` and \
             `STOW_RUSTC_DATA_BASE_URL` is not set"
        )));
    };
    let url = format!("{}/{path}", base.trim_end_matches('/'));
    let bytes = get_bytes(http, &url).await?;
    String::from_utf8(bytes)
        .map_err(|error| ResolverError::CratesIo(format!("{url} is not UTF-8: {error}")))
}

/// The `rustc -vV`/`--print cfg` inputs one resolve needs — vendored
/// tables first, then the generated tree `STOW_RUSTC_DATA_BASE_URL`
/// serves for a stable newer than the bundle.
async fn rustc_inputs(
    http: &ResolveHttp,
    base_url: Option<&str>,
    rustc_version: &WireRustcVersion,
    host_triple: &str,
    cfg_keys: &BTreeSet<String>,
) -> Result<(String, BTreeMap<String, Vec<String>>), ResolverError> {
    let version = rustc_version.as_str();
    let verbose = match rustc_data::verbose_version(version, host_triple) {
        Some(text) => text.to_owned(),
        None => {
            fetch_rustc_data(
                http,
                base_url,
                &format!("{version}/verbose/{host_triple}.txt"),
            )
            .await?
        }
    };
    let mut cfg = BTreeMap::new();
    for triple in cfg_keys {
        let lines = if let Some(lines) = rustc_data::cfg(version, triple) {
            lines
        } else {
            let text =
                fetch_rustc_data(http, base_url, &format!("{version}/cfg/{triple}.txt")).await?;
            text.lines().map(str::to_owned).collect()
        };
        cfg.insert(triple.clone(), lines);
    }
    Ok((verbose, cfg))
}

/// Run one resolve against the shared workspace for one target.
async fn resolve_workspace(
    http: &ResolveHttp,
    source: &SourceWorkspace,
    seed_features: &BTreeSet<String>,
    no_default_features: bool,
    target: &TargetTriple,
    rustc_version: &WireRustcVersion,
    rustc_data_base_url: Option<&str>,
) -> Result<api::StowResolveOutput, ResolverError> {
    let host_triple = runner_family(target.as_str())
        .ok_or_else(|| {
            ResolverError::BadRequest(format!("`{}` is not a CI target", target.as_str()))
        })?
        .host_triple()
        .to_string();
    let cfg_keys = BTreeSet::from([host_triple.clone(), target.as_str().to_owned()]);
    tracing::info!(target = %target, "resolve: rustc inputs begin");
    let (verbose, cfg) = rustc_inputs(
        http,
        rustc_data_base_url,
        rustc_version,
        &host_triple,
        &cfg_keys,
    )
    .await?;
    tracing::info!(target = %target, "resolve: rustc inputs ready");

    // The ambient VFS is thread-local while resolves interleave on the
    // isolate's single thread, so the section that depends on it swaps
    // this request's tree in for each poll and restores it afterwards —
    // no cross-request lock: a request the runtime abandons mid-resolve
    // can no longer strand every later resolve on a permit nobody
    // releases.
    let vfs = source.vfs.clone();
    tracing::info!(target = %target, "resolve: vfs section begin");
    poll_scoped(vfs, async move {
        let mut gctx = GlobalContext::new_for_resolve(
            PathBuf::from(WORKSPACE_DIR),
            source.cargo_home.clone(),
            Shell::new(),
            Env::new(),
            false,
        )
        .map_err(|error| ResolverError::CratesIo(format!("resolver context: {error}")))?;
        gctx.set_http(Client::new(http.clone()));
        tracing::info!(target = %target, "resolve: api::resolve begin");
        let output = api::resolve(
            &gctx,
            StowResolveInput {
                manifest_path: source.manifest_path.clone(),
                filter_platforms: vec![target.as_str().to_owned()],
                host_triple,
                features: seed_features.iter().cloned().collect(),
                all_features: false,
                no_default_features,
                members_are_crates_io: source.members_are_crates_io,
                rustc_verbose_version: verbose.clone(),
                cfg,
            },
        )
        .await
        .map_err(|error| ResolverError::CratesIo(format!("resolve failed: {error:#}")))?;
        tracing::info!(
            target = %target,
            units = output.units.len(),
            "resolve: api::resolve done"
        );
        Ok(output)
    })
    .await
}

/// The production HTTP transport: `worker::Fetch`.
#[cfg(target_family = "wasm")]
struct WorkerFetchHttp {
    /// The invoking request's outbound-connection budget — every fetch
    /// this transport issues waits for a slot before it goes on the wire.
    pool: OutboundPool,
}

#[cfg(target_family = "wasm")]
impl HttpClient for WorkerFetchHttp {
    fn request<'a>(
        &'a self,
        request: http::Request<Vec<u8>>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = stow_resolve::util::errors::CargoResult<http::Response<Vec<u8>>>,
                > + 'a,
        >,
    > {
        use skyzen_cloudflare::worker::send::IntoSendFuture as _;
        use skyzen_cloudflare::{CfFetch, worker};
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let _ = body; // GET requests carry no payload.
            let headers = worker::Headers::new();
            for (name, value) in &parts.headers {
                headers
                    .set(
                        name.as_str(),
                        value.to_str().map_err(|error| {
                            anyhow::format_err!("invalid header value for `{name}`: {error}")
                        })?,
                    )
                    .map_err(|error| anyhow::format_err!("set header `{name}`: {error}"))?;
            }
            let mut init = worker::RequestInit::new();
            init.with_method(worker::Method::Get).with_headers(headers);
            let request = worker::Request::new_with_init(parts.uri.to_string().as_str(), &init)
                .map_err(|error| anyhow::format_err!("build fetch {}: {error}", parts.uri))?;
            // A slot caps how many resolve-path fetches hold connections
            // at once; held until the body is buffered below.
            let url = parts.uri.to_string();
            let (held, waiting) = self.pool.stats();
            tracing::info!(held, waiting, "fetch: slot wait");
            let _slot = self.pool.slot().await;
            let (held, waiting) = self.pool.stats();
            tracing::info!(url = %url, held, waiting, "fetch: slot acquired");
            tracing::info!(url = %url, "fetch: sent");
            let mut response = CfFetch
                .request(&request)
                .into_send()
                .await
                .map_err(|error| anyhow::format_err!("fetch {}: {error}", parts.uri))?;
            let status = http::StatusCode::from_u16(response.status_code())
                .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
            tracing::info!(url = %url, status = status.as_u16(), "fetch: response");
            let mut builder = http::Response::builder().status(status);
            for (name, value) in response.headers().entries() {
                builder = builder.header(name.as_str(), value.as_str());
            }
            let bytes = response
                .bytes()
                .into_send()
                .await
                .map_err(|error| anyhow::format_err!("read {}: {error}", parts.uri))?;
            tracing::info!(url = %url, bytes = bytes.len(), "fetch: body buffered");
            builder
                .body(bytes)
                .map_err(|error| anyhow::format_err!("build response: {error}"))
        })
    }

    /// The streaming lane — tarballs too large to buffer in the isolate
    /// read through `worker::Response::stream()` instead of `bytes()`.
    // The permit is moved into `slotted` — it must outlive the fetch and
    // bind to the stream; the lint's `drop(slot)` suggestion would be a
    // use-after-move.
    #[allow(clippy::significant_drop_tightening)]
    fn request_stream<'a>(
        &'a self,
        request: http::Request<Vec<u8>>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = stow_resolve::util::errors::CargoResult<http::Response<BodyStream>>,
                > + 'a,
        >,
    > {
        use skyzen_cloudflare::worker::send::IntoSendFuture as _;
        use skyzen_cloudflare::{CfFetch, worker};
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let _ = body; // GET requests carry no payload.
            let headers = worker::Headers::new();
            for (name, value) in &parts.headers {
                headers
                    .set(
                        name.as_str(),
                        value.to_str().map_err(|error| {
                            anyhow::format_err!("invalid header value for `{name}`: {error}")
                        })?,
                    )
                    .map_err(|error| anyhow::format_err!("set header `{name}`: {error}"))?;
            }
            let mut init = worker::RequestInit::new();
            init.with_method(worker::Method::Get).with_headers(headers);
            let request = worker::Request::new_with_init(parts.uri.to_string().as_str(), &init)
                .map_err(|error| anyhow::format_err!("build fetch {}: {error}", parts.uri))?;
            // The slot outlives the fetch itself: a streamed body holds
            // its connection until the tarball drains, so the permit
            // binds to the stream, not to this async block.
            let (held, waiting) = self.pool.stats();
            tracing::info!(held, waiting, "fetch: slot wait");
            let slot = self.pool.slot().await;
            let (held, waiting) = self.pool.stats();
            let url = parts.uri.to_string();
            tracing::info!(url = %url, held, waiting, "fetch: slot acquired");
            tracing::info!(url = %url, "fetch: sent");
            let mut response = CfFetch
                .request(&request)
                .into_send()
                .await
                .map_err(|error| anyhow::format_err!("fetch {}: {error}", parts.uri))?;
            let status = http::StatusCode::from_u16(response.status_code())
                .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
            tracing::info!(url = %url, status = status.as_u16(), "fetch: response");
            let mut builder = http::Response::builder().status(status);
            for (name, value) in response.headers().entries() {
                builder = builder.header(name.as_str(), value.as_str());
            }
            let uri = parts.uri.to_string();
            let body: BodyStream = if let Ok(stream) = response.stream() {
                use futures_util::StreamExt as _;
                tarball::body_stream(stream.map(move |chunk| {
                    chunk.map_err(|error| anyhow::format_err!("read {uri}: {error}"))
                }))
            } else {
                // `stream()` fails when the response was already consumed —
                // fall back to a buffered body rather than fail the fetch.
                let bytes = response
                    .bytes()
                    .into_send()
                    .await
                    .map_err(|error| anyhow::format_err!("read {uri}: {error}"))?;
                tarball::body_stream(futures_util::stream::once(async move { Ok(bytes) }))
            };
            let body = crate::fetch_guard::slotted(body, slot, url);
            builder
                .body(body)
                .map_err(|error| anyhow::format_err!("build response: {error}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;
    use stow_resolve::api::{StowDep, StowSide};
    use stow_resolve::core::PackageIdSpec;
    use stow_resolve::core::dependency::DepKind;
    use stow_resolve::testing::RecordedHttp;
    use stow_resolve::util::fs::{self, OsVfs, RawDirEntry, RawMetadata, Vfs};

    /// Interleaved polls of two `poll_scoped` futures each see their
    /// own ambient VFS, and the ambient is restored after every poll —
    /// the property that lets resolves run concurrently on the isolate's
    /// single thread without a cross-request lock.
    #[test]
    fn poll_scoped_swaps_ambient_per_poll() {
        use std::task::Context;

        let a: Rc<dyn Vfs> = Rc::new(MemoryVfs::new());
        let b: Rc<dyn Vfs> = Rc::new(MemoryVfs::new());
        let a_own = a.clone();
        let b_own = b.clone();
        let mut fut_a = std::pin::pin!(poll_scoped(a, async move {
            assert!(Rc::ptr_eq(&fs::current(), &a_own));
            futures_util::future::pending::<()>().await;
        }));
        let mut fut_b = std::pin::pin!(poll_scoped(b, async move {
            assert!(Rc::ptr_eq(&fs::current(), &b_own));
            futures_util::future::pending::<()>().await;
        }));
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        for _ in 0..2 {
            assert!(fut_a.as_mut().poll(&mut cx).is_pending());
            // Nothing leaks out of the scope — an interleaved future
            // sees the ambient exactly as the last poll left it.
            assert!(fs::replace_vfs(None).is_none());
            assert!(fut_b.as_mut().poll(&mut cx).is_pending());
            assert!(fs::replace_vfs(None).is_none());
        }
    }

    /// `features_json` is the request's complete feature set, so defaults
    /// are on iff it carries `"default"`.
    #[test]
    fn no_default_features_from_complete_set() {
        assert!(no_default_features_for(&BTreeSet::new()));
        assert!(no_default_features_for(
            &std::iter::once("preserve_order".to_owned()).collect()
        ));
        assert!(!no_default_features_for(
            &["default".to_owned(), "preserve_order".to_owned()]
                .into_iter()
                .collect()
        ));
    }

    /// Every `Cargo.lock` under the selected workspace is dropped unless
    /// the lane asked to keep it — root and member-dir lockfiles alike —
    /// while non-lock files survive untouched.
    #[test]
    fn build_workspace_drops_nested_lockfiles() {
        let files: BTreeMap<PathBuf, Vec<u8>> = [
            ("Cargo.toml", "[workspace]\nmembers = [\"crates/*\"]\n"),
            ("Cargo.lock", "version = 4\n"),
            (
                "crates/member/Cargo.toml",
                "[package]\nname = \"m\"\nversion = \"0.1.0\"\n",
            ),
            ("crates/member/Cargo.lock", "version = 4\n"),
            ("crates/member/src/lib.rs", ""),
        ]
        .into_iter()
        .map(|(path, data)| (PathBuf::from(path), data.as_bytes().to_vec()))
        .collect();
        let ws = build_workspace(files.clone(), false, false).unwrap();
        for lock in ["Cargo.lock", "crates/member/Cargo.lock"] {
            assert!(
                ws.vfs
                    .read(Path::new(WORKSPACE_DIR).join(lock).as_path())
                    .is_err(),
                "{lock} should be dropped"
            );
        }
        assert!(
            ws.vfs
                .read(
                    Path::new(WORKSPACE_DIR)
                        .join("crates/member/src/lib.rs")
                        .as_path()
                )
                .is_ok()
        );

        // The request lane's keep flag preserves the workspace root lock.
        let kept = build_workspace(files, true, false).unwrap();
        assert!(
            kept.vfs
                .read(Path::new(WORKSPACE_DIR).join("Cargo.lock").as_path())
                .is_ok()
        );
    }

    fn unit(
        name: &str,
        platform: &str,
        side: StowSide,
        is_crates_io: bool,
        deps: Vec<StowDep>,
    ) -> StowUnit {
        StowUnit {
            key: StowUnitKey {
                pkg: PackageIdSpec::parse(&format!("{name}@1.0.0")).unwrap(),
                platform: platform.to_owned(),
                side,
                kind: StowUnitKind::Lib,
            },
            name: name.to_owned(),
            version: "1.0.0".to_owned(),
            unit_kind: StowUnitKind::Lib,
            features: Vec::new(),
            is_crates_io,
            deps,
        }
    }

    fn lib_dep(unit: &StowUnit) -> StowDep {
        StowDep {
            key: unit.key.clone(),
            name: unit.name.clone(),
            version: unit.version.clone(),
            dep_kind: DepKind::Normal,
        }
    }

    /// Only crates.io units mint tasks; members, path deps and git
    /// packages are traversed — a crates.io node's deps reach the next
    /// crates.io lib across non-node units in between.
    #[test]
    fn task_graph_walks_through_non_crates_io_units() {
        const T: &str = "x86_64-unknown-linux-gnu";
        let member = unit("member", T, StowSide::Target, false, vec![]);
        let itoa = unit("itoa", T, StowSide::Target, true, vec![]);
        let serde = unit("serde", T, StowSide::Target, true, vec![lib_dep(&member)]);
        let member = StowUnit {
            deps: vec![lib_dep(&itoa)],
            ..member
        };
        let units = vec![serde, member, itoa];
        let (nodes, edges) = task_graph(&units).unwrap();

        assert_eq!(
            nodes
                .iter()
                .map(|n| n.crate_name.as_str())
                .collect::<Vec<_>>(),
            ["itoa", "serde"]
        );
        let serde_node = nodes
            .iter()
            .find(|n| n.crate_name.as_str() == "serde")
            .unwrap();
        let serde_deps = &edges[serde_node];
        assert!(
            serde_deps.iter().any(|n| n.crate_name.as_str() == "itoa"),
            "serde's task deps should reach itoa through the member"
        );
    }

    /// `task_graph` CPU on a real zed resolve — the `--emit-units` lane of
    /// `resolve-diff` writes the unit graph production produces; point
    /// `STOW_ZED_UNITS_JSON` at one and run
    /// `cargo test -p stow-edge zed_task_graph_cpu -- --ignored --nocapture`.
    #[test]
    #[ignore = "reads STOW_ZED_UNITS_JSON"]
    fn zed_task_graph_cpu() {
        let path = std::env::var("STOW_ZED_UNITS_JSON").expect("STOW_ZED_UNITS_JSON");
        let text = std::fs::read_to_string(path).unwrap();
        let units: Vec<StowUnit> = serde_json::from_str(&text).unwrap();
        let start = std::time::Instant::now();
        let (nodes, edges) = task_graph(&units).unwrap();
        let elapsed = start.elapsed();
        let edge_count: usize = edges.values().map(BTreeSet::len).sum();
        eprintln!(
            "task_graph: {} units -> {} nodes, {edge_count} edges in {elapsed:?}",
            units.len(),
            nodes.len()
        );
    }

    /// `task_graph` errors propagate out of `enqueue_requests_from_output`
    /// rather than silently minting an empty batch.
    #[test]
    fn enqueue_requests_propagates_graph_errors() {
        let units = vec![unit(
            "na\u{ef}ve",
            "x86_64-unknown-linux-gnu",
            StowSide::Target,
            true,
            vec![],
        )];
        let rustc_version = WireRustcVersion::parse("1.98.1").unwrap();
        assert!(
            enqueue_requests_from_output(&units, &rustc_version, EnqueueSource::CrateUpdate, 0)
                .is_err()
        );
    }

    /// The issue-317 contract end to end over the fixture machinery: a
    /// workspace whose build needs `serde_derive` resolves its
    /// host-side units onto the runner family's host triple with the
    /// host-side feature sets cargo computes, a package needed on both
    /// sides becomes two nodes, and every edge into a host unit points
    /// at the host node. `syn = "3"` as a normal dep of `app` puts the
    /// same `syn` version on both sides with different feature sets.
    ///
    /// `resolve-diff-fixture/http` carries every crates.io exchange the
    /// resolve makes: the sparse index metadata and the `.crate`
    /// tarballs of the resolved set (`serde`, `serde_core`,
    /// `serde_derive`, `syn`, `proc-macro2`, `quote`, `unicode-ident`).
    #[tokio::test]
    async fn host_units_key_on_the_family_host_and_edges_point_at_them() {
        let http: ResolveHttp = Rc::new(RecordedHttp::new(PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../resolve/tests/resolve-diff-fixture/http"
        ))));
        let files: BTreeMap<PathBuf, Vec<u8>> = [
            (
                "Cargo.toml",
                concat!(
                    "[package]\n",
                    "name = \"app\"\n",
                    "version = \"0.1.0\"\n",
                    "edition = \"2021\"\n",
                    "\n",
                    "[dependencies]\n",
                    "serde = { version = \"1\", features = [\"derive\"] }\n",
                    "syn = { version = \"3\", features = [\"extra-traits\"] }\n",
                ),
            ),
            ("src/lib.rs", ""),
        ]
        .into_iter()
        .map(|(path, data)| (PathBuf::from(path), data.as_bytes().to_vec()))
        .collect();
        let mut source = build_workspace(files, false, false).expect("workspace");
        // On host the tarball unpack path is `std::fs` inside
        // `Entry::unpack_in`, so cargo home must be a real directory on a
        // real fs. Overlay it: paths under `cargo_home` route to `OsVfs`,
        // everything else stays in the shared memory tree.
        let cargo_home =
            std::env::temp_dir().join(format!("stow-host-units-cargo-home-{}", std::process::id()));
        std::fs::create_dir_all(&cargo_home).expect("cargo home");
        source.vfs = Rc::new(CargoHomeOverlay {
            inner: source.vfs.clone(),
            cargo_home: cargo_home.clone(),
        });
        source.cargo_home = cargo_home;
        let rustc_version = WireRustcVersion::parse("1.98.1").unwrap();
        let targets = vec![
            TargetTriple::parse("wasm32-unknown-unknown").unwrap(),
            TargetTriple::parse("aarch64-apple-ios").unwrap(),
        ];
        let resolved = source_resolve(&http, &source, &targets, &rustc_version, 0, None)
            .await
            .expect("resolve");

        assert_wasm32_host_units(&resolved.targets[0]);
        assert_ios_host_units(&resolved.targets[1]);
    }

    /// wasm32: `serde_derive` is a proc-macro — it mints on the wasm32
    /// family host `x86_64-unknown-linux-gnu` — and every `depends_on`
    /// edge into a host unit names that same host platform.
    fn assert_wasm32_host_units((target, requests): &(TargetTriple, Vec<EnqueueRequest>)) {
        assert_eq!(target.as_str(), "wasm32-unknown-unknown");
        let wasm = requests_by_name(requests);
        let host = "x86_64-unknown-linux-gnu";
        let serde_derive = wasm
            .get(&("serde_derive", host))
            .expect("serde_derive mints on the wasm32 family host");
        let serde = wasm
            .get(&("serde", "wasm32-unknown-unknown"))
            .expect("serde is a wasm32 task");
        assert!(
            serde.depends_on.iter().any(|dependency| {
                dependency.crate_name.as_str() == "serde_derive"
                    && dependency.target.as_str() == host
            }),
            "serde's edge must point at serde_derive's host node, got {:?}",
            serde.depends_on
        );

        // `syn` resolves on both sides at the same version: the target
        // node carries `app`'s `extra-traits` plus syn's defaults; the
        // host node carries the set serde_derive asks for — `default`
        // and `extra-traits` are what tells them apart.
        let syn_target = wasm
            .get(&("syn", "wasm32-unknown-unknown"))
            .expect("syn as a normal dep mints on the consumer target");
        let syn_host = wasm
            .get(&("syn", host))
            .expect("syn as a proc-macro dep mints on the host");
        assert_eq!(syn_target.version, syn_host.version);
        let target_features = syn_target.features_json.features();
        assert!(
            target_features.contains(&"default".to_owned())
                && target_features.contains(&"extra-traits".to_owned()),
            "target syn carries app's feature set: {target_features:?}"
        );
        let host_features = syn_host.features_json.features();
        for feature in ["derive", "parsing", "printing", "proc-macro"] {
            assert!(
                host_features.contains(&feature.to_owned()),
                "host syn features must include {feature}: {host_features:?}"
            );
        }
        for feature in ["default", "extra-traits"] {
            assert!(
                !host_features.contains(&feature.to_owned()),
                "the host syn node carries its own side's features: {host_features:?}"
            );
        }

        // Every edge a host unit itself carries also names host
        // platforms: serde_derive's syn/proc-macro2/quote deps and syn's
        // proc-macro2/quote/unicode-ident deps are all host tasks.
        for (dependent, dep) in [
            (serde_derive, "syn"),
            (serde_derive, "proc-macro2"),
            (serde_derive, "quote"),
            (syn_host, "proc-macro2"),
            (syn_host, "quote"),
            (syn_host, "unicode-ident"),
        ] {
            assert!(
                dependent.depends_on.iter().any(|dependency| {
                    dependency.crate_name.as_str() == dep && dependency.target.as_str() == host
                }),
                "{} must wait on {} at the host triple",
                dependent.crate_name,
                dep
            );
        }
    }

    /// The same resolve for `aarch64-apple-ios` lands its host units on
    /// `aarch64-apple-darwin`.
    fn assert_ios_host_units((target, requests): &(TargetTriple, Vec<EnqueueRequest>)) {
        assert_eq!(target.as_str(), "aarch64-apple-ios");
        let ios = requests_by_name(requests);
        let host = "aarch64-apple-darwin";
        assert!(
            ios.contains_key(&("serde_derive", host)),
            "ios host units mint on the macOS family host"
        );
        assert!(
            ios.contains_key(&("syn", host)),
            "the host-side syn node lands on darwin too"
        );
        let serde = ios
            .get(&("serde", "aarch64-apple-ios"))
            .expect("serde mints on the ios target");
        assert!(
            serde.depends_on.iter().any(|dependency| {
                dependency.crate_name.as_str() == "serde_derive"
                    && dependency.target.as_str() == host
            }),
            "serde's edge names serde_derive's darwin node"
        );
    }

    fn requests_by_name(requests: &[EnqueueRequest]) -> BTreeMap<(&str, &str), &EnqueueRequest> {
        requests
            .iter()
            .map(|request| {
                (
                    (request.crate_name.as_str(), request.target.as_str()),
                    request,
                )
            })
            .collect()
    }

    /// A test-only [`Vfs`] overlay: paths under `cargo_home` resolve
    /// against the real fs (the host tarball unpack uses `std::fs`
    /// through `Entry::unpack_in`), everything else stays in memory.
    struct CargoHomeOverlay {
        inner: Rc<dyn Vfs>,
        cargo_home: PathBuf,
    }

    impl CargoHomeOverlay {
        fn backend(&self, path: &Path) -> &dyn Vfs {
            if path.starts_with(&self.cargo_home) {
                &OsVfs
            } else {
                self.inner.as_ref()
            }
        }
    }

    impl Vfs for CargoHomeOverlay {
        fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
            self.backend(path).read(path)
        }
        fn write(&self, path: &Path, data: &[u8]) -> std::io::Result<()> {
            self.backend(path).write(path, data)
        }
        fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
            self.backend(path).create_dir_all(path)
        }
        fn read_dir(&self, path: &Path) -> std::io::Result<Vec<RawDirEntry>> {
            self.backend(path).read_dir(path)
        }
        fn metadata(&self, path: &Path) -> std::io::Result<RawMetadata> {
            self.backend(path).metadata(path)
        }
        fn remove_file(&self, path: &Path) -> std::io::Result<()> {
            self.backend(path).remove_file(path)
        }
        fn remove_dir_all(&self, path: &Path) -> std::io::Result<()> {
            self.backend(path).remove_dir_all(path)
        }
        fn canonicalize(&self, path: &Path) -> std::io::Result<PathBuf> {
            self.backend(path).canonicalize(path)
        }
        fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
            self.backend(from).rename(from, to)
        }
        fn mtime(&self, path: &Path) -> std::io::Result<SystemTime> {
            self.backend(path).mtime(path)
        }
        fn set_mtime(&self, path: &Path, t: SystemTime) -> std::io::Result<()> {
            self.backend(path).set_mtime(path, t)
        }
    }

    /// A proc-macro request's root task keys on the runner-family host
    /// triple its `roots` entry carries — never the requested target.
    #[test]
    fn request_plan_roots_at_key_platform() {
        let proc = unit(
            "my-proc",
            "x86_64-unknown-linux-gnu",
            StowSide::Host,
            true,
            vec![],
        );
        let roots = vec![proc.key.clone()];
        let crate_name = CrateName::parse("my-proc".to_owned()).unwrap();
        let version = semver::Version::parse("1.0.0").unwrap();
        let target = TargetTriple::parse("wasm32-unknown-unknown").unwrap();
        let parts = request_plan_parts(&[proc], &roots, &crate_name, &version, &target).unwrap();
        assert_eq!(parts.root_target, "x86_64-unknown-linux-gnu");
        let root_key = parts.root_key.expect("lib root");
        assert_eq!(root_key.target, "x86_64-unknown-linux-gnu");
    }
}
