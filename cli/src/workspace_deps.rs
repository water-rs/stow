use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use async_process::Command;
use cargo_lock::{Lockfile, package::SourceId};
use glob::glob;
use semver::Version;
use serde::Deserialize;
use stow_types::api::{ResolvedDependencyGraphDependency, ResolvedDependencyGraphEntry};
use stow_types::error::Context;
use stow_types::public_cache::UnitSide;

use crate::cargo_cmd::MetadataArgs;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct SelectedRegistryDependency {
    /// Every extern name this node is a direct dependency under —
    /// renamed deps across roots spell their own (`once_cell` beside
    /// `oc = { package = "once_cell" }`), and rustc needs each.
    pub extern_names: BTreeSet<String>,
    pub crate_name: String,
    pub version: Version,
    /// Cargo's recorded features for this side — never unioned across
    /// sides; a crate that is direct on both lands as two entries.
    pub features: Vec<String>,
    /// Which half of the unit graph the dependency edge lands on.
    pub host_side: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PackageKey {
    pub(crate) crate_name: String,
    pub(crate) version: Version,
    pub(crate) source: Option<String>,
}

/// The units cargo compiles for the wrapped command — one
/// `cargo <subcommand> --unit-graph` run — projected onto the facts
/// the local index resolver needs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExpandedDependencyGraph {
    /// The normalized expanded graph the resolver and the admissions
    /// request both consume.
    pub entries: Vec<ResolvedDependencyGraphEntry>,
    /// The roots' direct registry externs — the top-crate path's
    /// dependency set, from the same unit graph.
    pub direct_dependencies: Vec<SelectedRegistryDependency>,
    /// Every local (path-source) package manifest cargo read for this
    /// answer, with its content hash — path deps outside the workspace
    /// root are inputs too, so the persisted copy verifies these on
    /// load instead of trying to name them in the cache key.
    pub local_manifests: Vec<LocalManifestHash>,
    /// The raw `cargo --unit-graph` stdout this graph was expanded
    /// from — the build stage's dependency-context check projects this
    /// onto the shared [`stow_types::unit_graph::TaskUnit`] model
    /// (stow#588). Empty on rows decoded from a pre-588 cache.
    #[serde(default)]
    pub raw_unit_graph: Vec<u8>,
}

impl ExpandedDependencyGraph {
    /// The units cargo's unit graph compiled, in the shared task-unit
    /// model — the identity lens `resolved_task_graph` projects (stow#588).
    ///
    /// `target` is the triple cargo was given (`None` for the native
    /// spelling), `host_triple` the runner family's host triple the
    /// `platform: null` units compile for.
    ///
    /// # Errors
    /// Re-parse failures and the conversion's consistency checks — see
    /// [`unit_graph_task_units`]. An empty `raw_unit_graph` (a graph
    /// decoded from a pre-588 cache) is an error, not an empty answer.
    pub fn task_units(
        &self,
        target: Option<&str>,
        host_triple: &str,
    ) -> stow_types::error::Result<Vec<stow_types::unit_graph::TaskUnit>> {
        if self.raw_unit_graph.is_empty() {
            return Err(stow_types::stow_error!(
                "expanded dependency graph carries no raw unit graph (a pre-588 cached row) — cannot derive task units"
            ));
        }
        let graph: UnitGraph<'_> = serde_json::from_slice(&self.raw_unit_graph)
            .wrap_err("parse cargo --unit-graph JSON")?;
        if graph.version != 1 {
            return Err(stow_types::stow_error!(
                "cargo --unit-graph reported version {}; only version 1 is understood",
                graph.version
            ));
        }
        unit_graph_task_units(&graph, target, host_triple)
    }
}

/// A manifest cargo read, recorded with its blake3 so a later cache
/// load can check it has not changed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LocalManifestHash {
    pub path: PathBuf,
    pub blake3: String,
}

impl LocalManifestHash {
    /// Whether the file still hashes to the recorded value — a missing
    /// or unreadable manifest is a mismatch, not an error.
    pub fn verify(&self) -> bool {
        std::fs::read(&self.path)
            .is_ok_and(|bytes| blake3::hash(&bytes).to_hex().as_str() == self.blake3)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceLayout {
    pub(crate) workspace_root: PathBuf,
    pub(crate) manifest_path: PathBuf,
}

pub fn resolve_workspace_layout(
    invocation_dir: &Path,
    manifest_override: Option<&Path>,
) -> stow_types::error::Result<WorkspaceLayout> {
    let selected_manifest = match manifest_override {
        Some(path) => canonicalize_or_original(path),
        None => find_nearest_manifest(invocation_dir)?,
    };
    let Some(selected_dir) = selected_manifest.parent() else {
        return Err(stow_types::stow_error!(
            "manifest path {} has no parent directory",
            selected_manifest.display()
        ));
    };

    if let Some(workspace_root) = find_workspace_root(&selected_manifest)? {
        return Ok(WorkspaceLayout {
            manifest_path: selected_manifest,
            workspace_root,
        });
    }

    Ok(WorkspaceLayout {
        workspace_root: selected_dir.to_path_buf(),
        manifest_path: selected_manifest,
    })
}

/// The registry `(name, version)` pairs `<workspace_root>/Cargo.lock`
/// pins — the units this build compiles as far as the lockfile knows
/// (stow#617). The serve map's local half is this read's only consumer,
/// and it asks for the lockfile and nothing else: no manifest, no
/// member walk, no feature resolution.
///
/// `Ok(None)` when the lockfile does not exist: cargo writes it during
/// this very build, so absence is a defined state — the build carries
/// no local half — not an error and not a warning (stow#608).
#[tracing::instrument(name = "stow.workspace.lockfile_registry_packages", skip_all)]
pub fn lockfile_registry_packages(
    workspace_root: &Path,
) -> stow_types::error::Result<Option<BTreeSet<(String, Version)>>> {
    let lockfile_path = workspace_root.join("Cargo.lock");
    if !lockfile_path.exists() {
        return Ok(None);
    }
    let lockfile = Lockfile::load(&lockfile_path).map_err(|error| {
        stow_types::stow_error!("load lockfile {}: {error}", lockfile_path.display())
    })?;
    Ok(Some(
        lockfile
            .packages
            .iter()
            .filter(|package| package.source.as_ref().is_some_and(SourceId::is_registry))
            .map(|package| (package.name.to_string(), package.version.clone()))
            .collect(),
    ))
}

/// Re-run the wrapped cargo subcommand as `cargo <subcommand>
/// --unit-graph` with the user's own arguments (stow#551).
///
/// `target` is the triple cargo was given — by `--target`, by
/// `CARGO_BUILD_TARGET`, or by `build.target` — and `None` when the
/// build is native. Several given targets resolve side-by-side in
/// cargo's graph; units for a target other than `target` are never
/// nodes (stow serves one target's units), so they are filtered by
/// `platform` rather than merged.
///
/// # Errors
///
/// Fails when cargo rejects the invocation or reports a unit-graph
/// format version this code does not understand, and when the graph's
/// own consistency checks trip — see [`expanded_dependency_graph`].
#[tracing::instrument(name = "stow.workspace_deps.unit_graph", skip_all)]
#[allow(clippy::too_many_arguments)]
pub async fn resolve_exact_dependency_graph(
    manifest_path: &Path,
    action: &str,
    cargo_args: &[OsString],
    target: Option<&str>,
    current_dir: &Path,
    host_triple: &str,
    rustc_version: &stow_types::identity::WireRustcVersion,
    cargo_home: Option<&Path>,
) -> stow_types::error::Result<ExpandedDependencyGraph> {
    let (mut unit_graph, subcommand) =
        unit_graph_command(manifest_path, action, cargo_args, current_dir, cargo_home).await?;
    let unit_graph_output = unit_graph
        .output()
        .await
        .wrap_err("spawn cargo --unit-graph")?;
    expand_unit_graph_output(
        unit_graph_output,
        subcommand,
        target,
        host_triple,
        rustc_version,
    )
    .await
}

/// The command half of [`resolve_exact_dependency_graph`]: the `cargo
/// <subcommand> --unit-graph` invocation, built but not yet spawned,
/// and the subcommand name the failure's error text uses (stow#667).
/// `cargo_home` pins `CARGO_HOME` on the child — and the global config
/// the `[unstable]` gate reads — so a test answers from its own home
/// rather than the developer's; `None` inherits the process's.
async fn unit_graph_command(
    manifest_path: &Path,
    action: &str,
    cargo_args: &[OsString],
    current_dir: &Path,
    cargo_home: Option<&Path>,
) -> stow_types::error::Result<(Command, &'static str)> {
    let subcommand = unit_graph_subcommand(action)?;
    let mut unit_graph = Command::new("cargo");
    if let Some(home) = cargo_home {
        unit_graph.env("CARGO_HOME", home);
    }
    unit_graph
        .arg(subcommand)
        // Before the user's args: never lands behind a `--` terminator.
        .arg("--unit-graph")
        .arg("-Z")
        .arg("unstable-options")
        .current_dir(current_dir)
        // A build aborts its in-flight analysis when cargo exits: dropping
        // this resolve kills the child rather than orphaning it to keep
        // probing rustc after stow has returned (stow#624).
        .kill_on_drop(true);
    // `-Z` needs nightly cargo or RUSTC_BOOTSTRAP. On a stable channel
    // with no user-set value, the child gets cargo's own channel
    // override instead: cargo treats itself as nightly and accepts
    // `-Z unstable-options`, while rustc — which never reads the
    // variable — keeps answering `--print cfg` as stable, so
    // `cfg(target_thread_local)`-class cfgs stay absent exactly as the
    // user's build sees them (stow#551). RUSTC_BOOTSTRAP would change
    // rustc's answer, so it is never injected; a user-set value passes
    // through untouched because the user's build sees the same cfgs.
    // If a future cargo drops the override, cargo rejects `-Z` and the
    // query fails loudly below — no fallback.
    if std::env::var_os("RUSTC_BOOTSTRAP").is_none() && cargo_channel_is_stable(current_dir).await?
    {
        unstable_feature_gate(current_dir, cargo_args, cargo_home)?;
        for (key, value) in unit_graph_channel_env() {
            unit_graph.env(key, value);
        }
    }
    // `--offline` is non-negotiable: dropping it makes cargo refresh the
    // crates.io index on each invocation — a multi-second blocking call
    // that turns small projects (clap ~1s vanilla) into 20-second stow
    // runs and explodes the no-slowdown budget.
    if !arg_spelled(cargo_args, "--offline") {
        unit_graph.arg("--offline");
    }
    if !arg_spelled(cargo_args, "--manifest-path") {
        unit_graph.arg("--manifest-path").arg(manifest_path);
    }
    unit_graph.args(cargo_args);
    Ok((unit_graph, subcommand))
}

/// The read half of [`resolve_exact_dependency_graph`]'s run: the
/// status check, then the parse and the expansion, which walk cargo's
/// whole unit table — input that grows with the workspace — on a
/// blocking thread (stow#624).
async fn expand_unit_graph_output(
    output: async_process::Output,
    subcommand: &str,
    target: Option<&str>,
    host_triple: &str,
    rustc_version: &stow_types::identity::WireRustcVersion,
) -> stow_types::error::Result<ExpandedDependencyGraph> {
    if !output.status.success() {
        return Err(stow_types::stow_error!(
            "cargo {subcommand} --unit-graph failed on toolchain {}: {}",
            rustc_version.as_str(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let stdout = output.stdout;
    let target = target.map(str::to_owned);
    let host_triple = host_triple.to_owned();
    let rustc_version = rustc_version.clone();
    smol::unblock(move || {
        let mut graph =
            expanded_dependency_graph(&stdout, target.as_deref(), &host_triple, &rustc_version)?;
        graph.raw_unit_graph = stdout;
        Ok(graph)
    })
    .await
}

/// [`resolve_exact_dependency_graph`] under the drain's derivation
/// gate: a stow command connecting to the slot's listener kills the
/// cargo child — killed and reaped before the requester's connection
/// closes, so a released command never queues behind a drain cargo
/// that still holds the package-cache lock (stow#667). `Ok(None)` is
/// the stopped run: the drain keeps the units journaled.
#[allow(clippy::too_many_arguments)]
pub async fn resolve_exact_dependency_graph_stoppable(
    manifest_path: &Path,
    action: &str,
    cargo_args: &[OsString],
    target: Option<&str>,
    current_dir: &Path,
    host_triple: &str,
    rustc_version: &stow_types::identity::WireRustcVersion,
    cargo_home: Option<&Path>,
    slot: &mut crate::derive_gate::DerivationSlot,
) -> stow_types::error::Result<Option<ExpandedDependencyGraph>> {
    let (mut unit_graph, subcommand) =
        unit_graph_command(manifest_path, action, cargo_args, current_dir, cargo_home).await?;
    unit_graph
        .stdout(async_process::Stdio::piped())
        .stderr(async_process::Stdio::piped());
    let mut child = unit_graph.spawn().wrap_err("spawn cargo --unit-graph")?;
    match run_stoppable_child(&mut child, slot).await? {
        Some(output) => {
            expand_unit_graph_output(output, subcommand, target, host_triple, rustc_version)
                .await
                .map(Some)
        }
        None => Ok(None),
    }
}

/// Drive `child` to its end — both pipes read concurrently so the
/// child never stalls on a full one — or kill it when a stow command
/// connects to the slot's listener (stow#667). The kill is explicit
/// and awaited, not `kill_on_drop`'s: the slot keeps the requester
/// parked on the connection until the child is reaped, so the
/// requester is released only once the child holds no package-cache
/// lock.
///
/// `Ok(None)` is the stopped run.
async fn run_stoppable_child(
    child: &mut async_process::Child,
    slot: &mut crate::derive_gate::DerivationSlot,
) -> stow_types::error::Result<Option<async_process::Output>> {
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| stow_types::stow_error!("the stoppable child's stdout pipe is missing"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| stow_types::stow_error!("the stoppable child's stderr pipe is missing"))?;
    let pipes = async move {
        let mut out = Vec::new();
        let mut err = Vec::new();
        futures_lite::future::try_zip(
            futures_lite::AsyncReadExt::read_to_end(&mut stdout, &mut out),
            futures_lite::AsyncReadExt::read_to_end(&mut stderr, &mut err),
        )
        .await?;
        std::io::Result::Ok((out, err))
    };
    tokio::select! {
        output = pipes => {
            let (stdout, stderr) = output.wrap_err("read the stoppable child's pipes")?;
            let status = child.status().await.wrap_err("await the stoppable child's exit")?;
            Ok(Some(async_process::Output { status, stdout, stderr }))
        }
        () = slot.stop_requested() => {
            child.kill().wrap_err("kill the stoppable child")?;
            child.status().await.wrap_err("await the stopped child's exit")?;
            Ok(None)
        }
    }
}

/// The read half of [`resolve_exact_dependency_graph`].
///
/// Turns captured `cargo <subcommand> --unit-graph` stdout into the
/// entries, direct dependencies and local manifests.
/// `target` is the triple cargo was given, `None` when the build is
/// native. Exposed so the trusted builder's consumption set can be
/// exercised against a graph fixture without spawning cargo (stow#589).
///
/// # Errors
///
/// Fails when the JSON is not a unit-graph document, the graph's
/// `version` is not 1, a `dependencies`/`roots` index is out of bounds,
/// or a graph unit is unreachable from the roots — cargo reporting a
/// graph this code does not understand is an error, never a guess.
pub fn expanded_dependency_graph(
    unit_graph_json: &[u8],
    target: Option<&str>,
    host_triple: &str,
    rustc_version: &stow_types::identity::WireRustcVersion,
) -> stow_types::error::Result<ExpandedDependencyGraph> {
    let graph: UnitGraph<'_> =
        serde_json::from_slice(unit_graph_json).wrap_err("parse cargo --unit-graph JSON")?;
    if graph.version != 1 {
        return Err(stow_types::stow_error!(
            "cargo --unit-graph reported version {} (toolchain {}); only version 1 is understood",
            graph.version,
            rustc_version.as_str()
        ));
    }
    let (entries, direct_dependencies, local_manifests) =
        emit_expanded_graph(&graph, target, host_triple, rustc_version)?;
    Ok(ExpandedDependencyGraph {
        entries,
        direct_dependencies,
        local_manifests,
        // `resolve_exact_dependency_graph` fills this from the stdout
        // it already holds; direct parse callers get an empty marker —
        // `task_units` fails on it rather than answering without the
        // raw graph.
        raw_unit_graph: Vec::new(),
    })
}

/// The cargo subcommand whose unit graph each wrapped action compiles;
/// `predict` answers what `check` compiles. Only the actions stow
/// wraps (`check`, `build`, `test`, `predict`) reach this mapping.
fn unit_graph_subcommand(action: &str) -> stow_types::error::Result<&'static str> {
    Ok(match action {
        "check" | "predict" => "check",
        "build" => "build",
        "test" => "test",
        other => {
            return Err(stow_types::stow_error!(
                "stow action `{other}` has no cargo unit-graph subcommand"
            ));
        }
    })
}

/// `cargo -V`'s channel: `cargo X.Y.Z` is stable; `-nightly`/`-dev`
/// suffixes take `-Z` flags without `RUSTC_BOOTSTRAP`, so the query needs
/// no injection there (beta counts as stable-channel, the same answer
/// cargo's own feature gate gives for `RUSTC_BOOTSTRAP`).
async fn cargo_channel_is_stable(current_dir: &Path) -> stow_types::error::Result<bool> {
    let output = Command::new("cargo")
        .arg("-V")
        .current_dir(current_dir)
        // Dropped with the resolve it answers for (stow#624).
        .kill_on_drop(true)
        .output()
        .await
        .wrap_err("spawn cargo -V")?;
    let version = String::from_utf8_lossy(&output.stdout);
    Ok(!(version.contains("nightly") || version.contains("-dev")))
}

/// cargo's own channel override variable: `nightly` makes cargo accept
/// `-Z` without `RUSTC_BOOTSTRAP`, and rustc never reads it — the
/// probe keeps answering stable cfgs (stow#551).
const CARGO_CHANNEL_OVERRIDE: &str = "__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS";

/// The extra environment the unit-graph child needs beyond the user's,
/// reached only when stable cargo must accept `-Z` and the user's own
/// environment does not already unlock it. `RUSTC_BOOTSTRAP` is never
/// set here — it changes rustc's `--print cfg` answer.
fn unit_graph_channel_env() -> Vec<(&'static str, &'static str)> {
    vec![(CARGO_CHANNEL_OVERRIDE, "nightly")]
}

/// Fail when cargo config enables unstable features: under the nightly
/// channel override cargo honors `[unstable]`/`CARGO_UNSTABLE_*`, while
/// the user's stable build ignores them — the query cannot represent
/// that build, so it must not answer.
fn unstable_feature_gate(
    current_dir: &Path,
    cargo_args: &[OsString],
    cargo_home: Option<&Path>,
) -> stow_types::error::Result<()> {
    let mut enabled = Vec::<String>::new();
    for (key, _value) in std::env::vars() {
        if let Some(name) = key.strip_prefix("CARGO_UNSTABLE_") {
            enabled.push(format!("CARGO_UNSTABLE_{name}"));
        }
    }
    for (source, document) in
        crate::mold::cargo_config_documents(current_dir, cargo_args, cargo_home)
    {
        let Some(item) = document.get("unstable") else {
            continue;
        };
        match item.as_table_like() {
            Some(table) => enabled.extend(
                table
                    .iter()
                    .map(|(key, _)| format!("{source}: unstable.{key}")),
            ),
            None => enabled.push(format!("{source}: unstable")),
        }
    }
    if enabled.is_empty() {
        return Ok(());
    }
    enabled.sort();
    Err(stow_types::stow_error!(
        "cargo unstable feature{} enabled, but stable cargo would ignore it outside the unit-graph query: {}",
        if enabled.len() == 1 { " is" } else { "s are" },
        enabled.join(", ")
    ))
}

/// `--unit-graph` kinds that are library compilations.
const LIB_KINDS: &[&str] = &["lib", "rlib", "dylib", "proc-macro", "staticlib", "cdylib"];

/// Real-compilation modes — `cargo check` names its lib units `check`.
const COMPILE_MODES: &[&str] = &["build", "check"];

/// The `pkg_id` prefix every crates.io unit carries — alternative-registry
/// packages must not become nodes.
const CRATES_IO_PREFIX: &str = "registry+https://github.com/rust-lang/crates.io-index#";

const HOST: u8 = 1;
const TARGET: u8 = 2;

/// `cargo <subcommand> --unit-graph` stdout, format version 1 (borrowed).
#[derive(Deserialize)]
struct UnitGraph<'a> {
    version: u32,
    #[serde(borrow)]
    units: Vec<Unit<'a>>,
    roots: Vec<u32>,
}

#[derive(Deserialize)]
struct Unit<'a> {
    #[serde(borrow)]
    pkg_id: &'a str,
    target: UnitTarget<'a>,
    /// `null` marks the host half when cargo was given a target; the
    /// triple otherwise. Several targets resolve side-by-side and each
    /// unit records the one it compiles for.
    platform: Option<&'a str>,
    #[serde(borrow)]
    mode: &'a str,
    #[serde(borrow, default)]
    features: Vec<&'a str>,
    #[serde(borrow, default)]
    dependencies: Vec<UnitDependency<'a>>,
}

#[derive(Deserialize)]
struct UnitTarget<'a> {
    #[serde(borrow)]
    kind: Vec<&'a str>,
}

#[derive(Deserialize)]
struct UnitDependency<'a> {
    index: u32,
    #[serde(borrow)]
    extern_crate_name: &'a str,
    /// `kind: "build"` marks a build-dependency edge; normal edges carry
    /// `kind: null` or no entry at all.
    #[serde(borrow, default)]
    dep_kinds: Vec<UnitDepKind<'a>>,
}

#[derive(Deserialize)]
struct UnitDepKind<'a> {
    #[serde(borrow)]
    kind: Option<&'a str>,
}

/// A build-dependency edge — its dep unit is always host-side.
fn is_build_dep_edge(dependency: &UnitDependency<'_>) -> bool {
    dependency
        .dep_kinds
        .iter()
        .any(|entry| entry.kind == Some("build"))
}

/// `flag` or `flag=…` appears in `args`.
fn arg_spelled(args: &[OsString], flag: &str) -> bool {
    args.iter().any(|arg| {
        arg.as_os_str() == flag
            || arg
                .to_str()
                .is_some_and(|a| a.starts_with(&format!("{flag}=")))
    })
}

/// The source `Cargo.lock` records for crates.io packages — the
/// `CRATES_IO_PREFIX` without the `#` pkg-id separator.
pub const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// `registry+…#name@version` → (name, version, is-crates-io).
fn parse_pkg_id(pkg_id: &str) -> (&str, &str, bool) {
    match pkg_id
        .rsplit('#')
        .next()
        .and_then(|frag| frag.split_once('@'))
    {
        Some((name, version)) => (name, version, pkg_id.starts_with(CRATES_IO_PREFIX)),
        None => (pkg_id, "", false),
    }
}

/// Per-unit facts the projection consults: `parsed` is `Some` exactly
/// when the unit is a node — non-registry pkg ids (`path+`, `git+`)
/// are not `name@version` and cannot be parsed.
struct UnitInfo<'a> {
    name: &'a str,
    version_str: &'a str,
    /// `Some` exactly when the unit is a node — a crates.io lib in a
    /// real-compilation mode (`unit_infos` computes the flag once).
    parsed: Option<(stow_types::identity::CrateName, Version)>,
}

impl UnitInfo<'_> {
    /// `(CrateName, Version)` of a node unit — the `unit_infos` gate.
    const fn parsed(&self) -> &(stow_types::identity::CrateName, Version) {
        self.parsed.as_ref().expect("node units are parsed")
    }
}

fn unit_infos<'a>(graph: &UnitGraph<'a>) -> stow_types::error::Result<Vec<UnitInfo<'a>>> {
    graph
        .units
        .iter()
        .map(|unit| {
            let (name, version, crates_io) = parse_pkg_id(unit.pkg_id);
            let node = crates_io
                && unit.target.kind.iter().any(|kind| LIB_KINDS.contains(kind))
                && COMPILE_MODES.contains(&unit.mode);
            let parsed = node
                .then(|| {
                    let bad = |error: &dyn std::fmt::Display| {
                        stow_types::stow_error!(
                            "cargo --unit-graph pkg_id `{}`: {error}",
                            unit.pkg_id
                        )
                    };
                    Ok::<_, stow_types::error::Error>((
                        stow_types::identity::CrateName::parse(name)
                            .map_err(|error| bad(&error))?,
                        Version::parse(version).map_err(|error| bad(&error))?,
                    ))
                })
                .transpose()?;
            Ok(UnitInfo {
                name,
                version_str: version,
                parsed,
            })
        })
        .collect()
}

fn info_at<'a>(
    infos: &'a [UnitInfo<'a>],
    index: u32,
) -> stow_types::error::Result<&'a UnitInfo<'a>> {
    infos.get(index as usize).ok_or_else(|| {
        stow_types::stow_error!("cargo --unit-graph dependency index {index} is out of bounds")
    })
}

/// A proc-macro or build-script unit — cargo's `CompileKind::Host`.
fn host_kinded(unit: &Unit<'_>) -> bool {
    unit.target.kind == ["custom-build"] || unit.target.kind.contains(&"proc-macro")
}

/// Side per unit. When cargo was given a target, host units are
/// `platform: null` and target units carry their triple — a unit for a
/// different target than the one served gets side 0 (never a node).
/// Without a given target the side is cargo's `CompileKind` rule —
/// roots and normal deps target, anything under a
/// proc-macro/build-script/host unit host. Both sides reachable carries
/// both bits.
fn unit_sides(graph: &UnitGraph<'_>, target: Option<&str>) -> stow_types::error::Result<Vec<u8>> {
    if let Some(target) = target {
        return Ok(graph
            .units
            .iter()
            .map(|unit| match unit.platform {
                None => HOST,
                Some(platform) if platform == target => TARGET,
                // cargo compiles the other targets it was given too;
                // their units are never nodes for the served target.
                Some(_) => 0,
            })
            .collect());
    }
    let mut sides = vec![0u8; graph.units.len()];
    let mut queue = VecDeque::<(usize, u8)>::new();
    for &root in &graph.roots {
        let root = info_at_index(graph, root)?;
        let side = if host_kinded(&graph.units[root]) {
            HOST
        } else {
            TARGET
        };
        if sides[root] & side == 0 {
            sides[root] |= side;
            queue.push_back((root, side));
        }
    }
    while let Some((index, side)) = queue.pop_front() {
        for dependency in &graph.units[index].dependencies {
            let dep = info_at_index(graph, dependency.index)?;
            let dep_side = if host_kinded(&graph.units[dep]) || side == HOST {
                HOST
            } else {
                TARGET
            };
            if sides[dep] & dep_side == 0 {
                sides[dep] |= dep_side;
                queue.push_back((dep, dep_side));
            }
        }
    }
    Ok(sides)
}

/// Project one unit graph onto the shared [`stow_types::unit_graph::TaskUnit`]
/// model — the same shape `stow-resolver`'s `emit.rs` assigns, so the
/// build stage's dependency-context check resolves onto the same task
/// identities the resolver mints (stow#588).
///
/// `target` is the triple cargo was given (`None` native); `host_triple`
/// is the platform `platform: null` units compile for — the runner
/// family's host triple on the trusted builder. Side and platform
/// mirror `emit.rs`: compile-script units always key host-side at the
/// host triple, run units take their owning lib's side and platform,
/// and a lib reachable only from host-kinded units is host-side while a
/// both-reachable lib is target-side (the shadow-twin dedup shape).
fn unit_graph_task_units(
    graph: &UnitGraph<'_>,
    target: Option<&str>,
    host_triple: &str,
) -> stow_types::error::Result<Vec<stow_types::unit_graph::TaskUnit>> {
    use stow_types::unit_graph::{TaskUnit, TaskUnitDep, TaskUnitKey, TaskUnitKind, TaskUnitSide};
    let sides = unit_sides(graph, target)?;
    // Under the native spelling (`--target` not given) cargo dedups a
    // lib reachable at the same features from host-kinded and
    // target-kinded consumers into ONE unit — but the resolver mints
    // two, a host key and a target key, with `dedup_shadow_edges`
    // pointing host consumers at the target twin. Re-split every
    // both-reachable lib into the twin pair so this projection mints
    // the same identities the resolver did (stow#588). Only the Lib
    // kind splits: build-script compile units are always host, and run
    // units stay interior on the host side either way.
    let native = target.is_none();
    let mut converted: Vec<Vec<TaskUnit>> = Vec::with_capacity(graph.units.len());
    for (index, unit) in graph.units.iter().enumerate() {
        let kind = if unit.mode == "run-custom-build" {
            TaskUnitKind::RunBuildScript
        } else if unit.target.kind == ["custom-build"] {
            TaskUnitKind::BuildScript
        } else if unit.target.kind.iter().any(|kind| LIB_KINDS.contains(kind))
            && COMPILE_MODES.contains(&unit.mode)
        {
            TaskUnitKind::Lib
        } else {
            // Bins, tests, benches, examples and doctest units compile
            // nothing the cache serves — the resolver drops them too.
            converted.push(Vec::new());
            continue;
        };
        if sides[index] == 0 {
            // A unit for a target other than the served one is never a
            // node — `unit_sides` marks it and the expanded entries skip
            // it; the lean model drops it the same way.
            converted.push(Vec::new());
            continue;
        }
        let (name, version, crates_io) = parse_pkg_id(unit.pkg_id);
        let platform = unit.platform.unwrap_or(host_triple).to_owned();
        let emit = |side: TaskUnitSide| TaskUnit {
            key: TaskUnitKey {
                // `pkg_id` is the full cargo package id — source
                // included — exactly what `PackageIdSpec` stringifies.
                pkg: unit.pkg_id.to_owned(),
                platform: platform.clone(),
                side,
                kind,
            },
            name: name.to_owned(),
            version: version.to_owned(),
            features: unit
                .features
                .iter()
                .map(|feature| (*feature).to_owned())
                .collect(),
            is_crates_io: crates_io,
            deps: Vec::new(),
        };
        // A build-script *compile* unit is host-side by construction;
        // a `run-custom-build` unit takes its owning lib's side, which
        // is exactly what its `platform` records under a spelled target
        // and what the host-kinded BFS marks under a native one. A
        // both-reachable lib is the deduped unit a host consumer's
        // shadow edge reaches — under the native spelling it becomes
        // the twin pair the resolver emitted.
        let emitted = if kind == TaskUnitKind::BuildScript || sides[index] == HOST {
            vec![emit(TaskUnitSide::Host)]
        } else if native && kind == TaskUnitKind::Lib && sides[index] & HOST != 0 {
            vec![emit(TaskUnitSide::Host), emit(TaskUnitSide::Target)]
        } else {
            vec![emit(TaskUnitSide::Target)]
        };
        converted.push(emitted);
    }
    let mut units = Vec::with_capacity(converted.iter().map(Vec::len).sum());
    for (index, unit) in graph.units.iter().enumerate() {
        if converted[index].is_empty() {
            continue;
        }
        for base in converted[index].iter().cloned() {
            let mut deps = Vec::with_capacity(unit.dependencies.len());
            for dependency in &unit.dependencies {
                let dep_index = info_at_index(graph, dependency.index)?;
                let dep_unit = &graph.units[dep_index];
                let dep_units = &converted[dep_index];
                // A build-dependency edge lands on the dep's host twin;
                // every other edge lands on the dep unit of the
                // consumer's own side. A dep that emitted exactly one
                // unit serves either edge kind — the reachability BFS
                // already guarantees the side it compiled on.
                let want = if is_build_dep_edge(dependency) {
                    TaskUnitSide::Host
                } else {
                    base.key.side
                };
                let dep_base = dep_units
                    .iter()
                    .find(|dep| dep.key.side == want)
                    .or_else(|| {
                        if dep_units.len() == 1 {
                            dep_units.first()
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| {
                        stow_types::stow_error!(
                            "cargo --unit-graph unit `{}` depends on unit {} — no task unit on the {:?} side",
                            unit.pkg_id,
                            dep_unit.pkg_id,
                            want,
                        )
                    })?;
                let (name, version, _) = parse_pkg_id(dep_unit.pkg_id);
                deps.push(TaskUnitDep {
                    key: dep_base.key.clone(),
                    name: name.to_owned(),
                    version: version.to_owned(),
                    // The dep edge puts a proc-macro in the parent's
                    // `--extern` exactly when the dep unit IS the
                    // proc-macro lib — the flag the shared projection
                    // derives `KeysApart` from (stow#736).
                    proc_macro: dep_unit.target.kind.contains(&"proc-macro"),
                });
            }
            units.push(TaskUnit { deps, ..base });
        }
    }
    Ok(units)
}

fn info_at_index(graph: &UnitGraph<'_>, index: u32) -> stow_types::error::Result<usize> {
    let index = index as usize;
    if index >= graph.units.len() {
        return Err(stow_types::stow_error!(
            "cargo --unit-graph index {index} is out of bounds"
        ));
    }
    Ok(index)
}

/// Each unit's registry lib-dep edges per consumer side — slot 0 host,
/// slot 1 target. A dep lands `HOST` when it is host-kinded or the
/// consumer is host-side, else `TARGET` — under spelled `--target` the
/// dep's own `platform` flag, under native the consumer's side (one
/// shared unit serves both).
fn unit_dep_edges(
    graph: &UnitGraph<'_>,
    infos: &[UnitInfo],
    sides: &[u8],
) -> stow_types::error::Result<Vec<[BTreeSet<ResolvedDependencyGraphDependency>; 2]>> {
    let mut edges = Vec::with_capacity(graph.units.len());
    for (index, unit) in graph.units.iter().enumerate() {
        let mut by_side: [BTreeSet<ResolvedDependencyGraphDependency>; 2] =
            [BTreeSet::new(), BTreeSet::new()];
        for dependency in &unit.dependencies {
            let dep_index = dependency.index as usize;
            let dep = info_at(infos, dependency.index)?;
            if dep.parsed.is_none() {
                continue;
            }
            for consumer_side in [HOST, TARGET] {
                if sides[index] & consumer_side == 0 {
                    continue;
                }
                let dep_side = if host_kinded(&graph.units[dep_index]) || consumer_side == HOST {
                    HOST
                } else {
                    TARGET
                };
                if sides[dep_index] & dep_side == 0 {
                    continue;
                }
                let (crate_name, version) = dep.parsed();
                by_side[usize::from(consumer_side == TARGET)].insert(
                    ResolvedDependencyGraphDependency {
                        crate_name: crate_name.clone(),
                        version: version.clone(),
                        host_side: dep_side == HOST,
                    },
                );
            }
        }
        edges.push(by_side);
    }
    Ok(edges)
}

/// Direct registry externs — the roots' lib deps in the same graph,
/// keyed by node identity `(crate, version, side)`. Two extern names
/// for one crate (a rename in one member's manifest) union into the
/// same node's `extern_names` instead of colliding; a crate that is a
/// direct dependency on both sides lands as two entries with each
/// side's own recorded features — features are never unioned across
/// sides.
fn direct_dependencies(
    graph: &UnitGraph<'_>,
    infos: &[UnitInfo],
    sides: &[u8],
) -> stow_types::error::Result<Vec<SelectedRegistryDependency>> {
    let mut direct =
        BTreeMap::<(String, Version, bool), (BTreeSet<String>, BTreeSet<String>)>::new();
    for &root in &graph.roots {
        let root_index = info_at_index(graph, root)?;
        for dependency in &graph.units[root_index].dependencies {
            let dep_index = info_at_index(graph, dependency.index)?;
            let dep = info_at(infos, dependency.index)?;
            if dep.parsed.is_none() || sides[dep_index] == 0 {
                continue;
            }
            for consumer_side in [HOST, TARGET] {
                if sides[root_index] & consumer_side == 0 {
                    continue;
                }
                let dep_side = if host_kinded(&graph.units[dep_index]) || consumer_side == HOST {
                    HOST
                } else {
                    TARGET
                };
                if sides[dep_index] & dep_side == 0 {
                    continue;
                }
                let entry = direct
                    .entry((
                        dep.name.to_owned(),
                        dep.parsed().1.clone(),
                        dep_side == HOST,
                    ))
                    .or_default();
                entry.0.insert(dependency.extern_crate_name.to_owned());
                entry.1.extend(
                    graph.units[dep_index]
                        .features
                        .iter()
                        .map(|feature| (*feature).to_owned()),
                );
            }
        }
    }
    Ok(direct
        .into_iter()
        .map(
            |((crate_name, version, host_side), (extern_names, features))| {
                SelectedRegistryDependency {
                    extern_names,
                    crate_name,
                    version,
                    features: features.into_iter().collect(),
                    host_side,
                }
            },
        )
        .collect())
}

/// The wire rustc the unit-graph projection fixtures mint under
/// (tests only).
#[cfg(test)]
fn rustc_test() -> &'static stow_types::identity::WireRustcVersion {
    static RUSTC: std::sync::OnceLock<stow_types::identity::WireRustcVersion> =
        std::sync::OnceLock::new();
    RUSTC.get_or_init(|| {
        stow_types::identity::WireRustcVersion::parse("1.91.1").expect("rustc parses")
    })
}

/// The unit graph as `ResolvedDependencyGraphEntry` rows + root direct
/// deps + the local manifests cargo read. `target` is cargo's given
/// target triple; `None` is a native build.
fn emit_expanded_graph(
    graph: &UnitGraph<'_>,
    target: Option<&str>,
    host_triple: &str,
    rustc_version: &stow_types::identity::WireRustcVersion,
) -> stow_types::error::Result<(
    Vec<ResolvedDependencyGraphEntry>,
    Vec<SelectedRegistryDependency>,
    Vec<LocalManifestHash>,
)> {
    let infos = unit_infos(graph)?;
    let sides = unit_sides(graph, target)?;
    let unit_edges = unit_dep_edges(graph, &infos, &sides)?;

    // A package's build-dependencies hang under its build-script
    // compile unit (a host-side unit); merge its edges onto the
    // package's lib node(s).
    let mut extra_edges = BTreeMap::<usize, &BTreeSet<ResolvedDependencyGraphDependency>>::new();
    for (index, unit) in graph.units.iter().enumerate() {
        // A build-script *compile* unit's deps are the package's
        // `[build-dependencies]` lib units.
        if !(unit.target.kind == ["custom-build"] && unit.mode == "build") {
            continue;
        }
        for (lib_index, lib) in infos.iter().enumerate() {
            if lib.parsed.is_some()
                && lib.name == infos[index].name
                && lib.version_str == infos[index].version_str
            {
                extra_edges.insert(lib_index, &unit_edges[index][0]);
            }
        }
    }

    let mut entries = BTreeMap::<(String, Version, bool), ResolvedDependencyGraphEntry>::new();
    for (index, (unit, info)) in graph.units.iter().zip(infos.iter()).enumerate() {
        if info.parsed.is_none() {
            continue;
        }
        // A node unit for a different given target never compiles for
        // the served one — skip it; an eligible unit unreachable from
        // the roots has no side to compile on — surface it.
        if sides[index] == 0 {
            if target.is_none_or(|t| unit.platform == Some(t) || unit.platform.is_none()) {
                return Err(stow_types::stow_error!(
                    "cargo --unit-graph unit {} is unreachable from the roots",
                    unit.pkg_id
                ));
            }
            continue;
        }
        for side in [HOST, TARGET] {
            if sides[index] & side == 0 {
                continue;
            }
            let (crate_name, version) = info.parsed();
            let mut unit_features = unit
                .features
                .iter()
                .map(|feature| (*feature).to_owned())
                .collect::<Vec<_>>();
            unit_features.sort();
            unit_features.dedup();
            let entry = entries
                .entry((info.name.to_owned(), version.clone(), side == HOST))
                .or_insert_with(|| ResolvedDependencyGraphEntry {
                    crate_name: crate_name.clone(),
                    version: version.clone(),
                    features: unit_features.clone(),
                    host_side: side == HOST,
                    dependencies: Vec::new(),
                    dependency_subgraph: stow_types::api::TaskSubgraph::default(),
                    explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
                });
            // One `(crate, version, side)` key is one node, and cargo's
            // resolver assigns it one feature set — a second, different
            // set landing on the same key is a unit-graph shape this
            // projection cannot represent, not something to union away
            // (the builder's `phase_feature_sets` holds the same rule,
            // stow#615).
            if entry.features != unit_features {
                return Err(stow_types::stow_error!(
                    "cargo --unit-graph holds two feature sets for the {} lib unit of {} {}: {:?} and {:?}",
                    if side == HOST { "host" } else { "target" },
                    info.name,
                    version,
                    entry.features,
                    unit_features,
                ));
            }
            entry.dependencies.extend(
                unit_edges[index][usize::from(side == TARGET)]
                    .iter()
                    .cloned(),
            );
            entry.dependencies.extend(
                extra_edges
                    .get(&index)
                    .into_iter()
                    .flat_map(|set| set.iter().cloned()),
            );
        }
    }
    for entry in entries.values_mut() {
        entry.features.sort();
        entry.features.dedup();
        entry.dependencies.sort();
        entry.dependencies.dedup();
    }
    // Each entry's dependency subgraph comes from the resolved task
    // graph over this same unit graph — a covered dep still has its
    // own real context there, so nothing is minted leaf-shaped
    // (stow#588). The node's explicit-spelling flag is derived on the
    // same pass — the shared projection computes it bottom-up from the
    // dep edges' proc-macro flags (stow#736).
    let task_units = unit_graph_task_units(graph, target, host_triple)?;
    let resolved = stow_types::unit_graph::resolved_task_graph(&task_units, rustc_version)?;
    for entry in entries.values_mut() {
        let (subgraph, spelling) = node_subgraph(&resolved, entry)?;
        entry.dependency_subgraph = subgraph;
        entry.explicit_spelling = spelling;
    }
    Ok((
        entries.into_values().collect(),
        direct_dependencies(graph, &infos, &sides)?,
        local_manifest_hashes(graph)?,
    ))
}

/// The wire subgraph for one expanded-graph entry: the entry's own
/// node inside the resolved task graph, located by its identity
/// `(name, version, feature set, side)` — exact package identity, not
/// a name association (stow#588). Two resolved nodes sharing the
/// entry's `(name, version, side)` but differing in features cannot
/// both back one merged entry, so any ambiguity or absence is an
/// error, never a guess.
fn node_subgraph(
    resolved: &stow_types::task_graph::ResolvedTaskGraph,
    entry: &ResolvedDependencyGraphEntry,
) -> stow_types::error::Result<(
    stow_types::api::TaskSubgraph,
    stow_types::public_cache::ExplicitSpelling,
)> {
    let mut matched = resolved.nodes().iter().enumerate().filter(|(_, node)| {
        node.identity.crate_name.as_str() == entry.crate_name.as_str()
            && node.identity.version.as_semver() == &entry.version
            && node.identity.host_side == entry.host_side
            && node.identity.features_json.features() == entry.features.as_slice()
    });
    let Some((index, node)) = matched.next() else {
        return Err(stow_types::stow_error!(
            "cargo --unit-graph has no task node for {} {} (host_side={}) at features {:?} — cannot mint its dependency subgraph",
            entry.crate_name,
            entry.version,
            entry.host_side,
            entry.features,
        ));
    };
    let spelling = node.explicit_spelling;
    let subgraph = stow_types::api::TaskSubgraph::from_resolved(resolved, index)
        .map_err(|e| stow_types::stow_error!("{e}"))?;
    Ok((subgraph, spelling))
}

/// Every local package manifest cargo read for this answer —
/// `path+file://` pkg ids (path deps anywhere on disk, not only
/// workspace members), hashed at resolve time for the persisted
/// graph's load-side verification.
fn local_manifest_hashes(
    graph: &UnitGraph<'_>,
) -> stow_types::error::Result<Vec<LocalManifestHash>> {
    let mut paths = BTreeSet::<PathBuf>::new();
    for unit in &graph.units {
        if !unit.pkg_id.starts_with("path+") {
            continue;
        }
        paths.insert(path_pkg_root(unit.pkg_id)?.join("Cargo.toml"));
    }
    paths
        .into_iter()
        .map(|path| {
            let bytes = std::fs::read(&path).wrap_err_with(|| {
                format!("read local manifest {} from unit graph", path.display())
            })?;
            Ok(LocalManifestHash {
                path,
                blake3: blake3::hash(&bytes).to_hex().to_string(),
            })
        })
        .collect()
}

/// The local root a `path+file://` pkg id points at: the pkgid is a
/// URL, so `Url::to_file_path` converts it the way the host OS reads
/// it — Windows drive letters and percent escapes. String surgery on
/// the URL leaves a leading `/` (an unreadable path on Windows) and
/// keeps the escapes.
fn path_pkg_root(pkg_id: &str) -> stow_types::error::Result<PathBuf> {
    let not_file =
        || stow_types::stow_error!("cargo --unit-graph pkg_id `{pkg_id}` is not a path+file url");
    let url = url::Url::parse(pkg_id.strip_prefix("path+").ok_or_else(not_file)?)
        .map_err(|e| stow_types::stow_error!("cargo --unit-graph pkg_id `{pkg_id}`: {e}"))?;
    if url.scheme() != "file" {
        return Err(not_file());
    }
    url.to_file_path().map_err(|()| not_file())
}

/// The graph one build's compile observations mint misses from
/// (stow#317).
///
/// Every locally-compiled unit is a miss by definition and becomes a
/// node keyed `(crate, version, host_side)`, where `host_side` marks a
/// compile for the build's probed host — the host triple cargo never
/// passes `--target` for — rather than the consumer's target. The node
/// is still minted at the family host triple downstream; `build_host`
/// exists only to tell a host compile from a target one (stow#317).
/// A unit's `dependencies` are its invocation's `--extern` deps
/// named at each dep's own recorded identity; a dep the build served
/// rather than compiled joins as a leaf node at the unit graph node's
/// feature set so every edge resolves to a node. A unit whose externs
/// do not all resolve to a recorded identity is not minted — a miss
/// whose deps cannot be named is a miss stow does not post.
pub struct ObservedMissGraph {
    /// The misses to enqueue: the observed (compiled-locally) units.
    pub roots: Vec<stow_types::api::DependencyGraphEntry>,
    /// The expanded graph their `depends_on` edges resolve against.
    pub expanded: Vec<ResolvedDependencyGraphEntry>,
}

/// One pass over the build's unit graph: `(name, version, side)` → the
/// node's cargo-resolved feature set — the answer every extern lookup and
/// leaf mint in [`observed_miss_graph`] shares. The graph holds one set
/// per key for one build (the `emit_expanded_graph` rule); a second,
/// different set is a shape this projection cannot represent — an error
/// naming both, never a pick (stow#615).
fn node_feature_index(
    resolved: &stow_types::task_graph::ResolvedTaskGraph,
) -> stow_types::error::Result<NodeFeatureIndex<'_>> {
    let mut node_features = NodeFeatureIndex::new();
    for node in resolved.nodes() {
        let key = (
            node.identity.crate_name.as_str(),
            node.identity.version.as_semver(),
            node.identity.host_side,
        );
        match node_features.entry(key) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(node.identity.features_json.features());
            }
            std::collections::btree_map::Entry::Occupied(slot)
                if *slot.get() == node.identity.features_json.features() => {}
            std::collections::btree_map::Entry::Occupied(slot) => {
                return Err(stow_types::stow_error!(
                    "the build's unit graph holds two feature sets for the {} node of {} {}: {:?} and {:?}",
                    if node.identity.host_side {
                        "host"
                    } else {
                        "target"
                    },
                    node.identity.crate_name,
                    node.identity.version,
                    slot.get(),
                    node.identity.features_json.features(),
                ));
            }
        }
    }
    Ok(node_features)
}

/// Build the miss graph from the build's compile observations and the
/// dependency identities recorded in the artifact cache. `resolved` is
/// the shared projection of the build's own `cargo --unit-graph` —
/// every minted entry's dependency subgraph comes out of it, so an
/// entry whose node the unit graph does not hold fails the call rather
/// than carrying a synthesized context (stow#588).
pub fn observed_miss_graph(
    observations: &[crate::artifact_cache::ObservedUnit],
    dep_identities: &BTreeMap<String, crate::artifact_cache::ObservedDepIdentity>,
    consumer_spelled_target: bool,
    resolved: &stow_types::task_graph::ResolvedTaskGraph,
) -> stow_types::error::Result<ObservedMissGraph> {
    let node_features = node_feature_index(resolved)?;

    let mut entries = BTreeMap::<(String, String, bool), ResolvedDependencyGraphEntry>::new();
    let mut roots = Vec::new();
    // `(dep key, side, features)` triples an observed edge needs a node
    // for — synthesized after the observed units so an observed node
    // always wins over a leaf.
    let mut referenced = BTreeSet::<DepNodeRef>::new();

    for observation in observations {
        let (Ok(crate_name), Ok(version)) = (
            stow_types::identity::CrateName::parse(&observation.crate_name),
            Version::parse(&observation.crate_version),
        ) else {
            tracing::warn!(
                crate_name = %observation.crate_name,
                crate_version = %observation.crate_version,
                "observed unit's identity does not parse; not minting it as a miss"
            );
            continue;
        };
        // The unit's node is the build's own unit graph's answer: the
        // node's side and the feature set cargo resolved it at. The
        // observation's `features` — the argv `--cfg feature="…"` scan —
        // is evidence for the resolution, never the node's set: a build
        // script's `cargo:rustc-cfg=feature="…"` lines ride it (stow#615).
        let Some(node) = resolve_observed_unit(observation, consumer_spelled_target, resolved)
        else {
            continue;
        };
        let features = node.features.to_vec();
        let host_side = node.host_side;
        let Some((mut dependencies, dep_nodes)) =
            observed_dep_edges(observation, dep_identities, host_side, &node_features)
        else {
            continue;
        };
        // A skipped unit's deps must not mint orphan leaf nodes —
        // record the keys only once the unit's edges all resolved.
        referenced.extend(dep_nodes);
        dependencies.sort();
        dependencies.dedup();
        let key = (
            observation.crate_name.clone(),
            observation.crate_version.clone(),
            host_side,
        );
        roots.push(stow_types::api::DependencyGraphEntry {
            crate_name: crate_name.clone(),
            version: version.clone(),
            features: features.clone(),
        });
        entries.insert(
            key,
            ResolvedDependencyGraphEntry {
                crate_name,
                version,
                features,
                host_side,
                dependencies,
                dependency_subgraph: stow_types::api::TaskSubgraph::default(),
                explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
            },
        );
    }

    roots.sort();
    roots.dedup();

    for (name, version, side, features) in referenced {
        entries
            .entry((name.clone(), version.clone(), side))
            .or_insert_with(|| {
                // A served dep's leaf carries the graph node's feature
                // set — it rode along on the edge's node ref (stow#615).
                ResolvedDependencyGraphEntry {
                    crate_name: stow_types::identity::CrateName::parse(&name)
                        .expect("referenced dep name parses"),
                    version: Version::parse(&version).expect("referenced dep version parses"),
                    features,
                    host_side: side,
                    dependencies: Vec::new(),
                    dependency_subgraph: stow_types::api::TaskSubgraph::default(),
                    explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
                }
            });
    }

    for entry in entries.values_mut() {
        let (subgraph, spelling) = node_subgraph(resolved, entry)?;
        entry.dependency_subgraph = subgraph;
        entry.explicit_spelling = spelling;
    }

    Ok(ObservedMissGraph {
        roots,
        expanded: entries.into_values().collect(),
    })
}

/// The graph node one observed unit compiled as — `None` when the
/// build's unit graph does not carry it, skipped with a warning like an
/// unresolvable extern (stow#615).
fn resolve_observed_unit<'r>(
    observation: &crate::artifact_cache::ObservedUnit,
    consumer_spelled_target: bool,
    resolved: &'r stow_types::task_graph::ResolvedTaskGraph,
) -> Option<crate::unit_node::NodeCoordinates<'r>> {
    let feature_scan = observation
        .features
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    match crate::unit_node::resolve_unit_node(
        resolved
            .nodes()
            .iter()
            .map(crate::unit_node::NodeCoordinates::from),
        consumer_spelled_target,
        &crate::unit_node::UnitEvidence {
            crate_name: observation.crate_name.as_str(),
            version: observation.crate_version.as_str(),
            spelled_target: observation.explicit_target.is_some(),
            feature_scan: &feature_scan,
            build_override: observation.build_override,
        },
    ) {
        Ok(node) => Some(node),
        Err(error) => {
            tracing::warn!(
                error = %error,
                crate_name = %observation.crate_name,
                crate_version = %observation.crate_version,
                "observed unit does not resolve against the build's unit graph; not minting it as a miss"
            );
            None
        }
    }
}

/// A referenced dep's leaf slot: the `(name, version, host_side)` key
/// it mints under and the feature set the graph node carries (stow#615).
type DepNodeRef = (String, String, bool, Vec<String>);

/// `(crate name, version, host_side)` → the node's cargo-resolved
/// feature set, borrowed from the build's unit graph (stow#615).
type NodeFeatureIndex<'r> = BTreeMap<(&'r str, &'r Version, bool), &'r [String]>;

/// Resolve one observed unit's `--extern` deps into graph edges at each
/// dep's own recorded identity, returning the (name, version, side)
/// node refs — each carrying the graph node's feature set — alongside
/// the edges. `None` — and the unit is not minted — when any extern has
/// no recorded identity or names no node of the build's unit graph: a
/// miss whose deps cannot be named is a miss stow does not post.
fn observed_dep_edges(
    observation: &crate::artifact_cache::ObservedUnit,
    dep_identities: &BTreeMap<String, crate::artifact_cache::ObservedDepIdentity>,
    observation_host_side: bool,
    node_features: &NodeFeatureIndex<'_>,
) -> Option<(Vec<ResolvedDependencyGraphDependency>, Vec<DepNodeRef>)> {
    let mut dependencies = Vec::new();
    let mut dep_nodes = Vec::new();
    for extern_dep in &observation.externs {
        let dep = dep_identities.get(&extern_dep.c_metadata).and_then(|dep| {
            Some((
                stow_types::identity::CrateName::parse(&dep.crate_name).ok()?,
                Version::parse(&dep.crate_version).ok()?,
                dep.unit_shape,
                dep.proc_macro,
            ))
        });
        let Some((dep_name, dep_version, dep_shape, dep_proc_macro)) = dep else {
            tracing::warn!(
                crate_name = %observation.crate_name,
                c_metadata = %extern_dep.c_metadata,
                "observed unit's --extern dep has no recorded identity; not minting it as a miss"
            );
            return None;
        };
        // The dep's published shape says which side its node serves.
        // Without one — a dep no published row names — the edge's own
        // semantics decide: every extern of a host unit is host-side,
        // and a target unit's only host extern is a proc-macro.
        let dep_side = dep_shape.map_or(observation_host_side || dep_proc_macro, |shape| {
            shape.side == UnitSide::Host
        });
        // The dep node a leaf mints under is the build's own graph's —
        // its feature set comes from that node, not the artifact row's
        // recorded label, and travels with the node ref (stow#615). A
        // dep the graph does not carry is treated like an extern with
        // no recorded identity.
        let Some(dep_features) = node_features
            .get(&(dep_name.as_str(), &dep_version, dep_side))
            .copied()
        else {
            tracing::warn!(
                crate_name = %observation.crate_name,
                dep_name = %dep_name,
                dep_version = %dep_version,
                dep_side,
                "observed unit's --extern dep names no node in the build's unit graph; not minting it as a miss"
            );
            return None;
        };
        dep_nodes.push((
            dep_name.as_str().to_owned(),
            dep_version.to_string(),
            dep_side,
            dep_features.to_vec(),
        ));
        dependencies.push(ResolvedDependencyGraphDependency {
            crate_name: dep_name,
            version: dep_version,
            host_side: dep_side,
        });
    }
    Some((dependencies, dep_nodes))
}

fn find_nearest_manifest(current_dir: &Path) -> stow_types::error::Result<PathBuf> {
    for ancestor in current_dir.ancestors() {
        let manifest_path = ancestor.join("Cargo.toml");
        if manifest_path.exists() {
            return Ok(canonicalize_or_original(&manifest_path));
        }
    }
    Err(stow_types::stow_error!(
        "could not find Cargo.toml by searching upward from {}",
        current_dir.display()
    ))
}

fn find_workspace_root(selected_manifest: &Path) -> stow_types::error::Result<Option<PathBuf>> {
    let Some(selected_dir) = selected_manifest.parent() else {
        return Err(stow_types::stow_error!(
            "manifest path {} has no parent directory",
            selected_manifest.display()
        ));
    };
    let selected_manifest = canonicalize_or_original(selected_manifest);
    for ancestor in selected_dir.ancestors() {
        let manifest_path = ancestor.join("Cargo.toml");
        if !manifest_path.exists() {
            continue;
        }
        let manifest = load_manifest(&manifest_path)?;
        if manifest.workspace.is_none() {
            continue;
        }
        if manifest_in_workspace(ancestor, &manifest, &selected_manifest)? {
            return Ok(Some(ancestor.to_path_buf()));
        }
    }
    Ok(None)
}

fn manifest_in_workspace(
    workspace_root: &Path,
    workspace_manifest: &Manifest,
    selected_manifest: &Path,
) -> stow_types::error::Result<bool> {
    let workspace_manifest_path = canonicalize_or_original(&workspace_root.join("Cargo.toml"));
    if workspace_manifest_path == selected_manifest {
        return Ok(true);
    }
    Ok(expand_workspace_members(workspace_root, workspace_manifest)?.contains(selected_manifest))
}

/// Reverse the expanded graph's dependency edges: for every entry,
/// the registry packages that depend on it. This is the unit-graph
/// substitute for the lockfile's `parents_by_package` — ranking reads
/// whether a dep still has parents among the compiled set (stow#551).
pub fn parents_by_package(
    entries: &[ResolvedDependencyGraphEntry],
) -> BTreeMap<PackageKey, Vec<PackageKey>> {
    let mut parents: BTreeMap<PackageKey, Vec<PackageKey>> = BTreeMap::new();
    for entry in entries {
        for dependency in &entry.dependencies {
            parents
                .entry(PackageKey {
                    crate_name: dependency.crate_name.to_string(),
                    version: dependency.version.clone(),
                    source: Some(CRATES_IO_SOURCE.to_owned()),
                })
                .or_default()
                .push(PackageKey {
                    crate_name: entry.crate_name.to_string(),
                    version: entry.version.clone(),
                    source: Some(CRATES_IO_SOURCE.to_owned()),
                });
        }
    }
    for parents in parents.values_mut() {
        parents.sort();
        parents.dedup();
    }
    parents
}

/// The manifests of every workspace member, following cargo's rules: the
/// root package when the root manifest has one, every `[workspace].members`
/// glob match, and every path dependency of a member that lives under the
/// workspace root — minus `[workspace].exclude`. A `[workspace]` table with
/// no `members` key is a single-package workspace, not an error.
pub fn expand_workspace_members(
    workspace_root: &Path,
    workspace_manifest: &Manifest,
) -> stow_types::error::Result<BTreeSet<PathBuf>> {
    let root_manifest = canonicalize_or_original(&workspace_root.join("Cargo.toml"));
    let Some(workspace) = workspace_manifest.workspace.as_ref() else {
        return Ok(BTreeSet::from([root_manifest]));
    };
    let excluded = workspace
        .exclude
        .iter()
        .flatten()
        .map(|dir| canonicalize_or_original(&workspace_root.join(dir)))
        .collect::<BTreeSet<_>>();
    let is_excluded = |manifest: &Path| {
        manifest
            .parent()
            .is_some_and(|dir| excluded.iter().any(|excluded| dir.starts_with(excluded)))
    };

    let mut pending = VecDeque::<PathBuf>::new();
    if workspace_manifest.package.is_some() {
        pending.push_back(root_manifest);
    }
    for member in workspace.members.iter().flatten() {
        let pattern = workspace_root.join(member).join("Cargo.toml");
        let pattern = pattern.to_str().ok_or_else(|| {
            stow_types::stow_error!(
                "workspace member pattern {} is not UTF-8",
                pattern.display()
            )
        })?;
        let mut matched = false;
        for entry in glob(pattern)
            .wrap_err_with(|| format!("expand workspace member pattern `{pattern}`"))?
        {
            let path =
                entry.wrap_err_with(|| format!("expand workspace member pattern `{pattern}`"))?;
            matched = true;
            pending.push_back(canonicalize_or_original(&path));
        }
        if !matched {
            return Err(stow_types::stow_error!(
                "workspace member pattern `{member}` matched no Cargo.toml files"
            ));
        }
    }

    // Path dependencies under the workspace root are members too, and their
    // own path dependencies in turn, so walk to a fixpoint.
    let workspace_root = canonicalize_or_original(workspace_root);
    let mut members = BTreeSet::<PathBuf>::new();
    while let Some(manifest_path) = pending.pop_front() {
        if is_excluded(&manifest_path) || !members.insert(manifest_path.clone()) {
            continue;
        }
        let manifest = load_manifest(&manifest_path)?;
        let member_dir = manifest_path.parent().ok_or_else(|| {
            stow_types::stow_error!(
                "workspace member manifest {} has no parent directory",
                manifest_path.display()
            )
        })?;
        for path in manifest.path_dependencies() {
            let dependency_manifest =
                canonicalize_or_original(&member_dir.join(path).join("Cargo.toml"));
            if dependency_manifest.starts_with(&workspace_root) {
                pending.push_back(dependency_manifest);
            }
        }
    }
    Ok(members)
}

/// Returns the names of optional dependencies that the manifest's feature
/// graph activates under the given metadata args (default features unless
/// `--no-default-features` is set, plus any explicit `--features`).
///
/// This mirrors what cargo's resolver does when populating `Cargo.lock`:
/// optional deps gated by an inactive feature get no lockfile pin; ones
/// transitively enabled by `default` (e.g., bat's `default → application
/// → bugreport`) DO get pinned. The CLI's user-direct collection uses
/// this to only ship enabled-optional deps to the resolver — sending
/// every declared optional would block seed search on perfectly-cached
/// projects whose preheat closure intentionally skipped feature-disabled
/// optionals.
pub fn enabled_optional_dependency_names(
    manifest_path: &Path,
    args: &crate::cargo_cmd::MetadataArgs,
) -> stow_types::error::Result<BTreeSet<String>> {
    let manifest = load_manifest(manifest_path)?;
    let package_name = manifest
        .package
        .as_ref()
        .map(|package| package.name.clone())
        .unwrap_or_default();
    Ok(enabled_optional_deps(&manifest, &package_name, args))
}

pub fn load_manifest(path: &Path) -> stow_types::error::Result<Manifest> {
    let contents = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("read Cargo.toml {}", path.display()))?;
    toml::from_str::<Manifest>(&contents)
        .wrap_err_with(|| format!("parse Cargo.toml {}", path.display()))
}

/// Canonical form for path comparisons: the deepest existing ancestor
/// resolves symlinks (macOS `/var -> /private/var`, Windows short
/// names) and any components below it rejoin verbatim, so a path that
/// does not exist yet still lands in the same canonical form as the
/// root it sits under. Every side of a `strip_prefix`/`starts_with`
/// must go through the same conversion — resolving one side but not
/// the other leaves a symlinked spelling that never matches.
pub fn canonicalize_or_original(path: &Path) -> PathBuf {
    for ancestor in path.ancestors() {
        if let Ok(mut resolved) = std::fs::canonicalize(ancestor) {
            resolved.extend(
                path.strip_prefix(ancestor)
                    .expect("Path::ancestors yields only prefixes"),
            );
            return resolved;
        }
    }
    path.to_path_buf()
}

/// The optional dependencies a manifest's feature graph activates under
/// `args` — default features unless `--no-default-features`, plus any
/// spelled `--features` for this package.
fn enabled_optional_deps(
    manifest: &Manifest,
    package_name: &str,
    args: &MetadataArgs,
) -> BTreeSet<String> {
    let feature_map = manifest.features.clone().unwrap_or_default();
    let dependency_names = manifest
        .dependencies
        .iter()
        .chain(manifest.build_dependencies.iter())
        .chain(manifest.dev_dependencies.iter())
        .flat_map(|deps| deps.keys().cloned())
        .collect::<BTreeSet<_>>();
    let mut activated_features = BTreeSet::<String>::new();
    let mut queue = VecDeque::<String>::new();
    let mut enabled_optional_deps = BTreeSet::<String>::new();

    if args.all_features {
        for feature in feature_map.keys() {
            if activated_features.insert(feature.clone()) {
                queue.push_back(feature.clone());
            }
        }
    } else {
        if !args.no_default_features
            && let Some(default_items) = feature_map.get("default")
        {
            for item in default_items {
                apply_feature_item(
                    item,
                    &feature_map,
                    &dependency_names,
                    &mut activated_features,
                    &mut queue,
                    &mut enabled_optional_deps,
                );
            }
        }
        for raw_feature in args.features.iter().map(String::as_str) {
            if let Some((feature_package, feature_name)) = raw_feature.split_once('/') {
                if feature_package != package_name {
                    continue;
                }
                let feature_name = feature_name.to_owned();
                if activated_features.insert(feature_name.clone()) {
                    queue.push_back(feature_name);
                }
                continue;
            }
            let raw_feature = raw_feature.to_owned();
            if activated_features.insert(raw_feature.clone()) {
                queue.push_back(raw_feature);
            }
        }
    }

    while let Some(feature) = queue.pop_front() {
        let Some(items) = feature_map.get(&feature) else {
            if dependency_names.contains(&feature) {
                enabled_optional_deps.insert(feature);
            }
            continue;
        };
        for item in items {
            apply_feature_item(
                item,
                &feature_map,
                &dependency_names,
                &mut activated_features,
                &mut queue,
                &mut enabled_optional_deps,
            );
        }
    }

    enabled_optional_deps
}

fn apply_feature_item(
    item: &str,
    feature_map: &BTreeMap<String, Vec<String>>,
    dependency_names: &BTreeSet<String>,
    activated_features: &mut BTreeSet<String>,
    queue: &mut VecDeque<String>,
    enabled_optional_deps: &mut BTreeSet<String>,
) {
    if let Some(dep_name) = item.strip_prefix("dep:") {
        enabled_optional_deps.insert(dep_name.to_owned());
        return;
    }
    if let Some((dependency_name, _)) = item.split_once('/') {
        let conditional = dependency_name.ends_with('?');
        let dependency_name = dependency_name.trim_end_matches('?');
        if conditional && !enabled_optional_deps.contains(dependency_name) {
            return;
        }
        enabled_optional_deps.insert(dependency_name.to_owned());
        return;
    }
    if feature_map.contains_key(item) {
        if activated_features.insert(item.to_owned()) {
            queue.push_back(item.to_owned());
        }
        return;
    }
    if dependency_names.contains(item) {
        enabled_optional_deps.insert(item.to_owned());
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    package: Option<PackageSection>,
    workspace: Option<WorkspaceSection>,
    features: Option<BTreeMap<String, Vec<String>>>,
    dependencies: Option<BTreeMap<String, toml::Value>>,
    #[serde(rename = "build-dependencies")]
    build_dependencies: Option<BTreeMap<String, toml::Value>>,
    #[serde(rename = "dev-dependencies")]
    dev_dependencies: Option<BTreeMap<String, toml::Value>>,
}

#[derive(Debug, Clone, Deserialize)]
struct PackageSection {
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct WorkspaceSection {
    members: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
}

impl Manifest {
    /// The `path` of every path dependency in this manifest's normal, build
    /// and dev dependency tables, relative to the manifest's directory.
    fn path_dependencies(&self) -> impl Iterator<Item = &str> {
        [
            self.dependencies.as_ref(),
            self.build_dependencies.as_ref(),
            self.dev_dependencies.as_ref(),
        ]
        .into_iter()
        .flatten()
        .flat_map(BTreeMap::values)
        .filter_map(|spec| spec.get("path").and_then(toml::Value::as_str))
    }
}

#[cfg(test)]
mod workspace_member_tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use super::{Manifest, expand_workspace_members};

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("manifest parent")).expect("create dir");
        std::fs::write(path, contents).expect("write manifest");
    }

    fn members(root: &Path) -> BTreeSet<PathBuf> {
        let manifest = toml::from_str::<Manifest>(
            &std::fs::read_to_string(root.join("Cargo.toml")).expect("read root manifest"),
        )
        .expect("parse root manifest");
        expand_workspace_members(root, &manifest)
            .expect("expand members")
            .into_iter()
            .map(|path| {
                path.strip_prefix(std::fs::canonicalize(root).expect("canonical root"))
                    .expect("member under root")
                    .to_path_buf()
            })
            .collect()
    }

    fn paths(parts: &[&str]) -> BTreeSet<PathBuf> {
        parts.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn a_workspace_table_without_members_is_the_root_package_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(
            dir.path(),
            "Cargo.toml",
            "[workspace]\nresolver = \"2\"\n\n[package]\nname = \"solo\"\nversion = \"0.1.0\"\n",
        );
        assert_eq!(members(dir.path()), paths(&["Cargo.toml"]));
    }

    #[test]
    fn the_root_package_joins_its_listed_members() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(
            dir.path(),
            "Cargo.toml",
            "[workspace]\nmembers = [\"tools/*\"]\n\n[package]\nname = \"root\"\nversion = \"0.1.0\"\n",
        );
        write(
            dir.path(),
            "tools/a/Cargo.toml",
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
        );
        assert_eq!(
            members(dir.path()),
            paths(&["Cargo.toml", "tools/a/Cargo.toml"])
        );
    }

    #[test]
    fn path_dependencies_under_the_root_are_members_and_excludes_are_not() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(
            dir.path(),
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\"]\nexclude = [\"vendored\"]\n",
        );
        write(
            dir.path(),
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nderive = { path = \"../derive\" }\nvendored = { path = \"../vendored\" }\n",
        );
        write(
            dir.path(),
            "derive/Cargo.toml",
            "[package]\nname = \"derive\"\nversion = \"0.1.0\"\n\n[build-dependencies]\nhelper = { path = \"../helper\" }\n",
        );
        write(
            dir.path(),
            "helper/Cargo.toml",
            "[package]\nname = \"helper\"\nversion = \"0.1.0\"\n",
        );
        write(
            dir.path(),
            "vendored/Cargo.toml",
            "[package]\nname = \"vendored\"\nversion = \"0.1.0\"\n",
        );
        assert_eq!(
            members(dir.path()),
            paths(&["app/Cargo.toml", "derive/Cargo.toml", "helper/Cargo.toml"])
        );
    }
}

#[cfg(test)]
mod lockfile_package_tests {
    use std::collections::BTreeSet;

    use super::lockfile_registry_packages;

    /// Registry pins alone come back: path and workspace-member entries
    /// carry no source, git entries carry a `git+` source, and neither
    /// is a unit this build compiles from a registry (stow#617).
    #[test]
    fn only_registry_packages_are_returned() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("Cargo.lock"),
            "version = 4\n\n\
             [[package]]\nname = \"probe\"\nversion = \"0.1.0\"\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.0\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n\
             [[package]]\nname = \"serde\"\nversion = \"1.0.228\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n\
             [[package]]\nname = \"helper\"\nversion = \"0.2.0\"\n\
             source = \"git+https://github.com/water-rs/helper?rev=9f8e7d6c#9f8e7d6c5b4a32109f8e7d6c5b4a32109f8e7d6c\"\n\n\
             [[package]]\nname = \"sibling\"\nversion = \"0.3.0\"\n",
        )
        .expect("write lockfile");
        let packages = lockfile_registry_packages(dir.path())
            .expect("parse")
            .expect("lockfile present");
        assert_eq!(
            packages,
            BTreeSet::from([
                ("cfg-if".to_owned(), semver::Version::new(1, 0, 0)),
                ("serde".to_owned(), semver::Version::new(1, 0, 228)),
            ])
        );
    }

    /// A lockfile cargo has not written yet is a defined state, not an
    /// error (stow#608).
    #[test]
    fn a_missing_lockfile_is_none_not_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            lockfile_registry_packages(dir.path()).expect("an absent lockfile is not an error"),
            None
        );
    }
}

#[cfg(test)]
mod observed_miss_tests {
    use std::collections::BTreeMap;

    use super::{ObservedMissGraph, observed_miss_graph};
    use crate::artifact_cache::{DependencyCMetadataIdentity, ObservedDepIdentity, ObservedUnit};

    const HOST: &str = "x86_64-unknown-linux-gnu";

    fn observation(
        crate_name: &str,
        version: &str,
        target: &str,
        features: &[&str],
        externs: &[(&str, &str)],
    ) -> ObservedUnit {
        // `observed_miss_graph` reads the recorded compile triple, not
        // the flag; tests that exercise the drain set it themselves.
        ObservedUnit {
            crate_name: crate_name.to_owned(),
            crate_version: version.to_owned(),
            features: features
                .iter()
                .map(|feature| (*feature).to_owned())
                .collect(),
            target: target.to_owned(),
            explicit_target: None,
            build_override: false,
            externs: externs
                .iter()
                .map(|(name, c_metadata)| DependencyCMetadataIdentity {
                    crate_name: (*name).to_owned(),
                    c_metadata: (*c_metadata).to_owned(),
                })
                .collect(),
        }
    }

    /// `(c_metadata, name, version, features, published_host_side,
    /// proc_macro)` — the published side is the dep row's recorded
    /// `unit_shape` (`None` for a dep the published slices do not name),
    /// `proc_macro` the artifact's recorded kind.
    type DepIdentityFixture<'a> = (&'a str, &'a str, &'a str, &'a [&'a str], Option<bool>, bool);

    fn task_node(
        crate_name: &str,
        version: &str,
        features: &[&str],
        host_side: bool,
    ) -> stow_types::task_graph::ResolvedTaskNode {
        use stow_types::identity::{
            CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion,
        };
        use stow_types::task_graph::TaskNodeIdentity;
        stow_types::task_graph::ResolvedTaskNode {
            identity: TaskNodeIdentity {
                crate_name: CrateName::parse(crate_name).expect("crate name parses"),
                version: CrateVersion::new(
                    semver::Version::parse(version).expect("version parses"),
                ),
                features_json: FeaturesJson::canonicalize(
                    features
                        .iter()
                        .map(|feature| (*feature).to_owned())
                        .collect(),
                )
                .expect("features canonicalize"),
                target: TargetTriple::parse("x86_64-unknown-linux-gnu").expect("target parses"),
                rustc_version: WireRustcVersion::parse("1.91.1").expect("rustc parses"),
                host_side,
            },
            explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
            dependencies: Vec::new(),
        }
    }

    fn resolved_graph(
        nodes: Vec<stow_types::task_graph::ResolvedTaskNode>,
    ) -> stow_types::task_graph::ResolvedTaskGraph {
        stow_types::task_graph::ResolvedTaskGraph::resolve(nodes).expect("fixture resolves")
    }

    /// A resolved task graph covering every node an observed miss
    /// graph could mint from these inputs — one leaf node per
    /// `(name, version, features, side)` an observation or dep identity
    /// names, on both sides for dep rows whose side the edge decides
    /// downstream (stow#588).
    fn resolved_fixture(
        observations: &[crate::artifact_cache::ObservedUnit],
        deps: &BTreeMap<String, ObservedDepIdentity>,
        consumer_spelled_target: bool,
    ) -> stow_types::task_graph::ResolvedTaskGraph {
        let mut nodes = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for observation in observations {
            let host_side = observation.explicit_target.is_none()
                && (consumer_spelled_target || observation.build_override);
            let mut features: Vec<&str> = observation.features.iter().map(String::as_str).collect();
            features.sort_unstable();
            features.dedup();
            if seen.insert((
                observation.crate_name.clone(),
                observation.crate_version.clone(),
                features.clone(),
                host_side,
            )) {
                nodes.push(task_node(
                    &observation.crate_name,
                    &observation.crate_version,
                    &features,
                    host_side,
                ));
            }
        }
        for dep in deps.values() {
            for side in [false, true] {
                let mut features: Vec<&str> = dep.features.iter().map(String::as_str).collect();
                features.sort_unstable();
                features.dedup();
                if seen.insert((
                    dep.crate_name.clone(),
                    dep.crate_version.clone(),
                    features.clone(),
                    side,
                )) {
                    nodes.push(task_node(
                        &dep.crate_name,
                        &dep.crate_version,
                        &features,
                        side,
                    ));
                }
            }
        }
        resolved_graph(nodes)
    }

    fn dep_identities(deps: &[DepIdentityFixture<'_>]) -> BTreeMap<String, ObservedDepIdentity> {
        deps.iter()
            .map(
                |(c_metadata, name, version, features, host_side, proc_macro)| {
                    (
                        (*c_metadata).to_owned(),
                        ObservedDepIdentity {
                            crate_name: (*name).to_owned(),
                            crate_version: (*version).to_owned(),
                            features: features
                                .iter()
                                .map(|feature| (*feature).to_owned())
                                .collect(),
                            unit_shape: host_side.map(|side| stow_types::public_cache::UnitShape {
                                side: if side {
                                    stow_types::public_cache::UnitSide::Host
                                } else {
                                    stow_types::public_cache::UnitSide::Target
                                },
                                invocation: stow_types::public_cache::UnitInvocation::Native,
                                kind: stow_types::public_cache::UnitKind::Linked,
                            }),
                            proc_macro: *proc_macro,
                        },
                    )
                },
            )
            .collect()
    }

    fn node<'a>(
        graph: &'a ObservedMissGraph,
        crate_name: &str,
        host_side: bool,
    ) -> &'a stow_types::api::ResolvedDependencyGraphEntry {
        graph
            .expanded
            .iter()
            .find(|entry| entry.crate_name.as_str() == crate_name && entry.host_side == host_side)
            .unwrap_or_else(|| panic!("node {crate_name} host_side={host_side} exists"))
    }

    /// A native build: the consumer's target IS the family host triple,
    /// so every observed unit is target-side, and each `depends_on` names
    /// the dep's own recorded identity.
    #[test]
    fn native_build_mints_target_side_nodes_with_dep_edges() {
        let observations = vec![
            observation(
                "app",
                "1.0.0",
                HOST,
                &["full"],
                &[("serde", "aaaa0000aaaa0000")],
            ),
            observation("serde", "1.0.228", HOST, &["derive"], &[]),
        ];
        let dep_identities = dep_identities(&[(
            "aaaa0000aaaa0000",
            "serde",
            "1.0.228",
            &["derive"],
            None,
            false,
        )]);
        let graph = observed_miss_graph(
            &observations,
            &dep_identities,
            false,
            &resolved_fixture(&observations, &dep_identities, false),
        )
        .expect("miss graph mints");

        let app = node(&graph, "app", false);
        assert_eq!(app.features, vec!["full"]);
        assert_eq!(app.dependencies.len(), 1);
        assert_eq!(app.dependencies[0].crate_name.as_str(), "serde");
        assert!(!app.dependencies[0].host_side);
        assert_eq!(graph.roots.len(), 2);
    }

    /// A native build records every unit at the host triple, so the
    /// host/target split falls to the profile: a unit compiled under
    /// the build-override profile — the shape a proc-macro's deps
    /// compile at — is a host-side node, and the dependent's edge into
    /// it names the same side (stow#349).
    #[test]
    fn native_build_classifies_host_units_by_their_build_override() {
        let mut serde_derive = observation("serde_derive", "1.0.228", HOST, &[], &[]);
        serde_derive.build_override = true;
        let observations = vec![
            observation(
                "serde",
                "1.0.228",
                HOST,
                &["derive"],
                &[("serde_derive", "bbbb0000bbbb0000")],
            ),
            serde_derive,
        ];
        let dep_identities = dep_identities(&[(
            "bbbb0000bbbb0000",
            "serde_derive",
            "1.0.228",
            &[],
            None,
            true,
        )]);
        let graph = observed_miss_graph(
            &observations,
            &dep_identities,
            false,
            &resolved_fixture(&observations, &dep_identities, false),
        )
        .expect("miss graph mints");

        let serde = node(&graph, "serde", false);
        assert_eq!(serde.dependencies[0].crate_name.as_str(), "serde_derive");
        assert!(
            serde.dependencies[0].host_side,
            "a native consumer's proc-macro dep edge is host-side"
        );
        node(&graph, "serde_derive", true);
        assert_eq!(graph.roots.len(), 2);
    }

    /// A one-node resolved graph at an explicitly chosen side — the
    /// projection's own answer, independent of the observation's argv.
    fn resolved_at(
        crate_name: &str,
        version: &str,
        features: &[&str],
        host_side: bool,
    ) -> stow_types::task_graph::ResolvedTaskGraph {
        use stow_types::identity::{
            CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion,
        };
        use stow_types::task_graph::{ResolvedTaskGraph, ResolvedTaskNode, TaskNodeIdentity};
        ResolvedTaskGraph::resolve(vec![ResolvedTaskNode {
            identity: TaskNodeIdentity {
                crate_name: CrateName::parse(crate_name).expect("crate name parses"),
                version: CrateVersion::new(
                    semver::Version::parse(version).expect("version parses"),
                ),
                features_json: FeaturesJson::canonicalize(
                    features
                        .iter()
                        .map(|feature| (*feature).to_owned())
                        .collect(),
                )
                .expect("features canonicalize"),
                target: TargetTriple::parse("x86_64-unknown-linux-gnu").expect("target parses"),
                rustc_version: WireRustcVersion::parse("1.91.1").expect("rustc parses"),
                host_side,
            },
            explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
            dependencies: Vec::new(),
        }])
        .expect("fixture resolves")
    }

    /// The `debug = 0` shape CI runs: cargo strips the codegen flags
    /// the build-override heuristic reads from EVERY unit's argv, so a
    /// plain dep's compile is indistinguishable from a host unit's
    /// (stow#588). The unit graph arbitrates — cfg-if is a normal dep,
    /// so the unit is target-side however its argv read.
    #[test]
    fn a_flagless_native_compile_takes_the_unit_graphs_side() {
        let mut cfg_if = observation("cfg-if", "1.0.5", HOST, &[], &[]);
        cfg_if.build_override = true; // the flagless-argv false positive
        let observations = vec![cfg_if];
        let graph = observed_miss_graph(
            &observations,
            &BTreeMap::new(),
            false,
            &resolved_at("cfg-if", "1.0.5", &[], false),
        )
        .expect("miss graph mints");

        node(&graph, "cfg-if", false);
        assert_eq!(graph.roots.len(), 1);
    }

    /// The same flagless argv on a unit the graph carries host-side
    /// only: the arbitration keeps it host — a real build-override
    /// compile is not re-sided to target.
    #[test]
    fn a_flagless_native_compile_on_a_host_only_unit_stays_host() {
        let mut anyhow = observation("anyhow", "1.0.104", HOST, &["std"], &[]);
        anyhow.build_override = true;
        let observations = vec![anyhow];
        let graph = observed_miss_graph(
            &observations,
            &BTreeMap::new(),
            false,
            &resolved_at("anyhow", "1.0.104", &["std"], true),
        )
        .expect("miss graph mints");

        node(&graph, "anyhow", true);
        assert_eq!(graph.roots.len(), 1);
    }

    /// A `--target wasm32` cross build: a unit recorded at the build
    /// host's triple is a host-side node, and the dependent's edge into
    /// it names the same side. The build host is what classifies — a
    /// build running on a host outside the CI family (say aarch64-linux
    /// for an aarch64-darwin family host) still reads host compiles
    /// correctly.
    #[test]
    fn cross_build_classifies_against_the_probed_build_host() {
        // An aarch64-linux machine building wasm32: the proc-macro
        // compiled at aarch64-linux, which is not the x86_64-linux
        // family host the minted node will land at — classifying
        // against the family host would mint it consumer-side.
        let build_host = "aarch64-unknown-linux-gnu";
        let mut serde = observation(
            "serde",
            "1.0.228",
            "wasm32-unknown-unknown",
            &["derive"],
            &[("serde_derive", "bbbb0000bbbb0000")],
        );
        serde.explicit_target = Some("wasm32-unknown-unknown".to_owned());
        let observations = vec![
            serde,
            observation("serde_derive", "1.0.228", build_host, &[], &[]),
        ];
        let dep_identities = dep_identities(&[(
            "bbbb0000bbbb0000",
            "serde_derive",
            "1.0.228",
            &[],
            None,
            true,
        )]);
        let graph = observed_miss_graph(
            &observations,
            &dep_identities,
            true,
            &resolved_fixture(&observations, &dep_identities, true),
        )
        .expect("miss graph mints");

        let serde = node(&graph, "serde", false);
        assert_eq!(serde.dependencies[0].crate_name.as_str(), "serde_derive");
        assert!(serde.dependencies[0].host_side);
        node(&graph, "serde_derive", true);
        assert_eq!(graph.roots.len(), 2);
    }

    /// A `--target wasm32` cross build: a unit recorded at the family
    /// host triple is a host-side node, and the dependent's edge into it
    /// names the same side.
    #[test]
    fn cross_build_mints_host_side_nodes() {
        let mut serde = observation(
            "serde",
            "1.0.228",
            "wasm32-unknown-unknown",
            &["derive"],
            &[("serde_derive", "bbbb0000bbbb0000")],
        );
        serde.explicit_target = Some("wasm32-unknown-unknown".to_owned());
        let observations = vec![
            serde,
            observation("serde_derive", "1.0.228", HOST, &[], &[]),
        ];
        let dep_identities = dep_identities(&[(
            "bbbb0000bbbb0000",
            "serde_derive",
            "1.0.228",
            &[],
            Some(true),
            false,
        )]);
        let graph = observed_miss_graph(
            &observations,
            &dep_identities,
            true,
            &resolved_fixture(&observations, &dep_identities, true),
        )
        .expect("miss graph mints");

        let serde = node(&graph, "serde", false);
        assert_eq!(serde.dependencies[0].crate_name.as_str(), "serde_derive");
        assert!(serde.dependencies[0].host_side);
        node(&graph, "serde_derive", true);
        assert_eq!(graph.roots.len(), 2);
    }

    /// A served dep joins as a leaf node at its recorded identity so the
    /// observed unit's edge resolves to a node.
    #[test]
    fn served_dep_joins_as_a_leaf_node() {
        let observations = vec![observation(
            "app",
            "1.0.0",
            HOST,
            &[],
            &[("serde", "aaaa0000aaaa0000")],
        )];
        let dep_identities = dep_identities(&[(
            "aaaa0000aaaa0000",
            "serde",
            "1.0.228",
            &["std"],
            None,
            false,
        )]);
        let graph = observed_miss_graph(
            &observations,
            &dep_identities,
            false,
            &resolved_fixture(&observations, &dep_identities, false),
        )
        .expect("miss graph mints");

        let serde = node(&graph, "serde", false);
        assert_eq!(serde.features, vec!["std"]);
        assert_eq!(
            serde.dependencies,
            [] as [stow_types::api::ResolvedDependencyGraphDependency; 0]
        );
        // The dep was served, not compiled — it is not a miss root.
        assert_eq!(graph.roots.len(), 1);
        assert_eq!(graph.roots[0].crate_name.as_str(), "app");
    }

    /// A unit skipped for an unresolvable `--extern` does not leave
    /// leaf nodes behind for the deps it did resolve.
    #[test]
    fn a_skipped_unit_mints_no_orphan_leaf_nodes() {
        let observations = vec![observation(
            "app",
            "1.0.0",
            HOST,
            &[],
            &[("serde", "aaaa0000aaaa0000"), ("lost", "ffff0000ffff0000")],
        )];
        // `serde` resolves; `lost` does not — the unit is skipped, and
        // the resolved dep joins nothing.
        let dep_identities = dep_identities(&[(
            "aaaa0000aaaa0000",
            "serde",
            "1.0.228",
            &["std"],
            None,
            false,
        )]);
        let graph = observed_miss_graph(
            &observations,
            &dep_identities,
            false,
            &resolved_fixture(&observations, &dep_identities, false),
        )
        .expect("miss graph mints");

        assert_eq!(
            graph.roots,
            [] as [stow_types::api::DependencyGraphEntry; 0]
        );
        assert_eq!(
            graph.expanded,
            [] as [stow_types::api::ResolvedDependencyGraphEntry; 0]
        );
    }

    /// A unit whose `--extern` does not resolve to a recorded identity is
    /// not minted — no fabricated empty edge set.
    #[test]
    fn unresolvable_extern_skips_the_unit() {
        let observations = vec![
            observation("app", "1.0.0", HOST, &[], &[("serde", "ffff0000ffff0000")]),
            observation("serde", "1.0.228", HOST, &["derive"], &[]),
        ];
        let dep_identities = dep_identities(&[]);
        let graph = observed_miss_graph(
            &observations,
            &dep_identities,
            false,
            &resolved_fixture(&observations, &dep_identities, false),
        )
        .expect("miss graph mints");

        assert_eq!(graph.expanded.len(), 1);
        assert_eq!(graph.expanded[0].crate_name.as_str(), "serde");
        assert_eq!(graph.roots.len(), 1);
        assert_eq!(graph.roots[0].crate_name.as_str(), "serde");
    }

    /// `cargo build --target <host-triple>` — an explicit target that is
    /// the build host's own triple — still splits the sides: cargo
    /// passes `--target` to the target units and maps the codegen flags
    /// onto the host units too, so neither `explicit_target` nor the
    /// build-override profile separates them; the consumer's spelled
    /// flag does. Without it, a `--target host` build's host misses
    /// mint on the target side and collide with the real target node
    /// on one task id (stow#367).
    #[test]
    fn explicit_host_target_build_classifies_units_by_the_spelled_flag() {
        let mut serde = observation(
            "serde",
            "1.0.228",
            HOST,
            &["derive"],
            &[("serde_derive", "bbbb0000bbbb0000")],
        );
        serde.explicit_target = Some(HOST.to_owned());
        // The host unit carries no `--target` and — under a spelled
        // build — the same debuginfo flag a target dep would, so
        // `build_override` stays false.
        let serde_derive = observation("serde_derive", "1.0.228", HOST, &[], &[]);
        let observations = vec![serde, serde_derive];
        let dep_identities = dep_identities(&[(
            "bbbb0000bbbb0000",
            "serde_derive",
            "1.0.228",
            &[],
            None,
            true,
        )]);
        let graph = observed_miss_graph(
            &observations,
            &dep_identities,
            true,
            &resolved_fixture(&observations, &dep_identities, true),
        )
        .expect("miss graph mints");

        let serde = node(&graph, "serde", false);
        assert_eq!(serde.dependencies[0].crate_name.as_str(), "serde_derive");
        assert!(
            serde.dependencies[0].host_side,
            "a spelled-target consumer's proc-macro dep edge is host-side"
        );
        node(&graph, "serde_derive", true);
        assert_eq!(graph.roots.len(), 2);
    }

    /// stow#615: the observation's `features` are the argv scan — a
    /// build script's `cargo:rustc-cfg=feature="…"` output inflates it
    /// past cargo's resolved set. The minted node carries the unit
    /// graph node's set and resolves against the build's own task
    /// graph, so one such crate can no longer fail the whole call.
    #[test]
    fn a_build_script_inflated_scan_mints_at_the_resolved_set() {
        let observation = observation(
            "scripted",
            "1.0.0",
            HOST,
            &["declared", "probe_from_build_script"],
            &[],
        );
        let dep_identities = dep_identities(&[]);
        // The build's unit graph carries cargo's resolved set alone.
        let resolved = resolved_graph(vec![task_node("scripted", "1.0.0", &["declared"], false)]);
        let graph = observed_miss_graph(&[observation], &dep_identities, false, &resolved)
            .expect("miss graph mints");

        let entry = node(&graph, "scripted", false);
        assert_eq!(entry.features, vec!["declared"]);
        assert_eq!(graph.roots.len(), 1);
        assert_eq!(graph.roots[0].features, vec!["declared"]);
        assert!(
            super::node_subgraph(&resolved, entry).is_ok(),
            "the minted node resolves inside the build's unit graph"
        );
    }

    /// stow#615: an observation the build's unit graph does not carry is
    /// skipped like an unresolvable extern — it costs that unit's mint,
    /// not the build's other misses.
    #[test]
    fn an_observation_absent_from_the_graph_is_skipped() {
        let observations = vec![
            observation("absent", "1.0.0", HOST, &["derive"], &[]),
            observation("present", "1.0.0", HOST, &[], &[]),
        ];
        let dep_identities = dep_identities(&[]);
        let resolved = resolved_graph(vec![task_node("present", "1.0.0", &[], false)]);
        let graph = observed_miss_graph(&observations, &dep_identities, false, &resolved)
            .expect("miss graph mints");

        assert_eq!(graph.expanded.len(), 1);
        assert_eq!(graph.expanded[0].crate_name.as_str(), "present");
        assert_eq!(graph.roots.len(), 1);
        assert_eq!(graph.roots[0].crate_name.as_str(), "present");
    }

    /// stow#615: a served dep that joins as a leaf carries the graph
    /// node's feature set, not the published row's recorded label —
    /// the label is the row's own consumer's answer.
    #[test]
    fn a_served_dep_leaf_carries_the_graph_nodes_feature_set() {
        let observations = vec![observation(
            "app",
            "1.0.0",
            HOST,
            &[],
            &[("serde", "aaaa0000aaaa0000")],
        )];
        // The artifact row was labelled under another consumer's
        // resolution; this build's unit graph resolved the dep at a
        // different set.
        let dep_identities = dep_identities(&[(
            "aaaa0000aaaa0000",
            "serde",
            "1.0.228",
            &["row-label"],
            None,
            false,
        )]);
        let resolved = resolved_graph(vec![
            task_node("app", "1.0.0", &[], false),
            task_node("serde", "1.0.228", &["resolved"], false),
            task_node("serde", "1.0.228", &["resolved"], true),
        ]);
        let graph = observed_miss_graph(&observations, &dep_identities, false, &resolved)
            .expect("miss graph mints");

        let leaf = node(&graph, "serde", false);
        assert_eq!(leaf.features, vec!["resolved"]);
    }

    /// stow#615: a served dep the build's unit graph does not carry
    /// cannot mint a leaf — the referencing unit is not minted either,
    /// like an extern the identity map lacks.
    #[test]
    fn a_served_dep_absent_from_the_graph_skips_its_unit() {
        let observations = vec![observation(
            "app",
            "1.0.0",
            HOST,
            &[],
            &[("serde", "aaaa0000aaaa0000")],
        )];
        let dep_identities = dep_identities(&[(
            "aaaa0000aaaa0000",
            "serde",
            "1.0.228",
            &["derive"],
            None,
            false,
        )]);
        // No serde node in this build's unit graph.
        let resolved = resolved_graph(vec![task_node("app", "1.0.0", &[], false)]);
        let graph = observed_miss_graph(&observations, &dep_identities, false, &resolved)
            .expect("miss graph mints");

        assert_eq!(
            graph.roots,
            [] as [stow_types::api::DependencyGraphEntry; 0]
        );
        assert_eq!(
            graph.expanded,
            [] as [stow_types::api::ResolvedDependencyGraphEntry; 0]
        );
    }

    /// stow#615: the node index is one answer per `(name, version,
    /// side)` — two nodes on one side carrying different feature sets is
    /// a graph shape the miss graph cannot project: a hard error naming
    /// the crate, the side and both sets, never a pick.
    #[test]
    fn a_conflicting_node_set_fails_the_index() {
        let resolved = resolved_graph(vec![
            task_node("dep", "1.0.0", &["a"], false),
            task_node("dep", "1.0.0", &["a", "b"], false),
        ]);
        let error = observed_miss_graph(&[], &BTreeMap::new(), false, &resolved)
            .err()
            .expect("conflicting feature sets fail the graph");
        let message = error.to_string();
        assert!(message.contains("dep"), "{message}");
        assert!(message.contains("1.0.0"), "{message}");
        assert!(message.contains("target"), "{message}");
        assert!(message.contains("[\"a\"]"), "{message}");
        assert!(message.contains("[\"a\", \"b\"]"), "{message}");
    }

    /// A dep's own published `unit_shape` decides its edge's side when
    /// the index carries one — a non-proc-macro host dep (a build
    /// script's ordinary dependency) resolves host-side without leaning
    /// on the proc-macro heuristic.
    #[test]
    fn dep_side_reads_the_deps_published_shape() {
        let mut serde = observation(
            "serde",
            "1.0.228",
            HOST,
            &["derive"],
            &[("serde_derive", "bbbb0000bbbb0000")],
        );
        serde.explicit_target = Some("wasm32-unknown-unknown".to_owned());
        let observations = vec![serde];
        let dep_identities = dep_identities(&[(
            "bbbb0000bbbb0000",
            "serde_derive",
            "1.0.228",
            &[],
            Some(true),
            false,
        )]);
        let graph = observed_miss_graph(
            &observations,
            &dep_identities,
            true,
            &resolved_fixture(&observations, &dep_identities, true),
        )
        .expect("miss graph mints");

        let serde = node(&graph, "serde", false);
        assert!(serde.dependencies[0].host_side);
        node(&graph, "serde_derive", true);
    }
}

#[cfg(test)]
mod unit_graph_tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::OsString;
    use std::path::Path;

    use tempfile::TempDir;

    use super::{
        CARGO_CHANNEL_OVERRIDE, SelectedRegistryDependency, UnitGraph, emit_expanded_graph,
        parse_pkg_id, path_pkg_root, resolve_exact_dependency_graph, rustc_test,
        unit_graph_channel_env, unit_graph_subcommand, unstable_feature_gate,
    };
    use stow_types::api::ResolvedDependencyGraphEntry;

    const WINDOWS_TARGET: &str = "x86_64-pc-windows-msvc";

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("parent dir")).expect("create dir");
        std::fs::write(path, contents).expect("write file");
    }

    fn vendored(root: &Path, name: &str, manifest: &str) {
        let base = format!("vendor/{name}");
        write(root, &format!("{base}/Cargo.toml"), manifest);
        write(
            root,
            &format!("{base}/src/lib.rs"),
            "pub fn vendored() {}\n",
        );
        write(
            root,
            &format!("{base}/.cargo-checksum.json"),
            "{\"files\":{}}",
        );
    }

    /// A one-member root-package workspace whose dependencies exercise
    /// every defect cargo's unit graph now answers for us: `feat-a`
    /// reaches both sides at different feature sets, `opt-dep` is pulled
    /// only through a weak feature edge (never compiled), `unix-host-dep`
    /// and `win-host-dep` gate on cfg either side of a cross build, and
    /// `dev-dep` exists only for dev-including subcommands.
    fn fixture() -> TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_path_buf();

        write(
            &root,
            ".cargo/config.toml",
            "[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n\
             [source.vendored-sources]\ndirectory = \"vendor\"\n",
        );
        write(
            &root,
            "Cargo.toml",
            "[package]\nname = \"member\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [workspace]\nresolver = \"2\"\n\n\
             [features]\nmember-feat = [\"opt-dep?/f1\"]\n\n\
             [dependencies]\nfeat-a = { version = \"1\", default-features = false }\n\
             opt-dep = { version = \"1\", optional = true }\n\n\
             [build-dependencies]\nhost-side = \"1\"\n\n\
             [target.'cfg(unix)'.build-dependencies]\nunix-host-dep = \"1\"\n\n\
             [target.'cfg(windows)'.build-dependencies]\nwin-host-dep = \"1\"\n\n\
             [dev-dependencies]\ndev-dep = \"1\"\n",
        );
        write(&root, "src/lib.rs", "pub fn member() {}\n");
        write(&root, "build.rs", "fn main() {}\n");

        vendored(
            &root,
            "feat-a",
            "[package]\nname = \"feat-a\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\n\
             [features]\ndefault = [\"f1\"]\nf1 = []\nf2 = []\n\n\
             [dependencies]\nleaf = \"1\"\n\
             renamed = { version = \"1\", optional = true, package = \"opt-dep\" }\n",
        );
        vendored(
            &root,
            "leaf",
            "[package]\nname = \"leaf\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\n\
             [dependencies]\nprobe-dep = { version = \"1\", features = [\"declared\"] }\n",
        );
        vendored(
            &root,
            "host-side",
            "[package]\nname = \"host-side\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\n\
             [dependencies]\nfeat-a = \"1\"\n",
        );
        vendored(
            &root,
            "opt-dep",
            "[package]\nname = \"opt-dep\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\n\
             [features]\ndefault = [\"f1\"]\nf1 = []\n",
        );
        vendored(
            &root,
            "unix-host-dep",
            "[package]\nname = \"unix-host-dep\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
        );
        vendored(
            &root,
            "win-host-dep",
            "[package]\nname = \"win-host-dep\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
        );
        vendored(
            &root,
            "dev-dep",
            "[package]\nname = \"dev-dep\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
        );
        vendored(
            &root,
            "probe-dep",
            "[package]\nname = \"probe-dep\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\
             build = \"build.rs\"\n\n\
             [features]\ndefault = [\"declared\"]\ndeclared = []\n",
        );
        // The build script adds a feature cfg cargo never resolved:
        // rustc sees it on the unit's argv; the unit graph does not
        // (stow#615).
        write(
            &root,
            "vendor/probe-dep/build.rs",
            "fn main() {\n    println!(\"cargo:rustc-cfg=feature=\\\"probe_from_build_script\\\"\");\n}\n",
        );

        dir
    }

    fn resolve(root: &Path, action: &str, cargo_args: &[&str]) -> super::ExpandedDependencyGraph {
        let cargo_args = cargo_args.iter().map(OsString::from).collect::<Vec<_>>();
        let spelled_target = cargo_args
            .iter()
            .skip_while(|arg| arg.as_os_str() != "--target")
            .nth(1)
            .map(|arg| arg.to_string_lossy().into_owned());
        let spelled_target = cargo_args
            .iter()
            .find_map(|arg| {
                arg.to_str()
                    .and_then(|arg| arg.strip_prefix("--target="))
                    .map(str::to_owned)
            })
            .or(spelled_target);
        // A cargo home of the fixture's own: the `--unit-graph` child
        // and the `[unstable]` gate's document walk would otherwise read
        // the developer's `$CARGO_HOME/config.toml` (stow#800).
        let cargo_home = root.join("cargo-home");
        std::fs::create_dir_all(&cargo_home).expect("create cargo home");
        smol::block_on(resolve_exact_dependency_graph(
            &root.join("Cargo.toml"),
            action,
            &cargo_args,
            spelled_target.as_deref(),
            root,
            "x86_64-unknown-linux-gnu",
            rustc_test(),
            Some(&cargo_home),
        ))
        .expect("resolve exact dependency graph")
    }

    fn index(
        entries: &[ResolvedDependencyGraphEntry],
    ) -> BTreeMap<(&str, bool), &ResolvedDependencyGraphEntry> {
        entries
            .iter()
            .map(|entry| ((entry.crate_name.as_str(), entry.host_side), entry))
            .collect()
    }

    fn dependencies(entry: &ResolvedDependencyGraphEntry) -> BTreeSet<(String, bool)> {
        entry
            .dependencies
            .iter()
            .map(|dep| (dep.crate_name.as_str().to_owned(), dep.host_side))
            .collect()
    }

    /// Defect 1: `node.features` was one set unified across both sides.
    /// `feat-a` is a target dependency with no features and a build-dep
    /// chain dependency with its defaults — cargo compiles the two sides
    /// separately, so the graph must carry both sets.
    #[test]
    fn each_side_carries_its_own_feature_set() {
        let root = fixture();
        let graph = resolve(root.path(), "build", &[]);
        let entries = index(&graph.entries);

        let target_side = entries[&("feat-a", false)];
        let host_side = entries[&("feat-a", true)];
        assert_eq!(target_side.features, [] as [String; 0]);
        assert_eq!(host_side.features, vec!["default", "f1"]);
    }

    /// stow#615: a build script's `cargo:rustc-cfg=feature="…"` prints
    /// into the unit's argv `--cfg` scan, never into cargo's resolved
    /// feature set — the unit graph's node carries the cargo set alone,
    /// and an observed unit whose scan additionally names the
    /// build-script cfg resolves back to that node.
    #[test]
    fn a_build_script_feature_cfg_stays_out_of_the_resolved_set() {
        let root = fixture();
        let graph = resolve(root.path(), "build", &[]);
        let entries = index(&graph.entries);

        // `probe-dep` reaches both sides through `leaf`; the two nodes
        // carry the same cargo-resolved set.
        let node = entries[&("probe-dep", false)];
        assert_eq!(node.features, vec!["declared", "default"]);
        assert_eq!(node.features, entries[&("probe-dep", true)].features,);

        // The scan the wrapper journals for that unit additionally
        // carries the cfg the build script printed.
        let scan = node
            .features
            .iter()
            .cloned()
            .chain(std::iter::once("probe_from_build_script".to_owned()))
            .collect::<BTreeSet<_>>();
        let table = crate::unit_node::UnitNodeTable::from_expanded(&graph.entries, false);
        let resolved_node = crate::unit_node::resolve_unit_node(
            table.coordinates(),
            table.consumer_spelled_target,
            &crate::unit_node::UnitEvidence {
                crate_name: "probe-dep",
                version: "1.0.0",
                spelled_target: false,
                feature_scan: &scan,
                build_override: false,
            },
        )
        .expect("the inflated scan resolves to the graph's node");
        assert_eq!(resolved_node.features, node.features.as_slice());
    }

    /// Defect 2: an optional dependency reachable only through a weak
    /// (`dep?/feat`) feature edge stayed in the hand-walked resolve even
    /// though cargo never compiles it.
    #[test]
    fn weak_only_optional_dependency_is_not_built() {
        let root = fixture();
        let graph = resolve(root.path(), "build", &["--features", "member-feat"]);
        assert!(
            !graph
                .entries
                .iter()
                .any(|entry| entry.crate_name.as_str() == "opt-dep")
        );
    }

    /// Defect 3: `--filter-platform <target>` evaluated build-dep edges
    /// with the target's cfg. On a unix host cross-compiling for
    /// windows, cargo still builds the unix-gated build dependency — and
    /// never builds the windows-gated one, since build deps compile for
    /// host.
    #[cfg(unix)]
    #[test]
    fn host_side_edges_use_the_host_cfg_when_cross_compiling() {
        let root = fixture();
        let graph = resolve(root.path(), "build", &["--target", WINDOWS_TARGET]);
        let entries = index(&graph.entries);

        assert!(entries.contains_key(&("unix-host-dep", true)));
        assert!(!entries.contains_key(&("win-host-dep", true)));
        assert!(!entries.contains_key(&("win-host-dep", false)));
    }

    /// Defect 4: dev edges were always followed. `dev-dep` is present
    /// only when the wrapped subcommand compiles dev-dependencies.
    #[test]
    fn dev_edges_follow_the_wrapped_subcommand() {
        let root = fixture();
        let build_graph = resolve(root.path(), "build", &[]);
        let test_graph = resolve(root.path(), "test", &[]);

        assert!(
            !build_graph
                .entries
                .iter()
                .any(|entry| entry.crate_name.as_str() == "dev-dep")
        );
        let test = index(&test_graph.entries);
        assert!(test.contains_key(&("dev-dep", false)));
    }

    /// The edges are the unit graph's own: a dep edge lands on the side
    /// the consumer needs it for. Cargo emits ONE `leaf` unit in dev
    /// (both `feat-a` units dep on it) and one per side in release —
    /// either way the target `feat-a` lists only the target `leaf` and
    /// the host `feat-a` only the host `leaf`.
    #[test]
    fn edges_are_the_unit_graphs_own() {
        let root = fixture();
        // Dev shares one `leaf` unit between feat-a's host and target
        // consumers; each consumer's edge lands on its own side — cargo
        // splits the unit per side under `--target`, and a target entry
        // never carries host-side dep edges.
        let dev = resolve(root.path(), "build", &[]);
        let dev_entries = index(&dev.entries);
        assert_eq!(
            dependencies(dev_entries[&("feat-a", false)]),
            BTreeSet::from([("leaf".to_owned(), false)])
        );
        assert_eq!(
            dependencies(dev_entries[&("feat-a", true)]),
            BTreeSet::from([("leaf".to_owned(), true)])
        );
        // Build-dependencies hang under the build-script compile unit;
        // they merge onto the package's host node.
        assert_eq!(
            dependencies(dev_entries[&("host-side", true)]),
            BTreeSet::from([("feat-a".to_owned(), true)])
        );

        let release = resolve(root.path(), "build", &["--release"]);
        let release_entries = index(&release.entries);
        assert_eq!(
            dependencies(release_entries[&("feat-a", false)]),
            BTreeSet::from([("leaf".to_owned(), false)])
        );
        assert_eq!(
            dependencies(release_entries[&("feat-a", true)]),
            BTreeSet::from([("leaf".to_owned(), true)])
        );
    }

    /// The native (unspelled `--target`) invocation's projection must
    /// equal the explicit `--target <host>` projection — the host-side
    /// derivation (`platform` is null for every native unit) must land
    /// the same units on each side.
    #[test]
    fn native_side_derivation_matches_spelled_target() {
        let root = fixture();
        let native = resolve(root.path(), "build", &[]);
        let host = rustc_host_triple();
        let spelled = resolve(root.path(), "build", &["--target", &host]);

        let shape = |graph: &super::ExpandedDependencyGraph| {
            graph
                .entries
                .iter()
                .map(|entry| {
                    (
                        entry.crate_name.as_str().to_owned(),
                        entry.version.to_string(),
                        entry.host_side,
                        entry.features.clone(),
                    )
                })
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(shape(&native), shape(&spelled));
    }

    /// The user's own args forward verbatim: `--release` resolves the
    /// same node set (cargo may emit a different unit layout — shared
    /// dep units split per side — but the packages and feature sets are
    /// the graph's).
    #[test]
    fn release_flag_resolves_the_same_nodes() {
        let root = fixture();
        let dev = resolve(root.path(), "build", &[]);
        let release = resolve(root.path(), "build", &["--release"]);
        let nodes = |graph: &super::ExpandedDependencyGraph| {
            graph
                .entries
                .iter()
                .map(|entry| {
                    (
                        entry.crate_name.as_str().to_owned(),
                        entry.version.to_string(),
                        entry.host_side,
                        entry.features.clone(),
                    )
                })
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(nodes(&dev), nodes(&release));
    }

    /// The wrapped action picks the cargo subcommand whose unit graph it
    /// compiles — clippy resolves the graph `check` compiles, predict
    /// answers against the same shape.
    #[test]
    fn action_maps_to_subcommand() {
        assert_eq!(unit_graph_subcommand("check").unwrap(), "check");
        assert_eq!(unit_graph_subcommand("build").unwrap(), "build");
        assert_eq!(unit_graph_subcommand("test").unwrap(), "test");
        assert_eq!(unit_graph_subcommand("predict").unwrap(), "check");
        // Only check/build/test/predict reach the query — every other
        // action names itself rather than guessing a graph cargo would
        // not build (stow#551).
        for action in ["clippy", "run", "bench", "doc", "rustc", "publish"] {
            assert!(unit_graph_subcommand(action).is_err(), "{action}");
        }
    }

    /// Direct registry dependencies are the roots' lib deps in the same
    /// unit graph, keyed by their extern name — here `feat-a` and
    /// nothing transitive.
    #[test]
    fn direct_dependencies_are_the_roots_lib_deps() {
        let root = fixture();
        let graph = resolve(root.path(), "build", &[]);
        assert_eq!(
            graph.direct_dependencies,
            vec![SelectedRegistryDependency {
                extern_names: std::iter::once("feat_a".to_owned()).collect(),
                crate_name: "feat-a".to_owned(),
                version: semver::Version::parse("1.0.0").unwrap(),
                features: vec![],
                host_side: false,
            }]
        );
    }

    fn rustc_host_triple() -> String {
        let output = std::process::Command::new("rustc")
            .args(["--print", "host-tuple"])
            .output()
            .expect("rustc host tuple");
        String::from_utf8(output.stdout)
            .expect("utf8 host tuple")
            .trim()
            .to_owned()
    }

    /// The projection answers only `pkg_id`s whose source is the
    /// crates.io index.
    #[test]
    fn parse_pkg_id_extracts_crates_io_packages() {
        let (name, version, crates_io) =
            parse_pkg_id("registry+https://github.com/rust-lang/crates.io-index#feat-a@1.0.0");
        assert_eq!((name, version, crates_io), ("feat-a", "1.0.0", true));

        let (_, _, crates_io) = parse_pkg_id("path+file:///tmp/member#0.1.0");
        assert!(!crates_io);
        let (_, _, crates_io) = parse_pkg_id("registry+https://other.registry/index#feat-a@1.0.0");
        assert!(!crates_io);
        let (_, _, crates_io) = parse_pkg_id("sparse+https://index.crates.io/#feat-a@1.0.0");
        assert!(!crates_io, "only the registry+ crates.io form qualifies");
    }

    /// A `path+file` pkg id is a URL, converted by `Url::to_file_path`
    /// the way the host OS reads it — Windows drive letters get no
    /// leading `/` and percent escapes decode. String surgery produced
    /// `/C:/...`, an unreadable path (os error 123) on Windows.
    #[test]
    fn path_pkg_root_converts_pkgid_urls() {
        #[cfg(windows)]
        let cases = [
            (
                "path+file:///C:/Users/runner/proj#0.1.0",
                r"C:\Users\runner\proj",
            ),
            (
                "path+file:///C:/tmp/spaced%20dir#0.1.0",
                r"C:\tmp\spaced dir",
            ),
        ];
        #[cfg(not(windows))]
        let cases = [
            (
                "path+file:///C:/Users/runner/proj#0.1.0",
                "/C:/Users/runner/proj",
            ),
            ("path+file:///tmp/spaced%20dir#0.1.0", "/tmp/spaced dir"),
        ];
        for (pkg_id, expected) in cases {
            assert_eq!(
                path_pkg_root(pkg_id).expect("pkgid path"),
                Path::new(expected),
                "{pkg_id}"
            );
        }
        assert!(path_pkg_root("path+https://host/x#0.1.0").is_err());
    }

    /// The hash path a `path+file` unit lands on really is the manifest
    /// — a percent-escaped directory must resolve to the real file.
    #[test]
    fn local_manifests_read_the_decoded_pkgid_path() {
        let root = TempDir::new().expect("tempdir");
        let project = root.path().join("spaced dir");
        write(
            &project,
            "Cargo.toml",
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
        );
        let url = url::Url::from_directory_path(&project).expect("dir url");
        let json = format!(
            r#"{{"version":1,"roots":[0],"units":[{{"pkg_id":"path+{url}#0.1.0","target":{{"kind":["lib"],"name":"x","crate_types":["lib"]}},"platform":null,"mode":"build","features":[],"dependencies":[]}}]}}"#
        );
        let graph: UnitGraph<'_> = serde_json::from_str(&json).expect("parse");
        let hashes = super::local_manifest_hashes(&graph).expect("hashes");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].path, project.join("Cargo.toml"));
    }

    /// A `version` other than 1 fails fast — the projection can only be
    /// read while its wire shape is the one cargo documents. The emit
    /// side fails fast too: a dependency index outside `units` is an
    /// error, never a dropped edge.
    #[test]
    fn malformed_unit_graph_is_an_error() {
        let out_of_bounds = r#"{
            "version": 1,
            "roots": [0],
            "units": [{
                "pkg_id": "registry+https://github.com/rust-lang/crates.io-index#a@1.0.0",
                "target": {"kind": ["lib"]},
                "platform": null,
                "mode": "build",
                "features": [],
                "dependencies": [{"index": 9, "extern_crate_name": "b"}]
            }]
        }"#;
        let graph: UnitGraph<'_> = serde_json::from_str(out_of_bounds).expect("parse");
        assert!(
            emit_expanded_graph(&graph, None, "x86_64-unknown-linux-gnu", rustc_test()).is_err()
        );
    }

    /// Members `a` and `b` depending on one crate under two extern
    /// names — `oc = { package = "shared" }` — record one dependency
    /// entry carrying both names, not a duplicate the analysis index
    /// would reject (stow#551).
    #[test]
    fn renamed_extern_names_for_one_crate_fold() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        write(
            root,
            ".cargo/config.toml",
            "[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n[source.vendored-sources]\ndirectory = \"vendor\"\n",
        );
        write(
            root,
            "Cargo.toml",
            "[workspace]\nresolver = \"2\"\nmembers = [\"a\", \"b\"]\n",
        );
        write(
            root,
            "a/Cargo.toml",
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nshared = \"1\"\n",
        );
        write(root, "a/src/lib.rs", "pub fn a() {}\n");
        write(
            root,
            "b/Cargo.toml",
            "[package]\nname = \"b\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\noc = { package = \"shared\", version = \"1\" }\n",
        );
        write(root, "b/src/lib.rs", "pub fn b() {}\n");
        vendored(
            root,
            "shared",
            "[package]\nname = \"shared\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
        );
        // The fixture's own cargo home — the developer's
        // `$CARGO_HOME/config.toml` must not merge into this resolution
        // (stow#800).
        std::process::Command::new("cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(root)
            .env("CARGO_HOME", root.join("cargo-home"))
            .output()
            .expect("generate lockfile");

        let graph = resolve(root, "build", &[]);
        let mut shared = graph
            .direct_dependencies
            .iter()
            .filter(|dependency| dependency.crate_name == "shared");
        let entry = shared.next().expect("shared is a direct dependency");
        assert!(
            shared.next().is_none(),
            "one crate version must not emit two analysis requests"
        );
        assert_eq!(
            entry.extern_names.iter().collect::<Vec<_>>(),
            vec!["oc", "shared"],
            "both extern names ride the one entry"
        );
    }

    /// A dep behind `cfg(target_thread_local)` must not appear: the
    /// query unlocks `-Z` through cargo's channel override, which rustc
    /// never reads — cargo evaluates the cfg exactly as the user's
    /// stable build does, where bootstrap would report the cfg and a
    /// phantom node would land (stow#551).
    #[test]
    fn channel_override_hides_bootstrap_cfgs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        write(
            root,
            ".cargo/config.toml",
            "[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n[source.vendored-sources]\ndirectory = \"vendor\"\n",
        );
        write(
            root,
            "Cargo.toml",
            "[package]\nname = \"member\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\nresolver = \"2\"\n\n[target.'cfg(target_thread_local)'.dependencies]\nanyhow = \"1\"\n",
        );
        write(root, "src/lib.rs", "pub fn member() {}\n");
        vendored(
            root,
            "anyhow",
            "[package]\nname = \"anyhow\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
        );
        // The fixture's own cargo home — the developer's
        // `$CARGO_HOME/config.toml` must not merge into this resolution
        // (stow#800).
        std::process::Command::new("cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(root)
            .env("CARGO_HOME", root.join("cargo-home"))
            .output()
            .expect("generate lockfile");

        let graph = resolve(root, "build", &[]);
        assert!(
            graph
                .entries
                .iter()
                .all(|entry| entry.crate_name.as_str() != "anyhow"),
            "cfg(target_thread_local) is a bootstrap cfg the stable build cannot satisfy"
        );
    }

    /// The query's extra environment is exactly the channel override:
    /// `RUSTC_BOOTSTRAP` must never appear in it — bootstrap changes
    /// rustc's `--print cfg` answer, so a user who did not set it must
    /// not have it injected (stow#551).
    #[test]
    fn query_env_never_injects_bootstrap() {
        let env = unit_graph_channel_env();
        assert_eq!(env, vec![(CARGO_CHANNEL_OVERRIDE, "nightly")]);
        assert!(
            env.iter().all(|(key, _)| *key != "RUSTC_BOOTSTRAP"),
            "RUSTC_BOOTSTRAP changes rustc's probe answer; only a user-set value may reach the query"
        );
    }

    /// An `[unstable]` config table is honored under the query's
    /// channel override while the user's stable cargo would ignore it —
    /// the query cannot represent their build, so the setting must
    /// name itself in the error (stow#551).
    #[test]
    fn unstable_config_is_an_error_on_stable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        write(
            root,
            ".cargo/config.toml",
            "[unstable]\nunit-graph = true\n",
        );
        // The gate's document walk pins the fixture's own cargo home —
        // a developer's `$CARGO_HOME/config.toml` must not merge in
        // (stow#800).
        let cargo_home = root.join("cargo-home");
        std::fs::create_dir_all(&cargo_home).expect("create cargo home");
        let error =
            unstable_feature_gate(root, &[], Some(&cargo_home)).expect_err("unstable gate errors");
        assert!(
            error.to_string().contains("unstable.unit-graph"),
            "the setting names itself: {error}"
        );
    }

    /// Several spelled `--target`s: only the units for the resolved
    /// target plus the host units survive — no merging, no other
    /// platform's packages (stow#551).
    #[test]
    fn multiple_spelled_targets_keep_only_the_resolved_one() {
        let json = r#"{
            "version": 1,
            "roots": [0, 1],
            "units": [
                {"pkg_id": "registry+https://github.com/rust-lang/crates.io-index#a@1.0.0",
                 "target": {"kind": ["lib"]}, "platform": "x86_64-pc-windows-msvc",
                 "mode": "build", "features": [], "dependencies": []},
                {"pkg_id": "registry+https://github.com/rust-lang/crates.io-index#a@1.0.0",
                 "target": {"kind": ["lib"]}, "platform": "x86_64-unknown-linux-gnu",
                 "mode": "build", "features": [], "dependencies": []},
                {"pkg_id": "registry+https://github.com/rust-lang/crates.io-index#h@1.0.0",
                 "target": {"kind": ["lib"]}, "platform": null,
                 "mode": "build", "features": [], "dependencies": []}
            ]
        }"#;
        let graph: UnitGraph<'_> = serde_json::from_str(json).expect("parse");
        let (entries, _, _) = emit_expanded_graph(
            &graph,
            Some("x86_64-unknown-linux-gnu"),
            "x86_64-unknown-linux-gnu",
            rustc_test(),
        )
        .expect("resolved target is present");
        assert_eq!(
            entries
                .iter()
                .map(|entry| (entry.crate_name.as_str(), entry.host_side))
                .collect::<Vec<_>>(),
            vec![("a", false), ("h", true)],
            "the unselected platform's units are excluded, host units kept"
        );
    }
}
/// stow#667: the gated run's stop path — the drain's cargo child is
/// killed and reaped before the stopping command is released.
#[cfg(all(test, unix))]
mod stoppable_child_tests {
    use super::{Command, run_stoppable_child};
    use crate::derive_gate::{DerivationGate, ForegroundHold};

    /// The requester parks on the slot's connection until the child is
    /// dead *and* reaped: when the helper answers "stopped", the
    /// child's pid already names no live process.
    #[tokio::test]
    async fn a_stop_kills_the_child_before_the_requester_is_released() {
        let dir = tempfile::tempdir().expect("temp dir");
        let gate_dir = dir.path().join("gate");
        let mut gate = DerivationGate::unopened(gate_dir.clone());
        let enter = {
            let slot = gate
                .slot()
                .await
                .expect("the gate opens with no command present");
            let mut command = Command::new("sleep");
            command
                .arg("30")
                .stdout(async_process::Stdio::piped())
                .stderr(async_process::Stdio::piped());
            let mut child = command.spawn().expect("spawn sleep");
            let pid = child.id();
            let enter = tokio::spawn({
                let gate_dir = gate_dir.clone();
                async move { ForegroundHold::enter(&gate_dir).await }
            });
            let outcome = run_stoppable_child(&mut child, slot)
                .await
                .expect("run the gated child");
            assert!(outcome.is_none(), "the run reports stopped");
            // Reaped, not merely signaled: `ESRCH` is the answer a
            // dead pid gives.
            let pid = i32::try_from(pid).expect("pid fits i32");
            assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH),
                "the stopped child's pid is dead when the helper returns"
            );
            assert!(
                !enter.is_finished(),
                "the command still waits on the open stop connection"
            );
            enter
        };
        gate.shut().await;
        let hold = enter.await.expect("enter task").expect("enter");
        hold.release();
    }
}
