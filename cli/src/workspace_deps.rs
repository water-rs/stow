use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use async_process::Command;
use cargo_lock::{Lockfile, package::SourceId};
use glob::glob;
use semver::{Version, VersionReq};
use serde::Deserialize;
use stow_types::api::{ResolvedDependencyGraphDependency, ResolvedDependencyGraphEntry};
use stow_types::error::Context;
use stow_types::public_cache::UnitSide;

use crate::cargo_cmd::MetadataArgs;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DirectDependency {
    pub(crate) crate_name: String,
    pub(crate) version: Version,
    pub(crate) source: Option<String>,
    pub(crate) features: Vec<String>,
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockfileGraph {
    pub(crate) direct_dependencies: Vec<DirectDependency>,
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

#[tracing::instrument(name = "stow.workspace.resolve_lockfile_graph", skip_all)]
pub fn resolve_lockfile_graph(
    workspace_root: &Path,
    manifest_path: &Path,
    args: &MetadataArgs,
) -> stow_types::error::Result<LockfileGraph> {
    let workspace_manifest_path = workspace_root.join("Cargo.toml");
    let workspace_manifest = load_manifest(&workspace_manifest_path)?;
    let workspace_members = expand_workspace_members(workspace_root, &workspace_manifest)?;
    let selected_manifest_path = canonicalize_or_original(manifest_path);
    let workspace_manifest_path = canonicalize_or_original(&workspace_manifest_path);
    let selected_members = if selected_manifest_path == workspace_manifest_path {
        workspace_members
    } else {
        BTreeSet::from([selected_manifest_path])
    };

    let lockfile_path = workspace_root.join("Cargo.lock");
    let lockfile = Lockfile::load(&lockfile_path).map_err(|error| {
        stow_types::stow_error!("load lockfile {}: {error}", lockfile_path.display())
    })?;
    let lock_packages = lockfile
        .packages
        .iter()
        .map(|package| {
            (
                PackageKey {
                    crate_name: package.name.to_string(),
                    version: package.version.clone(),
                    source: package.source.as_ref().map(ToString::to_string),
                },
                package,
            )
        })
        .collect::<BTreeMap<_, _>>();

    let workspace_deps = workspace_manifest
        .workspace
        .as_ref()
        .and_then(|workspace| workspace.dependencies.as_ref());
    let mut merged_dependencies =
        BTreeMap::<(String, Version, Option<String>), BTreeSet<String>>::new();
    for member_path in &selected_members {
        let member_manifest = load_manifest(member_path)?;
        let member_package = member_manifest.package.as_ref().ok_or_else(|| {
            stow_types::stow_error!(
                "selected manifest {} is missing [package]",
                member_path.display()
            )
        })?;
        // The member's own lockfile entry records exactly which version cargo
        // assigned to each of its dependency edges — the only correct answer
        // when the lockfile pins several semver-compatible versions at once.
        // A stow-synthesized lockfile omits workspace members entirely (it
        // pins exactly one version per crate), so absence is a defined input
        // shape, not an error: edges then resolve by requirement match with
        // a uniqueness guarantee enforced in `resolve_lockfile_package`.
        let member_lock_package = lockfile.packages.iter().find(|package| {
            package.name.as_str() == member_package.name && package.source.is_none()
        });
        let feature_config = FeatureConfig::new(&member_manifest, &member_package.name, args);
        collect_dependency_section(
            member_manifest.dependencies.as_ref(),
            workspace_deps,
            &feature_config,
            member_lock_package,
            &lock_packages,
            &mut merged_dependencies,
        )?;
        // Build- and dev-dependencies compile in a different rustc context
        // (host triple, separate c_metadata chain) than the runtime closure
        // that the public artifact cache covers. Including them here makes
        // the lockfile-walker hard-fail when the synthesized stow lockfile
        // intentionally pins only the runtime graph — even though those
        // pins have no bearing on what the cache can serve. Skip them for
        // the cache-graph builder; cargo's own resolver still handles them
        // when it reads `Cargo.toml` directly.
    }

    let direct_dependencies = merged_dependencies
        .into_iter()
        .map(
            |((crate_name, version, source), features)| DirectDependency {
                crate_name,
                version,
                source,
                features: features.into_iter().collect(),
            },
        )
        .collect::<Vec<_>>();

    Ok(LockfileGraph {
        direct_dependencies,
    })
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
pub async fn resolve_exact_dependency_graph(
    manifest_path: &Path,
    action: &str,
    cargo_args: &[OsString],
    target: Option<&str>,
    current_dir: &Path,
    toolchain: &str,
) -> stow_types::error::Result<ExpandedDependencyGraph> {
    let subcommand = unit_graph_subcommand(action)?;
    let mut unit_graph = Command::new("cargo");
    unit_graph
        .arg(subcommand)
        // Before the user's args: never lands behind a `--` terminator.
        .arg("--unit-graph")
        .arg("-Z")
        .arg("unstable-options")
        .current_dir(current_dir);
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
        unstable_feature_gate(current_dir, cargo_args)?;
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

    let unit_graph = unit_graph
        .output()
        .await
        .wrap_err("spawn cargo --unit-graph")?;
    if !unit_graph.status.success() {
        return Err(stow_types::stow_error!(
            "cargo {subcommand} --unit-graph failed on toolchain {toolchain}: {}",
            String::from_utf8_lossy(&unit_graph.stderr).trim()
        ));
    }
    expanded_dependency_graph(&unit_graph.stdout, target, toolchain)
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
    toolchain: &str,
) -> stow_types::error::Result<ExpandedDependencyGraph> {
    let graph: UnitGraph<'_> =
        serde_json::from_slice(unit_graph_json).wrap_err("parse cargo --unit-graph JSON")?;
    if graph.version != 1 {
        return Err(stow_types::stow_error!(
            "cargo --unit-graph reported version {} (toolchain {toolchain}); only version 1 is understood",
            graph.version
        ));
    }
    let (entries, direct_dependencies, local_manifests) = emit_expanded_graph(&graph, target)?;
    Ok(ExpandedDependencyGraph {
        entries,
        direct_dependencies,
        local_manifests,
    })
}

/// The cargo subcommand whose unit graph each wrapped action compiles;
/// `predict` answers what `check` compiles. Only the actions stow
/// wraps (`check`, `build`, `test`, `predict`) reach this mapping.
fn unit_graph_subcommand(action: &str) -> stow_types::error::Result<&str> {
    Ok(match action {
        "check" | "predict" => "check",
        "build" | "test" => action,
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
) -> stow_types::error::Result<()> {
    let mut enabled = Vec::<String>::new();
    for (key, _value) in std::env::vars() {
        if let Some(name) = key.strip_prefix("CARGO_UNSTABLE_") {
            enabled.push(format!("CARGO_UNSTABLE_{name}"));
        }
    }
    for (source, document) in crate::mold::cargo_config_documents(current_dir, cargo_args) {
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

/// Bounds-checked unit index — an out-of-range `roots`/`dependencies`
/// index is cargo reporting a graph we do not understand, not a unit
/// to skip.
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

/// The unit graph as `ResolvedDependencyGraphEntry` rows + root direct
/// deps + the local manifests cargo read. `target` is cargo's given
/// target triple; `None` is a native build.
fn emit_expanded_graph(
    graph: &UnitGraph<'_>,
    target: Option<&str>,
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
            let entry = entries
                .entry((info.name.to_owned(), version.clone(), side == HOST))
                .or_insert_with(|| ResolvedDependencyGraphEntry {
                    crate_name: crate_name.clone(),
                    version: version.clone(),
                    features: Vec::new(),
                    host_side: side == HOST,
                    dependencies: Vec::new(),
                });
            entry
                .features
                .extend(unit.features.iter().map(|feature| (*feature).to_owned()));
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
    Ok((
        entries.into_values().collect(),
        direct_dependencies(graph, &infos, &sides)?,
        local_manifest_hashes(graph)?,
    ))
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
/// rather than compiled joins as a leaf node at the artifact's recorded
/// feature set so every edge resolves to a node. A unit whose externs
/// do not all resolve to a recorded identity is not minted — a miss
/// whose deps cannot be named is a miss stow does not post.
pub struct ObservedMissGraph {
    /// The misses to enqueue: the observed (compiled-locally) units.
    pub roots: Vec<stow_types::api::DependencyGraphEntry>,
    /// The expanded graph their `depends_on` edges resolve against.
    pub expanded: Vec<ResolvedDependencyGraphEntry>,
}

/// Build the miss graph from the build's compile observations and the
/// dependency identities recorded in the artifact cache.
pub fn observed_miss_graph(
    observations: &[crate::artifact_cache::ObservedUnit],
    dep_identities: &BTreeMap<String, crate::artifact_cache::ObservedDepIdentity>,
    consumer_spelled_target: bool,
) -> ObservedMissGraph {
    let mut entries = BTreeMap::<(String, String, bool), ResolvedDependencyGraphEntry>::new();
    let mut roots = Vec::new();
    // `(dep key, side)` pairs an observed edge needs a node for —
    // synthesized after the observed units so an observed node always
    // wins over a leaf.
    let mut referenced = BTreeSet::<(String, String, bool)>::new();
    let mut referenced_features = BTreeMap::<(String, String, bool), Vec<String>>::new();

    for observation in observations {
        // A host unit is the one cargo never passes `--target`. When
        // the consumer's own cargo invocation spelled `--target` —
        // even when it spelled the host triple — that alone decides
        // it, because cargo then compiles host units with the mapped
        // codegen flags a target dep also carries, leaving no profile
        // signal to split them by. Under a native build the split
        // falls to the profile the unit's argv carried — host units
        // compile under the build-override profile (stow#349).
        let host_side = observation.explicit_target.is_none()
            && (consumer_spelled_target || observation.build_override);
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
        let Some((mut dependencies, dep_nodes)) =
            observed_dep_edges(observation, dep_identities, host_side)
        else {
            continue;
        };
        // A skipped unit's deps must not mint orphan leaf nodes —
        // record the keys only once the unit's edges all resolved.
        for (dep_key, dep_features) in dep_nodes {
            referenced.insert(dep_key.clone());
            referenced_features.insert(dep_key, dep_features);
        }
        dependencies.sort();
        dependencies.dedup();
        let mut features = observation.features.clone();
        features.sort();
        features.dedup();
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
            },
        );
    }

    roots.sort();
    roots.dedup();

    for (name, version, side) in referenced {
        entries
            .entry((name.clone(), version.clone(), side))
            .or_insert_with(|| {
                let crate_name = stow_types::identity::CrateName::parse(&name)
                    .expect("referenced dep name parses");
                ResolvedDependencyGraphEntry {
                    crate_name,
                    version: Version::parse(&version).expect("referenced dep version parses"),
                    features: referenced_features
                        .remove(&(name, version, side))
                        .unwrap_or_default(),
                    host_side: side,
                    dependencies: Vec::new(),
                }
            });
    }

    ObservedMissGraph {
        roots,
        expanded: entries.into_values().collect(),
    }
}

/// The `(name, version, host_side)` key a referenced dep mints its leaf
/// node under, plus the recorded feature set it carries there.
type DepNodeRef = ((String, String, bool), Vec<String>);

/// Resolve one observed unit's `--extern` deps into graph edges at each
/// dep's own recorded identity, returning the (name, version, side) keys
/// the graph must carry a node for alongside the edges. `None` — and
/// the unit is not minted — when any extern has no recorded identity:
/// a miss whose deps cannot be named is a miss stow does not post.
fn observed_dep_edges(
    observation: &crate::artifact_cache::ObservedUnit,
    dep_identities: &BTreeMap<String, crate::artifact_cache::ObservedDepIdentity>,
    observation_host_side: bool,
) -> Option<(Vec<ResolvedDependencyGraphDependency>, Vec<DepNodeRef>)> {
    let mut dependencies = Vec::new();
    let mut dep_nodes = Vec::new();
    for extern_dep in &observation.externs {
        let dep = dep_identities.get(&extern_dep.c_metadata).and_then(|dep| {
            Some((
                stow_types::identity::CrateName::parse(&dep.crate_name).ok()?,
                Version::parse(&dep.crate_version).ok()?,
                dep.features.clone(),
                dep.unit_shape,
                dep.proc_macro,
            ))
        });
        let Some((dep_name, dep_version, dep_features, dep_shape, dep_proc_macro)) = dep else {
            tracing::warn!(
                crate_name = %observation.crate_name,
                c_metadata = %extern_dep.c_metadata,
                "observed unit's --extern dep has no recorded identity; not minting it as a miss"
            );
            return None;
        };
        // The dep's published shape says which side its node serves.
        // Without one — a local artifact, or a legacy shapeless row —
        // the edge's own semantics decide: every extern of a host unit
        // is host-side, and a target unit's only host extern is a
        // proc-macro.
        let dep_side = dep_shape.map_or(observation_host_side || dep_proc_macro, |shape| {
            shape.side == UnitSide::Host
        });
        dep_nodes.push((
            (
                dep_name.as_str().to_owned(),
                dep_version.to_string(),
                dep_side,
            ),
            dep_features,
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

fn collect_dependency_section(
    section: Option<&BTreeMap<String, DependencySpec>>,
    workspace_deps: Option<&BTreeMap<String, DependencySpec>>,
    feature_config: &FeatureConfig,
    member_lock_package: Option<&cargo_lock::Package>,
    lock_packages: &BTreeMap<PackageKey, &cargo_lock::Package>,
    merged_dependencies: &mut BTreeMap<(String, Version, Option<String>), BTreeSet<String>>,
) -> stow_types::error::Result<()> {
    let Some(section) = section else {
        return Ok(());
    };
    for (dependency_key, raw_spec) in section {
        let Some(spec) = resolve_dependency_spec(dependency_key, raw_spec, workspace_deps)? else {
            continue;
        };
        if spec.optional
            && !feature_config
                .enabled_optional_deps
                .contains(dependency_key)
        {
            continue;
        }
        let Some(version_req) = spec.version.as_deref() else {
            continue;
        };
        let package = resolve_lockfile_package(
            &spec.crate_name,
            version_req,
            member_lock_package,
            lock_packages,
        )?;
        if !package_is_crates_io(package) {
            continue;
        }
        let mut features = BTreeSet::<String>::new();
        if spec.default_features {
            features.insert("default".to_owned());
        }
        features.extend(spec.features);
        if let Some(extra_features) = feature_config.dependency_features.get(dependency_key) {
            features.extend(extra_features.iter().cloned());
        }
        merged_dependencies
            .entry((
                spec.crate_name,
                package.version.clone(),
                package.source.as_ref().map(ToString::to_string),
            ))
            .or_default()
            .extend(features);
    }
    Ok(())
}

fn resolve_dependency_spec(
    dependency_key: &str,
    raw_spec: &DependencySpec,
    workspace_deps: Option<&BTreeMap<String, DependencySpec>>,
) -> stow_types::error::Result<Option<ResolvedDependencySpec>> {
    let workspace_spec = if raw_spec.workspace() {
        Some(
            workspace_deps
                .and_then(|deps| deps.get(dependency_key))
                .ok_or_else(|| {
                    stow_types::stow_error!(
                        "workspace dependency `{dependency_key}` is missing from [workspace.dependencies]"
                    )
                })?,
        )
    } else {
        None
    };
    let crate_name = raw_spec
        .package()
        .or_else(|| workspace_spec.and_then(|spec| spec.package()))
        .unwrap_or(dependency_key)
        .to_owned();
    let version = raw_spec
        .version()
        .or_else(|| workspace_spec.and_then(|spec| spec.version()))
        .map(str::to_owned);
    let path = raw_spec
        .path()
        .or_else(|| workspace_spec.and_then(|spec| spec.path()));
    let git = raw_spec
        .git()
        .or_else(|| workspace_spec.and_then(|spec| spec.git()));
    let registry = raw_spec
        .registry()
        .or_else(|| workspace_spec.and_then(|spec| spec.registry()));
    let registry_index = raw_spec
        .registry_index()
        .or_else(|| workspace_spec.and_then(|spec| spec.registry_index()));
    if path.is_some() || git.is_some() || registry.is_some() || registry_index.is_some() {
        return Ok(None);
    }

    let mut features = workspace_spec
        .map(DependencySpec::features)
        .unwrap_or_default();
    features.extend(raw_spec.features());

    Ok(Some(ResolvedDependencySpec {
        crate_name,
        version,
        features,
        optional: raw_spec
            .optional()
            .or_else(|| workspace_spec.and_then(DependencySpec::optional))
            .unwrap_or(false),
        default_features: raw_spec
            .default_features()
            .or_else(|| workspace_spec.and_then(DependencySpec::default_features))
            .unwrap_or(true),
    }))
}

fn resolve_lockfile_package<'a>(
    crate_name: &str,
    version_req: &str,
    parent: Option<&cargo_lock::Package>,
    lock_packages: &'a BTreeMap<PackageKey, &cargo_lock::Package>,
) -> stow_types::error::Result<&'a cargo_lock::Package> {
    let version_req = VersionReq::parse(version_req).wrap_err_with(|| {
        format!("parse version requirement `{version_req}` for dependency `{crate_name}`")
    })?;
    // Without a member entry (stow-synthesized lockfiles omit workspace
    // members), resolve by requirement match — but demand uniqueness so a
    // lockfile pinning several compatible versions can never be silently
    // mis-resolved.
    let Some(parent) = parent else {
        let mut matching = lock_packages.iter().filter(|(key, package)| {
            key.crate_name == crate_name
                && version_req.matches(&key.version)
                && package_is_crates_io(package)
        });
        let package = matching.next().map(|(_, package)| *package).ok_or_else(|| {
            stow_types::stow_error!(
                "no lockfile package matched dependency `{crate_name}` requirement `{version_req}`"
            )
        })?;
        if matching.next().is_some() {
            return Err(stow_types::stow_error!(
                "dependency `{crate_name} {version_req}` matches multiple lockfile versions and the                  workspace member entry needed to disambiguate is absent"
            ));
        }
        return Ok(package);
    };
    // Cargo.lock records exactly which version this parent's edge resolved
    // to. Picking `max_by(version)` over all matching packages instead would
    // silently target the wrong artifact whenever the lockfile pins several
    // semver-compatible versions of the same crate.
    let edge = parent
        .dependencies
        .iter()
        .find(|dependency| {
            dependency.name.as_str() == crate_name && version_req.matches(&dependency.version)
        })
        .ok_or_else(|| {
            stow_types::stow_error!(
                "Cargo.lock entry for `{}` has no dependency edge matching `{crate_name} {version_req}`",
                parent.name
            )
        })?;
    if let Some(source) = edge.source.as_ref() {
        let key = PackageKey {
            crate_name: crate_name.to_owned(),
            version: edge.version.clone(),
            source: Some(source.to_string()),
        };
        return lock_packages.get(&key).copied().ok_or_else(|| {
            stow_types::stow_error!(
                "Cargo.lock dependency edge `{crate_name} {}` has no package entry",
                edge.version
            )
        });
    }
    // Lockfiles omit the dependency source when the (name, version) pair is
    // unambiguous; require exactly one package entry in that case.
    let mut matches = lock_packages
        .iter()
        .filter(|(key, _)| key.crate_name == crate_name && key.version == edge.version);
    let package = matches.next().map(|(_, package)| *package).ok_or_else(|| {
        stow_types::stow_error!(
            "Cargo.lock dependency edge `{crate_name} {}` has no package entry",
            edge.version
        )
    })?;
    if matches.next().is_some() {
        return Err(stow_types::stow_error!(
            "Cargo.lock dependency edge `{crate_name} {}` is ambiguous across multiple sources",
            edge.version
        ));
    }
    Ok(package)
}

fn package_is_crates_io(package: &cargo_lock::Package) -> bool {
    package
        .source
        .as_ref()
        .is_some_and(SourceId::is_default_registry)
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
    let feature_config = FeatureConfig::new(&manifest, &package_name, args);
    Ok(feature_config.enabled_optional_deps)
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

#[derive(Debug, Clone, Default)]
struct FeatureConfig {
    enabled_optional_deps: BTreeSet<String>,
    dependency_features: BTreeMap<String, BTreeSet<String>>,
}

impl FeatureConfig {
    fn new(manifest: &Manifest, package_name: &str, args: &MetadataArgs) -> Self {
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
        let mut dependency_features = BTreeMap::<String, BTreeSet<String>>::new();

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
                        &mut dependency_features,
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
                    &mut dependency_features,
                );
            }
        }

        Self {
            enabled_optional_deps,
            dependency_features,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_feature_item(
    item: &str,
    feature_map: &BTreeMap<String, Vec<String>>,
    dependency_names: &BTreeSet<String>,
    activated_features: &mut BTreeSet<String>,
    queue: &mut VecDeque<String>,
    enabled_optional_deps: &mut BTreeSet<String>,
    dependency_features: &mut BTreeMap<String, BTreeSet<String>>,
) {
    if let Some(dep_name) = item.strip_prefix("dep:") {
        enabled_optional_deps.insert(dep_name.to_owned());
        return;
    }
    if let Some((dependency_name, dependency_feature)) = item.split_once('/') {
        let conditional = dependency_name.ends_with('?');
        let dependency_name = dependency_name.trim_end_matches('?');
        if conditional && !enabled_optional_deps.contains(dependency_name) {
            return;
        }
        enabled_optional_deps.insert(dependency_name.to_owned());
        dependency_features
            .entry(dependency_name.to_owned())
            .or_default()
            .insert(dependency_feature.to_owned());
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

#[derive(Debug, Clone)]
struct ResolvedDependencySpec {
    crate_name: String,
    version: Option<String>,
    features: BTreeSet<String>,
    optional: bool,
    default_features: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    package: Option<PackageSection>,
    workspace: Option<WorkspaceSection>,
    features: Option<BTreeMap<String, Vec<String>>>,
    dependencies: Option<BTreeMap<String, DependencySpec>>,
    #[serde(rename = "build-dependencies")]
    build_dependencies: Option<BTreeMap<String, DependencySpec>>,
    #[serde(rename = "dev-dependencies")]
    dev_dependencies: Option<BTreeMap<String, DependencySpec>>,
}

#[derive(Debug, Clone, Deserialize)]
struct PackageSection {
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct WorkspaceSection {
    members: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
    dependencies: Option<BTreeMap<String, DependencySpec>>,
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
        .filter_map(DependencySpec::path)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum DependencySpec {
    Simple(String),
    Detailed(DetailedDependencySpec),
}

impl DependencySpec {
    fn version(&self) -> Option<&str> {
        match self {
            Self::Simple(version) => Some(version.as_str()),
            Self::Detailed(spec) => spec.version.as_deref(),
        }
    }

    fn features(&self) -> BTreeSet<String> {
        match self {
            Self::Simple(_) => BTreeSet::new(),
            Self::Detailed(spec) => spec.features.iter().cloned().collect(),
        }
    }

    const fn optional(&self) -> Option<bool> {
        match self {
            Self::Simple(_) => None,
            Self::Detailed(spec) => spec.optional,
        }
    }

    const fn default_features(&self) -> Option<bool> {
        match self {
            Self::Simple(_) => None,
            Self::Detailed(spec) => spec.default_features,
        }
    }

    const fn workspace(&self) -> bool {
        match self {
            Self::Simple(_) => false,
            Self::Detailed(spec) => spec.workspace,
        }
    }

    fn package(&self) -> Option<&str> {
        match self {
            Self::Simple(_) => None,
            Self::Detailed(spec) => spec.package.as_deref(),
        }
    }

    fn path(&self) -> Option<&str> {
        match self {
            Self::Simple(_) => None,
            Self::Detailed(spec) => spec.path.as_deref(),
        }
    }

    fn git(&self) -> Option<&str> {
        match self {
            Self::Simple(_) => None,
            Self::Detailed(spec) => spec.git.as_deref(),
        }
    }

    fn registry(&self) -> Option<&str> {
        match self {
            Self::Simple(_) => None,
            Self::Detailed(spec) => spec.registry.as_deref(),
        }
    }

    fn registry_index(&self) -> Option<&str> {
        match self {
            Self::Simple(_) => None,
            Self::Detailed(spec) => spec.registry_index.as_deref(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct DetailedDependencySpec {
    version: Option<String>,
    #[serde(default)]
    features: Vec<String>,
    optional: Option<bool>,
    #[serde(rename = "default-features")]
    default_features: Option<bool>,
    #[serde(default)]
    workspace: bool,
    package: Option<String>,
    path: Option<String>,
    git: Option<String>,
    registry: Option<String>,
    #[serde(rename = "registry-index")]
    registry_index: Option<String>,
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
    /// `unit_shape` (`None` for a dep with no shape row), `proc_macro`
    /// the artifact's recorded kind.
    type DepIdentityFixture<'a> = (&'a str, &'a str, &'a str, &'a [&'a str], Option<bool>, bool);

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
        let graph = observed_miss_graph(&observations, &dep_identities, false);

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
        let graph = observed_miss_graph(&observations, &dep_identities, false);

        let serde = node(&graph, "serde", false);
        assert_eq!(serde.dependencies[0].crate_name.as_str(), "serde_derive");
        assert!(
            serde.dependencies[0].host_side,
            "a native consumer's proc-macro dep edge is host-side"
        );
        node(&graph, "serde_derive", true);
        assert_eq!(graph.roots.len(), 2);
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
        let graph = observed_miss_graph(&observations, &dep_identities, true);

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
        let graph = observed_miss_graph(&observations, &dep_identities, true);

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
        let graph = observed_miss_graph(&observations, &dep_identities, false);

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
        let graph = observed_miss_graph(&observations, &dep_identities, false);

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
        let graph = observed_miss_graph(&observations, &dep_identities, false);

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
        let graph = observed_miss_graph(&observations, &dep_identities, true);

        let serde = node(&graph, "serde", false);
        assert_eq!(serde.dependencies[0].crate_name.as_str(), "serde_derive");
        assert!(
            serde.dependencies[0].host_side,
            "a spelled-target consumer's proc-macro dep edge is host-side"
        );
        node(&graph, "serde_derive", true);
        assert_eq!(graph.roots.len(), 2);
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
        let graph = observed_miss_graph(&observations, &dep_identities, true);

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
        parse_pkg_id, path_pkg_root, resolve_exact_dependency_graph, unit_graph_channel_env,
        unit_graph_subcommand, unstable_feature_gate,
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
            "[package]\nname = \"leaf\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
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
        smol::block_on(resolve_exact_dependency_graph(
            &root.join("Cargo.toml"),
            action,
            &cargo_args,
            spelled_target.as_deref(),
            root,
            "rustc",
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
        assert!(emit_expanded_graph(&graph, None).is_err());
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
        std::process::Command::new("cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(root)
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
        std::process::Command::new("cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(root)
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
        let error = unstable_feature_gate(root, &[]).expect_err("unstable gate errors");
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
        let (entries, _, _) = emit_expanded_graph(&graph, Some("x86_64-unknown-linux-gnu"))
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
