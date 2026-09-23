//! The stow-facing resolve entry point.
//!
//! [`resolve`] produces what `cargo metadata --filter-platform <target>`
//! produces (the `packages` array, the `resolve` node map, features and
//! `dep_kinds` — the [`ExportInfo`] payload is byte-for-byte cargo's own
//! serialization) plus the per-side unit graph stow actually builds on: one
//! node per `(package, side)` as cargo's feature resolver decides them —
//! `FeaturesFor::NormalOrDev` on the requested target, `FeaturesFor::HostDep`
//! and proc-macro units on the host triple, `FeaturesFor::ArtifactDep(t)` on
//! `t` — where "the host triple" is the runner-family host triple supplied by
//! the caller, not whatever machine the resolver happens to run on.
//!
//! Edges between nodes come from [`FeatureResolver::resolve_and_edges`]:
//! exactly the dependency edges cargo would compile, with dev-dependency
//! edges absent (stow builds the same unit set `cargo build` does, not
//! `cargo test`).

use crate::core::compiler::{CompileKind, CompileKindFallback, RustcTargetData};
use crate::core::dependency::DepKind;
use crate::core::resolver::features::{
    CliFeatures, FeaturesFor, ForceAllTargets, HasDevUnits, PackageFeaturesKey, SideEdge,
};
use crate::core::{PackageId, PackageIdSpec, Workspace};
use crate::ops::cargo_output_metadata::{self, ExportInfo, OutputMetadataOptions};
use crate::ops::{self, Packages};
use crate::util::CargoResult;
use crate::util::context::ConfigValue as CV;
use crate::util::context::GlobalContext;
use crate::util::context::value::Definition;
use crate::util::fs;
use crate::util::rustc::Rustc;
use anyhow::{Context, anyhow, bail};
use cargo_platform::Cfg;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::str::FromStr;

/// Everything a resolve needs that a real `cargo` invocation would read from
/// the environment: the workspace, the requested platforms, the toolchain's
/// identity, and each platform's `--print=cfg` data.
pub struct StowResolveInput {
    /// Absolute path of the workspace root `Cargo.toml` inside `gctx`'s
    /// filesystem — the manifest that produces the resolve. For stow this is
    /// a virtual manifest carrying exactly the requested dependencies.
    pub manifest_path: PathBuf,
    /// `--filter-platform` targets. Each entry becomes a `CompileKind::Target`;
    /// an empty list resolves for the host only, as cargo does.
    pub filter_platforms: Vec<String>,
    /// The triple host-gated units compile on — the runner-family host
    /// triple of the build this resolve feeds (`RunnerFamily::host_triple`).
    /// This is *also* the triple the injected [`Rustc`] must report as its
    /// host so host-cfg edges evaluate against the runner, not this machine.
    pub host_triple: String,
    /// `--features` values.
    pub features: Vec<String>,
    /// `--all-features`.
    pub all_features: bool,
    /// `--no-default-features` (inverted to `uses_default_features`).
    pub no_default_features: bool,
    /// `rustc -vV` stdout of the toolchain the build would use. Injected via
    /// [`GlobalContext::set_rustc`]; the `host:` line must equal
    /// [`host_triple`](Self::host_triple).
    pub rustc_verbose_version: String,
    /// `rustc --print cfg` output lines keyed by target triple. The map must
    /// cover the host triple and every `filter_platforms` triple; artifact
    /// dependencies may demand more kinds mid-resolve, and a missing key is
    /// an error, not a guess.
    pub cfg: BTreeMap<String, Vec<String>>,
    /// Whether the workspace's own members are crates.io packages — `true`
    /// when the tree is a published `.crate` tarball, `false` for a project
    /// checkout. A member's `SourceId` is a path source either way, so the
    /// provenance is the caller's fact: consumers building task graphs
    /// treat units whose package is not crates.io-sourced as traversal,
    /// never nodes — but a `.crate` member *is* the published package.
    pub members_are_crates_io: bool,
}

/// Cargo's `cargo metadata` document plus stow's per-side unit graph under
/// `units`/`roots`. Serializes as the metadata document itself with the
/// extras flattened in.
#[derive(Serialize)]
pub struct StowResolveOutput {
    /// Identical to `cargo metadata` output for the same inputs.
    #[serde(flatten)]
    pub metadata: ExportInfo,
    /// One node per `(package, side)` cargo would compile — the units stow
    /// keys builds and dedup on.
    pub units: Vec<StowUnit>,
    /// Unit keys the workspace members produce — the roots of `units`.
    pub roots: Vec<StowUnitKey>,
    /// Whether any workspace member declares or autodiscovers a `[[bin]]`
    /// — cargo's own target discovery (declared `[bin]`/`[[bin]]` plus
    /// `src/main.rs`, `src/bin/*.rs`, `src/bin/*/main.rs` under `autobins`)
    /// ran during package load, so this sees member binaries in nested
    /// `crates/*` dirs exactly as `cargo build` does.
    pub has_binary: bool,
}

/// A node's identity: which package, on which platform, with which side's
/// feature set.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct StowUnitKey {
    /// Package-id spec as cargo prints it (`name version (source)`).
    pub pkg: PackageIdSpec,
    /// Triple the unit compiles on: a requested `filter_platforms` target,
    /// [`StowResolveInput::host_triple`], or an artifact-dep target.
    pub platform: String,
    /// Which cargo side produced the features: `target`, `host`, or an
    /// artifact-dep target. Two nodes can share `(pkg, platform)` with
    /// different sides and carry different feature sets.
    pub side: StowSide,
    /// Which unit of the package this is — a package supplies both a lib
    /// and a build script.
    pub kind: StowUnitKind,
}

/// The cargo side a unit's features were resolved under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StowSide {
    /// `FeaturesFor::NormalOrDev` — the normal/dev side.
    Target,
    /// `FeaturesFor::HostDep` — build-dep/proc-macro side, features unified
    /// under the host platform.
    Host,
    /// `FeaturesFor::ArtifactDep(t)` — an `-Z bindeps` artifact dependency.
    Artifact,
}

/// Which unit of a package a node represents, mirroring `cargo build
/// --unit-graph`'s `mode`/`target.kind`: every package with a `build.rs`
/// produces a host compile unit *and* a `run` unit on the owning lib's
/// platform; the lib unit edges to its run unit, the run unit to the
/// compile unit, and the compile unit to the build-dep libs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StowUnitKind {
    /// A `lib`/`proc-macro` library target — the unit stow builds and caches.
    Lib,
    /// A `build.rs` compile unit — always a host compile.
    BuildScript,
    /// The `build.rs` execution unit — sits at the owning lib's platform
    /// between the lib and the script compile, as `run-custom-build` does in
    /// cargo's unit graph.
    RunBuildScript,
}

/// One build unit in the resolved graph.
#[derive(Debug, Clone, Serialize)]
pub struct StowUnit {
    /// The node's identity.
    #[serde(flatten)]
    pub key: StowUnitKey,
    /// Crate name.
    pub name: String,
    /// Crate version.
    pub version: String,
    /// Which target of the package this unit compiles.
    pub unit_kind: StowUnitKind,
    /// Resolved feature set for this side — cargo's `activated_features`.
    pub features: Vec<String>,
    /// Whether the unit's package is a crates.io package — a registry
    /// `SourceId`, or a workspace member the caller marked
    /// [`StowResolveInput::members_are_crates_io`]. Path members, path
    /// deps, and git packages are traversed by the graph but are not
    /// build tasks; only `is_crates_io` units may become tasks.
    pub is_crates_io: bool,
    /// Direct dependency edges of this unit.
    pub deps: Vec<StowDep>,
}

/// An edge from one unit to the unit that dep resolves to.
#[derive(Debug, Clone, Serialize)]
pub struct StowDep {
    /// The target unit's identity.
    #[serde(flatten)]
    pub key: StowUnitKey,
    /// Dependency crate name.
    pub name: String,
    /// Dependency crate version.
    pub version: String,
    /// The dep's manifest kind on this edge.
    pub dep_kind: DepKind,
}

/// `.cargo/config.toml` files inside the fetched tree, loaded the way
/// cargo's own config walk loads them: each ancestor directory of the
/// manifest is probed (`config.toml` preferred over `config`), files are
/// merged so the closest definition wins ties, and the result is installed
/// with [`GlobalContext::set_values`]. That makes `[source]` replacement,
/// `paths` overrides, `resolver.*` settings and `[target]`/`[build]`
/// rustflags behave exactly as a real `cargo metadata` run inside the
/// tree. Deliberately not consulted: user and `CARGO_HOME` config — the
/// resolve sees only what ships in the archive.
fn load_in_tree_config(gctx: &GlobalContext, manifest_dir: &Path) -> CargoResult<()> {
    let mut map: HashMap<String, CV> = HashMap::new();
    for dir in manifest_dir.ancestors() {
        for name in ["config.toml", "config"] {
            let file = dir.join(".cargo").join(name);
            if !fs::exists(&file) {
                continue;
            }
            let text = fs::read_to_string(&file)
                .with_context(|| format!("failed to read `{}`", file.display()))?;
            let toml = text
                .parse::<toml::Table>()
                .map(toml::Value::Table)
                .with_context(|| format!("could not parse TOML in `{}`", file.display()))?;
            let cv = CV::from_toml(Definition::Path(file.clone()), toml)?;
            let CV::Table(table, _) = cv else {
                bail!("expected a TOML table in `{}`", file.display());
            };
            // The file with the closest definition wins a primitive tie;
            // lists concatenate in walk order — `merge` already encodes
            // both rules via `Definition` priority.
            for (key, value) in table {
                match map.entry(key) {
                    std::collections::hash_map::Entry::Occupied(mut entry) => {
                        entry.get_mut().merge(value, false)?;
                    }
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(value);
                    }
                }
            }
            break;
        }
    }
    if map.is_empty() {
        return Ok(());
    }
    gctx.set_values(map)
}

/// `--cfg` flags inside an effective-rustflags list, parsed the way
/// `rustc --print cfg` would report them: `--cfg name` or
/// `--cfg name="value"` become `Cfg::Name`/`Cfg::KeyPair`. Every other
/// flag is ignored — only cfg definitions reach the resolve.
fn cfgs_from_rustflags(rustflags: &[String]) -> CargoResult<Vec<Cfg>> {
    let mut out = Vec::new();
    let mut iter = rustflags.iter();
    while let Some(flag) = iter.next() {
        let spec = if flag == "--cfg" {
            iter.next().map(String::as_str)
        } else {
            flag.strip_prefix("--cfg=")
        };
        if let Some(spec) = spec {
            // rustc's --cfg takes `name` or `name="value"`; the print-cfg
            // grammar is the same, and anything else fails the probe
            // identically.
            out.push(
                Cfg::from_str(spec).with_context(|| {
                    format!("invalid `--cfg {spec}` in rustflags configuration")
                })?,
            );
        }
    }
    Ok(out)
}

/// The injected-cfg map key for a compile kind — the host triple for
/// `Host`, the target's short name otherwise.
fn cfg_key(host_triple: &str, kind: CompileKind) -> String {
    match kind {
        CompileKind::Host => host_triple.to_string(),
        CompileKind::Target(target) => target.short_name().to_string(),
    }
}

/// Runs the full resolve: cargo's `metadata` output plus the per-side unit
/// graph described in the module docs.
pub async fn resolve(
    gctx: &GlobalContext,
    input: StowResolveInput,
) -> CargoResult<StowResolveOutput> {
    let rustc = Rustc::new_from_verbose_version(
        PathBuf::from("rustc"),
        input.rustc_verbose_version.clone(),
    )?;
    if rustc.host.as_str() != input.host_triple {
        anyhow::bail!(
            "injected rustc host `{}` does not match host_triple `{}`",
            rustc.host,
            input.host_triple
        );
    }
    gctx.set_rustc(rustc)?;

    // `.cargo/config.toml` in the fetched tree applies to everything below
    // (`[source]` replacement, `paths`, `resolver.*`, target rustflags) —
    // load it before any lazy config read can freeze `values` empty.
    let manifest_dir = input
        .manifest_path
        .parent()
        .expect("manifest_path points into the workspace")
        .to_path_buf();
    load_in_tree_config(gctx, &manifest_dir)?;

    // `rustc --print cfg` per kind, exactly as `TargetInfo::new` would read
    // from a live rustc; keyed `host`/`target <triple>` like CompileKind.
    let host_triple = input.host_triple.clone();
    let mut cfgs: HashMap<String, Vec<Cfg>> = HashMap::new();
    for (triple, lines) in &input.cfg {
        let parsed = lines
            .iter()
            .map(|line| Cfg::from_str(line))
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("invalid `rustc --print cfg` output for `{triple}`"))?;
        cfgs.insert(triple.clone(), parsed);
    }

    let requested_kinds = CompileKind::from_requested_targets_with_fallback(
        gctx,
        &input.filter_platforms,
        CompileKindFallback::JustHost,
    )?;

    // rustflags reach the resolver the way they reach a real `rustc
    // --print cfg` probe: upstream runs the probe with the effective
    // flags, so `--cfg` declarations from `[target]`/`[build]`/`[host]`
    // sections land in the cfg list. The two passes are cargo's own
    // fixed-point — `target.'cfg(...)'.rustflags` sections can add flags
    // whose keys only match once the first pass's cfgs exist.
    for kind in &requested_kinds {
        let key = cfg_key(&host_triple, *kind).to_string();
        let vendored = cfgs
            .get(&key)
            .cloned()
            .ok_or_else(|| anyhow!("no injected `rustc --print cfg` for `{key}` ({kind:?})"))?;
        let flags = crate::core::compiler::build_context::target_info::effective_rustflags(
            gctx,
            &requested_kinds,
            &host_triple,
            None,
            *kind,
        )?;
        let mut merged = vendored;
        merged.extend(cfgs_from_rustflags(&flags)?);
        let flags = crate::core::compiler::build_context::target_info::effective_rustflags(
            gctx,
            &requested_kinds,
            &host_triple,
            Some(&merged),
            *kind,
        )?;
        merged.extend(cfgs_from_rustflags(&flags)?);
        cfgs.insert(key, merged);
    }

    let cfg_source = {
        let host_triple = host_triple.clone();
        Rc::new(move |kind: CompileKind| -> CargoResult<Vec<Cfg>> {
            let key = cfg_key(&host_triple, kind);
            cfgs.get(&key)
                .cloned()
                .ok_or_else(|| anyhow!("no injected `rustc --print cfg` for `{key}` ({kind:?})"))
        })
    };

    let ws = Workspace::new(&input.manifest_path, gctx)?;
    let cli_features = CliFeatures::from_command_line(
        &input.features,
        input.all_features,
        !input.no_default_features,
    )?;
    let mut target_data = RustcTargetData::new_injected(&ws, &requested_kinds, cfg_source)?;

    let opt = OutputMetadataOptions {
        cli_features,
        no_deps: false,
        version: 1,
        filter_platforms: input.filter_platforms.clone(),
    };
    let (metadata, _ws_resolve) =
        cargo_output_metadata::output_metadata_with(&ws, &opt, &mut target_data, &requested_kinds)
            .await?;

    // The unit graph is `cargo build`'s: dev dependencies are not built, so
    // the per-side features and edges come from a second resolve without dev
    // units — metadata's resolve keeps them, because `cargo metadata`
    // reports them.
    // `cargo build` in a workspace builds the default members, and the unit
    // graph covers only what they pull in — the same spec set.
    let specs = Packages::Default.to_package_id_specs(&ws)?;
    let force_all = if input.filter_platforms.is_empty() {
        ForceAllTargets::Yes
    } else {
        ForceAllTargets::No
    };
    let dry_run = false;
    let build_resolve = ops::resolve_ws_with_opts(
        &ws,
        &mut target_data,
        &requested_kinds,
        &opt.cli_features,
        &specs,
        HasDevUnits::No,
        force_all,
        dry_run,
    )
    .await?;

    let (units, roots) = emit_units(
        &ws,
        &build_resolve,
        &requested_kinds,
        &host_triple,
        input.members_are_crates_io,
    )?;
    let has_binary = ws
        .members()
        .any(|member| member.targets().iter().any(|target| target.is_bin()));
    Ok(StowResolveOutput {
        metadata,
        units,
        roots,
        has_binary,
    })
}

/// Which side a `(pkg, fk)` feature set belongs to in the output.
fn side_of(fk: FeaturesFor) -> StowSide {
    match fk {
        FeaturesFor::NormalOrDev => StowSide::Target,
        FeaturesFor::HostDep => StowSide::Host,
        FeaturesFor::ArtifactDep(_) => StowSide::Artifact,
    }
}

/// The triple a `CompileKind` compiles on.
fn kind_triple(kind: &CompileKind, host_triple: &str) -> String {
    match kind {
        CompileKind::Host => host_triple.to_string(),
        CompileKind::Target(t) => t.short_name().to_string(),
    }
}

/// Builds the unit graph from the resolved per-side edges.
///
/// Platform derivation follows cargo's unit construction:
/// - a member's own `lib` compiles on the requested target — unless the member
///   is a proc-macro crate, whose lib compiles on the host;
/// - a dep edge lands on the host when the dep is a build dep or a proc-macro;
///   on the artifact target for `ArtifactDep`; otherwise on the parent unit's
///   platform (host propagates: deps of host units are host units);
/// - every package with a `build.rs` gets a host `CustomBuild` unit per side,
///   and its build-deps are that unit's edges, not the lib's — matching the
///   unit graph's `RunCustomBuild` wiring.
///
/// `Development` dep edges are dropped: they exist only for `cargo test`,
/// which stow never builds.
fn emit_units(
    ws: &Workspace<'_>,
    ws_resolve: &crate::ops::WorkspaceResolve<'_>,
    requested_kinds: &[CompileKind],
    host_triple: &str,
    members_are_crates_io: bool,
) -> CargoResult<(Vec<StowUnit>, Vec<StowUnitKey>)> {
    let package_map: BTreeMap<PackageId, _> = ws_resolve
        .pkg_set
        .packages()
        .map(|pkg| (pkg.package_id(), pkg))
        .collect();
    let pkg_by_id = |id: PackageId| -> CargoResult<&crate::core::Package> {
        package_map
            .get(&id)
            .copied()
            .ok_or_else(|| anyhow::format_err!("{id} was resolved but not downloaded"))
    };

    // Multiple `specs` entries each produce their own `ResolvedFeatures`;
    // union their activated sets and edges into one view.
    let mut all_features: HashMap<PackageFeaturesKey, BTreeSet<String>> = HashMap::new();
    let mut all_edges: HashMap<PackageFeaturesKey, Vec<SideEdge>> = HashMap::new();
    for spec_f in &ws_resolve.specs_and_features {
        for ((pkg, fk), feats) in spec_f.resolved_features.activated_features.iter() {
            all_features
                .entry((*pkg, *fk))
                .or_default()
                .extend(feats.iter().map(|f| f.to_string()));
        }
        for (key, edges) in &spec_f.edges {
            all_edges
                .entry(*key)
                .or_default()
                .extend(edges.iter().cloned());
        }
    }

    type UnitId = (PackageId, String, FeaturesFor);
    let mut visited: BTreeSet<UnitId> = BTreeSet::new();
    let mut units: Vec<StowUnit> = Vec::new();
    let mut roots: Vec<StowUnitKey> = Vec::new();
    let mut queue: VecDeque<UnitId> = VecDeque::new();
    // One build-script *compile* per distinct feature set — cargo shares it
    // across sides when the sides resolve to the same features, and emits a
    // second compile unit only when they differ. The run units are always
    // per-side.
    let mut compiles: HashMap<(PackageId, Vec<String>), StowUnitKey> = HashMap::new();

    fn seed(
        visited: &mut BTreeSet<UnitId>,
        queue: &mut VecDeque<UnitId>,
        roots: &mut Vec<StowUnitKey>,
        pkg_id: PackageId,
        platform: String,
        fk: FeaturesFor,
        is_member_lib: bool,
    ) -> CargoResult<()> {
        if !visited.insert((pkg_id, platform.clone(), fk)) {
            return Ok(());
        }
        queue.push_back((pkg_id, platform.clone(), fk));
        if is_member_lib {
            roots.push(StowUnitKey {
                pkg: pkg_id.to_spec(),
                platform,
                side: side_of(fk),
                kind: StowUnitKind::Lib,
            });
        }
        Ok(())
    }

    for member in ws.default_members() {
        let member_id = member.package_id();
        // cargo's unit graph keys a proc-macro member's lib on the host
        // with its `HostDep` features — `do_resolve` activates that side
        // whenever the resolver tracks a host split. Only the lib target's
        // `proc-macro` flag counts: a proc-macro example or test never
        // changes where the lib compiles. A resolve that unified
        // everything (host tracking off) reports the same features under
        // the normal side.
        let proc_macro_lib = member.library().is_some_and(|t| t.proc_macro());
        let host_side_active = all_features.contains_key(&(member_id, FeaturesFor::HostDep))
            || all_edges.contains_key(&(member_id, FeaturesFor::HostDep));
        let (platform, fk) = if proc_macro_lib {
            (
                host_triple.to_string(),
                if host_side_active {
                    FeaturesFor::HostDep
                } else {
                    FeaturesFor::NormalOrDev
                },
            )
        } else {
            // A lib member compiles once per requested kind; without a lib
            // target the member still seeds the graph (its bin/example units
            // are intentionally absent — binaries are not units in stow).
            (
                match requested_kinds.first() {
                    Some(kind) => kind_triple(kind, host_triple),
                    None => host_triple.to_string(),
                },
                FeaturesFor::NormalOrDev,
            )
        };
        seed(
            &mut visited,
            &mut queue,
            &mut roots,
            member_id,
            platform.clone(),
            fk,
            member.library().is_some(),
        )?;
        // A member bin-only package still resolves deps for every requested
        // kind; seed the remaining kinds without emitting roots.
        for kind in requested_kinds.iter().skip(1) {
            seed(
                &mut visited,
                &mut queue,
                &mut roots,
                member_id,
                kind_triple(kind, host_triple),
                FeaturesFor::NormalOrDev,
                false,
            )?;
        }
    }

    while let Some((pkg_id, platform, fk)) = queue.pop_front() {
        let pkg = pkg_by_id(pkg_id)?;
        let features: Vec<String> = all_features
            .get(&(pkg_id, fk))
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default();
        let edges: &[SideEdge] = all_edges
            .get(&(pkg_id, fk))
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let side = side_of(fk);

        // Partition dep edges the way cargo's unit construction does: normal
        // deps feed the lib unit; build deps feed the build-script compile
        // unit, and only exist at all when the package has a build script
        // (a proc-macro without `build.rs` never compiles its declared
        // build-deps); dev deps never exist in `cargo build`'s graph.
        let mut lib_deps = Vec::new();
        let mut build_deps = Vec::new();
        let mut run_deps = Vec::new();
        let has_custom_build = pkg.has_custom_build();
        for edge in edges {
            if edge.dep_kind == DepKind::Development {
                continue;
            }
            if edge.dep_kind == DepKind::Build && !has_custom_build {
                continue;
            }
            let (dep_id, dep_fk) = edge.to;
            let dep_platform = dep_platform(&platform, edge, dep_fk, host_triple);
            let dep_pkg = pkg_by_id(dep_id)?;
            let dep = StowDep {
                key: StowUnitKey {
                    pkg: dep_id.to_spec(),
                    platform: dep_platform.clone(),
                    side: side_of(dep_fk),
                    kind: StowUnitKind::Lib,
                },
                name: dep_id.name().to_string(),
                version: dep_id.version().to_string(),
                dep_kind: edge.dep_kind,
            };
            if edge.dep_kind == DepKind::Build {
                build_deps.push(dep);
            } else {
                // `run-custom-build` units depend on the run units of sibling
                // deps that declare `links` — build script outputs of
                // linkable deps feed the dependent's build script.
                let links_dep = dep_pkg.manifest().links().is_some()
                    && dep_pkg.library().is_some_and(|t| t.is_linkable());
                if links_dep {
                    run_deps.push(StowDep {
                        key: StowUnitKey {
                            pkg: dep_id.to_spec(),
                            platform: dep_platform.clone(),
                            side: side_of(dep_fk),
                            kind: StowUnitKind::RunBuildScript,
                        },
                        name: dep_id.name().to_string(),
                        version: dep_id.version().to_string(),
                        dep_kind: edge.dep_kind,
                    });
                }
                lib_deps.push(dep);
            }
            seed(
                &mut visited,
                &mut queue,
                &mut roots,
                dep_id,
                dep_platform,
                dep_fk,
                false,
            )?;
        }

        let is_crates_io =
            pkg_id.source_id().is_crates_io() || (members_are_crates_io && ws.is_member_id(pkg_id));
        let push_unit = |platform: String, kind: StowUnitKind, deps: Vec<StowDep>| StowUnit {
            key: StowUnitKey {
                pkg: pkg_id.to_spec(),
                platform,
                side,
                kind,
            },
            name: pkg_id.name().to_string(),
            version: pkg_id.version().to_string(),
            unit_kind: kind,
            features: features.clone(),
            is_crates_io,
            deps,
        };

        if has_custom_build {
            // lib -> run -> compile, as cargo's `run-custom-build` wiring;
            // the run also follows the run of each links-bearing dep.
            let is_new = !compiles.contains_key(&(pkg_id, features.clone()));
            let build_key = compiles
                .entry((pkg_id, features.clone()))
                .or_insert_with(|| StowUnitKey {
                    pkg: pkg_id.to_spec(),
                    platform: host_triple.to_string(),
                    side,
                    kind: StowUnitKind::BuildScript,
                })
                .clone();
            let mut run_dep_list = vec![StowDep {
                key: build_key.clone(),
                name: pkg_id.name().to_string(),
                version: pkg_id.version().to_string(),
                dep_kind: DepKind::Build,
            }];
            run_dep_list.extend(run_deps);
            units.push(push_unit(
                platform.clone(),
                StowUnitKind::RunBuildScript,
                run_dep_list,
            ));
            if is_new {
                units.push(push_unit(
                    host_triple.to_string(),
                    StowUnitKind::BuildScript,
                    build_deps,
                ));
            }
            lib_deps.push(StowDep {
                key: StowUnitKey {
                    pkg: pkg_id.to_spec(),
                    platform: platform.clone(),
                    side,
                    kind: StowUnitKind::RunBuildScript,
                },
                name: pkg_id.name().to_string(),
                version: pkg_id.version().to_string(),
                dep_kind: DepKind::Build,
            });
        }
        if pkg.library().is_some() {
            units.push(push_unit(platform, StowUnitKind::Lib, lib_deps));
        }
    }

    units.sort_by(|a, b| a.key.cmp(&b.key));
    Ok((units, roots))
}

/// The platform a dep edge lands on.
fn dep_platform(
    parent_platform: &str,
    edge: &SideEdge,
    dep_fk: FeaturesFor,
    host_triple: &str,
) -> String {
    if edge.dep_kind == DepKind::Build || edge.proc_macro {
        host_triple.to_string()
    } else if let FeaturesFor::ArtifactDep(target) = dep_fk {
        target.short_name().to_string()
    } else {
        parent_platform.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rustc_data;
    use crate::sources::SourceConfigMap;
    use crate::util::context::StringList;
    use crate::util::context::environment::Env;
    use crate::util::fs::{MemoryVfs, set_vfs};
    use crate::util::shell::Shell;

    /// The resolve refuses to start when the injected `rustc`'s host is not
    /// the runner-family host — so every family host needs a real `-vV`
    /// vendored, and every CI target its `cfg`.
    #[test]
    fn vendored_rustc_data_covers_every_family() {
        const PIN: &str = "1.98.1";
        let families: &[(&str, &[&str])] = &[
            (
                "x86_64-unknown-linux-gnu",
                &[
                    "aarch64-linux-android",
                    "x86_64-unknown-linux-gnu",
                    "aarch64-unknown-linux-gnu",
                    "wasm32-unknown-unknown",
                ],
            ),
            (
                "aarch64-apple-darwin",
                &[
                    "aarch64-apple-darwin",
                    "aarch64-apple-ios",
                    "aarch64-apple-ios-sim",
                ],
            ),
            (
                "x86_64-pc-windows-msvc",
                &["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"],
            ),
        ];
        for (host, targets) in families {
            assert!(
                rustc_data::verbose_version(PIN, host).is_some(),
                "no vendored `rustc -vV` for {host}"
            );
            for target in targets.iter() {
                assert!(
                    rustc_data::cfg(PIN, target).is_some(),
                    "no vendored `rustc --print cfg` for {target}"
                );
            }
        }
    }

    fn test_gctx(cwd: &str) -> GlobalContext {
        GlobalContext::new_for_resolve(
            PathBuf::from(cwd),
            PathBuf::from("/home/user"),
            Shell::new(),
            Env::new(),
            true,
        )
        .expect("gctx")
    }

    /// `.cargo/config.toml` inside the fetched tree configures the resolve
    /// through cargo's own merge rules: `build.rustflags`,
    /// `[target.'cfg()'.rustflags]`, `[source]` replacement, `paths`
    /// overrides and `resolver.*` all land in the gctx's value map — and
    /// the walk reads them from the VFS, so a Worker sees them too.
    #[test]
    fn in_tree_config_loads_through_vfs() {
        // An absolute root is required: `directory` sources build a
        // `file:///` url out of it, which rejects a drive-less path on
        // Windows (`\repo` has no root).
        let repo: &str = if cfg!(windows) { "C:/repo" } else { "/repo" };
        let vfs = Rc::new(MemoryVfs::new());
        set_vfs(vfs.clone());
        vfs.insert(
            Path::new(repo).join(".cargo/config.toml"),
            format!(
                r#"
paths = ["{repo}/patches/ser"]

[build]
rustflags = ["--cfg", "stow_fixture_cfg"]

[target.'cfg(unix)']
rustflags = ["--cfg", "unix_cfg"]

[resolver]
incompatible-rust-versions = "fallback"

[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
"#
            ),
        );
        let gctx = test_gctx(repo);
        load_in_tree_config(&gctx, Path::new(repo)).unwrap();

        let rustflags = gctx
            .get::<Option<StringList>>("build.rustflags")
            .unwrap()
            .expect("build.rustflags");
        assert_eq!(rustflags.as_slice(), ["--cfg", "stow_fixture_cfg"]);

        let target_cfgs = gctx.target_cfgs().unwrap();
        assert_eq!(
            target_cfgs
                .iter()
                .map(|(k, _)| k.as_str())
                .collect::<Vec<_>>(),
            ["cfg(unix)"]
        );

        let resolver = gctx
            .get::<Option<String>>("resolver.incompatible-rust-versions")
            .unwrap();
        assert_eq!(resolver.as_deref(), Some("fallback"));

        let paths = gctx.paths_overrides().unwrap().expect("paths override");
        assert_eq!(paths.val.len(), 1);
        assert_eq!(paths.val[0].0, PathBuf::from(repo).join("patches/ser"));

        // `[source.crates-io] replace-with` reaches the source map: the
        // registry SourceId now loads the `vendor/` directory source.
        let sources = SourceConfigMap::new(&gctx).unwrap();
        let crates_io = gctx.crates_io_source_id().unwrap();
        let source = sources.load(crates_io).unwrap();
        assert!(
            !source.replaced_source_id().is_registry(),
            "crates.io should resolve to the vendored-sources directory"
        );
    }

    /// Deliberately not loaded: `$CARGO_HOME/.cargo` (and the user's home
    /// config). A resolve reads the fetched tree only — the worker's own
    /// files never influence it.
    #[test]
    fn user_config_is_not_loaded() {
        let vfs = Rc::new(MemoryVfs::new());
        set_vfs(vfs.clone());
        vfs.insert(
            "/home/user/.cargo/config.toml",
            br#"
[build]
rustflags = ["--cfg", "user_cfg"]
"#,
        );
        let gctx = test_gctx("/repo");
        load_in_tree_config(&gctx, Path::new("/repo")).unwrap();
        assert!(
            gctx.get::<Option<StringList>>("build.rustflags")
                .unwrap()
                .is_none(),
            "CARGO_HOME config must not reach the resolve"
        );
    }

    /// The closest `.cargo/config.toml` to the manifest wins a primitive
    /// tie — cargo's document-merged order, reproduced over the VFS.
    #[test]
    fn nearest_config_wins() {
        let vfs = Rc::new(MemoryVfs::new());
        set_vfs(vfs.clone());
        vfs.insert("/repo/.cargo/config.toml", "[build]\njobs = 4\n");
        vfs.insert("/repo/workspace/.cargo/config.toml", "[build]\njobs = 8\n");
        let gctx = test_gctx("/repo/workspace");
        load_in_tree_config(&gctx, Path::new("/repo/workspace")).unwrap();
        assert_eq!(gctx.get::<Option<u32>>("build.jobs").unwrap(), Some(8));
    }
}
