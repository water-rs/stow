//! The selection half of `resolve_ws_with_opts` — the vendored
//! `ops::resolve` ported onto the published `cargo` crate, synchronous
//! throughout: cargo 0.99's `resolver::resolve`, `PackageRegistry::patch`,
//! and `PackageSet::download_accessible` all drive their async pieces
//! internally.
//!
//! The one seam upstream does not expose is the yanked whitelist: the
//! vendored tree carries `PackageRegistry::add_to_yanked_whitelist`, so
//! here a [`WhitelistRegistry`] wrapper rewrites `IndexSummary::Yanked` to
//! `Candidate` for the whitelisted ids during `resolver::resolve`'s
//! queries — admission only, exactly the vendored placement.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use cargo::CargoResult;
use cargo::core::compiler::{CompileKind, RustcTargetData};
use cargo::core::dependency::Dependency;
use cargo::core::registry::{LockedPatchDependency, PackageRegistry, Registry};
use cargo::core::resolver::features::{
    CliFeatures, FeatureOpts, FeatureResolver, ForceAllTargets, HasDevUnits, RequestedFeatures,
};
use cargo::core::resolver::{
    self, PublishAgePolicy, Resolve, ResolveOpts, ResolveVersion, VersionOrdering,
    VersionPreferences,
};
use cargo::core::summary::Summary;
use cargo::core::{
    GitReference, PackageId, PackageIdSpec, PackageIdSpecQuery, PackageSet, SourceId, Workspace,
};
use cargo::ops;
use cargo::ops::Packages;
use cargo::sources::registry::IndexSummary;
use cargo::sources::source::QueryKind;
use cargo::util::CanonicalUrl;
use cargo::util::cache_lock::CacheLockMode;
use cargo::util::context::FeatureUnification;
use cargo_util_schemas::core::PartialVersion;
use cargo_util_terminal::report::{Group, Level};
use tracing::{debug, trace};

use crate::edges::{EdgeOpts, edges};
use crate::units::SpecsAndResolvedFeatures;

/// `ops::resolve::Keep`.
type Keep<'a> = &'a dyn Fn(&PackageId) -> bool;

const UNUSED_PATCH_WARNING: &str = "\
Check that the patched package version and available features are compatible
with the dependency requirements. If the patch has a different version from
what is locked in the Cargo.lock file, run `cargo update` to use the new
version. This may also occur with an optional dependency that is not enabled.";

/// The registry a dropped lockfile's pins pass through: ids the project
/// itself once locked are admissible even though the index marks them
/// yanked. Delegates everything else to the real `PackageRegistry`
/// (`describe_source`/`is_replaced` included — `RegistryQueryer` calls
/// them for error context).
struct WhitelistRegistry<'a, 'gctx> {
    inner: &'a PackageRegistry<'gctx>,
    whitelist: HashSet<PackageId>,
}

impl Registry for WhitelistRegistry<'_, '_> {
    // `Registry::query` is cargo's single-threaded contract — the
    // future borrows `f` and never crosses a thread boundary.
    #[allow(clippy::future_not_send)]
    async fn query(
        &self,
        dep: &Dependency,
        kind: QueryKind,
        f: &mut dyn FnMut(IndexSummary),
    ) -> CargoResult<()> {
        let whitelist = &self.whitelist;
        self.inner
            .query(dep, kind, &mut |summary| {
                match summary {
                    // A whitelisted version — one the project's own
                    // lockfile pins — is admissible even though yanked.
                    IndexSummary::Yanked(summary) if whitelist.contains(&summary.package_id()) => {
                        f(IndexSummary::Candidate(summary));
                    }
                    summary => f(summary),
                }
            })
            .await
    }

    fn describe_source(&self, source: SourceId) -> String {
        self.inner.describe_source(source)
    }

    fn is_replaced(&self, source: SourceId) -> bool {
        self.inner.is_replaced(source)
    }
}

/// The target-independent half of [`select_ws_with_opts`] — everything up
/// to package accessibility: the feature-unification split, the registry,
/// the version search, and the resolved package set. Targets only enter
/// through [`Self::project`], so a multi-target caller selects once and
/// projects once per target instead of repeating the search.
///
/// [`ops::get_resolved_packages`] consumes the [`PackageRegistry`] that
/// issued the version-selection queries, so by construction nothing after
/// this point can query the index again.
pub struct ResolveSelection<'gctx> {
    /// Packages to be downloaded.
    pub pkg_set: PackageSet<'gctx>,
    /// The resolve for the entire workspace.
    ///
    /// This may be `None` for things like `cargo install` and
    /// `-Zavoid-dev-deps`. This does not include `paths` overrides.
    /// Kept for parity with upstream's `get_resolved_packages` — nothing
    /// in this crate reads it (no lockfile is written).
    #[expect(dead_code)]
    pub workspace_resolve: Option<Resolve>,
    /// The narrowed resolve, with the specific features enabled.
    pub targeted_resolve: Resolve,
    /// The workspace's feature unification mode — drives the per-specs
    /// feature narrowing in [`Self::project`].
    feature_unification: FeatureUnification,
    /// Specs grouped by feature unification — one `FeatureResolver` pass
    /// per group.
    individual_specs: Vec<Vec<PackageIdSpec>>,
    /// `Workspace::members_with_features` for the flattened specs, kept
    /// for the `FeatureUnification::Package` narrowing.
    members_with_features: Vec<(PackageId, CliFeatures)>,
    /// Resolved workspace member ids.
    member_ids: Vec<PackageId>,
    /// The `HasDevUnits` this selection was computed with — projections
    /// inherit it.
    has_dev_units: HasDevUnits,
}

impl<'gctx> ResolveSelection<'gctx> {
    /// The per-target half of `resolve_ws_with_opts`: downloads the
    /// packages accessible under `requested_targets`, then runs the
    /// feature resolver for each spec group. May be called once per
    /// target; the shared [`PackageSet`] dedupes packages an earlier
    /// projection already fetched.
    pub fn project(
        &self,
        ws: &Workspace<'gctx>,
        target_data: &mut RustcTargetData<'gctx>,
        requested_targets: &[CompileKind],
        cli_features: &CliFeatures,
        force_all_targets: ForceAllTargets,
    ) -> CargoResult<Vec<SpecsAndResolvedFeatures>> {
        let resolved_with_overrides = &self.targeted_resolve;
        let pkg_set = &self.pkg_set;

        pkg_set.download_accessible(
            resolved_with_overrides,
            &self.member_ids,
            self.has_dev_units,
            requested_targets,
            target_data,
            force_all_targets,
        )?;

        let mut specs_and_features = Vec::new();

        for specs in &self.individual_specs {
            let feature_opts = FeatureOpts::new(ws, self.has_dev_units, force_all_targets)?;

            // Narrow the features to the current specs — the same
            // FeatureUnification::Package logic as upstream.
            let narrowed_features = match self.feature_unification {
                FeatureUnification::Package => {
                    let mut narrowed_features = cli_features.clone();
                    let enabled_features = self
                        .members_with_features
                        .iter()
                        .filter_map(|(package_id, cli_features)| {
                            specs
                                .iter()
                                .any(|spec| spec.matches(*package_id))
                                .then_some(cli_features.features.iter())
                        })
                        .flatten()
                        .cloned()
                        .collect();
                    narrowed_features.features = Rc::new(enabled_features);
                    std::borrow::Cow::Owned(narrowed_features)
                }
                FeatureUnification::Selected | FeatureUnification::Workspace => {
                    std::borrow::Cow::Borrowed(cli_features)
                }
            };

            let resolved_features = FeatureResolver::resolve(
                ws,
                target_data,
                resolved_with_overrides,
                pkg_set,
                &narrowed_features,
                specs,
                requested_targets,
                feature_opts,
            )?;

            let edge_opts = EdgeOpts::new(ws, self.has_dev_units, force_all_targets)?;
            let resolved_edges = edges(
                ws,
                target_data,
                resolved_with_overrides,
                pkg_set,
                &resolved_features,
                requested_targets,
                edge_opts,
            )?;

            specs_and_features.push(SpecsAndResolvedFeatures {
                specs: specs.clone(),
                resolved_features,
                edges: resolved_edges,
            });
        }
        Ok(specs_and_features)
    }
}

/// Resolves dependencies for some packages of the workspace, taking into
/// account `paths` overrides and activated features — the selection half
/// of `resolve_ws_with_opts`, split out so a caller can run it once and
/// [`ResolveSelection::project`] per target.
///
/// `dropped_lockfile` is the contents of a `Cargo.lock` the caller
/// deleted from the project tree: its registry pins go to the resolve's
/// yanked whitelist (admission only, never preference) and each of its
/// git pins locks the git dep to the pinned sha via
/// [`PackageRegistry::register_lock`] — the semantics the vendored
/// resolver's `dropped_lockfile` input carries.
#[allow(clippy::too_many_lines)] // one resolve pipeline; kept in the upstream's shape
pub fn select_ws_with_opts<'gctx>(
    ws: &Workspace<'gctx>,
    cli_features: &CliFeatures,
    specs: &[PackageIdSpec],
    has_dev_units: HasDevUnits,
    dry_run: bool,
    dropped_lockfile: Option<&str>,
) -> CargoResult<ResolveSelection<'gctx>> {
    let feature_unification = ws.resolve_feature_unification();
    let individual_specs = match feature_unification {
        FeatureUnification::Selected => vec![specs.to_owned()],
        FeatureUnification::Workspace => {
            vec![Packages::All(Vec::new()).to_package_id_specs(ws)?]
        }
        FeatureUnification::Package => specs.iter().map(|spec| vec![spec.clone()]).collect(),
    };
    let specs: Vec<_> = individual_specs.iter().flatten().cloned().collect();
    let specs = &specs[..];
    let mut registry = ws.package_registry()?;

    let whitelist = match dropped_lockfile {
        Some(contents) => {
            let ids = crate::lockfile::lockfile_package_ids(contents)?;
            // Registry pins go to the yanked whitelist; git pins lock the
            // git dep to its sha. Registering anything else would be
            // wrong: `lock()` rewrites a registered node's deps to the
            // lockfile's versions too.
            let whitelist: HashSet<PackageId> = ids
                .iter()
                .copied()
                .filter(|id| id.source_id().is_registry())
                .collect();
            for (node, deps) in crate::lockfile::lockfile_git_pins(contents)? {
                registry.register_lock(node, deps);
            }
            whitelist
        }
        None => HashSet::new(),
    };

    let (resolve, resolved_with_overrides) = if ws.ignore_lock() {
        let add_patches = true;
        let resolve = None;
        let resolved_with_overrides = resolve_with_previous(
            &mut registry,
            ws,
            cli_features,
            has_dev_units,
            resolve.as_ref(),
            None,
            specs,
            add_patches,
            &whitelist,
        )?;
        ops::print_lockfile_changes(ws, None, &resolved_with_overrides, &mut registry)?;
        (resolve, resolved_with_overrides)
    } else if ws.require_optional_deps() {
        // First, resolve the root_package's *listed* dependencies, as well as
        // downloading and updating all remotes and such.
        let resolve = resolve_with_registry(ws, &mut registry, dry_run, &whitelist)?;
        // No need to add patches again, `resolve_with_registry` has done it.
        let add_patches = false;

        // Second, resolve with precisely what we're doing. Filter out
        // transitive dependencies if necessary, specify features, handle
        // overrides, etc.
        ops::add_overrides(&mut registry, ws)?;

        for (replace_spec, dep) in ws.root_replace() {
            if !resolve
                .iter()
                .any(|r| replace_spec.matches(r) && !dep.matches_id(r))
            {
                ws.gctx()
                    .shell()
                    .warn(format!("package replacement is not used: {replace_spec}"))?;
            }

            let mut unused_fields = Vec::new();
            if !dep.features().is_empty() {
                unused_fields.push("`features`");
            }
            if !dep.uses_default_features() {
                unused_fields.push("`default-features`");
            }
            if !unused_fields.is_empty() {
                ws.gctx().shell().print_report(
                    &[Level::WARNING
                        .secondary_title(format!(
                            "unused field in replacement for `{}`: {}",
                            dep.package_name(),
                            unused_fields.join(", ")
                        ))
                        .element(Level::NOTE.message(format!(
                            "configure {} in the `dependencies` entry",
                            unused_fields.join(", ")
                        )))],
                    false,
                )?;
            }
        }

        let resolved_with_overrides = resolve_with_previous(
            &mut registry,
            ws,
            cli_features,
            has_dev_units,
            Some(&resolve),
            None,
            specs,
            add_patches,
            &whitelist,
        )?;
        (Some(resolve), resolved_with_overrides)
    } else {
        let add_patches = true;
        let resolve = ops::load_pkg_lockfile(ws)?;
        let resolved_with_overrides = resolve_with_previous(
            &mut registry,
            ws,
            cli_features,
            has_dev_units,
            resolve.as_ref(),
            None,
            specs,
            add_patches,
            &whitelist,
        )?;
        // Skipping `print_lockfile_changes` as there are cases where this prints irrelevant
        // information
        (resolve, resolved_with_overrides)
    };

    let pkg_set = ops::get_resolved_packages(&resolved_with_overrides, registry)?;

    let members_with_features = ws
        .members_with_features(specs, cli_features)?
        .into_iter()
        .map(|(package, cli_features)| (package.package_id(), cli_features))
        .collect::<Vec<_>>();
    let member_ids = members_with_features
        .iter()
        .map(|(package_id, _fts)| *package_id)
        .collect::<Vec<_>>();

    Ok(ResolveSelection {
        pkg_set,
        workspace_resolve: resolve,
        targeted_resolve: resolved_with_overrides,
        feature_unification,
        individual_specs,
        members_with_features,
        member_ids,
        has_dev_units,
    })
}

/// `ops::resolve_with_registry`, verbatim: resolves the root package's
/// listed dependencies, loading the lockfile as the previous resolve.
fn resolve_with_registry<'gctx>(
    ws: &Workspace<'gctx>,
    registry: &mut PackageRegistry<'gctx>,
    dry_run: bool,
    whitelist: &HashSet<PackageId>,
) -> CargoResult<Resolve> {
    let prev = ops::load_pkg_lockfile(ws)?;
    let mut resolve = resolve_with_previous(
        registry,
        ws,
        &CliFeatures::new_all(true),
        HasDevUnits::Yes,
        prev.as_ref(),
        None,
        &[],
        true,
        whitelist,
    )?;

    let print = if !ws.is_ephemeral() && ws.require_optional_deps() {
        if dry_run {
            true
        } else {
            ops::write_pkg_lockfile(ws, &mut resolve)?
        }
    } else {
        // This mostly represents
        // - `cargo install --locked` and the only change is the package is no longer local but
        //   from the registry which is noise
        // - publish of libraries
        false
    };
    if print {
        ops::print_lockfile_changes(ws, prev.as_ref(), &resolve, registry)?;
    }
    Ok(resolve)
}

/// `ops::resolve_with_previous`, verbatim except the registry passes
/// through [`WhitelistRegistry`] for the `resolver::resolve` call — the
/// only place upstream's `PackageRegistry` can't be wrapped otherwise.
#[tracing::instrument(skip_all)]
#[allow(clippy::too_many_arguments)]
fn resolve_with_previous<'gctx>(
    registry: &mut PackageRegistry<'gctx>,
    ws: &Workspace<'gctx>,
    cli_features: &CliFeatures,
    has_dev_units: HasDevUnits,
    previous: Option<&Resolve>,
    keep_previous: Option<Keep<'_>>,
    specs: &[PackageIdSpec],
    register_patches: bool,
    whitelist: &HashSet<PackageId>,
) -> CargoResult<Resolve> {
    // We only want one Cargo at a time resolving a crate graph since this can
    // involve a lot of frobbing of the global caches.
    let _lock = ws
        .gctx()
        .acquire_package_cache_lock(CacheLockMode::DownloadExclusive)?;

    // Some packages are already loaded when setting up a workspace. This
    // makes it so anything that was already loaded will not be loaded again.
    // Without this there were cases where members would be parsed multiple times
    ws.preload(registry);

    // In case any members were not already loaded or the Workspace is_ephemeral.
    for member in ws.members() {
        registry.add_sources(Some(member.package_id().source_id()))?;
    }

    // Try to keep all from previous resolve if no instruction given.
    let keep_previous = keep_previous.unwrap_or(&|_| true);

    // While registering patches, we will record preferences for particular versions
    // of various packages.
    let mut version_prefs = VersionPreferences::default();
    if ws.gctx().cli_unstable().minimal_versions {
        version_prefs.version_ordering(VersionOrdering::MinimumVersionsFirst);
    }
    if ws.resolve_honors_rust_version() {
        let mut rust_versions: Vec<_> = ws
            .members()
            .filter_map(|p| {
                p.rust_version()
                    .map(cargo_util_schemas::manifest::RustVersion::to_partial)
            })
            .collect();
        if rust_versions.is_empty() {
            let rustc = ws.gctx().load_global_rustc(Some(ws))?;
            let rust_version: PartialVersion = rustc.version.into();
            rust_versions.push(rust_version);
        }
        version_prefs.rust_versions(rust_versions);
    }
    if let Some(publish_time) = ws.resolve_publish_time() {
        version_prefs.publish_time(publish_time);
    }
    if ws.resolve_honors_publish_age()
        && let Some(policy) = PublishAgePolicy::new(ws.gctx())?
    {
        version_prefs.publish_age(policy);
    }

    let avoid_patch_ids = if register_patches {
        register_patch_entries(registry, ws, previous, &mut version_prefs, keep_previous)?
    } else {
        HashSet::new()
    };

    // Refine `keep` with patches that should avoid locking.
    let keep = |p: &PackageId| keep_previous(p) && !avoid_patch_ids.contains(p);

    let dev_deps = ws.require_optional_deps() || has_dev_units == HasDevUnits::Yes;

    if let Some(r) = previous {
        trace!("previous: {:?}", r);

        // In the case where a previous instance of resolve is available, we
        // want to lock as many packages as possible to the previous version
        // without disturbing the graph structure.
        register_previous_locks(ws, registry, r, &keep, dev_deps);

        // Prefer to use anything in the previous lock file, aka we want to have conservative updates.
        let _span = tracing::span!(tracing::Level::TRACE, "prefer_package_id").entered();
        for id in r.iter().filter(keep) {
            debug!("attempting to prefer {}", id);
            version_prefs.prefer_package_id(id);
        }
    }

    if register_patches {
        registry.lock_patches();
    }

    let summaries: Vec<(Summary, ResolveOpts)> = {
        let _span = tracing::span!(tracing::Level::TRACE, "registry.lock").entered();
        ws.members_with_features(specs, cli_features)?
            .into_iter()
            .map(|(member, features)| {
                let summary = registry.lock(member.summary().clone());
                (
                    summary,
                    ResolveOpts {
                        dev_deps,
                        features: RequestedFeatures::CliFeatures(features),
                    },
                )
            })
            .collect()
    };

    let replace = lock_replacements(ws, previous, &keep);

    let mut resolved = {
        let whitelist_registry = WhitelistRegistry {
            inner: registry,
            whitelist: whitelist.clone(),
        };
        resolver::resolve(
            &summaries,
            &replace,
            &whitelist_registry,
            &version_prefs,
            ResolveVersion::with_rust_version(ws.lowest_rust_version()),
            Some(ws.gctx()),
        )?
    };

    let patches = registry.patches().values().flat_map(|v| v.iter());
    resolved.register_used_patches(patches);

    if register_patches && !resolved.unused_patches().is_empty() {
        emit_warnings_of_unused_patches(ws, &resolved, registry)?;
    }

    if let Some(previous) = previous {
        resolved.merge_from(previous)?;
    }
    let gctx = ws.gctx();
    let mut deferred = gctx.deferred_global_last_use()?;
    deferred.save_no_error(gctx);
    drop(deferred);
    Ok(resolved)
}

/// `ops::register_previous_locks`, verbatim.
#[tracing::instrument(skip_all)]
fn register_previous_locks(
    ws: &Workspace<'_>,
    registry: &mut PackageRegistry<'_>,
    resolve: &Resolve,
    keep: Keep<'_>,
    dev_deps: bool,
) {
    let path_pkg = |id: SourceId| {
        if !id.is_path() {
            return None;
        }
        if let Ok(path) = id.url().to_file_path()
            && let Ok(pkg) = ws.load(&path.join("Cargo.toml"))
        {
            return Some(pkg);
        }
        None
    };

    // See upstream for the full commentary on the `avoid_locking` rules.
    let mut avoid_locking = HashSet::new();
    for node in resolve.iter() {
        if !keep(&node) {
            add_deps(resolve, node, &mut avoid_locking);
        }
    }

    {
        let _span = tracing::span!(tracing::Level::TRACE, "poison").entered();
        let mut path_deps = ws.members().cloned().collect::<Vec<_>>();
        let mut visited = HashSet::new();
        while let Some(member) = path_deps.pop() {
            if !visited.insert(member.package_id()) {
                continue;
            }
            let is_ws_member = ws.is_member(&member);
            for dep in member.dependencies() {
                if !is_ws_member && (dep.is_optional() || !dep.is_transitive()) {
                    continue;
                }
                if !dep.is_transitive() && !dev_deps {
                    continue;
                }
                if let Some(pkg) = path_pkg(dep.source_id()) {
                    path_deps.push(pkg);
                    continue;
                }
                if resolve.iter().any(|id| dep.matches_ignoring_source(id)) {
                    continue;
                }
                debug!(
                    "poisoning {} because {} looks like it changed {}",
                    dep.source_id(),
                    member.package_id(),
                    dep.package_name()
                );
                for id in resolve
                    .iter()
                    .filter(|id| id.source_id() == dep.source_id())
                {
                    add_deps(resolve, id, &mut avoid_locking);
                }
            }
        }
    }

    for node in resolve.iter() {
        if let Some(pkg) = path_pkg(node.source_id())
            && pkg.package_id() != node
        {
            avoid_locking.insert(node);
        }
    }

    let keep = |id: &PackageId| keep(id) && !avoid_locking.contains(id);

    registry.clear_lock();
    {
        let _span = tracing::span!(tracing::Level::TRACE, "register_lock").entered();
        for node in resolve.iter().filter(keep) {
            let deps = resolve
                .deps_not_replaced(node)
                .map(|p| p.0)
                .filter(keep)
                .collect::<Vec<_>>();

            if let Some(node) = master_branch_git_source(node, resolve) {
                registry.register_lock(node, deps.clone());
            }

            registry.register_lock(node, deps);
        }
    }

    /// Recursively add `node` and all its transitive dependencies to `set`.
    fn add_deps(resolve: &Resolve, node: PackageId, set: &mut HashSet<PackageId>) {
        if !set.insert(node) {
            return;
        }
        debug!("ignoring any lock pointing directly at {}", node);
        for (dep, _) in resolve.deps_not_replaced(node) {
            add_deps(resolve, dep, set);
        }
    }
}

/// `ops::master_branch_git_source`, verbatim.
fn master_branch_git_source(id: PackageId, resolve: &Resolve) -> Option<PackageId> {
    if resolve.version() <= ResolveVersion::V2 {
        let source = id.source_id();
        if matches!(source.git_reference(), Some(GitReference::DefaultBranch)) {
            let new_source =
                SourceId::for_git(source.url(), GitReference::Branch("master".to_string()))
                    .unwrap()
                    .with_precise_from(source);
            return Some(id.with_source_id(new_source));
        }
    }
    None
}

/// `ops::emit_warnings_of_unused_patches`, verbatim.
fn emit_warnings_of_unused_patches(
    ws: &Workspace<'_>,
    resolve: &Resolve,
    registry: &PackageRegistry<'_>,
) -> CargoResult<()> {
    const MESSAGE: &str = "was not used in the crate graph";

    // Patch package with the source URLs being patch
    let mut patch_pkgid_to_urls = HashMap::new();
    for (url, summaries) in registry.patches() {
        for summary in summaries {
            patch_pkgid_to_urls
                .entry(summary.package_id())
                .or_insert_with(HashSet::new)
                .insert(url);
        }
    }

    // pkg name -> all source IDs of under the same pkg name
    let mut source_ids_grouped_by_pkg_name = HashMap::new();
    for pkgid in resolve.iter() {
        source_ids_grouped_by_pkg_name
            .entry(pkgid.name())
            .or_insert_with(HashSet::new)
            .insert(pkgid.source_id());
    }

    let mut unemitted_unused_patches = Vec::new();
    for unused in resolve.unused_patches() {
        // Show alternative source URLs if the source URLs being patched
        // cannot be found in the crate graph.
        match (
            source_ids_grouped_by_pkg_name.get(&unused.name()),
            patch_pkgid_to_urls.get(unused),
        ) {
            (Some(ids), Some(patched_urls))
                if ids
                    .iter()
                    .all(|id| !patched_urls.contains(id.canonical_url())) =>
            {
                let mut help = "perhaps you meant one of the following:".to_owned();
                for id in ids {
                    help.push_str("\n\t");
                    help.push_str(&id.display_registry_name());
                }
                ws.gctx().shell().print_report(
                    &[Level::WARNING
                        .secondary_title(format!("patch `{unused}` {MESSAGE}"))
                        .element(Level::HELP.message(help))],
                    false,
                )?;
            }
            _ => unemitted_unused_patches.push(unused),
        }
    }

    // Show general help message.
    if !unemitted_unused_patches.is_empty() {
        let mut warnings: Vec<_> = unemitted_unused_patches
            .iter()
            .map(|pkgid| {
                Group::with_title(
                    Level::WARNING.secondary_title(format!("patch `{pkgid}` {MESSAGE}")),
                )
            })
            .collect();
        warnings.push(Group::with_title(
            Level::HELP.secondary_title(UNUSED_PATCH_WARNING),
        ));
        ws.gctx().shell().print_report(&warnings, false)?;
    }

    Ok(())
}

/// `ops::register_patch_entries`, verbatim (sync — upstream `patch` is).
#[tracing::instrument(level = "debug", skip_all, ret)]
fn register_patch_entries(
    registry: &mut PackageRegistry<'_>,
    ws: &Workspace<'_>,
    previous: Option<&Resolve>,
    version_prefs: &mut VersionPreferences,
    keep_previous: Keep<'_>,
) -> CargoResult<HashSet<PackageId>> {
    let mut avoid_patch_ids = HashSet::new();
    for (url, patches) in &ws.root_patch()? {
        for patch in patches {
            version_prefs.prefer_dependency(patch.dep.clone());
        }
        let Some(previous) = previous else {
            let patches: Vec<_> = patches.iter().map(|p| (p, None)).collect();
            let unlock_ids = registry.patch(url, &patches)?;
            // Since nothing is locked, this shouldn't possibly return anything.
            assert!(unlock_ids.is_empty());
            continue;
        };

        // This is a list of pairs where the first element of the pair is
        // the raw `Dependency` which matches what's listed in `Cargo.toml`.
        // The second element is, if present, the "locked" version of
        // the `Dependency` as well as the `PackageId` that it previously
        // resolved to.
        let mut registrations = Vec::new();
        for patch in patches {
            let dep = &patch.dep;
            let candidates = || {
                previous
                    .iter()
                    .chain(previous.unused_patches().iter().copied())
                    .filter(&keep_previous)
            };

            let lock = candidates().find(|id| dep.matches_id(*id)).map_or_else(
                || {
                    candidates()
                        .find(|&id| {
                            master_branch_git_source(id, previous)
                                .is_some_and(|id| dep.matches_id(id))
                        })
                        .map(|id_using_default| {
                            let id_using_master = id_using_default.with_source_id(
                                dep.source_id()
                                    .with_precise_from(id_using_default.source_id()),
                            );

                            let mut locked_dep = dep.clone();
                            locked_dep.lock_to(id_using_master);
                            LockedPatchDependency {
                                dependency: locked_dep,
                                package_id: id_using_master,
                                alt_package_id: Some(id_using_default),
                            }
                        })
                },
                // If we found an exactly matching candidate in our list of
                // candidates, then that's the one to use.
                |package_id| {
                    let mut locked_dep = dep.clone();
                    locked_dep.lock_to(package_id);
                    Some(LockedPatchDependency {
                        dependency: locked_dep,
                        package_id,
                        alt_package_id: None,
                    })
                },
            );

            registrations.push((patch, lock));
        }

        let canonical = CanonicalUrl::new(url)?;
        for (orig_patch, unlock_id) in registry.patch(url, &registrations)? {
            // Avoid the locked patch ID.
            avoid_patch_ids.insert(unlock_id);
            // Also avoid the thing it is patching.
            avoid_patch_ids.extend(previous.iter().filter(|id| {
                orig_patch.dep.matches_ignoring_source(*id)
                    && *id.source_id().canonical_url() == canonical
            }));
        }
    }

    Ok(avoid_patch_ids)
}

/// `ops::lock_replacements`, verbatim.
fn lock_replacements(
    ws: &Workspace<'_>,
    previous: Option<&Resolve>,
    keep: Keep<'_>,
) -> Vec<(PackageIdSpec, Dependency)> {
    let root_replace = ws.root_replace();

    previous.map_or_else(
        || root_replace.to_vec(),
        |r| {
            root_replace
                .iter()
                .map(|(spec, dep)| {
                    for (&key, &val) in r.replacements() {
                        if spec.matches(key) && dep.matches_id(val) && keep(&val) {
                            let mut dep = dep.clone();
                            dep.lock_to(val);
                            return (spec.clone(), dep);
                        }
                    }
                    (spec.clone(), dep.clone())
                })
                .collect::<Vec<_>>()
        },
    )
}
