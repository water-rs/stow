use crate::core::PackageId;
use crate::core::Registry as _;
use crate::core::registry::PackageRegistry;
use crate::core::resolver::PublishAgePolicy;
use crate::core::{Resolve, SourceId, Workspace};
use crate::sources::IndexSummary;
use crate::sources::source::QueryKind;
use crate::util::cache_lock::CacheLockMode;
use crate::util::style;
use crate::util::{CargoResult, VersionExt};

use cargo_util_schemas::core::PartialVersion;
use indexmap::IndexMap;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use tracing::debug;

pub async fn print_lockfile_changes(
    ws: &Workspace<'_>,
    previous_resolve: Option<&Resolve>,
    resolve: &Resolve,
    registry: &mut PackageRegistry<'_>,
) -> CargoResult<()> {
    let _lock = ws
        .gctx()
        .acquire_package_cache_lock(CacheLockMode::DownloadExclusive)?;
    if let Some(previous_resolve) = previous_resolve {
        print_lockfile_sync(ws, previous_resolve, resolve, registry).await
    } else {
        print_lockfile_generation(ws, resolve, registry).await
    }
}

async fn print_lockfile_generation(
    ws: &Workspace<'_>,
    resolve: &Resolve,
    registry: &mut PackageRegistry<'_>,
) -> CargoResult<()> {
    let mut changes = PackageChange::new(ws, resolve);
    let num_pkgs: usize = changes
        .values()
        .filter(|change| change.kind.is_new() && !change.is_member.unwrap_or(false))
        .count();
    if num_pkgs == 0 {
        // nothing worth reporting
        return Ok(());
    }
    annotate_required_rust_version(ws, resolve, &mut changes);
    let publish_age = publish_age_policy_for_report(ws);

    status_locking(ws, num_pkgs)?;
    for change in changes.values() {
        if change.is_member.unwrap_or(false) {
            continue;
        };
        match change.kind {
            PackageChangeKind::Added => {
                let possibilities = if let Some(query) = change.alternatives_query() {
                    registry.query_vec(&query, QueryKind::Exact).await?
                } else {
                    vec![]
                };

                let required_rust_version = report_required_rust_version(resolve, change);
                let too_new = report_too_new(resolve, change, publish_age.as_ref());
                let latest = report_latest(&possibilities, change, publish_age.as_ref());
                let note = required_rust_version.or(too_new).or(latest);

                if let Some(note) = note {
                    ws.gctx().shell().status_with_color(
                        change.kind.status(),
                        format!("{change}{note}"),
                        &change.kind.style(),
                    )?;
                }
            }
            PackageChangeKind::Upgraded
            | PackageChangeKind::Downgraded
            | PackageChangeKind::Removed
            | PackageChangeKind::Unchanged => {
                unreachable!("without a previous resolve, everything should be added")
            }
        }
    }

    Ok(())
}

async fn print_lockfile_sync(
    ws: &Workspace<'_>,
    previous_resolve: &Resolve,
    resolve: &Resolve,
    registry: &mut PackageRegistry<'_>,
) -> CargoResult<()> {
    let mut changes = PackageChange::diff(ws, previous_resolve, resolve);
    let num_pkgs: usize = changes
        .values()
        .filter(|change| change.kind.is_new() && !change.is_member.unwrap_or(false))
        .count();
    if num_pkgs == 0 {
        // nothing worth reporting
        return Ok(());
    }
    annotate_required_rust_version(ws, resolve, &mut changes);
    let publish_age = publish_age_policy_for_report(ws);

    status_locking(ws, num_pkgs)?;
    for change in changes.values() {
        if change.is_member.unwrap_or(false) {
            continue;
        };
        match change.kind {
            PackageChangeKind::Added
            | PackageChangeKind::Upgraded
            | PackageChangeKind::Downgraded => {
                let possibilities = if let Some(query) = change.alternatives_query() {
                    registry.query_vec(&query, QueryKind::Exact).await?
                } else {
                    vec![]
                };

                let required_rust_version = report_required_rust_version(resolve, change);
                let too_new = report_too_new(resolve, change, publish_age.as_ref());
                let latest = report_latest(&possibilities, change, publish_age.as_ref());
                let note = required_rust_version
                    .or(too_new)
                    .or(latest)
                    .unwrap_or_default();

                ws.gctx().shell().status_with_color(
                    change.kind.status(),
                    format!("{change}{note}"),
                    &change.kind.style(),
                )?;
            }
            PackageChangeKind::Removed | PackageChangeKind::Unchanged => {}
        }
    }

    Ok(())
}

fn status_locking(ws: &Workspace<'_>, num_pkgs: usize) -> CargoResult<()> {
    use std::fmt::Write as _;

    let plural = if num_pkgs == 1 { "" } else { "s" };

    let mut cfg = String::new();
    // Don't have a good way to describe `direct_minimal_versions` atm
    if !ws.gctx().cli_unstable().direct_minimal_versions {
        write!(&mut cfg, " to")?;
        if ws.gctx().cli_unstable().minimal_versions {
            write!(&mut cfg, " earliest")?;
        } else {
            write!(&mut cfg, " latest")?;
        }

        if let Some(rust_version) = required_rust_version(ws) {
            write!(&mut cfg, " Rust {rust_version}")?;
        }
        write!(&mut cfg, " compatible version{plural}")?;
        if let Some(publish_time) = ws.resolve_publish_time() {
            write!(&mut cfg, " as of {publish_time}")?;
        }
    }

    ws.gctx()
        .shell()
        .status("Locking", format!("{num_pkgs} package{plural}{cfg}"))?;
    Ok(())
}

fn required_rust_version(ws: &Workspace<'_>) -> Option<PartialVersion> {
    if !ws.resolve_honors_rust_version() {
        return None;
    }

    if let Some(ver) = ws.lowest_rust_version() {
        Some(ver.to_partial())
    } else {
        let rustc = ws.gctx().load_global_rustc(Some(ws)).ok()?;
        let rustc_version = rustc.version.clone().into();
        Some(rustc_version)
    }
}

fn publish_age_policy_for_report(ws: &Workspace<'_>) -> Option<PublishAgePolicy> {
    if !ws.resolve_honors_publish_age() {
        return None;
    }
    PublishAgePolicy::for_report(ws.gctx()).ok().flatten()
}

fn report_required_rust_version(resolve: &Resolve, change: &PackageChange) -> Option<String> {
    if change.package_id.source_id().is_path() {
        return None;
    }
    let summary = resolve.summary(change.package_id);
    let package_rust_version = summary.rust_version()?;
    let required_rust_version = change.required_rust_version.as_ref()?;
    if package_rust_version.is_compatible_with(required_rust_version) {
        return None;
    }

    let error = style::ERROR;
    Some(format!(
        " {error}(requires Rust {package_rust_version}){error:#}"
    ))
}

/// Reports when the selected version is too new and violates `min-publish-age` config.
fn report_too_new(
    resolve: &Resolve,
    change: &PackageChange,
    publish_age: Option<&PublishAgePolicy>,
) -> Option<String> {
    let summary = resolve.summary(change.package_id);
    let note = publish_age?.too_new(summary)?.note();

    let warn = style::WARN;
    Some(format!(" {warn}({note}){warn:#}"))
}

fn report_latest(
    possibilities: &[IndexSummary],
    change: &PackageChange,
    publish_age: Option<&PublishAgePolicy>,
) -> Option<String> {
    let package_id = change.package_id;
    if !package_id.source_id().is_registry() {
        return None;
    }

    let version_req = package_id.version().to_caret_req();
    let required_rust_version = change.required_rust_version.as_ref();

    let publish_note = |summary| {
        let age = publish_age?.too_new(summary)?.age_label();
        Some(format!(", published {age}"))
    };

    let compat_ver_compat_msrv_summary = possibilities
        .iter()
        .filter_map(|s| match s {
            IndexSummary::Candidate(s) => Some(s),
            _ => None,
        })
        .filter(|s| {
            if let (Some(summary_rust_version), Some(required_rust_version)) =
                (s.rust_version(), required_rust_version)
            {
                summary_rust_version.is_compatible_with(required_rust_version)
            } else {
                true
            }
        })
        .filter(|s| package_id.version() != s.version() && version_req.matches(s.version()))
        .max_by_key(|s| s.version());
    if let Some(summary) = compat_ver_compat_msrv_summary {
        let warn = style::WARN;
        let version = summary.version();
        let publish_note = publish_note(summary).unwrap_or_default();
        let report = format!(" {warn}(available: v{version}{publish_note}){warn:#}");
        return Some(report);
    }

    if !change.is_transitive.unwrap_or(true) {
        let incompat_ver_compat_msrv_summary = possibilities
            .iter()
            .filter_map(|s| match s {
                IndexSummary::Candidate(s) => Some(s),
                _ => None,
            })
            .filter(|s| {
                if let (Some(summary_rust_version), Some(required_rust_version)) =
                    (s.rust_version(), required_rust_version)
                {
                    summary_rust_version.is_compatible_with(required_rust_version)
                } else {
                    true
                }
            })
            .filter(|s| is_latest(s.version(), package_id.version()))
            .max_by_key(|s| s.version());
        if let Some(summary) = incompat_ver_compat_msrv_summary {
            let warn = style::WARN;
            let version = summary.version();
            let publish_note = publish_note(summary).unwrap_or_default();
            let report = format!(" {warn}(available: v{version}{publish_note}){warn:#}");
            return Some(report);
        }
    }

    let compat_ver_summary = possibilities
        .iter()
        .filter_map(|s| match s {
            IndexSummary::Candidate(s) => Some(s),
            _ => None,
        })
        .filter(|s| package_id.version() != s.version() && version_req.matches(s.version()))
        .max_by_key(|s| s.version());
    if let Some(summary) = compat_ver_summary {
        let msrv_note = summary
            .rust_version()
            .map(|rv| format!(", requires Rust {rv}"))
            .unwrap_or_default();
        let warn = style::NOP;
        let version = summary.version();
        let publish_note = publish_note(summary).unwrap_or_default();
        let report = format!(" {warn}(available: v{version}{msrv_note}{publish_note}){warn:#}");
        return Some(report);
    }

    if !change.is_transitive.unwrap_or(true) {
        let incompat_ver_summary = possibilities
            .iter()
            .filter_map(|s| match s {
                IndexSummary::Candidate(s) => Some(s),
                _ => None,
            })
            .filter(|s| is_latest(s.version(), package_id.version()))
            .max_by_key(|s| s.version());
        if let Some(summary) = incompat_ver_summary {
            let msrv_note = summary
                .rust_version()
                .map(|rv| format!(", requires Rust {rv}"))
                .unwrap_or_default();
            let warn = style::NOP;
            let version = summary.version();
            let publish_note = publish_note(summary).unwrap_or_default();
            let report = format!(" {warn}(available: v{version}{msrv_note}{publish_note}){warn:#}");
            return Some(report);
        }
    }

    None
}

fn is_latest(candidate: &semver::Version, current: &semver::Version) -> bool {
    current < candidate
                // Only match pre-release if major.minor.patch are the same
                && (candidate.pre.is_empty()
                    || (candidate.major == current.major
                        && candidate.minor == current.minor
                        && candidate.patch == current.patch))
}

fn fill_with_deps<'a>(
    resolve: &'a Resolve,
    dep: PackageId,
    set: &mut HashSet<PackageId>,
    visited: &mut HashSet<PackageId>,
) {
    if !visited.insert(dep) {
        return;
    }
    set.insert(dep);
    for (dep, _) in resolve.deps_not_replaced(dep) {
        fill_with_deps(resolve, dep, set, visited);
    }
}

#[derive(Clone, Debug)]
struct PackageChange {
    package_id: PackageId,
    previous_id: Option<PackageId>,
    kind: PackageChangeKind,
    is_member: Option<bool>,
    is_transitive: Option<bool>,
    required_rust_version: Option<PartialVersion>,
}

impl PackageChange {
    pub fn new(ws: &Workspace<'_>, resolve: &Resolve) -> IndexMap<PackageId, Self> {
        let diff = PackageDiff::new(resolve);
        Self::with_diff(diff, ws, resolve)
    }

    pub fn diff(
        ws: &Workspace<'_>,
        previous_resolve: &Resolve,
        resolve: &Resolve,
    ) -> IndexMap<PackageId, Self> {
        let diff = PackageDiff::diff(previous_resolve, resolve);
        Self::with_diff(diff, ws, resolve)
    }

    fn with_diff(
        diff: impl Iterator<Item = PackageDiff>,
        ws: &Workspace<'_>,
        resolve: &Resolve,
    ) -> IndexMap<PackageId, Self> {
        let member_ids: HashSet<_> = ws.members().map(|p| p.package_id()).collect();

        let mut changes = IndexMap::new();
        for diff in diff {
            if let Some((previous_id, package_id)) = diff.change() {
                // If versions differ only in build metadata, we call it an "update"
                // regardless of whether the build metadata has gone up or down.
                // This metadata is often stuff like git commit hashes, which are
                // not meaningfully ordered.
                let kind = if previous_id.version().cmp_precedence(package_id.version())
                    == Ordering::Greater
                {
                    PackageChangeKind::Downgraded
                } else {
                    PackageChangeKind::Upgraded
                };
                let is_member = Some(member_ids.contains(&package_id));
                let is_transitive = Some(true);
                let change = Self {
                    package_id,
                    previous_id: Some(previous_id),
                    kind,
                    is_member,
                    is_transitive,
                    required_rust_version: None,
                };
                changes.insert(change.package_id, change);
            } else {
                for package_id in diff.removed {
                    let kind = PackageChangeKind::Removed;
                    let is_member = None;
                    let is_transitive = None;
                    let change = Self {
                        package_id,
                        previous_id: None,
                        kind,
                        is_member,
                        is_transitive,
                        required_rust_version: None,
                    };
                    changes.insert(change.package_id, change);
                }
                for package_id in diff.added {
                    let kind = PackageChangeKind::Added;
                    let is_member = Some(member_ids.contains(&package_id));
                    let is_transitive = Some(true);
                    let change = Self {
                        package_id,
                        previous_id: None,
                        kind,
                        is_member,
                        is_transitive,
                        required_rust_version: None,
                    };
                    changes.insert(change.package_id, change);
                }
            }
            for package_id in diff.unchanged {
                let kind = PackageChangeKind::Unchanged;
                let is_member = Some(member_ids.contains(&package_id));
                let is_transitive = Some(true);
                let change = Self {
                    package_id,
                    previous_id: None,
                    kind,
                    is_member,
                    is_transitive,
                    required_rust_version: None,
                };
                changes.insert(change.package_id, change);
            }
        }

        for member_id in &member_ids {
            let Some(change) = changes.get_mut(member_id) else {
                continue;
            };
            change.is_transitive = Some(false);
            for (direct_dep_id, _) in resolve.deps(*member_id) {
                let Some(change) = changes.get_mut(&direct_dep_id) else {
                    continue;
                };
                change.is_transitive = Some(false);
            }
        }

        changes
    }

    /// For querying [`PackageRegistry`] for alternative versions to report to the user
    fn alternatives_query(&self) -> Option<crate::core::dependency::Dependency> {
        if !self.package_id.source_id().is_registry() {
            return None;
        }

        let query = crate::core::dependency::Dependency::parse(
            self.package_id.name(),
            None,
            self.package_id.source_id(),
        )
        .expect("already a valid dependency");
        Some(query)
    }
}

impl std::fmt::Display for PackageChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let package_id = self.package_id;
        if let Some(previous_id) = self.previous_id {
            if package_id.source_id().is_git() {
                write!(
                    f,
                    "{previous_id} -> #{}",
                    &package_id.source_id().precise_git_fragment().unwrap()[..8],
                )
            } else {
                write!(f, "{previous_id} -> v{}", package_id.version())
            }
        } else {
            write!(f, "{package_id}")
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum PackageChangeKind {
    Added,
    Removed,
    Upgraded,
    Downgraded,
    Unchanged,
}

impl PackageChangeKind {
    pub fn is_new(&self) -> bool {
        match self {
            Self::Added | Self::Upgraded | Self::Downgraded => true,
            Self::Removed | Self::Unchanged => false,
        }
    }

    pub fn status(&self) -> &'static str {
        match self {
            Self::Added => "Adding",
            Self::Removed => "Removing",
            Self::Upgraded => "Updating",
            Self::Downgraded => "Downgrading",
            Self::Unchanged => "Unchanged",
        }
    }

    pub fn style(&self) -> anstyle::Style {
        match self {
            Self::Added => style::UPDATE_ADDED,
            Self::Removed => style::UPDATE_REMOVED,
            Self::Upgraded => style::UPDATE_UPGRADED,
            Self::Downgraded => style::UPDATE_DOWNGRADED,
            Self::Unchanged => style::UPDATE_UNCHANGED,
        }
    }
}

/// All resolved versions of a package name within a [`SourceId`]
#[derive(Default, Clone, Debug)]
pub struct PackageDiff {
    removed: Vec<PackageId>,
    added: Vec<PackageId>,
    unchanged: Vec<PackageId>,
}

impl PackageDiff {
    pub fn new(resolve: &Resolve) -> impl Iterator<Item = Self> {
        let mut changes = BTreeMap::new();
        let empty = Self::default();
        for dep in resolve.iter() {
            changes
                .entry(Self::key(dep))
                .or_insert_with(|| empty.clone())
                .added
                .push(dep);
        }

        changes.into_iter().map(|(_, v)| v)
    }

    pub fn diff(previous_resolve: &Resolve, resolve: &Resolve) -> impl Iterator<Item = Self> {
        fn vec_subset(a: &[PackageId], b: &[PackageId]) -> Vec<PackageId> {
            a.iter().filter(|a| !contains_id(b, a)).cloned().collect()
        }

        fn vec_intersection(a: &[PackageId], b: &[PackageId]) -> Vec<PackageId> {
            a.iter().filter(|a| contains_id(b, a)).cloned().collect()
        }

        // Check if a PackageId is present `b` from `a`.
        //
        // Note that this is somewhat more complicated because the equality for source IDs does not
        // take precise versions into account (e.g., git shas), but we want to take that into
        // account here.
        fn contains_id(haystack: &[PackageId], needle: &PackageId) -> bool {
            let Ok(i) = haystack.binary_search(needle) else {
                return false;
            };

            // If we've found `a` in `b`, then we iterate over all instances
            // (we know `b` is sorted) and see if they all have different
            // precise versions. If so, then `a` isn't actually in `b` so
            // we'll let it through.
            //
            // Note that we only check this for non-registry sources,
            // however, as registries contain enough version information in
            // the package ID to disambiguate.
            if needle.source_id().is_registry() {
                return true;
            }
            haystack[i..]
                .iter()
                .take_while(|b| &needle == b)
                .any(|b| needle.source_id().has_same_precise_as(b.source_id()))
        }

        // Map `(package name, package source)` to `(removed versions, added versions)`.
        let mut changes = BTreeMap::new();
        let empty = Self::default();
        for dep in previous_resolve.iter() {
            changes
                .entry(Self::key(dep))
                .or_insert_with(|| empty.clone())
                .removed
                .push(dep);
        }
        for dep in resolve.iter() {
            changes
                .entry(Self::key(dep))
                .or_insert_with(|| empty.clone())
                .added
                .push(dep);
        }

        for v in changes.values_mut() {
            let Self {
                removed: ref mut old,
                added: ref mut new,
                unchanged: ref mut other,
            } = *v;
            old.sort();
            new.sort();
            let removed = vec_subset(old, new);
            let added = vec_subset(new, old);
            let unchanged = vec_intersection(new, old);
            *old = removed;
            *new = added;
            *other = unchanged;
        }
        debug!("{:#?}", changes);

        changes.into_iter().map(|(_, v)| v)
    }

    fn key(dep: PackageId) -> (&'static str, SourceId) {
        (dep.name().as_str(), dep.source_id())
    }

    /// Guess if a package upgraded/downgraded
    ///
    /// All `PackageDiff` knows is that entries were added/removed within [`Resolve`].
    /// A package could be added or removed because of dependencies from other packages
    /// which makes it hard to definitively say "X was upgrade to N".
    pub fn change(&self) -> Option<(PackageId, PackageId)> {
        if self.removed.len() == 1 && self.added.len() == 1 {
            Some((self.removed[0], self.added[0]))
        } else {
            None
        }
    }
}

fn annotate_required_rust_version(
    ws: &Workspace<'_>,
    resolve: &Resolve,
    changes: &mut IndexMap<PackageId, PackageChange>,
) {
    let rustc = ws.gctx().load_global_rustc(Some(ws)).ok();
    let rustc_version: Option<PartialVersion> =
        rustc.as_ref().map(|rustc| rustc.version.clone().into());

    if ws.resolve_honors_rust_version() {
        let mut queue: std::collections::VecDeque<_> = ws
            .members()
            .map(|p| {
                (
                    p.rust_version()
                        .map(|r| r.to_partial())
                        .or_else(|| rustc_version.clone()),
                    p.package_id(),
                )
            })
            .collect();
        while let Some((required_rust_version, current_id)) = queue.pop_front() {
            let Some(required_rust_version) = required_rust_version else {
                continue;
            };
            if let Some(change) = changes.get_mut(&current_id) {
                if let Some(existing) = change.required_rust_version.as_ref() {
                    if *existing <= required_rust_version {
                        // Stop early; we already walked down this path with a better match
                        continue;
                    }
                }
                change.required_rust_version = Some(required_rust_version.clone());
            }
            queue.extend(
                resolve
                    .deps(current_id)
                    .map(|(dep, _)| (Some(required_rust_version.clone()), dep)),
            );
        }
    } else {
        for change in changes.values_mut() {
            change.required_rust_version = rustc_version.clone();
        }
    }
}
