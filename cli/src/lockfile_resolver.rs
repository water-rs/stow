//! The stow lockfile resolver, run locally over a verified index slice.
//!
//! Ported from the edge's `resolver.rs` (stow#194): given a project's
//! direct deps, synthesize a `Cargo.lock` whose every package pins a
//! cached artifact. The search (seed fast path, candidate filtering,
//! backtracking) is pure data logic over
//! [`stow_types::index::ArtifactIndexRow`] — the whole
//! `(target, rustc_version)` slice is already resident, so every closure
//! walk resolves against the in-memory index the slice decodes to.

use std::collections::{BTreeMap, BTreeSet};

use stow_types::identity::CrateName;
use stow_types::index::ArtifactIndexRow;

/// A direct dep the user's manifests declare: crate name, the semver
/// requirement string from `[dependencies]`, and the feature names the
/// manifest enables (`default` included unless `default-features = false`).
/// The local equivalent of the edge's `DirectDependency`.
#[derive(Debug, Clone)]
pub struct DirectDependency {
    /// Crate name as published on crates.io.
    pub crate_name: CrateName,
    /// Semver requirement string (e.g. `"^1.0"`, `">=1.0,<2"`, `"=1.5.3"`).
    pub req: String,
    /// Feature names the manifest enables for this dep, in raw form.
    pub features: Vec<String>,
}

/// The outcome of a lockfile resolve — the local equivalent of the edge's
/// `LockfileResolution`.
#[derive(Debug, Clone)]
pub struct LockfileResolution {
    /// `Some` when the resolver found a consistent cache-optimized
    /// assignment for every direct dep + transitive closure. `None` when
    /// no consistent assignment exists in cache — the caller falls back
    /// to cargo's own resolver.
    pub lockfile_toml: Option<String>,
    /// Crate names from `direct` the resolver could not satisfy from
    /// cache. Empty when `lockfile_toml` is `Some`.
    pub uncovered_direct: Vec<CrateName>,
    /// Number of (crate, version) candidate slots the resolver explored.
    pub candidates_considered: u32,
    /// Top partial-match candidates from the seed search, each entry
    /// `"<crate> <version> covered=<n>/<total>: <reason>"`. Empty when a
    /// seed was found.
    pub seed_diagnostics: Vec<String>,
}

/// A direct dep with its semver requirement and requested feature set
/// parsed once, before candidate search begins.
type TypedDirectDep = (CrateName, semver::VersionReq, BTreeSet<String>);

/// Mutable counters shared by every search step: `considered` is reported
/// back as `candidates_considered`, `budget` hard-caps search steps so a
/// pathological closure cannot stall the resolve.
#[derive(Debug)]
struct SearchState {
    considered: u32,
    budget: u32,
}

impl SearchState {
    /// Spend one search step; false once the budget is exhausted.
    const fn step(&mut self) -> bool {
        if self.budget == 0 {
            return false;
        }
        self.budget -= 1;
        self.considered = self.considered.saturating_add(1);
        true
    }
}

/// In-memory index over the slice's rows: seed candidates, plus the
/// `by_pair`/`by_c_metadata`/`by_crate` maps every closure walk resolves
/// against.
///
/// `by_pair` is dual-keyed on the dashed and underscored name forms:
/// `dependency_c_metadata_json` is captured from rustc `--extern` arg
/// names (underscored — `grep_cli`, `nu_ansi_term`), but the row's
/// `crate_name` carries cargo's published name (dashed — `grep-cli`,
/// `nu-ansi-term`). Both forms are cached under the same `c_metadata`,
/// so both resolve to the same row. The fix-at-write-time lives in the
/// CI capture path (stow-build's `dep_scan`); this in-resolver
/// normalization is a forward-compatible bridge.
struct ResolverIndex<'a> {
    /// Rows whose dep closure could cover the whole direct-dep set —
    /// the only rows the seed scan may consider.
    seeds: Vec<&'a ArtifactIndexRow>,
    by_pair: BTreeMap<(String, String), &'a ArtifactIndexRow>,
    /// `c_metadata` is unique per (target, `rustc_version`), so this is a
    /// 1:1 index — the fallback when a `dependency_c_metadata_json`
    /// entry's name disagrees with the cached row's name (Cargo lets a
    /// project rename a dep via `package = "..."`; rustc captures the
    /// local alias, the cache stores the published name).
    by_c_metadata: BTreeMap<String, &'a ArtifactIndexRow>,
    by_crate: BTreeMap<String, Vec<&'a ArtifactIndexRow>>,
}

impl<'a> ResolverIndex<'a> {
    fn new(all: &'a [ArtifactIndexRow], min_seed_deps: usize) -> Self {
        let mut index = Self {
            seeds: Vec::new(),
            by_pair: BTreeMap::new(),
            by_c_metadata: BTreeMap::new(),
            by_crate: BTreeMap::new(),
        };
        for row in all {
            if row.dependency_c_metadata_json.entries().len() >= min_seed_deps {
                index.seeds.push(row);
            }
        }
        for row in all {
            index.by_pair.insert(
                (
                    row.crate_name.as_str().to_owned(),
                    row.c_metadata.as_str().to_owned(),
                ),
                row,
            );
            let alt = row.crate_name.as_str().replace('-', "_");
            if alt != row.crate_name.as_str() {
                index
                    .by_pair
                    .insert((alt, row.c_metadata.as_str().to_owned()), row);
            }
            index
                .by_c_metadata
                .insert(row.c_metadata.as_str().to_owned(), row);
            index
                .by_crate
                .entry(row.crate_name.as_str().to_owned())
                .or_default()
                .push(row);
        }
        index
    }

    /// Look up a cached row by (name, `c_metadata`), trying the verbatim
    /// name first, then the dash↔underscore alt, then — for renamed deps
    /// where the rustc alias diverges from the cargo-published name
    /// entirely — by `c_metadata` alone (1:1 in this target/rustc index).
    fn lookup_dep_row(&self, name: &str, c_metadata: &str) -> Option<&'a ArtifactIndexRow> {
        if let Some(row) = self.by_pair.get(&(name.to_owned(), c_metadata.to_owned())) {
            return Some(*row);
        }
        let alt = name.replace('_', "-");
        if alt != name
            && let Some(row) = self.by_pair.get(&(alt, c_metadata.to_owned()))
        {
            return Some(*row);
        }
        let alt = name.replace('-', "_");
        if alt != name
            && let Some(row) = self.by_pair.get(&(alt, c_metadata.to_owned()))
        {
            return Some(*row);
        }
        self.by_c_metadata.get(c_metadata).copied()
    }

    /// Reject candidates whose transitive closure (recursive) contains a
    /// (name, `c_metadata`) pair we have no cached row for. Pre-filtering
    /// this before backtracking enters its inner loop turns the search
    /// from "explore every dead-end version" into "search only over
    /// coherent candidates", which is what makes large user dep graphs
    /// solvable.
    fn candidate_closure_is_cached(&self, candidate: &ArtifactIndexRow) -> bool {
        let mut visited: BTreeSet<String> = BTreeSet::new();
        self.closure_is_cached_recursive(candidate, &mut visited)
    }

    /// Diagnostic version of [`Self::candidate_closure_is_cached`] —
    /// returns the first `(name, c_metadata)` along the closure walk that
    /// has no cached row. Used by the seed-search diagnostic so a "passed
    /// user-direct cover but transitive closure has uncached pin" failure
    /// tells the operator *which* pin to preheat.
    fn first_uncached_in_closure(
        &self,
        candidate: &'a ArtifactIndexRow,
    ) -> Option<(String, String)> {
        let mut visited: BTreeSet<String> = BTreeSet::new();
        self.first_uncached_recursive(candidate, &mut visited)
    }

    fn first_uncached_recursive(
        &self,
        candidate: &'a ArtifactIndexRow,
        visited: &mut BTreeSet<String>,
    ) -> Option<(String, String)> {
        if !visited.insert(candidate.c_metadata.as_str().to_owned()) {
            return None;
        }
        for (name, c_metadata) in dep_pairs(candidate) {
            let Some(dep_row) = self.lookup_dep_row(&name, &c_metadata) else {
                return Some((name, c_metadata));
            };
            if let Some(miss) = self.first_uncached_recursive(dep_row, visited) {
                return Some(miss);
            }
        }
        None
    }

    fn closure_is_cached_recursive(
        &self,
        candidate: &ArtifactIndexRow,
        visited: &mut BTreeSet<String>,
    ) -> bool {
        if !visited.insert(candidate.c_metadata.as_str().to_owned()) {
            return true;
        }
        for (name, c_metadata) in dep_pairs(candidate) {
            let Some(dep_row) = self.lookup_dep_row(&name, &c_metadata) else {
                return false;
            };
            if !self.closure_is_cached_recursive(dep_row, visited) {
                return false;
            }
        }
        true
    }

    /// Pin a candidate plus every (transitively-pinned) `dep_c_metadata`,
    /// returning false on a (name → different `c_metadata`) conflict or a
    /// lookup miss — and restoring `pinned` on the way out.
    fn try_extend_closure(
        &self,
        pinned: &mut BTreeMap<(String, String), ResolverPin>,
        candidate: &'a ArtifactIndexRow,
        state: &mut SearchState,
        mut diag: Option<&mut Vec<String>>,
    ) -> bool {
        let pin_key = (
            candidate.crate_name.as_str().to_owned(),
            candidate.c_metadata.as_str().to_owned(),
        );
        if pinned.contains_key(&pin_key) {
            return true;
        }
        let deps = dep_pairs(candidate);
        let features = features_set(candidate);
        pinned.insert(
            pin_key.clone(),
            ResolverPin {
                version: candidate.version.to_string(),
                features,
                c_metadata: candidate.c_metadata.as_str().to_owned(),
                deps: deps.clone(),
            },
        );
        for (dep_name, dep_c_metadata) in &deps {
            if !state.step() {
                pinned.remove(&pin_key);
                if let Some(d) = diag.as_deref_mut() {
                    d.push("budget exhausted".to_owned());
                }
                return false;
            }
            // Pinning is keyed on (name, c_metadata), so two
            // SemVer-incompatible versions of the same crate can coexist.
            // We only short-circuit when this exact (name, c_metadata)
            // pair is already pinned — distinct c_metadata for the same
            // name is a legitimate diamond.
            let lookup_dep_key = (dep_name.clone(), dep_c_metadata.clone());
            if pinned.contains_key(&lookup_dep_key) {
                continue;
            }
            let Some(dep_row) = self.lookup_dep_row(dep_name, dep_c_metadata) else {
                pinned.remove(&pin_key);
                if let Some(d) = diag.as_deref_mut() {
                    d.push(format!(
                        "lookup miss for {} c={} (referenced from {})",
                        dep_name, dep_c_metadata, candidate.crate_name
                    ));
                }
                return false;
            };
            // The dep_row's actual crate_name might differ from `dep_name`
            // (a renamed-dep alias). Pin under the row's real name;
            // subsequent (alias, c_metadata) lookups land here too because
            // pin_key uses c_metadata which is unique.
            if !self.try_extend_closure(pinned, dep_row, state, diag.as_deref_mut()) {
                pinned.remove(&pin_key);
                return false;
            }
        }
        true
    }
}

/// The `(crate_name, c_metadata)` pairs a row's
/// `dependency_c_metadata_json` declares — already sorted, deduplicated,
/// and shape-validated by the index decoder.
fn dep_pairs(row: &ArtifactIndexRow) -> Vec<(String, String)> {
    row.dependency_c_metadata_json
        .entries()
        .iter()
        .map(|entry| {
            (
                entry.crate_name.as_str().to_owned(),
                entry.c_metadata.as_str().to_owned(),
            )
        })
        .collect()
}

/// The row's canonical feature list as a set.
fn features_set(row: &ArtifactIndexRow) -> BTreeSet<String> {
    row.features_json.features().iter().cloned().collect()
}

/// Resolve `direct` to a synthesized `Cargo.lock` pinning only cached
/// artifacts, or report the deps no cached closure could satisfy.
///
/// `rows` is the whole verified slice for the caller's
/// `(target, rustc_version)` — the index cache's decoded rows.
///
/// # Errors
///
/// Returns an error only when the synthesized lockfile fails to
/// serialize; every resolvable-vs-not outcome is data in the response.
pub fn resolve_lockfile(
    rows: &[ArtifactIndexRow],
    direct: &[DirectDependency],
) -> stow_types::error::Result<LockfileResolution> {
    // Hard cap on the search budget. The in-memory index makes each step
    // cheap, but a 200k budget can still take 30+ s on a deep tree where
    // every direct dep has dozens of candidates and the closure walks each
    // 50-deep. The CLI's fall-back path runs after we return, so a too-
    // generous budget here just adds wall-clock latency to every "no seed
    // found" project. 20k still covers every realistic top-100 binary
    // closure (cargo-make resolves at ~4k); pathological cases exit
    // quickly and let the fall-back run.
    const MAX_RESOLVER_BUDGET: u32 = 20_000;

    // Empty workspace: no direct deps means nothing to accelerate, and an
    // empty lockfile would mislead the CLI into believing it can use
    // `--locked`. Return None so the CLI falls back unchanged.
    if direct.is_empty() {
        return Ok(LockfileResolution {
            lockfile_toml: None,
            uncovered_direct: Vec::new(),
            candidates_considered: 0,
            seed_diagnostics: Vec::new(),
        });
    }

    let typed_direct = match type_direct_deps(direct) {
        Ok(typed_direct) => typed_direct,
        Err(uncovered) => {
            return Ok(LockfileResolution {
                lockfile_toml: None,
                uncovered_direct: uncovered,
                candidates_considered: 0,
                seed_diagnostics: Vec::new(),
            });
        }
    };

    let index = ResolverIndex::new(rows, typed_direct.len());
    let mut state = SearchState {
        considered: 0,
        budget: MAX_RESOLVER_BUDGET,
    };
    let direct_candidates = viable_direct_candidates(&index, &typed_direct, &mut state.considered);

    // Pinned set keyed by (crate_name, c_metadata): cargo allows multiple
    // versions of the same crate name to coexist when SemVer-incompatible
    // (e.g., `log 0.3` and `log 0.4`), so a name-only key would falsely
    // reject any seed whose closure pulls two such versions through
    // different transitives.
    let mut pinned: BTreeMap<(String, String), ResolverPin> = BTreeMap::new();
    let mut seed_diagnostics = Vec::<String>::new();
    apply_seed_artifact(
        &index,
        &typed_direct,
        &mut pinned,
        &mut state,
        &mut seed_diagnostics,
    );
    let solved = if pinned.is_empty() {
        backtrack_solve(
            &index,
            &typed_direct,
            &direct_candidates,
            0,
            &mut pinned,
            &mut state,
        )
    } else {
        true
    };

    if !solved {
        let pinned_names: BTreeSet<&str> = pinned.keys().map(|(name, _)| name.as_str()).collect();
        let uncovered: Vec<CrateName> = typed_direct
            .into_iter()
            .filter_map(|(name, _, _)| {
                if pinned_names.contains(name.as_str()) {
                    None
                } else {
                    Some(name)
                }
            })
            .collect();
        return Ok(LockfileResolution {
            lockfile_toml: None,
            uncovered_direct: uncovered,
            candidates_considered: state.considered,
            seed_diagnostics,
        });
    }

    let lockfile_toml = render_lockfile(&pinned)?;
    Ok(LockfileResolution {
        lockfile_toml: Some(lockfile_toml),
        uncovered_direct: Vec::new(),
        candidates_considered: state.considered,
        seed_diagnostics: Vec::new(),
    })
}

/// Parse each direct dep's semver requirement once. A dep whose req
/// string does not parse cannot be satisfied from cache — it is reported
/// uncovered so the caller falls back to cargo's resolver.
fn type_direct_deps(direct: &[DirectDependency]) -> Result<Vec<TypedDirectDep>, Vec<CrateName>> {
    let mut typed_direct = Vec::with_capacity(direct.len());
    let mut uncovered = Vec::new();
    for dep in direct {
        match semver::VersionReq::parse(dep.req.as_str()) {
            Ok(req) => typed_direct.push((
                dep.crate_name.clone(),
                req,
                dep.features.iter().cloned().collect(),
            )),
            Err(_) => uncovered.push(dep.crate_name.clone()),
        }
    }
    if uncovered.is_empty() {
        Ok(typed_direct)
    } else {
        Err(uncovered)
    }
}

/// Filter each direct dep's cached rows down to candidates that satisfy
/// the version req, carry a superset of the requested features, and have
/// a fully-cached transitive closure. The closure filter is the critical
/// one: a candidate whose `dependency_c_metadata_json` references a
/// (name, `c_metadata`) we haven't preheated can never produce a coherent
/// closure, so it is rejected before backtracking ever touches it.
///
/// Viable candidates are ordered by cached transitive-closure size, then
/// version descending — the big-closure heuristic anchors search to
/// "binary-style" coherent preheats: a binary's own root row tends to
/// have the deepest tree.
fn viable_direct_candidates<'a>(
    index: &ResolverIndex<'a>,
    typed_direct: &[TypedDirectDep],
    considered: &mut u32,
) -> Vec<Vec<&'a ArtifactIndexRow>> {
    let mut direct_candidates = Vec::with_capacity(typed_direct.len());
    for (crate_name, req, user_features) in typed_direct {
        let Some(rows) = index.by_crate.get(crate_name.as_str()) else {
            direct_candidates.push(Vec::new());
            continue;
        };
        let mut filtered: Vec<&ArtifactIndexRow> = Vec::new();
        for row in rows {
            *considered = considered.saturating_add(1);
            if !req.matches(row.version.as_semver()) {
                continue;
            }
            let features = features_set(row);
            let mut effective = user_features.clone();
            if effective.contains("default") && !features.contains("default") {
                effective.remove("default");
            }
            if !effective.is_subset(&features) {
                continue;
            }
            if !index.candidate_closure_is_cached(row) {
                continue;
            }
            filtered.push(*row);
        }
        filtered.sort_by(|a, b| {
            b.dependency_c_metadata_json
                .entries()
                .len()
                .cmp(&a.dependency_c_metadata_json.entries().len())
                .then(b.version.as_semver().cmp(a.version.as_semver()))
        });
        direct_candidates.push(filtered);
    }
    direct_candidates
}

/// Phase 1 — seed-artifact fast path. If any cached artifact's own
/// `dependency_c_metadata_json` already covers every user direct dep
/// with semver+features-compatible pins (i.e. the user's project shape
/// matches some preheated closure as a subset), extend `pinned` from it
/// directly: that closure came from a single cargo build, so it is
/// coherent by construction. This is the path that turns "user runs
/// `stow check` against bat 0.26.1's source" into 100% cache hits —
/// bat's own preheat row IS that seed.
fn apply_seed_artifact(
    index: &ResolverIndex<'_>,
    typed_direct: &[TypedDirectDep],
    pinned: &mut BTreeMap<(String, String), ResolverPin>,
    state: &mut SearchState,
    diagnostics: &mut Vec<String>,
) {
    let Some(seed_row) =
        find_seed_artifact(index, typed_direct, &mut state.considered, diagnostics)
    else {
        return;
    };
    diagnostics.push(format!(
        "seed found: {} {} ({})",
        seed_row.crate_name, seed_row.version, seed_row.c_metadata
    ));
    if index.try_extend_closure(pinned, seed_row, state, Some(diagnostics)) {
        diagnostics.push(format!(
            "extend ok, pinned {} crates pre-remove-self",
            pinned.len()
        ));
        pinned.remove(&(
            seed_row.crate_name.as_str().to_owned(),
            seed_row.c_metadata.as_str().to_owned(),
        ));
    } else {
        diagnostics.push("extend failed for selected seed".to_owned());
        pinned.clear();
    }
}

/// Search the index for a "seed" row whose own
/// `dependency_c_metadata_json` already covers every user direct dep with
/// semver+features-compatible pins. When the user's project IS one of the
/// preheated binaries (or shares its dep shape exactly), this finds it in
/// one pass and gives the resolver a guaranteed-coherent full closure to
/// walk, with no backtracking needed.
fn find_seed_artifact<'a>(
    index: &ResolverIndex<'a>,
    typed_direct: &[TypedDirectDep],
    considered: &mut u32,
    diagnostics: &mut Vec<String>,
) -> Option<&'a ArtifactIndexRow> {
    let direct_index: BTreeMap<&str, (&semver::VersionReq, &BTreeSet<String>)> = typed_direct
        .iter()
        .map(|(name, req, features)| (name.as_str(), (req, features)))
        .collect();
    let mut best: Option<(&ArtifactIndexRow, usize)> = None;
    let mut diagnostic_size_pass = 0_usize;
    let mut diagnostic_partial_match: Vec<(String, String, usize, String)> = Vec::new();
    for &row in &index.seeds {
        *considered = considered.saturating_add(1);
        let deps = dep_pairs(row);
        // `index.seeds` is already bounded by the dep-identity count —
        // the same `deps.len() >= typed_direct.len()` predicate — so
        // every iterated row is a size-pass.
        diagnostic_size_pass += 1;
        let covered_count = match seed_row_direct_coverage(index, &direct_index, &deps) {
            Ok(covered_count) => covered_count,
            Err((covered_count, fail_reason)) => {
                // Record every size-pass failure so a 0-coverage seed (the
                // common case for "wrong artifact name happens to have many
                // deps") still surfaces *why* it didn't seed — not just that
                // 14 candidates passed the size filter and silently failed.
                diagnostic_partial_match.push((
                    row.crate_name.as_str().to_owned(),
                    row.version.to_string(),
                    covered_count,
                    fail_reason,
                ));
                continue;
            }
        };
        // Confirm the seed's own full transitive closure is cached — a row
        // with a missing transitive can't actually be walked.
        if !index.candidate_closure_is_cached(row) {
            let reason = match index.first_uncached_in_closure(row) {
                Some((name, c_metadata)) => format!("transitive uncached: {name}/{c_metadata}"),
                None => "transitive closure walk failed".to_owned(),
            };
            diagnostic_partial_match.push((
                row.crate_name.as_str().to_owned(),
                row.version.to_string(),
                covered_count,
                reason,
            ));
            continue;
        }
        // Prefer larger seeds (more transitives covered) so we lock in the
        // most amount of cache work per pin. Tie-break by version DESC.
        let dep_count = deps.len();
        let take_this = match best {
            None => true,
            Some((current, current_deps)) => match dep_count.cmp(&current_deps) {
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Less => false,
                std::cmp::Ordering::Equal => current.version.as_semver() < row.version.as_semver(),
            },
        };
        if take_this {
            best = Some((row, dep_count));
        }
    }
    if best.is_none() {
        diagnostic_partial_match.sort_by_key(|entry| std::cmp::Reverse(entry.2));
        diagnostics.push(format!(
            "size_pass={} user_direct={}",
            diagnostic_size_pass,
            typed_direct.len()
        ));
        for (name, version, cov, reason) in diagnostic_partial_match.iter().take(20) {
            diagnostics.push(format!(
                "{name} {version}: covered={cov}/{total} fail={reason}",
                total = typed_direct.len()
            ));
        }
    }
    best.map(|(row, _)| row)
}

/// Whether `row`'s dep index covers every user direct dep with a cached
/// pin satisfying the req and feature subset. `Ok` carries the covered
/// count (always `direct_index.len()`); `Err` carries the covered-so-far
/// count plus the first failure reason, for the seed diagnostics.
fn seed_row_direct_coverage(
    index: &ResolverIndex<'_>,
    direct_index: &BTreeMap<&str, (&semver::VersionReq, &BTreeSet<String>)>,
    deps: &[(String, String)],
) -> Result<usize, (usize, String)> {
    let mut row_dep_index: BTreeMap<String, &str> = BTreeMap::new();
    for (dep_name, dep_c_metadata) in deps {
        row_dep_index.insert(dep_name.clone(), dep_c_metadata.as_str());
        // Also accept normalized form (rustc underscored vs. cargo
        // dashed) so user direct deps named with dashes match a row
        // whose extern was captured with underscores.
        row_dep_index.insert(dep_name.replace('_', "-"), dep_c_metadata.as_str());
    }
    let mut covered_count = 0_usize;
    for (user_name, (user_req, user_features)) in direct_index {
        let lookup_keys = [
            (*user_name).to_owned(),
            user_name.replace('-', "_"),
            user_name.replace('_', "-"),
        ];
        let mut hit = None;
        for key in &lookup_keys {
            if let Some(c_metadata) = row_dep_index.get(key) {
                hit = Some(c_metadata);
                break;
            }
        }
        let Some(c_metadata) = hit else {
            return Err((
                covered_count,
                format!("name `{user_name}` not in row_dep_index"),
            ));
        };
        let Some(pinned_row) = lookup_keys
            .iter()
            .find_map(|key| {
                index
                    .by_pair
                    .get(&((*key).clone(), (*c_metadata).to_owned()))
            })
            .copied()
            .or_else(|| index.by_c_metadata.get(*c_metadata).copied())
        else {
            return Err((
                covered_count,
                format!("by_pair miss for `{user_name}`/{c_metadata}"),
            ));
        };
        let pinned_version = pinned_row.version.as_semver();
        if !user_req.matches(pinned_version) {
            return Err((
                covered_count,
                format!("req `{user_req}` does not match pinned {user_name} {pinned_version}"),
            ));
        }
        let pinned_features = features_set(pinned_row);
        // "default" is a meta-feature: cargo only passes --cfg
        // feature="default" to rustc when the crate actually defines a
        // `default` feature. For crates with no `default` declared
        // (e.g., bincode 1.3.3), the cache stores features=[] regardless
        // of whether the user said default-features=true. Treat user's
        // "default" request as satisfied when the candidate has no
        // "default" feature recorded — it's a no-op.
        let mut effective_user_features: BTreeSet<String> = (*user_features).clone();
        if effective_user_features.contains("default") && !pinned_features.contains("default") {
            effective_user_features.remove("default");
        }
        if !effective_user_features.is_subset(&pinned_features) {
            let user_set: Vec<&String> = user_features.iter().collect();
            let pinned_set: Vec<&String> = pinned_features.iter().collect();
            return Err((
                covered_count,
                format!(
                    "features mismatch for {user_name}: user wants {user_set:?} but cache has {pinned_set:?}"
                ),
            ));
        }
        covered_count += 1;
    }
    Ok(covered_count)
}

/// Recursive backtracking solver running entirely on the in-memory index.
/// For each direct dep at `position`, try every viable candidate
/// (already filtered for req+features+full-closure-coverage); on conflict
/// downstream the per-candidate `pinned` snapshot is restored before
/// trying the next.
fn backtrack_solve(
    index: &ResolverIndex<'_>,
    typed_direct: &[TypedDirectDep],
    direct_candidates: &[Vec<&ArtifactIndexRow>],
    position: usize,
    pinned: &mut BTreeMap<(String, String), ResolverPin>,
    state: &mut SearchState,
) -> bool {
    if position >= typed_direct.len() {
        return true;
    }
    let (crate_name, _, _) = &typed_direct[position];
    // A direct dep is "satisfied" when ANY (name, c_metadata) for this name
    // is already in pinned (the seed search or earlier direct-dep iteration
    // already pulled it into the closure).
    let already_pinned = pinned.keys().any(|(name, _)| name == crate_name.as_str());
    if already_pinned {
        return backtrack_solve(
            index,
            typed_direct,
            direct_candidates,
            position + 1,
            pinned,
            state,
        );
    }
    for candidate in &direct_candidates[position] {
        if !state.step() {
            return false;
        }
        let snapshot = pinned.clone();
        if index.try_extend_closure(pinned, candidate, state, None)
            && backtrack_solve(
                index,
                typed_direct,
                direct_candidates,
                position + 1,
                pinned,
                state,
            )
        {
            return true;
        }
        *pinned = snapshot;
    }
    false
}

#[derive(Debug, Clone)]
struct ResolverPin {
    version: String,
    features: BTreeSet<String>,
    c_metadata: String,
    /// Sorted (`dep_name`, `dep_c_metadata`) pairs from the cached
    /// artifact's `dependency_c_metadata_json`. Stored verbatim so the
    /// lockfile-render step can resolve them to (name, version) via
    /// `pinned`.
    deps: Vec<(String, String)>,
}

const CRATES_IO_REGISTRY_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

fn render_lockfile(
    pinned: &BTreeMap<(String, String), ResolverPin>,
) -> stow_types::error::Result<String> {
    // Cargo's lockfile keys packages by (name, version, source). Two pins
    // that share (name, version) but differ on c_metadata are functionally
    // the SAME package compiled with different feature unifications;
    // cargo would build them as ONE entry with feature union. Reduce
    // multi-c_metadata pins to one canonical entry per (name, version)
    // before rendering — picking the pin with the largest feature set so
    // any user that wanted the smaller set still finds everything it
    // needs in the chosen entry's compile.
    let mut canonical: BTreeMap<(String, String), &ResolverPin> = BTreeMap::new();
    for ((name, _), pin) in pinned {
        let key = (name.clone(), pin.version.clone());
        match canonical.get(&key) {
            Some(existing) if existing.features.len() >= pin.features.len() => {}
            _ => {
                canonical.insert(key, pin);
            }
        }
    }
    // Build a `c_metadata → canonical (name, version)` index. Both pins of
    // a (name, version) duplicate land here, mapping to the same canonical
    // entry — so any dep reference by either c_metadata renders to the
    // same `(name, version)` line.
    let by_c_metadata: BTreeMap<&str, (&str, &ResolverPin)> = pinned
        .iter()
        .map(|((name, _), pin)| {
            let canonical_pin = canonical
                .get(&(name.clone(), pin.version.clone()))
                .copied()
                .unwrap_or(pin);
            (pin.c_metadata.as_str(), (name.as_str(), canonical_pin))
        })
        .collect();
    let mut entries: Vec<((&str, &str), &ResolverPin)> = canonical
        .iter()
        .map(|((name, version), pin)| ((name.as_str(), version.as_str()), *pin))
        .collect();
    entries.sort_by_key(|(name_version, _)| *name_version);
    let package = entries
        .iter()
        .map(|((name, version), pin)| {
            let mut dependencies: Vec<String> = pin
                .deps
                .iter()
                .filter_map(|(_, dep_c_metadata)| {
                    by_c_metadata
                        .get(dep_c_metadata.as_str())
                        .map(|(canonical_name, dep_pin)| {
                            format!(
                                "{} {} ({})",
                                canonical_name, dep_pin.version, CRATES_IO_REGISTRY_SOURCE
                            )
                        })
                })
                .collect();
            dependencies.sort();
            dependencies.dedup();
            RenderedLockPackage {
                name: (*name).to_owned(),
                version: (*version).to_owned(),
                source: CRATES_IO_REGISTRY_SOURCE.to_owned(),
                dependencies,
            }
        })
        .collect();
    let body = toml::to_string(&RenderedLockfile {
        version: 3,
        package,
    })
    .map_err(|error| stow_types::stow_error!("serialize synthesized lockfile: {error}"))?;
    Ok(format!(
        "# This file is automatically @generated by stow.\n# It is not intended for manual editing.\n{body}"
    ))
}

/// Serde shape of the synthesized Cargo.lock (v3).
#[derive(serde::Serialize)]
struct RenderedLockfile {
    version: u32,
    package: Vec<RenderedLockPackage>,
}

#[derive(serde::Serialize)]
struct RenderedLockPackage {
    name: String,
    version: String,
    source: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    dependencies: Vec<String>,
}

#[cfg(test)]
mod tests {
    use semver::Version;
    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::identity::{
        CMetadata, CrateName, CrateVersion, DependencyCMetadataIdentity, DependencyCMetadataJson,
        FeaturesJson,
    };
    use stow_types::platform::{PanicStrategy, Profile, StripLevel};

    use super::*;

    const DEP_A: &str = "aaaaaaaaaaaaaaaa";
    const DEP_B: &str = "bbbbbbbbbbbbbbbb";
    const SUITE: &str = "cccccccccccccccc";
    const DEP_A1: &str = "dddddddddddddddd";

    fn artifact(
        crate_name: &str,
        version: &str,
        c_metadata: &str,
        deps: &[(&str, &str)],
    ) -> ArtifactIndexRow {
        ArtifactIndexRow {
            crate_name: CrateName::parse(crate_name).expect("name"),
            version: CrateVersion::new(Version::parse(version).expect("version")),
            features_json: FeaturesJson::canonicalize(vec!["default".to_owned()])
                .expect("features"),
            dependency_c_metadata_json: DependencyCMetadataJson::canonicalize(
                deps.iter()
                    .map(|(name, meta)| DependencyCMetadataIdentity {
                        crate_name: CrateName::parse(*name).expect("dep name"),
                        c_metadata: CMetadata::parse(*meta).expect("dep c_metadata"),
                    })
                    .collect(),
            )
            .expect("deps"),
            c_metadata: CMetadata::parse(c_metadata).expect("c_metadata"),
            compile_key: format!("{c_metadata}{c_metadata}"),
            bundle_digest:
                "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            bundle_size: 1,
            artifact_kind: ArtifactKind::Rlib,
            crate_types: vec![RustCrateType::Rlib],
            profile: Profile {
                opt_level: "0".to_owned(),
                debuginfo: 0,
                debug_assertions: true,
                overflow_checks: true,
                panic: PanicStrategy::Unwind,
                strip: StripLevel::None,
            },
            emit: vec!["link".to_owned()],
            min_glibc: None,
            unit_shape: None,
        }
    }

    fn dep_a_direct() -> DirectDependency {
        DirectDependency {
            crate_name: CrateName::parse("dep-a").expect("name"),
            req: "^1.0.0".to_owned(),
            features: vec!["default".to_owned()],
        }
    }

    /// A seed row is never named by the user's direct deps — the resolver
    /// finds it only through its dep-identity count. The seed's dep
    /// closure then expands level-by-level over `c_metadata` lookups until
    /// the whole pinned closure is resident.
    ///
    /// The seed records dep-a `1.0.1` while the standalone `1.0.0` row
    /// carries more deps and therefore sorts first for backtracking —
    /// `1.0.1` in the rendered lockfile proves the seed applied.
    #[test]
    fn resolve_lockfile_seeds_from_covering_binary_row() {
        let rows = vec![
            artifact("dep-a", "1.0.0", DEP_A, &[("dep-b", DEP_B)]),
            artifact("dep-a", "1.0.1", DEP_A1, &[]),
            artifact("dep-b", "1.0.0", DEP_B, &[]),
            artifact(
                "suite",
                "1.0.0",
                SUITE,
                &[("dep-a", DEP_A1), ("dep-b", DEP_B)],
            ),
        ];

        let outcome = resolve_lockfile(&rows, &[dep_a_direct()]).expect("resolve");

        let lockfile = outcome.lockfile_toml.expect("lockfile");
        assert_eq!(lock_version(&lockfile, "dep-a").as_deref(), Some("1.0.1"));
        assert_eq!(lock_version(&lockfile, "dep-b").as_deref(), Some("1.0.0"));
    }

    /// Without a covering seed the resolver walks direct-dep candidates and
    /// expands each candidate's dep closure through the same bounded
    /// `c_metadata` lookups.
    #[test]
    fn resolve_lockfile_expands_candidate_closures() {
        let rows = vec![
            artifact("dep-a", "1.0.0", DEP_A, &[("dep-b", DEP_B)]),
            artifact("dep-b", "1.0.0", DEP_B, &[]),
            artifact("dep-a", "1.0.1", DEP_A1, &[]),
        ];

        let outcome = resolve_lockfile(&rows, &[dep_a_direct()]).expect("resolve");

        let lockfile = outcome.lockfile_toml.expect("lockfile");
        assert_eq!(lock_version(&lockfile, "dep-a").as_deref(), Some("1.0.0"));
        assert_eq!(lock_version(&lockfile, "dep-b").as_deref(), Some("1.0.0"));
    }

    /// A direct dep whose semver req does not parse can never be satisfied
    /// from cache — it reports uncovered so the caller falls back.
    #[test]
    fn resolve_lockfile_reports_unparseable_requirements_uncovered() {
        let rows = vec![artifact("dep-a", "1.0.0", DEP_A, &[])];
        let outcome = resolve_lockfile(
            &rows,
            &[DirectDependency {
                crate_name: CrateName::parse("dep-a").expect("name"),
                req: "not-a-req".to_owned(),
                features: Vec::new(),
            }],
        )
        .expect("resolve");

        assert!(outcome.lockfile_toml.is_none());
        assert_eq!(
            outcome.uncovered_direct,
            vec![CrateName::parse("dep-a").expect("name")]
        );
    }

    /// An empty direct-dep list resolves to no lockfile — the CLI falls
    /// back to cargo's own resolver rather than taking an empty pin set
    /// as "fully cached".
    #[test]
    fn resolve_lockfile_empty_direct_deps_resolve_to_none() {
        let outcome = resolve_lockfile(&[], &[]).expect("resolve");
        assert!(outcome.lockfile_toml.is_none());
        assert_eq!(outcome.uncovered_direct, Vec::<CrateName>::new());
        assert_eq!(outcome.candidates_considered, 0);
    }

    /// Read a package's pinned version out of the synthesized lockfile.
    fn lock_version(lockfile: &str, crate_name: &str) -> Option<String> {
        let parsed = lockfile.parse::<toml::Table>().expect("lockfile toml");
        parsed
            .get("package")?
            .as_array()?
            .iter()
            .find(|package| package.get("name").and_then(toml::Value::as_str) == Some(crate_name))
            .and_then(|package| package.get("version"))
            .and_then(toml::Value::as_str)
            .map(str::to_owned)
    }
}
