//! The stow lockfile resolver: given a project's direct deps, synthesize a
//! `Cargo.lock` whose every package pins a cached artifact.
//!
//! The engine is pure data logic over [`crate::db`] — it lives outside the
//! wasm-gated `api` module so the whole search (seed fast path, candidate
//! filtering, backtracking) stays host-testable.

use std::collections::{BTreeMap, BTreeSet};

use skyzen_services::Db;
use stow_types::api::{ResolveLockfileRequest, ResolveLockfileResponse};

use crate::db;

/// A direct dep with its semver requirement and requested feature set
/// parsed once, before candidate search begins.
type TypedDirectDep = (
    stow_types::identity::CrateName,
    semver::VersionReq,
    BTreeSet<String>,
);

/// Mutable counters shared by every search step: `considered` is reported
/// back as `candidates_considered`, `budget` hard-caps search steps so a
/// pathological closure cannot stall the request.
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

/// In-memory index over the cached artifact rows one resolve can reach:
/// every row named by a direct dep, every row whose `dependency_count`
/// could cover the direct set (seed candidates), and every `c_metadata`
/// row those rows' dep closures expand to. The resolver runs all closure
/// walks against these maps — otherwise per-transitive D1 queries dominate
/// runtime when a resolve has 30+ direct deps each pulling 30+
/// transitives.
///
/// `by_pair` is dual-keyed on the dashed and underscored name forms:
/// `dependency_c_metadata_json` is captured from rustc `--extern` arg
/// names (underscored — `grep_cli`, `nu_ansi_term`), but
/// `artifacts.crate_name` carries cargo's published name (dashed —
/// `grep-cli`, `nu-ansi-term`). Both forms are cached under the same
/// `c_metadata`, so both resolve to the same row. The fix-at-write-time
/// lives in the CI capture path (stow-build's `dep_scan`); this in-resolver
/// normalization is a forward-compatible bridge.
struct ResolverIndex<'a> {
    /// Rows whose `dependency_count` could cover the whole direct-dep set —
    /// the only rows the seed scan may consider.
    seeds: Vec<&'a db::ResolverArtifactRow>,
    by_pair: BTreeMap<(String, String), &'a db::ResolverArtifactRow>,
    /// `c_metadata` is unique per (target, `rustc_version`), so this is a
    /// 1:1 index — the fallback when a `dependency_c_metadata_json`
    /// entry's name disagrees with the cached row's name (Cargo lets a
    /// project rename a dep via `package = "..."`; rustc captures the
    /// local alias, the cache stores the published name).
    by_c_metadata: BTreeMap<String, &'a db::ResolverArtifactRow>,
    by_crate: BTreeMap<String, Vec<&'a db::ResolverArtifactRow>>,
}

impl<'a> ResolverIndex<'a> {
    fn new(all: &'a [db::ResolverArtifactRow], min_seed_deps: i64) -> Self {
        let mut index = Self {
            seeds: Vec::new(),
            by_pair: BTreeMap::new(),
            by_c_metadata: BTreeMap::new(),
            by_crate: BTreeMap::new(),
        };
        for row in all {
            if row.dependency_count >= min_seed_deps {
                index.seeds.push(row);
            }
        }
        for row in all {
            index
                .by_pair
                .insert((row.crate_name.clone(), row.c_metadata.clone()), row);
            let alt = row.crate_name.replace('-', "_");
            if alt != row.crate_name {
                index.by_pair.insert((alt, row.c_metadata.clone()), row);
            }
            index.by_c_metadata.insert(row.c_metadata.clone(), row);
            index
                .by_crate
                .entry(row.crate_name.clone())
                .or_default()
                .push(row);
        }
        index
    }

    /// Look up a cached row by (name, `c_metadata`), trying the verbatim
    /// name first, then the dash↔underscore alt, then — for renamed deps
    /// where the rustc alias diverges from the cargo-published name
    /// entirely — by `c_metadata` alone (1:1 in this target/rustc index).
    fn lookup_dep_row(&self, name: &str, c_metadata: &str) -> Option<&'a db::ResolverArtifactRow> {
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
    fn candidate_closure_is_cached(&self, candidate: &db::ResolverArtifactRow) -> bool {
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
        candidate: &'a db::ResolverArtifactRow,
    ) -> Option<(String, String)> {
        let mut visited: BTreeSet<String> = BTreeSet::new();
        self.first_uncached_recursive(candidate, &mut visited)
    }

    fn first_uncached_recursive(
        &self,
        candidate: &'a db::ResolverArtifactRow,
        visited: &mut BTreeSet<String>,
    ) -> Option<(String, String)> {
        if !visited.insert(candidate.c_metadata.clone()) {
            return None;
        }
        let deps = parse_dep_c_metadata(&candidate.dependency_c_metadata_json).ok()?;
        for (name, c_metadata) in &deps {
            let Some(dep_row) = self.lookup_dep_row(name, c_metadata) else {
                return Some((name.clone(), c_metadata.clone()));
            };
            if let Some(miss) = self.first_uncached_recursive(dep_row, visited) {
                return Some(miss);
            }
        }
        None
    }

    fn closure_is_cached_recursive(
        &self,
        candidate: &db::ResolverArtifactRow,
        visited: &mut BTreeSet<String>,
    ) -> bool {
        if !visited.insert(candidate.c_metadata.clone()) {
            return true;
        }
        let Ok(deps) = parse_dep_c_metadata(&candidate.dependency_c_metadata_json) else {
            return false;
        };
        for (name, c_metadata) in &deps {
            let Some(dep_row) = self.lookup_dep_row(name, c_metadata) else {
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
        candidate: &db::ResolverArtifactRow,
        state: &mut SearchState,
        mut diag: Option<&mut Vec<String>>,
    ) -> bool {
        let pin_key = (candidate.crate_name.clone(), candidate.c_metadata.clone());
        if pinned.contains_key(&pin_key) {
            return true;
        }
        let deps = match parse_dep_c_metadata(&candidate.dependency_c_metadata_json) {
            Ok(deps) => deps,
            Err(error) => {
                if let Some(d) = diag.as_deref_mut() {
                    d.push(format!(
                        "parse_dep failed for {} {}: {error}",
                        candidate.crate_name, candidate.version
                    ));
                }
                return false;
            }
        };
        let features = match parse_features_array(&candidate.features_json) {
            Ok(features) => features,
            Err(error) => {
                if let Some(d) = diag.as_deref_mut() {
                    d.push(format!(
                        "parse_features failed for {} {}: {error}",
                        candidate.crate_name, candidate.version
                    ));
                }
                return false;
            }
        };
        pinned.insert(
            pin_key.clone(),
            ResolverPin {
                version: candidate.version.clone(),
                features,
                c_metadata: candidate.c_metadata.clone(),
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

/// Load exactly the artifact rows this resolve can reach, in two
/// index-seeked phases instead of one whole-table read. Phase one pulls
/// every row named by a direct dep plus every row whose `dependency_count`
/// could cover the direct set (seed candidates). Phase two expands the
/// `c_metadata` set those rows' dep closures reference, level by level,
/// until no new row appears — the same fixpoint the in-memory walks run,
/// so every later `lookup_dep_row` resolves against a fully populated
/// index.
async fn load_resolver_rows(
    db: &Db,
    request: &ResolveLockfileRequest,
    typed_direct: &[TypedDirectDep],
) -> Result<Vec<db::ResolverArtifactRow>, crate::errors::DbError> {
    let direct_names = typed_direct
        .iter()
        .map(|(name, _, _)| name.as_str())
        .collect::<Vec<_>>();
    let min_seed_deps = i64::try_from(typed_direct.len()).map_err(|_| {
        crate::errors::DbError::Invariant("direct dep count exceeds i64 range".to_owned())
    })?;
    let mut rows = db::list_resolver_candidates(
        db,
        request.target.as_str(),
        request.rustc_version.as_str(),
        &direct_names,
        min_seed_deps,
    )
    .await?;

    let mut seen: BTreeSet<String> = rows.iter().map(|row| row.c_metadata.clone()).collect();
    let mut frontier = referenced_c_metadatas(&rows, &seen);
    while !frontier.is_empty() {
        let level = db::list_artifacts_by_c_metadata(
            db,
            request.target.as_str(),
            request.rustc_version.as_str(),
            &frontier,
        )
        .await?;
        if level.is_empty() {
            break;
        }
        seen.extend(level.iter().map(|row| row.c_metadata.clone()));
        frontier = referenced_c_metadatas(&level, &seen);
        rows.extend(level);
    }
    Ok(rows)
}

/// `c_metadata` values the rows' dep closures reference that have not been
/// loaded yet — the next BFS frontier.
fn referenced_c_metadatas(
    rows: &[db::ResolverArtifactRow],
    seen: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut frontier = BTreeSet::new();
    for row in rows {
        let Ok(deps) = parse_dep_c_metadata(&row.dependency_c_metadata_json) else {
            continue;
        };
        for (_, c_metadata) in deps {
            if !seen.contains(&c_metadata) {
                frontier.insert(c_metadata);
            }
        }
    }
    frontier
}

pub async fn run_stow_resolver(
    db: &Db,
    request: &ResolveLockfileRequest,
) -> Result<ResolveLockfileResponse, crate::errors::DbError> {
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
    if request.direct.is_empty() {
        return Ok(ResolveLockfileResponse {
            lockfile_toml: None,
            uncovered_direct: Vec::new(),
            candidates_considered: 0,
            seed_diagnostics: Vec::new(),
        });
    }

    let typed_direct = match type_direct_deps(&request.direct) {
        Ok(typed_direct) => typed_direct,
        Err(uncovered) => {
            return Ok(ResolveLockfileResponse {
                lockfile_toml: None,
                uncovered_direct: uncovered,
                candidates_considered: 0,
                seed_diagnostics: Vec::new(),
            });
        }
    };

    let all_artifacts = load_resolver_rows(db, request, &typed_direct).await?;
    let min_seed_deps = i64::try_from(typed_direct.len()).map_err(|_| {
        crate::errors::DbError::Invariant("direct dep count exceeds i64 range".to_owned())
    })?;
    let index = ResolverIndex::new(&all_artifacts, min_seed_deps);
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
        let uncovered: Vec<stow_types::identity::CrateName> = typed_direct
            .into_iter()
            .filter_map(|(name, _, _)| {
                if pinned_names.contains(name.as_str()) {
                    None
                } else {
                    Some(name)
                }
            })
            .collect();
        return Ok(ResolveLockfileResponse {
            lockfile_toml: None,
            uncovered_direct: uncovered,
            candidates_considered: state.considered,
            seed_diagnostics,
        });
    }

    let lockfile_toml = render_lockfile(&pinned)?;
    Ok(ResolveLockfileResponse {
        lockfile_toml: Some(lockfile_toml),
        uncovered_direct: Vec::new(),
        candidates_considered: state.considered,
        seed_diagnostics: Vec::new(),
    })
}

/// Parse each request direct dep's semver requirement once. A dep whose
/// req string does not parse cannot be satisfied from cache — it is
/// reported uncovered so the caller falls back to cargo's resolver.
fn type_direct_deps(
    direct: &[stow_types::api::UserDirectDependency],
) -> Result<Vec<TypedDirectDep>, Vec<stow_types::identity::CrateName>> {
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
) -> Vec<Vec<&'a db::ResolverArtifactRow>> {
    let mut direct_candidates = Vec::with_capacity(typed_direct.len());
    for (crate_name, req, user_features) in typed_direct {
        let Some(rows) = index.by_crate.get(crate_name.as_str()) else {
            direct_candidates.push(Vec::new());
            continue;
        };
        let mut filtered: Vec<&db::ResolverArtifactRow> = Vec::new();
        for row in rows {
            *considered = considered.saturating_add(1);
            let Ok(version) = semver::Version::parse(&row.version) else {
                continue;
            };
            if !req.matches(&version) {
                continue;
            }
            let Ok(features) = parse_features_array(&row.features_json) else {
                continue;
            };
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
            let a_deps = a.dependency_c_metadata_json.matches('\"').count();
            let b_deps = b.dependency_c_metadata_json.matches('\"').count();
            let av = semver::Version::parse(&a.version)
                .unwrap_or_else(|_| semver::Version::new(0, 0, 0));
            let bv = semver::Version::parse(&b.version)
                .unwrap_or_else(|_| semver::Version::new(0, 0, 0));
            b_deps.cmp(&a_deps).then(bv.cmp(&av))
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
        pinned.remove(&(seed_row.crate_name.clone(), seed_row.c_metadata.clone()));
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
) -> Option<&'a db::ResolverArtifactRow> {
    let direct_index: BTreeMap<&str, (&semver::VersionReq, &BTreeSet<String>)> = typed_direct
        .iter()
        .map(|(name, req, features)| (name.as_str(), (req, features)))
        .collect();
    let mut best: Option<(&db::ResolverArtifactRow, usize)> = None;
    let mut diagnostic_size_pass = 0_usize;
    let mut diagnostic_partial_match: Vec<(String, String, usize, String)> = Vec::new();
    for &row in &index.seeds {
        *considered = considered.saturating_add(1);
        let Ok(deps) = parse_dep_c_metadata(&row.dependency_c_metadata_json) else {
            continue;
        };
        // `index.seeds` is already bounded by the recorded dependency_count
        // — the same `deps.len() >= typed_direct.len()` predicate — so
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
                    row.crate_name.clone(),
                    row.version.clone(),
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
                row.crate_name.clone(),
                row.version.clone(),
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
                std::cmp::Ordering::Equal => {
                    let cv = semver::Version::parse(&current.version).ok();
                    let nv = semver::Version::parse(&row.version).ok();
                    nv > cv
                }
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
        let Ok(pinned_version) = semver::Version::parse(&pinned_row.version) else {
            return Err((
                covered_count,
                format!("unparseable pinned version for {user_name}"),
            ));
        };
        if !user_req.matches(&pinned_version) {
            return Err((
                covered_count,
                format!("req `{user_req}` does not match pinned {user_name} {pinned_version}"),
            ));
        }
        let Ok(pinned_features) = parse_features_array(&pinned_row.features_json) else {
            return Err((
                covered_count,
                format!("unparseable pinned features for {user_name}"),
            ));
        };
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
    direct_candidates: &[Vec<&db::ResolverArtifactRow>],
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
    /// Sorted (`dep_name`, `dep_c_metadata`) pairs from the cached artifact's
    /// `dependency_c_metadata_json`. Stored verbatim so the lockfile-render
    /// step can resolve them to (name, version) via `pinned`.
    deps: Vec<(String, String)>,
}

#[derive(Debug, serde::Deserialize)]
struct DepCMetadataIdentity {
    crate_name: String,
    c_metadata: String,
}

fn parse_features_array(features_json: &str) -> Result<BTreeSet<String>, serde_json::Error> {
    let entries: Vec<String> = serde_json::from_str(features_json)?;
    Ok(entries.into_iter().collect())
}

fn parse_dep_c_metadata(json: &str) -> Result<Vec<(String, String)>, serde_json::Error> {
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    let entries: Vec<DepCMetadataIdentity> = serde_json::from_str(json)?;
    Ok(entries
        .into_iter()
        .map(|entry| (entry.crate_name, entry.c_metadata))
        .collect())
}

const CRATES_IO_REGISTRY_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

fn render_lockfile(
    pinned: &BTreeMap<(String, String), ResolverPin>,
) -> Result<String, crate::errors::DbError> {
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
    .map_err(|error| {
        crate::errors::DbError::Invariant(format!("serialize synthesized lockfile: {error}"))
    })?;
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

#[cfg(all(test, not(target_arch = "wasm32")))]
mod sqlite_tests {
    use stow_types::api::{ArtifactRecord, ResolveLockfileRequest, UserDirectDependency};
    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::identity::{
        CMetadata, CrateName, CrateVersion, DependencyCMetadataIdentity, DependencyCMetadataJson,
        FeaturesJson,
    };
    use stow_types::platform::{PanicStrategy, Profile};

    const TARGET: &str = "x86_64-unknown-linux-gnu";
    const RUSTC: &str = "1.85.0";
    const DEP_A: &str = "aaaaaaaaaaaaaaaa";
    const DEP_B: &str = "bbbbbbbbbbbbbbbb";
    const SUITE: &str = "cccccccccccccccc";
    const DEP_A1: &str = "dddddddddddddddd";

    fn artifact(
        crate_name: &str,
        version: &str,
        c_metadata: &str,
        deps: &[(&str, &str)],
    ) -> ArtifactRecord {
        ArtifactRecord {
            compile_key: format!("{c_metadata}{c_metadata}"),
            c_metadata: CMetadata::parse(c_metadata).expect("c_metadata"),
            extra_filename: format!("-{c_metadata}"),
            target: TARGET.parse().expect("target"),
            rustc_version: RUSTC.parse().expect("rustc"),
            profile: Profile {
                opt_level: "0".to_owned(),
                debuginfo: 0,
                debug_assertions: true,
                overflow_checks: true,
                panic: PanicStrategy::Unwind,
            },
            emit: vec!["link".to_owned()],
            crate_name: CrateName::parse(crate_name).expect("name"),
            version: CrateVersion::new(semver::Version::parse(version).expect("version")),
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
            oci_reference: format!(
                "ghcr.io/water-rs/stow-cache:{crate_name}.{version}-x86_64-linux-{RUSTC}-abcdef012345-{c_metadata}"
            ),
            oci_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            has_native: false,
            artifact_kind: ArtifactKind::Rlib,
            crate_types: vec![RustCrateType::Rlib],
            artifact_size: 1,
        }
    }

    fn resolve_request(direct: Vec<UserDirectDependency>) -> ResolveLockfileRequest {
        ResolveLockfileRequest {
            target: TARGET.parse().expect("target"),
            rustc_version: RUSTC.parse().expect("rustc"),
            direct,
        }
    }

    fn dep_a_direct() -> UserDirectDependency {
        UserDirectDependency {
            crate_name: CrateName::parse("dep-a").expect("name"),
            req: "^1.0.0".to_owned(),
            features: vec!["default".to_owned()],
        }
    }

    /// A seed row is never named by the user's direct deps — the resolver
    /// finds it only through `dependency_count`. The seed's dep closure
    /// then expands level-by-level over `c_metadata` lookups until the
    /// whole pinned closure is resident.
    ///
    /// The seed records dep-a `1.0.1` while the standalone `1.0.0` row
    /// carries more deps and therefore sorts first for backtracking —
    /// `1.0.1` in the rendered lockfile proves the seed applied.
    #[tokio::test]
    async fn resolve_lockfile_seeds_from_covering_binary_row() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        crate::db::ensure_schema(&db).await.expect("schema");
        for record in [
            artifact("dep-a", "1.0.0", DEP_A, &[("dep-b", DEP_B)]),
            artifact("dep-a", "1.0.1", DEP_A1, &[]),
            artifact("dep-b", "1.0.0", DEP_B, &[]),
            artifact(
                "suite",
                "1.0.0",
                SUITE,
                &[("dep-a", DEP_A1), ("dep-b", DEP_B)],
            ),
        ] {
            crate::db::insert_artifact_record(&db, &record)
                .await
                .expect("insert artifact");
        }

        let outcome = super::run_stow_resolver(&db, &resolve_request(vec![dep_a_direct()]))
            .await
            .expect("resolve");

        let lockfile = outcome.lockfile_toml.expect("lockfile");
        assert_eq!(lock_version(&lockfile, "dep-a").as_deref(), Some("1.0.1"));
        assert_eq!(lock_version(&lockfile, "dep-b").as_deref(), Some("1.0.0"));
    }

    /// Without a covering seed the resolver walks direct-dep candidates and
    /// expands each candidate's dep closure through the same bounded
    /// `c_metadata` lookups — rows outside the closure are never read.
    #[tokio::test]
    async fn resolve_lockfile_expands_candidate_closures() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        crate::db::ensure_schema(&db).await.expect("schema");
        for record in [
            artifact("dep-a", "1.0.0", DEP_A, &[("dep-b", DEP_B)]),
            artifact("dep-b", "1.0.0", DEP_B, &[]),
            artifact("dep-a", "1.0.1", DEP_A1, &[]),
        ] {
            crate::db::insert_artifact_record(&db, &record)
                .await
                .expect("insert artifact");
        }

        let outcome = super::run_stow_resolver(&db, &resolve_request(vec![dep_a_direct()]))
            .await
            .expect("resolve");

        let lockfile = outcome.lockfile_toml.expect("lockfile");
        assert_eq!(lock_version(&lockfile, "dep-a").as_deref(), Some("1.0.0"));
        assert_eq!(lock_version(&lockfile, "dep-b").as_deref(), Some("1.0.0"));
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
