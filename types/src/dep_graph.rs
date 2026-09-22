//! The host/target split of a resolved dependency graph.
//!
//! The rules both task sources apply so `cargo metadata` expansions and
//! crates.io human-request closures mint the same nodes. Cargo's unit
//! graph assigns every compiled package a compile kind:
//! `CompileKind::Target` for the consumer's library graph and
//! `CompileKind::Host` for proc-macro crates and every package reached
//! only through build-dependency or proc-macro edges (cargo's feature
//! resolver tracks the same distinction as `FeaturesFor::HostDep` —
//! `src/cargo/core/resolver/features.rs`). The pieces a task source
//! needs are the same in either metadata shape, so they live here: which
//! side an edge lands on, how a `target` cfg spec is evaluated, and the
//! per-package feature expansion that yields a side's feature set.

use std::collections::{BTreeMap, BTreeSet};

/// Which side of a consumer's build a graph node compiles for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CompileSide {
    /// Compiled on the builder's own host — proc-macro crates and every
    /// package compiled only for a build script or proc-macro.
    Host,
    /// Compiled for the target the consumer builds.
    Target,
}

/// The side a dependency edge lands on.
///
/// Cargo promotes an edge to `FeaturesFor::HostDep` when the dependency
/// is a build dependency or a proc-macro lib, and a `HostDep` package's
/// own dependencies stay `HostDep` — a build script's or proc-macro's
/// whole subgraph compiles for the host.
#[must_use]
pub const fn dep_side(parent: CompileSide, is_build: bool, dep_is_proc_macro: bool) -> CompileSide {
    match parent {
        CompileSide::Host => CompileSide::Host,
        CompileSide::Target if is_build || dep_is_proc_macro => CompileSide::Host,
        CompileSide::Target => CompileSide::Target,
    }
}

/// How many undecidable predicates one spec may name before the search
/// over their assignments is abandoned in favour of including the
/// dependency. Two is already unusual in a published manifest; eight
/// bounds the search at 256 evaluations.
const MAX_UNDECIDABLE_PREDICATES: usize = 8;

/// The distinct predicates in `expression` that a target triple cannot
/// decide, in a stable order.
fn undecidable_predicates(expression: &cfg_expr::Expression) -> Vec<cfg_expr::Predicate<'_>> {
    let mut undecidable = Vec::new();
    for predicate in expression.predicates() {
        if matches!(predicate, cfg_expr::Predicate::Target(_)) || undecidable.contains(&predicate) {
            continue;
        }
        undecidable.push(predicate);
    }
    undecidable
}

/// Whether a dependency `target` restriction applies to `target_triple`.
///
/// The restriction is a `cfg(...)` expression or a bare target triple.
/// Specs that cannot be evaluated include the dependency: dropping a
/// real edge would silently break the ordering guarantee, while an
/// extra task is a wasted build at worst. That rule holds per
/// predicate, not only per spec — see below.
#[must_use]
pub fn dep_target_matches(spec: &str, target_triple: &str) -> bool {
    if spec.starts_with("cfg") {
        let expression = match cfg_expr::Expression::parse(spec) {
            Ok(expression) => expression,
            Err(error) => {
                tracing::warn!(spec, %error, "unparseable dependency target spec — including dependency");
                return true;
            }
        };
        let Some(target_info) = cfg_expr::targets::get_builtin_target_by_triple(target_triple)
        else {
            tracing::warn!(
                spec,
                target_triple,
                "unknown builtin target — including dependency"
            );
            return true;
        };
        // A triple decides `target_os`, `target_arch` and their kin and
        // nothing else: `target_feature` depends on the flags the build
        // runs with, and a bare `cfg` flag on the compiler invocation.
        //
        // An undecidable predicate is safe to answer `true` only in a
        // positive position — under `not(...)` that answer *drops* a real
        // edge, which is how `encoding_rs`'s
        // `not(all(target_feature = "avx2", target_feature = "bmi1"))`
        // lost the whole `multiversion` subtree on x86_64 and made the
        // register check refuse `unicode-ident`, an artifact the build
        // really did compile. Answering them all `false` is no better:
        // it drops `all(target_feature = "avx2", not(target_feature =
        // "avx512f"))`, which a build with AVX2 and no AVX512F really
        // does compile.
        //
        // The dependency is included when *some* assignment of the
        // undecidable predicates satisfies the expression, so every
        // assignment is tried. Real specs name one or two of them; a
        // spec naming more than `MAX_UNDECIDABLE_PREDICATES` is included
        // without the search rather than paying for its powerset, since
        // an extra task is a wasted build and a dropped edge is a broken
        // one.
        let undecidable = undecidable_predicates(&expression);
        if undecidable.len() > MAX_UNDECIDABLE_PREDICATES {
            tracing::warn!(
                spec,
                predicates = undecidable.len(),
                "dependency target spec rests on too many undecidable predicates to search — including dependency"
            );
            return true;
        }
        (0..(1u32 << undecidable.len())).any(|assignment| {
            expression.eval(|predicate| match predicate {
                cfg_expr::Predicate::Target(target) => target.matches(target_info),
                other => undecidable
                    .iter()
                    .position(|candidate| candidate == other)
                    .is_some_and(|index| assignment & (1 << index) != 0),
            })
        })
    } else {
        spec == target_triple
    }
}

/// Every feature name a caller may legitimately select on a package.
///
/// The declared `[features]` keys plus the implicit feature cargo
/// grants each optional dependency — minus the optional dependencies
/// some declared feature reaches through `dep:<name>`, which hides the
/// implicit one. `optional_deps` maps each declared dependency's
/// manifest alias (the name feature expressions spell) to its
/// `optional` flag.
#[must_use]
pub fn selectable_features(
    features: &BTreeMap<String, Vec<String>>,
    optional_deps: &BTreeMap<String, bool>,
) -> BTreeSet<String> {
    let dep_referenced = features
        .values()
        .flat_map(|items| items.iter())
        .filter_map(|item| item.strip_prefix("dep:"))
        .collect::<BTreeSet<_>>();
    features
        .keys()
        .cloned()
        .chain(
            optional_deps
                .iter()
                .filter(|(_, optional)| **optional)
                .map(|(name, _)| name.as_str())
                .filter(|name| !dep_referenced.contains(name))
                .map(ToOwned::to_owned),
        )
        .collect()
}

/// The feature set one package resolves under `seeds`.
///
/// Seeds are restricted to names the package's feature graph actually
/// declares — a bogus seed must never mint a new canonical identity —
/// then closed over the `[features]` table, where an item naming
/// another feature pulls it in. `dep:`/`x/feat` items act on
/// dependencies, not on this package's own set, so they never enter it.
#[must_use]
pub fn resolve_features(
    features_map: &BTreeMap<String, Vec<String>>,
    selectable: &BTreeSet<String>,
    seeds: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut features = seeds
        .iter()
        .filter(|feature| selectable.contains(feature.as_str()))
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut queue = features
        .iter()
        .cloned()
        .collect::<std::collections::VecDeque<String>>();
    while let Some(feature) = queue.pop_front() {
        let Some(items) = features_map.get(&feature) else {
            continue;
        };
        for item in items {
            if item.starts_with("dep:") || item.contains('/') {
                continue;
            }
            if features.insert(item.clone()) {
                queue.push_back(item.clone());
            }
        }
    }
    features
}

/// Which dependency aliases a resolved feature set enables, and which
/// features it seeds on each of them.
///
/// `dep:x` and `x/feat` items both select `x` — the slash form
/// additionally seeds `feat` on it — while `x?/feat` seeds `feat` only,
/// applying when `x` was enabled by anything. Every name is the
/// manifest alias a feature expression spells, never the crate the
/// dependency resolves to.
#[derive(Debug, Default)]
pub struct DepEnable {
    /// Aliases the feature set selects as dependencies.
    pub enabled: BTreeSet<String>,
    /// Extra feature seeds per alias from `x/feat` and `x?/feat` items.
    pub feature_seeds: BTreeMap<String, BTreeSet<String>>,
}

/// Compute the [`DepEnable`] a package's resolved `features` produce
/// over its declared `[features]` table.
#[must_use]
pub fn enabled_dependencies(
    features_map: &BTreeMap<String, Vec<String>>,
    features: &BTreeSet<String>,
) -> DepEnable {
    let mut enable = DepEnable::default();
    for feature in features {
        let Some(items) = features_map.get(feature) else {
            continue;
        };
        for item in items {
            if let Some(dep) = item.strip_prefix("dep:") {
                enable.enabled.insert(dep.to_owned());
            } else if let Some((dep, dep_feature)) = item.split_once('/') {
                if let Some(weak) = dep.strip_suffix('?') {
                    enable
                        .feature_seeds
                        .entry(weak.to_owned())
                        .or_default()
                        .insert(dep_feature.to_owned());
                } else {
                    enable.enabled.insert(dep.to_owned());
                    enable
                        .feature_seeds
                        .entry(dep.to_owned())
                        .or_default()
                        .insert(dep_feature.to_owned());
                }
            }
        }
    }
    enable
}

#[cfg(test)]
mod tests {
    use super::dep_target_matches;

    /// `encoding_rs` gates `multiversion` on
    /// `not(all(target_feature = "avx2", target_feature = "bmi1"))`. A
    /// triple cannot decide a `target_feature`, and answering such a
    /// predicate `true` inside a `not(...)` drops the edge — which took
    /// `multiversion-macros`, `syn`, `proc-macro2` and `unicode-ident` out
    /// of every `x86_64` closure that reaches `encoding_rs`, so the register
    /// check refused artifacts the build really had compiled.
    #[test]
    fn a_dependency_behind_a_negated_target_feature_stays_in_the_closure() {
        assert!(dep_target_matches(
            "cfg(all(any(target_arch = \"x86_64\", target_arch = \"x86\"), not(all(target_feature = \"avx2\", target_feature = \"bmi1\"))))",
            "x86_64-unknown-linux-gnu",
        ));
    }

    /// Answering the undecidable predicates all-true or all-false are both
    /// wrong, in opposite directions: a spec that wants one feature and
    /// not another is satisfied only by a mixed assignment, and a build
    /// with AVX2 and no AVX512F really does compile this dependency.
    #[test]
    fn a_dependency_behind_two_opposed_target_features_stays_in_the_closure() {
        assert!(dep_target_matches(
            "cfg(all(target_feature = \"avx2\", not(target_feature = \"avx512f\")))",
            "x86_64-unknown-linux-gnu",
        ));
    }

    /// The triple still decides what it can: an arch the spec excludes
    /// keeps the dependency out, undecidable predicates or not.
    #[test]
    fn a_dependency_the_target_arch_excludes_stays_out() {
        assert!(!dep_target_matches(
            "cfg(all(any(target_arch = \"x86_64\", target_arch = \"x86\"), not(all(target_feature = \"avx2\", target_feature = \"bmi1\"))))",
            "aarch64-apple-darwin",
        ));
        assert!(!dep_target_matches(
            "cfg(windows)",
            "x86_64-unknown-linux-gnu",
        ));
        // No assignment of the undecidable half can rescue a decided
        // `false`, however the two are combined.
        assert!(!dep_target_matches(
            "cfg(all(target_os = \"windows\", target_feature = \"avx2\"))",
            "x86_64-unknown-linux-gnu",
        ));
    }

    /// A spec resting on more undecidable predicates than the search will
    /// enumerate keeps the dependency: an extra task is a wasted build,
    /// while a dropped edge breaks the closure the register check uses.
    #[test]
    fn a_spec_with_too_many_undecidable_predicates_keeps_the_dependency() {
        let features = (0..12)
            .map(|index| format!("target_feature = \"f{index}\""))
            .collect::<Vec<_>>()
            .join(", ");
        assert!(dep_target_matches(
            &format!("cfg(not(all({features})))"),
            "x86_64-unknown-linux-gnu",
        ));
    }

    /// The host-side counterpart of the cross-target rule: a `cfg(unix)`
    /// build dependency holds when evaluated against the linux host even
    /// though the consumer's target — `wasm32-unknown-unknown` — is not
    /// unix.
    #[test]
    fn a_host_side_dep_is_evaluated_against_the_host_triple() {
        assert!(dep_target_matches("cfg(unix)", "x86_64-unknown-linux-gnu"));
        assert!(!dep_target_matches("cfg(unix)", "wasm32-unknown-unknown"));
    }
}
