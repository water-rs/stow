//! The superset-serving rule (stow#881): feature sets are never
//! unioned, but a set contained in another set of the same
//! `(crate, version, target, side)` is served by that set instead of
//! built.
//!
//! The choice is deterministic so CI-side submission and the CLI pick
//! the same set: the *smallest* containing set, ties broken by the
//! sorted feature list. Only a set that is itself built can serve —
//! on the submit side that is a set contained in no other set of its
//! group ([`serving_map`]); on the consume side every published index
//! row is built by definition, so the CLI calls
//! [`smallest_containing_set`] over the slice's published sets
//! directly.

use std::collections::{BTreeMap, BTreeSet};

use crate::versioning::{SemverBreakingLine, breaking_line};

/// `true` when `candidate` contains every element of `requested` —
/// both lists are canonical (strictly sorted, deduplicated), so the
/// check is one ordered merge.
#[must_use]
pub fn contains_all(candidate: &[String], requested: &[String]) -> bool {
    let mut requested = requested.iter().peekable();
    'outer: for member in candidate {
        while let Some(&want) = requested.peek() {
            match want.as_str().cmp(member.as_str()) {
                std::cmp::Ordering::Less => return false,
                std::cmp::Ordering::Equal => {
                    requested.next();
                }
                std::cmp::Ordering::Greater => continue 'outer,
            }
        }
        return true;
    }
    requested.peek().is_none()
}

/// The smallest set in `candidates` that contains `requested`.
///
/// Ties break on the sorted feature list; `None` when no candidate
/// contains it. `requested` itself counts: a candidate holding exactly
/// it is the smallest containing set there is.
#[must_use]
pub fn smallest_containing_set<'a>(
    requested: &[String],
    candidates: impl IntoIterator<Item = &'a [String]>,
) -> Option<&'a [String]> {
    candidates
        .into_iter()
        .filter(|candidate| contains_all(candidate, requested))
        .min_by(|left, right| left.len().cmp(&right.len()).then(left.cmp(right)))
}

/// The serving set of every set in `family` — one identity group's
/// observed feature sets.
///
/// A set contained in no other set of the family is *built* and maps
/// to itself; every other set maps to the smallest built set that
/// contains it (ties by the sorted feature list), which is the only
/// shape of set that can ever exist as an artifact.
///
/// # Panics
/// Never in fact — every set is contained in itself, so the lookup
/// always finds a built set.
#[must_use]
pub fn serving_map(family: &BTreeSet<Vec<String>>) -> BTreeMap<Vec<String>, Vec<String>> {
    let built: Vec<&Vec<String>> = family
        .iter()
        .filter(|set| {
            !family
                .iter()
                .any(|other| *set != other && contains_all(other, set))
        })
        .collect();
    family
        .iter()
        .map(|set| {
            let serving = smallest_containing_set(set, built.iter().map(|set| set.as_slice()))
                .expect("a set is always contained in at least one built set: itself");
            (set.clone(), serving.to_vec())
        })
        .collect()
}

/// One rule a closure keeps for a node (stow#1470, stow#1487): each
/// node answers to both keys, and two nodes of one key must hold the
/// same [`ClosureHeld`].
///
/// `C`, `V` and `T` are the caller's handles of a crate name, a version
/// and a target.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClosureKey<C, V, T> {
    /// One version per crate and cargo compatibility range across the
    /// whole closure, both sides and every target: cargo activates one
    /// version per `(name, source, compatibility)` for the whole
    /// resolve, so a closure pinning two versions of one range cannot
    /// be fetched.
    Range {
        /// The crate.
        crate_name: C,
        /// Its compatibility range.
        line: SemverBreakingLine,
    },
    /// One feature set per package version, target and side: the
    /// build's wrapper manifest declares each package version once per
    /// side.
    Package {
        /// The crate.
        crate_name: C,
        /// The version.
        version: V,
        /// The target the node compiles for.
        target: T,
        /// Whether it compiles for the host.
        host_side: bool,
    },
}

/// What a node holds under a [`ClosureKey`]: its version under a
/// `Range` key, its feature set under a `Package` key. `F` is the
/// caller's handle of a canonical feature list, so equal handles are
/// equal sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosureHeld<V, F> {
    /// The version a `Range` key holds.
    Version(V),
    /// The feature set a `Package` key holds.
    Features(F),
}

/// A node's two keys and what it holds under each.
pub type ClosureMembers<C, V, T, F> = [(ClosureKey<C, V, T>, ClosureHeld<V, F>); 2];

/// A node's two closure members: its version under its crate's range,
/// and its feature set under its package. `version` is the parsed
/// version the range is computed from; `handle` is the caller's handle
/// of it.
#[must_use]
pub fn closure_members<C: Clone, V: Clone, T, F>(
    crate_name: &C,
    version: &semver::Version,
    handle: &V,
    target: T,
    host_side: bool,
    features: F,
) -> ClosureMembers<C, V, T, F> {
    [
        (
            ClosureKey::Range {
                crate_name: crate_name.clone(),
                line: breaking_line(version),
            },
            ClosureHeld::Version(handle.clone()),
        ),
        (
            ClosureKey::Package {
                crate_name: crate_name.clone(),
                version: handle.clone(),
                target,
                host_side,
            },
            ClosureHeld::Features(features),
        ),
    ]
}

/// The members each key holds across a closure (stow#1470, stow#1487).
///
/// The key type `G` is the caller's [`ClosureKey`] and `S` its
/// [`ClosureHeld`]. A superset move is accepted only when everything it
/// splices in agrees with the members already held, on the submit side
/// ([`closure_disagreement`]) and the consume side alike.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureAgreement<G, S> {
    held: BTreeMap<G, S>,
}

impl<G, S> Default for ClosureAgreement<G, S> {
    fn default() -> Self {
        Self {
            held: BTreeMap::new(),
        }
    }
}

impl<G: Ord + Clone, S: PartialEq + Clone> ClosureAgreement<G, S> {
    /// The first of `members` whose group is held with another member.
    #[must_use]
    pub fn disagreement<'a>(
        &self,
        members: impl IntoIterator<Item = (&'a G, &'a S)>,
    ) -> Option<&'a G>
    where
        G: 'a,
        S: 'a,
    {
        members
            .into_iter()
            .find(|(group, member)| self.held.get(*group).is_some_and(|held| held != *member))
            .map(|(group, _)| group)
    }

    /// Hold `members`. A group already held keeps its member; call
    /// [`Self::disagreement`] first when they may differ.
    pub fn hold<'a>(&mut self, members: impl IntoIterator<Item = (&'a G, &'a S)>)
    where
        G: 'a,
        S: 'a,
    {
        for (group, member) in members {
            self.held
                .entry(group.clone())
                .or_insert_with(|| member.clone());
        }
    }

    /// Hold `member` for `group`, replacing one held before.
    pub fn replace(&mut self, group: G, member: S) {
        self.held.insert(group, member);
    }
}

/// The first key that holds two members inside the dependency closure
/// of `start`, with the member met first and the one that disagrees —
/// `None` when the closure agrees.
///
/// `node` names a node's members — none for a node whose keys the
/// caller knows hold one member everywhere — and `dependencies` pushes
/// a node's direct dependencies; both are the caller's view of its
/// graph. One walk, each node visited once.
pub fn closure_disagreement<
    G: Ord + Clone,
    S: PartialEq + Clone,
    M: IntoIterator<Item = (G, S)>,
>(
    start: usize,
    node: impl Fn(usize) -> M,
    dependencies: impl Fn(usize, &mut Vec<usize>),
) -> Option<(G, S, S)> {
    let mut held = BTreeMap::<G, S>::new();
    let mut seen = std::collections::HashSet::new();
    let mut stack = vec![start];
    while let Some(index) = stack.pop() {
        if !seen.insert(index) {
            continue;
        }
        for (key, member) in node(index) {
            match held.get(&key) {
                Some(existing) if *existing != member => {
                    return Some((key, existing.clone(), member));
                }
                Some(_) => {}
                None => {
                    held.insert(key, member);
                }
            }
        }
        dependencies(index, &mut stack);
    }
    None
}

/// What a disagreeing closure holds twice, for [`disagreement_text`].
#[derive(Debug, Clone, Copy)]
pub enum ClosureConflict<'a> {
    /// Two versions of one compatibility range.
    Versions([&'a semver::Version; 2]),
    /// Two feature sets of one package version on one side.
    FeatureSets {
        /// The version.
        version: &'a semver::Version,
        /// The target the nodes compile for.
        target: &'a str,
        /// Whether they compile for the host.
        host_side: bool,
    },
}

/// The package a disagreeing closure holds twice, in the words every
/// refusal of one uses.
///
/// `<crate> <older> and <newer>, two
/// semver-compatible versions cargo unifies` for a range, `<crate>
/// <version> with two feature sets on the <side> side for <target>` for
/// a package.
#[must_use]
pub fn disagreement_text(
    crate_name: impl std::fmt::Display,
    conflict: ClosureConflict<'_>,
) -> String {
    match conflict {
        ClosureConflict::Versions(versions) => {
            let [older, newer] = if versions[0] <= versions[1] {
                versions
            } else {
                [versions[1], versions[0]]
            };
            format!(
                "{crate_name} {older} and {newer}, two semver-compatible versions cargo unifies"
            )
        }
        ClosureConflict::FeatureSets {
            version,
            target,
            host_side,
        } => {
            let side = if host_side { "host" } else { "target" };
            format!("{crate_name} {version} with two feature sets on the {side} side for {target}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(features: &[&str]) -> Vec<String> {
        features
            .iter()
            .map(|feature| (*feature).to_owned())
            .collect()
    }

    fn sets(list: &[&[&str]]) -> BTreeSet<Vec<String>> {
        list.iter().map(|features| set(features)).collect()
    }

    #[test]
    fn a_contained_set_is_served_by_the_smallest_container() {
        // Only a set that is itself built can serve: `["a","b"]` is
        // contained in `["a","b","c"]`, so the chain collapses to the
        // one built container.
        let family = sets(&[&["a"], &["a", "b"], &["a", "b", "c"], &["d"]]);
        let map = serving_map(&family);
        assert_eq!(map[&set(&["a"])], set(&["a", "b", "c"]));
        assert_eq!(map[&set(&["a", "b"])], set(&["a", "b", "c"]));
        assert_eq!(map[&set(&["a", "b", "c"])], set(&["a", "b", "c"]));
        assert_eq!(map[&set(&["d"])], set(&["d"]));
        // When the middle set is built, it is the smallest container.
        let family = sets(&[&["a"], &["a", "b"], &["d"]]);
        assert_eq!(serving_map(&family)[&set(&["a"])], set(&["a", "b"]));
    }

    #[test]
    fn a_tie_breaks_on_the_sorted_feature_list() {
        // `["a","d"]` and `["a","c"]` tie on size; the sorted-list
        // comparison picks `["a","c"]`.
        let family = sets(&[&["a"], &["a", "c"], &["a", "d"]]);
        let map = serving_map(&family);
        assert_eq!(map[&set(&["a"])], set(&["a", "c"]));
    }

    #[test]
    fn an_uncontained_set_is_built_as_itself() {
        // `{a, d}` beside `{a, b, c}`: neither contains the other, so
        // both build.
        let family = sets(&[&["a", "b", "c"], &["a", "d"]]);
        let map = serving_map(&family);
        assert_eq!(map[&set(&["a", "d"])], set(&["a", "d"]));
        assert_eq!(map[&set(&["a", "b", "c"])], set(&["a", "b", "c"]));
    }

    #[test]
    fn an_empty_set_is_contained_in_everything_built() {
        let family = sets(&[&[], &["a", "b"], &["a", "b", "c"]]);
        let map = serving_map(&family);
        // The empty set is served by the smallest built container.
        assert_eq!(map[&set(&[])], set(&["a", "b", "c"]));
        // Alone, it is built as itself.
        let alone = sets(&[&[]]);
        assert_eq!(serving_map(&alone)[&set(&[])], set(&[]));
    }

    #[test]
    fn identical_sets_collapse_to_one_built_set() {
        let family = sets(&[&["a", "b"], &["a", "b"]]);
        let map = serving_map(&family);
        assert_eq!(map.len(), 1);
        assert_eq!(map[&set(&["a", "b"])], set(&["a", "b"]));
    }

    #[test]
    fn the_chooser_serves_directly_over_a_candidate_pool() {
        let published = [set(&["a", "b"]), set(&["a", "b", "c"]), set(&["a", "d"])];
        let refs = published.iter().map(Vec::as_slice);
        assert_eq!(
            smallest_containing_set(&set(&["a"]), refs),
            Some(set(&["a", "b"]).as_slice())
        );
        assert_eq!(
            smallest_containing_set(&set(&["x"]), published.iter().map(Vec::as_slice)),
            None
        );
    }
}
