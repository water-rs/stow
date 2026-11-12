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

/// The one feature set each group holds across a closure (stow#1470):
/// a closure never carries two sets of one `(crate, version, target,
/// side)`, because the build's wrapper manifest declares each package
/// version once per side. The group type `G` is the caller's identity
/// of that tuple. A superset move is accepted only when everything it
/// splices in agrees with the sets already held, on the submit side
/// ([`closure_disagreement`]) and the consume side alike.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureAgreement<G> {
    sets: BTreeMap<G, Vec<String>>,
}

impl<G> Default for FeatureAgreement<G> {
    fn default() -> Self {
        Self {
            sets: BTreeMap::new(),
        }
    }
}

impl<G: Ord + Clone> FeatureAgreement<G> {
    /// The first of `members` whose group is held with another set.
    #[must_use]
    pub fn disagreement<'a>(
        &self,
        members: impl IntoIterator<Item = (&'a G, &'a [String])>,
    ) -> Option<&'a G>
    where
        G: 'a,
    {
        members
            .into_iter()
            .find(|(group, features)| self.sets.get(*group).is_some_and(|held| held != features))
            .map(|(group, _)| group)
    }

    /// Hold `members`' sets. A group already held keeps its set; call
    /// [`Self::disagreement`] first when they may differ.
    pub fn hold<'a>(&mut self, members: impl IntoIterator<Item = (&'a G, &'a [String])>)
    where
        G: 'a,
    {
        for (group, features) in members {
            self.sets
                .entry(group.clone())
                .or_insert_with(|| features.to_vec());
        }
    }

    /// Hold `features` for `group`, replacing a set held before.
    pub fn replace(&mut self, group: G, features: Vec<String>) {
        self.sets.insert(group, features);
    }
}

/// The first group that holds two feature sets inside the dependency
/// closure of `start` — `None` when the closure agrees. `node` names a
/// node's group and set — `None` for a node whose group the caller
/// knows holds one set everywhere — and `dependencies` pushes a node's
/// direct dependencies; both are the caller's view of its graph.
pub fn closure_disagreement<'a, G: Ord + Clone>(
    start: usize,
    node: impl Fn(usize) -> Option<(G, &'a [String])>,
    dependencies: impl Fn(usize, &mut Vec<usize>),
) -> Option<G> {
    let mut held = BTreeMap::<G, &'a [String]>::new();
    let mut seen = std::collections::HashSet::new();
    let mut stack = vec![start];
    while let Some(index) = stack.pop() {
        if !seen.insert(index) {
            continue;
        }
        if let Some((group, features)) = node(index) {
            match held.get(&group) {
                Some(existing) if *existing != features => return Some(group),
                Some(_) => {}
                None => {
                    held.insert(group, features);
                }
            }
        }
        dependencies(index, &mut stack);
    }
    None
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
