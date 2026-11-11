//! The serve map: what a build's index slices and local artifacts could
//! serve.
//!
//! `stow build` computes the `(crate, version)` pairs this build's cached
//! index slice and local artifacts cover, plus the crate names a
//! semver-compatible upgrade could serve when semantic fallback is on. The
//! build's background analysis replaces it once the fresh index slice and
//! the exact dependency graph land — work that runs while cargo builds
//! (stow#347). The session's plan path reads the current map: a
//! registry unit it does not cover compiles without a lookup.

use std::sync::Arc;

/// The version slot a wildcard entry holds instead of one version.
const WILDCARD: &str = "*";

/// The bound on a plan's wait for a pending serve map: long enough for the
/// driver's fresh slice fetch to land, short enough that a stuck fetch
/// cannot stall the build's unit queue past it (stow#347).
pub const SERVE_MAP_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The serve decision, distilled to what a plan can look up before any
/// lookup runs: which `(crate, version)` pairs this build could serve, per
/// side of the unit graph, plus `("name", "*")` entries meaning any
/// semver-compatible upgrade of that crate could serve.
///
/// Covering a unit that cannot actually serve only costs a lookup; the map
/// errs on that side. What it must never do is fail to cover a unit that
/// could serve — the plan that misses the map would compile it.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServeMap {
    /// Units invoked with `--target`: the consumer side of the graph.
    pub target: Vec<(String, String)>,
    /// Units invoked without one — host dependencies, and every unit on a
    /// native build.
    pub host: Vec<(String, String)>,
    /// The map may still grow: it was built from the cached slices alone
    /// because the fresh index fetch could not finish before cargo started
    /// (stow#347). A plan for a registry unit the map does not cover holds
    /// until the build's next map clears the flag, rather than compiling a
    /// unit the fetch may be about to cover (stow#788: "pending" means a
    /// fetch is in flight, so the set of names it can add is not yet
    /// closed).
    pub pending: bool,
}

impl ServeMap {
    /// Whether anything in the build could serve `name` at `version` on
    /// this side of the graph: an exact pair, or a wildcard when the
    /// build's semantic fallback is on.
    pub(crate) fn covers(&self, spelled_target: bool, canonical_name: &str, version: &str) -> bool {
        let entries = if spelled_target {
            &self.target
        } else {
            &self.host
        };
        entries.iter().any(|(entry_name, entry_version)| {
            entry_name == canonical_name && (entry_version == version || entry_version == WILDCARD)
        })
    }
}

/// The build's serve map as the plan path reads it: the latest map the
/// enrichment published, `None` for a build that has none — which then
/// plans every unit through the lookup chain.
#[derive(Debug, Clone)]
pub struct ServeMapView(tokio::sync::watch::Receiver<Option<Arc<ServeMap>>>);

impl Default for ServeMapView {
    fn default() -> Self {
        Self::absent()
    }
}

impl ServeMapView {
    /// A view of a build with no serve map.
    #[must_use]
    pub fn absent() -> Self {
        serve_map_cell(None).1
    }

    /// The latest published map.
    #[must_use]
    pub fn current(&self) -> Option<Arc<ServeMap>> {
        self.0.borrow().clone()
    }
}

/// The side of the serve map's cell that replaces it.
#[derive(Debug)]
pub struct ServeMapWriter(tokio::sync::watch::Sender<Option<Arc<ServeMap>>>);

impl ServeMapWriter {
    /// Replace the build's map: every plan after this reads `map`.
    pub fn publish(&self, map: ServeMap) {
        self.0.send_replace(Some(Arc::new(map)));
    }
}

/// A build's serve map cell: its first value, the writer that replaces it
/// and the view the plan path reads.
#[must_use]
pub fn serve_map_cell(initial: Option<ServeMap>) -> (ServeMapWriter, ServeMapView) {
    let (sender, receiver) = tokio::sync::watch::channel(initial.map(Arc::new));
    (ServeMapWriter(sender), ServeMapView(receiver))
}

/// The build's "the serve map is final" signal: the enrichment completes
/// it once the pending map's final write lands, and the waiters' guard
/// completes it on drop, so a failed or cancelled analysis still releases
/// every plan it held (stow#347).
#[derive(Debug)]
pub struct ServeMapSignal {
    latch: crate::Latch,
}

impl ServeMapSignal {
    /// A signal that has not yet seen the final write.
    #[must_use]
    pub fn pending() -> Self {
        Self {
            latch: crate::Latch::pending(),
        }
    }

    /// A signal already final — the at-once answer a session with no
    /// pending map to wait on gives.
    #[must_use]
    pub fn settled() -> Self {
        let signal = Self::pending();
        signal.complete();
        signal
    }

    /// The final map has landed: release every waiter, the ones already
    /// parked and the ones that have not asked yet.
    pub fn complete(&self) {
        self.latch.complete();
    }

    /// Whether the final write has landed — the at-once check for a
    /// caller that waits only on a still-pending signal.
    pub fn has_completed(&self) -> bool {
        self.latch.has_completed()
    }

    /// Wait for [`Self::complete`], whether the completion lands before
    /// or after the wait starts. A signal nobody completes resolves
    /// nothing.
    pub async fn wait(&self) {
        self.latch.wait().await;
    }

    /// Resolve once `waits` waits have parked on the still-pending
    /// signal — the test observation [`crate::Latch::parked`] carries
    /// (stow#810).
    #[cfg(test)]
    pub(crate) async fn parked(&self, waits: usize) {
        self.latch.parked(waits).await;
    }
}

impl Default for ServeMapSignal {
    /// A context nobody armed has no pending map: the answer is at once.
    fn default() -> Self {
        Self::settled()
    }
}

/// The completion side of a pending map's signal: dropping it — the
/// successful write, a failed fetch, a cancelled task — completes the
/// signal, so a plan's wait can never outlive the analysis it waits on
/// (stow#347).
#[derive(Debug)]
pub struct ServeMapWaiters(Arc<ServeMapSignal>);

impl ServeMapWaiters {
    /// Arm `signal` for this build's pending map.
    pub const fn new(signal: Arc<ServeMapSignal>) -> Self {
        Self(signal)
    }
}

impl Drop for ServeMapWaiters {
    fn drop(&mut self) {
        self.0.complete();
    }
}

#[cfg(test)]
mod tests {
    use super::{ServeMap, WILDCARD};

    /// The final write can land before any plan has asked: a plan that
    /// asks afterwards must hear it at once, not wait out its timeout on
    /// a signal handed to no subscriber.
    #[tokio::test]
    async fn a_signal_completed_before_its_first_waiter_still_releases_it() {
        let signal = super::ServeMapSignal::pending();
        signal.complete();
        tokio::time::timeout(std::time::Duration::from_secs(5), signal.wait())
            .await
            .expect("a completed signal answers a late waiter at once");
    }

    fn map(target: &[(&str, &str)], host: &[(&str, &str)]) -> ServeMap {
        ServeMap {
            target: target
                .iter()
                .map(|(name, version)| ((*name).to_owned(), (*version).to_owned()))
                .collect(),
            host: host
                .iter()
                .map(|(name, version)| ((*name).to_owned(), (*version).to_owned()))
                .collect(),
            pending: false,
        }
    }

    /// An exact pair covers the unit; a different version and a different
    /// crate do not.
    #[test]
    fn a_pair_covers_exactly_its_version() {
        let map = map(&[("serde", "1.0.219")], &[]);
        assert!(map.covers(true, "serde", "1.0.219"));
        assert!(!map.covers(true, "serde", "1.0.220"));
        assert!(!map.covers(true, "serde_json", "1.0.219"));
    }

    /// A wildcard covers every version of its crate — the semantic-fallback
    /// shape — and nothing else.
    #[test]
    fn a_wildcard_covers_every_version() {
        let map = map(&[("serde", WILDCARD)], &[]);
        assert!(map.covers(true, "serde", "0.9.0"));
        assert!(!map.covers(true, "serde_json", "1.0.219"));
    }

    /// The two sides answer from their own sets: a consumer-covered crate
    /// does not cover a host-side unit.
    #[test]
    fn each_side_reads_its_own_coverage() {
        let map = map(&[("serde", "1.0.219")], &[("proc_macro2", "1.0.101")]);
        assert!(!map.covers(false, "serde", "1.0.219"));
        assert!(map.covers(false, "proc_macro2", "1.0.101"));
    }

    /// The serialized shape round-trips.
    #[test]
    fn the_serialized_shape_round_trips() {
        let mut map = map(
            &[("serde", "1.0.219"), ("libc", WILDCARD)],
            &[("log", "0.4.27")],
        );
        map.pending = true;
        let encoded = serde_json::to_string(&map).expect("serialize");
        let decoded: ServeMap = serde_json::from_str(&encoded).expect("parse");
        assert!(decoded.covers(true, "serde", "1.0.219"));
        assert!(decoded.covers(true, "libc", "0.2.177"));
        assert!(decoded.covers(false, "log", "0.4.27"));
        assert!(!decoded.covers(true, "log", "0.4.27"));
        assert!(decoded.pending);
    }

    /// stow#608: a completion that lands before anyone waits still
    /// releases a waiter that arrives later — the latch stores its
    /// state with `send_replace`, where `watch::Sender::send` would
    /// have stored nothing for a receiver that was not yet subscribed.
    #[tokio::test]
    async fn a_late_waiter_sees_a_completed_serve_map() {
        let signal = super::ServeMapSignal::pending();
        signal.complete();
        tokio::time::timeout(std::time::Duration::from_secs(5), signal.wait())
            .await
            .expect("a waiter after completion returns at once");
    }

    /// A published map is what the next read sees, with the writer gone
    /// or not; a build with no map reads `None`.
    #[test]
    fn a_view_reads_the_latest_published_map() {
        assert!(super::ServeMapView::absent().current().is_none());
        let (writer, view) = super::serve_map_cell(Some(map(&[], &[])));
        assert!(view.current().is_some_and(|map| map.target.is_empty()));
        writer.publish(map(&[("serde", "1.0.219")], &[]));
        drop(writer);
        assert!(
            view.current()
                .is_some_and(|map| map.covers(true, "serde", "1.0.219"))
        );
    }
}
