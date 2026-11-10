//! The graph's fixed-size records (stow#878). A node is one 48-byte
//! record in an arena, identified by the 16-byte hash of its task id;
//! the fields only an unpublished node needs ride a 24-byte [`State`]
//! slab entry that is freed when the node publishes, and the rare ones
//! (a bound run, a backoff, an error, a retry count) ride [`Extra`]
//! side-table entries. The dependency digest a task id spells is not in
//! memory at all: it lives in the `node_digests` rows, by state slot.

use serde::{Deserialize, Serialize};
use stow_types::api::SubmissionSource;
use stow_types::node_profile::NodeProfile;

use super::IdKey;
use super::index::PriorityId;
use crate::errors::QueueError;

/// Queue status — the graph's lifecycle states. `Published` is a node
/// whose queue state is gone: it stays only while a retained node still
/// depends on it. `Free` marks a record the next compaction drops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum Status {
    Pending,
    Dispatched,
    Running,
    Completed,
    Failed,
    Published,
    Free,
}

impl Status {
    /// Statuses, for the per-status counters.
    pub(super) const COUNT: usize = 7;

    pub(super) const fn index(self) -> usize {
        self as usize
    }

    pub(super) fn from_byte(byte: u8) -> Result<Self, QueueError> {
        Ok(match byte {
            0 => Self::Pending,
            1 => Self::Dispatched,
            2 => Self::Running,
            3 => Self::Completed,
            4 => Self::Failed,
            5 => Self::Published,
            6 => Self::Free,
            other => {
                return Err(QueueError::Invariant(format!(
                    "snapshot node status byte {other}"
                )));
            }
        })
    }

    /// Whether the node holds a claim on a runner slot.
    pub(super) const fn in_flight(self) -> bool {
        matches!(self, Self::Dispatched | Self::Running)
    }

    /// Whether the node carries a [`State`] entry.
    pub(super) const fn has_state(self) -> bool {
        !matches!(self, Self::Published | Self::Free)
    }
}

/// The entry point a node arrived under — what the rank reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Lane {
    Miss,
    Human,
    Operations,
    Preheat,
}

impl Lane {
    pub(super) const fn from_source(source: SubmissionSource) -> Self {
        match source {
            SubmissionSource::Operations { .. } => Self::Operations,
            SubmissionSource::HumanRequest => Self::Human,
            SubmissionSource::Preheat => Self::Preheat,
            SubmissionSource::CacheMiss | SubmissionSource::InexactHit => Self::Miss,
        }
    }

    const fn bits(self) -> u8 {
        self as u8
    }

    const fn of_bits(bits: u8) -> Self {
        match bits {
            0 => Self::Miss,
            1 => Self::Human,
            2 => Self::Operations,
            _ => Self::Preheat,
        }
    }
}

const _: () = assert!(
    NodeProfile::ALL.len() <= 4,
    "the flags byte holds a profile ordinal in two bits"
);

/// Which side of the build a node compiles for, the two spelling flags,
/// the blocked bit, the lane and the profile, packed into one byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Flags(pub(super) u8);

impl Flags {
    const HOST: u8 = 1;
    const EXPLICIT: u8 = 1 << 1;
    const PRESERVE: u8 = 1 << 2;
    const BLOCKED: u8 = 1 << 3;
    const LANE_SHIFT: u8 = 4;
    const LANE_MASK: u8 = 0b11 << Self::LANE_SHIFT;
    const PROFILE_SHIFT: u8 = 6;
    const PROFILE_MASK: u8 = 0b11 << Self::PROFILE_SHIFT;

    pub(super) const fn new(
        host: bool,
        explicit: bool,
        preserve: bool,
        lane: Lane,
        profile: NodeProfile,
    ) -> Self {
        let mut flags = Self(lane.bits() << Self::LANE_SHIFT);
        flags.0 |= profile.ordinal() << Self::PROFILE_SHIFT;
        flags.set(Self::HOST, host);
        flags.set(Self::EXPLICIT, explicit);
        flags.set(Self::PRESERVE, preserve);
        flags
    }

    const fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    const fn set(&mut self, bit: u8, on: bool) {
        if on {
            self.0 |= bit;
        } else {
            self.0 &= !bit;
        }
    }

    pub(super) const fn host(self) -> bool {
        self.has(Self::HOST)
    }

    pub(super) const fn explicit(self) -> bool {
        self.has(Self::EXPLICIT)
    }

    pub(super) const fn preserve(self) -> bool {
        self.has(Self::PRESERVE)
    }

    /// The node's named profile.
    ///
    /// # Panics
    /// When the stored ordinal names no defined profile — the byte is
    /// written only from a [`NodeProfile`].
    pub(super) const fn profile(self) -> NodeProfile {
        match NodeProfile::from_ordinal((self.0 & Self::PROFILE_MASK) >> Self::PROFILE_SHIFT) {
            Some(profile) => profile,
            None => panic!("node flags carry a profile ordinal no profile is defined for"),
        }
    }

    pub(super) const fn blocked(self) -> bool {
        self.has(Self::BLOCKED)
    }

    pub(super) const fn set_blocked(&mut self, on: bool) {
        self.set(Self::BLOCKED, on);
    }

    pub(super) const fn lane(self) -> Lane {
        Lane::of_bits((self.0 & Self::LANE_MASK) >> Self::LANE_SHIFT)
    }

    pub(super) const fn set_lane(&mut self, lane: Lane) {
        self.0 = (self.0 & !Self::LANE_MASK) | (lane.bits() << Self::LANE_SHIFT);
    }
}

/// The marker for a node without a [`State`] entry.
pub(super) const NO_STATE: u32 = u32::MAX;

/// One graph node: its identity, interned, and the counters the gate
/// reads. 48 bytes.
#[derive(Debug, Clone, Copy)]
pub(super) struct Node {
    /// The first 16 bytes of the BLAKE3 hash of the task id — the
    /// node's identity, the published map's key, and (its first four
    /// bytes) the probe key of the id index. The id string itself is
    /// minted on demand from the interned fields and the digest row.
    pub(super) key: IdKey,
    pub(super) crate_name: u32,
    pub(super) version: u32,
    pub(super) features: u32,
    /// Index into the state slab, [`NO_STATE`] once published.
    pub(super) state: u32,
    /// First forward edge in the edge arrays.
    pub(super) edges_start: u32,
    /// Retained nodes holding an edge onto this one: the node is
    /// freed once it is published and this reaches zero.
    pub(super) refs: u32,
    pub(super) edges_len: u16,
    /// Edges not yet met.
    pub(super) unmet: u16,
    pub(super) target: u8,
    pub(super) rustc: u8,
    pub(super) status: Status,
    pub(super) flags: Flags,
}

/// The queue state of an unpublished node. 24 bytes.
#[derive(Debug, Clone, Copy)]
pub(super) struct State {
    pub(super) first_requested: i64,
    /// Changes with every daily resubmission, so it stays in memory.
    pub(super) downloads: u64,
    /// The last state transition (unix seconds) — the admin listing's
    /// `updated_at` and the purge age floor.
    pub(super) updated: u32,
    pub(super) priority: PriorityId,
}

const _: () = assert!(size_of::<Node>() == 48, "a node record is 48 bytes");
const _: () = assert!(size_of::<State>() == 24, "a queue state is 24 bytes");

impl State {
    /// A state last transitioned at `now_ms`.
    pub(super) fn new(
        first_requested: i64,
        now_ms: i64,
        priority: PriorityId,
        downloads: u64,
    ) -> Self {
        Self {
            first_requested,
            downloads,
            updated: seconds_of(now_ms),
            priority,
        }
    }

    /// The last transition as unix milliseconds, at second resolution.
    pub(super) fn updated_ms(&self) -> i64 {
        i64::from(self.updated) * 1000
    }

    /// Stamp a transition at `now_ms`.
    pub(super) fn touch(&mut self, now_ms: i64) {
        self.updated = seconds_of(now_ms);
    }
}

/// Unix seconds of a unix-ms instant.
///
/// # Panics
/// Past the year 2106, where the 32-bit stamp ends, or before 1970.
fn seconds_of(ms: i64) -> u32 {
    u32::try_from(ms.div_euclid(1000)).expect("a transition instant is unix seconds below 2^32")
}

/// A verified completion that beat its dispatch response — parked on
/// the task until `bind` lands (the `pending_run_completions` fence,
/// in memory).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunCompletion {
    pub run_id: u64,
    pub success: bool,
    pub cancelled: bool,
    pub source_failure: Option<stow_types::api::SourceFailureVerification>,
    pub error: Option<String>,
}

/// A node's attempt before any run counted against it.
pub(super) const FIRST_ATTEMPT: u8 = 1;

/// The fields few nodes carry: a claim's generation and bound run, its
/// claim and lease-renewal stamps, a retry backoff, the last error, a
/// parked completion, and the attempt counters only a dispatched node
/// moves off their defaults. A node has an entry only while one of
/// them is set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Extra {
    /// The build attempt cycle; [`FIRST_ATTEMPT`] unless a run failed.
    pub(super) attempt: u8,
    /// Dispatches claimed for the node; zero until its first claim.
    pub(super) dispatch_attempts: u16,
    pub(super) generation: u64,
    pub(super) run_id: u64,
    pub(super) claimed_at: i64,
    /// The last instant a `status` reconcile listed this claim's own
    /// run (stow#943) — in memory only: a wake re-derives it from the
    /// load-time reconcile, so it rides neither the log nor the
    /// snapshot.
    #[serde(skip)]
    pub(super) lease_at: i64,
    pub(super) not_before: i64,
    pub(super) error: Option<Box<str>>,
    /// Only a completion racing its dispatch binding owns this payload.
    /// Keep absent payloads out of every other side-table entry.
    pub(super) parked: Option<Box<RunCompletion>>,
}

impl Default for Extra {
    fn default() -> Self {
        Self {
            attempt: FIRST_ATTEMPT,
            dispatch_attempts: 0,
            generation: 0,
            run_id: 0,
            claimed_at: 0,
            lease_at: 0,
            not_before: 0,
            error: None,
            parked: None,
        }
    }
}

impl Extra {
    /// Whether no field is off its default — the entry can go.
    pub(super) const fn is_blank(&self) -> bool {
        self.attempt == FIRST_ATTEMPT
            && self.dispatch_attempts == 0
            && self.generation == 0
            && self.run_id == 0
            && self.claimed_at == 0
            && self.lease_at == 0
            && self.not_before == 0
            && self.error.is_none()
            && self.parked.is_none()
    }
}
