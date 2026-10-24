//! The graph's fixed-size records (stow#878). A node is one 68-byte
//! record in an arena; the fields only an unpublished node needs ride
//! a 48-byte [`State`] slab entry that is freed when the node
//! publishes, and the rare ones (a bound run, a backoff, an error)
//! ride [`Extra`] side-table entries.

use serde::{Deserialize, Serialize};
use stow_types::api::SubmissionSource;

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

/// Which side of the build a node compiles for, the two spelling flags,
/// the blocked bit and the lane, packed into one byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Flags(pub(super) u8);

impl Flags {
    const HOST: u8 = 1;
    const EXPLICIT: u8 = 1 << 1;
    const PRESERVE: u8 = 1 << 2;
    const BLOCKED: u8 = 1 << 3;
    const LANE_SHIFT: u8 = 4;
    const LANE_MASK: u8 = 0b11 << Self::LANE_SHIFT;

    pub(super) const fn new(host: bool, explicit: bool, preserve: bool, lane: Lane) -> Self {
        let mut flags = Self(lane.bits() << Self::LANE_SHIFT);
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
/// reads. 68 bytes.
#[derive(Debug, Clone, Copy)]
pub(super) struct Node {
    /// The node's dependency digest, the 32 bytes its task id spells
    /// as 64 hex digits.
    pub(super) digest: [u8; 32],
    pub(super) crate_name: u32,
    pub(super) version: u32,
    pub(super) features: u32,
    /// The first four bytes of the BLAKE3 hash of the task id — the
    /// probe key of the id index. The id string itself is re-minted
    /// on demand.
    pub(super) id_tag: u32,
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

/// The queue state of an unpublished node. 48 bytes.
#[derive(Debug, Clone, Copy)]
pub(super) struct State {
    pub(super) first_requested: i64,
    /// The last state transition (unix ms) — the admin listing's
    /// `updated_at` and the purge age floor.
    pub(super) updated: i64,
    pub(super) priority: i64,
    pub(super) demand: i64,
    pub(super) downloads: u64,
    pub(super) attempt: u8,
    pub(super) dispatch_attempts: u16,
}

/// A verified completion that beat its dispatch response — parked on
/// the task until `bind` lands (the `pending_run_completions` fence,
/// in memory).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ParkedCompletion {
    pub(super) run_id: u64,
    pub(super) success: bool,
    pub(super) cancelled: bool,
    pub(super) error: Option<String>,
}

/// The fields few nodes carry: a claim's generation and bound run, its
/// lease stamp, a retry backoff, the last error, a parked completion.
/// A node has an entry only while one of them is set.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(super) struct Extra {
    pub(super) generation: u64,
    pub(super) run_id: u64,
    pub(super) claimed_at: i64,
    pub(super) not_before: i64,
    pub(super) error: Option<Box<str>>,
    pub(super) parked: Option<ParkedCompletion>,
}

impl Extra {
    /// Whether no field is set — the entry can go.
    pub(super) const fn is_blank(&self) -> bool {
        self.generation == 0
            && self.run_id == 0
            && self.claimed_at == 0
            && self.not_before == 0
            && self.error.is_none()
            && self.parked.is_none()
    }
}
