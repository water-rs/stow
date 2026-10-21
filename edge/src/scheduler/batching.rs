//! §1.2 batch formation — the pure half of the batched claim pass
//! (stow#833).
//!
//! The claim walk produces candidate rows in `dispatch_key` (rank)
//! order; [`form_batches`] packs them into `build-batch.yml`
//! dispatches keyed `(rustc_version, runner family, lane)`. All slot
//! accounting and leg ordering rules live here so the claim pass stays
//! a mechanical drive and the policy host-tests. Formation runs before
//! any row is claimed, so it mints nothing: the batches it returns are
//! [`PlannedBatch`]es, and [`PlannedBatch::seal`] binds a batch id and
//! the legs' generation ids once the caller has minted them.

use stow_types::api::{BatchEncoder, BatchFit, BatchId, BuildTaskPayload, RunnerFamily, TaskLane};
use stow_types::identity::WireRustcVersion;

use crate::errors::QueueError;
use crate::scheduler::queue::{PendingLeg, QueuedTask};

/// One claimed row staged for batch assignment. The input's order is
/// the claim's rank order — index 0 is the head row.
pub struct BatchCandidate {
    /// The pending queue row — carried to the batch's leg list so the
    /// caller can bind run id, leg index and lease without a second
    /// read. It holds no `generation_id`: nothing is claimed until the
    /// formation is done.
    pub task: PendingLeg,
    /// The leg payload the encoder packs — the same fields the
    /// per-task dispatch serializes today.
    pub payload: BuildTaskPayload,
    /// The row's lane — human and miss never share a batch.
    pub lane: TaskLane,
    /// The row's runner family — a batch's `k` slots charge to exactly
    /// one family so the macOS cap stays enforceable.
    pub family: RunnerFamily,
    /// `crate_build_stats.median_ms` — the rank's cost operand; legs
    /// sort longest-first and an unmeasured pair sorts last, as it
    /// does for the rank.
    pub median_ms: Option<i64>,
}

impl BatchCandidate {
    /// The `(rustc_version, family, lane)` uniformity key every leg
    /// of one batch shares (§1.1).
    pub fn key(&self) -> BatchKey {
        BatchKey {
            rustc_version: self.payload.rustc_version.clone(),
            family: self.family,
            lane: self.lane,
        }
    }
}

/// The `(rustc_version, runner family, lane)` key a batch is uniform
/// in (§1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchKey {
    /// The one rustc every leg builds under.
    pub rustc_version: WireRustcVersion,
    /// The runner family the batch's slots charge against.
    pub family: RunnerFamily,
    /// The batch's lane — human and miss never share one.
    pub lane: TaskLane,
}

/// What the count rule does with one row of a key — the decision
/// [`SlotPlan::take`] commits or [`SlotPlan::admit`] applies at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotAdmission {
    /// A seat in the key's open batch — for the human lane that
    /// consumes one more family slot, since every human leg must run
    /// at once.
    Seat,
    /// The key's open batch is at `B` legs — it closes and the row
    /// re-evaluates as a fresh batch's opener.
    Saturated,
    /// A new batch opens for the key. `reserved` slots are charged to
    /// the family now — `min(k, free)` for the miss lane, one for a
    /// human batch's first leg — and `bound` is the largest value the
    /// batch's final `parallelism` can take, so the sorted re-encode
    /// at close can never measure larger than what fit at open.
    Open { reserved: u32, bound: u32 },
    /// No open batch has room and the family holds no free slot.
    Denied,
}

/// One key's still-open batch as the count rule sees it: legs seated
/// and family slots held.
struct OpenSlots {
    legs: u32,
    reserved: u32,
}

/// §1.2's count rule — the single place "can this row still go out"
/// is decided, shared by the claim walk (which admits rows on counts
/// alone, through [`Self::admit`]) and by [`form_batches`] (which
/// gates the same decisions on encoded size through
/// [`Self::admission`]/[`Self::take`]/[`Self::close`]).
///
/// The plan knows two things: how many runner slots each family's
/// pools still hold — the global concurrency bound's remainder is
/// `shared_free`, drawn by every reservation, and a family's own-cap
/// remainder (macOS's, today the only family bound) stacks on top —
/// and how many legs each [`BatchKey`]'s open batch already seats.
/// It knows nothing about encoded size: a batch that closes byte-Full
/// reports back through [`Self::close`], which refunds whatever its
/// reservation over-held.
pub struct SlotPlan {
    /// Slots the global concurrency bound still holds — every
    /// reservation draws from this pool, whatever the family.
    shared_free: u32,
    /// Each family's own-cap remainder, for the families that have
    /// one — an absent entry means the shared pool alone bounds the
    /// family. A family's effective free is `min(shared_free,
    /// family_free)`.
    family_free: std::collections::HashMap<RunnerFamily, u32>,
    /// Each key's open batch in open order — a `Vec` because a pass
    /// holds at most one entry per formed batch (⌈slots/k⌉ plus the
    /// human lane's), so a scan costs less than a hash.
    open: Vec<(BatchKey, OpenSlots)>,
    /// `k` — the slots a miss-lane batch reserves when it opens.
    batch_parallelism: u32,
    /// `B` — the leg count at which a batch closes.
    batch_max_tasks: u32,
}

impl SlotPlan {
    /// A pass's slot budget: `shared_free` is the global concurrency
    /// bound's remainder; `family_free` carries each family's own-cap
    /// remainder (only macOS has one today).
    pub const fn new(
        shared_free: u32,
        family_free: std::collections::HashMap<RunnerFamily, u32>,
        batch_parallelism: u32,
        batch_max_tasks: u32,
    ) -> Self {
        Self {
            shared_free,
            family_free,
            open: Vec::new(),
            batch_parallelism,
            batch_max_tasks,
        }
    }

    /// The slots `family` can still draw — its own-cap remainder
    /// bounded by the shared pool.
    fn effective_free(&self, family: RunnerFamily) -> u32 {
        self.family_free
            .get(&family)
            .copied()
            .unwrap_or(u32::MAX)
            .min(self.shared_free)
    }

    /// Rows the plan can still admit — every open batch's empty seats
    /// plus `B` for each batch the shared pool can still open (one
    /// slot minimum per batch). An upper bound the claim walk sizes
    /// its page to.
    pub fn remaining(&self) -> u32 {
        let seats = self
            .open
            .iter()
            .map(|(_, open)| self.batch_max_tasks.saturating_sub(open.legs))
            .sum::<u32>();
        seats.saturating_add(self.shared_free.saturating_mul(self.batch_max_tasks))
    }

    /// Whether `family` can take nothing more this pass — no free
    /// slot to open a batch with, and no open miss batch with seats
    /// left (a human batch's seats are not free room: each needs a
    /// slot of its own). The claim walk excludes such a family's rows
    /// from its page query.
    pub fn family_saturated(&self, family: RunnerFamily) -> bool {
        self.effective_free(family) == 0
            && !self.open.iter().any(|(key, open)| {
                key.family == family
                    && key.lane == TaskLane::Miss
                    && open.legs < self.batch_max_tasks
            })
    }

    /// The count decision for the next row of `key`, uncommitted.
    /// `form_batches` peeks here — it must try the encoder before a
    /// `Seat` or `Open` commits — while the claim walk commits
    /// directly through [`Self::admit`].
    pub fn admission(&self, key: &BatchKey) -> SlotAdmission {
        if let Some((_, open)) = self.open.iter().find(|(k, _)| *k == *key) {
            if open.legs >= self.batch_max_tasks {
                return SlotAdmission::Saturated;
            }
            return match key.lane {
                // A miss leg rides the slots its batch already holds.
                TaskLane::Miss => SlotAdmission::Seat,
                // A human leg holds a slot of its own — the batch
                // grows only while the family can still run it.
                TaskLane::Human => {
                    if self.effective_free(key.family) == 0 {
                        SlotAdmission::Denied
                    } else {
                        SlotAdmission::Seat
                    }
                }
            };
        }
        let free = self.effective_free(key.family);
        if free == 0 {
            return SlotAdmission::Denied;
        }
        let (reserved, bound) = match key.lane {
            TaskLane::Miss => (
                self.batch_parallelism.min(free),
                self.batch_parallelism.min(free),
            ),
            TaskLane::Human => (1, self.batch_max_tasks.min(free)),
        };
        SlotAdmission::Open { reserved, bound }
    }

    /// Commit an [`Self::admission`]: a `Seat` counts the leg (a
    /// human leg charges one more family slot), an `Open` records the
    /// key's new batch with its first leg seated and `reserved` slots
    /// charged. `Denied` commits nothing.
    ///
    /// # Errors
    /// [`QueueError::Invariant`] when the decision could not have come
    /// from this plan — a seat for a key with no open batch, a charge
    /// the family cannot pay, or `Saturated`, which only ever closes.
    pub fn take(&mut self, key: &BatchKey, admission: SlotAdmission) -> Result<(), QueueError> {
        match admission {
            SlotAdmission::Denied => {}
            SlotAdmission::Saturated => {
                return Err(QueueError::Invariant(format!(
                    "a saturated batch for {key:?} must close, not take"
                )));
            }
            SlotAdmission::Seat => {
                let Some(position) = self.open.iter().position(|(k, _)| *k == *key) else {
                    return Err(QueueError::Invariant(format!(
                        "seat for {key:?} with no open batch"
                    )));
                };
                if key.lane == TaskLane::Human {
                    self.charge(key.family, 1)?;
                }
                let open = &mut self.open[position].1;
                open.legs += 1;
                if key.lane == TaskLane::Human {
                    open.reserved += 1;
                }
            }
            SlotAdmission::Open { reserved, .. } => {
                self.charge(key.family, reserved)?;
                self.open
                    .push((key.clone(), OpenSlots { legs: 1, reserved }));
            }
        }
        Ok(())
    }

    /// Admit one row of `key` under the count rule alone — the claim
    /// walk's decision, committed at once. `Denied` leaves the row
    /// pending; anything else claims it. `Saturated` never returns:
    /// the full batch closes and the row re-admits.
    ///
    /// # Errors
    /// [`QueueError::Invariant`] when the plan's own decision fails to
    /// commit — a bug in the accounting, not bad input.
    pub fn admit(&mut self, key: &BatchKey) -> Result<SlotAdmission, QueueError> {
        loop {
            match self.admission(key) {
                SlotAdmission::Saturated => {
                    // A full batch's reservation is already inside
                    // its leg count, so closing frees nothing.
                    self.close(key)?;
                }
                admission => {
                    self.take(key, admission)?;
                    return Ok(admission);
                }
            }
        }
    }

    /// Close the key's open batch — returns the slots it actually
    /// holds (`min(reserved, legs)`, the batch's `parallelism`) and
    /// refunds whatever the reservation over-held to the family's
    /// pools.
    ///
    /// # Errors
    /// [`QueueError::Invariant`] when the key has no open batch.
    pub fn close(&mut self, key: &BatchKey) -> Result<u32, QueueError> {
        let Some(position) = self.open.iter().position(|(k, _)| *k == *key) else {
            return Err(QueueError::Invariant(format!(
                "close for {key:?} with no open batch"
            )));
        };
        let (_, open) = self.open.swap_remove(position);
        let held = open.reserved.min(open.legs);
        self.refund(key.family, open.reserved - held);
        Ok(held)
    }

    /// Draw `slots` from `family`'s pools — the shared pool always,
    /// the family's own cap when it has one.
    fn charge(&mut self, family: RunnerFamily, slots: u32) -> Result<(), QueueError> {
        if self.effective_free(family) < slots {
            return Err(QueueError::Invariant(format!(
                "slot plan charges {slots} slots to {family:?} holding {}",
                self.effective_free(family)
            )));
        }
        self.shared_free -= slots;
        if let Some(free) = self.family_free.get_mut(&family) {
            *free -= slots;
        }
        Ok(())
    }

    /// Return `slots` to `family`'s pools — a closed batch's unheld
    /// reservation.
    fn refund(&mut self, family: RunnerFamily, slots: u32) {
        self.shared_free += slots;
        if let Some(free) = self.family_free.get_mut(&family) {
            *free += slots;
        }
    }
}

/// One batch as formation decided it, before any id exists: its
/// `(rustc, family, lane)` key, the slots it holds and its legs in
/// matrix order. [`Self::seal`] turns it into a [`FormedBatch`].
pub struct PlannedBatch {
    /// The one rustc every leg builds under.
    pub rustc_version: WireRustcVersion,
    /// The family the batch's `parallelism` slots charge against.
    pub family: RunnerFamily,
    /// The batch's lane.
    pub lane: TaskLane,
    /// The matrix's `max-parallel`: `min(k, legs, free family slots)`
    /// for the miss lane, `min(legs, free family slots)` — one slot
    /// per leg — for the human lane, so a human task never waits
    /// behind another leg of its batch.
    pub parallelism: u32,
    /// The legs as indexes into the candidate set, in matrix order —
    /// expected cost descending, so the longest legs start first and
    /// the run's makespan stays shortest. Position is the leg index.
    pub legs: Vec<usize>,
}

/// One formed batch — its `(rustc, family, lane)` key, legs in matrix
/// order, encoded `batch` dispatch input and runner-slot claim.
pub struct FormedBatch {
    /// The caller-minted id — names the run (`<rustc>-b<batch_id>`)
    /// and the completion route.
    pub batch_id: BatchId,
    /// The one rustc every leg builds under.
    pub rustc_version: WireRustcVersion,
    /// The family the batch's `parallelism` slots charge against.
    pub family: RunnerFamily,
    /// The batch's lane.
    pub lane: TaskLane,
    /// The matrix's `max-parallel`, as [`PlannedBatch::parallelism`].
    pub parallelism: u32,
    /// The legs in matrix order. Position is the leg index:
    /// `batch_leg = tasks[i]`.
    pub tasks: Vec<QueuedTask>,
    /// `BatchEncoder::finish()` — the `batch` `workflow_dispatch`
    /// input, already under `DISPATCH_INPUT_LIMIT`.
    pub encoded: String,
}

impl PlannedBatch {
    /// Bind the minted ids: the batch encodes in matrix order under
    /// `batch_id`, and each leg takes the next of `generation_ids` as
    /// the `generation_id` of its claim.
    ///
    /// # Errors
    /// [`QueueError::Invariant`] when `generation_ids` runs out, or
    /// when the legs do not encode under the size the formation
    /// measured — the placeholder id the fit-checks carry is as wide
    /// as a minted one, so the same legs encode no larger; a miss is a
    /// bug in the accounting, not bad input.
    pub fn seal(
        self,
        batch_id: BatchId,
        candidates: &[BatchCandidate],
        generation_ids: &mut impl Iterator<Item = String>,
    ) -> Result<FormedBatch, QueueError> {
        let mut encoder = BatchEncoder::new(
            batch_id.clone(),
            self.rustc_version.clone(),
            self.parallelism,
        )
        .map_err(|error| QueueError::Invariant(error.to_string()))?;
        let mut tasks = Vec::with_capacity(self.legs.len());
        for &index in &self.legs {
            match encoder.push(&candidates[index].payload) {
                Ok(BatchFit::Fits) => {}
                // The scratch framing bounded parallelism at or above
                // this value, so the same leg set encodes no larger.
                Ok(BatchFit::Full) => {
                    return Err(QueueError::Invariant(format!(
                        "batch {batch_id} leg {index} exceeds the cap its fit-check measured under"
                    )));
                }
                Err(error) => return Err(QueueError::Invariant(error.to_string())),
            }
            let generation_id = generation_ids.next().ok_or_else(|| {
                QueueError::Invariant(format!("batch {batch_id}: generation ids exhausted"))
            })?;
            tasks.push(candidates[index].task.clone().claimed(generation_id));
        }
        let wire = encoder
            .finish()
            .map_err(|error| QueueError::Invariant(error.to_string()))?;
        Ok(FormedBatch {
            batch_id,
            rustc_version: self.rustc_version,
            family: self.family,
            lane: self.lane,
            parallelism: self.parallelism,
            tasks,
            encoded: wire,
        })
    }
}

/// What [`form_batches`] made of one candidate set.
pub struct BatchFormation {
    /// The batches to dispatch, in close order.
    pub batches: Vec<PlannedBatch>,
    /// Indexes of rows no open batch could take and no slot could
    /// open — they stay `pending`, untouched.
    pub unbatched: Vec<usize>,
    /// `(index, error)` — rows the encoder refused: oversize even on
    /// an empty batch, or a malformed subgraph. The caller fails them
    /// with the carried message.
    pub rejected: Vec<(usize, String)>,
}

/// The id the fit-check encoders carry. A minted id is 32 hex like
/// this one, so measuring under it measures the sealed encoding
/// exactly.
fn measuring_id() -> BatchId {
    "00000000000000000000000000000000"
        .parse()
        .expect("32 hex digits are a batch id")
}

/// A batch still filling: its key, the fit-check encoder, and its
/// leg list. The slots it reserved live in the [`SlotPlan`] the
/// caller drives — every slot decision goes through it.
struct OpenBatch {
    /// The batch's `(rustc_version, family, lane)` uniformity key.
    key: BatchKey,
    /// The fit oracle — pushed in arrival order because `BatchFit`
    /// answers "would it take the encoded batch past the cap", and the
    /// encoded size is order-independent (same leg set, same shared
    /// table). Its framing carries `parallelism_bound`, an upper bound
    /// on the final `parallelism`, so the sorted re-encode at close
    /// can never measure larger than what already fit.
    encoder: BatchEncoder,
    /// `(candidate index, cost)` in arrival order — sorted
    /// longest-first at close.
    legs: Vec<(usize, i64)>,
    /// The bound `encoder`'s framing carries — the `Open`
    /// admission's `bound`. A `Full` probe re-checks a candidate
    /// against an empty batch of this key under the same bound
    /// before the batch is closed over it.
    parallelism_bound: u32,
}

/// The `open` list position of `key`'s batch — `SlotPlan` seating a
/// row for a key whose batch is missing means the two open sets
/// diverged, which is a bug, not bad input.
fn open_position(open: &[OpenBatch], key: &BatchKey) -> Result<usize, QueueError> {
    open.iter()
        .position(|batch| batch.key == *key)
        .ok_or_else(|| QueueError::Invariant(format!("slot plan seats {key:?} with no open batch")))
}

/// Mutable state for one [`form_batches`] pass: the open batches, the
/// results accumulating around them, and the [`SlotPlan`] every slot
/// decision goes through.
struct Formation<'a> {
    /// The pass's count rule.
    slots: &'a mut SlotPlan,
    /// Batches still filling, in open order.
    open: Vec<OpenBatch>,
    /// Closed batches, in close order.
    batches: Vec<PlannedBatch>,
    /// Rows no open batch could take and no slot could open.
    unbatched: Vec<usize>,
    /// Rows the encoder refused.
    rejected: Vec<(usize, String)>,
}

impl Formation<'_> {
    /// The `Open` admission's arm: stage `index` as the first leg of
    /// a new batch for `key`, framed under `bound` so the sorted
    /// re-encode at close can never measure larger than what fit at
    /// open, and commit `reserved` slots through the plan. The row
    /// lands in `rejected` when an empty batch cannot carry it.
    fn open_batch(
        &mut self,
        key: &BatchKey,
        reserved: u32,
        bound: u32,
        index: usize,
        candidate: &BatchCandidate,
    ) -> Result<(), QueueError> {
        let mut encoder = BatchEncoder::new(measuring_id(), key.rustc_version.clone(), bound)
            .map_err(|error| QueueError::Invariant(error.to_string()))?;
        match encoder.push(&candidate.payload) {
            Ok(BatchFit::Fits) => {
                self.slots
                    .take(key, SlotAdmission::Open { reserved, bound })?;
                self.open.push(OpenBatch {
                    key: key.clone(),
                    encoder,
                    legs: vec![(index, candidate.median_ms.unwrap_or(0))],
                    parallelism_bound: bound,
                });
            }
            // An empty batch's push can only err — `Full` is
            // unreachable by `push`'s contract.
            Ok(BatchFit::Full) => {
                return Err(QueueError::Invariant(format!(
                    "batch {key:?}: first leg reported Full"
                )));
            }
            Err(error) => self.rejected.push((index, error.to_string())),
        }
        Ok(())
    }

    /// The `Seat` admission's arm: try `index` against `key`'s open
    /// batch. Returns `true` when the row did not fit but an empty
    /// batch of the key could carry it — the batch closed over the
    /// row and the caller re-admits it — and `false` when the row
    /// seated or was rejected where it stood.
    fn seat(
        &mut self,
        key: &BatchKey,
        index: usize,
        candidate: &BatchCandidate,
    ) -> Result<bool, QueueError> {
        let position = open_position(&self.open, key)?;
        match self.open[position].encoder.push(&candidate.payload) {
            Ok(BatchFit::Fits) => {
                self.slots.take(key, SlotAdmission::Seat)?;
                self.open[position]
                    .legs
                    .push((index, candidate.median_ms.unwrap_or(0)));
                Ok(false)
            }
            Ok(BatchFit::Full) => {
                // `Full` only says the row does not fit *this* batch.
                // Probe it against an empty batch of the same key
                // under the batch's own bound: a row no empty batch
                // can carry is rejected where it stands — closing over
                // it would strand the key's later rows in a fresh
                // batch while this one still has room. Only a row
                // that fits alone closes.
                let batch = &self.open[position];
                let mut probe = BatchEncoder::new(
                    measuring_id(),
                    batch.key.rustc_version.clone(),
                    batch.parallelism_bound,
                )
                .map_err(|error| QueueError::Invariant(error.to_string()))?;
                match probe.push(&candidate.payload) {
                    Err(error) => {
                        self.rejected.push((index, error.to_string()));
                        Ok(false)
                    }
                    Ok(BatchFit::Fits) => {
                        self.batches
                            .push(close(self.open.swap_remove(position), self.slots)?);
                        Ok(true)
                    }
                    // An empty batch's push can only err — `Full` is
                    // unreachable by `push`'s contract.
                    Ok(BatchFit::Full) => Err(QueueError::Invariant(format!(
                        "batch {key:?}: empty-batch probe reported Full"
                    ))),
                }
            }
            Err(error) => {
                self.rejected.push((index, error.to_string()));
                Ok(false)
            }
        }
    }

    /// The `Saturated` admission's arm: close `key`'s open batch.
    fn close_batch(&mut self, key: &BatchKey) -> Result<(), QueueError> {
        let position = open_position(&self.open, key)?;
        self.batches
            .push(close(self.open.swap_remove(position), self.slots)?);
        Ok(())
    }

    /// Close every batch still open, in open order — rank order for
    /// the pass's dispatches.
    fn drain(&mut self) -> Result<(), QueueError> {
        for batch in std::mem::take(&mut self.open) {
            self.batches.push(close(batch, self.slots)?);
        }
        Ok(())
    }
}

/// Pack claimed rows into batches keyed `(rustc_version, family,
/// lane)` (§1.2), driving `slots` for every slot decision.
///
/// Rules:
///
/// - the head row always goes out — its key's batch opens first, and
///   rank order is otherwise kept: a batch never skips past a
///   better-ranked row of its own key (a row whose key the plan
///   denies lands in `unbatched`, and so does every worse-ranked row
///   of the same key);
/// - a batch closes at `batch_max_tasks` legs (the plan answers
///   [`SlotAdmission::Saturated`]) or when [`BatchEncoder::push`]
///   returns [`BatchFit::Full`] for a row an empty batch of the key
///   could carry, and the row then opens a fresh batch for its key;
///   a `Full` row no empty batch can carry is `rejected` and the open
///   batch keeps filling;
/// - legs are ordered by `median_ms` longest-first — GitHub starts
///   matrix legs in order as slots free.
///
/// Nothing is claimed or minted here: the batches come back as
/// [`PlannedBatch`]es that [`PlannedBatch::seal`] binds to ids.
///
/// # Errors
/// [`QueueError::Invariant`] on encoder construction failures or a
/// slot decision the plan cannot take — bugs in the accounting, not
/// bad input.
///
/// # Panics
/// Never on a stow target — leg counts are `u32` and `usize` is at
/// least 32 bits on every target the edge builds for.
pub fn form_batches(
    candidates: &[BatchCandidate],
    slots: &mut SlotPlan,
) -> Result<BatchFormation, QueueError> {
    let mut formation = Formation {
        slots,
        open: Vec::new(),
        batches: Vec::new(),
        unbatched: Vec::new(),
        rejected: Vec::new(),
    };
    'assign: for (index, candidate) in candidates.iter().enumerate() {
        let key = candidate.key();
        loop {
            match formation.slots.admission(&key) {
                SlotAdmission::Denied => {
                    formation.unbatched.push(index);
                    continue 'assign;
                }
                SlotAdmission::Saturated => formation.close_batch(&key)?,
                SlotAdmission::Open { reserved, bound } => {
                    formation.open_batch(&key, reserved, bound, index, candidate)?;
                    continue 'assign;
                }
                SlotAdmission::Seat => {
                    if !formation.seat(&key, index, candidate)? {
                        continue 'assign;
                    }
                }
            }
        }
    }
    formation.drain()?;
    let Formation {
        batches,
        unbatched,
        rejected,
        ..
    } = formation;
    Ok(BatchFormation {
        batches,
        unbatched,
        rejected,
    })
}

/// Close a filled batch: legs sorted longest-first and the family's
/// pools refunded whatever the reservation over-held. The batch
/// encodes at [`PlannedBatch::seal`], once it has an id.
fn close(batch: OpenBatch, slots: &mut SlotPlan) -> Result<PlannedBatch, QueueError> {
    let OpenBatch { key, mut legs, .. } = batch;
    // Longest first; the stable sort keeps rank order inside equal
    // costs.
    legs.sort_by_key(|&(_, cost)| std::cmp::Reverse(cost));
    // `min(reserved, legs)` — a miss batch that closed short of its
    // reservation frees the rest inside this same pass; a human
    // batch's reservation is its leg count by construction.
    let parallelism = slots.close(&key)?;
    Ok(PlannedBatch {
        rustc_version: key.rustc_version,
        family: key.family,
        lane: key.lane,
        parallelism,
        legs: legs.into_iter().map(|(index, _)| index).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        BatchCandidate, BatchId, BatchKey, BuildTaskPayload, FormedBatch, PendingLeg, PlannedBatch,
        RunnerFamily, SlotAdmission, SlotPlan, TaskLane, WireRustcVersion, form_batches,
    };
    use std::collections::HashMap;
    use stow_types::api::TaskSubgraph;
    use stow_types::identity::{CrateName, CrateVersion, FeaturesJson, TargetTriple};
    use stow_types::public_cache::ExplicitSpelling;

    /// A minimal dep-free payload; `size` pads `task_id` for
    /// capacity tests.
    fn candidate(
        name: &str,
        lane: TaskLane,
        family: RunnerFamily,
        median_ms: Option<i64>,
        size: usize,
        rustc: &str,
    ) -> BatchCandidate {
        let task_id = format!("{name}{}", "x".repeat(size));
        BatchCandidate {
            task: PendingLeg {
                task_id: task_id.clone(),
                attempt: 1,
                crate_name: name.to_owned(),
                version: "1.0.0".to_owned(),
                features_json: "[]".to_owned(),
                target: match family {
                    RunnerFamily::Linux => "x86_64-unknown-linux-gnu",
                    RunnerFamily::MacOs => "aarch64-apple-darwin",
                    RunnerFamily::Windows => "x86_64-pc-windows-msvc",
                }
                .to_owned(),
                rustc_version: rustc.to_owned(),
                host_side: false,
                explicit_spelling: ExplicitSpelling::KeysAsNative,
                preserve_lockfile: false,
                dependency_subgraph: TaskSubgraph::default(),
            },
            payload: BuildTaskPayload {
                task_id,
                attempt: 1,
                crate_name: CrateName::parse(name).expect("crate name"),
                version: CrateVersion::new(semver::Version::parse("1.0.0").expect("version")),
                features_json: FeaturesJson::canonicalize(Vec::new()).expect("features"),
                target: TargetTriple::parse(match family {
                    RunnerFamily::Linux => "x86_64-unknown-linux-gnu",
                    RunnerFamily::MacOs => "aarch64-apple-darwin",
                    RunnerFamily::Windows => "x86_64-pc-windows-msvc",
                })
                .expect("target"),
                rustc_version: WireRustcVersion::parse(rustc).expect("rustc"),
                preserve_lockfile: false,
                host_side: false,
                explicit_spelling: ExplicitSpelling::KeysAsNative,
                dependency_subgraph: TaskSubgraph::default(),
            },
            lane,
            family,
            median_ms,
        }
    }

    fn linux(name: &str, median_ms: Option<i64>) -> BatchCandidate {
        candidate(
            name,
            TaskLane::Miss,
            RunnerFamily::Linux,
            median_ms,
            0,
            "1.91.0",
        )
    }

    /// The task ids of `batch`'s legs, in matrix order.
    fn leg_ids<'a>(batch: &PlannedBatch, candidates: &'a [BatchCandidate]) -> Vec<&'a str> {
        batch
            .legs
            .iter()
            .map(|&index| candidates[index].task.task_id.as_str())
            .collect()
    }

    /// `batch` sealed under the id `0000…0001` with generation ids
    /// `gen-0`, `gen-1`, …
    fn sealed(batch: PlannedBatch, candidates: &[BatchCandidate]) -> FormedBatch {
        let id: BatchId = format!("{:032x}", 1).parse().expect("batch id");
        batch
            .seal(
                id,
                candidates,
                &mut (0..).map(|generation| format!("gen-{generation}")),
            )
            .expect("seals")
    }

    /// A plan with `shared` free slots in the global pool, `k`/`B`
    /// as given — no family cap.
    fn plan(shared: u32, k: u32, b: u32) -> SlotPlan {
        SlotPlan::new(shared, HashMap::new(), k, b)
    }

    /// A plan with a macOS cap remainder on top of the shared pool.
    fn plan_macos(shared: u32, macos: u32, k: u32, b: u32) -> SlotPlan {
        SlotPlan::new(shared, HashMap::from([(RunnerFamily::MacOs, macos)]), k, b)
    }

    /// §1.2: the head row always goes out — its key's batch opens
    /// first, and legs arrive in it.
    #[test]
    fn the_head_row_always_goes_out() {
        let candidates = vec![linux("head", Some(100))];
        let formation = form_batches(&candidates, &mut plan(5, 5, 40)).expect("forms");
        assert_eq!(formation.batches.len(), 1);
        assert_eq!(leg_ids(&formation.batches[0], &candidates), ["head"]);
        assert!(formation.unbatched.is_empty() && formation.rejected.is_empty());
    }

    /// §1.2: a batch closes at `B` legs — the next same-key row opens a
    /// fresh batch for the key, and both dispatch.
    #[test]
    fn a_batch_closes_at_b_legs() {
        let candidates = vec![
            linux("a", Some(1)),
            linux("b", Some(1)),
            linux("c", Some(1)),
        ];
        let formation = form_batches(&candidates, &mut plan(9, 5, 2)).expect("forms");
        assert_eq!(formation.batches.len(), 2);
        assert_eq!(formation.batches[0].legs.len(), 2);
        assert_eq!(formation.batches[1].legs.len(), 1);
        assert_eq!(formation.unbatched, Vec::<usize>::new());
    }

    /// §1.2: a batch closes when `BatchEncoder::push` returns `Full` —
    /// the row that would not fit opens the next batch.
    #[test]
    fn a_batch_closes_when_the_encoder_reports_full() {
        // `b` fits an empty batch (task_id ~64.5k) but not after `a`'s
        // ~2.5k of framing and leg; `c` then joins `b`'s batch.
        let candidates = vec![
            candidate(
                "a",
                TaskLane::Miss,
                RunnerFamily::Linux,
                Some(1),
                2_000,
                "1.91.0",
            ),
            candidate(
                "b",
                TaskLane::Miss,
                RunnerFamily::Linux,
                Some(1),
                stow_types::api::DISPATCH_INPUT_LIMIT - 1_000,
                "1.91.0",
            ),
            linux("c", Some(1)),
        ];
        let formation = form_batches(&candidates, &mut plan(9, 5, 40)).expect("forms");
        assert_eq!(formation.batches.len(), 2, "{:?}", formation.rejected);
        assert_eq!(formation.batches[0].legs.len(), 1);
        assert_eq!(
            leg_ids(&formation.batches[1], &candidates),
            [
                candidates[1].task.task_id.as_str(),
                candidates[2].task.task_id.as_str()
            ],
            "the row past the fill opens the next batch and later rows join it"
        );
    }

    /// §1.2: a new batch opens only while its family has a free slot —
    /// a saturated family's key stays unbatched, and a worse-ranked row
    /// of the same key never goes ahead of it.
    #[test]
    fn a_batch_opens_only_with_a_free_family_slot() {
        let candidates = vec![
            candidate(
                "l1",
                TaskLane::Miss,
                RunnerFamily::Linux,
                Some(1),
                0,
                "1.90.0",
            ),
            linux("l2", Some(1)),
            candidate(
                "m1",
                TaskLane::Miss,
                RunnerFamily::MacOs,
                Some(1),
                0,
                "1.91.0",
            ),
        ];
        let formation = form_batches(&candidates, &mut plan_macos(1, 3, 1, 40)).expect("forms");
        // l1's batch holds the shared pool's only slot; l2 — same
        // family, different rustc — cannot open, and neither l2's
        // better rank nor m1's separate family cap changes that: every
        // reservation draws the shared pool.
        assert_eq!(formation.batches.len(), 1);
        assert_eq!(formation.unbatched, vec![1, 2]);

        // A family's own cap binds inside the shared pool: with slots
        // to spare, a macOS row still opens nothing when its cap is
        // spent, while a Linux row dispatches.
        let formation = form_batches(&candidates, &mut plan_macos(9, 0, 5, 40)).expect("forms");
        assert_eq!(formation.batches.len(), 2);
        assert_eq!(formation.unbatched, vec![2]);
        assert!(
            formation
                .batches
                .iter()
                .all(|batch| batch.family == RunnerFamily::Linux),
            "the family-capped macOS row stays unbatched"
        );
    }

    /// §1.2: human and miss rows of one `(rustc, family)` never share
    /// a batch — the lane is part of the key.
    #[test]
    fn human_and_miss_never_share_a_batch() {
        let candidates = vec![
            linux("miss", Some(1)),
            candidate(
                "human",
                TaskLane::Human,
                RunnerFamily::Linux,
                Some(1),
                0,
                "1.91.0",
            ),
        ];
        let formation = form_batches(&candidates, &mut plan(9, 5, 40)).expect("forms");
        assert_eq!(formation.batches.len(), 2);
        assert_eq!(formation.batches[0].lane, TaskLane::Miss);
        assert_eq!(formation.batches[1].lane, TaskLane::Human);
    }

    /// §1.2: legs order longest-first by `median_ms`, rank order held
    /// inside equal costs.
    #[test]
    fn legs_order_longest_first() {
        let candidates = vec![
            linux("fast", Some(100)),
            linux("slow", Some(900)),
            linux("mid", Some(400)),
            linux("unmeasured", None),
        ];
        let formation = form_batches(&candidates, &mut plan(9, 5, 40)).expect("forms");
        assert_eq!(
            leg_ids(&formation.batches[0], &candidates),
            ["slow", "mid", "fast", "unmeasured"]
        );
    }

    /// §1.2: miss parallelism is `min(k, legs, free family slots)` —
    /// the k bound, the legs bound and the slot bound each rule when
    /// smallest.
    #[test]
    fn miss_parallelism_is_min_k_legs_free() {
        // k binds.
        let candidates = vec![linux("a", Some(1)), linux("b", Some(1))];
        let formation = form_batches(&candidates, &mut plan(9, 5, 40)).expect("forms");
        assert_eq!(formation.batches[0].parallelism, 2);

        // free slots bind at open.
        let candidates = vec![
            linux("a", Some(1)),
            linux("b", Some(1)),
            linux("c", Some(1)),
        ];
        let formation = form_batches(&candidates, &mut plan(3, 5, 40)).expect("forms");
        assert_eq!(formation.batches[0].parallelism, 3);

        // k binds below free: reserve 5 of 9, refund frees the rest.
        let candidates = (0..8)
            .map(|i| linux(&format!("t{i}"), Some(1)))
            .collect::<Vec<_>>();
        let formation = form_batches(&candidates, &mut plan(9, 5, 40)).expect("forms");
        assert_eq!(formation.batches[0].parallelism, 5);
        // The over-reservation refunded: a second batch for another
        // key could open inside the same pass.
        assert_eq!(formation.batches.len(), 1);
    }

    /// §1.2: human parallelism is `min(legs, free family slots)` —
    /// every leg runs at once, and a leg past the pool stays
    /// unbatched rather than queueing inside the run.
    #[test]
    fn human_parallelism_is_min_legs_free() {
        let candidates = vec![
            candidate(
                "h1",
                TaskLane::Human,
                RunnerFamily::Linux,
                Some(1),
                0,
                "1.91.0",
            ),
            candidate(
                "h2",
                TaskLane::Human,
                RunnerFamily::Linux,
                Some(1),
                0,
                "1.91.0",
            ),
            candidate(
                "h3",
                TaskLane::Human,
                RunnerFamily::Linux,
                Some(1),
                0,
                "1.91.0",
            ),
        ];
        let formation = form_batches(&candidates, &mut plan(2, 5, 40)).expect("forms");
        assert_eq!(formation.batches.len(), 1);
        assert_eq!(formation.batches[0].parallelism, 2);
        assert_eq!(formation.batches[0].legs.len(), 2);
        assert_eq!(formation.unbatched, vec![2]);
    }

    /// The key is `(rustc, family, lane)`: same family different
    /// rustc, and same rustc different family, each form their own
    /// batch.
    #[test]
    fn the_batch_key_is_rustc_family_lane() {
        let candidates = vec![
            linux("a", Some(1)),
            candidate(
                "b",
                TaskLane::Miss,
                RunnerFamily::Linux,
                Some(1),
                0,
                "1.90.0",
            ),
            candidate(
                "c",
                TaskLane::Miss,
                RunnerFamily::MacOs,
                Some(1),
                0,
                "1.91.0",
            ),
        ];
        let formation = form_batches(&candidates, &mut plan_macos(15, 9, 5, 40)).expect("forms");
        assert_eq!(formation.batches.len(), 3);
    }

    /// A task the encoder cannot carry even on an empty batch is
    /// rejected with its error — the rest of the formation proceeds.
    #[test]
    fn an_oversize_leg_is_rejected_not_fatal() {
        let candidates = vec![
            linux("ok", Some(1)),
            candidate(
                "huge",
                TaskLane::Miss,
                RunnerFamily::Linux,
                Some(1),
                stow_types::api::DISPATCH_INPUT_LIMIT,
                "1.91.0",
            ),
            linux("also-ok", Some(1)),
        ];
        let formation = form_batches(&candidates, &mut plan(9, 5, 40)).expect("forms");
        assert_eq!(formation.rejected.len(), 1);
        assert_eq!(formation.rejected[0].0, 1);
        assert!(formation.rejected[0].1.contains("huge"));
        assert_eq!(formation.batches[0].legs.len(), 2);
    }

    /// The encoded payload carries the legs in the same order
    /// `tasks` reports them — leg `i` in the wire is `tasks[i]`.
    #[test]
    fn the_wire_order_matches_the_leg_list() {
        let candidates = vec![linux("fast", Some(100)), linux("slow", Some(900))];
        let formation = form_batches(&candidates, &mut plan(9, 5, 40)).expect("forms");
        let batch = sealed(
            formation.batches.into_iter().next().expect("one batch"),
            &candidates,
        );
        assert_eq!(batch.batch_id.as_str(), format!("{:032x}", 1));
        assert_eq!(
            batch
                .tasks
                .iter()
                .map(|task| task.generation_id.as_str())
                .collect::<Vec<_>>(),
            ["gen-0", "gen-1"],
            "each leg takes the next generation id in matrix order"
        );
        let payload: stow_types::api::BuildBatchPayload =
            serde_json::from_str(&batch.encoded).expect("encoded batch decodes");
        assert_eq!(payload.tasks.len(), 2);
        for (leg, wire) in payload.tasks.iter().enumerate() {
            assert_eq!(wire.task_id, batch.tasks[leg].task_id);
            assert_eq!(wire.leg as usize, leg);
        }
        assert_eq!(payload.parallelism, batch.parallelism);
    }

    /// A uniformity key for driving a `SlotPlan` directly.
    fn key(lane: TaskLane, family: RunnerFamily, rustc: &str) -> BatchKey {
        BatchKey {
            rustc_version: WireRustcVersion::parse(rustc).expect("rustc"),
            family,
            lane,
        }
    }

    /// §1.2's count rule: a miss batch reserves `min(k, free)` slots
    /// at open, and closing it refunds whatever the reservation
    /// over-held back to the family's pools.
    #[test]
    fn a_miss_batch_reserves_min_k_free_and_close_refunds() {
        let miss = |rustc: &str| key(TaskLane::Miss, RunnerFamily::Linux, rustc);
        let mut slots = plan(4, 5, 40);
        // Four free slots bound the five-slot reservation.
        assert_eq!(
            slots.admit(&miss("1.91.0")).expect("admits"),
            SlotAdmission::Open {
                reserved: 4,
                bound: 4
            }
        );
        // The reservation spends the pool — nothing else opens.
        assert_eq!(
            slots.admit(&miss("1.90.0")).expect("admits"),
            SlotAdmission::Denied
        );
        // One leg held one slot; the other three come back, and the
        // next batch reserves all three.
        assert_eq!(slots.close(&miss("1.91.0")).expect("closes"), 1);
        assert_eq!(
            slots.admit(&miss("1.90.0")).expect("admits"),
            SlotAdmission::Open {
                reserved: 3,
                bound: 3
            }
        );
    }

    /// §1.2's count rule: a human batch opens on one slot and every
    /// further leg charges one more — the batch grows only while the
    /// family can still run every leg at once.
    #[test]
    fn a_human_batch_charges_one_slot_per_leg() {
        let human = key(TaskLane::Human, RunnerFamily::Linux, "1.91.0");
        let mut slots = plan(3, 5, 40);
        assert_eq!(
            slots.admit(&human).expect("admits"),
            SlotAdmission::Open {
                reserved: 1,
                bound: 3
            }
        );
        assert_eq!(slots.admit(&human).expect("admits"), SlotAdmission::Seat);
        assert_eq!(slots.admit(&human).expect("admits"), SlotAdmission::Seat);
        // Three legs held three slots — the pool is spent.
        assert_eq!(slots.admit(&human).expect("admits"), SlotAdmission::Denied);
        // The reservation is exactly the leg count: closing holds all
        // three and refunds nothing.
        assert_eq!(slots.close(&human).expect("closes"), 3);
        let miss = key(TaskLane::Miss, RunnerFamily::Linux, "1.91.0");
        assert_eq!(slots.admit(&miss).expect("admits"), SlotAdmission::Denied);
    }

    /// §1.2's count rule: a batch at `B` legs saturates — the next
    /// same-key row closes it and opens a fresh batch only while a
    /// slot is free.
    #[test]
    fn a_saturated_batch_reopens_only_with_a_free_slot() {
        let miss = key(TaskLane::Miss, RunnerFamily::Linux, "1.91.0");

        // Slots to spare: the saturated batch closes (refunding its
        // over-reservation) and the row opens a new one.
        let mut slots = plan(6, 5, 2);
        assert_eq!(
            slots.admit(&miss).expect("admits"),
            SlotAdmission::Open {
                reserved: 5,
                bound: 5
            }
        );
        assert_eq!(slots.admit(&miss).expect("admits"), SlotAdmission::Seat);
        // Legs hit B: `admit` closes the batch — 2 of 5 slots held, 3
        // refunded into the 1 free — and re-admits on a fresh batch.
        assert_eq!(
            slots.admit(&miss).expect("admits"),
            SlotAdmission::Open {
                reserved: 4,
                bound: 4
            }
        );

        // No slot to spare: the row is denied where it stands.
        let mut slots = plan(1, 5, 2);
        assert_eq!(
            slots.admit(&miss).expect("admits"),
            SlotAdmission::Open {
                reserved: 1,
                bound: 1
            }
        );
        assert_eq!(slots.admit(&miss).expect("admits"), SlotAdmission::Seat);
        assert_eq!(slots.admit(&miss).expect("admits"), SlotAdmission::Denied);
    }

    /// §1.2's count rule: a family's own cap bounds only that family;
    /// the shared pool bounds every reservation.
    #[test]
    fn the_family_cap_and_the_shared_pool_each_bind() {
        let macos = |rustc: &str| key(TaskLane::Miss, RunnerFamily::MacOs, rustc);
        let linux = key(TaskLane::Miss, RunnerFamily::Linux, "1.91.0");
        let mut slots = plan_macos(4, 1, 5, 40);
        // The macOS cap, not the shared pool, sizes the reservation.
        assert_eq!(
            slots.admit(&macos("1.91.0")).expect("admits"),
            SlotAdmission::Open {
                reserved: 1,
                bound: 1
            }
        );
        // The cap is spent: a second macOS key opens nothing.
        assert_eq!(
            slots.admit(&macos("1.90.0")).expect("admits"),
            SlotAdmission::Denied
        );
        // Linux draws the shared pool's remaining three.
        assert_eq!(
            slots.admit(&linux).expect("admits"),
            SlotAdmission::Open {
                reserved: 3,
                bound: 3
            }
        );
        // And now the shared pool itself is spent.
        let windows = key(TaskLane::Miss, RunnerFamily::Windows, "1.91.0");
        assert_eq!(
            slots.admit(&windows).expect("admits"),
            SlotAdmission::Denied
        );
    }

    /// `family_saturated`: no free slot to open with, and no open
    /// miss batch of the family with a seat left — a human batch's
    /// seats are not free room.
    #[test]
    fn family_saturated_means_no_slot_and_no_open_seat() {
        let miss = key(TaskLane::Miss, RunnerFamily::Linux, "1.91.0");
        let human = key(TaskLane::Human, RunnerFamily::Linux, "1.91.0");

        // An open miss batch with seats left still admits the family.
        let mut slots = plan(1, 5, 2);
        assert!(!slots.family_saturated(RunnerFamily::Linux));
        slots.admit(&miss).expect("admits");
        assert!(!slots.family_saturated(RunnerFamily::Linux));
        // At B legs there is neither slot nor seat.
        slots.admit(&miss).expect("admits");
        assert!(slots.family_saturated(RunnerFamily::Linux));
        // A family that never opened anything is saturated the moment
        // the shared pool is empty.
        assert!(slots.family_saturated(RunnerFamily::MacOs));

        // A human batch's open seats do not count — every human leg
        // needs a slot of its own.
        let mut slots = plan(1, 5, 40);
        slots.admit(&human).expect("admits");
        assert!(slots.family_saturated(RunnerFamily::Linux));
        assert!(slots.family_saturated(RunnerFamily::MacOs));
    }

    /// The mixed-lane, mixed-family row sequence
    /// `admit_decides_what_form_batches_decides` drives: enough to
    /// saturate a miss batch, spend the macOS cap, and leave rows
    /// unbatched.
    fn admit_sequence() -> Vec<BatchCandidate> {
        vec![
            linux("a", Some(3)),
            candidate(
                "m1",
                TaskLane::Miss,
                RunnerFamily::MacOs,
                Some(2),
                0,
                "1.91.0",
            ),
            linux("b", Some(1)),
            candidate(
                "h1",
                TaskLane::Human,
                RunnerFamily::Linux,
                Some(5),
                0,
                "1.91.0",
            ),
            linux("c", Some(1)),
            candidate(
                "m2",
                TaskLane::Miss,
                RunnerFamily::MacOs,
                Some(1),
                0,
                "1.91.0",
            ),
            candidate(
                "h2",
                TaskLane::Human,
                RunnerFamily::Linux,
                Some(7),
                0,
                "1.91.0",
            ),
            linux("d", Some(9)),
            candidate(
                "m3",
                TaskLane::Miss,
                RunnerFamily::MacOs,
                Some(4),
                0,
                "1.91.0",
            ),
            candidate(
                "h3",
                TaskLane::Human,
                RunnerFamily::Linux,
                Some(1),
                0,
                "1.91.0",
            ),
            candidate(
                "e",
                TaskLane::Miss,
                RunnerFamily::Linux,
                Some(1),
                0,
                "1.90.0",
            ),
            candidate(
                "m4",
                TaskLane::Miss,
                RunnerFamily::MacOs,
                Some(1),
                0,
                "1.91.0",
            ),
        ]
    }

    /// §1.2's count rule: `admit` over a row sequence makes the same
    /// decisions `form_batches` makes over the same rows — same
    /// batches, same memberships, same parallelisms, same unbatched —
    /// when no batch closes byte-Full.
    #[test]
    fn admit_decides_what_form_batches_decides() {
        let candidates = admit_sequence();

        // Drive `admit` over the same rows and record the batches it
        // implies: `Open` starts a batch, `Seat` joins the key's open
        // one, `Denied` lands in unbatched.
        let mut slots = SlotPlan::new(8, HashMap::from([(RunnerFamily::MacOs, 2)]), 3, 3);
        let mut expected: Vec<(Vec<String>, u32)> = Vec::new();
        let mut open: Vec<(BatchKey, usize)> = Vec::new();
        let mut expected_unbatched = Vec::new();
        for (index, candidate) in candidates.iter().enumerate() {
            match slots.admit(&candidate.key()).expect("admits") {
                SlotAdmission::Open { reserved, .. } => {
                    expected.push((vec![candidate.task.task_id.clone()], reserved));
                    match open.iter_mut().find(|(key, _)| *key == candidate.key()) {
                        Some((_, position)) => *position = expected.len() - 1,
                        None => open.push((candidate.key(), expected.len() - 1)),
                    }
                }
                SlotAdmission::Seat => {
                    let position = open
                        .iter()
                        .find(|(key, _)| *key == candidate.key())
                        .map(|&(_, position)| position)
                        .expect("a seated key has an open batch");
                    expected[position].0.push(candidate.task.task_id.clone());
                    // A human seat charges a slot of its own.
                    if candidate.lane == TaskLane::Human {
                        expected[position].1 += 1;
                    }
                }
                SlotAdmission::Denied => expected_unbatched.push(index),
                SlotAdmission::Saturated => unreachable!("admit closes and re-admits"),
            }
        }

        // `form_batches` over the same rows and budget.
        let mut slots = SlotPlan::new(8, HashMap::from([(RunnerFamily::MacOs, 2)]), 3, 3);
        let formation = form_batches(&candidates, &mut slots).expect("forms");
        assert_eq!(formation.rejected, Vec::new());
        assert_eq!(formation.unbatched, expected_unbatched);

        // Same batches: same memberships (order inside a batch is the
        // close-time sort, so compare as sets) and same parallelisms
        // — `min(reserved, legs)` for both drivers.
        let mut actual: Vec<(Vec<String>, u32)> = formation
            .batches
            .iter()
            .map(|batch| {
                (
                    leg_ids(batch, &candidates)
                        .into_iter()
                        .map(str::to_owned)
                        .collect(),
                    batch.parallelism,
                )
            })
            .collect();
        for (tasks, parallelism) in &mut expected {
            tasks.sort();
            *parallelism = (*parallelism).min(u32::try_from(tasks.len()).expect("legs fit u32"));
        }
        for (tasks, _) in &mut actual {
            tasks.sort();
        }
        expected.sort();
        actual.sort();
        assert_eq!(actual, expected);
    }
}
