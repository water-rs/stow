//! §1.2 batch formation — the pure half of the batched claim pass
//! (stow#833).
//!
//! The claim walk produces candidate rows in `dispatch_key` (rank)
//! order; [`form_batches`] packs them into `build-batch.yml`
//! dispatches keyed `(rustc_version, runner family, lane)`. All slot
//! accounting, batch ids and leg ordering rules live here so the claim
//! pass stays a mechanical drive and the policy host-tests.

use std::collections::HashMap;

use stow_types::api::{
    BatchEncoder, BatchFit, BatchId, BuildTaskPayload, RunnerFamily, TaskLane,
};
use stow_types::identity::WireRustcVersion;

use crate::errors::QueueError;
use crate::scheduler::queue::QueuedTask;

/// One claimed row staged for batch assignment. The input's order is
/// the claim's rank order — index 0 is the head row.
pub struct BatchCandidate {
    /// The claimed queue row — carried to the batch's leg list so the
    /// caller can bind run id, leg index and lease without a second
    /// read.
    pub task: QueuedTask,
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
    /// The matrix's `max-parallel`: `min(k, legs, free family slots)`
    /// for the miss lane, `min(legs, free family slots)` — one slot
    /// per leg — for the human lane, so a human task never waits
    /// behind another leg of its batch.
    pub parallelism: u32,
    /// The legs in matrix order — expected cost descending, so the
    /// longest legs start first and the run's makespan stays shortest.
    /// Position is the leg index: `batch_leg = tasks[i]`.
    pub tasks: Vec<QueuedTask>,
    /// `BatchEncoder::finish()` — the `batch` `workflow_dispatch`
    /// input, already under `DISPATCH_INPUT_LIMIT`.
    pub encoded: String,
}

/// What [`form_batches`] made of one candidate set.
pub struct BatchFormation {
    /// The batches to dispatch, in close order.
    pub batches: Vec<FormedBatch>,
    /// Indexes of claimed rows no open batch could take and no slot
    /// could open — the caller returns them to `pending`.
    pub unbatched: Vec<usize>,
    /// `(index, error)` — rows the encoder refused: oversize even on
    /// an empty batch, or a malformed subgraph. The caller fails them
    /// with the carried message.
    pub rejected: Vec<(usize, String)>,
}

/// A batch still filling: its key fields, the fit-check encoder, and
/// the slots it reserved from its family's free pool.
struct OpenBatch {
    batch_id: BatchId,
    rustc_version: WireRustcVersion,
    family: RunnerFamily,
    lane: TaskLane,
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
    /// Slots held from the family's free pool: `min(k, free)` at open
    /// for the miss lane; one per leg for the human lane, so a human
    /// batch never queues a leg inside its run.
    reserved: u32,
    /// The bound `encoder`'s framing carries — `min(k, free)` for the
    /// miss lane, `min(B, free)` for the human lane. A `Full` probe
    /// re-checks a candidate against an empty batch of this key under
    /// the same bound before the batch is closed over it.
    parallelism_bound: u32,
}

/// Pack claimed rows into batches keyed `(rustc_version, family,
/// lane)` (§1.2).
///
/// Rules:
///
/// - the head row always goes out — its key's batch opens first, and
///   rank order is otherwise kept: a batch never skips past a
///   better-ranked row of its own key (a row whose key has no free
///   family slot lands in `unbatched`, and so does every worse-ranked
///   row of the same key);
/// - a batch closes at `batch_max_tasks` legs or when
///   [`BatchEncoder::push`] returns [`BatchFit::Full`] for a row an
///   empty batch of the key could carry, and the row then opens a
///   fresh batch for its key; a `Full` row no empty batch can carry is
///   `rejected` and the open batch keeps filling;
/// - a new batch opens only while its family has a free slot — a miss
///   batch reserves `min(k, free)` slots at open and frees whatever
///   its `legs < k` close leaves over; a human batch reserves one slot
///   per leg, so its legs never queue inside the run;
/// - legs are ordered by `median_ms` longest-first — GitHub starts
///   matrix legs in order as slots free.
///
/// `batch_ids` is the caller's id supply: at least `candidates.len()`
/// ids bound every formation. `free_slots` is each family's open
/// runner-slot count at the pass's capacity read.
///
/// # Errors
/// [`QueueError::Invariant`] on encoder construction failures or a
/// re-encode that could not reproduce a fit the scratch encoder
/// measured — both are bugs in the bound accounting, not bad input.
///
/// # Panics
/// Never on a stow target — `batch_max_tasks` is `u32` and `usize` is
/// at least 32 bits on every target the edge builds for.
pub fn form_batches(
    candidates: &[BatchCandidate],
    free_slots: &HashMap<RunnerFamily, u32>,
    batch_parallelism: u32,
    batch_max_tasks: u32,
    batch_ids: &mut impl Iterator<Item = BatchId>,
) -> Result<BatchFormation, QueueError> {
    let max_legs =
        usize::try_from(batch_max_tasks).expect("u32 fits usize on every stow target");
    let mut free: HashMap<RunnerFamily, u32> = free_slots.clone();
    let mut open: Vec<OpenBatch> = Vec::new();
    let mut batches = Vec::new();
    let mut unbatched = Vec::new();
    let mut rejected = Vec::new();

    'assign: for (index, candidate) in candidates.iter().enumerate() {
        let cost = candidate.median_ms.unwrap_or(0);
        loop {
            let position = open.iter().position(|batch| {
                batch.rustc_version == candidate.payload.rustc_version
                    && batch.family == candidate.family
                    && batch.lane == candidate.lane
            });
            let Some(position) = position else {
                match open_batch(
                    candidate,
                    index,
                    &mut free,
                    batch_parallelism,
                    batch_max_tasks,
                    batch_ids,
                )? {
                    OpenOutcome::Opened(batch) => open.push(*batch),
                    OpenOutcome::Unbatched => unbatched.push(index),
                    OpenOutcome::Rejected(error) => rejected.push((index, error)),
                }
                continue 'assign;
            };
            let batch = &mut open[position];
            if batch.legs.len() >= max_legs {
                batches.push(close(open.swap_remove(position), candidates, &mut free)?);
                continue;
            }
            match batch.encoder.push(&candidate.payload) {
                Ok(BatchFit::Fits) => {
                    // A human leg holds its own slot — the batch grows
                    // only while the family can still run it.
                    if candidate.lane == TaskLane::Human {
                        match free.get_mut(&candidate.family) {
                            Some(slots) if *slots > 0 => {
                                *slots -= 1;
                                batch.reserved += 1;
                            }
                            _ => {
                                unbatched.push(index);
                                continue 'assign;
                            }
                        }
                    }
                    batch.legs.push((index, cost));
                    continue 'assign;
                }
                Ok(BatchFit::Full) => {
                    // `Full` only says the row does not fit *this*
                    // batch. Probe it against an empty batch of the
                    // same key under the batch's own bound: a row no
                    // empty batch can carry is rejected where it
                    // stands — closing over it would strand the key's
                    // later rows in a fresh batch while this one still
                    // has room. Only a row that fits alone closes.
                    let batch_id = batch.batch_id.clone();
                    let mut probe = BatchEncoder::new(
                        batch_id.clone(),
                        batch.rustc_version.clone(),
                        batch.parallelism_bound,
                    )
                    .map_err(|error| QueueError::Invariant(error.to_string()))?;
                    match probe.push(&candidate.payload) {
                        Err(error) => {
                            rejected.push((index, error.to_string()));
                            continue 'assign;
                        }
                        Ok(BatchFit::Fits) => {
                            batches.push(close(
                                open.swap_remove(position),
                                candidates,
                                &mut free,
                            )?);
                        }
                        // An empty batch's push can only err — `Full`
                        // is unreachable by `push`'s contract.
                        Ok(BatchFit::Full) => {
                            return Err(QueueError::Invariant(format!(
                                "batch {batch_id}: empty-batch probe reported Full"
                            )));
                        }
                    }
                }
                Err(error) => {
                    rejected.push((index, error.to_string()));
                    continue 'assign;
                }
            }
        }
    }
    for batch in open {
        batches.push(close(batch, candidates, &mut free)?);
    }
    Ok(BatchFormation {
        batches,
        unbatched,
        rejected,
    })
}

/// What [`open_batch`] made of a row whose key had no open batch.
enum OpenOutcome {
    /// A batch opened and holds the row as its first leg.
    Opened(Box<OpenBatch>),
    /// The family's pool is exhausted — the row goes `unbatched`.
    Unbatched,
    /// The encoder refused the leg even on an empty batch — the row
    /// goes `rejected` with the error.
    Rejected(String),
}

/// Open `candidate`'s batch while its family has a free slot. The
/// miss lane reserves `min(k, free)` slots and the human lane one per
/// leg, with the scratch framing bounded by the batch's maximum
/// reachable parallelism so the close's sorted re-encode can never
/// measure larger.
fn open_batch(
    candidate: &BatchCandidate,
    index: usize,
    free: &mut HashMap<RunnerFamily, u32>,
    batch_parallelism: u32,
    batch_max_tasks: u32,
    batch_ids: &mut impl Iterator<Item = BatchId>,
) -> Result<OpenOutcome, QueueError> {
    let slots = free.get(&candidate.family).copied().unwrap_or(0);
    if slots == 0 {
        return Ok(OpenOutcome::Unbatched);
    }
    let (reserve, bound) = match candidate.lane {
        TaskLane::Miss => {
            let bound = batch_parallelism.min(slots);
            (bound, bound)
        }
        TaskLane::Human => (1, batch_max_tasks.min(slots)),
    };
    let Some(batch_id) = batch_ids.next() else {
        return Err(QueueError::Invariant(
            "batch id supply exhausted mid-formation".to_owned(),
        ));
    };
    let mut encoder =
        BatchEncoder::new(batch_id.clone(), candidate.payload.rustc_version.clone(), bound)
            .map_err(|error| QueueError::Invariant(error.to_string()))?;
    match encoder.push(&candidate.payload) {
        Ok(BatchFit::Fits) => {}
        // An empty batch's push can only err — `Full` is unreachable
        // here by `push`'s contract.
        Ok(BatchFit::Full) => {
            return Err(QueueError::Invariant(format!(
                "batch {batch_id}: first leg reported Full"
            )));
        }
        Err(error) => return Ok(OpenOutcome::Rejected(error.to_string())),
    }
    *free.entry(candidate.family).or_insert(0) = slots - reserve;
    Ok(OpenOutcome::Opened(Box::new(OpenBatch {
        batch_id,
        rustc_version: candidate.payload.rustc_version.clone(),
        family: candidate.family,
        lane: candidate.lane,
        encoder,
        legs: vec![(index, candidate.median_ms.unwrap_or(0))],
        reserved: reserve,
        parallelism_bound: bound,
    })))
}

/// Close a filled batch: legs sorted longest-first, the encoder
/// rebuilt in matrix order under the final parallelism, and the
/// family's pool refunded whatever the reservation over-held.
fn close(
    batch: OpenBatch,
    candidates: &[BatchCandidate],
    free: &mut HashMap<RunnerFamily, u32>,
) -> Result<FormedBatch, QueueError> {
    let OpenBatch {
        batch_id,
        rustc_version,
        family,
        lane,
        legs,
        reserved,
        ..
    } = batch;
    let mut legs = legs;
    // Longest first; the stable sort keeps rank order inside equal
    // costs.
    legs.sort_by_key(|&(_, cost)| std::cmp::Reverse(cost));
    let parallelism = match lane {
        TaskLane::Miss => reserved.min(
            u32::try_from(legs.len())
                .map_err(|_| QueueError::Invariant("batch leg count overflows u32".to_owned()))?,
        ),
        TaskLane::Human => reserved,
    };
    // A miss batch that closed short of `reserved` slots frees the
    // rest inside this same pass.
    *free.entry(family).or_insert(0) += reserved - parallelism;
    let mut encoder = BatchEncoder::new(batch_id.clone(), rustc_version.clone(), parallelism)
        .map_err(|error| QueueError::Invariant(error.to_string()))?;
    for &(index, _) in &legs {
        match encoder.push(&candidates[index].payload) {
            Ok(BatchFit::Fits) => {}
            // The scratch framing bounded parallelism at or above this
            // value, so the same leg set encodes no larger — a miss is
            // a bug in the bound, not bad input.
            Ok(BatchFit::Full) => {
                return Err(QueueError::Invariant(format!(
                    "batch {batch_id} leg {index} exceeds the cap its fit-check measured under"
                )));
            }
            Err(error) => {
                return Err(QueueError::Invariant(error.to_string()));
            }
        }
    }
    let wire = encoder
        .finish()
        .map_err(|error| QueueError::Invariant(error.to_string()))?;
    Ok(FormedBatch {
        batch_id,
        rustc_version,
        family,
        lane,
        parallelism,
        tasks: legs
            .iter()
            .map(|&(index, _)| candidates[index].task.clone())
            .collect(),
        encoded: wire,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        BatchCandidate, BatchId, BuildTaskPayload, QueuedTask, RunnerFamily, TaskLane,
        WireRustcVersion, form_batches,
    };
    use stow_types::api::TaskSubgraph;
    use stow_types::identity::{CrateName, CrateVersion, FeaturesJson, TargetTriple};
    use stow_types::public_cache::ExplicitSpelling;
    use std::collections::HashMap;

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
            task: QueuedTask {
                task_id: task_id.clone(),
                generation_id: format!("gen-{name}"),
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
        candidate(name, TaskLane::Miss, RunnerFamily::Linux, median_ms, 0, "1.91.0")
    }

    /// A deterministic id supply: `0000…0001`, `0000…0002`, …
    fn ids() -> impl Iterator<Item = BatchId> {
        (1_u64..).map(|n| format!("{n:032x}").parse().expect("batch id"))
    }

    fn free(slots: &[(RunnerFamily, u32)]) -> HashMap<RunnerFamily, u32> {
        slots.iter().copied().collect()
    }

    /// §1.2: the head row always goes out — its key's batch opens
    /// first, and legs arrive in it.
    #[test]
    fn the_head_row_always_goes_out() {
        let candidates = vec![linux("head", Some(100))];
        let formation = form_batches(
            &candidates,
            &free(&[(RunnerFamily::Linux, 5)]),
            5,
            40,
            &mut ids(),
        )
        .expect("forms");
        assert_eq!(formation.batches.len(), 1);
        assert_eq!(formation.batches[0].tasks[0].task_id, "head");
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
        let formation = form_batches(
            &candidates,
            &free(&[(RunnerFamily::Linux, 9)]),
            5,
            2,
            &mut ids(),
        )
        .expect("forms");
        assert_eq!(formation.batches.len(), 2);
        assert_eq!(formation.batches[0].tasks.len(), 2);
        assert_eq!(formation.batches[1].tasks.len(), 1);
        assert_eq!(formation.unbatched, Vec::<usize>::new());
    }

    /// §1.2: a batch closes when `BatchEncoder::push` returns `Full` —
    /// the row that would not fit opens the next batch.
    #[test]
    fn a_batch_closes_when_the_encoder_reports_full() {
        // `b` fits an empty batch (task_id ~64.5k) but not after `a`'s
        // ~2.5k of framing and leg; `c` then joins `b`'s batch.
        let candidates = vec![
            candidate("a", TaskLane::Miss, RunnerFamily::Linux, Some(1), 2_000, "1.91.0"),
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
        let formation = form_batches(
            &candidates,
            &free(&[(RunnerFamily::Linux, 9)]),
            5,
            40,
            &mut ids(),
        )
        .expect("forms");
        assert_eq!(formation.batches.len(), 2, "{:?}", formation.rejected);
        assert_eq!(formation.batches[0].tasks.len(), 1);
        assert_eq!(
            formation.batches[1]
                .tasks
                .iter()
                .map(|task| task.task_id.as_str())
                .collect::<Vec<_>>(),
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
            candidate("l1", TaskLane::Miss, RunnerFamily::Linux, Some(1), 0, "1.90.0"),
            linux("l2", Some(1)),
            candidate("m1", TaskLane::Miss, RunnerFamily::MacOs, Some(1), 0, "1.91.0"),
        ];
        let formation = form_batches(
            &candidates,
            &free(&[(RunnerFamily::Linux, 1), (RunnerFamily::MacOs, 3)]),
            1,
            40,
            &mut ids(),
        )
        .expect("forms");
        // l1's batch holds the family's only slot; l2 — same family,
        // different rustc — cannot open, and neither l2's better rank
        // nor m1's presence changes that.
        assert_eq!(formation.batches.len(), 2);
        assert_eq!(formation.unbatched, vec![1]);
        assert_eq!(formation.batches[1].tasks[0].task_id, "m1");
    }

    /// §1.2: human and miss rows of one `(rustc, family)` never share
    /// a batch — the lane is part of the key.
    #[test]
    fn human_and_miss_never_share_a_batch() {
        let candidates = vec![
            linux("miss", Some(1)),
            candidate("human", TaskLane::Human, RunnerFamily::Linux, Some(1), 0, "1.91.0"),
        ];
        let formation = form_batches(
            &candidates,
            &free(&[(RunnerFamily::Linux, 9)]),
            5,
            40,
            &mut ids(),
        )
        .expect("forms");
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
        let formation = form_batches(
            &candidates,
            &free(&[(RunnerFamily::Linux, 9)]),
            5,
            40,
            &mut ids(),
        )
        .expect("forms");
        let order: Vec<&str> = formation.batches[0]
            .tasks
            .iter()
            .map(|task| task.task_id.as_str())
            .collect();
        assert_eq!(order, ["slow", "mid", "fast", "unmeasured"]);
    }

    /// §1.2: miss parallelism is `min(k, legs, free family slots)` —
    /// the k bound, the legs bound and the slot bound each rule when
    /// smallest.
    #[test]
    fn miss_parallelism_is_min_k_legs_free() {
        // k binds.
        let candidates = vec![linux("a", Some(1)), linux("b", Some(1))];
        let formation = form_batches(
            &candidates,
            &free(&[(RunnerFamily::Linux, 9)]),
            5,
            40,
            &mut ids(),
        )
        .expect("forms");
        assert_eq!(formation.batches[0].parallelism, 2);

        // free slots bind at open.
        let candidates = vec![
            linux("a", Some(1)),
            linux("b", Some(1)),
            linux("c", Some(1)),
        ];
        let formation = form_batches(
            &candidates,
            &free(&[(RunnerFamily::Linux, 3)]),
            5,
            40,
            &mut ids(),
        )
        .expect("forms");
        assert_eq!(formation.batches[0].parallelism, 3);

        // k binds below free: reserve 5 of 9, refund frees the rest.
        let candidates = (0..8)
            .map(|i| linux(&format!("t{i}"), Some(1)))
            .collect::<Vec<_>>();
        let formation = form_batches(
            &candidates,
            &free(&[(RunnerFamily::Linux, 9)]),
            5,
            40,
            &mut ids(),
        )
        .expect("forms");
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
            candidate("h1", TaskLane::Human, RunnerFamily::Linux, Some(1), 0, "1.91.0"),
            candidate("h2", TaskLane::Human, RunnerFamily::Linux, Some(1), 0, "1.91.0"),
            candidate("h3", TaskLane::Human, RunnerFamily::Linux, Some(1), 0, "1.91.0"),
        ];
        let formation = form_batches(
            &candidates,
            &free(&[(RunnerFamily::Linux, 2)]),
            5,
            40,
            &mut ids(),
        )
        .expect("forms");
        assert_eq!(formation.batches.len(), 1);
        assert_eq!(formation.batches[0].parallelism, 2);
        assert_eq!(formation.batches[0].tasks.len(), 2);
        assert_eq!(formation.unbatched, vec![2]);
    }

    /// The key is `(rustc, family, lane)`: same family different
    /// rustc, and same rustc different family, each form their own
    /// batch.
    #[test]
    fn the_batch_key_is_rustc_family_lane() {
        let candidates = vec![
            linux("a", Some(1)),
            candidate("b", TaskLane::Miss, RunnerFamily::Linux, Some(1), 0, "1.90.0"),
            candidate("c", TaskLane::Miss, RunnerFamily::MacOs, Some(1), 0, "1.91.0"),
        ];
        let formation = form_batches(
            &candidates,
            &free(&[(RunnerFamily::Linux, 9), (RunnerFamily::MacOs, 9)]),
            5,
            40,
            &mut ids(),
        )
        .expect("forms");
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
        let formation = form_batches(
            &candidates,
            &free(&[(RunnerFamily::Linux, 9)]),
            5,
            40,
            &mut ids(),
        )
        .expect("forms");
        assert_eq!(formation.rejected.len(), 1);
        assert_eq!(formation.rejected[0].0, 1);
        assert!(formation.rejected[0].1.contains("huge"));
        assert_eq!(formation.batches[0].tasks.len(), 2);
    }

    /// The encoded payload carries the legs in the same order
    /// `tasks` reports them — leg `i` in the wire is `tasks[i]`.
    #[test]
    fn the_wire_order_matches_the_leg_list() {
        let candidates = vec![
            linux("fast", Some(100)),
            linux("slow", Some(900)),
        ];
        let formation = form_batches(
            &candidates,
            &free(&[(RunnerFamily::Linux, 9)]),
            5,
            40,
            &mut ids(),
        )
        .expect("forms");
        let batch = &formation.batches[0];
        let payload: stow_types::api::BuildBatchPayload =
            serde_json::from_str(&batch.encoded).expect("encoded batch decodes");
        assert_eq!(payload.tasks.len(), 2);
        for (leg, wire) in payload.tasks.iter().enumerate() {
            assert_eq!(wire.task_id, batch.tasks[leg].task_id);
            assert_eq!(wire.leg as usize, leg);
        }
        assert_eq!(payload.parallelism, batch.parallelism);
    }
}
