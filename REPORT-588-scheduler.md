# stow#588 — scheduler storage, migration and dispatch for dependency-aware identity

Branch `fix/588-scheduler-identity`, base `68de914` (`origin/fix/588-dependency-identity`).
Head: `848f90b`. Single executor; no pushes; history linear.

A task id is `prefix(crate, version, features, target, rustc) + "-d<dependency digest>" [+ "-host"]`,
the digest a Merkle hash over the node's dependency subgraph. This task owns the scheduler half:
`edge/`, the CLI admission path, and `admin/src/preheat.rs`. The builder half
(`types/`, `ci/`, `resolver/`, `admin/src/manual.rs`) was landed upstream and is edited only where
listed below.

## Commits

| sha | scope |
|---|---|
| `52ed112` | behaviors 1–4: node store, dispatch walk, contextual gates, schema 15 + migration |
| `fd2e42f` | behavior 5: admissions + CLI unit-graph projection |
| `ead1d7a` | behavior 6: miss drain re-mints from stored subgraph |
| `2f32935` | behavior 7: missed lane promotes by task id via `/tasks/submit-ids` |
| `4dbc7ac` | behavior 8: idle vitest fixtures + `missed_lane_end_to_end` |
| `d61726c` | review-adjacent: migrate-resume fixes + mandated migration/dispatch-walk tests |
| `9abaa18` | lead review 1a: v15 rebuild as shadow copy + mirror triggers + atomic swap |
| `1f0a6ff` | lead review 1b: `phase_unit_graphs` fails fast on no runner family |
| `8a07a13` | cost gate 1: delta DELETE bounded by the delta; slice identity NOT NULL |
| `848f90b` | cost gate 2: dep edges written only for rows the request inserts |

## 1. Node store

- `task_nodes` (content-addressed): `task_id` PK, the six identity fields,
  `dependency_identity`, `children_json` (direct children's task ids as a JSON array).
  Chosen over an edge table: a node's child list is written once and read as one value —
  the dispatch walk's per-level query is `task_id IN json_each(?)` either way, so the encoded
  column removes a table and a write without changing the read shape.
- `queue`, `queue_dependencies`, `published_slice_rows` carry `dependency_identity`;
  `queue_dependencies` also carries the dep's full identity (crate, version, features,
  target, rustc, side) so the gate never re-resolves a task id. NULL = unknown historical
  context, satisfies no dependency gate or coverage clause.
- Queue uniqueness is the task id; the old six-field UNIQUE is gone (it merged contexts).
- Every submit path (`/tasks/submit`, trusted enqueue, request outcomes, admissions drain)
  upserts each request's subgraph nodes with `INSERT OR IGNORE` — `store_task_nodes` batches
  them through one `json_each` INSERT per request. Dedup is by task id; storage grows with
  distinct nodes only.

Files: `edge/src/scheduler/schema.sql`, `edge/src/scheduler/queue.rs` (`store_task_nodes`,
`node_store_rows`, `insert_dep_edges`, `EnqueuePlan`), `edge/src/api.rs` admission tickets,
`edge/src/scheduler/fixture.rs` + `drives.rs` fixtures.

## 2. Dispatch

- `claim_dispatchable_row` yields covered deps by walking `queue_dependencies`; the claimed
  task's `BuildTaskPayload.dependency_subgraph` is rebuilt by `load_claimed_dep_pins` walking
  `task_nodes` BFS — one `task_id IN json_each(?)` per level, never per node. A missing node is
  a hard dispatch error naming the id; no leaf substitutes anywhere.
- Per-dispatch bound (stated beside the drive in `drives.rs`): `O(|V|)` nodes of the dispatched
  task's subgraph — one statement per BFS level, bounded rows total.
- The leaf/synthesized placeholders are all gone: `dependency_resolver.rs::build_enqueue_requests`
  derives every covered-pruned node's real subgraph from the route-held graph, `db.rs`
  `take_dependency_graph_misses`/`record_admitted_miss`, enqueue/dep_edges, miss_logger,
  drives/feed/enqueue fixtures and the test fixture all carry real digests.

## 3. Gates

- The dependency gate releases a dependent only when each dep's **exact contextual identity**
  is published in the latest slice for the dep's own target: `matched_edges_sql` probes
  `published_slice_rows` on the identity tuple **and** `dependency_identity` plus the existing
  unit-shape clauses (`dep_invocations`/`dep_shapes` carried on the edge keep it a row-count
  compare). Slice rows carry the identity from `PublishedSliceRow`; a row without it gates
  nothing (and can no longer be stored — see v15 / cost-gate 1).
- `dep_edge_requirements(owner_target, owner_host_side, dep_target, dep_host_side)` derives
  the dep's required shapes — a pure function of the edge endpoints.

## 4. Migration — SCHEMA_VERSION 15, operator-only, shadow copy

- `SCHEMA_VERSION = 15`. All schema change runs only through `POST /migrate`; request/alarm
  paths run no DDL, no schema probe, no backfill. The report's `after` equals 15 only when the
  copy completed — `migrate_dependency_identity_rebuilds` returns `false` to hold the stamp
  while the queue copy is unfinished.
- **Shadow copy (lead review):** `queue` stays live and readable by name for the whole copy.
  `queue_v15` is created alongside; AFTER INSERT/UPDATE/DELETE triggers on the live table
  mirror every write into the shadow (`INSERT OR REPLACE`/`DELETE` by `task_id`, identity
  NULL-preserved); historical rows copy in bounded cursor batches
  (`IDENTITY_COPY_BATCH_ROWS = 1_000`, ≤ `IDENTITY_COPY_BATCHES_PER_CALL = 8` per migrate call)
  with `INSERT OR IGNORE` — a mirrored row is newer and wins. When the cursor is exhausted one
  atomic tick verifies shadow == live in both directions, drops the triggers and the live
  table, renames the shadow to `queue`, replays its indexes/triggers from `schema.sql`, and
  recomputes `queue_status_counts` from the swapped table. Old code reads and writes the real
  `queue` at every moment; final `sqlite_master` matches a fresh database (asserted by test).
  `DurableDb` has no transaction primitive — atomicity is the DO input-gate tick (a write
  sequence with no intervening yields commits atomically); test backends commit each
  statement, so every interleave-point is also a crash point and resume handles partial swaps.
  Transient cost of the mirror triggers is stated in the migration comment: **each live write
  during the copy writes one extra row into `queue_v15`** (the mirrored row), plus a 1-row
  verify read per batch call.
- **Slice half (post cost-gate 1):** `published_slice_rows.dependency_identity` is
  `TEXT NOT NULL`, so every context-free historical row drops at the swap by design — the
  shadow's only valid content is empty and the whole swap (create shadow → verify empty →
  drop live → rename → index/trigger replay → cursor clear) is one tick; no mirror triggers,
  no copy batches. The crash-after-DROP recovery still merges straggler new-code writes via
  `INSERT OR REPLACE` over named columns guarded `WHERE dependency_identity IS NOT NULL`.
- Crash/resume: post-DROP state (new-shape live table + `*_v15` shadow) is detected by
  column probes on both names; recovery merges live rows into the shadow, drops the
  recreated table, finishes the swap tail. `INSERT OR IGNORE` means an interruption after any
  batch resumes; a crash between verify and swap leaves the live table intact for the next
  call; already-migrated is a no-op (probe `table_columns` and return).
- Lead-authored SQL drafts are used via `include_str!`: `copy_queue_dependency_identity.sql`
  (fixed: batch cursor bound, identity NULL preserved not guessed),
  `verify_queue_dependency_identity.sql` (fixed: EXCEPT both directions over every live
  column), `mirror_queue_identity_triggers.sql`. The slice-side mirror/copy drafts are deleted
  as obsolete under NOT NULL.

### Migration tests (all in `queue_tests.rs`, sqlite backend)

- v14 database seeded with historical rows of every status → migrate → every listed column
  preserved (task ids, status, attempts, generation, lane, request root, edges, demand,
  completions), context NULL on historical rows; context-free slice rows drop at the swap.
- Interruption after a batch → next migrate call resumes and completes.
- Interleaved submits/status updates/completions/deletes between copy batches — including one
  touching a not-yet-copied task — all survive the swap with latest values.
- Crash between verify and swap → live table intact, next call completes.
- Already-migrated is a no-op; swapped schema equals fresh `schema.sql` (`sqlite_master`
  compared against a fresh database).

## 5. Admissions

- `POST /api/v1/admissions` mints `EnqueueAdmission`s whose requests carry the dependency
  subgraph; the edge re-derives ids (`TaskSubgraph::resolve`) and refuses a request whose
  declared id disagrees.
- CLI (`cli/src/cargo_cmd.rs::admit_observed_misses`,
  `cli/src/workspace_deps.rs::observed_miss_graph`/`emit_expanded_graph`) builds the subgraph
  from the build's real `cargo --unit-graph` via
  `stow_types::unit_graph::resolved_task_graph` over `ExpandedDependencyGraph::task_units`;
  exact Cargo package ids identify units (replaces name/version association).

## 6. Miss drain

- `take_dependency_graph_misses` re-mints from the stored subgraph, not a leaf-only shape;
  historical miss rows without one drain as an explicit skip counted in the response/log —
  never promoted to a guessed context. `record_admitted_miss` persists the subgraph.

## 7. Missed lane promotes by task id

- `admin/src/preheat.rs` (`preheat missed`): miss rows admitted through the CLI already have
  their nodes in the node store, so the lane promotes by exact task id — the Analytics Engine
  miss row carries the task id (`miss_logger` blob added), `top_missed` → ids, submitted
  through the trusted `POST /tasks/submit-ids` route, which resolves each subgraph from the
  node store. An id the store doesn't hold is reported unknown — never re-minted.
- New route has a drive and sits inside the cost gate like every other route.

## 8. Suites

- `edge/tests/idle/` fixtures post the subgraph wire; every assertion's meaning preserved —
  7/7 on the real workerd build.
- `admin/tests/entrypoint_side_effects.rs::missed_lane_end_to_end` updated to promote-by-id:
  a known id dispatches, an unknown id is reported and never re-minted.

## Lead review — changes applied

1. Shadow-copy migration: see §4. `migrate_queue_dependencies_columns` keeps the
   `dep_met`/`dep_host_side`/`dep_invocations`/`dep_side_known` backfills.
2. `ci/src/task.rs::phase_unit_graphs`: `map_or(task.target, ...)` → `ok_or_else` fail-fast
   naming the target — every dispatched task has a runner family (`1f0a6ff`).

## Cost gate — review findings fixed (not run by Devin; user runs locally)

The gate needs a credential the VM must not hold; the user runs it on this head. The two
100k failures are fixed at root:

### Finding 1 — `POST /index/published (delta)`: rows_read 241243 / budget 488

`241120` rows = a full `published_slice_rows` scan inside the delta DELETE. Fixed:
- Join order forced `FROM json_each(?) j CROSS JOIN published_slice_rows p` — one PK probe
  per retired row; cost proportional to the delta.
- `dependency_identity` compared with `=` — the column is `NOT NULL` since v15; a NULL would
  be the bug, not a value to match.
- The required index `(target, rustc_version, generation, crate_name, version, features_json,
  dependency_identity, unit_side, unit_invocation, unit_linked)` already exists — it is the
  table's PK; no new index added.

**Defect-class sweep (every statement touching `published_slice_rows`/`queue_dependencies`
checked for the IS/join-order pattern):**

- `record_published_slice` delta DELETE — **the only instance**; fixed.
- `matched_edges_sql` (dep gate / `dep_edge_unpublished_sql_at`) — already `CROSS JOIN` with
  `=` on `dep_dependency_identity`.
- Slice-delta dep_met maintenance (`SET dep_met = answers.new_met`) — keyed by `=` through
  `idx_queue_dependencies_dep_match`; seed/fixture `WHERE NOT EXISTS` uses `=`.
- All other json_each statements key on `task_id` equality only.

### Finding 2 — `POST /admin/enqueue (trusted)`: rows_read 729 / budget 300

The 499-row reader was `apply_batched_dependency_sync`'s correlated json_each DELETE
per existing edge. With #588 a task id carries its Merkle digest, so **a task id's edge set
is a function of the id**: resubmitting an existing task cannot change edges. Fixed:

- `EnqueuePlan.resync` → `edge_inserts`: edges are built only for tasks this chunk inserts;
  the per-request DELETE+resync and the correlated json_each compare are gone.
- `refresh_deps_met_tasks` recounts only the newly-inserted owners.
- Stale edge rows outliving a deleted queue row are absorbed by insert-time
  `ON CONFLICT DO NOTHING` plus the same owner recount.
- `apply_batched_dependency_sync` deleted.

**Every `queue_dependencies` column is determined by the consumer's task id:**
`dep_crate_name`/`dep_version`/`dep_features_json`/`dep_target`/`dep_rustc_version`/
`dep_host_side`/`dep_dependency_identity` are the dep node's identity fields committed to by
the subgraph's Merkle digest; `dep_invocations`/`dep_shapes` =
`dep_edge_requirements(owner_target, owner_host_side, dep_target, dep_host_side)` — a pure
function of the edge endpoints; `dep_side_known` is 1 on every new-code write. No column
needed keying on a non-id determinant. Rows left failing-closed from pre-v15
(`dep_side_known != 1`) are the migration's job — and the derive now also recounts the
derived edges' `dep_met` and their owners' stored counters
(`derive_dev_era_edge_sides`, `848f90b`).

## Edits outside `edge/` / CLI / preheat scope (listed per the brief)

- `ci/src/task.rs` — `phase_unit_graphs` fail-fast (lead review item 2; committed `1f0a6ff`).
- `ci/src/context_tests.rs`, `ci/src/dep_scan.rs` — test-side digests for the new wire
  (behavior 5; committed in `fd2e42f`).
- `types/src/api.rs` — none beyond the landed builder side.
- `.github/workflows/` — untouched.

## Verification (all run on head `848f90b`; the budget gate is user-run locally)

```
cargo check -q --workspace --all-targets                 # clean, no output
cargo +stable clippy -p stow-edge --all-targets -- -D warnings        # clean
cargo +stable clippy -p stow-edge --target wasm32-unknown-unknown -- -D warnings  # clean
cargo +stable clippy --workspace --all-targets -- -D warnings        # clean
cargo test -p stow-edge -p stow-cli -p stow-admin        # all green; edge lib 404/404
cd edge/tests/idle && bun install && bunx vitest run     # 7/7 passed (real workerd)
cargo fmt --all --check                                  # clean
git diff --check                                         # clean
STOW_BUDGET_SIZES="100000 1000000" scripts/scheduler-budget.sh
   # NOT RUN by Devin — needs a credential the VM must not hold; user runs it locally.
   # The two 100k findings reported at d61726c are fixed at root in 8a07a13 + 848f90b.
```
