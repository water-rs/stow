-- One range of the version-15 identity rebuild's verify (stow#588):
-- the `queue_v15` shadow must equal the live `queue` over every column
-- the live schema carries, in BOTH directions, inside the task-id
-- range `(?, ?]` — a NULL second bound asks for the open tail
-- `(?, +inf)`, which is all that is left once the copy cursor is
-- exhausted. A live write that beat the copy cursor is present exactly
-- once (mirrored), a live delete is absent, and no shadow row may hold
-- a fabricated context.
--
-- This runs inside the same storage tick as the batch it verifies:
-- copied and verified are one decision, never two. A range that has
-- passed stays equal — the mirror triggers write every later live
-- change into the shadow identically — so the swap's final tick makes
-- no table-wide comparison.
SELECT EXISTS (
    SELECT task_id, crate_name, version, features_json, target, rustc_version,
           downloads, miss_count, request_count, priority, status, error_msg,
           preserve_lockfile, lane, dispatch_attempts, attempt, generation_id,
           not_before, first_requested_at, created_at, updated_at, github_run_id,
           host_side, shape_requeue, unpublished_deps, deps_met, blocked,
           wake_at, dispatch_family, value, demand, dispatch_key, claimed_at,
           dispatch_eligible
    FROM queue
    WHERE task_id > ? AND (? IS NULL OR task_id <= ?)
    EXCEPT
    SELECT task_id, crate_name, version, features_json, target, rustc_version,
           downloads, miss_count, request_count, priority, status, error_msg,
           preserve_lockfile, lane, dispatch_attempts, attempt, generation_id,
           not_before, first_requested_at, created_at, updated_at, github_run_id,
           host_side, shape_requeue, unpublished_deps, deps_met, blocked,
           wake_at, dispatch_family, value, demand, dispatch_key, claimed_at,
           dispatch_eligible
    FROM queue_v15
    WHERE task_id > ? AND (? IS NULL OR task_id <= ?)
) OR EXISTS (
    SELECT task_id, crate_name, version, features_json, target, rustc_version,
           downloads, miss_count, request_count, priority, status, error_msg,
           preserve_lockfile, lane, dispatch_attempts, attempt, generation_id,
           not_before, first_requested_at, created_at, updated_at, github_run_id,
           host_side, shape_requeue, unpublished_deps, deps_met, blocked,
           wake_at, dispatch_family, value, demand, dispatch_key, claimed_at,
           dispatch_eligible
    FROM queue_v15
    WHERE task_id > ? AND (? IS NULL OR task_id <= ?)
    EXCEPT
    SELECT task_id, crate_name, version, features_json, target, rustc_version,
           downloads, miss_count, request_count, priority, status, error_msg,
           preserve_lockfile, lane, dispatch_attempts, attempt, generation_id,
           not_before, first_requested_at, created_at, updated_at, github_run_id,
           host_side, shape_requeue, unpublished_deps, deps_met, blocked,
           wake_at, dispatch_family, value, demand, dispatch_key, claimed_at,
           dispatch_eligible
    FROM queue
    WHERE task_id > ? AND (? IS NULL OR task_id <= ?)
) OR EXISTS (
    SELECT 1 FROM queue_v15
    WHERE task_id > ? AND (? IS NULL OR task_id <= ?)
          AND dependency_identity IS NOT NULL
) AS differs;
