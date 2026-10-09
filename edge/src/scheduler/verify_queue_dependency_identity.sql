-- The swap gate for the version-15 identity rebuild (stow#588): the
-- `queue_v15` shadow must equal the live `queue` over every column the
-- live schema carries, in BOTH directions — a live write that beat the
-- copy cursor is present exactly once (mirrored), a live delete is
-- absent, and no shadow row may hold a fabricated context. Runs inside
-- the same storage tick as the swap itself: verified and swapped are
-- one decision, never two.
SELECT EXISTS (
    SELECT task_id, crate_name, version, features_json, target, rustc_version,
           downloads, miss_count, request_count, priority, status, error_msg,
           preserve_lockfile, lane, dispatch_attempts, attempt, generation_id,
           not_before, first_requested_at, created_at, updated_at, github_run_id,
           host_side, shape_requeue, unpublished_deps, deps_met, blocked,
           wake_at, dispatch_family, value, demand, dispatch_key, claimed_at,
           dispatch_eligible
    FROM queue
    EXCEPT
    SELECT task_id, crate_name, version, features_json, target, rustc_version,
           downloads, miss_count, request_count, priority, status, error_msg,
           preserve_lockfile, lane, dispatch_attempts, attempt, generation_id,
           not_before, first_requested_at, created_at, updated_at, github_run_id,
           host_side, shape_requeue, unpublished_deps, deps_met, blocked,
           wake_at, dispatch_family, value, demand, dispatch_key, claimed_at,
           dispatch_eligible
    FROM queue_v15
) OR EXISTS (
    SELECT task_id, crate_name, version, features_json, target, rustc_version,
           downloads, miss_count, request_count, priority, status, error_msg,
           preserve_lockfile, lane, dispatch_attempts, attempt, generation_id,
           not_before, first_requested_at, created_at, updated_at, github_run_id,
           host_side, shape_requeue, unpublished_deps, deps_met, blocked,
           wake_at, dispatch_family, value, demand, dispatch_key, claimed_at,
           dispatch_eligible
    FROM queue_v15
    EXCEPT
    SELECT task_id, crate_name, version, features_json, target, rustc_version,
           downloads, miss_count, request_count, priority, status, error_msg,
           preserve_lockfile, lane, dispatch_attempts, attempt, generation_id,
           not_before, first_requested_at, created_at, updated_at, github_run_id,
           host_side, shape_requeue, unpublished_deps, deps_met, blocked,
           wake_at, dispatch_family, value, demand, dispatch_key, claimed_at,
           dispatch_eligible
    FROM queue
) OR EXISTS (
    SELECT 1 FROM queue_v15 WHERE dependency_identity IS NOT NULL
) AS differs;
