-- One copy batch of the version-15 identity rebuild (stow#588).
--
-- Historical rows move from the LIVE `queue` into the new-shape
-- `queue_v15` shadow in `task_id` order, `OR IGNORE` keyed on the
-- task-id primary key: a row the mirror triggers already refreshed
-- (a live submit, update or completion that landed after the copy
-- cursor passed it) is newer than this stale read and wins.
-- `dependency_identity` is written NULL — historical rows carry
-- unknown context, never a guessed one.
INSERT OR IGNORE INTO queue_v15 (
    task_id, crate_name, version, features_json, target, rustc_version,
    downloads, miss_count, request_count, priority, status, error_msg,
    preserve_lockfile, lane, dispatch_attempts, attempt, generation_id,
    not_before, first_requested_at, created_at, updated_at, github_run_id,
    host_side, shape_requeue, unpublished_deps, deps_met, blocked,
    wake_at, dispatch_family, value, demand, dispatch_key, claimed_at,
    dispatch_eligible, dependency_identity
)
SELECT
    task_id, crate_name, version, features_json, target, rustc_version,
    downloads, miss_count, request_count, priority, status, error_msg,
    preserve_lockfile, lane, dispatch_attempts, attempt, generation_id,
    not_before, first_requested_at, created_at, updated_at, github_run_id,
    host_side, shape_requeue, unpublished_deps, deps_met, blocked,
    wake_at, dispatch_family, value, demand, dispatch_key, claimed_at,
    dispatch_eligible, NULL
FROM queue
WHERE task_id > ?
ORDER BY task_id
LIMIT ?;
