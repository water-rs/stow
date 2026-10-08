INSERT OR IGNORE INTO queue (
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
FROM queue_identity_legacy
WHERE task_id > ?
ORDER BY task_id
LIMIT ?;
