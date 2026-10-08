SELECT EXISTS (
    SELECT
        task_id, crate_name, version, features_json, target, rustc_version,
        downloads, miss_count, request_count, priority, status, error_msg,
        preserve_lockfile, lane, dispatch_attempts, attempt, generation_id,
        not_before, first_requested_at, created_at, updated_at, github_run_id,
        host_side, shape_requeue, unpublished_deps, deps_met, blocked,
        wake_at, dispatch_family, value, demand, dispatch_key, claimed_at,
        dispatch_eligible
    FROM queue_identity_legacy
    EXCEPT
    SELECT
        task_id, crate_name, version, features_json, target, rustc_version,
        downloads, miss_count, request_count, priority, status, error_msg,
        preserve_lockfile, lane, dispatch_attempts, attempt, generation_id,
        not_before, first_requested_at, created_at, updated_at, github_run_id,
        host_side, shape_requeue, unpublished_deps, deps_met, blocked,
        wake_at, dispatch_family, value, demand, dispatch_key, claimed_at,
        dispatch_eligible
    FROM queue
) OR EXISTS (
    SELECT 1
    FROM queue_identity_legacy old
    JOIN queue current USING (task_id)
    WHERE current.dependency_identity IS NOT NULL
) AS differs;
