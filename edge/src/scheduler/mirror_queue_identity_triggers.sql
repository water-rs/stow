-- Version-15 identity rebuild (stow#588): the mirror that keeps the
-- `queue_v15` shadow current while the historical copy runs. Every
-- write against the live `queue` writes a second row into the shadow —
-- `INSERT OR REPLACE` keyed on `task_id` for inserts and updates,
-- `DELETE` for deletes — so a mirrored row is always the newest write
-- and the copy's `INSERT OR IGNORE` never overwrites it.
-- `dependency_identity` mirrors NULL: the live table's shape predates
-- the column, so no live row carries context to preserve.
-- These triggers die with the live table at the swap's `DROP TABLE`.
CREATE TRIGGER IF NOT EXISTS v15_queue_mirror_insert
AFTER INSERT ON queue
BEGIN
    INSERT OR REPLACE INTO queue_v15 (
        task_id, crate_name, version, features_json, target, rustc_version,
        downloads, miss_count, request_count, priority, status, error_msg,
        preserve_lockfile, lane, dispatch_attempts, attempt, generation_id,
        not_before, first_requested_at, created_at, updated_at, github_run_id,
        host_side, shape_requeue, unpublished_deps, deps_met, blocked,
        wake_at, dispatch_family, value, demand, dispatch_key, claimed_at,
        dispatch_eligible, dependency_identity
    ) VALUES (
        NEW.task_id, NEW.crate_name, NEW.version, NEW.features_json, NEW.target,
        NEW.rustc_version, NEW.downloads, NEW.miss_count, NEW.request_count,
        NEW.priority, NEW.status, NEW.error_msg, NEW.preserve_lockfile, NEW.lane,
        NEW.dispatch_attempts, NEW.attempt, NEW.generation_id, NEW.not_before,
        NEW.first_requested_at, NEW.created_at, NEW.updated_at, NEW.github_run_id,
        NEW.host_side, NEW.shape_requeue, NEW.unpublished_deps, NEW.deps_met,
        NEW.blocked, NEW.wake_at, NEW.dispatch_family, NEW.value, NEW.demand,
        NEW.dispatch_key, NEW.claimed_at, NEW.dispatch_eligible, NULL
    );
END;

CREATE TRIGGER IF NOT EXISTS v15_queue_mirror_update
AFTER UPDATE ON queue
BEGIN
    -- The row's key is immutable in practice; the delete still runs so a
    -- key change could never strand the old task id in the shadow.
    DELETE FROM queue_v15 WHERE task_id = OLD.task_id;
    INSERT OR REPLACE INTO queue_v15 (
        task_id, crate_name, version, features_json, target, rustc_version,
        downloads, miss_count, request_count, priority, status, error_msg,
        preserve_lockfile, lane, dispatch_attempts, attempt, generation_id,
        not_before, first_requested_at, created_at, updated_at, github_run_id,
        host_side, shape_requeue, unpublished_deps, deps_met, blocked,
        wake_at, dispatch_family, value, demand, dispatch_key, claimed_at,
        dispatch_eligible, dependency_identity
    ) VALUES (
        NEW.task_id, NEW.crate_name, NEW.version, NEW.features_json, NEW.target,
        NEW.rustc_version, NEW.downloads, NEW.miss_count, NEW.request_count,
        NEW.priority, NEW.status, NEW.error_msg, NEW.preserve_lockfile, NEW.lane,
        NEW.dispatch_attempts, NEW.attempt, NEW.generation_id, NEW.not_before,
        NEW.first_requested_at, NEW.created_at, NEW.updated_at, NEW.github_run_id,
        NEW.host_side, NEW.shape_requeue, NEW.unpublished_deps, NEW.deps_met,
        NEW.blocked, NEW.wake_at, NEW.dispatch_family, NEW.value, NEW.demand,
        NEW.dispatch_key, NEW.claimed_at, NEW.dispatch_eligible, NULL
    );
END;

CREATE TRIGGER IF NOT EXISTS v15_queue_mirror_delete
AFTER DELETE ON queue
BEGIN
    DELETE FROM queue_v15 WHERE task_id = OLD.task_id;
END;
