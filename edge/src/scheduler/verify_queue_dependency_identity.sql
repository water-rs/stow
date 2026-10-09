SELECT EXISTS (
    -- Membership check on the columns the copy must preserve
    -- verbatim: the identity tuple plus the insert-time fields.
    -- Mutable columns (downloads, counters, status, attempt,
    -- generation, lane, error, and every gate/rank derivation) may
    -- legitimately drift under traffic between batched migrate calls,
    -- so comparing them here would report false differences.
    SELECT task_id, crate_name, version, features_json, target,
           rustc_version, preserve_lockfile, host_side,
           first_requested_at, created_at
    FROM queue_identity_legacy
    EXCEPT
    SELECT task_id, crate_name, version, features_json, target,
           rustc_version, preserve_lockfile, host_side,
           first_requested_at, created_at
    FROM queue
) OR EXISTS (
    -- A copied row carrying a digest means the copy wrote context it
    -- was told to write as NULL. Joined on task_id: a legacy id is
    -- never re-minted by new code (whose ids always carry the `-d`
    -- segment), so a non-NULL digest here can only be a copy defect.
    SELECT 1
    FROM queue_identity_legacy old
    JOIN queue current USING (task_id)
    WHERE current.dependency_identity IS NOT NULL
) AS differs;
