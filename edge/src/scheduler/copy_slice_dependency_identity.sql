-- One copy batch of the version-15 identity rebuild (stow#588).
--
-- Historical rows move from the LIVE `published_slice_rows` into the
-- new-shape `published_slice_rows_v15` shadow in storage (`rowid`)
-- order. The shadow's primary key includes the nullable
-- `dependency_identity`, where SQLite treats NULLs as distinct — a
-- plain `OR IGNORE` cannot dedup — so the `WHERE NOT EXISTS` guard on
-- the nine membership columns does the dedup: a row the mirror
-- triggers already wrote (a live publish after the cursor passed it)
-- is newer than this stale read and wins. `dependency_identity` is
-- written NULL — pre-identity reports never carried context.
WITH batch AS MATERIALIZED (
    SELECT *
    FROM published_slice_rows
    WHERE rowid > ?
    ORDER BY rowid
    LIMIT ?
)
INSERT INTO published_slice_rows_v15 (
    target, rustc_version, generation, crate_name, version, features_json,
    unit_side, unit_invocation, unit_linked, dependency_identity
)
SELECT
    old.target, old.rustc_version, old.generation,
    old.crate_name, old.version, old.features_json,
    old.unit_side, old.unit_invocation, old.unit_linked, NULL
FROM batch old
WHERE NOT EXISTS (
    SELECT 1 FROM published_slice_rows_v15 current
    WHERE current.target = old.target
      AND current.rustc_version = old.rustc_version
      AND current.generation = old.generation
      AND current.crate_name = old.crate_name
      AND current.version = old.version
      AND current.features_json = old.features_json
      AND current.unit_side = old.unit_side
      AND current.unit_invocation = old.unit_invocation
      AND current.unit_linked = old.unit_linked
      AND current.dependency_identity IS NULL
);
