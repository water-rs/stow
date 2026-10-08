WITH batch AS MATERIALIZED (
    SELECT *
    FROM published_slice_rows_identity_legacy
    WHERE rowid > ?
    ORDER BY rowid
    LIMIT ?
)
INSERT INTO published_slice_rows (
    target, rustc_version, generation, crate_name, version, features_json,
    unit_side, unit_invocation, unit_linked, dependency_identity
)
SELECT
    old.target, old.rustc_version, old.generation,
    old.crate_name, old.version, old.features_json,
    old.unit_side, old.unit_invocation, old.unit_linked, NULL
FROM batch old
WHERE NOT EXISTS (
    SELECT 1 FROM published_slice_rows current
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
)
;
