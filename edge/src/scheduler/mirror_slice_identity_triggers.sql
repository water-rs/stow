-- Version-15 identity rebuild (stow#588): the mirror that keeps the
-- `published_slice_rows_v15` shadow current while the historical copy
-- runs. The shadow's primary key contains the nullable
-- `dependency_identity`, so `OR REPLACE`/`OR IGNORE` cannot dedup
-- (SQLite never treats NULL as equal to NULL): inserts and updates
-- therefore apply by matching the nine membership columns, guarded so
-- a mirrored row is always the newest write and the copy's
-- `WHERE NOT EXISTS` batch never overwrites it. `dependency_identity`
-- mirrors NULL — the live table's shape predates the column.
-- These triggers die with the live table at the swap's `DROP TABLE`.
CREATE TRIGGER IF NOT EXISTS v15_slice_mirror_insert
AFTER INSERT ON published_slice_rows
BEGIN
    INSERT INTO published_slice_rows_v15 (
        target, rustc_version, generation, crate_name, version, features_json,
        unit_side, unit_invocation, unit_linked, dependency_identity
    ) SELECT
        NEW.target, NEW.rustc_version, NEW.generation, NEW.crate_name,
        NEW.version, NEW.features_json, NEW.unit_side, NEW.unit_invocation,
        NEW.unit_linked, NULL
    WHERE NOT EXISTS (
        SELECT 1 FROM published_slice_rows_v15 current
        WHERE current.target = NEW.target
          AND current.rustc_version = NEW.rustc_version
          AND current.generation = NEW.generation
          AND current.crate_name = NEW.crate_name
          AND current.version = NEW.version
          AND current.features_json = NEW.features_json
          AND current.unit_side = NEW.unit_side
          AND current.unit_invocation = NEW.unit_invocation
          AND current.unit_linked = NEW.unit_linked
          AND current.dependency_identity IS NULL
    );
END;

CREATE TRIGGER IF NOT EXISTS v15_slice_mirror_update
AFTER UPDATE ON published_slice_rows
BEGIN
    -- A slice row's columns are all primary-key columns, so an update
    -- lands as a retarget plus a guarded insert — matching the queue
    -- mirror's INSERT OR REPLACE semantics under a nullable key.
    UPDATE published_slice_rows_v15
    SET target = NEW.target, rustc_version = NEW.rustc_version,
        generation = NEW.generation, crate_name = NEW.crate_name,
        version = NEW.version, features_json = NEW.features_json,
        unit_side = NEW.unit_side, unit_invocation = NEW.unit_invocation,
        unit_linked = NEW.unit_linked
    WHERE target = OLD.target
      AND rustc_version = OLD.rustc_version
      AND generation = OLD.generation
      AND crate_name = OLD.crate_name
      AND version = OLD.version
      AND features_json = OLD.features_json
      AND unit_side = OLD.unit_side
      AND unit_invocation = OLD.unit_invocation
      AND unit_linked = OLD.unit_linked
      AND dependency_identity IS NULL;
    INSERT INTO published_slice_rows_v15 (
        target, rustc_version, generation, crate_name, version, features_json,
        unit_side, unit_invocation, unit_linked, dependency_identity
    ) SELECT
        NEW.target, NEW.rustc_version, NEW.generation, NEW.crate_name,
        NEW.version, NEW.features_json, NEW.unit_side, NEW.unit_invocation,
        NEW.unit_linked, NULL
    WHERE NOT EXISTS (
        SELECT 1 FROM published_slice_rows_v15 current
        WHERE current.target = NEW.target
          AND current.rustc_version = NEW.rustc_version
          AND current.generation = NEW.generation
          AND current.crate_name = NEW.crate_name
          AND current.version = NEW.version
          AND current.features_json = NEW.features_json
          AND current.unit_side = NEW.unit_side
          AND current.unit_invocation = NEW.unit_invocation
          AND current.unit_linked = NEW.unit_linked
          AND current.dependency_identity IS NULL
    );
END;

CREATE TRIGGER IF NOT EXISTS v15_slice_mirror_delete
AFTER DELETE ON published_slice_rows
BEGIN
    DELETE FROM published_slice_rows_v15
    WHERE target = OLD.target
      AND rustc_version = OLD.rustc_version
      AND generation = OLD.generation
      AND crate_name = OLD.crate_name
      AND version = OLD.version
      AND features_json = OLD.features_json
      AND unit_side = OLD.unit_side
      AND unit_invocation = OLD.unit_invocation
      AND unit_linked = OLD.unit_linked
      AND dependency_identity IS NULL;
END;
