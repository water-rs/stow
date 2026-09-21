-- The lockfile resolver moved client-side with the signed artifact index:
-- nothing on the edge reads `dependency_count` anymore, so the seed index
-- and the column go together.
DROP INDEX IF EXISTS idx_artifacts_seed;
ALTER TABLE artifacts DROP COLUMN dependency_count;
