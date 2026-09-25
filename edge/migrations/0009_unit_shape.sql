-- The unit shape a row serves, recorded verbatim by the builder: which
-- side of the host/target boundary the unit compiles for (0 = target,
-- 1 = host), the cargo invocation spelling that produced it
-- (0 = native, 1 = `--target`), and whether it links (0 = check-only,
-- 1 = built). `-1` on all three marks a row registered before the
-- columns existed — a shapeless row satisfies no coverage clause and
-- the dependent gated on it waits for the node to rebuild and
-- republish.
ALTER TABLE artifacts ADD COLUMN unit_side INTEGER NOT NULL DEFAULT -1;
ALTER TABLE artifacts ADD COLUMN unit_invocation INTEGER NOT NULL DEFAULT -1;
ALTER TABLE artifacts ADD COLUMN unit_linked INTEGER NOT NULL DEFAULT -1;
