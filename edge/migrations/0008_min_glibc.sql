-- The glibc floor a hosted artifact needs to load, measured at publish
-- from the bundle members' ELF version-needed entries (stow#336).
--
-- Tri-state TEXT: NULL means the row predates the measurement and is
-- excluded from the published index until `stow-admin index
-- backfill-min-glibc` measures it — an unmeasured row must never read as
-- "no floor". '' means measured with no glibc requirement (every non-ELF
-- payload), and 'x.y' is the floor itself.
ALTER TABLE artifacts ADD COLUMN min_glibc TEXT;
