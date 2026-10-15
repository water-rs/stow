-- stow#730: the Merkle dependency digest every record carries since
-- stow#588. Rows written before the column existed are invalid — the
-- operator empties and resyncs the mirror after this deploys, so a NULL
-- is never read; every decode treats it as an invariant violation.
ALTER TABLE artifacts ADD COLUMN dependency_identity TEXT;
