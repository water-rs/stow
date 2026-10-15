-- stow#736: a drained miss re-mints its `EnqueueRequest` with the
-- node's explicit-spelling flag — `KeysApart` when a proc-macro sits
-- in its `--extern` closure and a target-side node at a host triple
-- therefore owes both invocation spellings' shapes. NULL on
-- historical rows decodes as the flag those rows always carried.
ALTER TABLE dependency_graph_misses ADD COLUMN explicit_spelling INTEGER;
