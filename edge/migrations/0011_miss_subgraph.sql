-- stow#588: a drained miss re-mints its `EnqueueRequest` from the
-- dependency subgraph the verified admission carried, never a
-- leaf-only shape; `task_id` records the contextual identity the
-- admission minted so the drain can refuse a row that decodes to
-- something else. Both stay NULL on historical rows — unknown context
-- is never guessed; the drain consumes those rows as an explicit skip.
ALTER TABLE dependency_graph_misses ADD COLUMN subgraph_json TEXT;
ALTER TABLE dependency_graph_misses ADD COLUMN task_id TEXT;
