-- stow#317: a recorded miss carries the edges its compile observed —
-- the serialized `Vec<EnqueueDependency>` of the enqueue request that
-- admitted it, so the miss drain re-mints the unit with its
-- dependencies intact. Rows recorded before this column existed drain
-- as they always did: edge-less.
ALTER TABLE dependency_graph_misses ADD COLUMN depends_on_json TEXT NOT NULL DEFAULT '[]';
