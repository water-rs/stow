-- The D1 catalog's one schema — the artifact mirror `index sync` fills
-- from the signed GHCR records, plus the crates.io response caches the
-- edge keeps beside it. The store has no migration path: a schema
-- change is an operator reset — drop these objects, apply this file
-- with `wrangler d1 execute <db> --file schema.sql`, then resync from
-- the records (`stow-admin index export --full` + `index sync`).

-- One built artifact row per (c_metadata, target, rustc_version): the
-- compile key, the unit's semantic identity, the GHCR coordinates of
-- the bundle blob, and the recorded build cost.
CREATE TABLE artifacts (
    compile_key TEXT NOT NULL,
    c_metadata TEXT NOT NULL,
    extra_filename TEXT NOT NULL,
    target TEXT NOT NULL,
    rustc_version TEXT NOT NULL,
    crate_name TEXT NOT NULL,
    version TEXT NOT NULL,
    features_json TEXT NOT NULL,
    dependency_c_metadata_json TEXT NOT NULL DEFAULT '[]',
    oci_reference TEXT NOT NULL,
    oci_digest TEXT NOT NULL,
    has_native INTEGER NOT NULL DEFAULT 0,
    artifact_kind TEXT NOT NULL,
    crate_types_json TEXT NOT NULL,
    profile_json TEXT NOT NULL,
    emit_json TEXT NOT NULL,
    artifact_size INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    -- The trusted publish stage pushes the assembled bundle tar as the
    -- `<tag>.bundle` layer; the edge streams that blob by digest instead
    -- of assembling a tar from the artifact's layers. A row with an
    -- empty digest serves nothing and is pruned the first time it is
    -- served.
    bundle_digest TEXT NOT NULL DEFAULT '',
    bundle_size INTEGER NOT NULL DEFAULT 0,
    -- Wall-clock milliseconds the captured rustc invocation took,
    -- recorded at register time.
    compile_millis INTEGER NOT NULL DEFAULT 0,
    -- The glibc floor a hosted artifact needs to load, measured at
    -- publish from the bundle members' ELF version-needed entries.
    -- Tri-state TEXT: NULL means the row is unmeasured and must never
    -- read as "no floor"; '' means measured with no glibc requirement
    -- (every non-ELF payload); 'x.y' is the floor itself.
    min_glibc TEXT,
    -- The unit shape the row serves, recorded verbatim by the builder:
    -- which side of the host/target boundary the unit compiles for
    -- (0 = target, 1 = host), the cargo invocation spelling that
    -- produced it (0 = native, 1 = `--target`), and whether it links
    -- (0 = check-only, 1 = built). -1 on any of the three marks a
    -- shapeless row: it satisfies no coverage clause.
    unit_side INTEGER NOT NULL DEFAULT -1,
    unit_invocation INTEGER NOT NULL DEFAULT -1,
    unit_linked INTEGER NOT NULL DEFAULT -1,
    PRIMARY KEY (c_metadata, target, rustc_version)
);

-- The catalog pickers' per-crate walk.
CREATE INDEX idx_artifacts_catalog
ON artifacts (target, rustc_version, crate_name, features_json, version);

-- The admin index endpoint walks each (target, rustc_version) slice
-- ordered by c_metadata, one keyset page at a time; this index turns
-- every page into a bounded range scan instead of a full-slice sort.
CREATE INDEX idx_artifacts_index_page
ON artifacts (target, rustc_version, c_metadata);

-- A recorded cache miss: a node a user needed that nobody had built.
-- Keyed on the identity the queue deduplicates on — crate, version,
-- features, target, rustc, side — so a host miss and a target miss at
-- one semantic identity never collide. `depends_on_json` is the
-- serialized `Vec<EnqueueDependency>` of the enqueue request that
-- admitted the miss; `subgraph_json` + `task_id` record the contextual
-- identity the admission minted so the drain re-mints the exact unit —
-- both NULL on a row recorded without context, which the drain
-- consumes as an explicit skip, never a guess.
CREATE TABLE dependency_graph_misses (
    crate_name TEXT NOT NULL,
    version TEXT NOT NULL,
    features_json TEXT NOT NULL,
    target TEXT NOT NULL,
    rustc_version TEXT NOT NULL,
    host_side INTEGER NOT NULL DEFAULT 0,
    explicit_spelling INTEGER NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 0,
    first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    admitted_at TEXT,
    queued_at TEXT,
    depends_on_json TEXT NOT NULL DEFAULT '[]',
    subgraph_json TEXT,
    task_id TEXT,
    PRIMARY KEY (crate_name, version, features_json, target, rustc_version, host_side)
);

CREATE INDEX idx_dependency_graph_misses_target
ON dependency_graph_misses (target, rustc_version, last_seen_at);

-- crates.io response caches behind the site pickers and the request
-- route's version/rustc lookups.
CREATE TABLE crate_versions_cache (
    crate_name TEXT PRIMARY KEY,
    versions_json TEXT NOT NULL,
    fetched_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE crate_version_graph_cache (
    crate_name TEXT NOT NULL,
    version TEXT NOT NULL,
    graph_json TEXT NOT NULL,
    fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (crate_name, version)
);

CREATE TABLE schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
