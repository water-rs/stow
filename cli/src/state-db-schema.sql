-- The host state database's one schema — the shape `state_db.rs::connect_pool`
-- writes into a fresh database before stamping its blake3 identity into
-- `PRAGMA user_version`. Artifact and C/C++ cache catalogs live inside their
-- own self-contained tier directories (`crates-io/`, `local-crates-io/`,
-- `local/`); this database holds host-ephemeral runtime tables only.

CREATE TABLE metadata_values (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- stow#1540: the build directories stow placed under `<cache>/build-dir/`,
-- each attributed to the member manifests of the workspace builds of it
-- compiled (a JSON array of paths, empty when none was seen) and the
-- last time a build opened a session in it. A directory with no row is
-- collected by its modification times alone.
CREATE TABLE build_directories (
    build_dir TEXT PRIMARY KEY,
    manifests_json TEXT NOT NULL,
    last_built_ms INTEGER NOT NULL
);

CREATE TABLE circuit_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    consecutive_failures INTEGER NOT NULL,
    tripped_at_ms INTEGER
);

CREATE TABLE negative_cache_entries (
    cache_key TEXT PRIMARY KEY,
    inserted_at_ms INTEGER NOT NULL
);

-- `glibc_refusals` counts lookups refused because the artifact's
-- `min_glibc` exceeds the host's glibc — apart from misses, because the
-- artifact exists and the unit just compiled locally. `local_dependency_builds`
-- counts units that compiled locally with no lookup at all, because a
-- dependency they link was compiled locally in the same build — apart
-- from misses for the same reason. DEFAULT 0 covers the inserts that do
-- not name a column.
CREATE TABLE crate_stats (
    crate_name TEXT PRIMARY KEY,
    hits INTEGER NOT NULL,
    misses INTEGER NOT NULL,
    errors INTEGER NOT NULL,
    glibc_refusals INTEGER NOT NULL DEFAULT 0,
    local_dependency_builds INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE materialized_outputs (
    output_path TEXT PRIMARY KEY,
    c_metadata TEXT NOT NULL,
    -- `outputs_instance_digest` of the artifact instance at this path —
    -- which exact bytes a dependent's `--extern` resolves to.
    instance TEXT NOT NULL,
    -- `Reach` (`stow_types::public_cache`) as its small integer: a
    -- dependent folds this column into its own reach, so a git-sourced
    -- or codegen-keyed dep marks every consumer local-only (stow#1006).
    reach INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

-- Cache for cargo metadata expansions, keyed on Cargo.lock + workspace
-- toml + target + rustc_version. Holds the JSON-encoded
-- `ExpandedDependencyGraph` result of `resolve_exact_dependency_graph`.
CREATE TABLE lockfile_graph_cache (
    cache_key TEXT PRIMARY KEY,
    inserted_at_ms INTEGER NOT NULL,
    expanded_json TEXT NOT NULL
);

-- stow#317: per-compile observations are in-memory only, scoped to one
-- build — see `ObservedUnit` and `Session` in daemon/session. Misses
-- mint post-build from the build's own compile observations; nothing
-- about them is persisted here.

-- stow#608: the link resolution's outcome — the cargo `--config` args
-- mold provisioning returns — keyed by a digest of every input the
-- resolution reads (rustc -vV, target triple, config document contents,
-- env vars), with the probed files witnessed so a changed `cc` or
-- `ld.mold` reads as a miss. Only successful resolutions are recorded.
CREATE TABLE link_resolution_cache (
    inputs_digest TEXT PRIMARY KEY,
    args_json TEXT NOT NULL,
    witnesses_json TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);
