-- The state database's one schema — the shape `state_db.rs::connect_pool`
-- writes into a fresh database before stamping its blake3 identity into
-- `PRAGMA user_version`. A changed file is a different database: the open
-- fails fast and the user re-creates it with `stow clean`.

CREATE TABLE artifact_cache_entries (
    rustc_version TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    relative_dir TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    last_accessed_ms INTEGER NOT NULL,
    oci_reference TEXT NOT NULL,
    oci_digest TEXT NOT NULL,
    compile_key TEXT NOT NULL DEFAULT '',
    crate_name TEXT NOT NULL DEFAULT '',
    crate_version TEXT NOT NULL DEFAULT '',
    c_metadata TEXT NOT NULL DEFAULT '',
    features_json TEXT NOT NULL DEFAULT '',
    dependency_c_metadata_json TEXT NOT NULL DEFAULT '[]',
    dependency_compile_keys_json TEXT NOT NULL DEFAULT '[]',
    -- `[{crate_name, compile_key, instance}]`: the instance digest each
    -- direct dependency was compiled against — the digest over the dep
    -- entry's own output sha256s. Written by local stores; remote rows
    -- carry '[]' (a remote binding is the published instance by
    -- construction).
    dependency_instances_json TEXT NOT NULL DEFAULT '[]',
    compile_millis INTEGER NOT NULL DEFAULT 0,
    target TEXT NOT NULL DEFAULT '',
    profile_json TEXT NOT NULL DEFAULT '{}',
    emit_json TEXT NOT NULL DEFAULT '[]',
    kind_json TEXT NOT NULL DEFAULT '"Rlib"',
    crate_types_json TEXT NOT NULL DEFAULT '[]',
    verified_marker_version INTEGER,
    verified_marker_policy TEXT,
    provenance TEXT NOT NULL DEFAULT 'remote',
    -- `Reach` (`stow_types::public_cache`) as its small integer: a serve
    -- writes this entry's reach onto its `materialized_outputs` rows, so
    -- a local-only entry keeps marking its consumers local-only
    -- (stow#1006). Remote bundles are always `Public`; the semantic
    -- stage also restricts its candidates to `Public` rows, which are
    -- exactly the standard-codegen crates.io entries.
    reach INTEGER NOT NULL,
    PRIMARY KEY (rustc_version, cache_key)
);

CREATE INDEX idx_artifact_cache_entries_lru
ON artifact_cache_entries (rustc_version, last_accessed_ms, cache_key);

CREATE INDEX idx_artifact_cache_entries_semantic
ON artifact_cache_entries (
    rustc_version,
    target,
    crate_name,
    features_json,
    dependency_c_metadata_json,
    kind_json,
    crate_types_json,
    profile_json,
    crate_version,
    c_metadata
);

CREATE TABLE artifact_cache_outputs (
    rustc_version TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    file_name TEXT NOT NULL,
    media_type TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    PRIMARY KEY (rustc_version, cache_key, ordinal),
    FOREIGN KEY (rustc_version, cache_key)
        REFERENCES artifact_cache_entries (rustc_version, cache_key)
        ON DELETE CASCADE
);

CREATE TABLE artifact_cache_sigstore_signatures (
    rustc_version TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    payload_path TEXT NOT NULL,
    signature TEXT NOT NULL,
    certificate_pem TEXT NOT NULL,
    rekor_bundle_json TEXT,
    PRIMARY KEY (rustc_version, cache_key, ordinal),
    FOREIGN KEY (rustc_version, cache_key)
        REFERENCES artifact_cache_entries (rustc_version, cache_key)
        ON DELETE CASCADE
);

-- stow#980: one row per C/C++ object under `cache_dir/cc/` — the file is
-- `<cache_key>.o` — so `evict_entries` serves the objects under the same
-- `artifact_cache_max_bytes` budget and LRU as `artifact_cache_entries`.
-- A store inserts the row; a hit bumps `last_accessed_ms`.
CREATE TABLE cc_cache_entries (
    cache_key TEXT PRIMARY KEY,
    size_bytes INTEGER NOT NULL,
    last_accessed_ms INTEGER NOT NULL
);

CREATE INDEX idx_cc_cache_entries_lru
ON cc_cache_entries (last_accessed_ms, cache_key);

CREATE TABLE metadata_values (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
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
-- build — see `ObservedUnit` and `BuildSupervisor` in lib.rs. Misses
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
