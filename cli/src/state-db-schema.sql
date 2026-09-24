CREATE TABLE IF NOT EXISTS artifact_cache_entries (
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
    compile_millis INTEGER NOT NULL DEFAULT 0,
    target TEXT NOT NULL DEFAULT '',
    profile_json TEXT NOT NULL DEFAULT '{}',
    emit_json TEXT NOT NULL DEFAULT '[]',
    kind_json TEXT NOT NULL DEFAULT '"Rlib"',
    crate_types_json TEXT NOT NULL DEFAULT '[]',
    verified_marker_version INTEGER,
    verified_marker_policy TEXT,
    provenance TEXT NOT NULL DEFAULT 'remote',
    PRIMARY KEY (rustc_version, cache_key)
);

CREATE INDEX IF NOT EXISTS idx_artifact_cache_entries_lru
ON artifact_cache_entries (rustc_version, last_accessed_ms, cache_key);

CREATE INDEX IF NOT EXISTS idx_artifact_cache_entries_semantic
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

CREATE TABLE IF NOT EXISTS artifact_cache_outputs (
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

CREATE TABLE IF NOT EXISTS artifact_cache_sigstore_signatures (
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

CREATE TABLE IF NOT EXISTS artifact_cache_native_static_libs (
    rustc_version TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    lib_name TEXT NOT NULL,
    bytes_sha256 TEXT NOT NULL,
    PRIMARY KEY (rustc_version, cache_key, ordinal),
    FOREIGN KEY (rustc_version, cache_key)
        REFERENCES artifact_cache_entries (rustc_version, cache_key)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS artifact_cache_native_directives (
    rustc_version TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    directive TEXT NOT NULL,
    PRIMARY KEY (rustc_version, cache_key, ordinal),
    FOREIGN KEY (rustc_version, cache_key)
        REFERENCES artifact_cache_entries (rustc_version, cache_key)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS artifact_cache_native_dep_env_vars (
    rustc_version TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    env_key TEXT NOT NULL,
    env_value TEXT NOT NULL,
    PRIMARY KEY (rustc_version, cache_key, env_key),
    FOREIGN KEY (rustc_version, cache_key)
        REFERENCES artifact_cache_entries (rustc_version, cache_key)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS artifact_cache_native_out_dir_files (
    rustc_version TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    relative_path TEXT NOT NULL,
    sha256 TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (rustc_version, cache_key, ordinal),
    FOREIGN KEY (rustc_version, cache_key)
        REFERENCES artifact_cache_entries (rustc_version, cache_key)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS metadata_values (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- stow#294: the shown-once mold recommendation is gone with the feature
-- that needed it; shed the marker from existing state DBs.
DELETE FROM metadata_values WHERE key = 'mold_recommendation_shown';

CREATE TABLE IF NOT EXISTS circuit_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    consecutive_failures INTEGER NOT NULL,
    tripped_at_ms INTEGER
);

CREATE TABLE IF NOT EXISTS negative_cache_entries (
    cache_key TEXT PRIMARY KEY,
    inserted_at_ms INTEGER NOT NULL
);

-- stow#194: the edge-query graph cache is gone — the local index resolver
-- replaced it. Drop the legacy tables so existing state DBs shed them.
DROP TABLE IF EXISTS graph_cache_expanded_features;
DROP TABLE IF EXISTS graph_cache_expanded_entries;
DROP TABLE IF EXISTS graph_cache_prefetch_artifacts;
DROP TABLE IF EXISTS graph_cache_current_artifacts;
DROP TABLE IF EXISTS graph_cache_analysis_features;
DROP TABLE IF EXISTS graph_cache_analysis_entries;
DROP TABLE IF EXISTS graph_cache_entries;

CREATE TABLE IF NOT EXISTS crate_stats (
    crate_name TEXT PRIMARY KEY,
    hits INTEGER NOT NULL,
    misses INTEGER NOT NULL,
    errors INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS materialized_outputs (
    output_path TEXT PRIMARY KEY,
    c_metadata TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

-- P1.1: cache for cargo metadata expansions, keyed on Cargo.lock + workspace
-- toml + target + rustc_version. Holds the JSON-encoded
-- `ExpandedDependencyGraph` result of `resolve_exact_dependency_graph`.
CREATE TABLE IF NOT EXISTS lockfile_graph_cache (
    cache_key TEXT PRIMARY KEY,
    inserted_at_ms INTEGER NOT NULL,
    expanded_json TEXT NOT NULL
);

-- stow#317: per-compile observations are in-memory only, scoped to one
-- build — see `ObservedUnit` and `BuildSupervisor` in lib.rs. Misses
-- mint post-build from the build's own compile observations; nothing
-- about them is persisted here.
