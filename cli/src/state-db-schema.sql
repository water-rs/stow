CREATE TABLE IF NOT EXISTS artifact_cache_entries (
    rustc_version TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    relative_dir TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    last_accessed_ms INTEGER NOT NULL,
    oci_reference TEXT NOT NULL,
    oci_digest TEXT NOT NULL,
    verified_marker_version INTEGER,
    verified_marker_policy TEXT,
    PRIMARY KEY (rustc_version, cache_key)
);

CREATE INDEX IF NOT EXISTS idx_artifact_cache_entries_lru
ON artifact_cache_entries (rustc_version, last_accessed_ms, cache_key);

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
    PRIMARY KEY (rustc_version, cache_key, ordinal),
    FOREIGN KEY (rustc_version, cache_key)
        REFERENCES artifact_cache_entries (rustc_version, cache_key)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS metadata_values (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS circuit_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    consecutive_failures INTEGER NOT NULL,
    tripped_at_ms INTEGER
);

CREATE TABLE IF NOT EXISTS negative_cache_entries (
    cache_key TEXT PRIMARY KEY,
    inserted_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS graph_cache_entries (
    cache_key TEXT PRIMARY KEY,
    inserted_at_ms INTEGER NOT NULL,
    expanded_cached INTEGER NOT NULL,
    expanded_total INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS graph_cache_analysis_entries (
    cache_key TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    crate_name TEXT NOT NULL,
    version TEXT NOT NULL,
    current_artifact_count INTEGER NOT NULL,
    recommended_version TEXT,
    recommended_artifact_count INTEGER,
    PRIMARY KEY (cache_key, ordinal),
    FOREIGN KEY (cache_key)
        REFERENCES graph_cache_entries (cache_key)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS graph_cache_analysis_features (
    cache_key TEXT NOT NULL,
    entry_ordinal INTEGER NOT NULL,
    ordinal INTEGER NOT NULL,
    feature_name TEXT NOT NULL,
    PRIMARY KEY (cache_key, entry_ordinal, ordinal),
    FOREIGN KEY (cache_key, entry_ordinal)
        REFERENCES graph_cache_analysis_entries (cache_key, ordinal)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS graph_cache_current_artifacts (
    cache_key TEXT NOT NULL,
    entry_ordinal INTEGER NOT NULL,
    ordinal INTEGER NOT NULL,
    c_metadata TEXT NOT NULL,
    PRIMARY KEY (cache_key, entry_ordinal, ordinal),
    FOREIGN KEY (cache_key, entry_ordinal)
        REFERENCES graph_cache_analysis_entries (cache_key, ordinal)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS graph_cache_prefetch_artifacts (
    cache_key TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    crate_name TEXT NOT NULL,
    c_metadata TEXT NOT NULL,
    PRIMARY KEY (cache_key, ordinal),
    FOREIGN KEY (cache_key)
        REFERENCES graph_cache_entries (cache_key)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS crate_stats (
    crate_name TEXT PRIMARY KEY,
    hits INTEGER NOT NULL,
    misses INTEGER NOT NULL,
    errors INTEGER NOT NULL
);
