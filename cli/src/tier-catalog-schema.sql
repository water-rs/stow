-- Self-contained catalog schema for one cache tier (`crates-io/`,
-- `local-crates-io/`, or `local/`). Stamped into `PRAGMA user_version` by
-- `state_db.rs::connect_db_at` at creation and checked on every open.

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
    -- stow#1539: the bytes of the entry's files a clone elsewhere — a
    -- build directory's copy — still shares, as last measured at
    -- `shared_measured_ms`; deleting the entry frees `size_bytes` minus
    -- these. A new row is unmeasured and counts as unshared, so the cap
    -- over-counts it until an over-cap pass measures it.
    shared_bytes INTEGER NOT NULL DEFAULT 0,
    shared_measured_ms INTEGER NOT NULL DEFAULT 0,
    -- Within one tier, shared entries go last; cross-tier eviction rank
    -- (`crates-io` > `local-crates-io` > `local`) is ordered across the
    -- three tier catalogs by `CacheTier`.
    shared INTEGER GENERATED ALWAYS AS (shared_bytes > 0) VIRTUAL,
    PRIMARY KEY (rustc_version, cache_key)
);

CREATE INDEX idx_artifact_cache_entries_eviction
ON artifact_cache_entries (rustc_version, shared, last_accessed_ms, cache_key);

-- The shared entries an over-cap store re-measures, oldest measurement
-- first: a deleted clone changes no row, so a recorded share is only
-- trusted for `SHARE_REFRESH_INTERVAL_MS`.
CREATE INDEX idx_artifact_cache_entries_shared_age
ON artifact_cache_entries (rustc_version, shared_measured_ms)
WHERE shared_bytes > 0;

-- The closure walk of an eviction pass finds the providers of a compile
-- key through this index (stow#1053).
CREATE INDEX idx_artifact_cache_entries_compile_key
ON artifact_cache_entries (rustc_version, compile_key);

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

-- stow#1053: one row per compile key an entry's
-- `dependency_compile_keys_json` names, derived by the insert trigger
-- below and removed with the entry, so an eviction pass finds the
-- dependents of a compile key through `idx_artifact_cache_dependencies`
-- instead of listing every entry.
CREATE TABLE artifact_cache_dependencies (
    rustc_version TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    dependency_compile_key TEXT NOT NULL,
    PRIMARY KEY (rustc_version, cache_key, dependency_compile_key),
    FOREIGN KEY (rustc_version, cache_key)
        REFERENCES artifact_cache_entries (rustc_version, cache_key)
        ON DELETE CASCADE
);

CREATE INDEX idx_artifact_cache_dependencies
ON artifact_cache_dependencies (rustc_version, dependency_compile_key);

CREATE TRIGGER artifact_cache_entries_dependencies
AFTER INSERT ON artifact_cache_entries
BEGIN
    INSERT OR IGNORE INTO artifact_cache_dependencies
        (rustc_version, cache_key, dependency_compile_key)
    SELECT NEW.rustc_version, NEW.cache_key, json_extract(value, '$.compile_key')
    FROM json_each(NEW.dependency_compile_keys_json);
END;

-- stow#1053: the resident bytes of each rustc version's entries, kept by
-- the triggers below in the very transaction that inserts, resizes or
-- deletes a row, so the total is a function of the rows at every commit
-- and a store under the cap reads one row instead of the table.
CREATE TABLE artifact_cache_totals (
    rustc_version TEXT PRIMARY KEY,
    total_bytes INTEGER NOT NULL,
    -- stow#1539: the sum of the rows' `shared_bytes`.
    shared_bytes INTEGER NOT NULL
);

CREATE TRIGGER artifact_cache_entries_total_insert
AFTER INSERT ON artifact_cache_entries
BEGIN
    INSERT INTO artifact_cache_totals (rustc_version, total_bytes, shared_bytes)
    VALUES (NEW.rustc_version, NEW.size_bytes, NEW.shared_bytes)
    ON CONFLICT (rustc_version)
    DO UPDATE SET total_bytes = total_bytes + NEW.size_bytes,
                  shared_bytes = shared_bytes + NEW.shared_bytes;
END;

CREATE TRIGGER artifact_cache_entries_total_resize
AFTER UPDATE OF size_bytes, shared_bytes ON artifact_cache_entries
BEGIN
    UPDATE artifact_cache_totals
    SET total_bytes = total_bytes + NEW.size_bytes - OLD.size_bytes,
        shared_bytes = shared_bytes + NEW.shared_bytes - OLD.shared_bytes
    WHERE rustc_version = NEW.rustc_version;
END;

CREATE TRIGGER artifact_cache_entries_total_delete
AFTER DELETE ON artifact_cache_entries
BEGIN
    UPDATE artifact_cache_totals
    SET total_bytes = total_bytes - OLD.size_bytes,
        shared_bytes = shared_bytes - OLD.shared_bytes
    WHERE rustc_version = OLD.rustc_version;
END;

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

-- stow#980: one row per C/C++ object under `local/cc/` — the file is
-- `<cache_key>.o` — so `evict_entries` serves the objects under the same
-- `artifact_cache_max_bytes` budget and `local` tier rank.
CREATE TABLE cc_cache_entries (
    cache_key TEXT PRIMARY KEY,
    size_bytes INTEGER NOT NULL,
    last_accessed_ms INTEGER NOT NULL,
    shared_bytes INTEGER NOT NULL DEFAULT 0,
    shared_measured_ms INTEGER NOT NULL DEFAULT 0,
    shared INTEGER GENERATED ALWAYS AS (shared_bytes > 0) VIRTUAL
);

CREATE INDEX idx_cc_cache_entries_eviction
ON cc_cache_entries (shared, last_accessed_ms, cache_key);

CREATE INDEX idx_cc_cache_entries_shared_age
ON cc_cache_entries (shared_measured_ms)
WHERE shared_bytes > 0;

CREATE TABLE cc_cache_totals (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    total_bytes INTEGER NOT NULL,
    shared_bytes INTEGER NOT NULL
);

INSERT INTO cc_cache_totals (singleton, total_bytes, shared_bytes) VALUES (1, 0, 0);

CREATE TRIGGER cc_cache_entries_total_insert
AFTER INSERT ON cc_cache_entries
BEGIN
    UPDATE cc_cache_totals
    SET total_bytes = total_bytes + NEW.size_bytes,
        shared_bytes = shared_bytes + NEW.shared_bytes;
END;

CREATE TRIGGER cc_cache_entries_total_resize
AFTER UPDATE OF size_bytes, shared_bytes ON cc_cache_entries
BEGIN
    UPDATE cc_cache_totals
    SET total_bytes = total_bytes + NEW.size_bytes - OLD.size_bytes,
        shared_bytes = shared_bytes + NEW.shared_bytes - OLD.shared_bytes;
END;

CREATE TRIGGER cc_cache_entries_total_delete
AFTER DELETE ON cc_cache_entries
BEGIN
    UPDATE cc_cache_totals
    SET total_bytes = total_bytes - OLD.size_bytes,
        shared_bytes = shared_bytes - OLD.shared_bytes;
END;

CREATE TABLE tier_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
