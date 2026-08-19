INSERT OR REPLACE INTO artifacts (
    compile_key,
    c_metadata,
    extra_filename,
    target,
    rustc_version,
    crate_name,
    version,
    features_json,
    dependency_c_metadata_json,
    oci_reference,
    oci_digest,
    has_native,
    artifact_kind,
    crate_types_json,
    profile_json,
    emit_json,
    artifact_size,
    created_at
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now')
)
