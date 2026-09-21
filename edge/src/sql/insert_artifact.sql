INSERT INTO artifacts (
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
    bundle_digest,
    bundle_size,
    compile_millis,
    created_at
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now')
)
-- `created_at` stays out of the update list so an idempotent re-register
-- preserves the row's first-registration timestamp.
ON CONFLICT(c_metadata, target, rustc_version) DO UPDATE SET
    compile_key = excluded.compile_key,
    extra_filename = excluded.extra_filename,
    crate_name = excluded.crate_name,
    version = excluded.version,
    features_json = excluded.features_json,
    dependency_c_metadata_json = excluded.dependency_c_metadata_json,
    oci_reference = excluded.oci_reference,
    oci_digest = excluded.oci_digest,
    has_native = excluded.has_native,
    artifact_kind = excluded.artifact_kind,
    crate_types_json = excluded.crate_types_json,
    profile_json = excluded.profile_json,
    emit_json = excluded.emit_json,
    artifact_size = excluded.artifact_size,
    bundle_digest = excluded.bundle_digest,
    bundle_size = excluded.bundle_size,
    compile_millis = excluded.compile_millis
