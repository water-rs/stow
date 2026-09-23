//! The `OciManifest` wire shape is the OCI distribution spec's —
//! camelCase fields (`schemaVersion`, `mediaType`). Deserialize a
//! manifest document verbatim from a real `manifests/<reference>` GET
//! (this one is the index slice manifest `stow-mock-registry` serves,
//! byte-for-byte what GHCR returns for the same tag): a `snake_case`
//! drift in `types::api` breaks every manifest parse the edge does.

use stow_types::api::OciManifest;

/// The manifest `index.x86_64-unknown-linux-gnu.1.98.1` resolves to on
/// the mock registry — real camelCase wire bytes, not a hand-typed
/// approximation.
const OCI_INDEX_MANIFEST: &str = include_str!("fixtures/oci-index-manifest.json");

#[test]
fn a_real_oci_manifest_document_deserializes() {
    let manifest: OciManifest =
        serde_json::from_str(OCI_INDEX_MANIFEST).expect("OCI manifest document parses");

    assert_eq!(manifest.schema_version, 2);
    assert_eq!(
        manifest.media_type.as_deref(),
        Some("application/vnd.oci.image.manifest.v1+json")
    );
    assert_eq!(
        manifest.config.media_type,
        "application/vnd.stow.index.config.v1+json"
    );
    assert_eq!(manifest.config.size, 2);
    assert_eq!(manifest.layers.len(), 1);
    assert_eq!(
        manifest.layers[0].media_type,
        stow_types::index::STOW_INDEX_MEDIA_TYPE
    );
    assert!(manifest.layers[0].digest.starts_with("sha256:"));
    assert_eq!(manifest.layers[0].size, 582);
    assert_eq!(
        manifest
            .annotations
            .get("dev.stow.index.content-sha256")
            .map(String::as_str),
        Some("sha256:edbd256e6dad6d84fabcdd8976470def1e3848c9d5294a4e297e1c8467e1764b")
    );
}

#[test]
fn the_round_trip_writes_camel_case_fields_back() {
    let manifest: OciManifest =
        serde_json::from_str(OCI_INDEX_MANIFEST).expect("OCI manifest document parses");
    let value: serde_json::Value =
        serde_json::from_slice(&serde_json::to_vec(&manifest).expect("manifest serializes"))
            .expect("serialized manifest is json");
    assert_eq!(value["schemaVersion"], 2);
    assert!(value["layers"][0]["mediaType"].is_string());
    // And nothing leaks back out snake_case.
    assert!(value.get("schema_version").is_none());
    assert!(value["layers"][0].get("media_type").is_none());
}
