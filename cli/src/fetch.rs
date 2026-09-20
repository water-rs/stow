use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::io::Cursor;
use std::path::{Component, Path};

use oci_spec::image::ImageManifest;
use semver::Version;
use sha2::{Digest, Sha256};
use stow_types::bundle::{
    ArtifactBundleFile, ArtifactBundleManifest, STOW_BUNDLE_MANIFEST_PATH, STOW_OCI_CONFIG_PATH,
    STOW_OCI_MANIFEST_PATH, STOW_SIGSTORE_PAYLOAD_DIR, SigstoreSignature,
};
use stow_types::error::Context;
use stow_types::versioning::is_semver_compatible_upgrade;
use tar::Archive;

use crate::config::StowConfig;

#[derive(Debug, Clone)]
pub struct FetchRequest<'a> {
    pub target: &'a str,
    pub rustc_version: &'a str,
    pub c_metadata: &'a str,
}

#[derive(Debug, Clone)]
pub struct SemanticFetchRequest {
    pub crate_name: String,
    pub version: String,
    pub features_json: String,
    pub dependency_c_metadata_json: String,
    pub target: String,
    pub rustc_version: String,
    pub profile: stow_types::platform::Profile,
    pub emit: Vec<String>,
    pub kind: stow_types::artifact::ArtifactKind,
    pub crate_types: Vec<stow_types::artifact::RustCrateType>,
}

#[derive(Debug, Clone)]
pub struct ArtifactBundle {
    pub manifest: ArtifactBundleManifest,
    pub files: BTreeMap<String, Vec<u8>>,
}

/// The registry base this config pulls bundles from — `STOW_REGISTRY_BASE_URL`
/// in mock mode, GHCR otherwise.
pub fn registry_base(config: &StowConfig) -> stow_types::error::Result<stow_oci::RegistryBase> {
    stow_oci::RegistryBase::parse(&config.registry_base_url)
}

/// Pull one bundle blob by content digest and require the bytes to hash to
/// it — the digest is both the name and the checksum, so no index lookup or
/// manifest round trip is needed.
///
/// # Errors
///
/// Returns an error when the registry is unreachable or the blob fails the
/// digest check.
pub async fn download_bundle_bytes(
    base: &stow_oci::RegistryBase,
    bundle_digest: &str,
) -> stow_types::error::Result<Vec<u8>> {
    stow_oci::pull_blob_by_digest(base, bundle_digest).await
}

/// Pull and parse the bundle `bundle_digest` names.
///
/// # Errors
///
/// Returns an error when the pull fails or the bytes are not a well-formed
/// stow bundle.
pub async fn download_bundle(
    config: &StowConfig,
    bundle_digest: &str,
) -> stow_types::error::Result<ArtifactBundle> {
    let base = registry_base(config)?;
    let bytes = download_bundle_bytes(&base, bundle_digest).await?;
    parse_bundle(bytes).await
}

async fn parse_bundle(bytes: Vec<u8>) -> stow_types::error::Result<ArtifactBundle> {
    // CPU-bound tar walk over owned bytes: keep it off the async workers so
    // concurrent prefetch futures are not stalled behind unpacking.
    tokio::task::spawn_blocking(move || parse_bundle_sync(bytes))
        .await
        .wrap_err("join bundle parse task")?
}

pub async fn parse_downloaded_bundle(bytes: Vec<u8>) -> stow_types::error::Result<ArtifactBundle> {
    parse_bundle(bytes).await
}

pub fn validate_bundle_identity(
    bundle: &ArtifactBundle,
    crate_name: &str,
    c_metadata: &str,
    target: &str,
    rustc_version: &str,
) -> stow_types::error::Result<()> {
    if bundle.manifest.config.target != target {
        return Err(stow_types::stow_error!(
            "downloaded bundle target mismatch: expected {}, got {}",
            target,
            bundle.manifest.config.target
        ));
    }
    if bundle.manifest.config.rustc_version != rustc_version {
        return Err(stow_types::stow_error!(
            "downloaded bundle rustc mismatch: expected {}, got {}",
            rustc_version,
            bundle.manifest.config.rustc_version
        ));
    }
    if bundle.manifest.config.c_metadata != c_metadata {
        return Err(stow_types::stow_error!(
            "downloaded bundle c_metadata mismatch: expected {}, got {}",
            c_metadata,
            bundle.manifest.config.c_metadata
        ));
    }
    if canonical_crate_name(bundle.manifest.config.crate_name.as_str())
        != canonical_crate_name(crate_name)
    {
        return Err(stow_types::stow_error!(
            "downloaded bundle crate mismatch: expected {}, got {}",
            crate_name,
            bundle.manifest.config.crate_name
        ));
    }
    Ok(())
}

pub fn validate_semantic_bundle_identity(
    bundle: &ArtifactBundle,
    request: &SemanticFetchRequest,
) -> stow_types::error::Result<()> {
    if bundle.manifest.config.target.as_str() != request.target {
        return Err(stow_types::stow_error!(
            "downloaded semantic bundle target mismatch: expected {}, got {}",
            request.target,
            bundle.manifest.config.target
        ));
    }
    if bundle.manifest.config.rustc_version.as_str() != request.rustc_version {
        return Err(stow_types::stow_error!(
            "downloaded semantic bundle rustc mismatch: expected {}, got {}",
            request.rustc_version,
            bundle.manifest.config.rustc_version
        ));
    }
    validate_semantic_bundle_version(
        &request.version,
        &bundle.manifest.config.crate_version.to_string(),
    )?;
    if bundle.manifest.config.features_json.raw() != request.features_json {
        return Err(stow_types::stow_error!(
            "downloaded semantic bundle features mismatch: expected {}, got {}",
            request.features_json,
            bundle.manifest.config.features_json
        ));
    }
    if bundle.manifest.config.dependency_c_metadata_json.raw() != request.dependency_c_metadata_json
    {
        return Err(stow_types::stow_error!(
            "downloaded semantic bundle dependency_c_metadata_json mismatch"
        ));
    }
    if bundle.manifest.config.profile != request.profile {
        return Err(stow_types::stow_error!(
            "downloaded semantic bundle profile mismatch: bundle {:?}, request {:?}",
            bundle.manifest.config.profile,
            request.profile
        ));
    }
    if !emit_covers_request(&bundle.manifest.config.emit, &request.emit) {
        return Err(stow_types::stow_error!(
            "downloaded semantic bundle emit mismatch"
        ));
    }
    if bundle.manifest.config.kind != request.kind {
        return Err(stow_types::stow_error!(
            "downloaded semantic bundle artifact kind mismatch: expected {}, got {}",
            request.kind.as_str(),
            bundle.manifest.config.kind.as_str()
        ));
    }
    if bundle.manifest.config.crate_types != request.crate_types {
        return Err(stow_types::stow_error!(
            "downloaded semantic bundle crate types mismatch"
        ));
    }
    if canonical_crate_name(bundle.manifest.config.crate_name.as_str())
        != canonical_crate_name(&request.crate_name)
    {
        return Err(stow_types::stow_error!(
            "downloaded semantic bundle crate mismatch: expected {}, got {}",
            request.crate_name,
            bundle.manifest.config.crate_name
        ));
    }
    Ok(())
}

fn canonical_crate_name(name: &str) -> String {
    name.replace('-', "_")
}

fn emit_covers_request(candidate_emit: &[String], requested_emit: &[String]) -> bool {
    let candidate = candidate_emit.iter().collect::<BTreeSet<_>>();
    requested_emit
        .iter()
        .all(|requested| candidate.contains(requested))
}

fn validate_semantic_bundle_version(
    requested_version: &str,
    bundle_version: &str,
) -> stow_types::error::Result<()> {
    let requested = Version::parse(requested_version)
        .wrap_err_with(|| format!("parse requested semantic version {requested_version}"))?;
    let actual = Version::parse(bundle_version)
        .wrap_err_with(|| format!("parse bundle semantic version {bundle_version}"))?;
    if actual == requested || is_semver_compatible_upgrade(&requested, &actual) {
        return Ok(());
    }
    Err(stow_types::stow_error!(
        "downloaded semantic bundle version mismatch: expected {} or semver-compatible upgrade, got {}",
        requested_version,
        bundle_version
    ))
}

fn parse_bundle_sync(bytes: Vec<u8>) -> stow_types::error::Result<ArtifactBundle> {
    let mut archive = Archive::new(Cursor::new(bytes));
    let mut manifest: Option<ArtifactBundleManifest> = None;
    let mut files = BTreeMap::new();

    for entry in archive.entries().wrap_err("read artifact bundle entries")? {
        let mut entry = entry.wrap_err("read artifact bundle entry")?;
        let path = entry
            .path()
            .wrap_err("read artifact bundle entry path")?
            .to_string_lossy()
            .to_string();
        let mut contents = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut contents)
            .wrap_err_with(|| format!("read artifact bundle entry {path}"))?;

        if path == STOW_BUNDLE_MANIFEST_PATH {
            if manifest.is_some() {
                return Err(stow_types::stow_error!(
                    "artifact bundle contains duplicate entry {}",
                    STOW_BUNDLE_MANIFEST_PATH
                ));
            }
            manifest = Some(parse_bundle_manifest_json(&contents)?);
            continue;
        }
        if files.insert(path.clone(), contents).is_some() {
            return Err(stow_types::stow_error!(
                "artifact bundle contains duplicate entry {}",
                path
            ));
        }
    }

    finalize_bundle(manifest, files)
}

fn finalize_bundle(
    manifest: Option<ArtifactBundleManifest>,
    files: BTreeMap<String, Vec<u8>>,
) -> stow_types::error::Result<ArtifactBundle> {
    let manifest = manifest
        .ok_or_else(|| stow_types::stow_error!("artifact bundle is missing manifest.json"))?;
    validate_sigstore_payload_paths(&manifest.sigstore_signatures)?;
    validate_output_file_names(&manifest)?;
    validate_declared_bundle_entries(&manifest, &files)?;
    validate_oci_manifest(&manifest, &files)?;
    validate_output_entries_present(
        &manifest.config.outputs,
        manifest.config.native_archive.as_ref(),
        &files,
    )?;
    Ok(ArtifactBundle { manifest, files })
}

/// The exact set of tar entry paths a bundle may carry besides
/// `manifest.json`: the signature-bound OCI manifest and config, every layer
/// payload the config declares, and the sigstore payload blobs. Tar entries
/// outside this set are unsigned data the serving edge appended on top of a
/// validly signed bundle, so `files` must match this set exactly.
fn declared_bundle_paths(manifest: &ArtifactBundleManifest) -> BTreeSet<String> {
    let mut paths = BTreeSet::from([
        STOW_OCI_MANIFEST_PATH.to_owned(),
        STOW_OCI_CONFIG_PATH.to_owned(),
    ]);
    for file in manifest
        .config
        .outputs
        .iter()
        .chain(manifest.config.native_archive.as_ref())
    {
        paths.insert(bundle_file_path(&file.file_name));
    }
    for signature in &manifest.sigstore_signatures {
        paths.insert(signature.payload_path.clone());
    }
    paths
}

fn validate_declared_bundle_entries(
    manifest: &ArtifactBundleManifest,
    files: &BTreeMap<String, Vec<u8>>,
) -> stow_types::error::Result<()> {
    let declared = declared_bundle_paths(manifest);
    for path in files.keys() {
        if !declared.contains(path) {
            return Err(stow_types::stow_error!(
                "artifact bundle contains undeclared entry {path}"
            ));
        }
    }
    for path in &declared {
        if !files.contains_key(path) {
            return Err(stow_types::stow_error!(
                "artifact bundle is missing declared entry {path}"
            ));
        }
    }
    Ok(())
}

/// Output file names are signature-bound, but they still become cache
/// paths, so each must be exactly one path component: never empty, rooted
/// or traversing.
fn validate_output_file_names(manifest: &ArtifactBundleManifest) -> stow_types::error::Result<()> {
    for file in manifest
        .config
        .outputs
        .iter()
        .chain(manifest.config.native_archive.as_ref())
    {
        let mut components = Path::new(&file.file_name).components();
        let valid =
            matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
        if !valid {
            return Err(stow_types::stow_error!(
                "artifact bundle output file name {:?} is not a single path component",
                file.file_name
            ));
        }
    }
    Ok(())
}

/// Sigstore payload paths join the declared-entry set, so they must be
/// confined to `sigstore/<name>`: a single `Normal` component under the
/// payload directory, never rooted or traversing out of it.
fn validate_sigstore_payload_paths(
    signatures: &[SigstoreSignature],
) -> stow_types::error::Result<()> {
    for signature in signatures {
        let mut components = Path::new(&signature.payload_path).components();
        let valid = matches!(
            components.next(),
            Some(Component::Normal(dir)) if dir == OsStr::new(STOW_SIGSTORE_PAYLOAD_DIR)
        ) && matches!(components.next(), Some(Component::Normal(_)))
            && components.next().is_none();
        if !valid {
            return Err(stow_types::stow_error!(
                "sigstore payload path {} is not a single file under {STOW_SIGSTORE_PAYLOAD_DIR}/",
                signature.payload_path
            ));
        }
    }
    Ok(())
}

fn parse_bundle_manifest_json(
    contents: &[u8],
) -> stow_types::error::Result<ArtifactBundleManifest> {
    serde_json::from_slice(contents).map_err(|error| {
        let preview_len = contents.len().min(32);
        stow_types::stow_error!(
            "parse artifact bundle manifest json: {error}; len={}; first_bytes_hex={}",
            contents.len(),
            hex::encode(&contents[..preview_len]),
        )
    })
}

fn validate_oci_manifest(
    bundle_manifest: &ArtifactBundleManifest,
    files: &BTreeMap<String, Vec<u8>>,
) -> stow_types::error::Result<()> {
    let manifest_bytes = files.get(STOW_OCI_MANIFEST_PATH).ok_or_else(|| {
        stow_types::stow_error!("artifact bundle is missing {STOW_OCI_MANIFEST_PATH}")
    })?;
    let config_bytes = files.get(STOW_OCI_CONFIG_PATH).ok_or_else(|| {
        stow_types::stow_error!("artifact bundle is missing {STOW_OCI_CONFIG_PATH}")
    })?;
    let manifest_digest = sha256_prefixed(manifest_bytes);
    if manifest_digest != bundle_manifest.oci_digest {
        return Err(stow_types::stow_error!(
            "bundle OCI manifest digest mismatch: expected {}, got {}",
            bundle_manifest.oci_digest,
            manifest_digest
        ));
    }

    let manifest: ImageManifest =
        serde_json::from_slice(manifest_bytes).wrap_err("parse OCI manifest json")?;
    if manifest.config().digest().to_string() != sha256_prefixed(config_bytes) {
        return Err(stow_types::stow_error!("bundle OCI config digest mismatch"));
    }

    // The identity fields the CLI trusts (crate name/version, target,
    // rustc_version, c_metadata, features, dependency identities, profile,
    // emit, kind) live in manifest.json, which is NOT covered by the cosign
    // signature. `oci/config.json` IS covered (signature -> manifest digest
    // -> config digest), so the unsigned copy must byte-for-byte agree with
    // the signed one or a tamperer could relabel a validly-signed bundle as
    // a different artifact.
    let signed_config: serde_json::Value =
        serde_json::from_slice(config_bytes).wrap_err("parse signature-bound OCI config json")?;
    let manifest_config = serde_json::to_value(&bundle_manifest.config)
        .wrap_err("encode bundle manifest config for identity comparison")?;
    if signed_config != manifest_config {
        return Err(stow_types::stow_error!(
            "bundle manifest config does not match the signature-bound OCI config — \
             artifact identity may have been tampered with"
        ));
    }

    // `outputs` first, then the native archive when the config declares one.
    // The archive is a layer like any other, so the cosign signature covers it
    // through the manifest digest exactly as it covers the compiled outputs.
    let expected_layers = bundle_manifest
        .config
        .outputs
        .iter()
        .chain(bundle_manifest.config.native_archive.as_ref())
        .collect::<Vec<_>>();
    if manifest.layers().len() != expected_layers.len() {
        return Err(stow_types::stow_error!(
            "bundle OCI manifest layer count {} does not match config outputs {}",
            manifest.layers().len(),
            expected_layers.len()
        ));
    }

    for (file, descriptor) in expected_layers.into_iter().zip(manifest.layers().iter()) {
        let media_type = descriptor.media_type().to_string();
        let expected_media_type = file.storage_media_type();
        if media_type != expected_media_type {
            return Err(stow_types::stow_error!(
                "bundle OCI layer media type mismatch for {}: expected {}, got {}",
                file.file_name,
                expected_media_type,
                media_type
            ));
        }
        let bundle_path = bundle_file_path(&file.file_name);
        let contents = files
            .get(&bundle_path)
            .ok_or_else(|| stow_types::stow_error!("artifact bundle is missing {bundle_path}"))?;
        if descriptor.digest().to_string() != sha256_prefixed(contents) {
            return Err(stow_types::stow_error!(
                "bundle OCI layer digest mismatch for {}",
                file.file_name
            ));
        }
    }

    Ok(())
}

fn validate_output_entries_present(
    outputs: &[ArtifactBundleFile],
    native_archive: Option<&ArtifactBundleFile>,
    files: &BTreeMap<String, Vec<u8>>,
) -> stow_types::error::Result<()> {
    let mut seen_paths = BTreeSet::new();
    for file in outputs.iter().chain(native_archive) {
        let path = bundle_file_path(&file.file_name);
        if !seen_paths.insert(path.clone()) {
            return Err(stow_types::stow_error!(
                "artifact bundle config contains duplicate output path {}",
                path
            ));
        }
        let contents = files
            .get(&path)
            .ok_or_else(|| stow_types::stow_error!("artifact bundle is missing {path}"))?;
        if contents.is_empty() {
            return Err(stow_types::stow_error!(
                "artifact bundle contains empty output payload for {}",
                file.file_name
            ));
        }
    }
    Ok(())
}

pub fn bundle_file_path(file_name: &str) -> String {
    format!("files/{file_name}")
}

pub fn decode_bundle_output_bytes(
    file: &ArtifactBundleFile,
    contents: &[u8],
) -> stow_types::error::Result<Vec<u8>> {
    zstd::stream::decode_all(std::io::Cursor::new(contents)).map_err(|error| {
        stow_types::stow_error!(
            "zstd decompress bundled artifact {}: {error}",
            file.file_name
        )
    })
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::bundle::{
        ArtifactBlobConfig, ArtifactBundleFile, ArtifactBundleManifest, STOW_OCI_CONFIG_PATH,
        STOW_OCI_MANIFEST_PATH, SigstoreSignature,
    };

    use super::{
        bundle_file_path, emit_covers_request, finalize_bundle, sha256_prefixed,
        validate_output_entries_present, validate_semantic_bundle_version,
    };

    #[test]
    fn semantic_emit_accepts_superset() {
        assert!(emit_covers_request(
            &[
                "dep-info".to_owned(),
                "link".to_owned(),
                "metadata".to_owned()
            ],
            &["dep-info".to_owned(), "metadata".to_owned()],
        ));
        assert!(!emit_covers_request(
            &["dep-info".to_owned(), "metadata".to_owned()],
            &[
                "dep-info".to_owned(),
                "link".to_owned(),
                "metadata".to_owned()
            ],
        ));
    }

    #[test]
    fn semantic_version_accepts_compatible_upgrade() {
        validate_semantic_bundle_version("1.4.3", "1.4.9").unwrap();
        validate_semantic_bundle_version("0.9.1", "0.9.7").unwrap();
        validate_semantic_bundle_version("0.0.5", "0.0.5").unwrap();
    }

    #[test]
    fn semantic_version_rejects_incompatible_bundle() {
        assert!(validate_semantic_bundle_version("1.4.3", "2.0.0").is_err());
        assert!(validate_semantic_bundle_version("0.9.1", "0.10.0").is_err());
        assert!(validate_semantic_bundle_version("0.0.5", "0.0.6").is_err());
        assert!(validate_semantic_bundle_version("1.4.3", "1.4.2").is_err());
    }

    #[test]
    fn duplicate_bundle_output_paths_are_rejected() {
        let outputs = vec![
            ArtifactBundleFile {
                file_name: "libslug-abc.rlib".to_owned(),
                media_type: stow_types::bundle::STOW_RLIB_MEDIA_TYPE.to_owned(),
                sha256: "deadbeef".to_owned(),
            },
            ArtifactBundleFile {
                file_name: "libslug-abc.rlib".to_owned(),
                media_type: stow_types::bundle::STOW_RLIB_MEDIA_TYPE.to_owned(),
                sha256: "cafebabe".to_owned(),
            },
        ];
        let mut files = BTreeMap::new();
        files.insert("files/libslug-abc.rlib".to_owned(), vec![1, 2, 3]);

        let error = validate_output_entries_present(&outputs, None, &files)
            .expect_err("duplicate path must fail");
        assert!(
            error
                .to_string()
                .contains("artifact bundle config contains duplicate output path")
        );
    }

    #[test]
    fn bundle_with_exactly_declared_entries_is_accepted() {
        let (manifest, files) = declared_bundle_parts();
        finalize_bundle(Some(manifest), files).expect("declared bundle must pass");
    }

    #[test]
    fn traversing_output_file_name_is_rejected() {
        let (mut manifest, mut files) = declared_bundle_parts();
        let declared = bundle_file_path(&manifest.config.outputs[0].file_name);
        let bytes = files.remove(&declared).expect("declared output present");
        manifest.config.outputs[0].file_name = "../escape.rlib".to_owned();
        files.insert(bundle_file_path("../escape.rlib"), bytes);
        let error = finalize_bundle(Some(manifest), files).expect_err("traversal must fail");
        assert!(
            error.to_string().contains("is not a single path component"),
            "{error}"
        );
    }

    #[test]
    fn undeclared_bundle_entry_is_rejected() {
        let (manifest, mut files) = declared_bundle_parts();
        files.insert("files/extra.txt".to_owned(), b"canary".to_vec());
        let error = finalize_bundle(Some(manifest), files).expect_err("undeclared entry must fail");
        assert_eq!(
            error.to_string(),
            "artifact bundle contains undeclared entry files/extra.txt"
        );
    }

    #[test]
    fn aliased_bundle_entry_path_is_rejected() {
        // Tar entry paths are compared as strings: `files/./x` aliases the
        // declared `files/x` once it hits the filesystem but is not in the
        // declared set.
        let (manifest, mut files) = declared_bundle_parts();
        files.insert(
            "files/./libdemo-aabbccddeeff0011.rmeta".to_owned(),
            b"canary".to_vec(),
        );
        let error = finalize_bundle(Some(manifest), files).expect_err("aliased entry must fail");
        assert_eq!(
            error.to_string(),
            "artifact bundle contains undeclared entry files/./libdemo-aabbccddeeff0011.rmeta"
        );
    }

    #[test]
    fn sigstore_payload_paths_outside_sigstore_dir_are_rejected() {
        for payload_path in ["../payload.json", "sigstore/../x.json", "sigstore/a/b.json"] {
            let (mut manifest, mut files) = declared_bundle_parts();
            let payload = files
                .remove("sigstore/payload-0.json")
                .expect("sigstore payload entry");
            manifest.sigstore_signatures[0].payload_path = payload_path.to_owned();
            files.insert(payload_path.to_owned(), payload);
            let error = finalize_bundle(Some(manifest), files)
                .expect_err("payload path outside sigstore/ must fail");
            assert!(
                error.to_string().contains("sigstore payload path"),
                "payload_path {payload_path}: {error}"
            );
        }
    }

    /// A bundle whose `files` map is exactly the declared set, with OCI
    /// manifest and config digests consistent enough to pass
    /// `validate_oci_manifest`.
    fn declared_bundle_parts() -> (ArtifactBundleManifest, BTreeMap<String, Vec<u8>>) {
        let output_contents = b"demo-artifact".to_vec();
        let config = ArtifactBlobConfig {
            compile_key: "compile-key".to_owned(),
            crate_name: stow_types::identity::CrateName::parse("demo").unwrap(),
            crate_version: stow_types::identity::CrateVersion::new(
                semver::Version::parse("1.0.0").unwrap(),
            ),
            c_metadata: stow_types::identity::CMetadata::parse("aabbccddeeff0011").unwrap(),
            extra_filename: "-aabbccddeeff0011".to_owned(),
            target: stow_types::identity::TargetTriple::parse("aarch64-apple-darwin").unwrap(),
            rustc_version: stow_types::identity::WireRustcVersion::parse("1.91.1").unwrap(),
            features_json: stow_types::identity::FeaturesJson::default(),
            dependency_c_metadata_json: stow_types::identity::DependencyCMetadataJson::default(),
            dependency_compile_keys_json: "[]".to_owned(),
            profile: stow_types::platform::Profile {
                opt_level: "0".to_owned(),
                debuginfo: 0,
                debug_assertions: true,
                overflow_checks: true,
                panic: stow_types::platform::PanicStrategy::Unwind,
                strip: stow_types::platform::StripLevel::None,
            },
            emit: vec!["metadata".to_owned()],
            artifact_size: output_contents.len() as u64,
            compile_millis: 0,
            kind: ArtifactKind::Rlib,
            crate_types: vec![RustCrateType::Lib],
            outputs: vec![ArtifactBundleFile {
                file_name: "libdemo-aabbccddeeff0011.rmeta".to_owned(),
                media_type: stow_types::bundle::STOW_RMETA_MEDIA_TYPE.to_owned(),
                sha256: sha256_prefixed(&output_contents),
            }],
            native: None,
            native_archive: None,
        };
        let config_bytes = serde_json::to_vec(&config).expect("serialize bundle config");
        let oci_manifest_bytes = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": sha256_prefixed(&config_bytes),
                "size": config_bytes.len(),
            },
            "layers": [{
                "mediaType": config.outputs[0].storage_media_type(),
                "digest": sha256_prefixed(&output_contents),
                "size": output_contents.len(),
            }],
        }))
        .expect("serialize OCI manifest");
        let manifest = ArtifactBundleManifest {
            oci_reference: "ghcr.io/water-rs/stow-cache:demo.test".to_owned(),
            oci_digest: sha256_prefixed(&oci_manifest_bytes),
            config,
            sigstore_signatures: vec![SigstoreSignature {
                payload_path: "sigstore/payload-0.json".to_owned(),
                signature: "MEUCIQDUMMY".to_owned(),
                certificate_pem: "mock-local".to_owned(),
                rekor_bundle_json: None,
            }],
        };
        let files = BTreeMap::from([
            (STOW_OCI_MANIFEST_PATH.to_owned(), oci_manifest_bytes),
            (STOW_OCI_CONFIG_PATH.to_owned(), config_bytes),
            (
                bundle_file_path("libdemo-aabbccddeeff0011.rmeta"),
                output_contents,
            ),
            ("sigstore/payload-0.json".to_owned(), b"{}".to_vec()),
        ]);
        (manifest, files)
    }
}
