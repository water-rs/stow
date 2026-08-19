use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::time::Instant;

use async_tar::Archive as AsyncArchive;
use futures_util::io::AsyncReadExt as _;
use futures_util::{StreamExt, TryStreamExt};
use oci_spec::image::ImageManifest;
use semver::Version;
use sha2::{Digest, Sha256};
use stow_types::api::{BatchArtifactRequest, BatchArtifactRequestEntry, SemanticArtifactRequest};
use stow_types::bundle::{
    ArtifactBatchManifest, ArtifactBundleFile, ArtifactBundleManifest, STOW_BATCH_BUNDLES_DIR,
    STOW_BATCH_MANIFEST_PATH, STOW_BUNDLE_MANIFEST_PATH, STOW_OCI_CONFIG_PATH,
    STOW_OCI_MANIFEST_PATH,
};
use stow_types::error::Context;
use stow_types::versioning::is_semver_compatible_upgrade;
use tar::Archive;
use zenwave::Client;

use crate::config::StowConfig;

/// Decode a stored canonical features-json string into the structured wire type.
fn parse_features_json_field(
    raw: &str,
) -> stow_types::error::Result<stow_types::identity::FeaturesJson> {
    let parsed: Vec<String> = serde_json::from_str(raw)
        .map_err(|error| stow_types::stow_error!("parse features_json `{raw}`: {error}"))?;
    stow_types::identity::FeaturesJson::from_sorted(parsed)
        .map_err(|error| stow_types::stow_error!("invalid features_json: {error}"))
}

/// Decode a stored canonical dependency-c-metadata-json string into the
/// structured wire type.
fn parse_dependency_c_metadata_json_field(
    raw: &str,
) -> stow_types::error::Result<stow_types::identity::DependencyCMetadataJson> {
    let parsed: Vec<stow_types::identity::DependencyCMetadataIdentity> =
        serde_json::from_str(raw).map_err(|error| {
            stow_types::stow_error!("parse dependency_c_metadata_json `{raw}`: {error}")
        })?;
    stow_types::identity::DependencyCMetadataJson::from_sorted(parsed)
        .map_err(|error| stow_types::stow_error!("invalid dependency_c_metadata_json: {error}"))
}

#[derive(Debug, Clone)]
pub struct FetchRequest<'a> {
    pub target: &'a str,
    pub rustc_version: &'a str,
    pub c_metadata: &'a str,
    pub crate_name: &'a str,
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

#[derive(Debug, Clone)]
pub struct BatchDownloadedArtifact {
    pub crate_name: String,
    pub c_metadata: String,
    pub bundle_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BatchDownloadResult {
    pub bundles: Vec<BatchDownloadedArtifact>,
    pub missing: Vec<BatchArtifactRequestEntry>,
    pub request_ms: u128,
    pub unpack_ms: u128,
}

pub async fn download_bundle(
    config: &StowConfig,
    request: &FetchRequest<'_>,
) -> Result<ArtifactBundle, FetchError> {
    let url = artifact_url(
        &config.edge_url,
        request.target,
        request.rustc_version,
        request.c_metadata,
        request.crate_name,
    );
    let mut client = zenwave::client().timeout(config.request_timeout);
    let response = client
        .get(&url)
        .map_err(classify_transport_error)?
        .await
        .map_err(|error| classify_client_error(&error))?;
    parse_bundle_response(response)
        .await
        .map_err(FetchError::Bundle)
}

pub async fn download_semantic_bundle(
    config: &StowConfig,
    request: &SemanticFetchRequest,
) -> Result<ArtifactBundle, FetchError> {
    let url = format!(
        "{}/api/v1/artifacts/semantic",
        config.edge_url.trim_end_matches('/')
    );
    let body = SemanticArtifactRequest {
        crate_name: stow_types::identity::CrateName::parse(request.crate_name.as_str())
            .map_err(|error| FetchError::Other(format!("invalid crate_name: {error}")))?,
        version: stow_types::identity::CrateVersion::new(
            semver::Version::parse(&request.version)
                .map_err(|error| FetchError::Other(format!("invalid version: {error}")))?,
        ),
        features_json: parse_features_json_field(&request.features_json)
            .map_err(FetchError::Bundle)?,
        dependency_c_metadata_json: parse_dependency_c_metadata_json_field(
            &request.dependency_c_metadata_json,
        )
        .map_err(FetchError::Bundle)?,
        target: stow_types::identity::TargetTriple::parse(request.target.as_str())
            .map_err(|error| FetchError::Other(format!("invalid target: {error}")))?,
        rustc_version: stow_types::identity::WireRustcVersion::parse(request.rustc_version.as_str())
            .map_err(|error| FetchError::Other(format!("invalid rustc_version: {error}")))?,
        profile: request.profile.clone(),
        emit: request.emit.clone(),
        kind: request.kind.clone(),
        crate_types: request.crate_types.clone(),
    };
    let mut client = zenwave::client().timeout(config.request_timeout);
    let response = client
        .post(&url)
        .map_err(classify_transport_error)?
        .json_body(&body)
        .map_err(classify_transport_error)?
        .await
        .map_err(|error| classify_client_error(&error))?;
    parse_bundle_response(response)
        .await
        .map_err(FetchError::Bundle)
}

pub async fn download_batch_bundles(
    config: &StowConfig,
    target: &str,
    rustc_version: &str,
    requests: &[BatchArtifactRequestEntry],
) -> Result<BatchDownloadResult, FetchError> {
    if requests.is_empty() {
        return Ok(BatchDownloadResult {
            bundles: Vec::new(),
            missing: Vec::new(),
            request_ms: 0,
            unpack_ms: 0,
        });
    }

    let url = format!(
        "{}/api/v1/artifacts/batch",
        config.edge_url.trim_end_matches('/')
    );
    let body = BatchArtifactRequest {
        target: stow_types::identity::TargetTriple::parse(target)
            .map_err(|error| FetchError::Other(format!("invalid target: {error}")))?,
        rustc_version: stow_types::identity::WireRustcVersion::parse(rustc_version)
            .map_err(|error| FetchError::Other(format!("invalid rustc_version: {error}")))?,
        entries: requests.to_vec(),
    };
    let mut client = zenwave::client().timeout(config.request_timeout);
    let request = client
        .post(&url)
        .map_err(classify_transport_error)?
        .json_body(&body)
        .map_err(classify_transport_error)?;
    let request_started = Instant::now();
    let response = request.await.map_err(|error| classify_client_error(&error))?;
    let request_ms = request_started.elapsed().as_millis();
    let unpack_started = Instant::now();
    let mut result = parse_batch_bundle_response(response, target, rustc_version, requests)
        .await
        .map_err(FetchError::Bundle)?;
    result.request_ms = request_ms;
    result.unpack_ms = unpack_started.elapsed().as_millis();
    Ok(result)
}

pub async fn download_raw_bundle(
    config: &StowConfig,
    request: &FetchRequest<'_>,
) -> Result<Vec<u8>, FetchError> {
    let url = artifact_url(
        &config.edge_url,
        request.target,
        request.rustc_version,
        request.c_metadata,
        request.crate_name,
    );
    let mut client = zenwave::client().timeout(config.request_timeout);
    let response = client
        .get(&url)
        .map_err(classify_transport_error)?
        .await
        .map_err(|error| classify_client_error(&error))?;
    let bytes = response.into_body().into_bytes().await.map_err(|error| {
        FetchError::Other(format!("read artifact response body failed: {error}"))
    })?;
    Ok(bytes.to_vec())
}

async fn parse_bundle(bytes: Vec<u8>) -> stow_types::error::Result<ArtifactBundle> {
    // CPU-bound tar walk over owned bytes: keep it off the async workers so
    // concurrent prefetch futures are not stalled behind unpacking.
    tokio::task::spawn_blocking(move || parse_bundle_sync(bytes))
        .await
        .wrap_err("join bundle parse task")?
}

async fn parse_bundle_response(
    response: zenwave::Response,
) -> stow_types::error::Result<ArtifactBundle> {
    let stream = response.into_body().map(|chunk| {
        chunk.map_err(|error| std::io::Error::other(format!("read artifact body chunk: {error}")))
    });
    let reader = stream.into_async_read();
    parse_bundle_stream(reader).await
}

async fn parse_batch_bundle_response(
    response: zenwave::Response,
    target: &str,
    rustc_version: &str,
    requests: &[BatchArtifactRequestEntry],
) -> stow_types::error::Result<BatchDownloadResult> {
    let stream = response.into_body().map(|chunk| {
        chunk.map_err(|error| {
            std::io::Error::other(format!("read batch artifact body chunk: {error}"))
        })
    });
    let reader = stream.into_async_read();
    parse_batch_bundle_stream(reader, target, rustc_version, requests).await
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
            "downloaded semantic bundle profile mismatch"
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

async fn parse_batch_bundle_stream<R>(
    reader: R,
    target: &str,
    rustc_version: &str,
    requests: &[BatchArtifactRequestEntry],
) -> stow_types::error::Result<BatchDownloadResult>
where
    R: futures_util::io::AsyncRead + Send + Unpin + 'static,
{
    let archive = AsyncArchive::new(reader);
    let mut entries = archive
        .entries()
        .wrap_err("read batch artifact archive entries")?;
    let mut manifest: Option<ArtifactBatchManifest> = None;
    let mut bundle_files = BTreeMap::<String, Vec<u8>>::new();

    while let Some(entry) = entries.next().await {
        let mut entry = entry.wrap_err("read batch artifact archive entry")?;
        let path = entry
            .path()
            .wrap_err("read batch artifact archive entry path")?
            .to_string_lossy()
            .to_string();
        let mut contents = Vec::new();
        entry
            .read_to_end(&mut contents)
            .await
            .wrap_err_with(|| format!("read batch artifact archive entry {path}"))?;

        if path == STOW_BATCH_MANIFEST_PATH {
            manifest = Some(
                serde_json::from_slice(&contents).wrap_err("parse batch artifact manifest json")?,
            );
            continue;
        }
        if !path.starts_with(&format!("{STOW_BATCH_BUNDLES_DIR}/")) {
            return Err(stow_types::stow_error!(
                "batch artifact archive contains unexpected entry {}",
                path
            ));
        }
        if bundle_files.insert(path.clone(), contents).is_some() {
            return Err(stow_types::stow_error!(
                "batch artifact archive contains duplicate entry {}",
                path
            ));
        }
    }

    finalize_batch_download_result(manifest, bundle_files, target, rustc_version, requests)
}

async fn parse_bundle_stream<R>(reader: R) -> stow_types::error::Result<ArtifactBundle>
where
    R: futures_util::io::AsyncRead + Send + Unpin + 'static,
{
    let archive = AsyncArchive::new(reader);
    let mut entries = archive.entries().wrap_err("read artifact bundle entries")?;
    let mut manifest: Option<ArtifactBundleManifest> = None;
    let mut files = BTreeMap::new();

    while let Some(entry) = entries.next().await {
        let mut entry = entry.wrap_err("read artifact bundle entry")?;
        let path = entry
            .path()
            .wrap_err("read artifact bundle entry path")?
            .to_string_lossy()
            .to_string();
        let mut contents = Vec::new();
        entry
            .read_to_end(&mut contents)
            .await
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
    validate_oci_manifest(&manifest, &files)?;
    validate_output_entries_present(&manifest.config.outputs, &files)?;
    Ok(ArtifactBundle { manifest, files })
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

fn finalize_batch_download_result(
    manifest: Option<ArtifactBatchManifest>,
    mut bundle_files: BTreeMap<String, Vec<u8>>,
    target: &str,
    rustc_version: &str,
    requests: &[BatchArtifactRequestEntry],
) -> stow_types::error::Result<BatchDownloadResult> {
    let manifest = manifest
        .ok_or_else(|| stow_types::stow_error!("batch artifact archive is missing manifest"))?;
    if manifest.target != target {
        return Err(stow_types::stow_error!(
            "batch artifact manifest target mismatch: expected {}, got {}",
            target,
            manifest.target
        ));
    }
    if manifest.rustc_version != rustc_version {
        return Err(stow_types::stow_error!(
            "batch artifact manifest rustc mismatch: expected {}, got {}",
            rustc_version,
            manifest.rustc_version
        ));
    }
    if manifest.entries.len() != requests.len() {
        return Err(stow_types::stow_error!(
            "batch artifact manifest entry count mismatch: expected {}, got {}",
            requests.len(),
            manifest.entries.len()
        ));
    }

    let requested = requests
        .iter()
        .map(|entry| {
            (
                entry.crate_name.as_str().to_owned(),
                entry.c_metadata.as_str().to_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::<(String, String)>::new();
    let mut bundles = Vec::new();
    let mut missing = Vec::new();
    for entry in manifest.entries {
        let key = (
            entry.crate_name.as_str().to_owned(),
            entry.c_metadata.as_str().to_owned(),
        );
        if !requested.contains(&key) {
            return Err(stow_types::stow_error!(
                "batch artifact manifest returned unexpected entry {} {}",
                entry.crate_name,
                entry.c_metadata
            ));
        }
        if !seen.insert(key.clone()) {
            return Err(stow_types::stow_error!(
                "batch artifact manifest returned duplicate entry {} {}",
                entry.crate_name,
                entry.c_metadata
            ));
        }
        match entry.bundle_path {
            Some(bundle_path) => {
                let expected_path = batch_bundle_path(entry.c_metadata.as_str());
                if bundle_path != expected_path {
                    return Err(stow_types::stow_error!(
                        "batch artifact manifest path mismatch for {}: expected {}, got {}",
                        entry.c_metadata,
                        expected_path,
                        bundle_path
                    ));
                }
                let bundle_bytes = bundle_files.remove(&bundle_path).ok_or_else(|| {
                    stow_types::stow_error!(
                        "batch artifact archive is missing bundle file {}",
                        bundle_path
                    )
                })?;
                bundles.push(BatchDownloadedArtifact {
                    crate_name: entry.crate_name.into_inner(),
                    c_metadata: entry.c_metadata.into_inner(),
                    bundle_bytes,
                });
            }
            None => missing.push(BatchArtifactRequestEntry {
                crate_name: entry.crate_name,
                c_metadata: entry.c_metadata,
            }),
        }
    }

    if !bundle_files.is_empty() {
        return Err(stow_types::stow_error!(
            "batch artifact archive contains {} unreferenced bundle files",
            bundle_files.len()
        ));
    }

    Ok(BatchDownloadResult {
        bundles,
        missing,
        request_ms: 0,
        unpack_ms: 0,
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

    if manifest.layers().len() != bundle_manifest.config.outputs.len() {
        return Err(stow_types::stow_error!(
            "bundle OCI manifest layer count {} does not match config outputs {}",
            manifest.layers().len(),
            bundle_manifest.config.outputs.len()
        ));
    }

    for (file, descriptor) in bundle_manifest
        .config
        .outputs
        .iter()
        .zip(manifest.layers().iter())
    {
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
    files: &BTreeMap<String, Vec<u8>>,
) -> stow_types::error::Result<()> {
    let mut seen_paths = BTreeSet::new();
    for file in outputs {
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

fn batch_bundle_path(c_metadata: &str) -> String {
    format!("{STOW_BATCH_BUNDLES_DIR}/{c_metadata}.tar")
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

fn artifact_url(
    edge_url: &str,
    target: &str,
    rustc_version: &str,
    c_metadata: &str,
    crate_name: &str,
) -> String {
    format!(
        "{}/api/v1/artifacts/{}/{}/{}?crate={}",
        edge_url.trim_end_matches('/'),
        target,
        rustc_version,
        c_metadata,
        crate_name
    )
}

fn classify_transport_error(error: zenwave::Error) -> FetchError {
    match error {
        zenwave::Error::Http { status, .. } if status.as_u16() == 404 => FetchError::NotFound,
        zenwave::Error::Timeout => FetchError::Timeout,
        zenwave::Error::Http { status, .. } => FetchError::Http(status.as_u16()),
        other if other.is_network_error() => FetchError::Network(other.to_string()),
        other => FetchError::Other(other.to_string()),
    }
}

fn classify_client_error(error: &impl zenwave::HttpError) -> FetchError {
    let status = error.status();
    if status.as_u16() == 404 {
        return FetchError::NotFound;
    }
    if status == zenwave::StatusCode::REQUEST_TIMEOUT
        || status == zenwave::StatusCode::GATEWAY_TIMEOUT
    {
        return FetchError::Timeout;
    }
    FetchError::Http(status.as_u16())
}

#[derive(Debug)]
pub enum FetchError {
    NotFound,
    Timeout,
    Http(u16),
    Network(String),
    Bundle(stow_types::error::Error),
    Other(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "artifact not found"),
            Self::Timeout => write!(f, "artifact fetch timed out"),
            Self::Http(status) => write!(f, "artifact fetch returned HTTP {status}"),
            Self::Network(message) => write!(f, "artifact fetch network error: {message}"),
            Self::Bundle(error) => write!(f, "artifact bundle parse failed: {error}"),
            Self::Other(message) => write!(f, "artifact fetch failed: {message}"),
        }
    }
}

impl std::error::Error for FetchError {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use stow_types::bundle::ArtifactBundleFile;

    use super::{
        emit_covers_request, validate_output_entries_present, validate_semantic_bundle_version,
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

        let error = validate_output_entries_present(&outputs, &files)
            .expect_err("duplicate path must fail");
        assert!(
            error
                .to_string()
                .contains("artifact bundle config contains duplicate output path")
        );
    }
}
