use std::collections::BTreeMap;
use std::io::Cursor;
use std::time::Instant;

use async_tar::Archive as AsyncArchive;
use eyre::Context;
use futures_util::io::AsyncReadExt as _;
use futures_util::{StreamExt, TryStreamExt};
use oci_spec::image::ImageManifest;
use sha2::{Digest, Sha256};
use stow_types::api::{BatchArtifactRequest, BatchArtifactRequestEntry, SemanticArtifactRequest};
use stow_types::bundle::{
    ArtifactBatchManifest, ArtifactBundleFile, ArtifactBundleManifest, STOW_BATCH_BUNDLES_DIR,
    STOW_BATCH_MANIFEST_PATH, STOW_BUNDLE_MANIFEST_PATH, STOW_OCI_CONFIG_PATH,
    STOW_OCI_MANIFEST_PATH,
};
use tar::Archive;
use zenwave::Client;

use crate::config::StowConfig;

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
    pub target: String,
    pub rustc_version: String,
    pub kind: stow_types::artifact::ArtifactKind,
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
        .map_err(classify_client_error)?;
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
        crate_name: request.crate_name.clone(),
        version: request.version.clone(),
        features_json: request.features_json.clone(),
        target: request.target.clone(),
        rustc_version: request.rustc_version.clone(),
        kind: request.kind.clone(),
    };
    let mut client = zenwave::client().timeout(config.request_timeout);
    let response = client
        .post(&url)
        .map_err(classify_transport_error)?
        .json_body(&body)
        .map_err(classify_transport_error)?
        .await
        .map_err(classify_client_error)?;
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
        target: target.to_owned(),
        rustc_version: rustc_version.to_owned(),
        entries: requests.to_vec(),
    };
    let mut client = zenwave::client().timeout(config.request_timeout);
    let request = client
        .post(&url)
        .map_err(classify_transport_error)?
        .json_body(&body)
        .map_err(classify_transport_error)?;
    let request_started = Instant::now();
    let response = request.await.map_err(classify_client_error)?;
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
        .map_err(classify_client_error)?;
    let bytes = response.into_body().into_bytes().await.map_err(|error| {
        FetchError::Other(format!("read artifact response body failed: {error}"))
    })?;
    Ok(bytes.to_vec())
}

async fn parse_bundle(bytes: Vec<u8>) -> eyre::Result<ArtifactBundle> {
    parse_bundle_sync(bytes)
}

async fn parse_bundle_response(response: zenwave::Response) -> eyre::Result<ArtifactBundle> {
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
) -> eyre::Result<BatchDownloadResult> {
    let stream = response.into_body().map(|chunk| {
        chunk.map_err(|error| {
            std::io::Error::other(format!("read batch artifact body chunk: {error}"))
        })
    });
    let reader = stream.into_async_read();
    parse_batch_bundle_stream(reader, target, rustc_version, requests).await
}

pub async fn parse_downloaded_bundle(bytes: Vec<u8>) -> eyre::Result<ArtifactBundle> {
    parse_bundle(bytes).await
}

pub fn validate_bundle_identity(
    bundle: &ArtifactBundle,
    crate_name: &str,
    c_metadata: &str,
    target: &str,
    rustc_version: &str,
) -> eyre::Result<()> {
    if bundle.manifest.config.target != target {
        return Err(eyre::eyre!(
            "downloaded bundle target mismatch: expected {}, got {}",
            target,
            bundle.manifest.config.target
        ));
    }
    if bundle.manifest.config.rustc_version != rustc_version {
        return Err(eyre::eyre!(
            "downloaded bundle rustc mismatch: expected {}, got {}",
            rustc_version,
            bundle.manifest.config.rustc_version
        ));
    }
    if bundle.manifest.config.c_metadata != c_metadata {
        return Err(eyre::eyre!(
            "downloaded bundle c_metadata mismatch: expected {}, got {}",
            c_metadata,
            bundle.manifest.config.c_metadata
        ));
    }
    if canonical_crate_name(&bundle.manifest.config.crate_name) != canonical_crate_name(crate_name)
    {
        return Err(eyre::eyre!(
            "downloaded bundle crate mismatch: expected {}, got {}",
            crate_name,
            bundle.manifest.config.crate_name
        ));
    }
    Ok(())
}

fn canonical_crate_name(name: &str) -> String {
    name.replace('-', "_")
}

fn parse_bundle_sync(bytes: Vec<u8>) -> eyre::Result<ArtifactBundle> {
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
            manifest = Some(
                serde_json::from_slice(&contents)
                    .wrap_err("parse artifact bundle manifest json")?,
            );
            continue;
        }
        files.insert(path, contents);
    }

    finalize_bundle(manifest, files)
}

async fn parse_batch_bundle_stream<R>(
    reader: R,
    target: &str,
    rustc_version: &str,
    requests: &[BatchArtifactRequestEntry],
) -> eyre::Result<BatchDownloadResult>
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
            return Err(eyre::eyre!(
                "batch artifact archive contains unexpected entry {}",
                path
            ));
        }
        if bundle_files.insert(path.clone(), contents).is_some() {
            return Err(eyre::eyre!(
                "batch artifact archive contains duplicate entry {}",
                path
            ));
        }
    }

    finalize_batch_download_result(manifest, bundle_files, target, rustc_version, requests)
}

async fn parse_bundle_stream<R>(reader: R) -> eyre::Result<ArtifactBundle>
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
            manifest = Some(
                serde_json::from_slice(&contents)
                    .wrap_err("parse artifact bundle manifest json")?,
            );
            continue;
        }
        files.insert(path, contents);
    }

    finalize_bundle(manifest, files)
}

fn finalize_bundle(
    manifest: Option<ArtifactBundleManifest>,
    files: BTreeMap<String, Vec<u8>>,
) -> eyre::Result<ArtifactBundle> {
    let manifest =
        manifest.ok_or_else(|| eyre::eyre!("artifact bundle is missing manifest.json"))?;
    validate_oci_manifest(&manifest, &files)?;
    validate_output_entries_present(&manifest.config.outputs, &files)?;
    Ok(ArtifactBundle { manifest, files })
}

fn finalize_batch_download_result(
    manifest: Option<ArtifactBatchManifest>,
    mut bundle_files: BTreeMap<String, Vec<u8>>,
    target: &str,
    rustc_version: &str,
    requests: &[BatchArtifactRequestEntry],
) -> eyre::Result<BatchDownloadResult> {
    let manifest =
        manifest.ok_or_else(|| eyre::eyre!("batch artifact archive is missing manifest"))?;
    if manifest.target != target {
        return Err(eyre::eyre!(
            "batch artifact manifest target mismatch: expected {}, got {}",
            target,
            manifest.target
        ));
    }
    if manifest.rustc_version != rustc_version {
        return Err(eyre::eyre!(
            "batch artifact manifest rustc mismatch: expected {}, got {}",
            rustc_version,
            manifest.rustc_version
        ));
    }
    if manifest.entries.len() != requests.len() {
        return Err(eyre::eyre!(
            "batch artifact manifest entry count mismatch: expected {}, got {}",
            requests.len(),
            manifest.entries.len()
        ));
    }

    let requested = requests
        .iter()
        .map(|entry| ((entry.crate_name.clone(), entry.c_metadata.clone()), ()))
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeMap::<(String, String), ()>::new();
    let mut bundles = Vec::new();
    let mut missing = Vec::new();
    for entry in manifest.entries {
        let key = (entry.crate_name.clone(), entry.c_metadata.clone());
        if !requested.contains_key(&key) {
            return Err(eyre::eyre!(
                "batch artifact manifest returned unexpected entry {} {}",
                entry.crate_name,
                entry.c_metadata
            ));
        }
        if seen.insert(key.clone(), ()).is_some() {
            return Err(eyre::eyre!(
                "batch artifact manifest returned duplicate entry {} {}",
                entry.crate_name,
                entry.c_metadata
            ));
        }
        match entry.bundle_path {
            Some(bundle_path) => {
                let expected_path = batch_bundle_path(&entry.c_metadata);
                if bundle_path != expected_path {
                    return Err(eyre::eyre!(
                        "batch artifact manifest path mismatch for {}: expected {}, got {}",
                        entry.c_metadata,
                        expected_path,
                        bundle_path
                    ));
                }
                let bundle_bytes = bundle_files.remove(&bundle_path).ok_or_else(|| {
                    eyre::eyre!(
                        "batch artifact archive is missing bundle file {}",
                        bundle_path
                    )
                })?;
                bundles.push(BatchDownloadedArtifact {
                    crate_name: entry.crate_name,
                    c_metadata: entry.c_metadata,
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
        return Err(eyre::eyre!(
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
) -> eyre::Result<()> {
    let manifest_bytes = files
        .get(STOW_OCI_MANIFEST_PATH)
        .ok_or_else(|| eyre::eyre!("artifact bundle is missing {STOW_OCI_MANIFEST_PATH}"))?;
    let config_bytes = files
        .get(STOW_OCI_CONFIG_PATH)
        .ok_or_else(|| eyre::eyre!("artifact bundle is missing {STOW_OCI_CONFIG_PATH}"))?;
    let manifest_digest = sha256_prefixed(manifest_bytes);
    if manifest_digest != bundle_manifest.oci_digest {
        return Err(eyre::eyre!(
            "bundle OCI manifest digest mismatch: expected {}, got {}",
            bundle_manifest.oci_digest,
            manifest_digest
        ));
    }

    let manifest: ImageManifest =
        serde_json::from_slice(manifest_bytes).wrap_err("parse OCI manifest json")?;
    if manifest.config().digest().to_string() != sha256_prefixed(config_bytes) {
        return Err(eyre::eyre!("bundle OCI config digest mismatch"));
    }

    for descriptor in manifest.layers() {
        let media_type = descriptor.media_type().to_string();
        let file = bundle_manifest
            .config
            .outputs
            .iter()
            .find(|file| file.storage_media_type() == media_type)
            .ok_or_else(|| {
                eyre::eyre!("bundle config is missing layer metadata for {media_type}")
            })?;
        let bundle_path = bundle_file_path(&file.file_name);
        let contents = files
            .get(&bundle_path)
            .ok_or_else(|| eyre::eyre!("artifact bundle is missing {bundle_path}"))?;
        if descriptor.digest().to_string() != sha256_prefixed(contents) {
            return Err(eyre::eyre!(
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
) -> eyre::Result<()> {
    for file in outputs {
        let path = bundle_file_path(&file.file_name);
        let contents = files
            .get(&path)
            .ok_or_else(|| eyre::eyre!("artifact bundle is missing {path}"))?;
        if contents.is_empty() {
            return Err(eyre::eyre!(
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
) -> eyre::Result<Vec<u8>> {
    zstd::stream::decode_all(std::io::Cursor::new(contents)).map_err(|error| {
        eyre::eyre!(
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

fn classify_client_error(error: impl zenwave::HttpError) -> FetchError {
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
    Bundle(eyre::Report),
    Other(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::NotFound => write!(f, "artifact not found"),
            FetchError::Timeout => write!(f, "artifact fetch timed out"),
            FetchError::Http(status) => write!(f, "artifact fetch returned HTTP {status}"),
            FetchError::Network(message) => write!(f, "artifact fetch network error: {message}"),
            FetchError::Bundle(error) => write!(f, "artifact bundle parse failed: {error}"),
            FetchError::Other(message) => write!(f, "artifact fetch failed: {message}"),
        }
    }
}

impl std::error::Error for FetchError {}
