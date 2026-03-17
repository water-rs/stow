use std::io::Cursor;

use oci_spec::image::ImageManifest;
use skyzen_cloudflare::{CfFetch, worker};
use stow_types::bundle::{
    ArtifactBlobConfig, ArtifactBundleManifest, STOW_BUNDLE_MANIFEST_PATH, STOW_OCI_CONFIG_PATH,
    STOW_OCI_MANIFEST_PATH, STOW_SIGSTORE_PAYLOAD_DIR, SigstoreSignature,
};
use tar::{Builder, Header};

/// Default base URL for the OCI registry used by edge artifact fetches.
const DEFAULT_REGISTRY_BASE: &str = "https://ghcr.io/v2/stow-rs/cache";
const SIGSTORE_OCI_MEDIA_TYPE: &str = "application/vnd.dev.cosign.simplesigning.v1+json";
const SIGSTORE_SIGNATURE_ANNOTATION: &str = "dev.cosignproject.cosign/signature";
const SIGSTORE_BUNDLE_ANNOTATION: &str = "dev.sigstore.cosign/bundle";
const SIGSTORE_CERT_ANNOTATION: &str = "dev.sigstore.cosign/certificate";

pub const fn default_base_url() -> &'static str {
    DEFAULT_REGISTRY_BASE
}

pub async fn fetch_bundle(
    base_url: &str,
    oci_reference: &str,
    name: &str,
    reference: &str,
    token: &str,
) -> Result<Vec<u8>, FetchError> {
    let manifest_bytes = fetch_manifest_bytes(base_url, name, reference, token).await?;
    let manifest: ImageManifest =
        serde_json::from_slice(&manifest_bytes).map_err(FetchError::InvalidManifest)?;
    let config_digest = manifest.config().digest().to_string();
    let config_bytes = fetch_blob(base_url, name, &config_digest, token).await?;
    let config: ArtifactBlobConfig =
        serde_json::from_slice(&config_bytes).map_err(FetchError::InvalidConfig)?;
    let signature_materials = fetch_signature_materials(base_url, name, reference, token).await?;
    build_bundle(
        base_url,
        oci_reference,
        reference,
        name,
        &manifest,
        &manifest_bytes,
        &config,
        &config_bytes,
        &signature_materials,
        token,
    )
    .await
}

/// Resolve the GHCR blob redirect URL for client-side fallback.
pub async fn resolve_blob_redirect_url(
    base_url: &str,
    name: &str,
    digest: &str,
    token: &str,
) -> Result<String, FetchError> {
    let url = format!("{}/{name}/blobs/{digest}", base_url.trim_end_matches('/'));
    let response = send_request(&url, worker::Method::Head, token, None).await?;

    let Some(location) = response
        .headers()
        .get("location")
        .map_err(|error| FetchError::Network(error.to_string()))?
    else {
        return Err(FetchError::NoRedirect);
    };

    Ok(location)
}

async fn build_bundle(
    base_url: &str,
    oci_reference: &str,
    oci_digest: &str,
    name: &str,
    manifest: &ImageManifest,
    manifest_bytes: &[u8],
    config: &ArtifactBlobConfig,
    config_bytes: &[u8],
    signature_materials: &[FetchedSigstoreSignature],
    token: &str,
) -> Result<Vec<u8>, FetchError> {
    let mut tar = Builder::new(Vec::new());
    append_bytes(
        &mut tar,
        STOW_BUNDLE_MANIFEST_PATH,
        &serde_json::to_vec(&ArtifactBundleManifest {
            oci_reference: oci_reference.to_owned(),
            oci_digest: oci_digest.to_owned(),
            config: config.clone(),
            sigstore_signatures: signature_materials
                .iter()
                .map(|material| SigstoreSignature {
                    payload_path: material.payload_path.clone(),
                    signature: material.signature.clone(),
                    certificate_pem: material.certificate_pem.clone(),
                    rekor_bundle_json: material.rekor_bundle_json.clone(),
                })
                .collect(),
        })
        .map_err(FetchError::SerializeBundle)?,
    )?;
    append_bytes(&mut tar, STOW_OCI_MANIFEST_PATH, manifest_bytes)?;
    append_bytes(&mut tar, STOW_OCI_CONFIG_PATH, config_bytes)?;
    for material in signature_materials {
        append_bytes(&mut tar, &material.payload_path, &material.payload_bytes)?;
    }

    for file in &config.outputs {
        let digest = digest_for_media_type(manifest, &file.storage_media_type())?;
        let blob = fetch_blob(base_url, name, &digest, token).await?;
        append_bytes(&mut tar, &bundle_entry_path(&file.file_name), &blob)?;
    }

    tar.into_inner().map_err(FetchError::BuildBundle)
}

async fn fetch_signature_materials(
    base_url: &str,
    name: &str,
    oci_digest: &str,
    token: &str,
) -> Result<Vec<FetchedSigstoreSignature>, FetchError> {
    let signature_reference = format!("{}.sig", oci_digest.replace(':', "-"));
    let manifest_bytes = fetch_manifest_bytes(base_url, name, &signature_reference, token).await?;
    let manifest: ImageManifest =
        serde_json::from_slice(&manifest_bytes).map_err(FetchError::InvalidSignatureManifest)?;
    let mut materials = Vec::new();

    for (index, descriptor) in manifest.layers().iter().enumerate() {
        if descriptor.media_type().to_string() != SIGSTORE_OCI_MEDIA_TYPE {
            continue;
        }
        let annotations = descriptor
            .annotations()
            .as_ref()
            .ok_or(FetchError::MissingSignatureAnnotations)?;
        let signature = annotations
            .get(SIGSTORE_SIGNATURE_ANNOTATION)
            .cloned()
            .ok_or(FetchError::MissingSignatureAnnotations)?;
        let certificate_pem = annotations
            .get(SIGSTORE_CERT_ANNOTATION)
            .cloned()
            .ok_or(FetchError::MissingSignatureAnnotations)?;
        let rekor_bundle_json = annotations.get(SIGSTORE_BUNDLE_ANNOTATION).cloned();
        let payload_bytes =
            fetch_blob(base_url, name, &descriptor.digest().to_string(), token).await?;
        let payload_path = format!("{STOW_SIGSTORE_PAYLOAD_DIR}/payload-{index}.json");
        materials.push(FetchedSigstoreSignature {
            payload_path,
            payload_bytes,
            signature,
            certificate_pem,
            rekor_bundle_json,
        });
    }

    if materials.is_empty() {
        return Err(FetchError::MissingSignatureLayer(signature_reference));
    }

    Ok(materials)
}

fn append_bytes(tar: &mut Builder<Vec<u8>>, path: &str, bytes: &[u8]) -> Result<(), FetchError> {
    let mut header = Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, path, Cursor::new(bytes))
        .map_err(FetchError::BuildBundle)
}

fn digest_for_media_type(manifest: &ImageManifest, media_type: &str) -> Result<String, FetchError> {
    let descriptor = manifest
        .layers()
        .iter()
        .find(|descriptor| descriptor.media_type().to_string() == media_type)
        .ok_or_else(|| FetchError::MissingLayer(media_type.to_owned()))?;
    Ok(descriptor.digest().to_string())
}

fn bundle_entry_path(file_name: &str) -> String {
    format!("files/{file_name}")
}

async fn fetch_manifest_bytes(
    base_url: &str,
    name: &str,
    reference: &str,
    token: &str,
) -> Result<Vec<u8>, FetchError> {
    let url = format!(
        "{}/{name}/manifests/{reference}",
        base_url.trim_end_matches('/')
    );
    let request = build_request(
        &url,
        worker::Method::Get,
        token,
        Some("application/vnd.oci.image.manifest.v1+json"),
    )?;
    CfFetch::default()
        .request_bytes(&request)
        .await
        .map_err(|error| FetchError::Network(error.to_string()))
}

async fn fetch_blob(
    base_url: &str,
    name: &str,
    digest: &str,
    token: &str,
) -> Result<Vec<u8>, FetchError> {
    let url = format!("{}/{name}/blobs/{digest}", base_url.trim_end_matches('/'));
    let request = build_request(&url, worker::Method::Get, token, None)?;
    CfFetch::default()
        .request_bytes(&request)
        .await
        .map_err(|error| FetchError::Network(error.to_string()))
}

async fn send_request(
    url: &str,
    method: worker::Method,
    token: &str,
    accept: Option<&str>,
) -> Result<worker::Response, FetchError> {
    let request = build_request(url, method, token, accept)?;
    let response = CfFetch::default()
        .request(&request)
        .await
        .map_err(|error| FetchError::Network(error.to_string()))?;
    classify_status(response)
}

fn build_request(
    url: &str,
    method: worker::Method,
    token: &str,
    accept: Option<&str>,
) -> Result<worker::Request, FetchError> {
    let headers = worker::Headers::new();
    if let Some(accept) = accept {
        headers
            .set("Accept", accept)
            .map_err(|error| FetchError::InvalidRequest(error.to_string()))?;
    }
    if !token.is_empty() {
        headers
            .set("Authorization", &format!("Bearer {token}"))
            .map_err(|error| FetchError::InvalidRequest(error.to_string()))?;
    }

    let mut init = worker::RequestInit::new();
    init.with_method(method);
    init.with_headers(headers);

    worker::Request::new_with_init(url, &init)
        .map_err(|error| FetchError::InvalidRequest(error.to_string()))
}

fn classify_status(response: worker::Response) -> Result<worker::Response, FetchError> {
    let status = response.status_code();
    match status {
        200..=299 => Ok(response),
        429 | 500..=599 => Err(FetchError::Unavailable),
        400..=499 => Err(FetchError::NotFound),
        _ => Err(FetchError::UnexpectedStatus(status)),
    }
}

#[derive(Debug)]
pub enum FetchError {
    InvalidRequest(String),
    InvalidManifest(serde_json::Error),
    InvalidConfig(serde_json::Error),
    InvalidSignatureManifest(serde_json::Error),
    SerializeBundle(serde_json::Error),
    BuildBundle(std::io::Error),
    MissingLayer(String),
    MissingSignatureLayer(String),
    MissingSignatureAnnotations,
    Network(String),
    Unavailable,
    NotFound,
    NoRedirect,
    UnexpectedStatus(u16),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::InvalidRequest(error) => write!(f, "invalid GHCR request: {error}"),
            FetchError::InvalidManifest(error) => write!(f, "invalid OCI manifest: {error}"),
            FetchError::InvalidConfig(error) => write!(f, "invalid OCI config: {error}"),
            FetchError::InvalidSignatureManifest(error) => {
                write!(f, "invalid cosign signature manifest: {error}")
            }
            FetchError::SerializeBundle(error) => write!(f, "serialize bundle manifest: {error}"),
            FetchError::BuildBundle(error) => write!(f, "build bundle tar: {error}"),
            FetchError::MissingLayer(media_type) => {
                write!(f, "OCI manifest missing layer with media type {media_type}")
            }
            FetchError::MissingSignatureLayer(reference) => {
                write!(
                    f,
                    "OCI signature image has no sigstore payload layers: {reference}"
                )
            }
            FetchError::MissingSignatureAnnotations => {
                write!(
                    f,
                    "OCI signature layer is missing required cosign annotations"
                )
            }
            FetchError::Network(error) => write!(f, "GHCR network error: {error}"),
            FetchError::Unavailable => write!(f, "GHCR unavailable (rate limit or 5xx)"),
            FetchError::NotFound => write!(f, "artifact not found in GHCR"),
            FetchError::NoRedirect => write!(f, "GHCR did not return redirect URL"),
            FetchError::UnexpectedStatus(status) => {
                write!(f, "GHCR returned unexpected HTTP status {status}")
            }
        }
    }
}

#[derive(Debug, Clone)]
struct FetchedSigstoreSignature {
    payload_path: String,
    payload_bytes: Vec<u8>,
    signature: String,
    certificate_pem: String,
    rekor_bundle_json: Option<String>,
}

#[allow(dead_code)]
fn assert_ghcr_futures_are_send() {
    fn assert_send<T: Send>(_: T) {}

    assert_send(fetch_bundle("", "", "", "", ""));
    assert_send(resolve_blob_redirect_url("", "", "", ""));
}
