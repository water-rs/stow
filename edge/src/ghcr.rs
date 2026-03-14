use std::io::Cursor;

use oci_spec::image::ImageManifest;
use stow_types::bundle::{
    ArtifactBlobConfig, ArtifactBundleManifest, STOW_BUNDLE_MANIFEST_PATH,
};
use tar::{Builder, Header};
use zenwave::Client;

/// Base URL for the GHCR OCI registry.
const GHCR_BASE: &str = "https://ghcr.io/v2/stow-rs/cache";

pub async fn fetch_bundle(name: &str, reference: &str, token: &str) -> Result<Vec<u8>, FetchError> {
    let manifest = fetch_manifest(name, reference, token).await?;
    let config_digest = manifest.config().digest().to_string();
    let config = fetch_config(name, &config_digest, token).await?;
    build_bundle(name, &manifest, &config, token).await
}

/// Resolve the GHCR blob redirect URL for client-side fallback.
pub async fn resolve_blob_redirect_url(
    name: &str,
    digest: &str,
    token: &str,
) -> Result<String, FetchError> {
    let url = format!("{GHCR_BASE}/{name}/blobs/{digest}");
    let mut client = zenwave::client();
    let response = client
        .method(zenwave::Method::HEAD, &url)
        .bearer_auth(token)
        .await
        .map_err(classify_fetch_error)?;

    let Some(location) = response.headers().get("location") else {
        return Err(FetchError::NoRedirect);
    };

    location
        .to_str()
        .map(str::to_owned)
        .map_err(|_| FetchError::NoRedirect)
}

async fn build_bundle(
    name: &str,
    manifest: &ImageManifest,
    config: &ArtifactBlobConfig,
    token: &str,
) -> Result<Vec<u8>, FetchError> {
    let mut tar = Builder::new(Vec::new());
    append_bytes(
        &mut tar,
        STOW_BUNDLE_MANIFEST_PATH,
        &serde_json::to_vec(&ArtifactBundleManifest {
            config: config.clone(),
        })
        .map_err(FetchError::SerializeBundle)?,
    )?;

    if let Some(file) = &config.rlib {
        let digest = digest_for_media_type(manifest, &file.media_type)?;
        let blob = fetch_blob(name, &digest, token).await?;
        append_bytes(&mut tar, &bundle_entry_path(&file.file_name), &blob)?;
    }
    if let Some(file) = &config.rmeta {
        let digest = digest_for_media_type(manifest, &file.media_type)?;
        let blob = fetch_blob(name, &digest, token).await?;
        append_bytes(&mut tar, &bundle_entry_path(&file.file_name), &blob)?;
    }
    if let Some(file) = &config.proc_macro {
        let digest = digest_for_media_type(manifest, &file.media_type)?;
        let blob = fetch_blob(name, &digest, token).await?;
        append_bytes(&mut tar, &bundle_entry_path(&file.file_name), &blob)?;
    }

    tar.into_inner().map_err(FetchError::BuildBundle)
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

async fn fetch_manifest(name: &str, reference: &str, token: &str) -> Result<ImageManifest, FetchError> {
    let url = format!("{GHCR_BASE}/{name}/manifests/{reference}");
    let mut client = zenwave::client();
    let bytes = client
        .get(&url)
        .header("Accept", "application/vnd.oci.image.manifest.v1+json")
        .bearer_auth(token)
        .bytes()
        .await
        .map_err(classify_fetch_error)?;
    serde_json::from_slice(&bytes).map_err(FetchError::InvalidManifest)
}

async fn fetch_config(name: &str, digest: &str, token: &str) -> Result<ArtifactBlobConfig, FetchError> {
    let bytes = fetch_blob(name, digest, token).await?;
    serde_json::from_slice(&bytes).map_err(FetchError::InvalidConfig)
}

async fn fetch_blob(name: &str, digest: &str, token: &str) -> Result<Vec<u8>, FetchError> {
    let url = format!("{GHCR_BASE}/{name}/blobs/{digest}");
    let mut client = zenwave::client();
    let bytes = client
        .get(&url)
        .bearer_auth(token)
        .bytes()
        .await
        .map_err(classify_fetch_error)?;
    Ok(bytes.to_vec())
}

fn classify_fetch_error(error: zenwave::Error) -> FetchError {
    match &error {
        zenwave::Error::Http { status, .. } if status.as_u16() == 429 || status.is_server_error() => {
            FetchError::Unavailable
        }
        zenwave::Error::Http { status, .. } if status.is_client_error() => FetchError::NotFound,
        _ if error.is_request_error() => FetchError::InvalidUrl,
        _ => FetchError::Network(error),
    }
}

#[derive(Debug)]
pub enum FetchError {
    InvalidUrl,
    InvalidManifest(serde_json::Error),
    InvalidConfig(serde_json::Error),
    SerializeBundle(serde_json::Error),
    BuildBundle(std::io::Error),
    MissingLayer(String),
    Network(zenwave::Error),
    Unavailable,
    NotFound,
    NoRedirect,
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::InvalidUrl => write!(f, "invalid GHCR URL"),
            FetchError::InvalidManifest(error) => write!(f, "invalid OCI manifest: {error}"),
            FetchError::InvalidConfig(error) => write!(f, "invalid OCI config: {error}"),
            FetchError::SerializeBundle(error) => write!(f, "serialize bundle manifest: {error}"),
            FetchError::BuildBundle(error) => write!(f, "build bundle tar: {error}"),
            FetchError::MissingLayer(media_type) => {
                write!(f, "OCI manifest missing layer with media type {media_type}")
            }
            FetchError::Network(error) => write!(f, "GHCR network error: {error}"),
            FetchError::Unavailable => write!(f, "GHCR unavailable (rate limit or 5xx)"),
            FetchError::NotFound => write!(f, "artifact not found in GHCR"),
            FetchError::NoRedirect => write!(f, "GHCR did not return redirect URL"),
        }
    }
}
