use std::collections::BTreeMap;
use std::io::Cursor;

use eyre::Context;
use futures_lite::future;
use oci_spec::image::ImageManifest;
use sha2::{Digest, Sha256};
use stow_types::bundle::{
    ArtifactBlobConfig, ArtifactBundleFile, ArtifactBundleManifest, STOW_BUNDLE_MANIFEST_PATH,
    STOW_OCI_CONFIG_PATH, STOW_OCI_MANIFEST_PATH,
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
pub struct ArtifactBundle {
    pub manifest: ArtifactBundleManifest,
    pub files: BTreeMap<String, Vec<u8>>,
}

pub async fn try_download(
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
    let mut client = zenwave::client();

    with_timeout(
        config.request_timeout,
        async { client.method(zenwave::Method::HEAD, &url).await },
    )
    .await?;

    let bytes = with_timeout(config.request_timeout, client.get(&url).bytes()).await?;
    parse_bundle(bytes.to_vec()).await.map_err(FetchError::Bundle)
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
    let mut client = zenwave::client();
    with_timeout(config.request_timeout, client.get(&url).bytes())
        .await
        .map(|bytes| bytes.to_vec())
}

async fn parse_bundle(bytes: Vec<u8>) -> eyre::Result<ArtifactBundle> {
    smol::unblock(move || parse_bundle_sync(bytes)).await
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

    let manifest = manifest.ok_or_else(|| eyre::eyre!("artifact bundle is missing manifest.json"))?;
    validate_bundle_files(&manifest, &manifest.config, &files)?;

    Ok(ArtifactBundle {
        manifest,
        files,
    })
}

fn validate_bundle_files(
    bundle_manifest: &ArtifactBundleManifest,
    config: &ArtifactBlobConfig,
    files: &BTreeMap<String, Vec<u8>>,
) -> eyre::Result<()> {
    validate_oci_manifest(bundle_manifest, files)?;
    validate_bundle_file(config.rlib.as_ref(), files)?;
    validate_bundle_file(config.rmeta.as_ref(), files)?;
    validate_bundle_file(config.proc_macro.as_ref(), files)?;
    Ok(())
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
        let file = if media_type == stow_types::bundle::STOW_RLIB_MEDIA_TYPE {
            bundle_manifest.config.rlib.as_ref()
        } else if media_type == stow_types::bundle::STOW_RMETA_MEDIA_TYPE {
            bundle_manifest.config.rmeta.as_ref()
        } else if media_type == stow_types::bundle::STOW_PROC_MACRO_MEDIA_TYPE {
            bundle_manifest.config.proc_macro.as_ref()
        } else {
            return Err(eyre::eyre!("unexpected OCI layer media type {media_type}"));
        }
        .ok_or_else(|| eyre::eyre!("bundle config is missing layer metadata for {media_type}"))?;
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

fn validate_bundle_file(
    file: Option<&ArtifactBundleFile>,
    files: &BTreeMap<String, Vec<u8>>,
) -> eyre::Result<()> {
    let Some(file) = file else {
        return Ok(());
    };
    let path = bundle_file_path(&file.file_name);
    let contents = files
        .get(&path)
        .ok_or_else(|| eyre::eyre!("artifact bundle is missing {path}"))?;
    let digest = hex::encode(Sha256::digest(contents));
    if digest != file.sha256 {
        return Err(eyre::eyre!(
            "artifact bundle checksum mismatch for {}",
            file.file_name
        ));
    }
    Ok(())
}

pub fn bundle_file_path(file_name: &str) -> String {
    format!("files/{file_name}")
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

async fn with_timeout<T>(
    timeout: std::time::Duration,
    request: impl std::future::Future<Output = Result<T, zenwave::Error>>,
) -> Result<T, FetchError> {
    future::or(
        async move { request.await.map_err(classify_transport_error) },
        async move {
            smol::Timer::after(timeout).await;
            Err(FetchError::Timeout)
        },
    )
    .await
}

fn classify_transport_error(error: zenwave::Error) -> FetchError {
    match error {
        zenwave::Error::Http { status, .. } if status.as_u16() == 404 => {
            FetchError::NotFound
        }
        zenwave::Error::Timeout => FetchError::Timeout,
        zenwave::Error::Http { status, .. } => FetchError::Http(status.as_u16()),
        other if other.is_network_error() => FetchError::Network(other.to_string()),
        other => FetchError::Other(other.to_string()),
    }
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
