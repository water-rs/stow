/// Base URL for the GHCR OCI registry.
const GHCR_BASE: &str = "https://ghcr.io/v2/stow-rs/cache";

/// Fetch an OCI artifact blob from GHCR.
///
/// Returns the raw bytes of the artifact. Uses zenwave HTTP client.
pub async fn fetch_artifact_blob(oci_digest: &str, token: &str) -> Result<Vec<u8>, FetchError> {
    // OCI digest is in format "sha256:abc123..."
    // The name is embedded in the oci_reference but we extract it from the digest
    let url = format!("{GHCR_BASE}/blobs/{oci_digest}");

    let resp = zenwave::get(&url)
        .await
        .map_err(|_| FetchError::InvalidUrl)?
        .header("Authorization", &format!("Bearer {token}"))
        .map_err(|_| FetchError::InvalidUrl)?
        .send()
        .await
        .map_err(FetchError::Network)?;

    if resp.status().is_success() {
        let bytes = resp.into_body().into_bytes().await.map_err(|e| {
            FetchError::Network(zenwave::Error::Transport(e.to_string().into()))
        })?;
        Ok(bytes.to_vec())
    } else if resp.status().as_u16() == 429 || resp.status().is_server_error() {
        Err(FetchError::Unavailable)
    } else {
        Err(FetchError::NotFound)
    }
}

/// Fetch an OCI manifest from GHCR by reference (tag or digest).
pub async fn fetch_manifest(name: &str, reference: &str, token: &str) -> Result<Vec<u8>, FetchError> {
    let url = format!("{GHCR_BASE}/{name}/manifests/{reference}");

    let resp = zenwave::get(&url)
        .await
        .map_err(|_| FetchError::InvalidUrl)?
        .header("Accept", "application/vnd.oci.image.manifest.v1+json")
        .map_err(|_| FetchError::InvalidUrl)?
        .header("Authorization", &format!("Bearer {token}"))
        .map_err(|_| FetchError::InvalidUrl)?
        .send()
        .await
        .map_err(FetchError::Network)?;

    if resp.status().is_success() {
        let bytes = resp.into_body().into_bytes().await.map_err(|e| {
            FetchError::Network(zenwave::Error::Transport(e.to_string().into()))
        })?;
        Ok(bytes.to_vec())
    } else if resp.status().as_u16() == 429 || resp.status().is_server_error() {
        Err(FetchError::Unavailable)
    } else {
        Err(FetchError::NotFound)
    }
}

/// Resolve the GHCR blob redirect URL for client-side fallback.
///
/// GHCR returns 307 to pkg-containers.githubusercontent.com with a
/// self-authorizing SAS token (Azure Blob Storage signed URL, TTL 15-60 min).
pub async fn resolve_blob_redirect_url(
    name: &str,
    digest: &str,
    token: &str,
) -> Result<String, FetchError> {
    let url = format!("{GHCR_BASE}/{name}/blobs/{digest}");

    // We want the redirect Location header, not the actual blob
    let resp = zenwave::client()
        .method(zenwave::Method::HEAD, &url)
        .map_err(|_| FetchError::InvalidUrl)?
        .header("Authorization", &format!("Bearer {token}"))
        .map_err(|_| FetchError::InvalidUrl)?
        .send()
        .await
        .map_err(FetchError::Network)?;

    // Look for redirect Location header
    if let Some(location) = resp.headers().get("location") {
        Ok(location.to_str().unwrap_or_default().to_string())
    } else {
        Err(FetchError::NoRedirect)
    }
}

#[derive(Debug)]
pub enum FetchError {
    InvalidUrl,
    Network(zenwave::Error),
    Unavailable,
    NotFound,
    NoRedirect,
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::InvalidUrl => write!(f, "invalid GHCR URL"),
            FetchError::Network(e) => write!(f, "GHCR network error: {e}"),
            FetchError::Unavailable => write!(f, "GHCR unavailable (rate limit or 5xx)"),
            FetchError::NotFound => write!(f, "artifact not found in GHCR"),
            FetchError::NoRedirect => write!(f, "GHCR did not return redirect URL"),
        }
    }
}
