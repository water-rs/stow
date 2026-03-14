use zenwave::Client;

/// Base URL for the GHCR OCI registry.
const GHCR_BASE: &str = "https://ghcr.io/v2/stow-rs/cache";

/// Fetch an OCI artifact blob from GHCR.
pub async fn fetch_artifact_blob(oci_digest: &str, token: &str) -> Result<Vec<u8>, FetchError> {
    let url = format!("{GHCR_BASE}/blobs/{oci_digest}");
    let mut client = zenwave::client();
    let bytes = client
        .get(&url)
        .bearer_auth(token)
        .bytes()
        .await
        .map_err(FetchError::Network)?;
    Ok(bytes.to_vec())
}

/// Fetch an OCI manifest from GHCR by reference (tag or digest).
pub async fn fetch_manifest(name: &str, reference: &str, token: &str) -> Result<Vec<u8>, FetchError> {
    let url = format!("{GHCR_BASE}/{name}/manifests/{reference}");
    let mut client = zenwave::client();
    let bytes = client
        .get(&url)
        .header("Accept", "application/vnd.oci.image.manifest.v1+json")
        .bearer_auth(token)
        .bytes()
        .await
        .map_err(classify_fetch_error)?;
    Ok(bytes.to_vec())
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
    Network(zenwave::Error),
    Unavailable,
    NotFound,
    NoRedirect,
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::InvalidUrl => write!(f, "invalid GHCR URL"),
            FetchError::Network(error) => write!(f, "GHCR network error: {error}"),
            FetchError::Unavailable => write!(f, "GHCR unavailable (rate limit or 5xx)"),
            FetchError::NotFound => write!(f, "artifact not found in GHCR"),
            FetchError::NoRedirect => write!(f, "GHCR did not return redirect URL"),
        }
    }
}
