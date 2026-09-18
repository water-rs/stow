use std::io::Cursor;

use oci_spec::image::ImageManifest;
use skyzen_cloudflare::worker::send::IntoSendFuture as _;
use skyzen_cloudflare::{CfFetch, worker};
use stow_types::bundle::{
    ArtifactBlobConfig, ArtifactBundleManifest, STOW_BUNDLE_MANIFEST_PATH, STOW_OCI_CONFIG_PATH,
    STOW_OCI_MANIFEST_PATH, STOW_SIGSTORE_PAYLOAD_DIR, SigstoreSignature,
};
use tar::{Builder, Header};

use crate::bundle_schema::BundleSchemaError;
use crate::cf_http;
use crate::registry_auth::{
    BearerChallenge, DEFAULT_TOKEN_TTL_SECS, RegistryTokens, TokenResponse, parse_bearer_challenge,
    pull_scope,
};

const SIGSTORE_OCI_MEDIA_TYPE: &str = "application/vnd.dev.cosign.simplesigning.v1+json";
const SIGSTORE_SIGNATURE_ANNOTATION: &str = "dev.cosignproject.cosign/signature";
const SIGSTORE_BUNDLE_ANNOTATION: &str = "dev.sigstore.cosign/bundle";
const SIGSTORE_CERT_ANNOTATION: &str = "dev.sigstore.cosign/certificate";

pub const fn default_base_url() -> &'static str {
    stow_types::registry::GHCR_V2_BASE_URL
}

pub async fn fetch_bundle(
    base_url: &str,
    oci_reference: &str,
    name: &str,
    reference: &str,
    tokens: &RegistryTokens,
) -> Result<Vec<u8>, FetchError> {
    let manifest_bytes = fetch_manifest_bytes(base_url, name, reference, tokens).await?;
    let manifest: ImageManifest =
        serde_json::from_slice(&manifest_bytes).map_err(FetchError::InvalidManifest)?;
    let config_digest = manifest.config().digest().to_string();
    let config_bytes = fetch_blob(base_url, name, &config_digest, tokens).await?;
    let config: ArtifactBlobConfig =
        serde_json::from_slice(&config_bytes).map_err(FetchError::InvalidConfig)?;
    let signature_materials = fetch_signature_materials(base_url, name, reference, tokens).await?;
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
        tokens,
    )
    .await
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
    tokens: &RegistryTokens,
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

    validate_manifest_layers(config, manifest)?;
    for (file, descriptor) in config
        .outputs
        .iter()
        .chain(config.native_archive.as_ref())
        .zip(manifest.layers().iter())
    {
        let blob = fetch_blob(base_url, name, descriptor.digest().as_ref(), tokens).await?;
        append_bytes(&mut tar, &bundle_entry_path(&file.file_name), &blob)?;
    }

    tar.into_inner().map_err(FetchError::BuildBundle)
}

async fn fetch_signature_materials(
    base_url: &str,
    name: &str,
    oci_digest: &str,
    tokens: &RegistryTokens,
) -> Result<Vec<FetchedSigstoreSignature>, FetchError> {
    let signature_reference = format!("{}.sig", oci_digest.replace(':', "-"));
    let manifest_bytes = fetch_manifest_bytes(base_url, name, &signature_reference, tokens).await?;
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
            fetch_blob(base_url, name, descriptor.digest().as_ref(), tokens).await?;
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

fn validate_manifest_layers(
    config: &ArtifactBlobConfig,
    manifest: &ImageManifest,
) -> Result<(), FetchError> {
    // `outputs` first, then the native archive when the config declares one —
    // the order CI pushes them in.
    let expected = config
        .outputs
        .iter()
        .chain(config.native_archive.as_ref())
        .collect::<Vec<_>>();
    if manifest.layers().len() != expected.len() {
        return Err(FetchError::InvalidBundle(format!(
            "OCI manifest layer count {} does not match config outputs {}",
            manifest.layers().len(),
            expected.len()
        )));
    }
    for (file, descriptor) in expected.into_iter().zip(manifest.layers().iter()) {
        let expected_media_type = file.storage_media_type();
        let actual_media_type = descriptor.media_type().to_string();
        if actual_media_type != expected_media_type {
            return Err(FetchError::MissingLayer(format!(
                "{} at {}",
                expected_media_type, file.file_name
            )));
        }
    }
    Ok(())
}

fn bundle_entry_path(file_name: &str) -> String {
    format!("files/{file_name}")
}

async fn fetch_manifest_bytes(
    base_url: &str,
    name: &str,
    reference: &str,
    tokens: &RegistryTokens,
) -> Result<Vec<u8>, FetchError> {
    let url = format!(
        "{}/{name}/manifests/{reference}",
        base_url.trim_end_matches('/')
    );
    let response = send_request(
        &url,
        tokens,
        &pull_scope(name),
        Some("application/vnd.oci.image.manifest.v1+json"),
    )
    .await?;
    read_response_bytes(response).await
}

async fn fetch_blob(
    base_url: &str,
    name: &str,
    digest: &str,
    tokens: &RegistryTokens,
) -> Result<Vec<u8>, FetchError> {
    let url = format!("{}/{name}/blobs/{digest}", base_url.trim_end_matches('/'));
    let response = send_request(&url, tokens, &pull_scope(name), None).await?;
    read_response_bytes(response).await
}

/// `GET url` through the registry token exchange.
///
/// The request goes out with the cached bearer for `scope` when one is
/// live, anonymously otherwise. A `401` is answered by parsing the
/// `WWW-Authenticate` Bearer challenge, exchanging at its realm once,
/// caching the issued token under the challenge's scope, and retrying the
/// request a single time. A cached bearer that was attached and still
/// rejected is dropped and the exchange runs fresh — a second `401` (or
/// any non-2xx terminal response) is classified and returned as an error.
async fn send_request(
    url: &str,
    tokens: &RegistryTokens,
    scope: &str,
    accept: Option<&str>,
) -> Result<worker::Response, FetchError> {
    let attached = tokens.bearer_for(scope, now_ms());
    let mut response = send(url, attached.as_deref(), accept).await?;
    if response.status_code() != 401 {
        return classify_status(response).await;
    }

    let challenge = parse_challenge(&mut response).await?;
    if attached.is_some() {
        tokens.remove(scope);
    }
    let scope = challenge.scope.clone().unwrap_or_else(|| scope.to_owned());
    let bearer = match attached {
        None => match tokens.bearer_for(&scope, now_ms()) {
            Some(token) => token,
            None => exchange_and_cache(&challenge, &scope, tokens).await?,
        },
        Some(_) => exchange_and_cache(&challenge, &scope, tokens).await?,
    };
    let response = send(url, Some(&bearer), accept).await?;
    classify_status(response).await
}

/// Parse the `WWW-Authenticate` Bearer challenge off a `401` response. A
/// response without the header is a plain unauthorized error carrying its
/// body; a present-but-broken challenge is [`FetchError::InvalidChallenge`].
async fn parse_challenge(response: &mut worker::Response) -> Result<BearerChallenge, FetchError> {
    let header = response
        .headers()
        .get("WWW-Authenticate")
        .map_err(|error| FetchError::Network(error.to_string()))?;
    match header {
        Some(header) => parse_bearer_challenge(&header)
            .map_err(|error| FetchError::InvalidChallenge(error.to_string())),
        None => Err(FetchError::Unauthorized {
            status: response.status_code(),
            body: read_response_text(response).await,
        }),
    }
}

/// Exchange the challenge's realm anonymously and cache the issued token
/// under `scope`.
async fn exchange_and_cache(
    challenge: &BearerChallenge,
    scope: &str,
    tokens: &RegistryTokens,
) -> Result<String, FetchError> {
    let (token, expires_in) = exchange_token(challenge).await?;
    tokens.insert(scope, token.clone(), expires_in, now_ms());
    Ok(token)
}

/// `GET {realm}?service=…&scope=…` anonymously; returns the bearer and its
/// TTL in seconds ([`DEFAULT_TOKEN_TTL_SECS`] when the realm omits it).
/// A non-2xx realm response, or a 2xx body with no `token`/`access_token`,
/// is [`FetchError::TokenExchange`] carrying status and body.
async fn exchange_token(challenge: &BearerChallenge) -> Result<(String, u64), FetchError> {
    let url = token_request_url(challenge)?;
    let mut response = send(&url, None, None).await?;
    let status = response.status_code();
    let body = read_response_text(&mut response).await;
    if !(200..300).contains(&status) {
        return Err(FetchError::TokenExchange { status, body });
    }
    let parsed: TokenResponse =
        serde_json::from_str(&body).map_err(|error| FetchError::TokenExchange {
            status,
            body: format!("{body} (unparseable token response: {error})"),
        })?;
    let Some(token) = parsed.bearer() else {
        return Err(FetchError::TokenExchange { status, body });
    };
    Ok((
        token.to_owned(),
        parsed.expires_in.unwrap_or(DEFAULT_TOKEN_TTL_SECS),
    ))
}

/// Build `{realm}?service=…&scope=…` through the platform `URL` API so
/// parameter encoding stays the runtime's job.
fn token_request_url(challenge: &BearerChallenge) -> Result<String, FetchError> {
    let url = web_sys::Url::new(&challenge.realm).map_err(|error| {
        FetchError::InvalidChallenge(format!("invalid realm {:?}: {error:?}", challenge.realm))
    })?;
    let params = url.search_params();
    if let Some(service) = &challenge.service {
        params.set("service", service);
    }
    if let Some(scope) = &challenge.scope {
        params.set("scope", scope);
    }
    Ok(url.href())
}

async fn send(
    url: &str,
    token: Option<&str>,
    accept: Option<&str>,
) -> Result<worker::Response, FetchError> {
    let request = build_request(url, token, accept)?;
    CfFetch
        .request(&request)
        .await
        .map_err(|error| FetchError::Network(error.to_string()))
}

fn build_request(
    url: &str,
    token: Option<&str>,
    accept: Option<&str>,
) -> Result<worker::Request, FetchError> {
    let bearer = token.map(|token| format!("Bearer {token}"));
    let mut headers: Vec<(&str, &str)> = Vec::with_capacity(2);
    if let Some(accept) = accept {
        headers.push(("Accept", accept));
    }
    if let Some(bearer) = &bearer {
        headers.push(("Authorization", bearer.as_str()));
    }
    cf_http::bare_request(worker::Method::Get, url, &headers, None)
        .map_err(|error| FetchError::InvalidRequest(error.to_string()))
}

async fn read_response_bytes(mut response: worker::Response) -> Result<Vec<u8>, FetchError> {
    response
        .bytes()
        .into_send()
        .await
        .map_err(|error| FetchError::Network(error.to_string()))
}

/// Body for an error variant that must carry it; an unreadable body is
/// still reported rather than dropped silently.
async fn read_response_text(response: &mut worker::Response) -> String {
    response
        .text()
        .into_send()
        .await
        .unwrap_or_else(|_| "<unreadable body>".to_owned())
}

async fn classify_status(mut response: worker::Response) -> Result<worker::Response, FetchError> {
    let status = response.status_code();
    match status {
        200..=299 => Ok(response),
        401 | 403 => Err(FetchError::Unauthorized {
            status,
            body: read_response_text(&mut response).await,
        }),
        404 => Err(FetchError::NotFound),
        429 | 500..=599 => Err(FetchError::Unavailable),
        _ => Err(FetchError::UnexpectedStatus(status)),
    }
}

/// `Date::now()` epoch milliseconds — the only wall clock Workers' wasm
/// runtime exposes; whole ms well below 2^53, so the cast never loses
/// precision.
fn now_ms() -> i64 {
    #[expect(clippy::cast_possible_truncation, reason = "epoch ms fits i64")]
    {
        js_sys::Date::now() as i64
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("invalid GHCR request: {0}")]
    InvalidRequest(String),
    #[error("invalid OCI manifest: {0}")]
    InvalidManifest(serde_json::Error),
    #[error("invalid OCI config: {0}")]
    InvalidConfig(serde_json::Error),
    #[error("invalid cosign signature manifest: {0}")]
    InvalidSignatureManifest(serde_json::Error),
    #[error("invalid artifact bundle: {0}")]
    InvalidBundle(String),
    #[error(transparent)]
    Schema(#[from] BundleSchemaError),
    #[error("serialize bundle manifest: {0}")]
    SerializeBundle(serde_json::Error),
    #[error("build bundle tar: {0}")]
    BuildBundle(std::io::Error),
    #[error("OCI manifest missing layer with media type {0}")]
    MissingLayer(String),
    #[error("OCI signature image has no sigstore payload layers: {0}")]
    MissingSignatureLayer(String),
    #[error("OCI signature layer is missing required cosign annotations")]
    MissingSignatureAnnotations,
    #[error("GHCR network error: {0}")]
    Network(String),
    #[error("GHCR unavailable (rate limit or 5xx)")]
    Unavailable,
    #[error("malformed registry auth challenge: {0}")]
    InvalidChallenge(String),
    #[error("registry token exchange failed (HTTP {status}): {body}")]
    TokenExchange {
        /// HTTP status of the realm response.
        status: u16,
        /// Realm response body for diagnostics.
        body: String,
    },
    #[error("GHCR authentication/authorization failed (HTTP {status}): {body}")]
    Unauthorized {
        /// HTTP status of the rejected request.
        status: u16,
        /// Response body for diagnostics.
        body: String,
    },
    #[error("artifact not found in GHCR")]
    NotFound,
    #[error("GHCR returned unexpected HTTP status {0}")]
    UnexpectedStatus(u16),
}

impl FetchError {
    pub const fn indicates_stale_artifact(&self) -> bool {
        match self {
            Self::InvalidManifest(_)
            | Self::InvalidConfig(_)
            | Self::InvalidSignatureManifest(_)
            | Self::InvalidBundle(_)
            | Self::Schema(_)
            | Self::MissingLayer(_)
            | Self::MissingSignatureLayer(_)
            | Self::MissingSignatureAnnotations
            | Self::NotFound => true,
            Self::InvalidRequest(_)
            | Self::SerializeBundle(_)
            | Self::BuildBundle(_)
            | Self::Network(_)
            | Self::Unavailable
            | Self::InvalidChallenge(_)
            | Self::TokenExchange { .. }
            | Self::Unauthorized { .. }
            | Self::UnexpectedStatus(_) => false,
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
