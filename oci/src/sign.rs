//! Keyless signing in process — what `cosign sign` did, without a
//! process per signature.
//!
//! A [`KeylessSigner`] holds one ephemeral P-256 key and the Fulcio
//! certificate issued for it, and reuses both for every signature made
//! while the certificate has more than [`RENEWAL_MARGIN`] left; every
//! signature still gets its own Rekor entry, which is what dates it. The
//! verifier checks the certificate at the entry's integrated time, so a
//! certificate reused inside its window verifies exactly like one issued
//! per signature.
//!
//! The signature image is cosign's legacy `sha256-<digest>.sig` layout —
//! the one the CLI and every records reader pull — pushed through the
//! caller's [`RegistrySession`], so its blob uploads are single requests,
//! a throttled write backs off in place, and every write spends the
//! process's write budget. The bytes match what `cosign sign
//! --new-bundle-format=false --use-signing-config=false
//! --sign-container-identity <reference>` wrote: the simple-signing
//! payload binding the tagged reference, a layer per signature carrying
//! the signature, certificate, chain and Rekor bundle annotations, and the
//! config go-containerregistry derives from the layers.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use oci_client::Reference;
use reqwest::Method;
use reqwest::header::{self, HeaderValue};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sigstore::cosign::bundle::{Bundle as RekorBundle, Payload as RekorPayload};
use sigstore::cosign::payload::simple_signing::{
    CRITICAL_TYPE_NAME, Critical, Identity, Image, SimpleSigning,
};
use sigstore::crypto::SigningScheme;
use sigstore::crypto::signing_key::SigStoreSigner;
use stow_types::bundle::{
    OCI_IMAGE_MANIFEST_MEDIA_TYPE, SIGSTORE_BUNDLE_ANNOTATION, SIGSTORE_CERT_ANNOTATION,
    SIGSTORE_OCI_MEDIA_TYPE, SIGSTORE_SIGNATURE_ANNOTATION, SigstoreSignature,
    sigstore_payload_path, sigstore_signature_tag,
};
use stow_types::error::Context as _;
use stow_types::registry::sha256_digest;
use x509_cert::Certificate;
use x509_cert::der::{DecodePem as _, Encode as _, EncodePem as _, pem::LineEnding};

use crate::client::{RegistryHttp, RegistrySession, Response, SessionRequest};
use crate::retry::retry_with_backoff;
use crate::verify::{TrustMaterial, verify_logged_signature, verify_payload_identity};

/// Push `manifest` so that `reference`'s tag never names an unsigned
/// manifest: the bytes go up by digest first, `sign` signs that digest
/// under the tagged identity, and only then does the tag move to it.
///
/// Tagging first leaves a window, as long as signing takes, in which every
/// reader resolves the tag to a digest whose `.sig` does not exist yet and
/// fails verification; a signing failure would leave the tag there for
/// good. Pushed this way, a reader sees the previous signed manifest or the
/// new signed one, and a failed signature leaves the tag untouched.
///
/// Returns the manifest digest.
///
/// # Errors
///
/// Returns an error when either manifest `PUT` or the signature fails.
pub async fn put_signed_manifest<S, Fut>(
    session: &RegistrySession,
    reference: &Reference,
    manifest: &[u8],
    sign: S,
) -> stow_types::error::Result<String>
where
    S: FnOnce(String) -> Fut,
    Fut: Future<Output = stow_types::error::Result<()>>,
{
    let digest = sha256_digest(manifest);
    let by_digest: Reference = format!(
        "{}/{}@{digest}",
        reference.registry(),
        reference.repository()
    )
    .parse()
    .map_err(|error| stow_types::stow_error!("parse digest reference for {reference}: {error}"))?;
    session
        .put_manifest(&by_digest, manifest)
        .await
        .map_err(|error| stow_types::stow_error!("push manifest {by_digest}: {error}"))?;
    sign(digest.clone()).await?;
    session
        .put_manifest(reference, manifest)
        .await
        .map_err(|error| stow_types::stow_error!("tag manifest {reference}: {error}"))?;
    Ok(digest)
}

/// The public-good Fulcio instance — cosign's default with the TUF signing
/// config off, the CA whose roots the TUF trust root carries.
pub const FULCIO_URL: &str = "https://fulcio.sigstore.dev";

/// The public-good Rekor v1 log — cosign's default with the TUF signing
/// config off, whose key the TUF trust root carries.
pub const REKOR_URL: &str = "https://rekor.sigstore.dev";

/// The job's OIDC token endpoint, set on a job granted `id-token: write`.
const OIDC_REQUEST_URL_ENV: &str = "ACTIONS_ID_TOKEN_REQUEST_URL";

/// The bearer the OIDC token endpoint takes.
const OIDC_REQUEST_TOKEN_ENV: &str = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";

/// The audience Fulcio requires of an identity token.
const OIDC_AUDIENCE: &str = "sigstore";

/// A certificate with less than this left is replaced before the next
/// signature. Fulcio issues ten-minute certificates; the margin outlasts
/// the longest a Rekor submission can take through the retry loop — seven
/// retries, each waiting at most 30 seconds — so the entry is integrated
/// while the certificate it names is still valid.
const RENEWAL_MARGIN: Duration = Duration::from_mins(4);

/// Rekor's `409` names an entry its read path may not serve yet: the
/// public-good log has answered `404` — the same empty answer as for an
/// entry it never logged — at the very `Location` it named, seconds after
/// the entry's integrated time, and served the entry there later. The
/// read-back retries that `404` this many times, waiting
/// [`REKOR_READ_BACK_INITIAL_DELAY`] doubled each time (about a minute in
/// all), before the entry's absence is final. The entry is already
/// integrated, so the wait does not count against the certificate's
/// [`RENEWAL_MARGIN`].
const REKOR_READ_BACK_MAX_ATTEMPTS: u32 = 8;

/// The first wait of the Rekor read-back's retries.
const REKOR_READ_BACK_INITIAL_DELAY: Duration = Duration::from_millis(500);

/// The go-containerregistry zero time every layer's history and the
/// config's `created` carry in a cosign signature image.
const ZERO_TIME: &str = "0001-01-01T00:00:00Z";

/// The media type of a signature image's config blob.
const OCI_IMAGE_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";

/// The annotation carrying the PEM chain above the signing certificate.
const SIGSTORE_CHAIN_ANNOTATION: &str = "dev.sigstore.cosign/chain";

/// Where the signer reaches Sigstore and the job's identity.
#[derive(Clone)]
pub struct SigstoreServices {
    /// The Fulcio root URL (`/api/v1/signingCert` hangs off it).
    pub fulcio_url: String,
    /// The Rekor root URL (`/api/v1/log/entries` hangs off it).
    pub rekor_url: String,
    /// The endpoint that mints the job's OIDC identity token.
    pub oidc_request_url: String,
    /// The bearer that endpoint takes.
    pub oidc_request_token: String,
}

/// The request token is a credential and never renders.
impl std::fmt::Debug for SigstoreServices {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SigstoreServices")
            .field("fulcio_url", &self.fulcio_url)
            .field("rekor_url", &self.rekor_url)
            .field("oidc_request_url", &self.oidc_request_url)
            .finish_non_exhaustive()
    }
}

impl SigstoreServices {
    /// The public-good instance and the job's own OIDC endpoint.
    ///
    /// # Errors
    ///
    /// `ACTIONS_ID_TOKEN_REQUEST_URL` or `ACTIONS_ID_TOKEN_REQUEST_TOKEN`
    /// is unset — the job lacks `id-token: write`.
    pub fn production_from_env() -> stow_types::error::Result<Self> {
        let required = |name: &str| {
            std::env::var(name).map_err(|_| {
                stow_types::stow_error!(
                    "missing required environment variable {name}: keyless signing needs a GitHub Actions job granted `id-token: write`"
                )
            })
        };
        Ok(Self {
            fulcio_url: FULCIO_URL.to_owned(),
            rekor_url: REKOR_URL.to_owned(),
            oidc_request_url: required(OIDC_REQUEST_URL_ENV)?,
            oidc_request_token: required(OIDC_REQUEST_TOKEN_ENV)?,
        })
    }
}

/// The process's keyless signer. Clones share the key and certificate, so
/// every task signing at once rides one certificate.
#[derive(Debug, Clone)]
pub struct KeylessSigner {
    state: Arc<SignerState>,
}

#[derive(Debug)]
struct SignerState {
    http: RegistryHttp,
    trust: Arc<TrustMaterial>,
    services: SigstoreServices,
    /// The current key and certificate, behind a lock so concurrent
    /// signers that find it due share a single renewal.
    identity: smol::lock::Mutex<Option<Arc<SigningIdentity>>>,
}

/// One ephemeral key and the certificate Fulcio issued for it.
struct SigningIdentity {
    signer: SigStoreSigner,
    /// The leaf, PEM as Go's `pem.EncodeToMemory` writes it — what cosign
    /// put in the certificate annotation and in the Rekor entry.
    certificate_pem: String,
    /// The PEM chain above the leaf, exactly as Fulcio returned it.
    chain_pem: String,
    /// The leaf's `notAfter`, seconds since the epoch.
    not_after: u64,
}

impl std::fmt::Debug for SigningIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SigningIdentity")
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

impl KeylessSigner {
    /// A signer over `services`, checking every signature it makes against
    /// `trust` before publishing it.
    #[must_use]
    pub fn new(http: RegistryHttp, trust: Arc<TrustMaterial>, services: SigstoreServices) -> Self {
        Self {
            state: Arc::new(SignerState {
                http,
                trust,
                services,
                identity: smol::lock::Mutex::new(None),
            }),
        }
    }

    /// The production signer: the public-good instance under the job's
    /// OIDC identity.
    ///
    /// # Errors
    ///
    /// As [`SigstoreServices::production_from_env`].
    pub fn from_env(
        http: RegistryHttp,
        trust: Arc<TrustMaterial>,
    ) -> stow_types::error::Result<Self> {
        Ok(Self::new(
            http,
            trust,
            SigstoreServices::production_from_env()?,
        ))
    }

    /// Sign the manifest `digest` under `reference` — the tagged reference
    /// readers bind — and append the signature to its `.sig` image through
    /// `session`.
    ///
    /// The signature is logged in Rekor and checked against the trust
    /// root before anything is pushed: a signature no reader would accept
    /// is an error here, never a published layer.
    ///
    /// # Errors
    ///
    /// The OIDC token, Fulcio or Rekor request fails, the signature does
    /// not verify against the trust root, or a registry push fails.
    pub async fn sign(
        &self,
        session: &RegistrySession,
        reference: &str,
        digest: &str,
    ) -> stow_types::error::Result<()> {
        let payload = simple_signing_payload(reference, digest)?;
        let identity = self.identity().await?;
        let signature = identity
            .signer
            .sign(&payload)
            .wrap_err_with(|| format!("sign the payload of {reference}@{digest}"))?;
        let bundle = self.log(&identity, &payload, &signature).await?;
        let layer = SignatureLayer {
            payload,
            signature: base64::engine::general_purpose::STANDARD.encode(&signature),
            certificate_pem: identity.certificate_pem.clone(),
            chain_pem: identity.chain_pem.clone(),
            bundle_json: serde_json::to_string(&bundle).wrap_err("encode the Rekor bundle")?,
        };
        self.check(&layer, reference, digest)?;
        push_signature_layer(session, digest, &layer).await?;
        tracing::info!(
            %reference,
            %digest,
            log_index = bundle.payload.log_index,
            "signed OCI artifact"
        );
        Ok(())
    }

    /// The signature as a reader will check it: the payload binds
    /// `reference` at `digest`, and the Rekor bundle, chain and signature
    /// verify against the trust root.
    fn check(
        &self,
        layer: &SignatureLayer,
        reference: &str,
        digest: &str,
    ) -> stow_types::error::Result<()> {
        verify_payload_identity(&layer.payload, reference, digest)?;
        verify_logged_signature(
            &self.state.trust,
            &SigstoreSignature {
                payload_path: sigstore_payload_path(0),
                signature: layer.signature.clone(),
                certificate_pem: layer.certificate_pem.clone(),
                rekor_bundle_json: Some(layer.bundle_json.clone()),
            },
            &layer.payload,
        )
        .wrap_err_with(|| {
            format!("the signature made for {reference}@{digest} does not verify against the Sigstore trust root")
        })?;
        Ok(())
    }

    /// The current key and certificate, renewed first when the
    /// certificate has less than [`RENEWAL_MARGIN`] left.
    async fn identity(&self) -> stow_types::error::Result<Arc<SigningIdentity>> {
        let mut current = self.state.identity.lock().await;
        let now = unix_now()?;
        if let Some(identity) = current.as_ref()
            && now.saturating_add(RENEWAL_MARGIN.as_secs()) < identity.not_after
        {
            return Ok(Arc::clone(identity));
        }
        let identity = Arc::new(self.issue().await?);
        *current = Some(Arc::clone(&identity));
        drop(current);
        tracing::info!(
            not_after = identity.not_after,
            "issued a Fulcio signing certificate"
        );
        Ok(identity)
    }

    /// A fresh key and the certificate Fulcio issues for it under the
    /// job's OIDC identity: `POST /api/v1/signingCert` with the public key
    /// and the token's subject signed as proof of possession — the
    /// request cosign makes.
    async fn issue(&self) -> stow_types::error::Result<SigningIdentity> {
        let token = self.oidc_token().await?;
        let subject = token_subject(&token)?;
        let signer = SigningScheme::ECDSA_P256_SHA256_ASN1
            .create_signer()
            .wrap_err("generate the ephemeral signing key")?;
        let public_key = signer
            .to_sigstore_keypair()
            .and_then(|keys| keys.public_key_to_der())
            .wrap_err("encode the ephemeral public key")?;
        let proof = signer
            .sign(subject.as_bytes())
            .wrap_err("sign the proof of possession")?;
        let base64 = base64::engine::general_purpose::STANDARD;
        let body = serde_json::to_vec(&FulcioRequest {
            public_key: FulcioPublicKey {
                content: base64.encode(&public_key),
                algorithm: "ecdsa",
            },
            signed_email_address: base64.encode(&proof),
        })?;
        let url = format!(
            "{}/api/v1/signingCert",
            self.state.services.fulcio_url.trim_end_matches('/')
        );
        let mut request = SessionRequest::new(Method::POST, url.clone());
        request.headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}"))
                .wrap_err("the OIDC token is not a valid header value")?,
        );
        request.headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        request.headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/pem-certificate-chain"),
        );
        request.body = Some(body);
        let response = self
            .send("request a Fulcio signing certificate", request)
            .await?;
        if response.status != reqwest::StatusCode::CREATED {
            return Err(refused(
                "Fulcio",
                "issue a signing certificate",
                &url,
                &response,
            ));
        }
        let chain = std::str::from_utf8(&response.body)
            .wrap_err("Fulcio answered a certificate chain that is not UTF-8")?;
        let (leaf, chain_pem) = split_certificate_chain(chain)?;
        let leaf_key = leaf
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .wrap_err("encode the issued certificate's public key")?;
        if leaf_key != public_key {
            return Err(stow_types::stow_error!(
                "Fulcio issued a certificate for a different public key than the one {url} was sent"
            ));
        }
        Ok(SigningIdentity {
            signer,
            certificate_pem: leaf
                .to_pem(LineEnding::LF)
                .wrap_err("encode the signing certificate as PEM")?,
            chain_pem,
            not_after: leaf
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs(),
        })
    }

    /// The job's OIDC identity token for the `sigstore` audience.
    async fn oidc_token(&self) -> stow_types::error::Result<String> {
        #[derive(Deserialize)]
        struct TokenAnswer {
            value: String,
        }
        let services = &self.state.services;
        let mut url = reqwest::Url::parse(&services.oidc_request_url)
            .wrap_err("parse ACTIONS_ID_TOKEN_REQUEST_URL")?;
        url.query_pairs_mut().append_pair("audience", OIDC_AUDIENCE);
        let url = url.to_string();
        let mut request = SessionRequest::new(Method::GET, url.clone());
        request.headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("bearer {}", services.oidc_request_token))
                .wrap_err("the OIDC request token is not a valid header value")?,
        );
        request
            .headers
            .insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        let response = self.send("request the job's OIDC token", request).await?;
        if !response.status.is_success() {
            return Err(refused(
                "the OIDC token endpoint",
                "mint an identity token",
                &url,
                &response,
            ));
        }
        let answer: TokenAnswer = serde_json::from_slice(&response.body)
            .wrap_err("the OIDC token endpoint answered without a `value`")?;
        Ok(answer.value)
    }

    /// Log `signature` over `payload` in Rekor as a `hashedrekord` entry
    /// naming the certificate, and return the entry as the cosign bundle.
    ///
    /// A submission whose answer was lost and is retried finds the entry
    /// already logged — Rekor answers `409` with its `Location` — and the
    /// existing entry is read back there rather than logged twice, waiting
    /// out the `404` Rekor answers until its read path serves the entry.
    async fn log(
        &self,
        identity: &SigningIdentity,
        payload: &[u8],
        signature: &[u8],
    ) -> stow_types::error::Result<RekorBundle> {
        let base64 = base64::engine::general_purpose::STANDARD;
        let entry = serde_json::json!({
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {
                "data": {
                    "hash": { "algorithm": "sha256", "value": hex::encode(Sha256::digest(payload)) },
                },
                "signature": {
                    "content": base64.encode(signature),
                    "publicKey": { "content": base64.encode(identity.certificate_pem.as_bytes()) },
                },
            },
        });
        let rekor = self.state.services.rekor_url.trim_end_matches('/');
        let url = format!("{rekor}/api/v1/log/entries");
        let mut request = SessionRequest::new(Method::POST, url.clone());
        request.headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        request
            .headers
            .insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        request.body = Some(serde_json::to_vec(&entry)?);
        let response = self.send("log the signature in Rekor", request).await?;
        let response = match response.status {
            reqwest::StatusCode::CREATED => response,
            reqwest::StatusCode::CONFLICT => {
                let location = response
                    .headers
                    .get(header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| {
                        stow_types::stow_error!(
                            "Rekor answered 409 for {url} without the Location of the existing entry"
                        )
                    })?;
                let existing = reqwest::Url::parse(&format!("{rekor}/"))
                    .and_then(|base| base.join(location))
                    .wrap_err_with(|| format!("resolve Rekor entry Location {location}"))?
                    .to_string();
                self.read_back(&existing)
                    .await
                    .map_err(|error| match error {
                        EntryRead::NotReadable(response) => stow_types::stow_error!(
                            "Rekor answered 409 for {url} naming the existing entry {existing}, \
                         which was still not readable there after \
                         {REKOR_READ_BACK_MAX_ATTEMPTS} reads: {}: {}",
                            response.status,
                            String::from_utf8_lossy(&response.body)
                        ),
                        EntryRead::Refused(response) => {
                            refused("Rekor", "read back the entry", &existing, &response)
                        }
                        EntryRead::Failed(error) => error,
                    })?
            }
            _ => return Err(refused("Rekor", "log the signature", &url, &response)),
        };
        rekor_bundle(&response.body)
    }

    /// Read the logged entry at `url`, retrying the `404` Rekor answers
    /// while an entry it already reported is not yet readable.
    async fn read_back(&self, url: &str) -> Result<Response, EntryRead> {
        retry_with_backoff(
            "read back the logged Rekor entry",
            REKOR_READ_BACK_MAX_ATTEMPTS,
            REKOR_READ_BACK_INITIAL_DELAY,
            || async {
                let response = self
                    .send(
                        "read back the logged Rekor entry",
                        SessionRequest::new(Method::GET, url.to_owned()),
                    )
                    .await
                    .map_err(EntryRead::Failed)?;
                match response.status {
                    status if status.is_success() => Ok(response),
                    reqwest::StatusCode::NOT_FOUND => {
                        Err(EntryRead::NotReadable(Box::new(response)))
                    }
                    _ => Err(EntryRead::Refused(Box::new(response))),
                }
            },
            |error| matches!(error, EntryRead::NotReadable(_)),
        )
        .await
    }

    /// One Sigstore exchange through the process's retry loop.
    async fn send(
        &self,
        what: &str,
        request: SessionRequest,
    ) -> stow_types::error::Result<Response> {
        self.state
            .http
            .send(what, request, None)
            .await
            .map_err(|error| stow_types::stow_error!("{error}"))
    }
}

/// A failed read of the Rekor entry a `409` named.
enum EntryRead {
    /// Rekor does not serve the entry (yet).
    NotReadable(Box<Response>),
    /// Rekor refused the read with another status.
    Refused(Box<Response>),
    /// The exchange itself failed.
    Failed(stow_types::error::Error),
}

impl std::fmt::Display for EntryRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotReadable(response) | Self::Refused(response) => write!(
                f,
                "{}: {}",
                response.status,
                String::from_utf8_lossy(&response.body)
            ),
            Self::Failed(error) => write!(f, "{error}"),
        }
    }
}

/// A Sigstore service's refusal, with its status and its body verbatim.
fn refused(service: &str, what: &str, url: &str, response: &Response) -> stow_types::error::Error {
    stow_types::stow_error!(
        "{service} refused to {what} ({url}): {}: {}",
        response.status,
        String::from_utf8_lossy(&response.body)
    )
}

/// The `POST /api/v1/signingCert` body: the public key and the signed
/// subject, under the field names Fulcio's v1 API defines.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FulcioRequest {
    public_key: FulcioPublicKey,
    signed_email_address: String,
}

#[derive(Serialize)]
struct FulcioPublicKey {
    content: String,
    algorithm: &'static str,
}

/// The subject the identity token names — the value Fulcio's GitHub
/// Actions issuer takes as the proof-of-possession challenge (the token
/// carries no `email`).
fn token_subject(token: &str) -> stow_types::error::Result<String> {
    #[derive(Deserialize)]
    struct Claims {
        sub: String,
    }
    let claims = token.split('.').nth(1).ok_or_else(|| {
        stow_types::stow_error!("the OIDC token is not a JWT: it has no claims segment")
    })?;
    let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(claims.trim_end_matches('='))
        .wrap_err("decode the OIDC token's claims")?;
    let claims: Claims =
        serde_json::from_slice(&claims).wrap_err("the OIDC token's claims carry no `sub`")?;
    Ok(claims.sub)
}

/// Split Fulcio's PEM chain into the leaf and the PEM above it, as Go's
/// `pem.Decode` splits it for cosign: everything after the leaf's END line
/// and its line break, byte for byte.
fn split_certificate_chain(chain: &str) -> stow_types::error::Result<(Certificate, String)> {
    const END: &str = "-----END CERTIFICATE-----";
    let leaf_end = chain
        .find(END)
        .ok_or_else(|| stow_types::stow_error!("Fulcio answered no PEM certificate"))?
        + END.len();
    let after = &chain[leaf_end..];
    let rest = match after.find('\n') {
        Some(line_end) if after[..line_end].trim().is_empty() => &after[line_end + 1..],
        None if after.trim().is_empty() => "",
        _ => {
            return Err(stow_types::stow_error!(
                "Fulcio's certificate chain has text after the leaf's END line"
            ));
        }
    };
    let leaf = Certificate::from_pem(&chain.as_bytes()[..leaf_end])
        .wrap_err("parse the Fulcio signing certificate")?;
    // `load_pem_chain` indexes `input.len() - 1` and panics on an empty
    // input, so the absent chain is answered before it is called.
    if rest.trim().is_empty() {
        return Err(stow_types::stow_error!(
            "Fulcio answered the signing certificate without its chain"
        ));
    }
    Certificate::load_pem_chain(rest.as_bytes()).wrap_err("parse the Fulcio certificate chain")?;
    Ok((leaf, rest.to_owned()))
}

/// The Rekor answer `{"<uuid>": entry}` as cosign's bundle.
fn rekor_bundle(body: &[u8]) -> stow_types::error::Result<RekorBundle> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Entry {
        body: String,
        integrated_time: i64,
        #[serde(rename = "logID")]
        log_id: String,
        log_index: i64,
        verification: Verification,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Verification {
        signed_entry_timestamp: String,
    }
    let entries: std::collections::BTreeMap<String, Entry> =
        serde_json::from_slice(body).wrap_err("parse Rekor's log entry answer")?;
    let mut entries = entries.into_values();
    let (Some(entry), None) = (entries.next(), entries.next()) else {
        return Err(stow_types::stow_error!(
            "Rekor answered a log entry submission with other than exactly one entry"
        ));
    };
    Ok(RekorBundle {
        signed_entry_timestamp: entry.verification.signed_entry_timestamp,
        payload: RekorPayload {
            body: entry.body,
            integrated_time: entry.integrated_time,
            log_index: entry.log_index,
            log_id: entry.log_id,
        },
    })
}

fn unix_now() -> stow_types::error::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .wrap_err("the system clock is before the Unix epoch")?
        .as_secs())
}

/// The simple-signing payload cosign signs: the tagged `reference` as the
/// claimed identity and the manifest `digest`, serialized in the field
/// order Go's encoder writes.
fn simple_signing_payload(reference: &str, digest: &str) -> stow_types::error::Result<Vec<u8>> {
    Ok(serde_json::to_vec(&SimpleSigning {
        critical: Critical {
            identity: Identity {
                docker_reference: reference.to_owned(),
            },
            image: Image {
                docker_manifest_digest: digest.to_owned(),
            },
            type_name: CRITICAL_TYPE_NAME.to_owned(),
        },
        optional: None,
    })?)
}

/// One signature, ready to append to the `.sig` image.
struct SignatureLayer {
    payload: Vec<u8>,
    signature: String,
    certificate_pem: String,
    chain_pem: String,
    bundle_json: String,
}

/// A signature image manifest, in the field order go-containerregistry
/// writes. Unknown fields are refused: appending to a manifest this type
/// cannot reproduce would drop them.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignatureManifest {
    schema_version: u32,
    media_type: String,
    config: SignatureDescriptor,
    layers: Vec<SignatureDescriptor>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignatureDescriptor {
    media_type: String,
    size: u64,
    digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    annotations: Option<std::collections::BTreeMap<String, String>>,
}

/// The config go-containerregistry derives for a signature image: one
/// zero-time history entry and one diff id per layer.
#[derive(Serialize)]
struct SignatureConfig<'a> {
    architecture: &'static str,
    created: &'static str,
    history: Vec<History>,
    os: &'static str,
    rootfs: RootFs<'a>,
    config: EmptyObject,
}

#[derive(Serialize)]
struct History {
    created: &'static str,
}

#[derive(Serialize)]
struct RootFs<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    diff_ids: Vec<&'a str>,
}

#[derive(Serialize)]
struct EmptyObject {}

/// The config blob for a signature image whose layers are `layers`.
fn signature_config(layers: &[SignatureDescriptor]) -> stow_types::error::Result<Vec<u8>> {
    Ok(serde_json::to_vec(&SignatureConfig {
        architecture: "",
        created: ZERO_TIME,
        history: layers
            .iter()
            .map(|_| History { created: ZERO_TIME })
            .collect(),
        os: "",
        rootfs: RootFs {
            kind: "layers",
            diff_ids: layers.iter().map(|layer| layer.digest.as_str()).collect(),
        },
        config: EmptyObject {},
    })?)
}

/// The signature image manifest over `layers` and its config.
fn signature_manifest(
    layers: Vec<SignatureDescriptor>,
) -> stow_types::error::Result<(Vec<u8>, Vec<u8>)> {
    let config = signature_config(&layers)?;
    let manifest = serde_json::to_vec(&SignatureManifest {
        schema_version: 2,
        media_type: OCI_IMAGE_MANIFEST_MEDIA_TYPE.to_owned(),
        config: SignatureDescriptor {
            media_type: OCI_IMAGE_CONFIG_MEDIA_TYPE.to_owned(),
            size: config.len() as u64,
            digest: sha256_digest(&config),
            annotations: None,
        },
        layers,
    })?;
    Ok((manifest, config))
}

/// Append `layer` to `digest`'s `.sig` image: read the image (absent is
/// empty), push the payload and the new config, then the manifest — three
/// writes.
async fn push_signature_layer(
    session: &RegistrySession,
    digest: &str,
    layer: &SignatureLayer,
) -> stow_types::error::Result<()> {
    let reference = session.reference(&sigstore_signature_tag(digest))?;
    let mut layers = match session.pull_manifest(&reference).await {
        Ok((bytes, _)) => {
            serde_json::from_slice::<SignatureManifest>(&bytes)
                .wrap_err_with(|| format!("parse the signature image {reference}"))?
                .layers
        }
        Err(error) if error.is_not_found() => Vec::new(),
        Err(error) => {
            return Err(stow_types::stow_error!(
                "read the signature image {reference}: {error}"
            ));
        }
    };
    let payload_digest = sha256_digest(&layer.payload);
    layers.push(SignatureDescriptor {
        media_type: SIGSTORE_OCI_MEDIA_TYPE.to_owned(),
        size: layer.payload.len() as u64,
        digest: payload_digest.clone(),
        annotations: Some(std::collections::BTreeMap::from([
            (
                SIGSTORE_SIGNATURE_ANNOTATION.to_owned(),
                layer.signature.clone(),
            ),
            (
                SIGSTORE_BUNDLE_ANNOTATION.to_owned(),
                layer.bundle_json.clone(),
            ),
            (
                SIGSTORE_CERT_ANNOTATION.to_owned(),
                layer.certificate_pem.clone(),
            ),
            (
                SIGSTORE_CHAIN_ANNOTATION.to_owned(),
                layer.chain_pem.clone(),
            ),
        ])),
    });
    let (manifest, config) = signature_manifest(layers)?;
    session
        .push_blob(&payload_digest, &layer.payload)
        .await
        .map_err(|error| {
            stow_types::stow_error!("push the signature payload of {reference}: {error}")
        })?;
    session
        .push_blob(&sha256_digest(&config), &config)
        .await
        .map_err(|error| {
            stow_types::stow_error!("push the signature config of {reference}: {error}")
        })?;
    session
        .put_manifest(&reference, &manifest)
        .await
        .map_err(|error| {
            stow_types::stow_error!("push the signature image {reference}: {error}")
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use stow_types::bundle::{SIGSTORE_CERT_ANNOTATION, SIGSTORE_OCI_MEDIA_TYPE};
    use stow_types::registry::sha256_digest;
    use x509_cert::der::{EncodePem as _, pem::LineEnding};

    use super::{
        SIGSTORE_CHAIN_ANNOTATION, SignatureManifest, rekor_bundle, signature_config,
        signature_manifest, simple_signing_payload, split_certificate_chain, token_subject,
    };

    /// A signature image `cosign sign` pushed to
    /// `ghcr.io/water-rs/stow-cache-1.99.1:sha256-f08ae48a…bd870b.sig`: two
    /// layers, one per records tag sharing the manifest, pulled anonymously
    /// byte for byte.
    const COSIGN_MANIFEST: &[u8] =
        include_bytes!("../tests/fixtures/cosign-signature/manifest.json");
    /// That image's config blob.
    const COSIGN_CONFIG: &[u8] = include_bytes!("../tests/fixtures/cosign-signature/config.json");
    const COSIGN_MANIFEST_DIGEST: &str =
        "sha256:ddccf08be7d705ba2462710ba64b9d06064cb24d990af8b915c2505b75bed709";
    const SIGNED_DIGEST: &str =
        "sha256:f08ae48a8118a242f715675eb67dd500ea13467522741c60e6e3342082bd870b";
    const SIGNED_REFERENCES: [&str; 2] = [
        "ghcr.io/water-rs/stow-cache-1.99.1:records-1.99.1-77ba78ec97e2e5f38caf63232e2d0ef03593a3804259d64cb002709a1928aec9-40626525226-1",
        "ghcr.io/water-rs/stow-cache-1.99.1:records-1.99.1-77ba78ec97e2e5f38caf63232e2d0ef03593a3804259d64cb002709a1928aec9-40703931160-1",
    ];

    fn cosign_manifest() -> SignatureManifest {
        serde_json::from_slice(COSIGN_MANIFEST).expect("the cosign manifest parses")
    }

    /// The manifest and config this module writes for cosign's layers are
    /// cosign's bytes: rebuilding the pulled image from its own layers
    /// reproduces its digest and its config blob.
    #[test]
    fn the_signature_image_is_byte_identical_to_cosigns() {
        assert_eq!(sha256_digest(COSIGN_MANIFEST), COSIGN_MANIFEST_DIGEST);
        let manifest = cosign_manifest();
        assert_eq!(
            signature_config(&manifest.layers).expect("config"),
            COSIGN_CONFIG
        );
        let (rebuilt, config) = signature_manifest(manifest.layers).expect("manifest");
        assert_eq!(config, COSIGN_CONFIG);
        assert_eq!(rebuilt, COSIGN_MANIFEST);
    }

    /// The payload this module signs is the blob cosign pushed for the
    /// same reference and digest.
    #[test]
    fn the_payload_is_byte_identical_to_cosigns() {
        let manifest = cosign_manifest();
        for (layer, reference) in manifest.layers.iter().zip(SIGNED_REFERENCES) {
            assert_eq!(layer.media_type, SIGSTORE_OCI_MEDIA_TYPE);
            let payload = simple_signing_payload(reference, SIGNED_DIGEST).expect("payload");
            assert_eq!(sha256_digest(&payload), layer.digest);
            assert_eq!(payload.len() as u64, layer.size);
        }
    }

    /// The certificate annotation is the leaf re-encoded the way Go's
    /// `pem.EncodeToMemory` writes it, and the chain annotation is what
    /// follows the leaf in Fulcio's answer; the bundle annotation is the
    /// Rekor bundle serialized in cosign's field order.
    #[test]
    fn the_annotations_are_byte_identical_to_cosigns() {
        for layer in cosign_manifest().layers {
            let annotations = layer.annotations.expect("annotations");
            let certificate = &annotations[SIGSTORE_CERT_ANNOTATION];
            let chain = &annotations[SIGSTORE_CHAIN_ANNOTATION];
            let fulcio_answer = format!("{certificate}{chain}");
            let (leaf, split_chain) = split_certificate_chain(&fulcio_answer).expect("split");
            assert_eq!(&split_chain, chain);
            let reencoded = leaf.to_pem(LineEnding::LF).expect("pem");
            assert_eq!(&reencoded, certificate);

            let bundle_json = &annotations[stow_types::bundle::SIGSTORE_BUNDLE_ANNOTATION];
            let bundle: sigstore::cosign::bundle::Bundle =
                serde_json::from_str(bundle_json).expect("bundle");
            assert_eq!(
                &serde_json::to_string(&bundle).expect("bundle json"),
                bundle_json
            );

            // The bundle as Rekor's entry answer carries it.
            let answer = serde_json::json!({
                "24296fb24b8ad77a": {
                    "body": bundle.payload.body,
                    "integratedTime": bundle.payload.integrated_time,
                    "logID": bundle.payload.log_id,
                    "logIndex": bundle.payload.log_index,
                    "verification": { "signedEntryTimestamp": bundle.signed_entry_timestamp },
                }
            });
            let from_answer =
                rekor_bundle(answer.to_string().as_bytes()).expect("answer to bundle");
            assert_eq!(
                &serde_json::to_string(&from_answer).expect("json"),
                bundle_json
            );
        }
    }

    /// A chain with no issuers, or text after the leaf, is refused.
    #[test]
    fn a_malformed_fulcio_chain_fails_fast() {
        let annotations = cosign_manifest()
            .layers
            .remove(0)
            .annotations
            .expect("annotations");
        let certificate = &annotations[SIGSTORE_CERT_ANNOTATION];
        let error = split_certificate_chain(certificate).expect_err("no chain");
        assert!(error.to_string().contains("without its chain"), "{error}");
        let error = split_certificate_chain(&certificate.replace(
            "-----END CERTIFICATE-----\n",
            "-----END CERTIFICATE----- trailing\n",
        ))
        .expect_err("text after END");
        assert!(error.to_string().contains("after the leaf"), "{error}");
        assert!(split_certificate_chain("no pem here").is_err());
    }

    #[test]
    fn the_challenge_is_the_token_subject() {
        let base64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let claims = base64::Engine::encode(
            &base64,
            br#"{"sub":"repo:water-rs/stow:ref:refs/heads/main","aud":"sigstore"}"#,
        );
        assert_eq!(
            token_subject(&format!("e30.{claims}.c2ln")).expect("subject"),
            "repo:water-rs/stow:ref:refs/heads/main"
        );
        assert!(token_subject("opaque").is_err());
        let no_sub = base64::Engine::encode(&base64, br#"{"aud":"sigstore"}"#);
        let error = token_subject(&format!("e30.{no_sub}.c2ln")).expect_err("no sub");
        assert!(error.to_string().contains("`sub`"), "{error}");
    }

    /// A job without `id-token: write` has no OIDC endpoint: the signer
    /// refuses to start and names the variable.
    #[test]
    #[serial_test::serial]
    fn a_job_without_the_oidc_grant_fails_fast() {
        // SAFETY: serialized against every other env-mutating test.
        unsafe {
            std::env::remove_var(super::OIDC_REQUEST_URL_ENV);
            std::env::set_var(super::OIDC_REQUEST_TOKEN_ENV, "token");
        }
        let error = super::SigstoreServices::production_from_env().expect_err("no endpoint");
        assert!(
            error.to_string().contains("ACTIONS_ID_TOKEN_REQUEST_URL"),
            "{error}"
        );
        // SAFETY: as above.
        unsafe {
            std::env::set_var(super::OIDC_REQUEST_URL_ENV, "https://example.invalid/token");
            std::env::remove_var(super::OIDC_REQUEST_TOKEN_ENV);
        }
        let error = super::SigstoreServices::production_from_env().expect_err("no token");
        assert!(
            error.to_string().contains("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
            "{error}"
        );
        // SAFETY: as above.
        unsafe { std::env::remove_var(super::OIDC_REQUEST_URL_ENV) };
    }

    /// Rekor answering anything but one entry is refused.
    #[test]
    fn a_rekor_answer_without_exactly_one_entry_fails_fast() {
        assert!(rekor_bundle(b"{}").is_err());
        assert!(rekor_bundle(b"not json").is_err());
    }
}
