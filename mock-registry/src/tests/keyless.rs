//! Keyless signing end to end against the mock registry and mock Sigstore
//! services: a Fulcio issuing under a throwaway CA, a Rekor signing entry
//! timestamps with a throwaway key, and the job's OIDC token endpoint.
//! Every signature is read back over HTTP and checked by the verifier the
//! CLI and the records readers run.

use std::collections::{BTreeMap, HashMap};
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, CustomExtension, ExtendedKeyUsagePurpose,
    IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PublicKeyData as _, SanType,
};
use sha2::Digest as _;
use sigstore::cosign::bundle::Payload as RekorPayload;
use sigstore::crypto::{CosignVerificationKey, Signature, SigningScheme};
use stow_oci::resign::{Identities, Signers};
use stow_oci::verify::ReleaseIdentity;
use stow_types::api::ArtifactRecord;
use stow_types::bundle::{
    SIGSTORE_BUNDLE_ANNOTATION, SIGSTORE_CERT_ANNOTATION, SIGSTORE_OCI_MEDIA_TYPE,
    SIGSTORE_SIGNATURE_ANNOTATION, sigstore_signature_tag,
};
use stow_types::identity::WireRustcVersion;
use stow_types::records::{BuildRecords, BuildRun};
use stow_types::registry::BUNDLE_TAG_SUFFIX;
use stow_types::trusted_builder::{CERTIFICATE_ISSUER, TrustedWorkflow};
use stow_types::upload_plan::PlannedArtifact;

use super::{RegistryProbe, push_session, serve_probe_registry, test_plan};

/// The exact subject the mock Fulcio issues: the build workflow at a
/// release tag, which the signer's self-check requires.
const CERTIFICATE_IDENTITY: &str =
    "https://github.com/water-rs/stow/.github/workflows/build-crate.yml@refs/tags/v1.2.3";

/// What the readers pin: the build workflow at any release tag.
fn reader_identity() -> ReleaseIdentity {
    ReleaseIdentity::new(TrustedWorkflow::BUILD)
}

/// The OIDC token's subject — Fulcio's proof-of-possession challenge.
const SUBJECT: &str = "repo:water-rs/stow:ref:refs/tags/v1.2.3";
/// The bearer the mock OIDC endpoint takes.
const REQUEST_TOKEN: &str = "mock-request-token";
/// The mock Rekor's log id.
const LOG_ID: &str = "6d6f636b2d7265";
/// The mock Rekor's active tree id in hex — the 16-hex prefix of an entry
/// UUID, as the public-good log's shard 1193050959916656506 prefixes its
/// entries `108e9186e8c5677a`.
const TREE_ID: &str = "108e9186e8c5677a";
const FULCIO_OIDC_ISSUER_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 57264, 1, 1];
/// What a P-256 `SubjectPublicKeyInfo` carries before the curve point.
const P256_SPKI_PREFIX_LEN: usize = 26;

/// The job's identity token: claims naming [`SUBJECT`] for the `sigstore`
/// audience. The mock Fulcio compares it verbatim instead of checking a
/// signature.
fn identity_token() -> String {
    let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(format!(r#"{{"sub":"{SUBJECT}","aud":"sigstore"}}"#));
    format!("e30.{claims}.c2ln")
}

fn unix_now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs(),
    )
    .expect("seconds fit i64")
}

/// A public key Fulcio was sent, as rcgen signs certificates for it.
struct RequestedKey(Vec<u8>);

impl rcgen::PublicKeyData for RequestedKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

/// The mock services' state and the knobs a test turns.
struct Sigstore {
    ca: CertifiedIssuer<'static, KeyPair>,
    rekor_key: KeyPair,
    /// How long an issued certificate is valid.
    lifetime: Duration,
    /// Answer every certificate request with this status instead.
    fulcio_refusal: Option<StatusCode>,
    /// Log the next this-many entries but answer `503`, as an answer lost
    /// on the way back.
    lose_answers: usize,
    /// Answer the next this-many reads of a logged entry `404` with an
    /// empty body, as Rekor answered at the `Location` of a `409` before
    /// its read path served the entry.
    unreadable_reads: usize,
    /// The subject the issued certificates carry; a test sets it before a
    /// signer it builds asks for its certificate.
    identity: String,
    certificates: usize,
    /// Entry reads Rekor answered, served or not.
    reads: usize,
    /// Logged entries by 64-hex entry hash, and the hash of each
    /// canonical body.
    entries: BTreeMap<String, serde_json::Value>,
    by_body: HashMap<String, String>,
}

#[derive(Clone)]
struct MockSigstore {
    state: Arc<Mutex<Sigstore>>,
    origin: String,
}

impl MockSigstore {
    /// Serve fresh mock services on a loopback port.
    async fn serve() -> Self {
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("ca key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_params.not_before =
            time::OffsetDateTime::from_unix_timestamp(unix_now() - 86_400).expect("time");
        ca_params.not_after =
            time::OffsetDateTime::from_unix_timestamp(unix_now() + 86_400).expect("time");
        let state = Arc::new(Mutex::new(Sigstore {
            ca: CertifiedIssuer::self_signed(ca_params, ca_key).expect("ca"),
            rekor_key: KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("rekor key"),
            lifetime: Duration::from_secs(600),
            fulcio_refusal: None,
            lose_answers: 0,
            unreadable_reads: 0,
            identity: CERTIFICATE_IDENTITY.to_owned(),
            certificates: 0,
            reads: 0,
            entries: BTreeMap::new(),
            by_body: HashMap::new(),
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind sigstore");
        let origin = format!("http://{}", listener.local_addr().expect("addr"));
        let app = Router::new()
            .route("/oidc/token", get(oidc_token))
            .route("/fulcio/api/v1/signingCert", post(signing_cert))
            .route("/rekor/api/v1/log/entries", post(log_entry))
            .route("/rekor/api/v1/log/entries/{uuid}", get(read_entry))
            .with_state(Arc::clone(&state));
        tokio::spawn(async move { axum::serve(listener, app).await.expect("serve sigstore") });
        Self { state, origin }
    }

    fn with<T>(&self, f: impl FnOnce(&mut Sigstore) -> T) -> T {
        f(&mut self.state.lock().expect("sigstore state poisoned"))
    }

    fn services(&self) -> stow_oci::SigstoreServices {
        stow_oci::SigstoreServices {
            fulcio_url: format!("{}/fulcio", self.origin),
            rekor_url: format!("{}/rekor", self.origin),
            oidc_request_url: format!("{}/oidc/token?api-version=2.0", self.origin),
            oidc_request_token: REQUEST_TOKEN.to_owned(),
        }
    }

    /// The trust a reader of these services verifies against.
    fn trust(&self) -> Arc<stow_oci::verify::TrustMaterial> {
        self.with(|state| {
            Arc::new(
                stow_oci::verify::TrustMaterial::from_mock_sigstore(
                    &[state.ca.der().clone()],
                    &[(LOG_ID.to_owned(), state.rekor_key.subject_public_key_info())],
                )
                .expect("mock trust"),
            )
        })
    }

    fn certificates(&self) -> usize {
        self.with(|state| state.certificates)
    }

    fn entries(&self) -> usize {
        self.with(|state| state.entries.len())
    }

    fn reads(&self) -> usize {
        self.with(|state| state.reads)
    }
}

type Shared = State<Arc<Mutex<Sigstore>>>;

/// `GET /oidc/token?…&audience=sigstore` with the request bearer.
async fn oidc_token(headers: HeaderMap, Query(query): Query<BTreeMap<String, String>>) -> Response {
    let authorized = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        == Some(&*format!("bearer {REQUEST_TOKEN}"));
    if !authorized || query.get("audience").map(String::as_str) != Some("sigstore") {
        return (StatusCode::UNAUTHORIZED, "bad token request").into_response();
    }
    axum::Json(serde_json::json!({ "value": identity_token() })).into_response()
}

/// `POST /api/v1/signingCert`: check the token and the proof of
/// possession, then issue a leaf for the sent key under the CA, answered
/// as Fulcio answers — the PEM chain, leaf first.
async fn signing_cert(State(state): Shared, headers: HeaderMap, body: Bytes) -> Response {
    let mut state = state.lock().expect("sigstore state poisoned");
    if let Some(status) = state.fulcio_refusal {
        return (status, "token audience rejected").into_response();
    }
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        != Some(&*format!("Bearer {}", identity_token()))
    {
        return (StatusCode::UNAUTHORIZED, "unknown identity token").into_response();
    }
    let request: serde_json::Value = serde_json::from_slice(&body).expect("fulcio request");
    assert_eq!(request["publicKey"]["algorithm"], "ecdsa");
    let base64 = base64::engine::general_purpose::STANDARD;
    let spki = base64
        .decode(request["publicKey"]["content"].as_str().expect("key"))
        .expect("key base64");
    let proof = base64
        .decode(request["signedEmailAddress"].as_str().expect("proof"))
        .expect("proof base64");
    if CosignVerificationKey::from_der(&spki, &SigningScheme::ECDSA_P256_SHA256_ASN1)
        .and_then(|key| key.verify_signature(Signature::Raw(&proof), SUBJECT.as_bytes()))
        .is_err()
    {
        return (StatusCode::BAD_REQUEST, "proof of possession failed").into_response();
    }
    assert_eq!(spki.len(), P256_SPKI_PREFIX_LEN + 65, "a P-256 key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
    params.subject_alt_names = vec![SanType::URI(
        state.identity.as_str().try_into().expect("identity URI"),
    )];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
    params.custom_extensions = vec![CustomExtension::from_oid_content(
        FULCIO_OIDC_ISSUER_OID,
        CERTIFICATE_ISSUER.as_bytes().to_vec(),
    )];
    let now = unix_now();
    params.not_before = time::OffsetDateTime::from_unix_timestamp(now - 1).expect("time");
    params.not_after = time::OffsetDateTime::from_unix_timestamp(
        now + i64::try_from(state.lifetime.as_secs()).expect("lifetime"),
    )
    .expect("time");
    let leaf = params
        .signed_by(
            &RequestedKey(spki[P256_SPKI_PREFIX_LEN..].to_vec()),
            &state.ca,
        )
        .expect("issue leaf");
    state.certificates += 1;
    let chain = format!("{}{}", leaf.pem(), state.ca.pem());
    (
        StatusCode::CREATED,
        [(header::CONTENT_TYPE, "application/pem-certificate-chain")],
        chain,
    )
        .into_response()
}

/// Canonical JSON, as Rekor stores entry bodies and signs timestamps.
fn canonical(value: &impl serde::Serialize) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut serializer =
        serde_json::Serializer::with_formatter(&mut bytes, olpc_cjson::CanonicalFormatter::new());
    value.serialize(&mut serializer).expect("canonical json");
    bytes
}

/// `POST /api/v1/log/entries`: log a `hashedrekord` entry and answer
/// `{uuid: entry}` with a signed entry timestamp; a body already logged
/// answers `409` with the entry's `Location`, as Rekor does. The entry
/// UUID is Rekor's: the tree id, then the RFC 6962 leaf hash of the
/// canonical body.
async fn log_entry(State(state): Shared, body: Bytes) -> Response {
    let mut state = state.lock().expect("sigstore state poisoned");
    let proposed: serde_json::Value = serde_json::from_slice(&body).expect("rekor request");
    assert_eq!(proposed["kind"], "hashedrekord");
    let canonical_body = canonical(&proposed);
    let entry_body = base64::engine::general_purpose::STANDARD.encode(&canonical_body);
    if let Some(hash) = state.by_body.get(&entry_body) {
        let mut response =
            (StatusCode::CONFLICT, "an equivalent entry already exists").into_response();
        response.headers_mut().insert(
            header::LOCATION,
            HeaderValue::from_str(&format!("/rekor/api/v1/log/entries/{TREE_ID}{hash}"))
                .expect("location"),
        );
        return response;
    }
    let payload = RekorPayload {
        body: entry_body.clone(),
        integrated_time: unix_now(),
        log_index: i64::try_from(state.entries.len()).expect("index"),
        log_id: LOG_ID.to_owned(),
    };
    let set = rcgen::SigningKey::sign(&state.rekor_key, &canonical(&payload)).expect("SET");
    let hash = hex::encode(
        sha2::Sha256::new()
            .chain_update([0_u8])
            .chain_update(&canonical_body)
            .finalize(),
    );
    let uuid = format!("{TREE_ID}{hash}");
    let entry = serde_json::json!({
        "body": payload.body,
        "integratedTime": payload.integrated_time,
        "logID": payload.log_id,
        "logIndex": payload.log_index,
        "verification": {
            "signedEntryTimestamp": base64::engine::general_purpose::STANDARD.encode(set),
        },
    });
    state.entries.insert(hash.clone(), entry.clone());
    state.by_body.insert(entry_body, hash);
    if state.lose_answers > 0 {
        state.lose_answers -= 1;
        return (StatusCode::SERVICE_UNAVAILABLE, "answer lost").into_response();
    }
    (
        StatusCode::CREATED,
        axum::Json(serde_json::json!({ uuid: entry })),
    )
        .into_response()
}

/// `GET /api/v1/log/entries/{uuid}`: the entry by its 80-hex UUID or its
/// 64-hex entry hash, answered under the 80-hex UUID as Rekor answers. An
/// entry Rekor does not serve — never logged, or not yet readable — is a
/// `404` with an empty body.
async fn read_entry(State(state): Shared, AxumPath(uuid): AxumPath<String>) -> Response {
    let mut state = state.lock().expect("sigstore state poisoned");
    state.reads += 1;
    let hash = uuid.strip_prefix(TREE_ID).unwrap_or(&uuid);
    let Some(entry) = state.entries.get(hash).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if state.unreadable_reads > 0 {
        state.unreadable_reads -= 1;
        return StatusCode::NOT_FOUND.into_response();
    }
    axum::Json(serde_json::json!({ format!("{TREE_ID}{hash}"): entry })).into_response()
}

/// A budget no test sweep reaches.
fn unbounded() -> stow_oci::WriteBudget {
    stow_oci::WriteBudget::per_minute(NonZeroU32::new(6_000_000).expect("rate"))
}

/// A plan of its own under `root/<index>`: distinct bytes and reference.
fn plan(root: &std::path::Path, index: usize) -> PlannedArtifact {
    let dir = root.join(format!("plan-{index}"));
    std::fs::create_dir_all(&dir).expect("plan dir");
    let mut plan = test_plan(&dir);
    let bytes = format!("the rlib of plan {index}").into_bytes();
    std::fs::write(&plan.outputs[0].path, &bytes).expect("output file");
    plan.outputs[0].bundle_file.sha256 = hex::encode(sha2::Sha256::digest(&bytes));
    plan.artifact_size = bytes.len() as u64;
    plan.oci_reference =
        plan.oci_reference
            .replacen("serde.1.0.0-", &format!("serde.1.0.{index}-"), 1);
    plan
}

/// Everything one test drives: the registry and its probe, the mock
/// services, and a signer over them.
struct Stack {
    _root: tempfile::TempDir,
    root: std::path::PathBuf,
    listen: String,
    probe: RegistryProbe,
    sigstore: MockSigstore,
    http: stow_oci::RegistryHttp,
}

impl Stack {
    async fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let root = tempfile::tempdir().expect("registry root");
        let (listen, probe) = serve_probe_registry(root.path()).await;
        Self {
            root: root.path().to_path_buf(),
            _root: root,
            listen,
            probe,
            sigstore: MockSigstore::serve().await,
            http: stow_oci::RegistryHttp::new(stow_oci::TransportPolicy::PATIENT)
                .await
                .expect("registry http"),
        }
    }

    fn signer(&self) -> stow_oci::KeylessSigner {
        self.signer_trusting(self.sigstore.trust())
    }

    fn signer_trusting(
        &self,
        trust: Arc<stow_oci::verify::TrustMaterial>,
    ) -> stow_oci::KeylessSigner {
        stow_oci::KeylessSigner::new(
            self.http.clone(),
            trust,
            self.sigstore.services(),
            CERTIFICATE_IDENTITY,
        )
    }

    /// A signer whose certificates carry `identity`: the services issue
    /// that subject from now on.
    fn signer_as(&self, identity: &str) -> stow_oci::KeylessSigner {
        self.sigstore
            .with(|state| state.identity = identity.to_owned());
        stow_oci::KeylessSigner::new(
            self.http.clone(),
            self.sigstore.trust(),
            self.sigstore.services(),
            identity,
        )
    }

    fn session(&self, writes: &stow_oci::WriteBudget) -> stow_oci::RegistrySession {
        push_session(&self.listen, &self.http, writes)
    }

    /// Publish `plans` at once through `session`, signing with `signer`;
    /// the row each plan's bundle landed under.
    async fn publish(
        session: &stow_oci::RegistrySession,
        signer: &stow_oci::KeylessSigner,
        plans: &[PlannedArtifact],
    ) -> stow_types::error::Result<Vec<ArtifactRecord>> {
        let sign = |reference: String, digest: String| async move {
            signer.sign_detached(&reference, &digest).await
        };
        let outcomes =
            futures_util::future::try_join_all(plans.iter().map(|plan| {
                stow_oci::push_artifacts_with(session, std::slice::from_ref(plan), &sign)
            }))
            .await?;
        let mut rows = Vec::with_capacity(plans.len());
        for (plan, outcome) in plans.iter().zip(outcomes) {
            rows.extend(row_of(plan, &outcome)?);
        }
        Ok(rows)
    }

    /// Verify the node `row` names from its bundle, as a reader does.
    async fn verify(
        &self,
        session: &stow_oci::RegistrySession,
        row: &ArtifactRecord,
    ) -> stow_types::error::Result<()> {
        stow_oci::pull_bundle(session, row).await?.verify(
            &stow_oci::verify::Trust::GithubCi(self.sigstore.trust()),
            &reader_identity(),
        )
    }

    /// The writes the registry saw.
    fn writes(&self) -> usize {
        self.probe.write_arrivals().len()
    }

    /// The `.sig` manifest of `digest`, parsed.
    fn signature_manifest(&self, digest: &str) -> Option<serde_json::Value> {
        let path = self
            .root
            .join("manifests")
            .join(super::REPOSITORY)
            .join(super::manifest_file_name(&sigstore_signature_tag(digest)));
        std::fs::read(path)
            .ok()
            .map(|bytes| serde_json::from_slice(&bytes).expect("signature manifest json"))
    }
}

/// The row `plan` published as, from its push outcome.
fn row_of(
    plan: &PlannedArtifact,
    outcome: &stow_oci::UploadOutcome,
) -> stow_types::error::Result<Vec<ArtifactRecord>> {
    stow_types::upload_plan::build_artifact_records(
        std::slice::from_ref(plan),
        &outcome.published_by_reference,
        &BTreeMap::from([(plan.oci_reference.clone(), None)]),
    )
}

/// A node's keyless signature travels in its bundle alone and verifies
/// with the reader's verifier; the publish costs three writes — the
/// bundle's layer, config and manifest — and pushes no `.sig` image.
#[tokio::test]
async fn a_keyless_signature_verifies_with_the_readers_verifier() {
    let stack = Stack::new().await;
    let session = stack.session(&unbounded());
    let plans = [plan(&stack.root, 0)];
    let rows = Stack::publish(&session, &stack.signer(), &plans)
        .await
        .expect("publish");
    stack
        .verify(&session, &rows[0])
        .await
        .expect("the signature verifies");

    assert_eq!(stack.sigstore.certificates(), 1);
    assert_eq!(stack.sigstore.entries(), 1);
    assert_eq!(
        stack.writes(),
        3,
        "requests: {:?}",
        stack.probe.request_log()
    );
    assert!(
        stack.signature_manifest(&rows[0].oci_digest).is_none(),
        "a node's signature has no .sig image"
    );
}

/// A signature of a manifest published under its own tag lands in cosign's
/// legacy layout and verifies with the reader's verifier; signing costs
/// three writes — the payload, the config and the `.sig` manifest.
#[tokio::test]
async fn a_signature_image_is_cosigns_legacy_layout() {
    let stack = Stack::new().await;
    let session = stack.session(&unbounded());
    let reference = session.reference("records-layout").expect("reference");
    let digest = stow_types::registry::sha256_digest(b"manifest");
    stack
        .signer()
        .sign(&session, &reference.to_string(), &digest)
        .await
        .expect("sign");
    stow_oci::verify_artifact_signature(
        &session,
        &stow_oci::verify::Trust::GithubCi(stack.sigstore.trust()),
        &reference,
        &reference.to_string(),
        &digest,
        &reader_identity(),
    )
    .await
    .expect("the signature verifies");
    assert_eq!(
        stack.writes(),
        3,
        "requests: {:?}",
        stack.probe.request_log()
    );

    let manifest = stack.signature_manifest(&digest).expect("signature image");
    assert_eq!(
        manifest["config"]["mediaType"],
        "application/vnd.oci.image.config.v1+json"
    );
    let layers = manifest["layers"].as_array().expect("layers");
    assert_eq!(layers.len(), 1);
    assert_eq!(layers[0]["mediaType"], SIGSTORE_OCI_MEDIA_TYPE);
    let annotations = layers[0]["annotations"].as_object().expect("annotations");
    assert_eq!(
        annotations.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            SIGSTORE_SIGNATURE_ANNOTATION,
            SIGSTORE_BUNDLE_ANNOTATION,
            SIGSTORE_CERT_ANNOTATION,
            "dev.sigstore.cosign/chain",
        ]
    );
    let chain = annotations["dev.sigstore.cosign/chain"]
        .as_str()
        .expect("chain");
    assert_eq!(chain, stack.sigstore.with(|state| state.ca.pem()));
}

/// A certificate for any identity but the one the signer is bound to is
/// refused before a signature layer is pushed.
#[tokio::test]
async fn a_certificate_for_another_identity_is_never_published() {
    let stack = Stack::new().await;
    let session = stack.session(&unbounded());
    let reference = session.reference("wrong-identity").expect("reference");
    let digest = stow_types::registry::sha256_digest(b"manifest");
    let other = "https://github.com/water-rs/stow/.github/workflows/repack.yml@refs/tags/v1.2.3";
    let signer = stow_oci::KeylessSigner::new(
        stack.http.clone(),
        stack.sigstore.trust(),
        stack.sigstore.services(),
        other,
    );
    let error = signer
        .sign(&session, &reference.to_string(), &digest)
        .await
        .expect_err("the certificate names another identity");
    assert!(
        format!("{error:?}").contains(other),
        "the error names the required identity: {error:?}"
    );
    assert!(
        stack.signature_manifest(&digest).is_none(),
        "nothing was pushed"
    );
}

/// The in-memory material is the signature published to the registry,
/// including its certificate and Rekor proof, and passes the reader's verifier.
#[tokio::test]
async fn signing_returns_the_verified_published_material() {
    let stack = Stack::new().await;
    let session = stack.session(&unbounded());
    let reference = session.reference("material").expect("reference");
    let digest = stow_types::registry::sha256_digest(b"manifest");
    let material = stack
        .signer()
        .sign(&session, &reference.to_string(), &digest)
        .await
        .expect("sign");
    let stored = stow_oci::pull_signature_materials(&session, &reference, &digest)
        .await
        .expect("stored signature");
    assert_eq!(stored.len(), 1);
    let stored = &stored[0];
    assert_eq!(material.payload_path, stored.payload_path);
    assert_eq!(material.payload_bytes, stored.payload_bytes);
    assert_eq!(material.signature, stored.signature);
    assert_eq!(material.certificate_pem, stored.certificate_pem);
    assert_eq!(material.rekor_bundle_json, stored.rekor_bundle_json);
    stow_oci::verify::verify_materials(
        &stow_oci::verify::Trust::GithubCi(stack.sigstore.trust()),
        &reference.to_string(),
        &digest,
        &[material],
        &reader_identity(),
    )
    .expect("returned material verifies");
}

/// Count full publications across artifact multiplicity and blob upload modes.
#[tokio::test]
async fn complete_publication_counts_artifacts_records_and_signatures() {
    for session_put in [false, true] {
        for artifact_count in 1..=3 {
            publication_write_cost(session_put, artifact_count).await;
        }
    }
}

async fn publication_write_cost(session_put: bool, artifact_count: usize) {
    let stack = Stack::new().await;
    if session_put {
        stack.probe.refuse_single_post();
    }
    let session = stack.session(&unbounded());
    let signer = stack.signer();
    let rustc = stow_types::identity::WireRustcVersion::parse("1.85.0").expect("rustc");
    for index in 0..2 {
        let plans = (0..artifact_count)
            .map(|offset| plan(&stack.root, index * artifact_count + offset))
            .collect::<Vec<_>>();
        let sign_detached = |reference: String, digest: String| {
            let signer = &signer;
            async move { signer.sign_detached(&reference, &digest).await }
        };
        let before = stack.writes();
        let outcome = stow_oci::push_artifacts_with(&session, &plans, &sign_detached)
            .await
            .expect("artifacts");
        let artifacts = stow_types::upload_plan::build_artifact_records(
            &plans,
            &outcome.published_by_reference,
            &plans
                .iter()
                .map(|plan| (plan.oci_reference.clone(), None))
                .collect(),
        )
        .expect("artifact records");
        let records = stow_types::records::BuildRecords {
            artifacts,
            local_programs: Vec::new(),
        };
        stow_oci::push_records_with(
            &session,
            &rustc,
            &format!("task-{index}"),
            stow_types::records::BuildRun {
                run_id: index as u64 + 1,
                run_attempt: 1,
            },
            &records,
            &sign_detached,
        )
        .await
        .expect("signed records");
        // Each artifact pushes its bundle layer + `<tag>.bundle` manifest
        // against the shared `{}` config (uploaded once on the cold first
        // publication); records push their JSON layer + `records-*` and
        // `built-*` manifests with inline signatures and no `.sig` image
        // (stow#1627). A missing blob costs two writes under upload-session
        // `POST` + `PUT` and one under monolithic `POST`.
        let (per_artifact, cold_records, warm_records) =
            if session_put { (3, 6, 4) } else { (2, 4, 3) };
        assert_eq!(
            stack.writes() - before,
            per_artifact * artifact_count
                + if index == 0 {
                    cold_records
                } else {
                    warm_records
                },
            "session_put={session_put} artifacts={artifact_count} publication={index}"
        );
    }
    assert_eq!(stack.sigstore.certificates(), 1);
    assert_eq!(
        stack.sigstore.entries(),
        2 * (artifact_count + 1),
        "each artifact and each node record is signed once"
    );
}

/// One certificate serves every signature while it has more than the
/// renewal margin left; one issued with less is replaced at the next
/// signature. Every signature has its own Rekor entry either way.
#[tokio::test]
async fn the_certificate_is_reused_while_valid_and_renewed_inside_the_margin() {
    let stack = Stack::new().await;
    let session = stack.session(&unbounded());
    let signer = stack.signer();
    let plans = (0..3)
        .map(|index| plan(&stack.root, index))
        .collect::<Vec<_>>();
    let rows = Stack::publish(&session, &signer, &plans)
        .await
        .expect("publish");
    assert_eq!(
        stack.sigstore.certificates(),
        1,
        "one certificate for three signatures"
    );
    assert_eq!(stack.sigstore.entries(), 3, "one Rekor entry per signature");
    for row in &rows {
        stack.verify(&session, row).await.expect("verifies");
    }

    // Two minutes left is inside the four-minute margin.
    stack
        .sigstore
        .with(|state| state.lifetime = Duration::from_secs(120));
    let renewing = stack.signer();
    let plans = (3..5)
        .map(|index| plan(&stack.root, index))
        .collect::<Vec<_>>();
    for plan in &plans {
        let rows = Stack::publish(&session, &renewing, std::slice::from_ref(plan))
            .await
            .expect("publish");
        stack.verify(&session, &rows[0]).await.expect("verifies");
    }
    assert_eq!(
        stack.sigstore.certificates(),
        3,
        "each signature renewed the short certificate"
    );
    assert_eq!(stack.sigstore.entries(), 5);
}

/// The most writes inside any `window` of `arrivals`.
fn peak(arrivals: &[Instant], window: Duration) -> usize {
    let mut start = 0;
    let mut best = 0;
    for (end, arrival) in arrivals.iter().enumerate() {
        while arrival.duration_since(arrivals[start]) >= window {
            start += 1;
        }
        best = best.max(end - start + 1);
    }
    best
}

/// The instants the write budget granted its tokens, read off the
/// `stow_oci::write_budget` events the budget logs as it grants one, for
/// as long as the guard lives on this thread.
struct GrantLog {
    grants: std::sync::Arc<std::sync::Mutex<Vec<Instant>>>,
    _guard: tracing::subscriber::DefaultGuard,
}

struct GrantLayer(std::sync::Arc<std::sync::Mutex<Vec<Instant>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for GrantLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _context: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if event.metadata().target() == "stow_oci::write_budget" {
            self.0.lock().expect("grants poisoned").push(Instant::now());
        }
    }
}

impl GrantLog {
    /// Record grants made on this thread: the test's current-thread
    /// runtime runs the whole publish here.
    fn install() -> Self {
        use tracing_subscriber::layer::SubscriberExt;
        let grants = std::sync::Arc::default();
        let subscriber =
            tracing_subscriber::registry().with(GrantLayer(std::sync::Arc::clone(&grants)));
        Self {
            grants,
            _guard: tracing::subscriber::set_default(subscriber),
        }
    }

    fn instants(&self) -> Vec<Instant> {
        self.grants.lock().expect("grants poisoned").clone()
    }
}

/// A sweep publishing many nodes at once against a registry that caps
/// writes stays under the write budget — no write is ever refused — and
/// completes with one certificate and exactly one Rekor entry per
/// signature: nothing is signed twice.
#[tokio::test]
async fn a_sweep_stays_under_the_write_budget() {
    let stack = Stack::new().await;
    // A sweep runs against a warm repository that already holds the shared
    // `{}` config blob (stow#1627).
    let blobs = stack.root.join("blobs");
    std::fs::create_dir_all(&blobs).expect("blobs dir");
    std::fs::write(
        blobs.join(stow_types::registry::sha256_digest(b"{}").replace(':', "_")),
        b"{}",
    )
    .expect("shared empty config");
    // 3000 a minute is 50 a second with a 50-write bucket: at most 100
    // writes in any second, under the registry's 110.
    stack.probe.cap_writes(110, Duration::from_secs(1));
    let budget = stow_oci::WriteBudget::per_minute(NonZeroU32::new(3000).expect("rate"));
    let grants = GrantLog::install();
    let session = stack.session(&budget);
    // 108 nodes at two writes each: 216 writes, past the budget's
    // 100-write first second.
    let nodes = 108;
    let plans = (0..nodes)
        .map(|index| plan(&stack.root, index))
        .collect::<Vec<_>>();
    let rows = Stack::publish(&session, &stack.signer(), &plans)
        .await
        .expect("the sweep completes");

    assert_eq!(stack.probe.throttled_writes(), 0, "no write was refused");
    let arrivals = stack.probe.write_arrivals();
    let grants = grants.instants();
    assert_eq!(
        arrivals.len(),
        nodes * 2,
        "requests: {:?}",
        stack.probe.request_log()
    );
    // The budget bounds when writes are issued, not when they arrive: a
    // loaded runner can bunch arrivals the publisher spaced out.
    assert_eq!(grants.len(), arrivals.len(), "every write took a grant");
    let peak = peak(&grants, Duration::from_secs(1));
    assert!(peak <= 101, "{peak} writes in one second, over the budget");
    assert_eq!(stack.sigstore.certificates(), 1);
    assert_eq!(stack.sigstore.entries(), nodes);
    for row in &rows {
        stack.verify(&session, row).await.expect("verifies");
    }
}

/// Without a budget that binds, the registry's cap refuses writes; each
/// refusal backs off in place and the sweep still completes without
/// re-signing anything.
#[tokio::test]
async fn a_refused_write_backs_off_in_place_without_re_signing() {
    let stack = Stack::new().await;
    // Twelve nodes publishing at once outrun twenty writes a second.
    stack.probe.cap_writes(20, Duration::from_secs(1));
    let session = stack.session(&unbounded());
    let plans = (0..12)
        .map(|index| plan(&stack.root, index))
        .collect::<Vec<_>>();
    let rows = Stack::publish(&session, &stack.signer(), &plans)
        .await
        .expect("the sweep completes");
    assert!(stack.probe.throttled_writes() > 0, "the cap refused writes");
    assert_eq!(stack.sigstore.certificates(), 1);
    assert_eq!(stack.sigstore.entries(), 12, "no signature was made twice");
    for row in &rows {
        stack.verify(&session, row).await.expect("verifies");
    }
}

/// Each CI job owns its budget and signer. A refusal of every job's
/// artifact manifest must recover without creating another signature.
#[tokio::test]
async fn independent_publishers_recover_without_re_signing() {
    let stack = Stack::new().await;
    let plans = (0..500)
        .map(|index| plan(&stack.root, index))
        .collect::<Vec<_>>();
    let bundle_manifest_path = |plan: &PlannedArtifact| {
        let reference: stow_oci::Reference = plan.oci_reference.parse().expect("reference");
        format!(
            "/manifests/{}{BUNDLE_TAG_SUFFIX}",
            reference.tag().expect("artifact tag")
        )
    };
    for plan in &plans {
        stack
            .probe
            .rate_limit(Method::PUT, &bundle_manifest_path(plan), 1);
    }
    // All 500 jobs are polled concurrently, each with an independent
    // 1500-write/minute budget, matching the production default.
    futures_util::future::try_join_all(plans.iter().enumerate().map(|(index, plan)| {
        let stack = &stack;
        async move {
            let budget = stow_oci::WriteBudget::per_minute(NonZeroU32::new(1500).expect("rate"));
            let http = stow_oci::RegistryHttp::new(stow_oci::TransportPolicy::PATIENT).await?;
            let session = push_session(&stack.listen, &http, &budget);
            let signer = stow_oci::KeylessSigner::new(
                http,
                stack.sigstore.trust(),
                stack.sigstore.services(),
                CERTIFICATE_IDENTITY,
            );
            let sign_detached = |reference: String, digest: String| {
                let signer = &signer;
                async move { signer.sign_detached(&reference, &digest).await }
            };
            let outcome =
                stow_oci::push_artifacts_with(&session, std::slice::from_ref(plan), &sign_detached)
                    .await?;
            let artifacts = row_of(plan, &outcome)?;
            let records = stow_types::records::BuildRecords {
                artifacts: artifacts.clone(),
                local_programs: Vec::new(),
            };
            let published_records = stow_oci::push_records_with(
                &session,
                &stow_types::identity::WireRustcVersion::parse("1.85.0")?,
                &format!("task-{index}"),
                stow_types::records::BuildRun {
                    run_id: index as u64 + 1,
                    run_attempt: 1,
                },
                &records,
                &sign_detached,
            )
            .await?;
            let pulled = stow_oci::pull_records_by_tag(&session, &published_records.tag).await?;
            pulled.verify(
                &stow_oci::verify::Trust::GithubCi(stack.sigstore.trust()),
                &published_records.oci_reference,
                &reader_identity(),
            )?;
            stack.verify(&session, &artifacts[0]).await?;
            Ok::<_, stow_types::error::Error>(())
        }
    }))
    .await
    .expect("all independent publications recover");
    assert_eq!(stack.sigstore.certificates(), plans.len());
    assert_eq!(stack.sigstore.entries(), plans.len() * 2);
    let requests = stack.probe.request_log();
    for plan in &plans {
        let path = bundle_manifest_path(plan);
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method == Method::PUT && request.path.ends_with(&path))
                .count(),
            2,
            "one refusal and one successful bundle manifest write"
        );
    }
}

/// A Rekor answer lost on the way back is retried; the retry meets the
/// logged entry (`409`), reads it back, and the signature has one entry.
#[tokio::test]
async fn a_lost_rekor_answer_reads_the_logged_entry_back() {
    let stack = Stack::new().await;
    stack.sigstore.with(|state| state.lose_answers = 1);
    let session = stack.session(&unbounded());
    let plans = [plan(&stack.root, 0)];
    let rows = Stack::publish(&session, &stack.signer(), &plans)
        .await
        .expect("publish");
    assert_eq!(stack.sigstore.entries(), 1);
    assert_eq!(stack.sigstore.reads(), 1);
    stack.verify(&session, &rows[0]).await.expect("verifies");
}

/// Rekor's real shape after a lost answer: the retry meets `409`, and the
/// entry its `Location` names answers `404` until Rekor's read path serves
/// it. The read-back waits that out, and the signature completes with one
/// entry and verifies.
#[tokio::test]
async fn a_logged_entry_not_yet_readable_is_read_back_once_it_is() {
    let stack = Stack::new().await;
    stack.sigstore.with(|state| {
        state.lose_answers = 1;
        state.unreadable_reads = 2;
    });
    let session = stack.session(&unbounded());
    let plans = [plan(&stack.root, 0)];
    let rows = Stack::publish(&session, &stack.signer(), &plans)
        .await
        .expect("publish");
    assert_eq!(stack.sigstore.entries(), 1, "no signature was logged twice");
    assert_eq!(stack.sigstore.reads(), 3, "two 404s, then the entry");
    stack.verify(&session, &rows[0]).await.expect("verifies");
}

/// A refused certificate request fails the signature with Fulcio's own
/// answer, and nothing of the node is written: it is signed before its
/// bundle is pushed.
#[tokio::test]
async fn a_refused_certificate_fails_fast_and_writes_no_signature() {
    let stack = Stack::new().await;
    stack
        .sigstore
        .with(|state| state.fulcio_refusal = Some(StatusCode::UNAUTHORIZED));
    let session = stack.session(&unbounded());
    let plans = [plan(&stack.root, 0)];
    let error = Stack::publish(&session, &stack.signer(), &plans)
        .await
        .expect_err("signing fails");
    let message = error.to_string();
    assert!(message.contains("Fulcio refused"), "{message}");
    assert!(message.contains("401"), "{message}");
    assert!(message.contains("token audience rejected"), "{message}");
    assert_eq!(stack.writes(), 0, "nothing of the node is written");
    assert_eq!(stack.sigstore.entries(), 0);
}

/// A signature that would not verify against the trust root — here, a
/// certificate from a CA the signer does not trust — is refused before
/// anything of it is pushed.
#[tokio::test]
async fn a_signature_the_trust_root_rejects_is_never_pushed() {
    let stack = Stack::new().await;
    let elsewhere = MockSigstore::serve().await;
    let session = stack.session(&unbounded());
    let plans = [plan(&stack.root, 0)];
    let error = Stack::publish(&session, &stack.signer_trusting(elsewhere.trust()), &plans)
        .await
        .expect_err("signing fails");
    let message = error.to_string();
    assert!(
        message.contains("does not verify against the Sigstore trust root"),
        "{message}"
    );
    assert_eq!(stack.writes(), 0, "nothing of the node is written");
}

// ---- the one-time re-sign from the branch identity to a release tag ----

/// The subject the build workflow signed under before the release-tag
/// switch.
const OLD_IDENTITY: &str =
    "https://github.com/water-rs/stow/.github/workflows/build-crate.yml@refs/heads/main";

/// The policy the old signatures verify under.
fn old_identity() -> stow_oci::resign::ExactIdentity {
    stow_oci::resign::ExactIdentity::new(OLD_IDENTITY, CERTIFICATE_ISSUER)
}

/// A task of two nodes signed under the old identity: its signed records,
/// and the rows they name.
struct OldTask {
    tag: String,
    rows: Vec<ArtifactRecord>,
}

impl Stack {
    async fn publish_old_task(&self, session: &stow_oci::RegistrySession) -> OldTask {
        let old_signer = self.signer_as(OLD_IDENTITY);
        let sign_detached = |reference: String, digest: String| {
            let signer = &old_signer;
            async move { signer.sign_detached(&reference, &digest).await }
        };
        let plans = vec![plan(&self.root, 0), plan(&self.root, 1)];
        let outcome = stow_oci::push_artifacts_with(session, &plans, &sign_detached)
            .await
            .expect("a build publishes");
        let rows = stow_types::upload_plan::build_artifact_records(
            &plans,
            &outcome.published_by_reference,
            &plans
                .iter()
                .map(|plan| (plan.oci_reference.clone(), None))
                .collect(),
        )
        .expect("records");
        let rustc = WireRustcVersion::parse(super::RUSTC).expect("rustc");
        let pushed = stow_oci::push_records_with(
            session,
            &rustc,
            "serde-1.0.0-task",
            BuildRun {
                run_id: 1,
                run_attempt: 1,
            },
            &BuildRecords {
                artifacts: rows.clone(),
                local_programs: Vec::new(),
            },
            &sign_detached,
        )
        .await
        .expect("records publish");
        OldTask {
            tag: pushed.tag,
            rows,
        }
    }

    /// Whether the `.sig`-signed manifest under `tag` verifies under `policy`.
    async fn tag_verifies(
        &self,
        session: &stow_oci::RegistrySession,
        tag: &str,
        digest: &str,
        policy: &(impl stow_oci::resign::VerificationPolicy + Sync),
    ) -> bool {
        let reference = session.reference(tag).expect("reference");
        stow_oci::verify_artifact_signature(
            session,
            &stow_oci::verify::Trust::GithubCi(self.sigstore.trust()),
            &reference,
            &reference.to_string(),
            digest,
            policy,
        )
        .await
        .is_ok()
    }

    /// Whether the records artifact under `tag` verifies under `policy` as
    /// a reader checks its inline signature envelope.
    async fn records_tag_verifies(
        &self,
        session: &stow_oci::RegistrySession,
        tag: &str,
        policy: &(impl stow_oci::resign::VerificationPolicy + Sync),
    ) -> bool {
        let reference = session.reference(tag).expect("reference");
        let pulled = stow_oci::pull_records_by_tag(session, tag)
            .await
            .expect("records pull");
        pulled
            .verify(
                &stow_oci::verify::Trust::GithubCi(self.sigstore.trust()),
                &reference.to_string(),
                policy,
            )
            .is_ok()
    }
}

/// Whether the bundle `row` names verifies under the new identity or,
/// when `new_identity` is false, the old one.
async fn bundle_verifies(
    session: &stow_oci::RegistrySession,
    trust: &stow_oci::verify::Trust,
    row: &stow_types::api::ArtifactRecord,
    new_identity: bool,
) -> bool {
    if new_identity {
        stow_oci::resign::bundle_verifies(session, trust, row, &reader_identity()).await
    } else {
        stow_oci::resign::bundle_verifies(session, trust, row, &old_identity()).await
    }
    .expect("the bundle reads")
}

/// A task's records and nodes signed under the old identity verify under
/// the new one only after the re-sign: the records gain a signature, each
/// node is republished with a bundle carrying the new signature alone, and
/// a new records artifact names the new bundles. A rerun writes nothing.
#[tokio::test]
async fn a_task_signed_under_the_old_identity_resigns_under_the_new_one() {
    let stack = Stack::new().await;
    let session = stack.session(&unbounded());
    let trust = stow_oci::verify::Trust::GithubCi(stack.sigstore.trust());
    let rustc = WireRustcVersion::parse(super::RUSTC).expect("rustc");
    let task = stack.publish_old_task(&session).await;

    assert!(
        !stack
            .records_tag_verifies(&session, &task.tag, &reader_identity())
            .await,
        "the old records do not verify under the release-tag identity"
    );
    assert!(
        stack
            .records_tag_verifies(&session, &task.tag, &old_identity())
            .await
    );

    let new_signer = stack.signer_as(CERTIFICATE_IDENTITY);
    let sign_detached = |reference: String, digest: String| {
        let signer = &new_signer;
        async move { signer.sign_detached(&reference, &digest).await }
    };
    let signers = || Signers {
        records: &sign_detached,
        node: &sign_detached,
    };
    let resigned = stow_oci::resign::resign_task(
        &session,
        &trust,
        &rustc,
        &[task.tag.as_str()],
        Identities {
            old: &old_identity(),
            new: &reader_identity(),
        },
        BuildRun {
            run_id: 2,
            run_attempt: 1,
        },
        signers(),
    )
    .await
    .expect("the task re-signs");
    assert_eq!(
        (
            resigned.records_signed,
            resigned.records_already,
            resigned.nodes_republished,
            resigned.nodes_already
        ),
        (1, 0, 2, 0)
    );
    assert!(
        stack
            .records_tag_verifies(&session, &task.tag, &reader_identity())
            .await,
        "the old records artifact now verifies under the new identity"
    );

    let published = resigned.published.expect("a new records artifact");
    assert!(
        stack
            .records_tag_verifies(&session, &published.tag, &reader_identity())
            .await
    );
    let new_rows = stow_oci::pull_records_by_tag(&session, &published.tag)
        .await
        .expect("new records")
        .records
        .artifacts;
    assert_eq!(new_rows.len(), task.rows.len());
    for (old_row, new_row) in task.rows.iter().zip(&new_rows) {
        assert_eq!(
            new_row.oci_digest, old_row.oci_digest,
            "the node is the same"
        );
        assert_ne!(new_row.bundle_digest, old_row.bundle_digest);
        stack
            .verify(&session, new_row)
            .await
            .expect("the node verifies under the new identity");
        let verifies = |row, new_identity| bundle_verifies(&session, &trust, row, new_identity);
        assert!(verifies(new_row, true).await);
        assert!(!verifies(new_row, false).await);
        assert!(verifies(old_row, false).await);
        assert!(!verifies(old_row, true).await);
    }

    // A rerun over every records tag the repository now holds finds all of
    // it done.
    let writes = stack.writes();
    let rerun = stow_oci::resign::resign_task(
        &session,
        &trust,
        &rustc,
        &[published.tag.as_str(), task.tag.as_str()],
        Identities {
            old: &old_identity(),
            new: &reader_identity(),
        },
        BuildRun {
            run_id: 3,
            run_attempt: 1,
        },
        signers(),
    )
    .await
    .expect("the rerun");
    assert_eq!(
        (
            rerun.records_signed,
            rerun.records_already,
            rerun.nodes_republished,
            rerun.nodes_already
        ),
        (0, 2, 0, 2)
    );
    assert!(rerun.published.is_none());
    assert_eq!(stack.writes(), writes, "a rerun writes nothing");
}

/// An index slice signed under the old identity gains a signature at the
/// same digest, a signature of any other identity is refused, and a rerun
/// writes nothing.
#[tokio::test]
async fn an_index_slice_signed_under_the_old_identity_resigns_under_the_new_one() {
    let stack = Stack::new().await;
    let session = stack.session(&unbounded());
    let trust = stow_oci::verify::Trust::GithubCi(stack.sigstore.trust());
    let tag = stow_types::index::index_tag(super::TARGET, super::RUSTC);
    let reference = session.reference(&tag).expect("reference");

    let layer = b"an index slice".to_vec();
    let layer_digest = stow_types::registry::sha256_digest(&layer);
    let config = b"{}".to_vec();
    let config_digest = stow_types::registry::sha256_digest(&config);
    session
        .push_blob(&layer_digest, &layer)
        .await
        .expect("layer");
    session
        .push_blob(&config_digest, &config)
        .await
        .expect("config");
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": stow_types::bundle::OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        "config": {
            "mediaType": stow_types::index::STOW_INDEX_CONFIG_MEDIA_TYPE,
            "digest": config_digest,
            "size": config.len(),
        },
        "layers": [{
            "mediaType": stow_types::index::STOW_INDEX_MEDIA_TYPE,
            "digest": layer_digest,
            "size": layer.len(),
        }],
    }))
    .expect("manifest");
    let session = &session;
    let sign_as = |identity: &str| {
        let signer = stack.signer_as(identity);
        move |reference: String, digest: String| {
            let signer = signer.clone();
            async move { signer.sign(session, &reference, &digest).await }
        }
    };
    let signed_by_other =
        sign_as("https://github.com/water-rs/stow/.github/workflows/other.yml@refs/heads/main");
    let digest = stow_oci::put_signed_manifest(session, &reference, &manifest, |digest| {
        signed_by_other(reference.to_string(), digest)
    })
    .await
    .expect("publish")
    .digest;

    let resign = |sign| {
        let (trust, reference, digest) = (&trust, &reference, &digest);
        async move {
            stow_oci::resign::resign_manifest(
                session,
                trust,
                reference,
                &reference.to_string(),
                digest,
                Identities {
                    old: &old_identity(),
                    new: &reader_identity(),
                },
                &sign,
            )
            .await
        }
    };
    let error = resign(sign_as(CERTIFICATE_IDENTITY))
        .await
        .expect_err("a signature of another identity is not re-signed");
    assert!(format!("{error:?}").contains("old identity"), "{error:?}");
    assert!(
        !stack
            .tag_verifies(session, &tag, &digest, &reader_identity())
            .await
    );

    // The same manifest signed under the old identity re-signs.
    sign_as(OLD_IDENTITY)(reference.to_string(), digest.clone())
        .await
        .expect("old signature");
    assert_eq!(
        resign(sign_as(CERTIFICATE_IDENTITY))
            .await
            .expect("re-signs"),
        stow_oci::resign::Resigned::Signed
    );
    assert!(
        stack
            .tag_verifies(session, &tag, &digest, &reader_identity())
            .await
    );
    let pulled = stow_oci::pull_index(session, super::TARGET, super::RUSTC)
        .await
        .expect("pull")
        .expect("published");
    assert_eq!(pulled.manifest_digest, digest, "the slice is untouched");

    let writes = stack.writes();
    assert_eq!(
        resign(sign_as(CERTIFICATE_IDENTITY)).await.expect("rerun"),
        stow_oci::resign::Resigned::Already
    );
    assert_eq!(stack.writes(), writes, "a rerun writes nothing");
}

/// Duplicate-dispatch retagging reads the `built-*` marker's inline signed
/// manifest, signs it for the new run's `records-*` tag, and writes only
/// that one manifest (stow#1627).
#[tokio::test]
async fn retag_records_writes_one_manifest_and_verifies() {
    let stack = Stack::new().await;
    let session = stack.session(&unbounded());
    let signer = stack.signer();
    let trust = stow_oci::verify::Trust::GithubCi(stack.sigstore.trust());
    let rustc = WireRustcVersion::parse(super::RUSTC).expect("rustc");
    let task_id = "serde-1.0.0-dup-task";

    let sign_detached = |reference: String, digest: String| {
        let signer = &signer;
        async move { signer.sign_detached(&reference, &digest).await }
    };
    let first = stow_oci::push_records_with(
        &session,
        &rustc,
        task_id,
        BuildRun {
            run_id: 10,
            run_attempt: 1,
        },
        &BuildRecords::default(),
        &sign_detached,
    )
    .await
    .expect("first publish");

    let marker_tag = stow_types::records::published_tag(rustc.as_str(), task_id);
    let marker_ref = session.reference(&marker_tag).expect("marker ref");
    let marker_repo = format!("{}/{}", marker_ref.registry(), marker_ref.repository());
    let marker = stow_oci::pull_optional_records_by_tag(&session, &marker_tag)
        .await
        .expect("pull marker")
        .expect("marker exists");
    assert!(marker.verify_marker(&trust, &marker_repo, rustc.as_str(), &reader_identity()));

    let before = stack.writes();
    let second = stow_oci::retag_records_with(
        &session,
        &rustc,
        task_id,
        BuildRun {
            run_id: 11,
            run_attempt: 1,
        },
        &marker.envelope.signed_manifest,
        &sign_detached,
    )
    .await
    .expect("retag");
    assert_eq!(
        stack.writes() - before,
        1,
        "retagging writes only the new records-* manifest"
    );
    assert_eq!(second.signed_digest, first.signed_digest);
    assert!(
        stack
            .records_tag_verifies(&session, &second.tag, &reader_identity())
            .await
    );
}

/// Legacy `records-*` and `built-*` tags backed by standalone `.sig` images
/// are rejected by normal readers until migrated, convert in one manifest
/// `PUT` per tag without minting new signatures, and write nothing on rerun
/// (stow#1627).
#[tokio::test]
async fn legacy_records_and_markers_migrate_inline_and_rerun_writes_nothing() {
    let stack = Stack::new().await;
    let session = stack.session(&unbounded());
    let signer = stack.signer();
    let trust = stow_oci::verify::Trust::GithubCi(stack.sigstore.trust());
    let rustc = WireRustcVersion::parse(super::RUSTC).expect("rustc");
    let task_id = "legacy-task-1.0.0";
    let tag = stow_types::records::records_tag(
        rustc.as_str(),
        task_id,
        BuildRun {
            run_id: 7,
            run_attempt: 1,
        },
    );
    let marker_tag = stow_types::records::published_tag(rustc.as_str(), task_id);
    let reference = session.reference(&tag).expect("records ref");
    let marker_ref = session.reference(&marker_tag).expect("marker ref");

    let body = serde_json::to_vec(&BuildRecords::default()).expect("body");
    let layer_digest = stow_types::registry::sha256_digest(&body);
    let config = b"{}";
    let config_digest = stow_types::registry::sha256_digest(config);
    session
        .push_blob(&layer_digest, &body)
        .await
        .expect("layer");
    session
        .push_blob(&config_digest, config)
        .await
        .expect("config");
    let legacy_manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": stow_types::bundle::OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        "artifactType": stow_types::records::RECORDS_ARTIFACT_TYPE,
        "config": {
            "mediaType": stow_types::records::RECORDS_CONFIG_MEDIA_TYPE,
            "digest": config_digest,
            "size": config.len(),
        },
        "layers": [{
            "mediaType": stow_types::records::RECORDS_ARTIFACT_TYPE,
            "digest": layer_digest,
            "size": body.len(),
        }],
        "annotations": {
            stow_types::records::RECORDS_TASK_ID_ANNOTATION: task_id,
        },
    }))
    .expect("legacy manifest");
    let session_ref = &session;
    let signer_ref = &signer;
    let ref_str = reference.to_string();
    stow_oci::put_signed_manifest(&session, &reference, &legacy_manifest, |digest| {
        let ref_str = ref_str.clone();
        async move { signer_ref.sign(session_ref, &ref_str, &digest).await }
    })
    .await
    .expect("legacy signed push");
    session
        .put_manifest(&marker_ref, &legacy_manifest)
        .await
        .expect("legacy marker");

    // Normal readers do not fall back to `.sig`.
    assert!(stow_oci::pull_records_by_tag(&session, &tag).await.is_err());

    let entries_before = stack.sigstore.entries();
    let writes_before = stack.writes();
    let migrated = stow_oci::migrate_records::migrate_records_tag(
        &session,
        &trust,
        &ref_str,
        &tag,
        &reader_identity(),
    )
    .await
    .expect("migrate records");
    let stow_oci::migrate_records::RecordsTagMigration::Migrated { outer_bytes } = migrated else {
        panic!("expected Migrated");
    };
    let marker_repo = format!("{}/{}", marker_ref.registry(), marker_ref.repository());
    let marker_migrated = stow_oci::migrate_records::migrate_marker_tag(
        &session,
        &trust,
        &marker_repo,
        rustc.as_str(),
        &marker_tag,
        Some(&outer_bytes),
        &reader_identity(),
    )
    .await
    .expect("migrate marker");
    assert!(matches!(
        marker_migrated,
        stow_oci::migrate_records::RecordsTagMigration::Migrated { .. }
    ));
    assert_eq!(
        stack.writes() - writes_before,
        2,
        "one PUT per migrated tag"
    );
    assert_eq!(
        stack.sigstore.entries(),
        entries_before,
        "migration mints no new Rekor signature"
    );

    assert!(
        stack
            .records_tag_verifies(&session, &tag, &reader_identity())
            .await
    );
    let pulled_marker = stow_oci::pull_records_by_tag(&session, &marker_tag)
        .await
        .expect("pull migrated marker");
    assert!(pulled_marker.verify_marker(&trust, &marker_repo, rustc.as_str(), &reader_identity()));

    let writes_rerun = stack.writes();
    assert!(matches!(
        stow_oci::migrate_records::migrate_records_tag(
            &session,
            &trust,
            &ref_str,
            &tag,
            &reader_identity(),
        )
        .await
        .expect("rerun records"),
        stow_oci::migrate_records::RecordsTagMigration::Already { .. }
    ));
    assert!(matches!(
        stow_oci::migrate_records::migrate_marker_tag(
            &session,
            &trust,
            &marker_repo,
            rustc.as_str(),
            &marker_tag,
            Some(&outer_bytes),
            &reader_identity(),
        )
        .await
        .expect("rerun marker"),
        stow_oci::migrate_records::RecordsTagMigration::Already { .. }
    ));
    assert_eq!(stack.writes(), writes_rerun, "a rerun writes nothing");
}

#[tokio::test]
async fn legacy_standalone_sig_records_and_markers_under_old_identity_resign_in_one_pass() {
    let stack = Stack::new().await;
    let session = stack.session(&unbounded());
    let trust = stow_oci::verify::Trust::GithubCi(stack.sigstore.trust());
    let rustc = WireRustcVersion::parse(super::RUSTC).expect("rustc");
    let old_signer = stack.signer_as(OLD_IDENTITY);
    let old_detached = |reference: String, digest: String| {
        let signer = &old_signer;
        async move { signer.sign_detached(&reference, &digest).await }
    };

    let plans = vec![plan(&stack.root, 0)];
    let outcome = stow_oci::push_artifacts_with(&session, &plans, &old_detached)
        .await
        .expect("old bundle publish");
    let rows = stow_types::upload_plan::build_artifact_records(
        &plans,
        &outcome.published_by_reference,
        &plans
            .iter()
            .map(|plan| (plan.oci_reference.clone(), None))
            .collect(),
    )
    .expect("records");

    let push_legacy = |task_id: &'static str, records: BuildRecords| {
        let session = &session;
        let old_signer = &old_signer;
        let rustc = &rustc;
        async move {
            let tag = stow_types::records::records_tag(
                rustc.as_str(),
                task_id,
                BuildRun {
                    run_id: 1,
                    run_attempt: 1,
                },
            );
            let marker_tag = stow_types::records::published_tag(rustc.as_str(), task_id);
            let reference = session.reference(&tag).expect("records ref");
            let marker_ref = session.reference(&marker_tag).expect("marker ref");
            let body = serde_json::to_vec(&records).expect("body");
            let layer_digest = stow_types::registry::sha256_digest(&body);
            let config = b"{}";
            let config_digest = stow_types::registry::sha256_digest(config);
            session
                .push_blob(&layer_digest, &body)
                .await
                .expect("layer");
            session
                .push_blob(&config_digest, config)
                .await
                .expect("config");
            let legacy_manifest = serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "mediaType": stow_types::bundle::OCI_IMAGE_MANIFEST_MEDIA_TYPE,
                "artifactType": stow_types::records::RECORDS_ARTIFACT_TYPE,
                "config": {
                    "mediaType": stow_types::records::RECORDS_CONFIG_MEDIA_TYPE,
                    "digest": config_digest,
                    "size": config.len(),
                },
                "layers": [{
                    "mediaType": stow_types::records::RECORDS_ARTIFACT_TYPE,
                    "digest": layer_digest,
                    "size": body.len(),
                }],
                "annotations": {
                    stow_types::records::RECORDS_TASK_ID_ANNOTATION: task_id,
                },
            }))
            .expect("legacy manifest");
            let ref_str = reference.to_string();
            stow_oci::put_signed_manifest(session, &reference, &legacy_manifest, |digest| {
                let ref_str = ref_str.clone();
                async move { old_signer.sign(session, &ref_str, &digest).await }
            })
            .await
            .expect("legacy signed push");
            let marker_str = ref_str.clone();
            stow_oci::put_signed_manifest(session, &marker_ref, &legacy_manifest, |digest| {
                let marker_str = marker_str.clone();
                async move { old_signer.sign(session, &marker_str, &digest).await }
            })
            .await
            .expect("legacy marker push");
            (tag, marker_tag)
        }
    };

    // Task 1: legacy `.sig` + `@refs/heads/main` with live node bundle.
    let (node_tag, node_marker) = push_legacy(
        "legacy-node-task",
        BuildRecords {
            artifacts: rows.clone(),
            local_programs: Vec::new(),
        },
    )
    .await;
    // Task 2: orphan legacy `.sig` `built-*` marker signed under `@refs/heads/main`.
    let (_, orphan_marker) = push_legacy("legacy-orphan-task", BuildRecords::default()).await;

    let new_signer = stack.signer_as(CERTIFICATE_IDENTITY);
    let sign_detached = |reference: String, digest: String| {
        let signer = &new_signer;
        async move { signer.sign_detached(&reference, &digest).await }
    };
    let identities = Identities {
        old: &old_identity(),
        new: &reader_identity(),
    };
    let resigned = stow_oci::resign::resign_task(
        &session,
        &trust,
        &rustc,
        &[node_tag.as_str()],
        identities,
        BuildRun {
            run_id: 2,
            run_attempt: 1,
        },
        Signers {
            records: &sign_detached,
            node: &sign_detached,
        },
    )
    .await
    .expect("legacy .sig task re-signs");
    assert_eq!(
        (resigned.records_signed, resigned.nodes_republished),
        (1, 1)
    );
    let published = resigned.published.expect("republished task records");
    assert!(
        stack
            .records_tag_verifies(&session, &node_tag, &reader_identity())
            .await
    );
    assert!(
        stack
            .records_tag_verifies(&session, &published.tag, &reader_identity())
            .await
    );
    assert_eq!(
        stow_oci::resign::resign_marker(
            &session,
            &trust,
            &rustc,
            &node_marker,
            None,
            identities,
            &sign_detached,
        )
        .await
        .expect("task marker already updated by push_records_with"),
        stow_oci::resign::Resigned::Already
    );
    assert_eq!(
        stow_oci::resign::resign_marker(
            &session,
            &trust,
            &rustc,
            &orphan_marker,
            None,
            identities,
            &sign_detached,
        )
        .await
        .expect("orphan legacy marker re-signs in place"),
        stow_oci::resign::Resigned::Signed
    );

    let writes_before = stack.writes();
    let rerun = stow_oci::resign::resign_task(
        &session,
        &trust,
        &rustc,
        &[published.tag.as_str(), node_tag.as_str()],
        identities,
        BuildRun {
            run_id: 3,
            run_attempt: 1,
        },
        Signers {
            records: &sign_detached,
            node: &sign_detached,
        },
    )
    .await
    .expect("rerun succeeds");
    assert_eq!(
        (
            rerun.records_signed,
            rerun.records_already,
            rerun.nodes_republished,
            rerun.nodes_already
        ),
        (0, 2, 0, 1)
    );
    assert_eq!(
        stow_oci::resign::resign_marker(
            &session,
            &trust,
            &rustc,
            &orphan_marker,
            None,
            identities,
            &sign_detached,
        )
        .await
        .expect("rerun orphan marker"),
        stow_oci::resign::Resigned::Already
    );
    assert_eq!(stack.writes(), writes_before, "rerun writes nothing");
}
