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
use stow_types::bundle::{
    SIGSTORE_BUNDLE_ANNOTATION, SIGSTORE_CERT_ANNOTATION, SIGSTORE_OCI_MEDIA_TYPE,
    SIGSTORE_SIGNATURE_ANNOTATION, sigstore_signature_tag,
};
use stow_types::trusted_builder::{CERTIFICATE_IDENTITY, CERTIFICATE_ISSUER};
use stow_types::upload_plan::PlannedArtifact;

use super::{RegistryProbe, push_session, serve_probe_registry, test_plan};

/// The OIDC token's subject — Fulcio's proof-of-possession challenge.
const SUBJECT: &str = "repo:water-rs/stow:ref:refs/heads/main";
/// The bearer the mock OIDC endpoint takes.
const REQUEST_TOKEN: &str = "mock-request-token";
/// The mock Rekor's log id.
const LOG_ID: &str = "6d6f636b2d7265";
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
    certificates: usize,
    /// Logged entries by uuid, and the uuid of each canonical body.
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
            certificates: 0,
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
        CERTIFICATE_IDENTITY.try_into().expect("identity URI"),
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
/// answers `409` with the entry's `Location`, as Rekor does.
async fn log_entry(State(state): Shared, body: Bytes) -> Response {
    let mut state = state.lock().expect("sigstore state poisoned");
    let proposed: serde_json::Value = serde_json::from_slice(&body).expect("rekor request");
    assert_eq!(proposed["kind"], "hashedrekord");
    let entry_body = base64::engine::general_purpose::STANDARD.encode(canonical(&proposed));
    if let Some(uuid) = state.by_body.get(&entry_body) {
        let mut response =
            (StatusCode::CONFLICT, "an equivalent entry already exists").into_response();
        response.headers_mut().insert(
            header::LOCATION,
            HeaderValue::from_str(&format!("/rekor/api/v1/log/entries/{uuid}")).expect("location"),
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
    let uuid = hex::encode(sha2::Sha256::digest(entry_body.as_bytes()));
    let entry = serde_json::json!({
        "body": payload.body,
        "integratedTime": payload.integrated_time,
        "logID": payload.log_id,
        "logIndex": payload.log_index,
        "verification": {
            "signedEntryTimestamp": base64::engine::general_purpose::STANDARD.encode(set),
        },
    });
    state.entries.insert(uuid.clone(), entry.clone());
    state.by_body.insert(entry_body, uuid.clone());
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

/// `GET /api/v1/log/entries/{uuid}`.
async fn read_entry(State(state): Shared, AxumPath(uuid): AxumPath<String>) -> Response {
    let state = state.lock().expect("sigstore state poisoned");
    state.entries.get(&uuid).map_or_else(
        || StatusCode::NOT_FOUND.into_response(),
        |entry| axum::Json(serde_json::json!({ uuid: entry })).into_response(),
    )
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
        stow_oci::KeylessSigner::new(self.http.clone(), trust, self.sigstore.services())
    }

    fn session(&self, writes: &stow_oci::WriteBudget) -> stow_oci::RegistrySession {
        push_session(&self.listen, &self.http, writes)
    }

    /// Publish `plans` at once through `session`, signing with `signer`;
    /// the digest each plan's manifest landed under.
    async fn publish(
        session: &stow_oci::RegistrySession,
        signer: &stow_oci::KeylessSigner,
        plans: &[PlannedArtifact],
    ) -> stow_types::error::Result<Vec<String>> {
        let sign = |reference: String, digest: String| async move {
            signer.sign(session, &reference, &digest).await
        };
        let outcomes =
            futures_util::future::try_join_all(plans.iter().map(|plan| {
                stow_oci::push_artifacts_with(session, std::slice::from_ref(plan), &sign)
            }))
            .await?;
        Ok(plans
            .iter()
            .zip(outcomes)
            .map(|(plan, outcome)| {
                outcome.published_by_reference[&plan.oci_reference]
                    .oci_digest
                    .clone()
            })
            .collect())
    }

    /// Verify `plan`'s signature as a reader does.
    async fn verify(
        &self,
        session: &stow_oci::RegistrySession,
        plan: &PlannedArtifact,
        digest: &str,
    ) -> stow_types::error::Result<()> {
        let reference: stow_oci::Reference = plan.oci_reference.parse().expect("reference");
        stow_oci::verify_artifact_signature(
            session,
            &stow_oci::verify::Trust::GithubCi(self.sigstore.trust()),
            &reference,
            &plan.oci_reference,
            digest,
            CERTIFICATE_IDENTITY,
        )
        .await
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

/// A keyless signature lands in cosign's legacy layout and verifies with
/// the reader's verifier; signing costs three writes — the payload, the
/// config and the `.sig` manifest.
#[tokio::test]
async fn a_keyless_signature_verifies_with_the_readers_verifier() {
    let stack = Stack::new().await;
    let session = stack.session(&unbounded());
    let plans = [plan(&stack.root, 0)];
    let digests = Stack::publish(&session, &stack.signer(), &plans)
        .await
        .expect("publish");
    stack
        .verify(&session, &plans[0], &digests[0])
        .await
        .expect("the signature verifies");

    assert_eq!(stack.sigstore.certificates(), 1);
    assert_eq!(stack.sigstore.entries(), 1);
    // Layer, config and manifest by digest; the signature's payload,
    // config and manifest; the tag; the bundle's layer, config and
    // manifest.
    assert_eq!(stack.writes(), 10);
    let log = stack.probe.request_log();
    assert_eq!(
        log.iter()
            .filter(|record| record.method == Method::PUT && record.path.ends_with(".sig"))
            .count(),
        1,
        "one .sig manifest push"
    );

    let manifest = stack
        .signature_manifest(&digests[0])
        .expect("signature image");
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
    let digests = Stack::publish(&session, &signer, &plans)
        .await
        .expect("publish");
    assert_eq!(
        stack.sigstore.certificates(),
        1,
        "one certificate for three signatures"
    );
    assert_eq!(stack.sigstore.entries(), 3, "one Rekor entry per signature");
    for (plan, digest) in plans.iter().zip(&digests) {
        stack
            .verify(&session, plan, digest)
            .await
            .expect("verifies");
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
        let digests = Stack::publish(&session, &renewing, std::slice::from_ref(plan))
            .await
            .expect("publish");
        stack
            .verify(&session, plan, &digests[0])
            .await
            .expect("verifies");
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

/// A sweep publishing many nodes at once against a registry that caps
/// writes stays under the write budget — no write is ever refused — and
/// completes with one certificate and exactly one Rekor entry per
/// signature: nothing is signed twice.
#[tokio::test]
async fn a_sweep_stays_under_the_write_budget() {
    let stack = Stack::new().await;
    // 3000 a minute is 50 a second with a 50-write bucket: at most 100
    // writes in any second, under the registry's 110.
    stack.probe.cap_writes(110, Duration::from_secs(1));
    let budget = stow_oci::WriteBudget::per_minute(NonZeroU32::new(3000).expect("rate"));
    let session = stack.session(&budget);
    let plans = (0..24)
        .map(|index| plan(&stack.root, index))
        .collect::<Vec<_>>();
    let digests = Stack::publish(&session, &stack.signer(), &plans)
        .await
        .expect("the sweep completes");

    assert_eq!(stack.probe.throttled_writes(), 0, "no write was refused");
    let arrivals = stack.probe.write_arrivals();
    assert_eq!(arrivals.len(), 24 * 10);
    let peak = peak(&arrivals, Duration::from_secs(1));
    assert!(peak <= 101, "{peak} writes in one second, over the budget");
    assert_eq!(stack.sigstore.certificates(), 1);
    assert_eq!(stack.sigstore.entries(), 24);
    for (plan, digest) in plans.iter().zip(&digests) {
        stack
            .verify(&session, plan, digest)
            .await
            .expect("verifies");
        assert_eq!(
            stack.signature_manifest(digest).expect("signature")["layers"]
                .as_array()
                .expect("layers")
                .len(),
            1,
            "one signature layer"
        );
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
    let digests = Stack::publish(&session, &stack.signer(), &plans)
        .await
        .expect("the sweep completes");
    assert!(stack.probe.throttled_writes() > 0, "the cap refused writes");
    assert_eq!(stack.sigstore.certificates(), 1);
    assert_eq!(stack.sigstore.entries(), 12, "no signature was made twice");
    for (plan, digest) in plans.iter().zip(&digests) {
        stack
            .verify(&session, plan, digest)
            .await
            .expect("verifies");
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
    let digests = Stack::publish(&session, &stack.signer(), &plans)
        .await
        .expect("publish");
    assert_eq!(stack.sigstore.entries(), 1);
    stack
        .verify(&session, &plans[0], &digests[0])
        .await
        .expect("verifies");
}

/// A refused certificate request fails the signature with Fulcio's own
/// answer, and nothing of the signature is written: the tag never moves to
/// the unsigned manifest.
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
    // The layer, the config and the manifest by digest — nothing more.
    assert_eq!(stack.writes(), 3);
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
    assert_eq!(stack.writes(), 3, "no signature write");
}
