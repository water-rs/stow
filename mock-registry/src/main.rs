//! `stow-mock-registry`: a local OCI Registry V2 + cosign-compatible mock used
//! for end-to-end testing without contacting GHCR. Two modes: `populate`
//! materializes signed artifacts on disk from an upload plan; `serve` answers
//! HTTP requests from a wrangler-dev edge worker.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_fs::{create_dir_all, read, write};
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Path as AxumPath, Query, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    response::Response,
    routing::get,
};
use base64::Engine;
use clap::{Args, Parser, Subcommand};
use rusqlite::Connection;
use sha2::Digest;
use sigstore::cosign::payload::SimpleSigning;
use sigstore::crypto::signing_key::SigStoreKeyPair;
use sigstore::crypto::{SigStoreSigner, SigningScheme};
use stow_shim::schema as artifact_table_schema;
use stow_types::api::ArtifactRecord;
use stow_types::bundle::{
    ArtifactBlobConfig, BundleArtifactConfig, BundleLayer, BundleParts, BundleSignatureMaterial,
    OCI_IMAGE_MANIFEST_MEDIA_TYPE, SIGSTORE_CERT_ANNOTATION, SIGSTORE_OCI_MEDIA_TYPE,
    SIGSTORE_SIGNATURE_ANNOTATION, STOW_ARTIFACT_CONFIG_MEDIA_TYPE, STOW_BUNDLE_CONFIG_MEDIA_TYPE,
    STOW_BUNDLE_MEDIA_TYPE, assemble_bundle, sigstore_payload_path, sigstore_signature_tag,
};
use stow_types::bundle_schema::validate_bundle_schema;
use stow_types::identity::{TargetTriple, WireRustcVersion};
use stow_types::index::{
    ARTIFACT_INDEX_FORMAT_VERSION, ArtifactIndex, ArtifactIndexHeader, ArtifactIndexRow,
    STOW_INDEX_CONFIG_MEDIA_TYPE, STOW_INDEX_MEDIA_TYPE, content_sha256, index_tag,
};
use stow_types::registry::{GHCR_BASE, bundle_oci_reference, sha256_digest};
use stow_types::upload_plan::{PlannedArtifact, PublishedArtifact};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

const OCI_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
/// Manifest annotation the index publisher compares for change detection —
/// the same one `stow_oci::publish_index` writes on GHCR.
const INDEX_CONTENT_SHA256_ANNOTATION: &str = "dev.stow.index.content-sha256";
/// The certificate slot of a mock signature: `stow-cli` built with
/// `mock-verify` verifies against the mock public key and ignores it.
const MOCK_CERTIFICATE: &str = "mock-local";
const TOKEN_SERVICE: &str = "mock-registry";
const TOKEN_TTL_SECS: u64 = 300;

fn main() -> stow_types::error::Result<()> {
    // `sigstore`'s `sigstore-trust-root` feature pulls `tough`, which depends
    // on `rustls` with default features — that compiles in `aws_lc_rs`
    // alongside the `ring` provider selected elsewhere in the graph. `tough`'s
    // rustls dep cannot be reconfigured, so rustls cannot auto-select a
    // provider; install `ring` explicitly before any TLS client is built.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| stow_types::error::Error::msg("install ring CryptoProvider"))?;
    install_tracing();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn async_main() -> stow_types::error::Result<()> {
    match Cli::parse().command {
        Command::Populate(request) => populate_registry(request).await,
        Command::PublishIndex(request) => publish_index(request).await,
        Command::IndexFromRecords(request) => index_from_records(request).await,
        Command::Serve(request) => serve_registry(request).await,
    }
}

async fn populate_registry(request: PopulateArgs) -> stow_types::error::Result<()> {
    let plans = load_upload_plan(&request.upload_plan_path).await?;
    validate_upload_plan(&plans)?;
    create_dir_all(&request.registry_root).await?;
    if let Some(parent) = request.sqlite_path.as_ref().and_then(|p| p.parent()) {
        create_dir_all(parent).await?;
    }

    let key_pair = load_key_pair(&request.private_key_path).await?;
    if let Some(public_key_path) = request.public_key_path.as_ref() {
        write_public_key(public_key_path, &key_pair).await?;
    }
    let signer = key_pair
        .to_sigstore_signer(&SigningScheme::ECDSA_P256_SHA256_ASN1)
        .map_err(|error| stow_types::stow_error!("create mock signer from private key: {error}"))?;

    let mut published_by_reference = BTreeMap::new();
    for plan in &plans {
        let published = write_mock_registry_entry(&request.registry_root, &signer, plan).await?;
        published_by_reference.insert(plan.oci_reference.clone(), published);
    }

    let records = stow_types::upload_plan::build_artifact_records(&plans, &published_by_reference)?;
    write_records_outputs(&request, &records).await?;
    if let Some(sqlite_path) = request.sqlite_path.as_ref() {
        upsert_sqlite(sqlite_path, &records).await?;
    }
    tracing::info!(
        artifacts = records.len(),
        "mock registry population completed"
    );
    Ok(())
}

/// Write one signed index artifact into the on-disk registry — the mock
/// counterpart of `stow_oci::publish_index`. The layout is byte-for-byte
/// what `populate` produces for artifact manifests: the index blob, a
/// `{}` config blob, the manifest under both tag and digest, and the
/// cosign-shaped signature image under `sigstore_signature_tag`.
///
/// When the published tag already carries the file's `content_sha256`
/// annotation nothing is rewritten — the same skip the production
/// publisher makes.
async fn publish_index(request: PublishIndexArgs) -> stow_types::error::Result<()> {
    let index_bytes = read(&request.file).await.map_err(|error| {
        stow_types::stow_error!("read index file {}: {error}", request.file.display())
    })?;
    let index = stow_types::index::decode(&index_bytes).map_err(|error| {
        stow_types::stow_error!("decode index file {}: {error}", request.file.display())
    })?;
    write_signed_index(
        &request.registry_root,
        &request.private_key_path,
        &index,
        &index_bytes,
    )
    .await
}

/// `index-from-records` builds the signed slices a `populate` fixture
/// represents — the bench counterpart of `stow-admin index export` +
/// `index publish` against a live edge catalog, which a benchmark host
/// does not run. Records group by `(target, rustc_version)` and each
/// group publishes one slice; only rows with a pushed bundle enter, in
/// `c_metadata` order like the real export.
async fn index_from_records(request: IndexFromRecordsArgs) -> stow_types::error::Result<()> {
    let bytes = read(&request.records).await.map_err(|error| {
        stow_types::stow_error!("read records {}: {error}", request.records.display())
    })?;
    let records: Vec<ArtifactRecord> = serde_json::from_slice(&bytes).map_err(|error| {
        stow_types::stow_error!("decode records {}: {error}", request.records.display())
    })?;
    let mut slices: BTreeMap<(TargetTriple, WireRustcVersion), Vec<ArtifactIndexRow>> =
        BTreeMap::new();
    for record in records {
        if record.bundle_digest.is_empty() {
            continue;
        }
        let row = ArtifactIndexRow {
            crate_name: record.crate_name,
            version: record.version,
            features_json: record.features_json,
            dependency_c_metadata_json: record.dependency_c_metadata_json,
            c_metadata: record.c_metadata,
            compile_key: record.compile_key,
            bundle_digest: record.bundle_digest,
            bundle_size: record.bundle_size,
            artifact_kind: record.artifact_kind,
            crate_types: record.crate_types,
            profile: record.profile,
            emit: record.emit,
        };
        slices
            .entry((record.target, record.rustc_version))
            .or_default()
            .push(row);
    }
    for ((target, rustc_version), mut rows) in slices {
        rows.sort_by(|a, b| a.c_metadata.cmp(&b.c_metadata));
        let index = ArtifactIndex {
            header: ArtifactIndexHeader {
                format_version: ARTIFACT_INDEX_FORMAT_VERSION,
                target,
                rustc_version,
                generated_at: time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .map_err(|error| stow_types::stow_error!("format generated_at: {error}"))?,
                row_count: u64::try_from(rows.len())
                    .map_err(|_| stow_types::stow_error!("row count {} exceeds u64", rows.len()))?,
            },
            rows,
        };
        let index_bytes = stow_types::index::encode(&index)
            .map_err(|error| stow_types::stow_error!("encode index: {error}"))?;
        write_signed_index(
            &request.registry_root,
            &request.private_key_path,
            &index,
            &index_bytes,
        )
        .await?;
    }
    Ok(())
}

/// The shared tail of `publish-index` and `index-from-records`: write the
/// encoded slice's blob/manifest/signature into the on-disk registry.
async fn write_signed_index(
    registry_root: &Path,
    private_key_path: &Path,
    index: &ArtifactIndex,
    index_bytes: &[u8],
) -> stow_types::error::Result<()> {
    let content_sha256 = content_sha256(index)
        .map_err(|error| stow_types::stow_error!("digest index content: {error}"))?;
    let tag = index_tag(
        index.header.target.as_str(),
        index.header.rustc_version.as_str(),
    );
    let repository = stow_types::registry::GHCR_REPOSITORY;
    let reference = format!("{GHCR_BASE}:{tag}");

    let manifest_path = registry_root.join("manifests").join(repository).join(&tag);
    if let Ok(existing) = read(&manifest_path).await {
        let published: serde_json::Value = serde_json::from_slice(&existing).map_err(|error| {
            stow_types::stow_error!(
                "parse published index manifest {}: {error}",
                manifest_path.display()
            )
        })?;
        if published
            .pointer("/annotations/dev.stow.index.content-sha256")
            .and_then(serde_json::Value::as_str)
            == Some(content_sha256.as_str())
        {
            tracing::info!(%reference, %content_sha256, "index unchanged — skipping publish");
            report_index_publish("unchanged", &published_manifest_digest(&existing)?);
            return Ok(());
        }
    }

    let key_pair = load_key_pair(private_key_path).await?;
    let signer = key_pair
        .to_sigstore_signer(&SigningScheme::ECDSA_P256_SHA256_ASN1)
        .map_err(|error| stow_types::stow_error!("create mock signer from private key: {error}"))?;

    let layer_digest = sha256_digest(index_bytes);
    write_blob(registry_root, &layer_digest, index_bytes).await?;
    let config_bytes = b"{}".to_vec();
    let config_digest = sha256_digest(&config_bytes);
    write_blob(registry_root, &config_digest, &config_bytes).await?;
    let manifest_bytes = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        "config": {
            "mediaType": STOW_INDEX_CONFIG_MEDIA_TYPE,
            "digest": config_digest,
            "size": config_bytes.len(),
        },
        "layers": [{
            "mediaType": STOW_INDEX_MEDIA_TYPE,
            "digest": layer_digest,
            "size": index_bytes.len(),
        }],
        "annotations": {
            INDEX_CONTENT_SHA256_ANNOTATION: content_sha256,
        },
    }))?;
    let manifest_digest = sha256_digest(&manifest_bytes);
    write_manifest(registry_root, repository, &tag, &manifest_bytes).await?;
    write_manifest(registry_root, repository, &manifest_digest, &manifest_bytes).await?;

    let payload = SimpleSigning::new(&reference.parse()?, &manifest_digest);
    let payload_bytes = serde_json::to_vec(&payload)?;
    let payload_digest = sha256_digest(&payload_bytes);
    write_blob(registry_root, &payload_digest, &payload_bytes).await?;
    let signature = signer.sign(&payload_bytes).map_err(|error| {
        stow_types::stow_error!("sign mock index payload for {reference}: {error}")
    })?;
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature);
    let signature_manifest_bytes = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        "config": {
            "mediaType": OCI_CONFIG_MEDIA_TYPE,
            "digest": config_digest,
            "size": config_bytes.len(),
        },
        "layers": [{
            "mediaType": SIGSTORE_OCI_MEDIA_TYPE,
            "digest": payload_digest,
            "size": payload_bytes.len(),
            "annotations": {
                SIGSTORE_SIGNATURE_ANNOTATION: signature_b64,
                SIGSTORE_CERT_ANNOTATION: MOCK_CERTIFICATE,
            }
        }],
    }))?;
    write_manifest(
        registry_root,
        repository,
        &sigstore_signature_tag(&manifest_digest),
        &signature_manifest_bytes,
    )
    .await?;
    tracing::info!(%reference, %manifest_digest, "published mock index artifact");
    report_index_publish("published", &manifest_digest);
    Ok(())
}

/// The digest the published manifest file hashes to — derived from the
/// bytes on disk, so it is exactly what a reader re-hashes.
fn published_manifest_digest(manifest_bytes: &[u8]) -> stow_types::error::Result<String> {
    Ok(sha256_digest(manifest_bytes))
}

/// The machine-readable stdout line `stow-admin index publish` reads back.
fn report_index_publish(outcome: &str, manifest_digest: &str) {
    println!(
        "{}",
        serde_json::json!({
            "outcome": outcome,
            "manifest_digest": manifest_digest,
        })
    );
}

async fn serve_registry(request: ServeArgs) -> stow_types::error::Result<()> {
    let listener = TcpListener::bind(&request.listen).await.map_err(|error| {
        stow_types::stow_error!("bind mock registry {}: {error}", request.listen)
    })?;
    let app = registry_app(&request.listen, request.registry_root.clone());
    tracing::info!(
        listen = %request.listen,
        registry_root = %request.registry_root.display(),
        "mock registry server listening"
    );
    axum::serve(listener, app)
        .await
        .map_err(|error| stow_types::stow_error!("serve mock registry: {error}"))
}

/// The mock OCI registry speaking GHCR's anonymous token exchange: asset
/// requests without a bearer get `401` + `WWW-Authenticate` challenge,
/// `GET /token` mints the bearer the challenge points at, and only
/// registry-issued unexpired tokens are served. `POST` takes the monolithic
/// blob upload and `PUT` stores manifests — the same verbs GHCR answers.
fn registry_app(listen: &str, registry_root: PathBuf) -> Router {
    registry_app_with_probe(listen, registry_root, None)
}

fn registry_app_with_probe(
    listen: &str,
    registry_root: PathBuf,
    probe: Option<RegistryProbe>,
) -> Router {
    Router::new()
        .route("/v2", get(v2_ping).head(v2_ping))
        .route("/v2/", get(v2_ping).head(v2_ping))
        .route(
            "/v2/{*rest}",
            get(serve_v2).head(serve_v2).post(serve_v2).put(serve_v2),
        )
        .route("/token", get(issue_token))
        .route(
            "/api/v1/artifacts/{target}/{rustc_version}/{c_metadata}",
            get(serve_edge_artifact).head(serve_edge_artifact),
        )
        .with_state(MockRegistryState {
            registry_root,
            token_realm: format!("http://{listen}/token"),
            tokens: Arc::new(Mutex::new(TokenState::default())),
            index_slices: Arc::new(RwLock::new(HashMap::new())),
            requests: probe.as_ref().map(|probe| Arc::clone(&probe.requests)),
            rate_limits: probe.as_ref().map(|probe| Arc::clone(&probe.rate_limits)),
            toggles: probe.as_ref().map(|probe| Arc::clone(&probe.toggles)),
        })
}

/// A test's handle into a running mock registry: the ordered request log
/// and the scripted `429`s still owed. Production `serve` runs without one
/// — [`MockRegistryState::requests`] is `None` and nothing is recorded.
#[derive(Clone)]
struct RegistryProbe {
    /// Read only by `forge_manifest`, so absent from production builds.
    #[cfg(test)]
    registry_root: PathBuf,
    requests: Arc<Mutex<Vec<RequestRecord>>>,
    rate_limits: Arc<Mutex<Vec<RateLimitRule>>>,
    toggles: Arc<ProbeToggles>,
}

impl RegistryProbe {
    /// The registry with instrumentation attached: the app to serve, plus
    /// the probe the test reads requests through and programs `429`s into.
    #[cfg(test)]
    fn registry_app_probe(listen: &str, registry_root: PathBuf) -> (Router, Self) {
        let probe = Self {
            registry_root,
            requests: Arc::new(Mutex::new(Vec::new())),
            rate_limits: Arc::new(Mutex::new(Vec::new())),
            toggles: Arc::new(ProbeToggles::new()),
        };
        let root = probe.registry_root.clone();
        (
            registry_app_with_probe(listen, root, Some(probe.clone())),
            probe,
        )
    }

    /// One record per request the registry has seen, in arrival order.
    #[cfg(test)]
    fn request_log(&self) -> Vec<RequestRecord> {
        self.requests.lock().expect("request log poisoned").clone()
    }

    /// Refuse the next `remaining` requests whose method and path match with
    /// GHCR's rate-limit shape: `429 TOOMANYREQUESTS` carrying a
    /// `retry-after:` value inside the OCI error body.
    #[cfg(test)]
    fn rate_limit(&self, method: Method, path_substr: &str, remaining: usize) {
        self.rate_limits
            .lock()
            .expect("rate-limit rules poisoned")
            .push(RateLimitRule {
                method,
                path_substr: path_substr.to_owned(),
                remaining,
            });
    }

    /// Behave like a registry without single-`POST` upload support: every
    /// `POST /blobs/uploads` opens a session (`202` + `Location`) that only
    /// the commit `PUT` completes.
    #[cfg(test)]
    fn refuse_single_post(&self) {
        self.toggles.single_post.store(false, Ordering::Relaxed);
    }

    /// Answer `PUT /manifests` without `Docker-Content-Digest`, like a
    /// minimal registry — the client must then read the manifest back by
    /// digest and compare bytes.
    #[cfg(test)]
    fn omit_manifest_digest_header(&self) {
        self.toggles
            .manifest_digest_header
            .store(false, Ordering::Relaxed);
    }

    /// Serve `forged` bytes under `reference` while the
    /// `Docker-Content-Digest` header claims `claimed_digest` — the
    /// hostile-registry stub a digest-verifying client must reject.
    #[cfg(test)]
    fn forge_manifest(&self, reference: &str, forged: &[u8], claimed_digest: &str) {
        let file = manifest_file_name(reference);
        let path = self
            .registry_root
            .join("manifests")
            .join(stow_types::registry::GHCR_REPOSITORY)
            .join(&file);
        std::fs::create_dir_all(path.parent().expect("manifest parent")).expect("manifest dir");
        std::fs::write(&path, forged).expect("forged manifest");
        self.toggles
            .forged_digests
            .lock()
            .expect("forged digests poisoned")
            .insert(file, claimed_digest.to_owned());
    }
}

/// What the probe logs per request: the method and the `/v2/...` or
/// `/token` path (query excluded — the upload digest rides it).
#[derive(Clone, Debug, PartialEq, Eq)]
struct RequestRecord {
    method: Method,
    path: String,
}

/// One scripted refusal: the next `remaining` requests matching `method`
/// and containing `path_substr` get `429` — drained one per request.
#[derive(Debug)]
struct RateLimitRule {
    method: Method,
    path_substr: String,
    remaining: usize,
}

/// Registry behaviors a test can switch off to exercise the client's
/// spec-level fallbacks — the distribution spec's weaker forms.
#[derive(Debug)]
struct ProbeToggles {
    /// `false` makes `POST /blobs/uploads` answer `202` + a session
    /// `Location` like a registry without monolithic-upload support.
    single_post: AtomicBool,
    /// `false` makes `PUT /manifests` answer without
    /// `Docker-Content-Digest`, forcing the client to read the manifest
    /// back by digest.
    manifest_digest_header: AtomicBool,
    /// Manifest file name → the digest to claim for it while serving
    /// forged bytes — the hostile-registry stub.
    forged_digests: Mutex<HashMap<String, String>>,
    /// Session ids for opened upload sessions.
    next_upload_id: AtomicU64,
}

impl ProbeToggles {
    /// Constructed only through `registry_app_probe`.
    #[cfg(test)]
    fn new() -> Self {
        Self {
            single_post: AtomicBool::new(true),
            manifest_digest_header: AtomicBool::new(true),
            forged_digests: Mutex::new(HashMap::new()),
            next_upload_id: AtomicU64::new(0),
        }
    }
}

/// Load a plan written by `stow-build build`. Its output paths are relative
/// to the build output directory the plan file sits in, so they are resolved
/// against that directory here.
async fn load_upload_plan(path: &Path) -> stow_types::error::Result<Vec<PlannedArtifact>> {
    let bytes = read(path)
        .await
        .map_err(|error| stow_types::stow_error!("read upload plan {}: {error}", path.display()))?;
    let mut plans: Vec<PlannedArtifact> = serde_json::from_slice(&bytes).map_err(|error| {
        stow_types::stow_error!("parse upload plan {}: {error}", path.display())
    })?;
    let base = path.parent().ok_or_else(|| {
        stow_types::stow_error!("upload plan {} has no parent directory", path.display())
    })?;
    for plan in &mut plans {
        for output in plan.outputs.iter_mut().chain(plan.native_archive.as_mut()) {
            output.path = base.join(&output.path);
        }
    }
    Ok(plans)
}

fn validate_upload_plan(plans: &[PlannedArtifact]) -> stow_types::error::Result<()> {
    if plans.is_empty() {
        return Err(stow_types::stow_error!("upload plan is empty"));
    }

    let mut composite_keys = BTreeSet::new();
    for plan in plans {
        if plan.outputs.is_empty() {
            return Err(stow_types::stow_error!(
                "upload plan entry {} {} has no outputs",
                plan.crate_name,
                plan.c_metadata
            ));
        }
        let composite = (
            plan.c_metadata.as_str(),
            plan.target.as_str(),
            plan.rustc_version.as_str(),
        );
        if !composite_keys.insert(composite) {
            return Err(stow_types::stow_error!(
                "upload plan contains duplicate artifact key {} {} {}",
                plan.c_metadata,
                plan.target,
                plan.rustc_version
            ));
        }
        let mut output_file_names = BTreeSet::new();
        for output in &plan.outputs {
            if !output_file_names.insert(output.bundle_file.file_name.as_str()) {
                return Err(stow_types::stow_error!(
                    "upload plan entry {} {} contains duplicate bundled output file {}",
                    plan.crate_name,
                    plan.c_metadata,
                    output.bundle_file.file_name
                ));
            }
        }
    }

    Ok(())
}

async fn load_key_pair(path: &Path) -> stow_types::error::Result<SigStoreKeyPair> {
    let bytes = read(path)
        .await
        .map_err(|error| stow_types::stow_error!("read private key {}: {error}", path.display()))?;
    SigStoreKeyPair::from_pem(&bytes).map_err(|error| {
        stow_types::stow_error!("load mock private key {}: {error}", path.display())
    })
}

async fn write_public_key(
    path: &Path,
    key_pair: &SigStoreKeyPair,
) -> stow_types::error::Result<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent).await?;
    }
    let public_key = key_pair.public_key_to_pem().map_err(|error| {
        stow_types::stow_error!("encode mock public key {}: {error}", path.display())
    })?;
    write(path, public_key.as_bytes())
        .await
        .map_err(|error| stow_types::stow_error!("write public key {}: {error}", path.display()))
}

async fn write_mock_registry_entry(
    registry_root: &Path,
    signer: &SigStoreSigner,
    plan: &PlannedArtifact,
) -> stow_types::error::Result<PublishedArtifact> {
    let config = ArtifactBlobConfig {
        compile_key: plan.compile_key.clone(),
        crate_name: plan.crate_name.clone(),
        crate_version: plan.crate_version.clone(),
        c_metadata: plan.c_metadata.clone(),
        extra_filename: plan.extra_filename.clone(),
        target: plan.target.clone(),
        rustc_version: plan.rustc_version.clone(),
        features_json: plan.features_json.clone(),
        dependency_c_metadata_json: plan.dependency_c_metadata_json.clone(),
        dependency_compile_keys_json: plan.dependency_compile_keys_json.clone(),
        profile: plan.profile.clone(),
        emit: plan.emit.clone(),
        artifact_size: plan.artifact_size,
        compile_millis: plan.compile_millis,
        kind: plan.kind.clone(),
        crate_types: plan.crate_types.clone(),
        outputs: plan
            .outputs
            .iter()
            .map(|output| output.bundle_file.clone())
            .collect(),
        native: plan.native.clone(),
        native_archive: plan
            .native_archive
            .as_ref()
            .map(|archive| archive.bundle_file.clone()),
    };
    let config_bytes = serde_json::to_vec(&config)?;
    let config_digest = sha256_digest(&config_bytes);
    write_blob(registry_root, &config_digest, &config_bytes).await?;

    let mut layers = Vec::with_capacity(plan.outputs.len() + 1);
    let mut layer_blobs = Vec::with_capacity(plan.outputs.len() + 1);
    // Same order as CI pushes: outputs, then the native archive.
    for output in plan.outputs.iter().chain(plan.native_archive.as_ref()) {
        let bytes = read(&output.path).await.map_err(|error| {
            stow_types::stow_error!("read artifact output {}: {error}", output.path.display())
        })?;
        let path_for_error = output.path.clone();
        let compressed = smol::unblock(move || {
            zstd::bulk::compress(&bytes, stow_shim::STOW_ZSTD_COMPRESSION_LEVEL).map_err(|error| {
                stow_types::stow_error!(
                    "zstd compress {} at level {}: {error}",
                    path_for_error.display(),
                    stow_shim::STOW_ZSTD_COMPRESSION_LEVEL
                )
            })
        })
        .await?;
        let digest = sha256_digest(&compressed);
        write_blob(registry_root, &digest, &compressed).await?;
        layers.push(serde_json::json!({
            "mediaType": output.bundle_file.storage_media_type(),
            "digest": digest,
            "size": compressed.len(),
        }));
        layer_blobs.push((output.bundle_file.storage_media_type(), compressed));
    }

    let manifest_bytes = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        "config": {
            "mediaType": STOW_ARTIFACT_CONFIG_MEDIA_TYPE,
            "digest": config_digest,
            "size": config_bytes.len(),
        },
        "layers": layers,
    }))?;
    let manifest_digest = sha256_digest(&manifest_bytes);
    let (repo, tag) = split_reference(&plan.oci_reference)?;
    write_manifest(registry_root, &repo, &tag, &manifest_bytes).await?;
    write_manifest(registry_root, &repo, &manifest_digest, &manifest_bytes).await?;

    let (signature_b64, payload_bytes) =
        write_mock_signature(registry_root, signer, &plan.oci_reference, &manifest_digest).await?;

    // The same bundle tar the trusted publish stage pushes as
    // `<tag>.bundle`: the edge streams this blob by digest.
    let signature_material = BundleSignatureMaterial {
        payload_path: sigstore_payload_path(0),
        payload_bytes,
        signature: signature_b64,
        certificate_pem: MOCK_CERTIFICATE.to_owned(),
        rekor_bundle_json: None,
    };
    let bundle_layers = layer_blobs
        .iter()
        .map(|(media_type, bytes)| BundleLayer { media_type, bytes })
        .collect::<Vec<_>>();
    let bundle_bytes = assemble_bundle(&BundleParts {
        oci_reference: &plan.oci_reference,
        oci_digest: &manifest_digest,
        manifest_bytes: &manifest_bytes,
        config_bytes: &config_bytes,
        config: &config,
        signatures: std::slice::from_ref(&signature_material),
        layers: &bundle_layers,
    })
    .map_err(|error| {
        stow_types::stow_error!("assemble bundle for {}: {error}", plan.oci_reference)
    })?;
    validate_bundle_schema(&bundle_bytes).map_err(|error| {
        stow_types::stow_error!(
            "bundle for {} failed schema validation: {error}",
            plan.oci_reference
        )
    })?;
    let bundle_digest = sha256_digest(&bundle_bytes);
    let bundle_size = u64::try_from(bundle_bytes.len())?;
    write_blob(registry_root, &bundle_digest, &bundle_bytes).await?;
    let bundle_config_bytes = serde_json::to_vec(&BundleArtifactConfig {
        oci_reference: plan.oci_reference.clone(),
        oci_digest: manifest_digest.clone(),
    })?;
    let bundle_config_digest = sha256_digest(&bundle_config_bytes);
    write_blob(registry_root, &bundle_config_digest, &bundle_config_bytes).await?;
    let bundle_manifest_bytes = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        "config": {
            "mediaType": STOW_BUNDLE_CONFIG_MEDIA_TYPE,
            "digest": bundle_config_digest,
            "size": bundle_config_bytes.len(),
        },
        "layers": [{
            "mediaType": STOW_BUNDLE_MEDIA_TYPE,
            "digest": bundle_digest,
            "size": bundle_size,
        }],
    }))?;
    let bundle_reference = bundle_oci_reference(&plan.oci_reference).ok_or_else(|| {
        stow_types::stow_error!("no bundle reference fits for {}", plan.oci_reference)
    })?;
    let (_, bundle_tag) = split_reference(&bundle_reference)?;
    write_manifest(registry_root, &repo, &bundle_tag, &bundle_manifest_bytes).await?;

    Ok(PublishedArtifact {
        oci_digest: manifest_digest,
        bundle_digest,
        bundle_size,
    })
}

/// The signature pair the push path reads back through
/// `pull_signature_materials`: the simple-signing payload as a blob and
/// the `sha256-<digest>.sig` manifest whose layer carries the signature
/// and certificate annotations. Returns the base64 signature and the
/// payload bytes — the bundle embeds both.
async fn write_mock_signature(
    registry_root: &Path,
    signer: &SigStoreSigner,
    oci_reference: &str,
    manifest_digest: &str,
) -> stow_types::error::Result<(String, Vec<u8>)> {
    let payload = SimpleSigning::new(&oci_reference.parse()?, manifest_digest);
    let payload_bytes = serde_json::to_vec(&payload)?;
    let payload_digest = sha256_digest(&payload_bytes);
    write_blob(registry_root, &payload_digest, &payload_bytes).await?;
    let signature = signer.sign(&payload_bytes).map_err(|error| {
        stow_types::stow_error!("sign mock payload for {oci_reference}: {error}")
    })?;
    let signature_manifest_ref = sigstore_signature_tag(manifest_digest);
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature);
    let signature_config_bytes = b"{}".to_vec();
    let signature_config_digest = sha256_digest(&signature_config_bytes);
    write_blob(
        registry_root,
        &signature_config_digest,
        &signature_config_bytes,
    )
    .await?;
    let signature_manifest_bytes = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        "config": {
            "mediaType": OCI_CONFIG_MEDIA_TYPE,
            "digest": signature_config_digest,
            "size": signature_config_bytes.len(),
        },
        "layers": [{
            "mediaType": SIGSTORE_OCI_MEDIA_TYPE,
            "digest": payload_digest,
            "size": payload_bytes.len(),
            "annotations": {
                SIGSTORE_SIGNATURE_ANNOTATION: signature_b64,
                SIGSTORE_CERT_ANNOTATION: MOCK_CERTIFICATE,
            }
        }],
    }))?;
    let (repo, _) = split_reference(oci_reference)?;
    write_manifest(
        registry_root,
        &repo,
        &signature_manifest_ref,
        &signature_manifest_bytes,
    )
    .await?;
    Ok((signature_b64, payload_bytes))
}

async fn write_records_outputs(
    request: &PopulateArgs,
    records: &[ArtifactRecord],
) -> stow_types::error::Result<()> {
    if let Some(path) = request.records_output_path.as_ref() {
        if let Some(parent) = path.parent() {
            create_dir_all(parent).await?;
        }
        write(path, serde_json::to_vec_pretty(records)?)
            .await
            .map_err(|error| {
                stow_types::stow_error!("write artifact records {}: {error}", path.display())
            })?;
    }
    if let Some(path) = request.sql_output_path.as_ref() {
        if let Some(parent) = path.parent() {
            create_dir_all(parent).await?;
        }
        write(path, build_sql(records)).await.map_err(|error| {
            stow_types::stow_error!("write artifact SQL {}: {error}", path.display())
        })?;
    }
    Ok(())
}

async fn upsert_sqlite(path: &Path, records: &[ArtifactRecord]) -> stow_types::error::Result<()> {
    let sqlite_path = path.to_path_buf();
    let records = records.to_vec();
    smol::unblock(move || -> stow_types::error::Result<()> {
        let mut connection = Connection::open(&sqlite_path)
            .map_err(|error| stow_types::stow_error!("open sqlite {}: {error}", sqlite_path.display()))?;
        connection
            .execute_batch(include_str!("../../edge/migrations/0001_schema.sql"))
            .map_err(|error| stow_types::stow_error!("ensure sqlite schema {}: {error}", sqlite_path.display()))?;
        ensure_artifact_table_columns(&connection, &sqlite_path)?;
        // Mirror the edge's post-0005 schema: `dependency_count` is gone.
        connection
            .execute_batch(include_str!(
                "../../edge/migrations/0006_drop_dependency_count.sql"
            ))
            .map_err(|error| {
                stow_types::stow_error!("drop dependency_count in {}: {error}", sqlite_path.display())
            })?;
        let transaction = connection
            .transaction()
            .map_err(|error| stow_types::stow_error!("begin sqlite transaction {}: {error}", sqlite_path.display()))?;
        let sql = "INSERT INTO artifacts (compile_key, c_metadata, extra_filename, target, rustc_version, crate_name, version, features_json, dependency_c_metadata_json, oci_reference, oci_digest, has_native, artifact_kind, crate_types_json, profile_json, emit_json, artifact_size, bundle_digest, bundle_size, compile_millis, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, datetime('now')) ON CONFLICT(c_metadata, target, rustc_version) DO UPDATE SET compile_key=excluded.compile_key, extra_filename=excluded.extra_filename, crate_name=excluded.crate_name, version=excluded.version, features_json=excluded.features_json, dependency_c_metadata_json=excluded.dependency_c_metadata_json, oci_reference=excluded.oci_reference, oci_digest=excluded.oci_digest, has_native=excluded.has_native, artifact_kind=excluded.artifact_kind, crate_types_json=excluded.crate_types_json, profile_json=excluded.profile_json, emit_json=excluded.emit_json, artifact_size=excluded.artifact_size, bundle_digest=excluded.bundle_digest, bundle_size=excluded.bundle_size, compile_millis=excluded.compile_millis, created_at=datetime('now')";
        let mut statement = transaction
            .prepare(sql)
            .map_err(|error| stow_types::stow_error!("prepare sqlite upsert {}: {error}", sqlite_path.display()))?;
        for record in &records {
            let crate_types_json = serde_json::to_string(&record.crate_types)?;
            let profile_json = serde_json::to_string(&record.profile)?;
            let emit_json = serde_json::to_string(&record.emit)?;
            statement
                .execute(rusqlite::params![
                    record.compile_key,
                    record.c_metadata.as_str(),
                    record.extra_filename,
                    record.target.as_str(),
                    record.rustc_version.as_str(),
                    record.crate_name.as_str(),
                    record.version.to_string(),
                    record.features_json.raw(),
                    record.dependency_c_metadata_json.raw(),
                    record.oci_reference,
                    record.oci_digest,
                    if record.has_native { 1 } else { 0 },
                    record.artifact_kind.as_str(),
                    crate_types_json,
                    profile_json,
                    emit_json,
                    record.artifact_size,
                    record.bundle_digest,
                    record.bundle_size,
                    record.compile_millis,
                ])
                .map_err(|error| stow_types::stow_error!("upsert sqlite artifact {} {} {}: {error}", record.crate_name, record.target, record.c_metadata))?;
        }
        drop(statement);
        transaction
            .commit()
            .map_err(|error| stow_types::stow_error!("commit sqlite transaction {}: {error}", sqlite_path.display()))?;
        Ok(())
    })
    .await
}

fn ensure_artifact_table_columns(
    connection: &Connection,
    sqlite_path: &Path,
) -> stow_types::error::Result<()> {
    let mut statement = connection
        .prepare("PRAGMA table_info(artifacts)")
        .map_err(|error| {
            stow_types::stow_error!(
                "prepare table_info query {}: {error}",
                sqlite_path.display()
            )
        })?;
    let existing_columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|error| {
            stow_types::stow_error!("query table_info {}: {error}", sqlite_path.display())
        })?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|error| {
            stow_types::stow_error!("read table_info row {}: {error}", sqlite_path.display())
        })?;
    drop(statement);

    for column in artifact_table_schema::REQUIRED_ARTIFACT_COLUMNS {
        if existing_columns.contains(column.name) {
            continue;
        }
        connection.execute_batch(column.add_sql).map_err(|error| {
            stow_types::stow_error!(
                "migrate sqlite artifacts add column {} in {}: {error}",
                column.name,
                sqlite_path.display()
            )
        })?;
    }

    connection
        .execute(
            "DELETE FROM artifacts WHERE compile_key = '' OR compile_key IS NULL",
            [],
        )
        .map_err(|error| {
            stow_types::stow_error!(
                "delete sqlite artifacts with empty compile_key in {}: {error}",
                sqlite_path.display()
            )
        })?;

    // Rows under the retired per-crate layout point at unreachable private
    // packages; the edge applied this cleanup to D1 as a one-time sweep.
    connection
        .execute(
            &format!(
                "DELETE FROM artifacts WHERE oci_reference NOT GLOB '{}:*'",
                stow_types::registry::GHCR_BASE
            ),
            [],
        )
        .map_err(|error| {
            stow_types::stow_error!(
                "delete sqlite artifacts with legacy per-crate oci_reference in {}: {error}",
                sqlite_path.display()
            )
        })?;

    Ok(())
}

async fn write_blob(root: &Path, digest: &str, bytes: &[u8]) -> stow_types::error::Result<()> {
    let path = root.join("blobs").join(digest.replace(':', "_"));
    if let Some(parent) = path.parent() {
        create_dir_all(parent).await?;
    }
    write(&path, bytes)
        .await
        .map_err(|error| stow_types::stow_error!("write blob {}: {error}", path.display()))
}

async fn write_manifest(
    root: &Path,
    repo: &str,
    reference: &str,
    bytes: &[u8],
) -> stow_types::error::Result<()> {
    let file_name = if reference.starts_with("sha256:") {
        reference.replace(':', "_")
    } else {
        reference.to_owned()
    };
    let path = root.join("manifests").join(repo).join(file_name);
    if let Some(parent) = path.parent() {
        create_dir_all(parent).await?;
    }
    write(&path, bytes)
        .await
        .map_err(|error| stow_types::stow_error!("write manifest {}: {error}", path.display()))
}

fn split_reference(reference: &str) -> stow_types::error::Result<(String, String)> {
    let tag = stow_types::registry::oci_reference_tag(reference)
        .ok_or_else(|| stow_types::stow_error!("unexpected OCI reference shape: {reference}"))?;
    let repo = stow_types::registry::repository_path(reference).ok_or_else(|| {
        stow_types::stow_error!("missing OCI repository in reference {reference}")
    })?;
    Ok((repo.to_string(), tag.to_owned()))
}

fn build_sql(records: &[ArtifactRecord]) -> Vec<u8> {
    let mut sql = String::from("BEGIN;\n");
    for record in records {
        let crate_types_json = serde_json::to_string(&record.crate_types)
            .expect("crate_types serialization must succeed");
        let profile_json =
            serde_json::to_string(&record.profile).expect("profile serialization must succeed");
        let emit_json =
            serde_json::to_string(&record.emit).expect("emit serialization must succeed");
        sql.push_str("INSERT INTO artifacts (");
        sql.push_str("compile_key, c_metadata, extra_filename, target, rustc_version, crate_name, version, features_json, dependency_c_metadata_json, oci_reference, oci_digest, has_native, artifact_kind, crate_types_json, profile_json, emit_json, artifact_size, bundle_digest, bundle_size, compile_millis, created_at");
        sql.push_str(") VALUES (");
        sql.push_str(&sql_quote(&record.compile_key));
        sql.push_str(", ");
        sql.push_str(&sql_quote(record.c_metadata.as_str()));
        sql.push_str(", ");
        sql.push_str(&sql_quote(&record.extra_filename));
        sql.push_str(", ");
        sql.push_str(&sql_quote(record.target.as_str()));
        sql.push_str(", ");
        sql.push_str(&sql_quote(record.rustc_version.as_str()));
        sql.push_str(", ");
        sql.push_str(&sql_quote(record.crate_name.as_str()));
        sql.push_str(", ");
        sql.push_str(&sql_quote(&record.version.to_string()));
        sql.push_str(", ");
        sql.push_str(&sql_quote(&record.features_json.raw()));
        sql.push_str(", ");
        sql.push_str(&sql_quote(&record.dependency_c_metadata_json.raw()));
        sql.push_str(", ");
        sql.push_str(&sql_quote(&record.oci_reference));
        sql.push_str(", ");
        sql.push_str(&sql_quote(&record.oci_digest));
        sql.push_str(", ");
        sql.push_str(if record.has_native { "1" } else { "0" });
        sql.push_str(", ");
        sql.push_str(&sql_quote(record.artifact_kind.as_str()));
        sql.push_str(", ");
        sql.push_str(&sql_quote(&crate_types_json));
        sql.push_str(", ");
        sql.push_str(&sql_quote(&profile_json));
        sql.push_str(", ");
        sql.push_str(&sql_quote(&emit_json));
        sql.push_str(", ");
        sql.push_str(&record.artifact_size.to_string());
        sql.push_str(", ");
        sql.push_str(&sql_quote(&record.bundle_digest));
        sql.push_str(", ");
        sql.push_str(&record.bundle_size.to_string());
        sql.push_str(", ");
        sql.push_str(&record.compile_millis.to_string());
        sql.push_str(
            ", datetime('now')) ON CONFLICT(c_metadata, target, rustc_version) DO UPDATE SET ",
        );
        sql.push_str("compile_key=excluded.compile_key, extra_filename=excluded.extra_filename, crate_name=excluded.crate_name, version=excluded.version, features_json=excluded.features_json, dependency_c_metadata_json=excluded.dependency_c_metadata_json, ");
        sql.push_str("oci_reference=excluded.oci_reference, oci_digest=excluded.oci_digest, has_native=excluded.has_native, ");
        sql.push_str("artifact_kind=excluded.artifact_kind, crate_types_json=excluded.crate_types_json, profile_json=excluded.profile_json, emit_json=excluded.emit_json, artifact_size=excluded.artifact_size, bundle_digest=excluded.bundle_digest, bundle_size=excluded.bundle_size, compile_millis=excluded.compile_millis, created_at=datetime('now');\n");
    }
    sql.push_str("COMMIT;\n");
    sql.into_bytes()
}

fn sql_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn install_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        // stderr, never stdout: keep diagnostics off the data stream.
        .with_writer(std::io::stderr)
        .try_init();
}

#[derive(Debug, Parser)]
#[command(name = "stow-mock-registry")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Populate(PopulateArgs),
    /// Write a signed index artifact into the registry root — what
    /// `stow-admin index publish` shells out to under `mock-key` mode.
    PublishIndex(PublishIndexArgs),
    /// Build + sign + publish the index slice for `(target, rustc_version)`
    /// straight from a `populate --records-out` file — the bench pipeline
    /// has no edge to `stow-admin index export` from.
    IndexFromRecords(IndexFromRecordsArgs),
    Serve(ServeArgs),
}

#[derive(Debug, Clone, Args)]
struct PublishIndexArgs {
    /// The encoded (`zstd` JSON) index file `stow-admin index export` wrote.
    #[arg(long)]
    file: PathBuf,
    #[arg(long)]
    registry_root: PathBuf,
    #[arg(long = "private-key")]
    private_key_path: PathBuf,
}

#[derive(Debug, Clone, Args)]
struct PopulateArgs {
    #[arg(long = "upload-plan")]
    upload_plan_path: PathBuf,
    #[arg(long = "registry-root")]
    registry_root: PathBuf,
    /// Optional artifacts-table mirror — nothing reads it since the edge
    /// stopped serving artifact lookups, but it keeps the fixture's schema
    /// exercised against the real migrations.
    #[arg(long = "sqlite")]
    sqlite_path: Option<PathBuf>,
    #[arg(long = "private-key")]
    private_key_path: PathBuf,
    #[arg(long = "public-key")]
    public_key_path: Option<PathBuf>,
    #[arg(long = "records-out")]
    records_output_path: Option<PathBuf>,
    #[arg(long = "sql-out")]
    sql_output_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
struct IndexFromRecordsArgs {
    /// `populate --records-out` JSON file.
    #[arg(long)]
    records: PathBuf,
    #[arg(long)]
    registry_root: PathBuf,
    #[arg(long = "private-key")]
    private_key_path: PathBuf,
}

#[derive(Debug, Clone, Args)]
struct ServeArgs {
    #[arg(long)]
    registry_root: PathBuf,
    #[arg(long, default_value = "127.0.0.1:40123")]
    listen: String,
}

#[derive(Debug, Clone)]
struct MockRegistryState {
    registry_root: PathBuf,
    /// Realm the `WWW-Authenticate` challenge points at — this server's
    /// own `/token` endpoint.
    token_realm: String,
    tokens: Arc<Mutex<TokenState>>,
    /// Decoded index slices behind the edge byte-path stand-in, keyed by
    /// tag and revalidated against the published manifest's digest on
    /// every request, so a republished slice is picked up without a
    /// restart.
    index_slices: Arc<RwLock<HashMap<String, CachedIndexSlice>>>,
    /// The probe's request log — `Some` only when a test attached one.
    requests: Option<Arc<Mutex<Vec<RequestRecord>>>>,
    /// The probe's scripted `429`s — `Some` only when a test attached one.
    rate_limits: Option<Arc<Mutex<Vec<RateLimitRule>>>>,
    /// The probe's behavior toggles — `None` means the well-behaved
    /// registry: single `POST` uploads, digest headers, honest serving.
    toggles: Option<Arc<ProbeToggles>>,
}

/// One decoded slice plus the digest of the manifest it was decoded from.
#[derive(Debug, Clone)]
struct CachedIndexSlice {
    manifest_digest: String,
    index: Arc<ArtifactIndex>,
}

/// Issued bearer tokens and their expirations; `Instant` is enough
/// because the map dies with the process anyway.
#[derive(Debug, Default)]
struct TokenState {
    issued: HashMap<String, Instant>,
    /// Monotonic salt so back-to-back mints never collide.
    next: u64,
}

/// `GET /v2/` — GHCR answers the version ping with `401` plus the Bearer
/// challenge, which is how the registry client discovers the token realm;
/// a bare `200` leaves clients with no way to authenticate.
async fn v2_ping(State(state): State<MockRegistryState>) -> Response<Body> {
    state.record(&Method::GET, "/v2/");
    unauthorized(&state.token_realm)
}

/// `GET /token?service=…&scope=…` — mints an anonymous bearer exactly the
/// way GHCR does for public packages. The mock grants every requested
/// scope; the token is recorded with its expiry and later `/v2/` requests
/// are served only when they present it.
async fn issue_token(
    State(state): State<MockRegistryState>,
    Query(params): Query<BTreeMap<String, String>>,
) -> Json<serde_json::Value> {
    state.record(&Method::GET, "/token");
    let mut tokens = state
        .tokens
        .lock()
        .expect("mock registry token map poisoned");
    let serial = tokens.next;
    tokens.next += 1;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let token = format!(
        "mock.{}",
        hex::encode(sha2::Sha256::digest(format!("{serial}:{nanos}").as_bytes()))
    );
    tokens.issued.insert(
        token.clone(),
        Instant::now() + Duration::from_secs(TOKEN_TTL_SECS),
    );
    tracing::info!(
        service = params.get("service"),
        scope = params.get("scope"),
        "minted mock registry token"
    );
    Json(serde_json::json!({
        "token": token,
        "expires_in": TOKEN_TTL_SECS,
    }))
}

async fn serve_v2(
    State(state): State<MockRegistryState>,
    method: Method,
    headers: HeaderMap,
    AxumPath(rest): AxumPath<String>,
    Query(query): Query<BTreeMap<String, String>>,
    body: Body,
) -> Result<Response<Body>, StatusCode> {
    let path = format!("/v2/{rest}");
    state.record(&method, &path);
    if let Some(refusal) = state.rate_limited(&method, &path) {
        return Ok(refusal);
    }
    let asset = parse_registry_asset(&rest).map_err(|error| {
        tracing::warn!(path = %rest, %error, "invalid mock registry path");
        StatusCode::BAD_REQUEST
    })?;
    if !state.bearer_authorized(&headers) {
        return Ok(unauthorized(&state.token_realm));
    }
    match (method.clone(), asset) {
        (
            Method::GET | Method::HEAD,
            asset @ (RegistryAsset::Manifest { .. } | RegistryAsset::Blob { .. }),
        ) => serve_asset(&state, asset, method).await,
        (Method::POST, RegistryAsset::BlobUpload) => store_blob_upload(&state, &query, body).await,
        (Method::PUT, RegistryAsset::BlobUploadSession) => {
            commit_blob_upload(&state, &query, body).await
        }
        (Method::PUT, RegistryAsset::Manifest { reference }) => {
            store_manifest(&state, &reference, body).await
        }
        _ => Err(StatusCode::METHOD_NOT_ALLOWED),
    }
}

/// `GET|HEAD` of a stored manifest or blob — the file-serving side of
/// [`serve_v2`].
async fn serve_asset(
    state: &MockRegistryState,
    asset: RegistryAsset,
    method: Method,
) -> Result<Response<Body>, StatusCode> {
    let path = match &asset {
        RegistryAsset::Manifest { reference } => state
            .registry_root
            .join("manifests")
            .join(stow_types::registry::GHCR_REPOSITORY)
            .join(manifest_file_name(reference)),
        RegistryAsset::Blob { digest } => state
            .registry_root
            .join("blobs")
            .join(digest.replace(':', "_")),
        RegistryAsset::BlobUpload | RegistryAsset::BlobUploadSession => {
            return Err(StatusCode::METHOD_NOT_ALLOWED);
        }
    };
    let bytes = read(&path).await.map_err(|error| {
        tracing::warn!(path = %path.display(), %error, "mock registry asset missing");
        StatusCode::NOT_FOUND
    })?;
    let mut response = if method == Method::HEAD {
        Response::new(Body::empty())
    } else {
        Response::new(Body::from(bytes.clone()))
    };
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&bytes.len().to_string()).expect("content-length header"),
    );
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    // Manifests carry the content digest like GHCR does, so a HEAD
    // freshness probe (`fetch_manifest_digest`) never falls back to a
    // full GET — unless the probe forged a claim, which is the point of
    // the forgery tests.
    if let RegistryAsset::Manifest { reference } = &asset {
        let claimed = state.forged_digest(&manifest_file_name(reference));
        let digest = claimed.unwrap_or_else(|| sha256_digest(&bytes));
        response.headers_mut().insert(
            HeaderName::from_static("docker-content-digest"),
            HeaderValue::from_str(&digest).expect("digest header value"),
        );
    }
    Ok(response)
}

/// `POST /v2/{repo}/blobs/uploads/?digest=<sha256:…>` — the monolithic
/// upload the distribution spec defines: the whole blob in the request
/// body, `201` when the bytes hash to the promised digest. When the probe
/// disables single `POST`s the same request opens an upload session —
/// `202` plus the session's `Location` — which only the commit `PUT`
/// completes, exactly like a registry that never learned the one-shot
/// form.
async fn store_blob_upload(
    state: &MockRegistryState,
    query: &BTreeMap<String, String>,
    body: Body,
) -> Result<Response<Body>, StatusCode> {
    if let Some(toggles) = &state.toggles
        && !toggles.single_post.load(Ordering::Relaxed)
    {
        let session = toggles.next_upload_id.fetch_add(1, Ordering::Relaxed) + 1;
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::ACCEPTED;
        response.headers_mut().insert(
            header::LOCATION,
            HeaderValue::from_str(&format!(
                "/v2/{}/blobs/uploads/{session}",
                stow_types::registry::GHCR_REPOSITORY
            ))
            .expect("location header value"),
        );
        return Ok(response);
    }
    let Some(digest) = query.get("digest") else {
        tracing::warn!("blob upload POST carried no digest query");
        return Err(StatusCode::BAD_REQUEST);
    };
    finish_blob_upload(state, digest, body).await
}

/// `PUT /v2/{repo}/blobs/uploads/{session}?digest=<sha256:…>` — the commit
/// that completes an upload session the `202` opened: the body is the blob
/// and the digest query is the promise, identical to the single `POST`.
async fn commit_blob_upload(
    state: &MockRegistryState,
    query: &BTreeMap<String, String>,
    body: Body,
) -> Result<Response<Body>, StatusCode> {
    let Some(digest) = query.get("digest") else {
        tracing::warn!("blob upload commit carried no digest query");
        return Err(StatusCode::BAD_REQUEST);
    };
    finish_blob_upload(state, digest, body).await
}

/// Store the uploaded bytes as `digest`'s blob, answering `201` + the
/// blob's `Location` + `Docker-Content-Digest` — the shared tail of the
/// single `POST` and the session commit `PUT`.
async fn finish_blob_upload(
    state: &MockRegistryState,
    digest: &str,
    body: Body,
) -> Result<Response<Body>, StatusCode> {
    let bytes = to_bytes(body, usize::MAX)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if sha256_digest(&bytes) != *digest {
        tracing::warn!(%digest, "blob upload body hashes differently than promised");
        return Err(StatusCode::BAD_REQUEST);
    }
    write_blob(&state.registry_root, digest, &bytes)
        .await
        .map_err(|error| {
            tracing::warn!(%digest, %error, "blob upload store failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::CREATED;
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&format!(
            "/v2/{}/blobs/{digest}",
            stow_types::registry::GHCR_REPOSITORY
        ))
        .expect("location header value"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("docker-content-digest"),
        HeaderValue::from_str(digest).expect("digest header value"),
    );
    Ok(response)
}

/// `PUT /v2/{repo}/manifests/{reference}` — stores the bytes under the tag
/// (or digest) named and, like a real registry, under their own content
/// digest so digest-addressed pulls resolve.
async fn store_manifest(
    state: &MockRegistryState,
    reference: &str,
    body: Body,
) -> Result<Response<Body>, StatusCode> {
    let bytes = to_bytes(body, usize::MAX)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let manifest: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        tracing::warn!(%reference, %error, "manifest PUT body is not JSON");
        StatusCode::BAD_REQUEST
    })?;
    if manifest
        .get("schemaVersion")
        .and_then(serde_json::Value::as_u64)
        != Some(2)
    {
        tracing::warn!(%reference, "manifest PUT lacks schemaVersion 2");
        return Err(StatusCode::BAD_REQUEST);
    }
    let digest = sha256_digest(&bytes);
    let store = |reference: &str, bytes: &[u8]| {
        let root = state.registry_root.clone();
        let reference = reference.to_owned();
        let bytes = bytes.to_vec();
        async move {
            write_manifest(
                &root,
                stow_types::registry::GHCR_REPOSITORY,
                &reference,
                &bytes,
            )
            .await
            .map_err(|error| {
                tracing::warn!(%reference, %error, "manifest PUT store failed");
                StatusCode::INTERNAL_SERVER_ERROR
            })
        }
    };
    store(reference, &bytes).await?;
    if !reference.starts_with("sha256:") {
        store(&digest, &bytes).await?;
    }
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::CREATED;
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&format!(
            "/v2/{}/manifests/{digest}",
            stow_types::registry::GHCR_REPOSITORY
        ))
        .expect("location header value"),
    );
    // A minimal registry answers the PUT without reporting the stored
    // digest — the probe reproduces that so the client's read-back is
    // exercised.
    if state
        .toggles
        .as_ref()
        .is_none_or(|toggles| toggles.manifest_digest_header.load(Ordering::Relaxed))
    {
        response.headers_mut().insert(
            HeaderName::from_static("docker-content-digest"),
            HeaderValue::from_str(&digest).expect("digest header value"),
        );
    }
    Ok(response)
}

/// The edge byte path for hosts that run no worker (the bench lane):
/// `GET|HEAD /api/v1/artifacts/{target}/{rustc_version}/{c_metadata}`
/// resolves the key through the signed index slice published into this
/// registry root and serves the bundle blob it pins — the same contract the
/// real edge answers from D1 and GHCR, so `STOW_EDGE_URL` can point here.
async fn serve_edge_artifact(
    State(state): State<MockRegistryState>,
    method: Method,
    AxumPath((target, rustc_version, c_metadata)): AxumPath<(String, String, String)>,
) -> Result<Response<Body>, StatusCode> {
    let index = state.index_slice(&target, &rustc_version).await?;
    let Some(row) = index
        .rows
        .iter()
        .find(|row| row.c_metadata.as_str() == c_metadata)
    else {
        tracing::warn!(%target, %rustc_version, %c_metadata, "byte path: no index row");
        return Err(StatusCode::NOT_FOUND);
    };
    let path = state
        .registry_root
        .join("blobs")
        .join(row.bundle_digest.replace(':', "_"));
    let bytes = read(&path).await.map_err(|error| {
        tracing::warn!(path = %path.display(), %error, "byte path: bundle blob missing");
        StatusCode::NOT_FOUND
    })?;
    let mut response = if method == Method::HEAD {
        Response::new(Body::empty())
    } else {
        Response::new(Body::from(bytes.clone()))
    };
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&bytes.len().to_string()).expect("content-length header"),
    );
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(STOW_BUNDLE_MEDIA_TYPE),
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-stow-cache"),
        HeaderValue::from_static("miss"),
    );
    Ok(response)
}

impl MockRegistryState {
    /// The decoded slice for `(target, rustc_version)`: the cached copy
    /// when the published manifest still hashes the same, otherwise the
    /// slice re-read from the registry root. A missing or malformed
    /// publication is a 404 — the byte path answers exactly what the index
    /// pins, nothing else.
    async fn index_slice(
        &self,
        target: &str,
        rustc_version: &str,
    ) -> Result<Arc<ArtifactIndex>, StatusCode> {
        let tag = index_tag(target, rustc_version);
        let manifest_path = self
            .registry_root
            .join("manifests")
            .join(stow_types::registry::GHCR_REPOSITORY)
            .join(&tag);
        let manifest_bytes = read(&manifest_path).await.map_err(|error| {
            tracing::warn!(path = %manifest_path.display(), %error, "byte path: index slice not published");
            StatusCode::NOT_FOUND
        })?;
        let manifest_digest = sha256_digest(&manifest_bytes);
        if let Some(cached) = self
            .index_slices
            .read()
            .expect("index slice cache poisoned")
            .get(&tag)
            && cached.manifest_digest == manifest_digest
        {
            return Ok(Arc::clone(&cached.index));
        }
        let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).map_err(|error| {
            tracing::error!(path = %manifest_path.display(), %error, "byte path: malformed index manifest");
            StatusCode::NOT_FOUND
        })?;
        let layer_digest = manifest
            .pointer("/layers/0/digest")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                tracing::error!(path = %manifest_path.display(), "byte path: index manifest has no layer");
                StatusCode::NOT_FOUND
            })?;
        let blob_path = self
            .registry_root
            .join("blobs")
            .join(layer_digest.replace(':', "_"));
        let index_bytes = read(&blob_path).await.map_err(|error| {
            tracing::error!(path = %blob_path.display(), %error, "byte path: index blob missing");
            StatusCode::NOT_FOUND
        })?;
        let index = stow_types::index::decode(&index_bytes).map_err(|error| {
            tracing::error!(path = %blob_path.display(), %error, "byte path: index blob does not decode");
            StatusCode::NOT_FOUND
        })?;
        let index = Arc::new(index);
        self.index_slices
            .write()
            .expect("index slice cache poisoned")
            .insert(
                tag,
                CachedIndexSlice {
                    manifest_digest,
                    index: Arc::clone(&index),
                },
            );
        Ok(index)
    }

    /// The digest the probe claims for a forged manifest file, if the
    /// test registered one — served in place of the bytes' real hash.
    fn forged_digest(&self, file_name: &str) -> Option<String> {
        self.toggles.as_ref().and_then(|toggles| {
            toggles
                .forged_digests
                .lock()
                .expect("forged digests poisoned")
                .get(file_name)
                .cloned()
        })
    }

    /// Log one request when a probe is attached; a `None` log costs a
    /// branch per request.
    fn record(&self, method: &Method, path: &str) {
        if let Some(requests) = &self.requests {
            requests
                .lock()
                .expect("request log poisoned")
                .push(RequestRecord {
                    method: method.clone(),
                    path: path.to_owned(),
                });
        }
    }

    /// GHCR's refusal shape for a matching scripted rule: `429` carrying
    /// `retry-after: <duration>` inside the OCI error body — the value the
    /// client's backoff honours. `None` when no rule has hits left for
    /// this request.
    fn rate_limited(&self, method: &Method, path: &str) -> Option<Response<Body>> {
        let rate_limits = self.rate_limits.as_ref()?;
        let mut rules = rate_limits.lock().expect("rate-limit rules poisoned");
        let rule = rules.iter_mut().find(|rule| {
            rule.remaining > 0 && rule.method == *method && path.contains(&rule.path_substr)
        })?;
        rule.remaining -= 1;
        let body = serde_json::json!({
            "errors": [{
                "code": "TOOMANYREQUESTS",
                "message": "retry-after: 100ms, allowed: 2000/minute",
            }],
        });
        let mut response = Response::new(Body::from(body.to_string()));
        *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        Some(response)
    }

    /// `Authorization: Bearer` presents a token this server minted that
    /// has not expired. Expired entries are evicted on sight.
    fn bearer_authorized(&self, headers: &HeaderMap) -> bool {
        let Some(token) = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
        else {
            return false;
        };
        let mut tokens = self
            .tokens
            .lock()
            .expect("mock registry token map poisoned");
        match tokens.issued.get(token) {
            Some(expires_at) if *expires_at > Instant::now() => true,
            Some(_) => {
                tokens.issued.remove(token);
                false
            }
            None => false,
        }
    }
}

/// `401` carrying the Bearer challenge the edge's token exchange parses:
/// realm is this server's `/token`, scope is the single repository's
/// `repository:water-rs/stow-cache:pull`.
fn unauthorized(realm: &str) -> Response<Body> {
    let repository = stow_types::registry::GHCR_REPOSITORY;
    let challenge = format!(
        "Bearer realm=\"{realm}\",service=\"{TOKEN_SERVICE}\",scope=\"repository:{repository}:pull\""
    );
    let body = serde_json::json!({
        "errors": [{
            "code": "UNAUTHORIZED",
            "message": "authentication required",
            "detail": [{"Type": "repository", "Name": repository, "Action": "pull"}],
        }],
    });
    let mut response = Response::new(Body::from(body.to_string()));
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_str(&challenge).expect("challenge header value"),
    );
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

fn manifest_file_name(reference: &str) -> String {
    if reference.starts_with("sha256:") {
        reference.replace(':', "_")
    } else {
        reference.to_owned()
    }
}

/// `/v2/water-rs/stow-cache/(manifests|blobs)/<id>` — the mock serves the
/// single `water-rs/stow-cache` repository: manifests addressed by tag and
/// blobs by digest, nothing else.
fn parse_registry_asset(rest: &str) -> stow_types::error::Result<RegistryAsset> {
    let segments = rest
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    let repository = stow_types::registry::GHCR_REPOSITORY
        .split('/')
        .collect::<Vec<_>>();
    if segments.len() < repository.len() + 2
        || segments.len() > repository.len() + 3
        || segments[..repository.len()] != repository[..]
    {
        return Err(stow_types::stow_error!(
            "expected /v2/{}/(manifests|blobs)/<id>, got /v2/{rest}",
            stow_types::registry::GHCR_REPOSITORY
        ));
    }
    let identifier = segments[repository.len() + 1].to_owned();
    match segments[repository.len()] {
        "manifests" if segments.len() == repository.len() + 2 => Ok(RegistryAsset::Manifest {
            reference: identifier,
        }),
        "blobs" if identifier == "uploads" && segments.len() == repository.len() + 2 => {
            Ok(RegistryAsset::BlobUpload)
        }
        "blobs" if identifier == "uploads" && segments.len() == repository.len() + 3 => {
            Ok(RegistryAsset::BlobUploadSession)
        }
        "blobs" if segments.len() == repository.len() + 2 => {
            Ok(RegistryAsset::Blob { digest: identifier })
        }
        other => Err(stow_types::stow_error!(
            "expected manifests/blobs segment in /v2/{rest}, got {other}"
        )),
    }
}

enum RegistryAsset {
    Manifest {
        reference: String,
    },
    Blob {
        digest: String,
    },
    /// `POST .../blobs/uploads/` — the monolithic or session-opening
    /// upload endpoint.
    BlobUpload,
    /// `PUT .../blobs/uploads/{session}` — the commit of an upload a `202`
    /// opened.
    BlobUploadSession,
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use axum::http::{Method, Request, StatusCode, header};
    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::bundle::{ArtifactBundleFile, STOW_BUNDLE_MEDIA_TYPE, STOW_RLIB_MEDIA_TYPE};
    use stow_types::identity::{CMetadata, CrateName, DependencyCMetadataJson, FeaturesJson};
    use stow_types::index::{
        ARTIFACT_INDEX_FORMAT_VERSION, ArtifactIndex, ArtifactIndexHeader, ArtifactIndexRow,
        STOW_INDEX_MEDIA_TYPE, encode, index_tag,
    };
    use stow_types::platform::{PanicStrategy, Profile, StripLevel};
    use stow_types::registry::{GHCR_BASE, GHCR_REPOSITORY, sha256_digest};
    use stow_types::upload_plan::{PlannedArtifact, PlannedArtifactOutput};
    use tower::ServiceExt as _;

    use super::{
        Body, RegistryProbe, SigningScheme, registry_app, write_blob, write_manifest,
        write_mock_signature,
    };

    const MANIFEST_URI: &str = "/v2/water-rs/stow-cache/manifests/latest";

    fn manifest_request() -> Request<Body> {
        Request::builder()
            .uri(MANIFEST_URI)
            .body(Body::empty())
            .expect("request builds")
    }

    /// The protocol the edge's anonymous pull drives: challenge → token →
    /// served, and a bearer the registry never issued is still a 401.
    #[tokio::test]
    async fn challenge_exchange_then_served() {
        let root = tempfile::tempdir().expect("registry root");
        std::fs::create_dir_all(root.path().join("manifests/water-rs/stow-cache"))
            .expect("manifest dir");
        std::fs::write(
            root.path().join("manifests/water-rs/stow-cache/latest"),
            b"{\"schemaVersion\":2}",
        )
        .expect("manifest file");
        let app = registry_app("127.0.0.1:40123", root.path().to_path_buf());

        // 1. Unauthenticated asset request → 401 + Bearer challenge. The
        // version ping carries the same challenge — that is how the
        // registry client discovers the realm before its first asset pull.
        for request in [
            manifest_request(),
            Request::builder()
                .uri("/v2/")
                .body(Body::empty())
                .expect("ping request builds"),
        ] {
            let response = app.clone().oneshot(request).await.expect("401 response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let challenge = response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .expect("challenge header")
                .to_str()
                .expect("challenge is a string")
                .to_owned();
            assert_eq!(
                challenge,
                "Bearer realm=\"http://127.0.0.1:40123/token\",service=\"mock-registry\",scope=\"repository:water-rs/stow-cache:pull\""
            );
        }

        // 2. The realm mints a bearer anonymously.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/token?service=mock-registry&scope=repository:water-rs/stow-cache:pull")
                    .body(Body::empty())
                    .expect("token request builds"),
            )
            .await
            .expect("token response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("token body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("token json");
        let token = body["token"].as_str().expect("token field");
        assert_eq!(body["expires_in"], 300);

        // 3. The issued bearer is served.
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(MANIFEST_URI)
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("authorized request builds"),
            )
            .await
            .expect("served response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("manifest body");
        assert_eq!(body.as_ref(), b"{\"schemaVersion\":2}");

        // 4. A bearer the registry never issued is still a 401.
        let response = app
            .oneshot(
                Request::builder()
                    .uri(MANIFEST_URI)
                    .header(header::AUTHORIZATION, "Bearer mock.forged")
                    .body(Body::empty())
                    .expect("forged request builds"),
            )
            .await
            .expect("forged response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    const TARGET: &str = "x86_64-unknown-linux-gnu";
    const RUSTC: &str = "1.98.0";
    const C_METADATA: &str = "aabbccddeeff0011";

    /// Publish one index slice pinning one bundle blob into `root`, the
    /// way `index-from-records` and `populate` lay them out.
    async fn publish_slice(root: &std::path::Path, bundle: &[u8]) {
        let bundle_digest = sha256_digest(bundle);
        write_blob(root, &bundle_digest, bundle)
            .await
            .expect("bundle blob");
        let index = ArtifactIndex {
            header: ArtifactIndexHeader {
                format_version: ARTIFACT_INDEX_FORMAT_VERSION,
                target: TARGET.parse().expect("target"),
                rustc_version: RUSTC.parse().expect("rustc"),
                generated_at: "2026-09-20T00:00:00Z".to_owned(),
                row_count: 1,
            },
            rows: vec![ArtifactIndexRow {
                crate_name: CrateName::parse("serde").expect("name"),
                version: "1.0.0".parse().expect("version"),
                features_json: FeaturesJson::default(),
                dependency_c_metadata_json: DependencyCMetadataJson::default(),
                c_metadata: CMetadata::parse(C_METADATA).expect("c_metadata"),
                compile_key: format!("{C_METADATA}{C_METADATA}"),
                bundle_digest,
                bundle_size: u64::try_from(bundle.len()).expect("bundle size"),
                artifact_kind: ArtifactKind::Rlib,
                crate_types: vec![RustCrateType::Rlib],
                profile: Profile {
                    opt_level: "0".to_owned(),
                    debuginfo: 0,
                    debug_assertions: true,
                    overflow_checks: true,
                    panic: PanicStrategy::Unwind,
                    strip: StripLevel::None,
                },
                emit: vec!["link".to_owned()],
            }],
        };
        let index_bytes = encode(&index).expect("encode index");
        let layer_digest = sha256_digest(&index_bytes);
        write_blob(root, &layer_digest, &index_bytes)
            .await
            .expect("index blob");
        let manifest = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "layers": [{ "mediaType": STOW_INDEX_MEDIA_TYPE, "digest": layer_digest, "size": index_bytes.len() }],
        }))
        .expect("manifest json");
        write_manifest(root, GHCR_REPOSITORY, &index_tag(TARGET, RUSTC), &manifest)
            .await
            .expect("index manifest");
    }

    /// The edge byte-path stand-in answers the exact-key route from the
    /// published slice: the pinned bundle for a listed key, 404 for an
    /// unlisted one, and HEAD carries the length without the body.
    #[tokio::test]
    async fn byte_path_serves_the_bundle_the_index_pins() {
        let root = tempfile::tempdir().expect("registry root");
        let bundle = b"not really a tar, but the bytes the index pins".to_vec();
        publish_slice(root.path(), &bundle).await;
        let app = registry_app("127.0.0.1:40123", root.path().to_path_buf());
        let uri = format!("/api/v1/artifacts/{TARGET}/{RUSTC}/{C_METADATA}?crate=serde");

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&uri)
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("served response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            STOW_BUNDLE_MEDIA_TYPE
        );
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("bundle body");
        assert_eq!(body.as_ref(), bundle.as_slice());

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::HEAD)
                    .uri(&uri)
                    .body(Body::empty())
                    .expect("head request builds"),
            )
            .await
            .expect("head response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_LENGTH],
            bundle.len().to_string()
        );
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("head body");
        assert!(body.is_empty());

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/v1/artifacts/{TARGET}/{RUSTC}/0011aabbccddeeff"
                    ))
                    .body(Body::empty())
                    .expect("miss request builds"),
            )
            .await
            .expect("miss response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Bind an ephemeral loopback port, serve the probe-instrumented
    /// registry on it, and return its `127.0.0.1:port` address with the
    /// probe. The realm must carry the bound port, so the app is built
    /// after the listener — and `stow_oci::RegistrySession` speaks real
    /// HTTP, unlike the `oneshot` fixtures above.
    async fn serve_probe_registry(root: &std::path::Path) -> (String, RegistryProbe) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let listen = listener.local_addr().expect("local addr").to_string();
        let (app, probe) = RegistryProbe::registry_app_probe(&listen, root.to_path_buf());
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve mock registry");
        });
        (listen, probe)
    }

    /// A minimal one-layer plan pushing `serde 1.0.0` — enough shape to
    /// drive every verb the push path sends.
    fn test_plan(root: &std::path::Path) -> PlannedArtifact {
        let output_bytes = b"the rlib the mock uploads".to_vec();
        let file_name = format!("libserde-{C_METADATA}.rlib");
        let output_path = root.join(&file_name);
        std::fs::write(&output_path, &output_bytes).expect("output file");
        PlannedArtifact {
            compile_key: format!("{C_METADATA}{C_METADATA}"),
            crate_name: CrateName::parse("serde").expect("name"),
            crate_version: "1.0.0".parse().expect("version"),
            c_metadata: CMetadata::parse(C_METADATA).expect("c_metadata"),
            extra_filename: format!("-{C_METADATA}"),
            features_json: FeaturesJson::default(),
            dependency_c_metadata_json: DependencyCMetadataJson::default(),
            dependency_compile_keys_json: "[]".to_owned(),
            target: TARGET.parse().expect("target"),
            rustc_version: RUSTC.parse().expect("rustc"),
            profile: Profile {
                opt_level: "0".to_owned(),
                debuginfo: 0,
                debug_assertions: true,
                overflow_checks: true,
                panic: PanicStrategy::Unwind,
                strip: StripLevel::None,
            },
            emit: vec!["link".to_owned()],
            oci_reference: format!(
                "{GHCR_BASE}:serde.1.0.0-x86_64-linux-gnu-1_98.0-000000-{C_METADATA}"
            ),
            kind: ArtifactKind::Rlib,
            crate_types: vec![RustCrateType::Rlib],
            artifact_size: u64::try_from(output_bytes.len()).expect("size"),
            compile_millis: 1,
            outputs: vec![PlannedArtifactOutput {
                path: output_path,
                bundle_file: ArtifactBundleFile {
                    file_name,
                    media_type: STOW_RLIB_MEDIA_TYPE.to_owned(),
                    sha256: sha256_digest(&output_bytes),
                },
            }],
            native: None,
            native_archive: None,
        }
    }

    /// A credentialed `pull,push` session on the served mock.
    fn push_session(listen: &str) -> stow_oci::RegistrySession {
        let base = stow_oci::RegistryBase::parse(&format!("http://{listen}/{}", GHCR_REPOSITORY))
            .expect("registry base");
        let credentials = stow_oci::RegistryCredentials {
            username: "mock".to_owned(),
            password: "mock".to_owned(),
        };
        base.push_session(&credentials)
    }

    /// The in-process signer the push tests inject: writes the signature
    /// pair into the mock root so `pull_signature_materials` reads it back
    /// over HTTP — no cosign binary involved.
    fn mock_sign(
        root: &std::path::Path,
    ) -> impl Fn(
        String,
        String,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = stow_types::error::Result<()>> + Send>,
    > {
        let root = root.to_path_buf();
        move |oci_reference: String, manifest_digest: String| {
            let root = root.clone();
            Box::pin(async move {
                let signer = SigningScheme::ECDSA_P256_SHA256_ASN1
                    .create_signer()
                    .map_err(|error| stow_types::stow_error!("create mock signer: {error}"))?;
                write_mock_signature(&root, &signer, &oci_reference, &manifest_digest)
                    .await
                    .map(|_| ())
            })
        }
    }

    /// The push path's request count against a served registry: the
    /// challenge ping and a single token mint for the whole push, one HEAD
    /// per blob with a monolithic `POST ?digest=` per miss, one PUT per
    /// manifest, and the signature pull pair — never a chunked session or
    /// a per-operation token.
    #[tokio::test]
    async fn one_push_is_one_token_and_monolithic_uploads() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let root = tempfile::tempdir().expect("registry root");
        let plan = test_plan(root.path());
        let (listen, probe) = serve_probe_registry(root.path()).await;

        let session = push_session(&listen);
        stow_oci::push_artifacts_with(&session, &[plan], mock_sign(root.path()))
            .await
            .expect("push succeeds");

        let log = probe.request_log();
        let count = |method: Method, marker: &str| {
            log.iter()
                .filter(|record| record.method == method && record.path.contains(marker))
                .count()
        };
        assert_eq!(
            log.iter()
                .filter(|record| record.path == "/v2/" && record.method == Method::GET)
                .count(),
            1,
            "one challenge ping"
        );
        assert_eq!(
            count(Method::GET, "/token"),
            1,
            "one bearer minted for the whole push"
        );
        assert_eq!(
            count(Method::HEAD, "/blobs/"),
            4,
            "a HEAD per blob: artifact layer + config, bundle layer + config"
        );
        assert_eq!(
            count(Method::POST, "/blobs/uploads"),
            4,
            "one monolithic POST per missing blob"
        );
        assert_eq!(
            count(Method::PUT, "/manifests/"),
            2,
            "a PUT per manifest: artifact and bundle"
        );
        assert_eq!(
            count(Method::GET, "/manifests/"),
            1,
            "the signature manifest pull"
        );
        assert_eq!(
            count(Method::GET, "/blobs/"),
            1,
            "the signature payload pull"
        );
        assert!(
            !log.iter().any(|record| record.method == Method::PATCH),
            "no chunked upload session"
        );
        assert_eq!(log.len(), 14, "the full push in fourteen requests");
    }

    /// GHCR's cap shape — `429 TOOMANYREQUESTS` carrying
    /// `retry-after: 100ms` in the error body — refuses the first three
    /// blob uploads; the push still lands because the client retries the
    /// refused request, not the whole publish.
    #[tokio::test]
    async fn push_retries_rate_limited_uploads() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let root = tempfile::tempdir().expect("registry root");
        let plan = test_plan(root.path());
        let (listen, probe) = serve_probe_registry(root.path()).await;
        probe.rate_limit(Method::POST, "/blobs/uploads", 3);

        let session = push_session(&listen);
        stow_oci::push_artifacts_with(&session, &[plan], mock_sign(root.path()))
            .await
            .expect("push succeeds after retries");

        let uploads = probe
            .request_log()
            .iter()
            .filter(|record| {
                record.method == Method::POST && record.path.contains("/blobs/uploads")
            })
            .count();
        assert_eq!(uploads, 7, "three refused uploads retried, four accepted");
    }

    /// A registry that answers `202` + a session `Location` — the
    /// distribution spec's answer to a single `POST` it does not
    /// implement — still gets every blob through the commit `PUT`.
    #[tokio::test]
    async fn push_falls_back_to_the_upload_session_put() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let root = tempfile::tempdir().expect("registry root");
        let plan = test_plan(root.path());
        let (listen, probe) = serve_probe_registry(root.path()).await;
        probe.refuse_single_post();

        let session = push_session(&listen);
        stow_oci::push_artifacts_with(&session, &[plan], mock_sign(root.path()))
            .await
            .expect("push succeeds through commit PUTs");

        let count = |method: Method, marker: &str| {
            probe
                .request_log()
                .iter()
                .filter(|record| record.method == method && record.path.contains(marker))
                .count()
        };
        assert_eq!(
            count(Method::POST, "/blobs/uploads"),
            4,
            "each missing blob opened an upload session"
        );
        assert_eq!(
            count(Method::PUT, "/blobs/uploads/"),
            4,
            "each session committed with one PUT"
        );
        assert_eq!(
            count(Method::PUT, "/manifests/"),
            2,
            "manifest puts are unchanged by the upload fallback"
        );
    }

    /// A `PUT` answer without `Docker-Content-Digest` makes the client
    /// read the manifest back under the pushed bytes' own digest and
    /// require the same bytes — both manifests get the round trip.
    #[tokio::test]
    async fn push_verifies_manifest_bytes_without_digest_header() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let root = tempfile::tempdir().expect("registry root");
        let plan = test_plan(root.path());
        let (listen, probe) = serve_probe_registry(root.path()).await;
        probe.omit_manifest_digest_header();

        let session = push_session(&listen);
        stow_oci::push_artifacts_with(&session, &[plan], mock_sign(root.path()))
            .await
            .expect("push verifies manifests by read-back");

        let read_backs = probe
            .request_log()
            .iter()
            .filter(|record| {
                record.method == Method::GET && record.path.contains("/manifests/sha256:")
            })
            .count();
        assert_eq!(
            read_backs, 2,
            "artifact and bundle manifests each verified by digest"
        );
    }

    /// A hostile registry serving forged manifest bytes under a real
    /// `Docker-Content-Digest` is rejected — whether the pull names the
    /// manifest by tag or by the digest the header claims.
    #[tokio::test]
    async fn pull_rejects_forged_manifest_bodies() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let root = tempfile::tempdir().expect("registry root");
        let (listen, probe) = serve_probe_registry(root.path()).await;

        let real =
            br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}"#;
        let forged =
            br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[]}"#;
        let real_digest = sha256_digest(real);
        probe.forge_manifest("forged-tag", forged, &real_digest);
        probe.forge_manifest(&real_digest, forged, &real_digest);

        let base = stow_oci::RegistryBase::parse(&format!("http://{listen}/{GHCR_REPOSITORY}"))
            .expect("registry base");
        let session = base.session();

        let tag_reference = base.reference("forged-tag").expect("tag reference");
        let error = session
            .pull_manifest(&tag_reference)
            .await
            .expect_err("forged body under a tag is rejected");
        assert!(
            !error.is_not_found(),
            "a forged body is a refusal, not an absence: {error}"
        );

        let digest_reference = base
            .digest_reference(&real_digest)
            .expect("digest reference");
        let error = session
            .pull_manifest(&digest_reference)
            .await
            .expect_err("forged body under its claimed digest is rejected");
        assert!(
            !error.is_not_found(),
            "a forged body is a refusal, not an absence: {error}"
        );
    }
}
