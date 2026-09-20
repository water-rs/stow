//! `stow-mock-registry`: a local OCI Registry V2 + cosign-compatible mock used
//! for end-to-end testing without contacting GHCR. Two modes: `populate`
//! materializes signed artifacts on disk from an upload plan; `serve` answers
//! HTTP requests from a wrangler-dev edge worker.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_fs::{create_dir_all, read, write};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path as AxumPath, Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
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
use stow_types::registry::{bundle_oci_reference, sha256_digest};
use stow_types::upload_plan::{PlannedArtifact, PublishedArtifact};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

const OCI_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
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
        Command::Serve(request) => serve_registry(request).await,
    }
}

async fn populate_registry(request: PopulateArgs) -> stow_types::error::Result<()> {
    let plans = load_upload_plan(&request.upload_plan_path).await?;
    validate_upload_plan(&plans)?;
    create_dir_all(&request.registry_root).await?;
    if let Some(parent) = request.sqlite_path.parent() {
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
    upsert_sqlite(&request.sqlite_path, &records).await?;
    tracing::info!(
        artifacts = records.len(),
        "mock registry population completed"
    );
    Ok(())
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
/// registry-issued unexpired tokens are served.
fn registry_app(listen: &str, registry_root: PathBuf) -> Router {
    Router::new()
        .route("/v2", get(v2_ping).head(v2_ping))
        .route("/v2/", get(v2_ping).head(v2_ping))
        .route("/v2/{*rest}", get(serve_v2).head(serve_v2))
        .route("/token", get(issue_token))
        .with_state(MockRegistryState {
            registry_root,
            token_realm: format!("http://{listen}/token"),
            tokens: Arc::new(Mutex::new(TokenState::default())),
        })
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

    let payload = SimpleSigning::new(&plan.oci_reference.parse()?, &manifest_digest);
    let payload_bytes = serde_json::to_vec(&payload)?;
    let payload_digest = sha256_digest(&payload_bytes);
    write_blob(registry_root, &payload_digest, &payload_bytes).await?;
    let signature = signer.sign(&payload_bytes).map_err(|error| {
        stow_types::stow_error!("sign mock payload for {}: {error}", plan.oci_reference)
    })?;
    let signature_manifest_ref = sigstore_signature_tag(&manifest_digest);
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
    write_manifest(
        registry_root,
        &repo,
        &signature_manifest_ref,
        &signature_manifest_bytes,
    )
    .await?;

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
    Serve(ServeArgs),
}

#[derive(Debug, Clone, Args)]
struct PopulateArgs {
    #[arg(long = "upload-plan")]
    upload_plan_path: PathBuf,
    #[arg(long = "registry-root")]
    registry_root: PathBuf,
    #[arg(long = "sqlite")]
    sqlite_path: PathBuf,
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
}

/// Issued bearer tokens and their expirations; `Instant` is enough
/// because the map dies with the process anyway.
#[derive(Debug, Default)]
struct TokenState {
    issued: HashMap<String, Instant>,
    /// Monotonic salt so back-to-back mints never collide.
    next: u64,
}

async fn v2_ping() -> StatusCode {
    StatusCode::OK
}

/// `GET /token?service=…&scope=…` — mints an anonymous bearer exactly the
/// way GHCR does for public packages. The mock grants every requested
/// scope; the token is recorded with its expiry and later `/v2/` requests
/// are served only when they present it.
async fn issue_token(
    State(state): State<MockRegistryState>,
    Query(params): Query<BTreeMap<String, String>>,
) -> Json<serde_json::Value> {
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
) -> Result<Response<Body>, StatusCode> {
    let asset = parse_registry_asset(&rest).map_err(|error| {
        tracing::warn!(path = %rest, %error, "invalid mock registry path");
        StatusCode::BAD_REQUEST
    })?;
    if !state.bearer_authorized(&headers) {
        return Ok(unauthorized(&state.token_realm));
    }
    let path = match asset {
        RegistryAsset::Manifest { reference } => state
            .registry_root
            .join("manifests")
            .join(stow_types::registry::GHCR_REPOSITORY)
            .join(manifest_file_name(&reference)),
        RegistryAsset::Blob { digest } => state
            .registry_root
            .join("blobs")
            .join(digest.replace(':', "_")),
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
    Ok(response)
}

impl MockRegistryState {
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
    if segments.len() != repository.len() + 2 || segments[..repository.len()] != repository[..] {
        return Err(stow_types::stow_error!(
            "expected /v2/{}/(manifests|blobs)/<id>, got /v2/{rest}",
            stow_types::registry::GHCR_REPOSITORY
        ));
    }
    let identifier = segments[repository.len() + 1].to_owned();
    match segments[repository.len()] {
        "manifests" => Ok(RegistryAsset::Manifest {
            reference: identifier,
        }),
        "blobs" => Ok(RegistryAsset::Blob { digest: identifier }),
        other => Err(stow_types::stow_error!(
            "expected manifests/blobs segment in /v2/{rest}, got {other}"
        )),
    }
}

enum RegistryAsset {
    Manifest { reference: String },
    Blob { digest: String },
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt as _;

    use super::{Body, registry_app};

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

        // 1. Unauthenticated asset request → 401 + Bearer challenge.
        let response = app
            .clone()
            .oneshot(manifest_request())
            .await
            .expect("401 response");
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
}
