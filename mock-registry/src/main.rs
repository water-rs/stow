use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use async_fs::{create_dir_all, read, write};
use axum::{
    body::Body,
    extract::{Path as AxumPath, State},
    http::{HeaderValue, Method, StatusCode, header},
    response::Response,
    routing::get,
    Router,
};
use base64::Engine;
use clap::{Args, Parser, Subcommand};
use rusqlite::Connection;
use sha2::Digest;
use sigstore::cosign::payload::SimpleSigning;
use sigstore::crypto::signing_key::SigStoreKeyPair;
use sigstore::crypto::{SigStoreSigner, SigningScheme};
use stow_types::api::ArtifactRecord;
use stow_types::bundle::ArtifactBlobConfig;
use stow_types::upload_plan::PlannedArtifact;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;
#[path = "../../shared/artifact_table_schema.rs"]
mod artifact_table_schema;

const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
const STOW_CONFIG_MEDIA_TYPE: &str = "application/vnd.stow.artifact.config.v1+json";
const SIGSTORE_OCI_MEDIA_TYPE: &str = "application/vnd.dev.cosign.simplesigning.v1+json";
const SIGSTORE_SIGNATURE_ANNOTATION: &str = "dev.cosignproject.cosign/signature";
const SIGSTORE_CERT_ANNOTATION: &str = "dev.sigstore.cosign/certificate";

fn main() -> eyre::Result<()> {
    install_tracing();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn async_main() -> eyre::Result<()> {
    match Cli::parse().command {
        Command::Populate(request) => populate_registry(request).await,
        Command::Serve(request) => serve_registry(request).await,
    }
}

async fn populate_registry(request: PopulateArgs) -> eyre::Result<()> {
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
        .map_err(|error| eyre::eyre!("create mock signer from private key: {error}"))?;

    let mut digests_by_reference = BTreeMap::new();
    for plan in &plans {
        let digest = write_mock_registry_entry(&request.registry_root, &signer, plan).await?;
        digests_by_reference.insert(plan.oci_reference.clone(), digest);
    }

    let records = stow_types::upload_plan::build_artifact_records(&plans, &digests_by_reference)?;
    write_records_outputs(&request, &records).await?;
    upsert_sqlite(&request.sqlite_path, &records).await?;
    tracing::info!(
        artifacts = records.len(),
        "mock registry population completed"
    );
    Ok(())
}

async fn serve_registry(request: ServeArgs) -> eyre::Result<()> {
    let listener = TcpListener::bind(&request.listen)
        .await
        .map_err(|error| eyre::eyre!("bind mock registry {}: {error}", request.listen))?;
    let app = Router::new()
        .route("/v2", get(v2_ping).head(v2_ping))
        .route("/v2/", get(v2_ping).head(v2_ping))
        .route("/v2/{*rest}", get(serve_v2).head(serve_v2))
        .with_state(MockRegistryState {
            registry_root: request.registry_root.clone(),
        });
    tracing::info!(
        listen = %request.listen,
        registry_root = %request.registry_root.display(),
        "mock registry server listening"
    );
    axum::serve(listener, app)
        .await
        .map_err(|error| eyre::eyre!("serve mock registry: {error}"))
}

async fn load_upload_plan(path: &Path) -> eyre::Result<Vec<PlannedArtifact>> {
    let bytes = read(path)
        .await
        .map_err(|error| eyre::eyre!("read upload plan {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| eyre::eyre!("parse upload plan {}: {error}", path.display()))
}

fn validate_upload_plan(plans: &[PlannedArtifact]) -> eyre::Result<()> {
    if plans.is_empty() {
        return Err(eyre::eyre!("upload plan is empty"));
    }

    let mut composite_keys = BTreeSet::new();
    for plan in plans {
        if plan.outputs.is_empty() {
            return Err(eyre::eyre!(
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
            return Err(eyre::eyre!(
                "upload plan contains duplicate artifact key {} {} {}",
                plan.c_metadata,
                plan.target,
                plan.rustc_version
            ));
        }
    }

    Ok(())
}

async fn load_key_pair(path: &Path) -> eyre::Result<SigStoreKeyPair> {
    let bytes = read(path)
        .await
        .map_err(|error| eyre::eyre!("read private key {}: {error}", path.display()))?;
    SigStoreKeyPair::from_pem(&bytes)
        .map_err(|error| eyre::eyre!("load mock private key {}: {error}", path.display()))
}

async fn write_public_key(path: &Path, key_pair: &SigStoreKeyPair) -> eyre::Result<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent).await?;
    }
    let public_key = key_pair
        .public_key_to_pem()
        .map_err(|error| eyre::eyre!("encode mock public key {}: {error}", path.display()))?;
    write(path, public_key.as_bytes())
        .await
        .map_err(|error| eyre::eyre!("write public key {}: {error}", path.display()))
}

async fn write_mock_registry_entry(
    registry_root: &Path,
    signer: &SigStoreSigner,
    plan: &PlannedArtifact,
) -> eyre::Result<String> {
    let config_bytes = serde_json::to_vec(&ArtifactBlobConfig {
        crate_name: plan.crate_name.clone(),
        crate_version: plan.crate_version.clone(),
        c_metadata: plan.c_metadata.clone(),
        target: plan.target.clone(),
        rustc_version: plan.rustc_version.clone(),
        features_json: plan.features_json.clone(),
        artifact_size: plan.artifact_size,
        kind: plan.kind.clone(),
        crate_types: plan.crate_types.clone(),
        outputs: plan
            .outputs
            .iter()
            .map(|output| output.bundle_file.clone())
            .collect(),
        native: plan.native.clone(),
    })?;
    let config_digest = sha256_prefixed(&config_bytes);
    write_blob(registry_root, &config_digest, &config_bytes).await?;

    let mut layers = Vec::with_capacity(plan.outputs.len());
    for output in &plan.outputs {
        let bytes = read(&output.path).await.map_err(|error| {
            eyre::eyre!("read artifact output {}: {error}", output.path.display())
        })?;
        let output_path = output.path.clone();
        let compression_level = *zstd::compression_level_range().end();
        let compressed = smol::unblock(move || {
            zstd::bulk::compress(&bytes, compression_level).map_err(|error| {
                eyre::eyre!(
                    "zstd compress {} at level {}: {error}",
                    output_path.display(),
                    compression_level
                )
            })
        })
        .await?;
        let digest = sha256_prefixed(&compressed);
        write_blob(registry_root, &digest, &compressed).await?;
        layers.push(serde_json::json!({
            "mediaType": output.bundle_file.storage_media_type(),
            "digest": digest,
            "size": compressed.len(),
        }));
    }

    let manifest_bytes = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST_MEDIA_TYPE,
        "config": {
            "mediaType": STOW_CONFIG_MEDIA_TYPE,
            "digest": config_digest,
            "size": config_bytes.len(),
        },
        "layers": layers,
    }))?;
    let manifest_digest = sha256_prefixed(&manifest_bytes);
    let (repo, tag) = split_reference(&plan.oci_reference)?;
    write_manifest(registry_root, &repo, &tag, &manifest_bytes).await?;
    write_manifest(registry_root, &repo, &manifest_digest, &manifest_bytes).await?;

    let payload = SimpleSigning::new(&plan.oci_reference.parse()?, &manifest_digest);
    let payload_bytes = serde_json::to_vec(&payload)?;
    let payload_digest = sha256_prefixed(&payload_bytes);
    write_blob(registry_root, &payload_digest, &payload_bytes).await?;
    let signature = signer
        .sign(&payload_bytes)
        .map_err(|error| eyre::eyre!("sign mock payload for {}: {error}", plan.oci_reference))?;
    let signature_manifest_ref = format!("{}.sig", manifest_digest.replace(':', "-"));
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature);
    let signature_config_bytes = b"{}".to_vec();
    let signature_config_digest = sha256_prefixed(&signature_config_bytes);
    write_blob(
        registry_root,
        &signature_config_digest,
        &signature_config_bytes,
    )
    .await?;
    let signature_manifest_bytes = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST_MEDIA_TYPE,
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
                SIGSTORE_CERT_ANNOTATION: "mock-local",
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

    Ok(manifest_digest)
}

async fn write_records_outputs(
    request: &PopulateArgs,
    records: &[ArtifactRecord],
) -> eyre::Result<()> {
    if let Some(path) = request.records_output_path.as_ref() {
        if let Some(parent) = path.parent() {
            create_dir_all(parent).await?;
        }
        write(path, serde_json::to_vec_pretty(records)?)
            .await
            .map_err(|error| eyre::eyre!("write artifact records {}: {error}", path.display()))?;
    }
    if let Some(path) = request.sql_output_path.as_ref() {
        if let Some(parent) = path.parent() {
            create_dir_all(parent).await?;
        }
        write(path, build_sql(records))
            .await
            .map_err(|error| eyre::eyre!("write artifact SQL {}: {error}", path.display()))?;
    }
    Ok(())
}

async fn upsert_sqlite(path: &Path, records: &[ArtifactRecord]) -> eyre::Result<()> {
    let sqlite_path = path.to_path_buf();
    let records = records.to_vec();
    smol::unblock(move || -> eyre::Result<()> {
        let mut connection = Connection::open(&sqlite_path)
            .map_err(|error| eyre::eyre!("open sqlite {}: {error}", sqlite_path.display()))?;
        connection
            .execute_batch(include_str!("../../edge/src/schema.sql"))
            .map_err(|error| eyre::eyre!("ensure sqlite schema {}: {error}", sqlite_path.display()))?;
        ensure_artifact_table_columns(&connection, &sqlite_path)?;
        let transaction = connection
            .transaction()
            .map_err(|error| eyre::eyre!("begin sqlite transaction {}: {error}", sqlite_path.display()))?;
        let sql = "INSERT INTO artifacts (c_metadata, target, rustc_version, crate_name, version, features_json, oci_reference, oci_digest, has_native, artifact_kind, crate_types_json, artifact_size, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, datetime('now')) ON CONFLICT(c_metadata, target, rustc_version) DO UPDATE SET crate_name=excluded.crate_name, version=excluded.version, features_json=excluded.features_json, oci_reference=excluded.oci_reference, oci_digest=excluded.oci_digest, has_native=excluded.has_native, artifact_kind=excluded.artifact_kind, crate_types_json=excluded.crate_types_json, artifact_size=excluded.artifact_size, created_at=datetime('now')";
        let mut statement = transaction
            .prepare(sql)
            .map_err(|error| eyre::eyre!("prepare sqlite upsert {}: {error}", sqlite_path.display()))?;
        for record in &records {
            let crate_types_json = serde_json::to_string(&record.crate_types)?;
            statement
                .execute(rusqlite::params![
                    record.c_metadata,
                    record.target,
                    record.rustc_version,
                    record.crate_name,
                    record.version,
                    record.features_json,
                    record.oci_reference,
                    record.oci_digest,
                    if record.has_native { 1 } else { 0 },
                    record.artifact_kind.as_str(),
                    crate_types_json,
                    record.artifact_size,
                ])
                .map_err(|error| eyre::eyre!("upsert sqlite artifact {} {} {}: {error}", record.crate_name, record.target, record.c_metadata))?;
        }
        drop(statement);
        transaction
            .commit()
            .map_err(|error| eyre::eyre!("commit sqlite transaction {}: {error}", sqlite_path.display()))?;
        Ok(())
    })
    .await
}

fn ensure_artifact_table_columns(connection: &Connection, sqlite_path: &Path) -> eyre::Result<()> {
    let mut statement = connection
        .prepare("PRAGMA table_info(artifacts)")
        .map_err(|error| {
            eyre::eyre!(
                "prepare table_info query {}: {error}",
                sqlite_path.display()
            )
        })?;
    let existing_columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|error| eyre::eyre!("query table_info {}: {error}", sqlite_path.display()))?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|error| eyre::eyre!("read table_info row {}: {error}", sqlite_path.display()))?;
    drop(statement);

    for column in artifact_table_schema::REQUIRED_ARTIFACT_COLUMNS {
        if existing_columns.contains(column.name) {
            continue;
        }
        connection.execute_batch(column.add_sql).map_err(|error| {
            eyre::eyre!(
                "migrate sqlite artifacts add column {} in {}: {error}",
                column.name,
                sqlite_path.display()
            )
        })?;
    }

    Ok(())
}

async fn write_blob(root: &Path, digest: &str, bytes: &[u8]) -> eyre::Result<()> {
    let path = root.join("blobs").join(digest.replace(':', "_"));
    if let Some(parent) = path.parent() {
        create_dir_all(parent).await?;
    }
    write(&path, bytes)
        .await
        .map_err(|error| eyre::eyre!("write blob {}: {error}", path.display()))
}

async fn write_manifest(
    root: &Path,
    repo: &str,
    reference: &str,
    bytes: &[u8],
) -> eyre::Result<()> {
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
        .map_err(|error| eyre::eyre!("write manifest {}: {error}", path.display()))
}

fn split_reference(reference: &str) -> eyre::Result<(String, String)> {
    let without_prefix = reference
        .strip_prefix("ghcr.io/stow-rs/cache/")
        .ok_or_else(|| eyre::eyre!("unexpected OCI reference prefix: {reference}"))?;
    let (repo, tag) = without_prefix
        .split_once(':')
        .ok_or_else(|| eyre::eyre!("missing OCI tag in reference {reference}"))?;
    Ok((repo.to_owned(), tag.to_owned()))
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}

fn build_sql(records: &[ArtifactRecord]) -> Vec<u8> {
    let mut sql = String::from("BEGIN;\n");
    for record in records {
        let crate_types_json = serde_json::to_string(&record.crate_types)
            .expect("crate_types serialization must succeed");
        sql.push_str("INSERT INTO artifacts (");
        sql.push_str("c_metadata, target, rustc_version, crate_name, version, features_json, oci_reference, oci_digest, has_native, artifact_kind, crate_types_json, artifact_size, created_at");
        sql.push_str(") VALUES (");
        sql.push_str(&sql_quote(&record.c_metadata));
        sql.push_str(", ");
        sql.push_str(&sql_quote(&record.target));
        sql.push_str(", ");
        sql.push_str(&sql_quote(&record.rustc_version));
        sql.push_str(", ");
        sql.push_str(&sql_quote(&record.crate_name));
        sql.push_str(", ");
        sql.push_str(&sql_quote(&record.version));
        sql.push_str(", ");
        sql.push_str(&sql_quote(&record.features_json));
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
        sql.push_str(&record.artifact_size.to_string());
        sql.push_str(
            ", datetime('now')) ON CONFLICT(c_metadata, target, rustc_version) DO UPDATE SET ",
        );
        sql.push_str("crate_name=excluded.crate_name, version=excluded.version, features_json=excluded.features_json, ");
        sql.push_str("oci_reference=excluded.oci_reference, oci_digest=excluded.oci_digest, has_native=excluded.has_native, ");
        sql.push_str("artifact_kind=excluded.artifact_kind, crate_types_json=excluded.crate_types_json, artifact_size=excluded.artifact_size, created_at=datetime('now');\n");
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
}

async fn v2_ping() -> StatusCode {
    StatusCode::OK
}

async fn serve_v2(
    State(state): State<MockRegistryState>,
    method: Method,
    AxumPath(rest): AxumPath<String>,
) -> Result<Response<Body>, StatusCode> {
    let asset = parse_registry_asset(&rest).map_err(|error| {
        tracing::warn!(path = %rest, %error, "invalid mock registry path");
        StatusCode::BAD_REQUEST
    })?;
    let path = match asset {
        RegistryAsset::Manifest { repo, reference } => state
            .registry_root
            .join("manifests")
            .join(repo)
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

fn manifest_file_name(reference: &str) -> String {
    if reference.starts_with("sha256:") {
        reference.replace(':', "_")
    } else {
        reference.to_owned()
    }
}

fn parse_registry_asset(rest: &str) -> eyre::Result<RegistryAsset> {
    let segments = rest
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.len() < 5 || segments[0] != "stow-rs" || segments[1] != "cache" {
        return Err(eyre::eyre!(
            "expected /v2/stow-rs/cache/<repo>/(manifests|blobs)/<id>, got /v2/{rest}"
        ));
    }
    let marker_index = segments
        .iter()
        .position(|segment| matches!(*segment, "manifests" | "blobs"))
        .ok_or_else(|| eyre::eyre!("missing manifests/blobs segment in /v2/{rest}"))?;
    if marker_index <= 2 || marker_index + 1 >= segments.len() || marker_index + 2 != segments.len()
    {
        return Err(eyre::eyre!("invalid mock registry asset path /v2/{rest}"));
    }
    let repo = segments[2..marker_index].join("/");
    let identifier = segments[marker_index + 1].to_owned();
    match segments[marker_index] {
        "manifests" => Ok(RegistryAsset::Manifest {
            repo,
            reference: identifier,
        }),
        "blobs" => Ok(RegistryAsset::Blob { digest: identifier }),
        _ => unreachable!("validated above"),
    }
}

enum RegistryAsset {
    Manifest { repo: String, reference: String },
    Blob { digest: String },
}
