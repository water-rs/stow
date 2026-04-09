use std::collections::{BTreeMap, BTreeSet};

use stow_types::api::ArtifactRecord;
use zenwave::Client;

const CLOUDFLARE_API_TOKEN_ENV: &str = "CLOUDFLARE_API_TOKEN";
const CLOUDFLARE_ACCOUNT_ID_ENV: &str = "CLOUDFLARE_ACCOUNT_ID";
const CLOUDFLARE_D1_DATABASE_ID_ENV: &str = "CLOUDFLARE_D1_DATABASE_ID";

/// Register an artifact record directly in Cloudflare D1.
///
/// This is the trusted CI registration path — artifact records go straight
/// into D1 via the Cloudflare REST API, bypassing the untrusted edge entirely.
pub async fn register_artifact(record: &ArtifactRecord) -> eyre::Result<()> {
    let sql = "INSERT OR REPLACE INTO artifacts (compile_key, c_metadata, extra_filename, target, rustc_version, crate_name, version, features_json, dependency_c_metadata_json, oci_reference, oci_digest, has_native, artifact_kind, crate_types_json, profile_json, emit_json, artifact_size, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))";
    let crate_types_json = serde_json::to_string(&record.crate_types)?;
    let profile_json = serde_json::to_string(&record.profile)?;
    let emit_json = serde_json::to_string(&record.emit)?;
    let body = serde_json::json!({
        "sql": sql,
        "params": [
            record.compile_key,
            record.c_metadata,
            record.extra_filename,
            record.target,
            record.rustc_version,
            record.crate_name,
            record.version,
            record.features_json,
            record.dependency_c_metadata_json,
            record.oci_reference,
            record.oci_digest,
            if record.has_native { 1 } else { 0 },
            record.artifact_kind.as_str(),
            crate_types_json,
            profile_json,
            emit_json,
            record.artifact_size,
        ]
    });

    execute_query(body).await?;

    tracing::info!(
        crate_name = %record.crate_name,
        version = %record.version,
        target = %record.target,
        c_metadata = %record.c_metadata,
        "registered artifact record in Cloudflare D1"
    );

    Ok(())
}

pub async fn query_registered_artifacts(
    keys: &[(String, String, String)],
) -> eyre::Result<BTreeMap<String, String>> {
    if keys.is_empty() {
        return Ok(BTreeMap::new());
    }

    let mut params = Vec::with_capacity(keys.len() * 3);
    let tuples = keys
        .iter()
        .map(|(c_metadata, target, rustc_version)| {
            params.push(serde_json::Value::String(c_metadata.clone()));
            params.push(serde_json::Value::String(target.clone()));
            params.push(serde_json::Value::String(rustc_version.clone()));
            "(?, ?, ?)".to_owned()
        })
        .collect::<Vec<_>>()
        .join(", ");

    let sql = format!(
        "SELECT c_metadata, target, rustc_version, oci_reference, oci_digest \
         FROM artifacts \
         WHERE (c_metadata, target, rustc_version) IN ({tuples})"
    );
    let body = serde_json::json!({
        "sql": sql,
        "params": params,
    });
    let response = execute_query(body).await?;
    let mut rows = BTreeMap::new();
    let mut seen_keys = BTreeSet::new();

    for result in response.result {
        for row in result.results {
            let composite = (
                row.c_metadata.clone(),
                row.target.clone(),
                row.rustc_version.clone(),
            );
            if !seen_keys.insert(composite) {
                return Err(eyre::eyre!(
                    "D1 returned duplicate artifact registration for {} {} {}",
                    row.c_metadata,
                    row.target,
                    row.rustc_version
                ));
            }
            rows.insert(row.oci_reference, row.oci_digest);
        }
    }

    Ok(rows)
}

fn env_required(name: &str) -> eyre::Result<String> {
    std::env::var(name).map_err(|_| eyre::eyre!("missing required environment variable {name}"))
}

async fn execute_query(body: serde_json::Value) -> eyre::Result<D1QueryEnvelope> {
    let api_token = env_required(CLOUDFLARE_API_TOKEN_ENV)?;
    let account_id = env_required(CLOUDFLARE_ACCOUNT_ID_ENV)?;
    let database_id = env_required(CLOUDFLARE_D1_DATABASE_ID_ENV)?;
    let url = format!(
        "https://api.cloudflare.com/client/v4/accounts/{account_id}/d1/database/{database_id}/query"
    );

    let mut client = zenwave::client();
    let response: D1QueryEnvelope = client
        .post(&url)?
        .bearer_auth(api_token)
        .json_body(&body)?
        .json()
        .await?;

    if !response.success {
        return Err(eyre::eyre!("Cloudflare D1 query envelope reported failure"));
    }
    if response.result.iter().any(|result| !result.success) {
        return Err(eyre::eyre!("Cloudflare D1 query result reported failure"));
    }

    Ok(response)
}

#[derive(Debug, serde::Deserialize)]
struct D1QueryEnvelope {
    success: bool,
    result: Vec<D1QueryResult>,
}

#[derive(Debug, serde::Deserialize)]
struct D1QueryResult {
    success: bool,
    #[serde(default)]
    results: Vec<RegisteredArtifactRow>,
}

#[derive(Debug, serde::Deserialize)]
struct RegisteredArtifactRow {
    c_metadata: String,
    target: String,
    rustc_version: String,
    oci_reference: String,
    oci_digest: String,
}
