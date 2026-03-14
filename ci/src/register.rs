use stow_types::api::ArtifactRecord;
use zenwave::Client;

const CLOUDFLARE_API_TOKEN_ENV: &str = "CLOUDFLARE_API_TOKEN";
const CLOUDFLARE_ACCOUNT_ID_ENV: &str = "CLOUDFLARE_ACCOUNT_ID";
const CLOUDFLARE_D1_DATABASE_ID_ENV: &str = "CLOUDFLARE_D1_DATABASE_ID";

pub async fn register_artifact(record: &ArtifactRecord) -> eyre::Result<()> {
    let api_token = env_required(CLOUDFLARE_API_TOKEN_ENV)?;
    let account_id = env_required(CLOUDFLARE_ACCOUNT_ID_ENV)?;
    let database_id = env_required(CLOUDFLARE_D1_DATABASE_ID_ENV)?;
    let url = format!(
        "https://api.cloudflare.com/client/v4/accounts/{account_id}/d1/database/{database_id}/query"
    );

    let sql = "INSERT OR REPLACE INTO artifacts (c_metadata, target, rustc_version, crate_name, version, features_json, oci_reference, oci_digest, has_native, is_proc_macro, artifact_size, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))";
    let body = serde_json::json!({
        "sql": sql,
        "params": [
            record.c_metadata,
            record.target,
            record.rustc_version,
            record.crate_name,
            record.version,
            record.features_json,
            record.oci_reference,
            record.oci_digest,
            if record.has_native { 1 } else { 0 },
            if record.is_proc_macro { 1 } else { 0 },
            record.artifact_size,
        ]
    });

    let mut client = zenwave::client();
    client
        .post(&url)
        .bearer_auth(api_token)
        .json_body(&body)
        .await?;

    tracing::info!(
        crate_name = %record.crate_name,
        version = %record.version,
        target = %record.target,
        c_metadata = %record.c_metadata,
        "registered artifact record in Cloudflare D1"
    );

    Ok(())
}

fn env_required(name: &str) -> eyre::Result<String> {
    std::env::var(name).map_err(|_| eyre::eyre!("missing required environment variable {name}"))
}
