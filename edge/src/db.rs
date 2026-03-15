use skyzen_cloudflare::CfD1;
use skyzen_services::DbValue;

/// Result of looking up an artifact by composite key.
#[derive(Debug, serde::Deserialize)]
pub struct ArtifactRow {
    pub oci_reference: String,
    pub oci_digest: String,
    pub artifact_size: Option<u64>,
}

/// Validate that a c_metadata string is a cargo-generated hex hash.
fn validate_c_metadata(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err("invalid c_metadata format".to_owned());
    }
    Ok(())
}

/// Validate a target triple.
fn validate_target(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err("invalid target format".to_owned());
    }
    Ok(())
}

/// Validate stable rustc version strings such as `1.83.0`.
fn validate_rustc_version(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 32
        || !value.chars().all(|ch| ch.is_ascii_digit() || ch == '.')
    {
        return Err("invalid rustc_version format".to_owned());
    }
    Ok(())
}

/// Validate a crates.io crate name.
fn validate_crate_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err("invalid crate_name format".to_owned());
    }
    Ok(())
}

pub async fn get_artifact_reference(
    d1: &CfD1,
    c_metadata: &str,
    target: &str,
    rustc_version: &str,
) -> Result<Option<ArtifactRow>, String> {
    validate_c_metadata(c_metadata)?;
    validate_target(target)?;
    validate_rustc_version(rustc_version)?;

    d1.prepare(
        "SELECT oci_reference, oci_digest, artifact_size \
         FROM artifacts \
         WHERE c_metadata = ? AND target = ? AND rustc_version = ?",
    )
    .map_err(|error| format!("d1 prepare: {error}"))?
    .bind(&[
        DbValue::Text(c_metadata.to_owned()),
        DbValue::Text(target.to_owned()),
        DbValue::Text(rustc_version.to_owned()),
    ])
    .map_err(|error| format!("d1 bind: {error}"))?
    .first_json()
    .await
    .map_err(|error| format!("d1 query: {error}"))
}

pub async fn is_subscribed_crate(d1: &CfD1, crate_name: &str) -> Result<bool, String> {
    validate_crate_name(crate_name)?;

    let row: Option<SubscribedRow> = d1
        .prepare("SELECT crate_name FROM subscriptions WHERE crate_name = ?")
        .map_err(|error| format!("d1 prepare: {error}"))?
        .bind(&[DbValue::Text(crate_name.to_owned())])
        .map_err(|error| format!("d1 bind: {error}"))?
        .first_json()
        .await
        .map_err(|error| format!("d1 query: {error}"))?;

    Ok(row.is_some())
}

pub async fn log_cache_miss(
    d1: &CfD1,
    c_metadata: &str,
    crate_name: &str,
    target: &str,
    city_code: &str,
) -> Result<(), String> {
    validate_c_metadata(c_metadata)?;
    validate_crate_name(crate_name)?;
    validate_target(target)?;

    let city_code = sanitize_city_code(city_code);

    d1.prepare(
        "INSERT INTO cache_misses (crate_name, c_metadata, target, city_code) VALUES (?, ?, ?, ?)",
    )
    .map_err(|error| format!("d1 prepare: {error}"))?
    .bind(&[
        DbValue::Text(crate_name.to_owned()),
        DbValue::Text(c_metadata.to_owned()),
        DbValue::Text(target.to_owned()),
        DbValue::Text(city_code),
    ])
    .map_err(|error| format!("d1 bind: {error}"))?
    .run()
    .await
    .map_err(|error| format!("d1 miss log: {error}"))?;

    Ok(())
}

fn sanitize_city_code(city_code: &str) -> String {
    city_code
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(16)
        .collect()
}

#[derive(Debug, serde::Deserialize)]
struct SubscribedRow {
    crate_name: String,
}
