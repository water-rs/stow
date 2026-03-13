use skyzen_cloudflare::CfD1;

/// Result of looking up an artifact by composite key.
#[derive(Debug, serde::Deserialize)]
pub struct ArtifactRow {
    pub oci_reference: String,
    pub oci_digest: String,
    pub artifact_size: Option<i64>,
    pub is_proc_macro: i32,
    pub has_native: i32,
}

/// Validate that a c_metadata string is safe for SQL embedding.
/// c_metadata is a hex-encoded hash: only hex digits, bounded length.
fn validate_c_metadata(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validate that a target triple is safe for SQL embedding.
/// Only alphanumeric, hyphens, and underscores.
fn validate_target(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Validate that a rustc version string is safe for SQL embedding.
/// Semver format: digits and dots.
fn validate_rustc_version(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Validate a crate name for safe SQL embedding.
fn validate_crate_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Lookup an artifact's OCI reference by composite key.
///
/// Uses literal values in prepared statement SQL. All inputs are validated
/// to contain only safe characters before embedding.
pub async fn get_artifact_reference(
    d1: &CfD1,
    c_metadata: &str,
    target: &str,
    rustc_version: &str,
) -> Result<Option<ArtifactRow>, String> {
    if !validate_c_metadata(c_metadata) {
        return Err("invalid c_metadata format".into());
    }
    if !validate_target(target) {
        return Err("invalid target format".into());
    }
    if !validate_rustc_version(rustc_version) {
        return Err("invalid rustc_version format".into());
    }

    let sql = format!(
        "SELECT oci_reference, oci_digest, artifact_size, is_proc_macro, has_native \
         FROM artifacts \
         WHERE c_metadata = '{}' AND target = '{}' AND rustc_version = '{}'",
        c_metadata, target, rustc_version
    );

    let stmt = d1.prepare(&sql).map_err(|e| format!("d1 prepare: {e}"))?;
    let row: Option<ArtifactRow> = stmt
        .first_json()
        .await
        .map_err(|e| format!("d1 query: {e}"))?;
    Ok(row)
}

/// Check if a crate name is in the subscriptions table.
pub async fn is_subscribed_crate(d1: &CfD1, crate_name: &str) -> Result<bool, String> {
    if !validate_crate_name(crate_name) {
        return Ok(false);
    }

    let sql = format!(
        "SELECT 1 FROM subscriptions WHERE crate_name = '{}'",
        crate_name
    );
    let stmt = d1.prepare(&sql).map_err(|e| format!("d1 prepare: {e}"))?;
    let result: Option<serde_json::Value> = stmt
        .first_json()
        .await
        .map_err(|e| format!("d1 query: {e}"))?;
    Ok(result.is_some())
}

/// Log a cache miss to D1. Only logs for known (subscribed) crate names.
pub async fn log_cache_miss(
    d1: &CfD1,
    c_metadata: &str,
    crate_name: &str,
    target: &str,
    city_code: &str,
) -> Result<(), String> {
    if !validate_c_metadata(c_metadata) || !validate_crate_name(crate_name) || !validate_target(target)
    {
        return Ok(()); // silently skip invalid inputs
    }

    // Sanitize city_code (only alphanumeric)
    let city_code: String = city_code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(16)
        .collect();

    let sql = format!(
        "INSERT INTO cache_misses (crate_name, c_metadata, target, city_code) \
         VALUES ('{}', '{}', '{}', '{}')",
        crate_name, c_metadata, target, city_code
    );

    d1.exec(&sql)
        .await
        .map_err(|e| format!("d1 miss log: {e}"))?;
    Ok(())
}
