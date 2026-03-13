use skyzen_cloudflare::CfD1;

use crate::db;

/// Log a cache miss. Only logs if the crate name is in the subscriptions table.
///
/// Also sends a boost to the scheduler DO (fire-and-forget).
pub async fn log_miss(
    d1: &CfD1,
    c_metadata: &str,
    crate_name: &str,
    target: &str,
    city_code: &str,
    scheduler_do_url: Option<&str>,
) {
    // Only log misses for known/subscribed crates (anti-abuse)
    let is_subscribed = db::is_subscribed_crate(d1, crate_name).await.unwrap_or(false);
    if !is_subscribed {
        tracing::debug!(crate_name, "miss for unknown crate, not logging");
        return;
    }

    // Log miss to D1
    if let Err(e) = db::log_cache_miss(d1, c_metadata, crate_name, target, city_code).await {
        tracing::warn!(error = %e, "failed to log cache miss to D1");
    }

    // Fire-and-forget boost to scheduler DO
    if let Some(url) = scheduler_do_url {
        let boost = stow_types::api::MissBoost {
            crate_name: crate_name.to_string(),
            target: target.to_string(),
        };
        // Don't await — fire and forget
        let boost_url = format!("{url}/boost");
        let _ = send_boost(&boost_url, &boost).await;
    }
}

async fn send_boost(url: &str, boost: &stow_types::api::MissBoost) -> Result<(), String> {
    let body = serde_json::to_vec(boost).map_err(|e| e.to_string())?;
    let resp = zenwave::post(url)
        .await
        .map_err(|e| e.to_string())?
        .header("Content-Type", "application/json")
        .map_err(|e| e.to_string())?
        .bytes_body(body)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        tracing::warn!(status = resp.status().as_u16(), "scheduler boost failed");
    }
    Ok(())
}
