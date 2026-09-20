use skyzen_cloudflare::worker::{AnalyticsEngineDataPointBuilder, AnalyticsEngineDataset};
use skyzen_services::Db;

use crate::db;

/// Log a cache miss. Only logs if the crate name is in the subscriptions
/// table; the event lands in Analytics Engine rather than D1 so misses
/// never spend billed rows.
pub async fn log_miss(
    db: &Db,
    analytics: &AnalyticsEngineDataset,
    c_metadata: &str,
    crate_name: &str,
    target: &str,
    city_code: &str,
) {
    let is_subscribed = match db::is_subscribed_crate(db, crate_name).await {
        Ok(is_subscribed) => is_subscribed,
        Err(error) => {
            tracing::warn!(crate_name, error = %error, "failed to validate subscription");
            return;
        }
    };

    if !is_subscribed {
        tracing::debug!(crate_name, "miss for unknown crate, not logging");
        return;
    }

    let city_code = sanitize_city_code(city_code);
    if let Err(error) = AnalyticsEngineDataPointBuilder::new()
        .indexes([crate_name])
        .blobs([crate_name, c_metadata, target, city_code.as_str()])
        .write_to(analytics)
    {
        tracing::warn!(error = %error, "failed to log cache miss to Analytics Engine");
    }
}

fn sanitize_city_code(city_code: &str) -> String {
    city_code
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(16)
        .collect()
}
