use skyzen_services::Db;

use crate::db;

/// Log a cache miss. Only logs if the crate name is in the subscriptions table.
pub async fn log_miss(db: &Db, c_metadata: &str, crate_name: &str, target: &str, city_code: &str) {
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

    if let Err(error) = db::log_cache_miss(db, c_metadata, crate_name, target, city_code).await {
        tracing::warn!(error = %error, "failed to log cache miss to D1");
    }
}
