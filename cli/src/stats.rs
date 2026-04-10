use crate::config::StowConfig;
use crate::state_db::connect;

pub async fn record_hit(config: &StowConfig, crate_name: &str) -> stow_types::error::Result<()> {
    update_stats(config, crate_name, StatsField::Hits).await
}

pub async fn record_miss(config: &StowConfig, crate_name: &str) -> stow_types::error::Result<()> {
    update_stats(config, crate_name, StatsField::Misses).await
}

pub async fn record_error(config: &StowConfig, crate_name: &str) -> stow_types::error::Result<()> {
    update_stats(config, crate_name, StatsField::Errors).await
}

pub async fn read_summary(config: &StowConfig) -> stow_types::error::Result<StatsSummary> {
    let connection = connect(&config.cache_dir).await?;
    let rows = sqlx::query_as::<_, (String, i64, i64, i64)>(
        "SELECT crate_name, hits, misses, errors FROM crate_stats",
    )
    .fetch_all(&connection)
    .await?;

    let mut summary = StatsSummary::default();
    for (crate_name, hits, misses, errors) in rows {
        let (hits, misses, errors) = (hits as u64, misses as u64, errors as u64);
        if crate_name.starts_with("cc:") {
            summary.cc_hits = summary.cc_hits.saturating_add(hits);
            summary.cc_misses = summary.cc_misses.saturating_add(misses);
            summary.cc_errors = summary.cc_errors.saturating_add(errors);
        } else {
            summary.rust_hits = summary.rust_hits.saturating_add(hits);
            summary.rust_misses = summary.rust_misses.saturating_add(misses);
            summary.rust_errors = summary.rust_errors.saturating_add(errors);
        }
    }
    Ok(summary)
}

async fn update_stats(
    config: &StowConfig,
    crate_name: &str,
    field: StatsField,
) -> stow_types::error::Result<()> {
    let connection = connect(&config.cache_dir).await?;
    let query = match field {
        StatsField::Hits => {
            "INSERT INTO crate_stats (crate_name, hits, misses, errors) VALUES (?, 1, 0, 0) \
             ON CONFLICT(crate_name) DO UPDATE SET hits = crate_stats.hits + 1"
        }
        StatsField::Misses => {
            "INSERT INTO crate_stats (crate_name, hits, misses, errors) VALUES (?, 0, 1, 0) \
             ON CONFLICT(crate_name) DO UPDATE SET misses = crate_stats.misses + 1"
        }
        StatsField::Errors => {
            "INSERT INTO crate_stats (crate_name, hits, misses, errors) VALUES (?, 0, 0, 1) \
             ON CONFLICT(crate_name) DO UPDATE SET errors = crate_stats.errors + 1"
        }
    };
    sqlx::query(query)
        .bind(crate_name)
        .execute(&connection)
        .await?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum StatsField {
    Hits,
    Misses,
    Errors,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct StatsSummary {
    pub rust_hits: u64,
    pub rust_misses: u64,
    pub rust_errors: u64,
    pub cc_hits: u64,
    pub cc_misses: u64,
    pub cc_errors: u64,
}
