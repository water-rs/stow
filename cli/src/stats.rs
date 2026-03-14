use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use eyre::Context;
use fs2::FileExt;

use crate::config::StowConfig;

pub async fn record_hit(config: &StowConfig, crate_name: &str) -> eyre::Result<()> {
    update_stats(config, crate_name, |stats| stats.hits = stats.hits.saturating_add(1)).await
}

pub async fn record_miss(config: &StowConfig, crate_name: &str) -> eyre::Result<()> {
    update_stats(config, crate_name, |stats| stats.misses = stats.misses.saturating_add(1)).await
}

pub async fn record_error(config: &StowConfig, crate_name: &str) -> eyre::Result<()> {
    update_stats(config, crate_name, |stats| stats.errors = stats.errors.saturating_add(1)).await
}

pub async fn read_summary(config: &StowConfig) -> eyre::Result<StatsSummary> {
    let path = config.stats_path();
    smol::unblock(move || {
        if !path.exists() {
            return Ok(StatsSummary::default());
        }
        let raw = std::fs::read_to_string(&path)
            .map_err(|error| eyre::eyre!("read stats file {}: {error}", path.display()))?;
        let stats = if raw.trim().is_empty() {
            StatsFile::default()
        } else {
            serde_json::from_str::<StatsFile>(&raw)
                .map_err(|error| eyre::eyre!("parse stats file {}: {error}", path.display()))?
        };
        let mut summary = StatsSummary::default();
        for (label, value) in stats.per_crate {
            if label.starts_with("cc:") {
                summary.cc_hits = summary.cc_hits.saturating_add(value.hits);
                summary.cc_misses = summary.cc_misses.saturating_add(value.misses);
                summary.cc_errors = summary.cc_errors.saturating_add(value.errors);
            } else {
                summary.rust_hits = summary.rust_hits.saturating_add(value.hits);
                summary.rust_misses = summary.rust_misses.saturating_add(value.misses);
                summary.rust_errors = summary.rust_errors.saturating_add(value.errors);
            }
        }
        Ok(summary)
    })
    .await
}

async fn update_stats(
    config: &StowConfig,
    crate_name: &str,
    update: impl FnOnce(&mut StatsState) + Send + 'static,
) -> eyre::Result<()> {
    let path = config.stats_path();
    let crate_name = crate_name.to_owned();
    smol::unblock(move || with_locked_stats(&path, crate_name, update)).await
}

fn with_locked_stats(
    path: &Path,
    crate_name: String,
    update: impl FnOnce(&mut StatsState),
) -> eyre::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .wrap_err_with(|| format!("open stats file {}", path.display()))?;
    file.lock_exclusive()
        .wrap_err_with(|| format!("lock stats file {}", path.display()))?;

    let result = (|| {
        let mut raw = String::new();
        file.read_to_string(&mut raw)
            .wrap_err_with(|| format!("read stats file {}", path.display()))?;
        let mut stats = if raw.trim().is_empty() {
            StatsFile::default()
        } else {
            serde_json::from_str(&raw)
                .wrap_err_with(|| format!("parse stats file {}", path.display()))?
        };
        let entry = stats.per_crate.entry(crate_name).or_default();
        update(entry);
        let serialized = serde_json::to_vec(&stats)
            .wrap_err_with(|| format!("serialize stats file {}", path.display()))?;
        file.set_len(0)
            .wrap_err_with(|| format!("truncate stats file {}", path.display()))?;
        file.seek(SeekFrom::Start(0))
            .wrap_err_with(|| format!("seek stats file {}", path.display()))?;
        file.write_all(&serialized)
            .wrap_err_with(|| format!("write stats file {}", path.display()))?;
        file.sync_all()
            .wrap_err_with(|| format!("sync stats file {}", path.display()))?;
        Ok(())
    })();

    let unlock_result = file.unlock();
    match (result, unlock_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(eyre::eyre!(
            "unlock stats file {}: {error}",
            path.display()
        )),
        (Err(error), Err(_)) => Err(error),
    }
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct StatsFile {
    per_crate: std::collections::BTreeMap<String, StatsState>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct StatsState {
    hits: u64,
    misses: u64,
    errors: u64,
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
