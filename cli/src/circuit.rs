use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eyre::Context;
use fs2::FileExt;

use crate::config::StowConfig;

pub async fn is_tripped(config: &StowConfig) -> eyre::Result<bool> {
    let path = config.circuit_path();
    let reset_after = config.circuit_reset_after;
    smol::unblock(move || {
        with_locked_json_file::<CircuitState, bool>(&path, |state| {
            if let Some(tripped_at_ms) = state.tripped_at_ms {
                let elapsed = now_millis().saturating_sub(tripped_at_ms);
                if elapsed < duration_millis(reset_after) {
                    return Ok(true);
                }
                state.tripped_at_ms = None;
                state.consecutive_failures = 0;
            }
            Ok(false)
        })
    })
    .await
}

pub async fn record_success(config: &StowConfig) -> eyre::Result<()> {
    let path = config.circuit_path();
    smol::unblock(move || {
        with_locked_json_file::<CircuitState, ()>(&path, |state| {
            state.consecutive_failures = 0;
            state.tripped_at_ms = None;
            Ok(())
        })
    })
    .await
}

pub async fn record_failure(config: &StowConfig) -> eyre::Result<()> {
    let path = config.circuit_path();
    let trip_threshold = config.circuit_trip_threshold;
    smol::unblock(move || {
        with_locked_json_file::<CircuitState, ()>(&path, |state| {
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            if state.consecutive_failures >= trip_threshold {
                state.tripped_at_ms = Some(now_millis());
            }
            Ok(())
        })
    })
    .await
}

pub async fn negative_cache_contains(config: &StowConfig, key: &str) -> eyre::Result<bool> {
    let path = config.negative_cache_path();
    let key = key.to_owned();
    let ttl = config.negative_cache_ttl;
    smol::unblock(move || {
        with_locked_json_file::<NegativeCacheState, bool>(&path, |state| {
            let now_ms = now_millis();
            let ttl_ms = duration_millis(ttl);
            state.entries.retain(|_, inserted_at_ms| {
                now_ms.saturating_sub(*inserted_at_ms) < ttl_ms
            });
            Ok(state.entries.contains_key(&key))
        })
    })
    .await
}

pub async fn record_negative_cache(config: &StowConfig, key: &str) -> eyre::Result<()> {
    let path = config.negative_cache_path();
    let key = key.to_owned();
    let ttl = config.negative_cache_ttl;
    smol::unblock(move || {
        with_locked_json_file::<NegativeCacheState, ()>(&path, |state| {
            let now_ms = now_millis();
            let ttl_ms = duration_millis(ttl);
            state.entries.retain(|_, inserted_at_ms| {
                now_ms.saturating_sub(*inserted_at_ms) < ttl_ms
            });
            state.entries.insert(key.clone(), now_ms);
            Ok(())
        })
    })
    .await
}

fn with_locked_json_file<T, R>(
    path: &Path,
    mut operation: impl FnMut(&mut T) -> eyre::Result<R>,
) -> eyre::Result<R>
where
    T: Default + serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .wrap_err_with(|| format!("open state file {}", path.display()))?;
    file.lock_exclusive()
        .wrap_err_with(|| format!("lock state file {}", path.display()))?;

    let result = (|| {
        let mut raw = String::new();
        file.read_to_string(&mut raw)
            .wrap_err_with(|| format!("read state file {}", path.display()))?;
        let mut value = if raw.trim().is_empty() {
            T::default()
        } else {
            serde_json::from_str(&raw)
                .wrap_err_with(|| format!("parse state file {}", path.display()))?
        };
        let result = operation(&mut value)?;
        let serialized = serde_json::to_vec(&value)
            .wrap_err_with(|| format!("serialize state file {}", path.display()))?;
        file.set_len(0)
            .wrap_err_with(|| format!("truncate state file {}", path.display()))?;
        file.seek(SeekFrom::Start(0))
            .wrap_err_with(|| format!("seek state file {}", path.display()))?;
        file.write_all(&serialized)
            .wrap_err_with(|| format!("write state file {}", path.display()))?;
        file.sync_all()
            .wrap_err_with(|| format!("sync state file {}", path.display()))?;
        Ok(result)
    })();

    let unlock_result = file.unlock();
    match (result, unlock_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(eyre::eyre!(
            "unlock state file {}: {error}",
            path.display()
        )),
        (Err(error), Err(_)) => Err(error),
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis() as u64
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis() as u64
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct CircuitState {
    consecutive_failures: u32,
    tripped_at_ms: Option<u64>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct NegativeCacheState {
    entries: BTreeMap<String, u64>,
}
