use std::collections::BTreeMap;

use crate::config::StowConfig;
use crate::state_file::{duration_millis, now_millis, with_locked_json_file};

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
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct CircuitState {
    consecutive_failures: u32,
    tripped_at_ms: Option<u64>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct NegativeCacheState {
    entries: BTreeMap<String, u64>,
}
