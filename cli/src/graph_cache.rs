use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use stow_types::api::{DependencyGraphRequest, DependencyGraphResponse};

use crate::config::StowConfig;
use crate::state_file::{duration_millis, now_millis, with_locked_json_file};

pub async fn load(
    config: &StowConfig,
    request: &DependencyGraphRequest,
) -> eyre::Result<Option<DependencyGraphResponse>> {
    let path = config.graph_cache_path();
    let key = cache_key(request)?;
    let ttl = config.graph_cache_ttl;
    smol::unblock(move || {
        with_locked_json_file::<GraphCacheState, Option<DependencyGraphResponse>>(&path, |state| {
            let now_ms = now_millis();
            let ttl_ms = duration_millis(ttl);
            state
                .entries
                .retain(|_, entry| now_ms.saturating_sub(entry.inserted_at_ms) < ttl_ms);
            Ok(state.entries.get(&key).map(|entry| entry.response.clone()))
        })
    })
    .await
}

pub async fn store(
    config: &StowConfig,
    request: &DependencyGraphRequest,
    response: &DependencyGraphResponse,
) -> eyre::Result<()> {
    let path = config.graph_cache_path();
    let key = cache_key(request)?;
    let response = response.clone();
    let ttl = config.graph_cache_ttl;
    smol::unblock(move || {
        with_locked_json_file::<GraphCacheState, ()>(&path, |state| {
            let now_ms = now_millis();
            let ttl_ms = duration_millis(ttl);
            state
                .entries
                .retain(|_, entry| now_ms.saturating_sub(entry.inserted_at_ms) < ttl_ms);
            state.entries.insert(
                key.clone(),
                GraphCacheEntry {
                    inserted_at_ms: now_ms,
                    response: response.clone(),
                },
            );
            Ok(())
        })
    })
    .await
}

fn cache_key(request: &DependencyGraphRequest) -> eyre::Result<String> {
    let bytes = serde_json::to_vec(request)
        .map_err(|error| eyre::eyre!("serialize dependency graph cache key: {error}"))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct GraphCacheState {
    entries: BTreeMap<String, GraphCacheEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GraphCacheEntry {
    inserted_at_ms: u64,
    response: DependencyGraphResponse,
}
