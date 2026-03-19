use skyzen_services::{Db, Kv};
use zenwave::Client;

const CRATE_VERSION_KEY_PREFIX: &str = "crate-version";
const CRATES_IO_API_BASE: &str = "https://crates.io/api/v1/crates";
const CRATES_IO_USER_AGENT: &str = "stow-watcher";

#[derive(Debug, Clone, serde::Deserialize)]
pub struct SubscribedCrate {
    pub name: String,
    pub latest_version: String,
    pub downloads: u64,
}

pub async fn list_subscribed(db: &Db) -> Result<Vec<String>, String> {
    let rows = db
        .query("SELECT crate_name FROM subscriptions ORDER BY crate_name")
        .fetch_all::<SubscriptionRow>()
        .await
        .map_err(|error| format!("list subscribed crates: {error}"))?;

    Ok(rows.into_iter().map(|row| row.crate_name).collect())
}

pub async fn detect_updates(db: &Db, state_kv: &Kv) -> Result<Vec<SubscribedCrate>, String> {
    let crate_names = list_subscribed(db).await?;
    let mut updates = Vec::new();

    for crate_name in crate_names {
        let crate_info = fetch_crate(&crate_name).await?;
        let state_key = crate_version_key(&crate_name);
        let previous_version = state_kv
            .get_text(&state_key)
            .await
            .map_err(|error| format!("read watcher state for {crate_name}: {error}"))?;

        if previous_version.as_deref() != Some(crate_info.latest_version.as_str()) {
            tracing::info!(
                crate_name = %crate_info.name,
                previous_version = ?previous_version,
                latest_version = %crate_info.latest_version,
                "detected subscribed crate version change"
            );
            state_kv
                .put(state_key.as_str(), crate_info.latest_version.as_bytes())
                .await
                .map_err(|error| {
                    format!("persist watcher state for {}: {error}", crate_info.name)
                })?;
            updates.push(crate_info);
        }
    }

    Ok(updates)
}

pub async fn fetch_current(crate_name: &str) -> Result<SubscribedCrate, String> {
    let url = format!("{CRATES_IO_API_BASE}/{crate_name}");
    let mut client = zenwave::client();
    let response = client
        .get(&url)
        .map_err(|error| format!("build crates.io request for {crate_name}: {error}"))?
        .header("User-Agent", CRATES_IO_USER_AGENT)
        .map_err(|error| format!("set crates.io user-agent for {crate_name}: {error}"))?
        .json::<CrateResponse>()
        .await
        .map_err(|error| format!("fetch crates.io metadata for {crate_name}: {error}"))?;

    Ok(SubscribedCrate {
        name: response.krate.id,
        latest_version: response.krate.max_version,
        downloads: response.krate.downloads,
    })
}

async fn fetch_crate(crate_name: &str) -> Result<SubscribedCrate, String> {
    fetch_current(crate_name).await
}

fn crate_version_key(crate_name: &str) -> String {
    format!("{CRATE_VERSION_KEY_PREFIX}:{crate_name}")
}

#[derive(Debug, serde::Deserialize)]
struct SubscriptionRow {
    crate_name: String,
}

#[derive(Debug, serde::Deserialize)]
struct CrateResponse {
    #[serde(rename = "crate")]
    krate: CrateMetadata,
}

#[derive(Debug, serde::Deserialize)]
struct CrateMetadata {
    id: String,
    max_version: String,
    downloads: u64,
}
