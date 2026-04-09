use clap::{Parser, Subcommand};
use stow_types::api::{EnqueueRequest, EnqueueSource};
use tracing_subscriber::EnvFilter;
use zenwave::Client;

const STOW_EDGE_URL_ENV: &str = "STOW_EDGE_URL";
const SCHEDULER_AUTH_TOKEN_ENV: &str = "SCHEDULER_AUTH_TOKEN";
const SCHEDULER_AUTH_HEADER: &str = "x-stow-scheduler-token";
const CRATES_IO_API_BASE: &str = "https://crates.io/api/v1/crates";
const CRATES_IO_USER_AGENT: &str = "stow-admin";
const CRATES_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

#[derive(Parser)]
#[command(name = "stow-admin")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Submit(SubmitArgs),
    PreheatT100(PreheatT100Args),
}

#[derive(Parser)]
struct SubmitArgs {
    #[arg(long)]
    crate_name: String,
    #[arg(long)]
    version: String,
    #[arg(long)]
    features_json: String,
    #[arg(long)]
    target: String,
    #[arg(long)]
    rustc_version: String,
    #[arg(long, default_value_t = 0)]
    downloads: u64,
}

#[derive(Parser)]
struct PreheatT100Args {
    #[arg(long)]
    target: String,
    #[arg(long)]
    rustc_version: String,
    #[arg(long, default_value_t = 100)]
    limit: usize,
}

#[derive(Debug, serde::Deserialize)]
struct CratesResponse {
    crates: Vec<CrateSummary>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct CrateSummary {
    id: String,
    max_version: String,
    downloads: u64,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct CrateVersion {
    num: String,
    #[serde(default)]
    features: std::collections::BTreeMap<String, Vec<String>>,
    yanked: bool,
}

fn main() -> eyre::Result<()> {
    install_tracing();
    smol::block_on(run())
}

async fn run() -> eyre::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Submit(args) => {
            submit(vec![EnqueueRequest {
                crate_name: args.crate_name,
                version: args.version,
                features_json: args.features_json,
                target: args.target,
                rustc_version: args.rustc_version,
                downloads: args.downloads,
                source: EnqueueSource::CacheMiss,
                depends_on: Vec::new(),
            }])
            .await
        }
        Command::PreheatT100(args) => {
            let crates = fetch_top_crates(args.limit).await?;
            let mut requests = Vec::new();
            for krate in crates {
                let versions = fetch_versions(&krate.id).await?;
                let selected = select_version_lines(&versions)?;
                for version in selected {
                    let has_default = versions
                        .iter()
                        .find(|candidate| candidate.num == version)
                        .ok_or_else(|| {
                            eyre::eyre!(
                                "selected version {} missing from crates.io response for {}",
                                version,
                                krate.id
                            )
                        })?
                        .features
                        .contains_key("default");
                    requests.push(EnqueueRequest {
                        crate_name: krate.id.clone(),
                        version,
                        features_json: if has_default {
                            "[\"default\"]".to_owned()
                        } else {
                            "[]".to_owned()
                        },
                        target: args.target.clone(),
                        rustc_version: args.rustc_version.clone(),
                        downloads: krate.downloads,
                        source: EnqueueSource::CrateUpdate,
                        depends_on: Vec::new(),
                    });
                }
            }
            submit(requests).await
        }
    }
}

async fn fetch_top_crates(limit: usize) -> eyre::Result<Vec<CrateSummary>> {
    let per_page = limit.min(100);
    let url = format!("{CRATES_IO_API_BASE}?page=1&per_page={per_page}&sort=downloads");
    let response = get_json_with_retries::<CratesResponse>(&url).await?;
    Ok(response.crates.into_iter().take(limit).collect())
}

async fn fetch_versions(crate_name: &str) -> eyre::Result<Vec<CrateVersion>> {
    let url = format!("{CRATES_IO_API_BASE}/{crate_name}");
    let response = get_json_with_retries::<serde_json::Value>(&url).await?;
    let versions = serde_json::from_value::<Vec<CrateVersion>>(response["versions"].clone())?;
    Ok(versions
        .into_iter()
        .filter(|version| !version.yanked)
        .collect())
}

async fn get_json_with_retries<T>(url: &str) -> eyre::Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let mut last_error = None;
    for attempt in 1..=3 {
        let mut client = zenwave::client().timeout(CRATES_IO_TIMEOUT);
        match client
            .get(url)?
            .header("User-Agent", CRATES_IO_USER_AGENT)?
            .await
        {
            Ok(response) => match response.into_body().into_bytes().await {
                Ok(body) => match serde_json::from_slice::<T>(&body) {
                    Ok(parsed) => return Ok(parsed),
                    Err(error) => {
                        return Err(eyre::eyre!("parse crates.io response from {url}: {error}"));
                    }
                },
                Err(error) => {
                    tracing::warn!(url, attempt, %error, "crates.io response body read failed");
                    last_error = Some(eyre::eyre!("read crates.io response from {url}: {error}"));
                }
            },
            Err(error) => {
                tracing::warn!(url, attempt, %error, "crates.io request failed");
                last_error = Some(error.into());
            }
        }
    }
    Err(last_error.unwrap_or_else(|| eyre::eyre!("crates.io request to {url} failed after all retries")))
}

fn select_version_lines(versions: &[CrateVersion]) -> eyre::Result<Vec<String>> {
    let mut chosen = std::collections::BTreeMap::<(u64, u64), String>::new();
    for version in versions {
        let parsed = semver::Version::parse(&version.num)?;
        let key = if parsed.major >= 1 {
            (parsed.major, u64::MAX)
        } else {
            (0, parsed.minor)
        };
        chosen
            .entry(key)
            .and_modify(|existing| {
                if semver::Version::parse(existing)
                    .ok()
                    .is_some_and(|current| parsed > current)
                {
                    *existing = version.num.clone();
                }
            })
            .or_insert_with(|| version.num.clone());
    }
    let mut parsed_values = chosen
        .into_values()
        .map(|version| {
            let parsed = semver::Version::parse(&version)
                .map_err(|error| eyre::eyre!("invalid version in chosen set: {version}: {error}"))?;
            Ok((parsed, version))
        })
        .collect::<eyre::Result<Vec<_>>>()?;
    parsed_values.sort_by(|a, b| b.0.cmp(&a.0));
    parsed_values.truncate(3);
    Ok(parsed_values.into_iter().map(|(_, version)| version).collect())
}

async fn submit(requests: Vec<EnqueueRequest>) -> eyre::Result<()> {
    let edge_url =
        std::env::var(STOW_EDGE_URL_ENV).map_err(|_| eyre::eyre!("missing {STOW_EDGE_URL_ENV}"))?;
    let scheduler_auth_token = std::env::var(SCHEDULER_AUTH_TOKEN_ENV)
        .map_err(|_| eyre::eyre!("missing {SCHEDULER_AUTH_TOKEN_ENV}"))?;
    let url = format!(
        "{}/api/v1/scheduler/tasks/submit",
        edge_url.trim_end_matches('/')
    );
    let mut submitted = 0usize;
    for request in requests {
        let payload = [request];
        let mut last_error = None;
        for _ in 0..3 {
            let mut client = zenwave::client();
            match client
                .post(&url)?
                .header(SCHEDULER_AUTH_HEADER, &scheduler_auth_token)?
                .json_body(&payload)?
                .await
            {
                Ok(_) => {
                    submitted += 1;
                    last_error = None;
                    break;
                }
                Err(error) => {
                    last_error = Some(error);
                }
            }
        }
        if let Some(error) = last_error {
            return Err(error.into());
        }
    }
    tracing::info!(tasks = submitted, url, "submitted scheduler tasks");
    Ok(())
}

fn install_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}
