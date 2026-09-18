//! `stow-admin`: operations CLI that submits build tasks to the scheduler
//! Durable Object via the authenticated `/api/v1/scheduler/tasks/submit`
//! endpoint. Used to preheat the cache for popular crates.

use clap::{Parser, Subcommand};
use stow_types::api::{EnqueueRequest, EnqueueSource};
use stow_types::identity::{
    CrateName, CrateVersion as TypedCrateVersion, FeaturesJson, TargetTriple, WireRustcVersion,
};
use tracing_subscriber::EnvFilter;
use zenwave::{Client, ResponseExt};

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
    PreheatBinaryOverlay(PreheatBinaryOverlayArgs),
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
    /// When true, the trusted CI runner keeps the bundled `Cargo.lock`
    /// from the crates.io tarball. Required for the binary-overlay
    /// resolver path: a binary's preheat closure must resolve transitive
    /// deps the same way `cargo install --locked <bin>` would.
    #[arg(long, default_value_t = false)]
    preserve_lockfile: bool,
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

/// Submits one task per top-N most-downloaded *binary* crate, marking each
/// task with `preserve_lockfile = true` so the trusted CI runner builds
/// against the binary's published `Cargo.lock`. Building a binary captures
/// every transitive rustc invocation, so a single task populates artifacts
/// for the entire transitive closure with the same `dependency_c_metadata`
/// resolution `cargo install --locked <bin>` would produce on the user's
/// machine.
#[derive(Parser)]
struct PreheatBinaryOverlayArgs {
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
    downloads: u64,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct CrateVersion {
    num: String,
    #[serde(default)]
    features: std::collections::BTreeMap<String, Vec<String>>,
    yanked: bool,
}

fn main() -> stow_types::error::Result<()> {
    install_tracing();
    smol::block_on(run())
}

async fn run() -> stow_types::error::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Submit(args) => {
            let crate_name = CrateName::parse(args.crate_name)
                .map_err(|error| stow_types::stow_error!("submit crate_name: {error}"))?;
            let version = TypedCrateVersion::new(semver::Version::parse(&args.version)?);
            let features: Vec<String> = serde_json::from_str(&args.features_json)
                .map_err(|error| stow_types::stow_error!("submit features_json: {error}"))?;
            let features_json = FeaturesJson::canonicalize(features)
                .map_err(|error| stow_types::stow_error!("submit features_json: {error}"))?;
            let target = TargetTriple::parse(args.target)
                .map_err(|error| stow_types::stow_error!("submit target: {error}"))?;
            let rustc_version = WireRustcVersion::parse(args.rustc_version)
                .map_err(|error| stow_types::stow_error!("submit rustc_version: {error}"))?;
            submit(vec![EnqueueRequest {
                crate_name,
                version,
                features_json,
                target,
                rustc_version,
                downloads: args.downloads,
                source: EnqueueSource::CacheMiss,
                depends_on: Vec::new(),
                preserve_lockfile: args.preserve_lockfile,
            }])
            .await
        }
        Command::PreheatT100(args) => {
            let target = TargetTriple::parse(args.target.clone())
                .map_err(|error| stow_types::stow_error!("preheat target: {error}"))?;
            let rustc_version = WireRustcVersion::parse(args.rustc_version.clone())
                .map_err(|error| stow_types::stow_error!("preheat rustc_version: {error}"))?;
            let default_only = FeaturesJson::canonicalize(vec!["default".to_owned()])
                .expect("`default` is a valid feature name");
            let empty_features = FeaturesJson::default();

            let crates = fetch_top_crates(args.limit).await?;
            let mut requests = Vec::new();
            for krate in crates {
                let crate_name = CrateName::parse(krate.id.as_str()).map_err(|error| {
                    stow_types::stow_error!("crate_name from crates.io `{}`: {error}", krate.id)
                })?;
                let versions = fetch_versions(&krate.id).await?;
                let selected = select_version_lines(&versions)?;
                for version in selected {
                    let has_default = versions
                        .iter()
                        .find(|candidate| candidate.num == version)
                        .ok_or_else(|| {
                            stow_types::stow_error!(
                                "selected version {} missing from crates.io response for {}",
                                version,
                                krate.id
                            )
                        })?
                        .features
                        .contains_key("default");
                    let typed_version = TypedCrateVersion::new(
                        semver::Version::parse(&version).map_err(|error| {
                            stow_types::stow_error!(
                                "parse crates.io version `{version}` for `{}`: {error}",
                                krate.id
                            )
                        })?,
                    );
                    requests.push(EnqueueRequest {
                        crate_name: crate_name.clone(),
                        version: typed_version,
                        features_json: if has_default {
                            default_only.clone()
                        } else {
                            empty_features.clone()
                        },
                        target: target.clone(),
                        rustc_version: rustc_version.clone(),
                        downloads: krate.downloads,
                        source: EnqueueSource::CrateUpdate,
                        depends_on: Vec::new(),
                        preserve_lockfile: false,
                    });
                }
            }
            submit(requests).await
        }
        Command::PreheatBinaryOverlay(args) => preheat_binary_overlay(args).await,
    }
}

async fn preheat_binary_overlay(args: PreheatBinaryOverlayArgs) -> stow_types::error::Result<()> {
    let target = TargetTriple::parse(args.target.clone())
        .map_err(|error| stow_types::stow_error!("preheat target: {error}"))?;
    let rustc_version = WireRustcVersion::parse(args.rustc_version.clone())
        .map_err(|error| stow_types::stow_error!("preheat rustc_version: {error}"))?;
    let default_only = FeaturesJson::canonicalize(vec!["default".to_owned()])
        .expect("`default` is a valid feature name");
    let empty_features = FeaturesJson::default();

    let candidates = fetch_top_binary_crates(args.limit).await?;
    if candidates.is_empty() {
        return Err(stow_types::stow_error!(
            "no binary crates discovered from crates.io top-{} download list",
            args.limit
        ));
    }

    let mut requests = Vec::with_capacity(candidates.len());
    for binary in &candidates {
        let crate_name = CrateName::parse(binary.id.as_str()).map_err(|error| {
            stow_types::stow_error!("crate_name from crates.io `{}`: {error}", binary.id)
        })?;
        let typed_version = TypedCrateVersion::new(
            semver::Version::parse(&binary.latest_version).map_err(|error| {
                stow_types::stow_error!(
                    "parse crates.io version `{}` for `{}`: {error}",
                    binary.latest_version,
                    binary.id
                )
            })?,
        );
        requests.push(EnqueueRequest {
            crate_name,
            version: typed_version,
            features_json: if binary.has_default_feature {
                default_only.clone()
            } else {
                empty_features.clone()
            },
            target: target.clone(),
            rustc_version: rustc_version.clone(),
            downloads: binary.downloads,
            source: EnqueueSource::CrateUpdate,
            depends_on: Vec::new(),
            preserve_lockfile: true,
        });
    }

    tracing::info!(
        binaries = requests.len(),
        target = %args.target,
        rustc_version = %args.rustc_version,
        "submitting binary-overlay preheat tasks"
    );
    submit(requests).await
}

#[derive(Debug, Clone)]
struct BinaryCandidate {
    id: String,
    latest_version: String,
    downloads: u64,
    has_default_feature: bool,
}

async fn fetch_top_binary_crates(limit: usize) -> stow_types::error::Result<Vec<BinaryCandidate>> {
    // crates.io's `binaries` field on the per-crate detail endpoint is not
    // reliably populated, so we use the `command-line-utilities` category as
    // the canonical "this crate is a binary" signal — every crate registered
    // in that category ships at least one [[bin]] target. We still call
    // fetch_crate_detail to grab the latest non-yanked version + features.
    let mut binaries = Vec::with_capacity(limit);
    let mut page: u32 = 1;
    let scan_per_page: usize = 100;
    let max_scan_pages: u32 = 20;
    while binaries.len() < limit && page <= max_scan_pages {
        let url = format!(
            "{CRATES_IO_API_BASE}?category=command-line-utilities&page={page}&per_page={scan_per_page}&sort=downloads"
        );
        let response: CratesResponse = get_json_with_retries(&url).await?;
        if response.crates.is_empty() {
            break;
        }
        for summary in response.crates {
            let detail = match fetch_crate_detail(&summary.id).await {
                Ok(detail) => detail,
                Err(error) => {
                    tracing::warn!(
                        crate = %summary.id,
                        %error,
                        "skipping candidate; failed to fetch detail"
                    );
                    continue;
                }
            };
            let Some(latest_version) = detail.latest_version else {
                continue;
            };
            binaries.push(BinaryCandidate {
                id: summary.id.clone(),
                latest_version: latest_version.num.clone(),
                downloads: summary.downloads,
                has_default_feature: latest_version.features.contains_key("default"),
            });
            if binaries.len() >= limit {
                break;
            }
        }
        page += 1;
    }
    binaries.truncate(limit);
    Ok(binaries)
}

#[derive(Debug, Clone)]
struct CrateDetail {
    latest_version: Option<CrateVersion>,
}

#[derive(Debug, serde::Deserialize)]
struct CrateDetailResponse {
    #[serde(rename = "crate")]
    krate: CrateDetailNode,
    versions: Vec<CrateVersion>,
}

#[derive(Debug, serde::Deserialize)]
struct CrateDetailNode {
    #[serde(default)]
    max_stable_version: Option<String>,
    #[serde(default)]
    max_version: Option<String>,
}

async fn fetch_crate_detail(crate_name: &str) -> stow_types::error::Result<CrateDetail> {
    let url = format!("{CRATES_IO_API_BASE}/{crate_name}");
    let response: CrateDetailResponse = get_json_with_retries(&url).await?;
    let preferred_num = response
        .krate
        .max_stable_version
        .clone()
        .or_else(|| response.krate.max_version.clone());
    let latest_version = match preferred_num {
        Some(num) => response
            .versions
            .iter()
            .find(|candidate| candidate.num == num && !candidate.yanked)
            .cloned()
            .or_else(|| {
                response
                    .versions
                    .iter()
                    .find(|candidate| !candidate.yanked)
                    .cloned()
            }),
        None => response
            .versions
            .iter()
            .find(|candidate| !candidate.yanked)
            .cloned(),
    };
    Ok(CrateDetail { latest_version })
}

async fn fetch_top_crates(limit: usize) -> stow_types::error::Result<Vec<CrateSummary>> {
    let per_page = limit.min(100);
    let url = format!("{CRATES_IO_API_BASE}?page=1&per_page={per_page}&sort=downloads");
    let response = get_json_with_retries::<CratesResponse>(&url).await?;
    Ok(response.crates.into_iter().take(limit).collect())
}

async fn fetch_versions(crate_name: &str) -> stow_types::error::Result<Vec<CrateVersion>> {
    let url = format!("{CRATES_IO_API_BASE}/{crate_name}");
    let response = get_json_with_retries::<serde_json::Value>(&url).await?;
    let versions = serde_json::from_value::<Vec<CrateVersion>>(response["versions"].clone())?;
    Ok(versions
        .into_iter()
        .filter(|version| !version.yanked)
        .collect())
}

async fn get_json_with_retries<T>(url: &str) -> stow_types::error::Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let mut client = zenwave::client().timeout(CRATES_IO_TIMEOUT).retry(2);
    let response = client
        .get(url)?
        .header("User-Agent", CRATES_IO_USER_AGENT)?
        .await
        .map_err(|error| stow_types::stow_error!("fetch crates.io JSON from {url}: {error}"))?;
    response
        .into_json()
        .await
        .map_err(|error| stow_types::stow_error!("parse crates.io JSON from {url}: {error}"))
}

fn select_version_lines(versions: &[CrateVersion]) -> stow_types::error::Result<Vec<String>> {
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
                if semver::Version::parse(existing).is_ok_and(|current| parsed > current) {
                    existing.clone_from(&version.num);
                }
            })
            .or_insert_with(|| version.num.clone());
    }
    let mut parsed_values = chosen
        .into_values()
        .map(|version| {
            let parsed = semver::Version::parse(&version).map_err(|error| {
                stow_types::stow_error!("invalid version in chosen set: {version}: {error}")
            })?;
            Ok((parsed, version))
        })
        .collect::<stow_types::error::Result<Vec<_>>>()?;
    parsed_values.sort_by(|a, b| b.0.cmp(&a.0));
    parsed_values.truncate(3);
    Ok(parsed_values
        .into_iter()
        .map(|(_, version)| version)
        .collect())
}

async fn submit(requests: Vec<EnqueueRequest>) -> stow_types::error::Result<()> {
    let edge_url = std::env::var(STOW_EDGE_URL_ENV)
        .map_err(|_| stow_types::stow_error!("missing {STOW_EDGE_URL_ENV}"))?;
    let scheduler_auth_token = std::env::var(SCHEDULER_AUTH_TOKEN_ENV)
        .map_err(|_| stow_types::stow_error!("missing {SCHEDULER_AUTH_TOKEN_ENV}"))?;
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
            let attempt = match client
                .post(&url)?
                .header(SCHEDULER_AUTH_HEADER, &scheduler_auth_token)?
                .json_body(&payload)?
                .await
            {
                Ok(response) => response.error_for_status().await.map(|_| ()),
                Err(error) => Err(error),
            };
            match attempt {
                Ok(()) => {
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
        // stderr, never stdout: keep diagnostics off the data stream.
        .with_writer(std::io::stderr)
        .try_init();
}
