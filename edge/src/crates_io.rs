//! Cloudflare-fetch-backed [`CratesIo`] client.
//!
//! This is the only place edge code talks to crates.io over the network;
//! resolver logic depends on the [`CratesIo`] trait so it stays host-testable.

use std::collections::BTreeMap;

use semver::Version;
use skyzen_cloudflare::worker::send::SendWrapper;
use skyzen_cloudflare::{CfFetch, worker};

use crate::dependency_resolver::{CratesIo, CratesIoDependency};
use crate::errors::ResolverError;

const CRATES_IO_API_BASE: &str = "https://crates.io/api/v1/crates";
const CRATES_IO_USER_AGENT: &str = "stow-edge/graph-resolver";

/// Production crates.io client running on Cloudflare Workers fetch.
#[derive(Debug, Clone, Copy, Default)]
pub struct CfCratesIo;

#[derive(Debug, serde::Deserialize)]
struct CratesIoVersionResponse {
    version: CratesIoVersionDetail,
}

#[derive(Debug, serde::Deserialize)]
struct CratesIoVersionDetail {
    features: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, serde::Deserialize)]
struct CratesIoDependenciesResponse {
    dependencies: Vec<CratesIoDependency>,
}

#[derive(Debug, serde::Deserialize)]
struct CratesIoCrateResponse {
    versions: Vec<CratesIoPublishedVersion>,
}

#[derive(Debug, serde::Deserialize)]
struct CratesIoPublishedVersion {
    num: String,
    yanked: bool,
}

impl CratesIo for CfCratesIo {
    async fn version_features(
        &self,
        crate_name: &str,
        version: &Version,
    ) -> Result<BTreeMap<String, Vec<String>>, ResolverError> {
        let url = format!("{CRATES_IO_API_BASE}/{crate_name}/{version}");
        // `SendWrapper` keeps the `JsValue`-backed request handle sendable
        // across the await so the trait's `+ Send` future bound holds.
        let request = SendWrapper::new(build_get_request(&url)?);
        let response = CfFetch
            .request_json::<CratesIoVersionResponse>(&request)
            .await
            .map_err(|error| {
                format!("fetch crates.io version metadata {crate_name} {version}: {error}")
            })?;
        Ok(response.version.features)
    }

    async fn version_dependencies(
        &self,
        crate_name: &str,
        version: &Version,
    ) -> Result<Vec<CratesIoDependency>, ResolverError> {
        let url = format!("{CRATES_IO_API_BASE}/{crate_name}/{version}/dependencies");
        let request = SendWrapper::new(build_get_request(&url)?);
        let response = CfFetch
            .request_json::<CratesIoDependenciesResponse>(&request)
            .await
            .map_err(|error| {
                format!("fetch crates.io dependencies {crate_name} {version}: {error}")
            })?;
        Ok(response.dependencies)
    }

    async fn published_version_nums(&self, crate_name: &str) -> Result<Vec<String>, ResolverError> {
        let url = format!("{CRATES_IO_API_BASE}/{crate_name}");
        let request = SendWrapper::new(build_get_request(&url)?);
        let response = CfFetch
            .request_json::<CratesIoCrateResponse>(&request)
            .await
            .map_err(|error| format!("fetch crates.io crate metadata {crate_name}: {error}"))?;
        Ok(response
            .versions
            .into_iter()
            .filter(|version| !version.yanked)
            .map(|version| version.num)
            .collect())
    }
}

fn build_get_request(url: &str) -> Result<worker::Request, ResolverError> {
    let headers = worker::Headers::new();
    headers
        .set("User-Agent", CRATES_IO_USER_AGENT)
        .map_err(|error| ResolverError::CratesIo(error.to_string()))?;

    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Get);
    init.with_headers(headers);

    worker::Request::new_with_init(url, &init)
        .map_err(|error| ResolverError::CratesIo(error.to_string()))
}
