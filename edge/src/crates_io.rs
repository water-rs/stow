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
        let response: CratesIoVersionResponse = request_json(&url, crate_name).await?;
        Ok(response.version.features)
    }

    async fn version_dependencies(
        &self,
        crate_name: &str,
        version: &Version,
    ) -> Result<Vec<CratesIoDependency>, ResolverError> {
        let url = format!("{CRATES_IO_API_BASE}/{crate_name}/{version}/dependencies");
        let response: CratesIoDependenciesResponse = request_json(&url, crate_name).await?;
        Ok(response.dependencies)
    }

    async fn published_version_nums(&self, crate_name: &str) -> Result<Vec<String>, ResolverError> {
        let url = format!("{CRATES_IO_API_BASE}/{crate_name}");
        let response: CratesIoCrateResponse = request_json(&url, crate_name).await?;
        Ok(response
            .versions
            .into_iter()
            .filter(|version| !version.yanked)
            .map(|version| version.num)
            .collect())
    }
}

/// GET `url` and decode the body as `T`. The HTTP status is checked
/// before parsing: crates.io's 404 body is not the requested schema, so
/// without the check a missing crate surfaced as a decode error — and a
/// 500 — instead of [`ResolverError::CrateNotPublished`]. Other non-2xx
/// statuses stay [`ResolverError::CratesIo`]; the error body is never
/// read, since upstream diagnostics must not reach clients.
async fn request_json<T: serde::de::DeserializeOwned>(
    url: &str,
    crate_name: &str,
) -> Result<T, ResolverError> {
    use skyzen_cloudflare::worker::send::IntoSendFuture as _;

    // `SendWrapper` keeps the `JsValue`-backed request handle sendable
    // across the await so the trait's `+ Send` future bound holds.
    let request = SendWrapper::new(build_get_request(url)?);
    let mut response = SendWrapper::new(
        CfFetch
            .request(&request)
            .await
            .map_err(|error| ResolverError::CratesIo(format!("fetch {url}: {error}")))?,
    );
    let status = response.status_code();
    if status == 404 {
        return Err(ResolverError::CrateNotPublished {
            crate_name: crate_name.to_owned(),
        });
    }
    if !(200..300).contains(&status) {
        return Err(ResolverError::CratesIo(format!(
            "crates.io {url} returned HTTP {status}"
        )));
    }
    response
        .json::<T>()
        .into_send()
        .await
        .map_err(|error| ResolverError::Json(format!("decode crates.io {url}: {error}")))
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
