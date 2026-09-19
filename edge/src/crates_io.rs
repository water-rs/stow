//! Cloudflare-fetch-backed [`CratesIo`] client.
//!
//! This is the only place edge code talks to crates.io over the network;
//! resolver logic depends on the [`CratesIo`] trait so it stays host-testable.

use std::collections::BTreeMap;

use semver::Version;
use skyzen_cloudflare::worker::send::SendWrapper;
use skyzen_cloudflare::{CfFetch, worker};

use crate::dependency_resolver::{
    CratesIo, CratesIoDependency, CratesIoDependencyKind, CratesIoSearchHit, index_path,
};
use crate::errors::ResolverError;

const CRATES_IO_API_BASE: &str = "https://crates.io/api/v1/crates";
/// The sparse registry index. Dependency metadata comes from here and not
/// from the web API because only the index records the name a dependency
/// is *declared* under: `alias = { package = "real" }` appears in the index
/// as `{"name":"alias","package":"real"}`, while the API reports only
/// `crate_id: "real"`. Every feature expression — `dep:alias`,
/// `alias/feat`, and the implicit feature of an optional dependency —
/// spells the alias, so resolving features without it mints feature names
/// cargo rejects.
const SPARSE_INDEX_BASE: &str = "https://index.crates.io";
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

/// One line of a sparse-index file: everything published under one version.
#[derive(Debug, serde::Deserialize)]
struct IndexVersionEntry {
    vers: String,
    #[serde(default)]
    deps: Vec<IndexDependency>,
}

/// One dependency edge as the sparse index records it.
#[derive(Debug, serde::Deserialize)]
struct IndexDependency {
    /// The name the dependent's manifest declares this edge under.
    name: String,
    /// The crate it resolves to, present only when the manifest renamed it.
    #[serde(default)]
    package: Option<String>,
    #[serde(default)]
    optional: bool,
    req: String,
    #[serde(default)]
    kind: CratesIoDependencyKind,
    #[serde(default)]
    features: Vec<String>,
    #[serde(default = "default_true")]
    default_features: bool,
    #[serde(default)]
    target: Option<String>,
}

const fn default_true() -> bool {
    true
}

impl From<IndexDependency> for CratesIoDependency {
    fn from(dependency: IndexDependency) -> Self {
        let crate_id = dependency
            .package
            .unwrap_or_else(|| dependency.name.clone());
        Self {
            name: dependency.name,
            crate_id,
            optional: dependency.optional,
            req: dependency.req,
            kind: dependency.kind,
            features: dependency.features,
            default_features: dependency.default_features,
            target: dependency.target,
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct CratesIoCrateResponse {
    versions: Vec<CratesIoPublishedVersion>,
}

#[derive(Debug, serde::Deserialize)]
struct CratesIoSearchResponse {
    crates: Vec<CratesIoSearchHit>,
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
        let response: CratesIoVersionResponse = request_json(&url, || {
            ResolverError::VersionNotPublished {
                crate_name: crate_name.to_owned(),
                version: version.to_string(),
            }
        })
        .await?;
        Ok(response.version.features)
    }

    async fn version_dependencies(
        &self,
        crate_name: &str,
        version: &Version,
    ) -> Result<Vec<CratesIoDependency>, ResolverError> {
        let url = format!("{SPARSE_INDEX_BASE}/{}", index_path(crate_name));
        let body = request_text(&url, || ResolverError::CrateNotPublished {
            crate_name: crate_name.to_owned(),
        })
        .await?;
        let wanted = version.to_string();
        for line in body.lines().filter(|line| !line.trim().is_empty()) {
            let entry: IndexVersionEntry = serde_json::from_str(line)
                .map_err(|error| ResolverError::Json(format!("decode index {url}: {error}")))?;
            if entry.vers == wanted {
                return Ok(entry.deps.into_iter().map(Into::into).collect());
            }
        }
        Err(ResolverError::VersionNotPublished {
            crate_name: crate_name.to_owned(),
            version: wanted,
        })
    }

    async fn published_version_nums(&self, crate_name: &str) -> Result<Vec<String>, ResolverError> {
        let url = format!("{CRATES_IO_API_BASE}/{crate_name}");
        let response: CratesIoCrateResponse = request_json(&url, || {
            ResolverError::CrateNotPublished {
                crate_name: crate_name.to_owned(),
            }
        })
        .await?;
        Ok(response
            .versions
            .into_iter()
            .filter(|version| !version.yanked)
            .map(|version| version.num)
            .collect())
    }

    async fn search(
        &self,
        query: &str,
        limit: u32,
    ) -> Result<Vec<CratesIoSearchHit>, ResolverError> {
        // The query is arbitrary user input, so it is percent-encoded
        // before it becomes part of the URL.
        let encoded = String::from(js_sys::encode_uri_component(query));
        let url = format!("{CRATES_IO_API_BASE}?q={encoded}&per_page={limit}");
        // crates.io has no 404 for a search that matches nothing, so this
        // arm only fires if the endpoint itself disappears.
        let response: CratesIoSearchResponse = request_json(&url, || {
            ResolverError::CratesIo(format!("crates.io {CRATES_IO_API_BASE} search returned 404"))
        })
        .await?;
        Ok(response.crates)
    }
}

/// GET `url` and decode the body as `T`. The HTTP status is checked
/// before parsing: crates.io's 404 body is not the requested schema, so
/// without the check a missing crate surfaced as a decode error — and a
/// 500. `missing` says what a 404 on *this* URL means, because only the
/// caller knows whether it asked for a crate or for one exact version of
/// one. Other non-2xx statuses stay [`ResolverError::CratesIo`]; the error
/// body is never read, since upstream diagnostics must not reach clients.
async fn request_json<T: serde::de::DeserializeOwned>(
    url: &str,
    missing: impl FnOnce() -> ResolverError,
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
        return Err(missing());
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

/// GET `url` and return the body as text. The sparse index serves
/// newline-delimited JSON, one object per published version, so it cannot
/// go through [`request_json`].
async fn request_text(
    url: &str,
    missing: impl FnOnce() -> ResolverError,
) -> Result<String, ResolverError> {
    use skyzen_cloudflare::worker::send::IntoSendFuture as _;

    let request = SendWrapper::new(build_get_request(url)?);
    let mut response = SendWrapper::new(
        CfFetch
            .request(&request)
            .await
            .map_err(|error| ResolverError::CratesIo(format!("fetch {url}: {error}")))?,
    );
    let status = response.status_code();
    if status == 404 {
        return Err(missing());
    }
    if !(200..300).contains(&status) {
        return Err(ResolverError::CratesIo(format!(
            "crates.io {url} returned HTTP {status}"
        )));
    }
    response
        .text()
        .into_send()
        .await
        .map_err(|error| ResolverError::CratesIo(format!("read crates.io {url}: {error}")))
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
