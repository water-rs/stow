//! `HttpClient` implementations for tests and the differential harness:
//! [`RecordedHttp`] replays a captured `URL -> response` fixture, and
//! [`RecordingHttp`] wraps a live client while writing that fixture. Both map
//! one URL to one on-disk pair — `<path>.body` plus `<path>.meta` (status +
//! headers) — under the fixture directory.

use crate::util::CargoResult;
use crate::util::network::http_async::HttpClient;
use anyhow::Context;
use http::header::{HeaderName, HeaderValue};
use http::{Request, Response, StatusCode};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A recorded HTTP exchange: status line and headers; the body lives in the
/// sibling `.body` file.
#[derive(serde::Serialize, serde::Deserialize)]
struct RecordedResponse {
    status: u16,
    headers: BTreeMap<String, String>,
}

fn body_path(base: &Path) -> PathBuf {
    base.with_file_name(format!(
        "{}.body",
        base.file_name().unwrap().to_string_lossy()
    ))
}

fn meta_path(base: &Path) -> PathBuf {
    base.with_file_name(format!(
        "{}.meta",
        base.file_name().unwrap().to_string_lossy()
    ))
}

/// Maps a request URL to a fixture file base, preserving the URL path shape
/// (`https://index.crates.io/me/rd/serde` -> `index.crates.io/me/rd/serde`).
fn url_to_path(dir: &Path, url: &str) -> PathBuf {
    let stripped = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let mut safe = String::new();
    for c in stripped.chars() {
        if c.is_ascii_alphanumeric() || c == '/' || c == '.' || c == '-' || c == '_' {
            safe.push(c);
        } else {
            safe.push('%');
            safe.push_str(&format!("{:02x}", c as u32));
        }
    }
    dir.join(safe)
}

/// An [`HttpClient`] that serves responses from a recorded fixture directory.
/// A URL with no recorded file is an error — the fixture is authoritative,
/// never the network.
pub struct RecordedHttp {
    dir: PathBuf,
}

impl RecordedHttp {
    /// `dir` holds `<host>/<path>` pairs as `.body` + `.meta` files.
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
}

impl HttpClient for RecordedHttp {
    fn request<'a>(
        &'a self,
        request: Request<Vec<u8>>,
    ) -> Pin<Box<dyn std::future::Future<Output = CargoResult<Response<Vec<u8>>>> + 'a>> {
        let url = request.uri().to_string();
        Box::pin(async move {
            let base = url_to_path(&self.dir, &url);
            let body_path = body_path(&base);
            if !body_path.exists() {
                anyhow::bail!("recorded fixture has no response for `{url}` (want {body_path:?})");
            }
            let meta_bytes = fs::read(meta_path(&base))
                .with_context(|| format!("fixture meta missing for `{url}`"))?;
            let meta: RecordedResponse = serde_json::from_slice(&meta_bytes)?;
            let body = fs::read(&body_path)?;
            let mut resp = Response::builder().status(StatusCode::from_u16(meta.status)?);
            for (k, v) in meta.headers {
                resp = resp.header(
                    HeaderName::from_bytes(k.as_bytes())?,
                    HeaderValue::from_str(&v)?,
                );
            }
            Ok(resp.body(body)?)
        })
    }
}

/// An [`HttpClient`] proxying a real client and recording every response to
/// `dir` so a later run replays deterministically through [`RecordedHttp`].
pub struct RecordingHttp<C> {
    inner: C,
    dir: PathBuf,
    misses: AtomicUsize,
}

impl<C: HttpClient> RecordingHttp<C> {
    /// Wraps `inner`; recorded pairs land under `dir`.
    pub fn new(inner: C, dir: PathBuf) -> Self {
        Self {
            inner,
            dir,
            misses: AtomicUsize::new(0),
        }
    }

    /// How many responses were recorded this run.
    pub fn recorded(&self) -> usize {
        self.misses.load(Ordering::SeqCst)
    }
}

impl<C: HttpClient> HttpClient for RecordingHttp<C> {
    fn request<'a>(
        &'a self,
        request: Request<Vec<u8>>,
    ) -> Pin<Box<dyn std::future::Future<Output = CargoResult<Response<Vec<u8>>>> + 'a>> {
        let url = request.uri().to_string();
        Box::pin(async move {
            let resp = self.inner.request(request).await?;
            let base = url_to_path(&self.dir, &url);
            let body_path = body_path(&base);
            let meta_path = meta_path(&base);
            if let Some(parent) = body_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let meta = RecordedResponse {
                status: resp.status().as_u16(),
                headers: resp
                    .headers()
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect(),
            };
            fs::write(&meta_path, serde_json::to_vec_pretty(&meta)?)?;
            fs::write(&body_path, resp.body())?;
            self.misses.fetch_add(1, Ordering::SeqCst);
            Ok(resp)
        })
    }
}
