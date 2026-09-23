//! The async HTTP client boundary.
//!
//! `cargo::util::network::http_async::Client` multiplexes curl `Easy2` handles
//! on a worker thread. curl cannot be carried to wasm32, so `Client` here is a
//! concrete handle over an injected transport ([`HttpClient`] for async
//! requests, optionally [`HttpClientBlocking`] for the one blocking call git's
//! GitHub fast path makes). The differential harness installs a reqwest-backed
//! transport; the worker installs a `fetch`-backed one.
//!
//! `Error` mirrors the variants the retry classifier needs: `Spurious` covers
//! transient transport failures (connect/resolve/timeout/HTTP2); anything
//! else is not retried.

use std::fmt;
use std::rc::Rc;

use http::Response;

use crate::util::errors::CargoResult;

/// A response body delivered as chunks off the wire. Transports with a
/// streaming primitive return it from [`HttpClient::request_stream`]; the
/// default implementation wraps the buffered body in a one-chunk stream.
pub type BodyStream = std::pin::Pin<Box<dyn futures::Stream<Item = CargoResult<Vec<u8>>>>>;

/// The transport the vendored call sites drive: send a request, get the whole
/// response back. Implementations own whatever runtime they need.
pub trait HttpClient {
    fn request<'a>(
        &'a self,
        request: http::Request<Vec<u8>>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = CargoResult<Response<Vec<u8>>>> + 'a>>;

    /// The same request with a streaming body. The tarball lanes need real
    /// bytes only for a small, fixed file set — streaming keeps a large
    /// response out of the isolate's memory. Transports without a stream
    /// primitive get the buffered default; the reader contract is the same.
    fn request_stream<'a>(
        &'a self,
        request: http::Request<Vec<u8>>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = CargoResult<Response<BodyStream>>> + 'a>>
    {
        Box::pin(async move {
            let response = self.request(request).await?;
            let (parts, body) = response.into_parts();
            Ok(Response::from_parts(
                parts,
                Box::pin(futures::stream::once(async move { Ok(body) })) as BodyStream,
            ))
        })
    }

    /// Approximate bytes still in flight across this client (progress only).
    fn bytes_pending(&self) -> u64 {
        0
    }
}

/// A synchronous transport. Only ever used by `sources::git::utils`' GitHub
/// fast-path check, which sits inside a sync `Source::update` call chain that
/// predates this crate's async plumbing.
pub trait HttpClientBlocking {
    fn request(&self, request: http::Request<Vec<u8>>) -> CargoResult<Response<Vec<u8>>>;
}

/// An async HTTP client shared across a resolve invocation.
#[derive(Clone)]
pub struct Client {
    inner: Rc<dyn HttpClient>,
    blocking: Option<Rc<dyn HttpClientBlocking>>,
}

impl Client {
    /// A client with only an async transport; `request_blocking` will fail.
    pub fn new(inner: Rc<dyn HttpClient>) -> Client {
        Client {
            inner,
            blocking: None,
        }
    }

    /// A client with both transports.
    pub fn with_blocking(
        inner: Rc<dyn HttpClient>,
        blocking: Rc<dyn HttpClientBlocking>,
    ) -> Client {
        Client {
            inner,
            blocking: Some(blocking),
        }
    }

    /// Perform the request, returning the full response (headers + body).
    pub async fn request(&self, request: http::Request<Vec<u8>>) -> CargoResult<Response<Vec<u8>>> {
        self.inner.request(request).await
    }

    /// Perform the request, returning headers + a streaming body.
    pub async fn request_stream(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> CargoResult<Response<BodyStream>> {
        self.inner.request_stream(request).await
    }

    /// Perform a blocking request.
    ///
    /// cargo drives this through curl's blocking mode; here it exists only
    /// where a transport was installed that can block — on wasm32 there is no
    /// such transport, so the absence is a truthful error, not a fallback.
    pub fn request_blocking(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> CargoResult<Response<Vec<u8>>> {
        let blocking = self.blocking.as_ref().ok_or_else(|| {
            anyhow::format_err!("no blocking HTTP transport configured for this client")
        })?;
        blocking.request(request)
    }

    /// Approximate bytes still in flight across this client (progress only).
    pub fn bytes_pending(&self) -> u64 {
        self.inner.bytes_pending()
    }
}

/// Error type returned by [`HttpClient`] implementations, carrying the
/// spurious-vs-fatal classification the retry layer applies.
#[derive(Debug)]
pub enum Error {
    /// A transient transport failure — retried by `retry::Retry`.
    Spurious(anyhow::Error),
    /// The server gave an unparseable/invalid header.
    BadHeader(anyhow::Error),
    /// Download fell under the configured low-speed threshold.
    TooSlow(anyhow::Error),
    /// Any other error (certificate, 4xx handled elsewhere, …).
    Other(anyhow::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Spurious(e) | Error::BadHeader(e) | Error::TooSlow(e) | Error::Other(e) => {
                e.fmt(f)
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Spurious(e) | Error::BadHeader(e) | Error::TooSlow(e) | Error::Other(e) => {
                Some(e.as_ref())
            }
        }
    }
}

/// Additional fields on an [`http::Response`].
#[derive(Clone, Debug, Default)]
pub struct Extensions {
    pub client_ip: Option<String>,
    pub effective_url: Option<String>,
}

pub trait ResponsePartsExtensions {
    fn client_ip(&self) -> Option<&str>;
    fn effective_url(&self) -> Option<&str>;
}

impl ResponsePartsExtensions for http::response::Parts {
    fn client_ip(&self) -> Option<&str> {
        self.extensions
            .get::<Extensions>()
            .and_then(|extensions| extensions.client_ip.as_deref())
    }

    fn effective_url(&self) -> Option<&str> {
        self.extensions
            .get::<Extensions>()
            .and_then(|extensions| extensions.effective_url.as_deref())
    }
}

impl ResponsePartsExtensions for Response<Vec<u8>> {
    fn client_ip(&self) -> Option<&str> {
        self.extensions()
            .get::<Extensions>()
            .and_then(|extensions| extensions.client_ip.as_deref())
    }

    fn effective_url(&self) -> Option<&str> {
        self.extensions()
            .get::<Extensions>()
            .and_then(|extensions| extensions.effective_url.as_deref())
    }
}

/// Attach [`Extensions`] metadata to a response — used by transports that
/// learn the effective URL / client IP.
pub fn insert_extensions(response: &mut Response<Vec<u8>>, extensions: Extensions) {
    response.extensions_mut().insert(extensions);
}
