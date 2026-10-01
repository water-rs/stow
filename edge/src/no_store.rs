//! `Cache-Control: no-store` on every error answer.
//!
//! Workers Cache applies RFC 9111 heuristic freshness to any response
//! that lacks `Cache-Control` — a 404 is held for three minutes, and
//! 405/410/414/501 are heuristically cacheable too — so every error the
//! edge emits has to say it is not cacheable. [`NoStoreOnError`] is the
//! one place those answers converge: the router's own misses (unmatched
//! path, wrong method) and handlers' bespoke error replies arrive as
//! `Ok` responses with an error status, while handler `Err`s are
//! rendered through [`skyzen::error_response`] here, the same way the
//! runtime renders them. Successes are untouched — each route family's
//! `Cache-Control` (immutable bytes, short max-ages, explicit no-store)
//! is its own contract.
//!
//! <https://developers.cloudflare.com/workers/cache/configuration/>

use skyzen::header::{CACHE_CONTROL, HeaderValue};
use skyzen::{Endpoint, Request, Response};

const NO_STORE: &str = "no-store";

/// Stamps `Cache-Control: no-store` on `response` when its status is an
/// error. Other statuses are left alone — their freshness contract is
/// already on the response or is the heuristic's business.
pub fn deny_error_caching(response: &mut Response) {
    if response.status().is_client_error() || response.status().is_server_error() {
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static(NO_STORE));
    }
}

/// The Worker's outer endpoint: wraps the router so every error answer —
/// the router's own `Ok` misses and the `Err` path — carries
/// `Cache-Control: no-store` before Workers Cache can see it.
#[derive(Clone)]
pub struct NoStoreOnError<E> {
    inner: E,
}

impl<E> NoStoreOnError<E> {
    pub const fn new(inner: E) -> Self {
        Self { inner }
    }
}

impl<E: Endpoint> Endpoint for NoStoreOnError<E> {
    type Error = E::Error;

    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        // Capture the request identity before `respond` takes the request
        // mutably, so the error log names the call the way the runtime's
        // own serve loop does.
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let mut response = match self.inner.respond(request).await {
            Ok(response) => response,
            Err(error) => {
                skyzen::log_endpoint_error(&error, &method, &path);
                skyzen::error_response(&error)
            }
        };
        deny_error_caching(&mut response);
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use std::future::{Future, ready};

    use skyzen::{Body, Method, Request, Response, StatusCode};

    use super::NoStoreOnError;
    use crate::errors::GetArtifactError;
    use skyzen::Endpoint;

    fn request() -> Request {
        let mut request = Request::new(Body::empty());
        *request.method_mut() = Method::GET;
        request
    }

    fn no_store(response: &Response) -> bool {
        response
            .headers()
            .get(skyzen::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            == Some("no-store")
    }

    /// The router's own answers — unmatched path, wrong method — come
    /// back `Ok` with an error status.
    struct StatusEndpoint(StatusCode);

    impl Endpoint for StatusEndpoint {
        type Error = GetArtifactError;

        fn respond(
            &mut self,
            _: &mut Request,
        ) -> impl Future<Output = Result<Response, Self::Error>> + Send {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = self.0;
            ready(Ok(response))
        }
    }

    /// Every handler error — `GetArtifactError` or anything else a
    /// handler can fail with — comes back `Err` and is rendered through
    /// the shared error envelope.
    struct FailsEndpoint(Option<GetArtifactError>);

    impl Endpoint for FailsEndpoint {
        type Error = GetArtifactError;

        fn respond(
            &mut self,
            _: &mut Request,
        ) -> impl Future<Output = Result<Response, Self::Error>> + Send {
            ready(Err(self.0.take().expect("each test calls respond once")))
        }
    }

    /// Router-level answers: the unmatched-path 404 and the wrong-method
    /// 405 — heuristic freshness would hold both for minutes.
    #[tokio::test]
    async fn router_level_error_answers_carry_no_store() {
        for status in [StatusCode::NOT_FOUND, StatusCode::METHOD_NOT_ALLOWED] {
            let mut endpoint = NoStoreOnError::new(StatusEndpoint(status));
            let response = endpoint.respond(&mut request()).await.unwrap();
            assert!(
                no_store(&response),
                "{status} answer must carry Cache-Control: no-store"
            );
        }
    }

    /// A representative handler error per route family: the byte-path
    /// and catalog 404s, the request-lane 422, the admission lane's 429
    /// fallback, and a 5xx — each rendered through the shared envelope.
    #[tokio::test]
    async fn handler_error_answers_carry_no_store() {
        let cases = [
            GetArtifactError::NotFound,
            GetArtifactError::BadRequest,
            GetArtifactError::SchedulerBusy(String::new()),
            GetArtifactError::InternalWithMessage(String::new()),
        ];
        for error in cases {
            let status = skyzen::HttpError::status(&error);
            let mut endpoint = NoStoreOnError::new(FailsEndpoint(Some(error)));
            let response = endpoint.respond(&mut request()).await.unwrap();
            assert_eq!(response.status(), status);
            assert!(
                no_store(&response),
                "{status} envelope must carry Cache-Control: no-store"
            );
        }
    }

    /// Handler-emitted error replies — `TurnstileRejected`'s bespoke
    /// rejection body, the `Retry-After` lanes — come back `Ok` with an
    /// error status and are stamped the same way.
    #[tokio::test]
    async fn bespoke_error_replies_carry_no_store() {
        for status in [StatusCode::FORBIDDEN, StatusCode::TOO_MANY_REQUESTS] {
            let mut endpoint = NoStoreOnError::new(StatusEndpoint(status));
            let response = endpoint.respond(&mut request()).await.unwrap();
            assert!(
                no_store(&response),
                "{status} reply must carry Cache-Control: no-store"
            );
        }
    }

    /// The byte paths' own answer shape: a 200 carrying the immutable
    /// Cache-Control the route set itself.
    struct ImmutableEndpoint;

    impl Endpoint for ImmutableEndpoint {
        type Error = GetArtifactError;

        fn respond(
            &mut self,
            _: &mut Request,
        ) -> impl Future<Output = Result<Response, Self::Error>> + Send {
            let mut response = Response::new(Body::empty());
            response.headers_mut().insert(
                skyzen::header::CACHE_CONTROL,
                skyzen::header::HeaderValue::from_static("public, max-age=31536000, immutable"),
            );
            ready(Ok(response))
        }
    }

    /// Successes keep the Cache-Control their route set — stamping here
    /// must never clobber the byte paths' immutable contract.
    #[tokio::test]
    async fn success_answers_are_untouched() {
        let mut endpoint = NoStoreOnError::new(ImmutableEndpoint);
        let response = endpoint.respond(&mut request()).await.unwrap();
        assert_eq!(
            response
                .headers()
                .get(skyzen::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("public, max-age=31536000, immutable"),
        );

        // A headerless success stays headerless — freshness there is the
        // route's own contract, not this boundary's.
        let mut endpoint = NoStoreOnError::new(StatusEndpoint(StatusCode::OK));
        let response = endpoint.respond(&mut request()).await.unwrap();
        assert!(
            response
                .headers()
                .get(skyzen::header::CACHE_CONTROL)
                .is_none()
        );
    }
}
