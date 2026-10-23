//! Scheduler-overload fault points: each detection writes one Analytics
//! Engine point into `stow_cache_misses` — `index1 = '#fault'` partitions
//! them from the miss rows (which index crate names), `blob1` the event
//! kind, `blob2` the public route that shed the load, `double1` the
//! count. The watchdog's `edge.do.overloaded` signal (stow#888) counts
//! these over the trailing hour.
//!
//! [`OverloadFaults`] is the single recording point — a router wrapper in
//! the `no_store` style that holds the `STOW_ANALYTICS` dataset through
//! the [`FaultLog`] boundary. Detection writes nothing:
//! `scheduler_client::fetch` classifies the platform's `overloaded`
//! rejection into [`crate::errors::SchedulerClientError::Overloaded`],
//! whose rendered envelope this wrapper marks; the two edge-side
//! queue-full arms in `api.rs` mark their own replies. A point carries
//! no request data — no IP, request id or artifact identity.

use skyzen::{Endpoint, Request, Response};

use crate::stats::AnalyticsConsent;

/// The `index1` every fault point carries — `#` can never collide with
/// the crate-name indexes the miss points use.
pub const FAULT_INDEX: &str = "#fault";

/// The overload event kind — `blob1` on every point this module writes.
pub const OVERLOAD_EVENT: &str = "overloaded";

/// The marker a response carries when an overload was shed in this
/// request's handling: set on the rendered envelope of a
/// `SchedulerOverloaded` error by [`OverloadFaults`], and on their own
/// 429 replies by the queue-full arms in `api.rs`. A response
/// extension — never a header, so nothing on the wire changes.
#[derive(Debug, Clone)]
pub struct OverloadFault;

/// Where fault points go. The worker writes the bound Analytics Engine
/// dataset; host tests record the calls they were handed.
pub trait FaultLog: Sync {
    /// Record one overload detection on the route `label` — the request
    /// path whose answer carries the marker. Infallible at the call
    /// site: analytics are a side channel that must never fail the
    /// request that observed the overload, so the writer reports its
    /// own failures. `consent` carries the request's
    /// `x-stow-no-analytics` opt-out; a refused consent writes nothing.
    fn write_overload(&self, consent: AnalyticsConsent, label: &str);
}

#[cfg(target_arch = "wasm32")]
impl FaultLog for skyzen_cloudflare::worker::AnalyticsEngineDataset {
    fn write_overload(&self, consent: AnalyticsConsent, label: &str) {
        use skyzen_cloudflare::worker::AnalyticsEngineDataPointBuilder;

        if !consent.allowed() {
            return;
        }
        if let Err(error) = AnalyticsEngineDataPointBuilder::new()
            .indexes([FAULT_INDEX])
            .blobs([OVERLOAD_EVENT, label])
            .doubles([1.0])
            .write_to(self)
        {
            tracing::warn!(%error, "failed to write overload point to Analytics Engine");
        }
    }
}

/// The Worker's recording boundary: wraps the router inside
/// `no_store`'s outer layer so every answer carrying an
/// [`OverloadFault`] marker leaves one fault point — marked `Ok`
/// replies and `SchedulerOverloaded` errors alike. An overload `Err` is
/// rendered through [`skyzen::error_response`] here, marked, and
/// recorded; any other error passes up untouched so `no_store` renders
/// and stamps it exactly as before.
#[derive(Clone)]
pub struct OverloadFaults<E, L> {
    inner: E,
    log: L,
}

impl<E, L> OverloadFaults<E, L> {
    pub const fn new(inner: E, log: L) -> Self {
        Self { inner, log }
    }
}

impl<E, L> Endpoint for OverloadFaults<E, L>
where
    E: Endpoint<Error = Box<dyn skyzen::HttpError>>,
    L: FaultLog + Send,
{
    type Error = E::Error;

    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        // Consent and the request identity are read before `respond`
        // takes the request mutably — the path is the point's `blob2`,
        // the route the caller saw the shed on.
        let consent = AnalyticsConsent::from_request(request);
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let response = match self.inner.respond(request).await {
            Ok(response) => response,
            Err(error) => {
                // The router erases the concrete error type into
                // `Box<dyn HttpError>` — `SchedulerOverloaded`'s
                // display prefix is the marker it leaves behind.
                if !error
                    .to_string()
                    .starts_with(crate::errors::OVERLOADED_PREFIX)
                {
                    return Err(error);
                }
                skyzen::log_endpoint_error(error.as_ref(), &method, &path);
                let mut response = skyzen::error_response(&error);
                response.extensions_mut().insert(OverloadFault);
                response
            }
        };
        if response.extensions().get::<OverloadFault>().is_some() {
            self.log.write_overload(consent, &path);
        }
        Ok(response)
    }
}

/// Recording [`FaultLog`] for host tests — stores each call's label and
/// whether the consent it carried allowed the write.
#[cfg(test)]
#[derive(Debug, Default, Clone)]
pub struct RecordingFaultLog {
    /// One `(label, allowed)` per `write_overload` call.
    pub points: std::sync::Arc<std::sync::Mutex<Vec<(String, bool)>>>,
}

#[cfg(test)]
impl FaultLog for RecordingFaultLog {
    fn write_overload(&self, consent: AnalyticsConsent, label: &str) {
        if !consent.allowed() {
            return;
        }
        self.points
            .lock()
            .expect("recording fault log mutex")
            .push((label.to_owned(), true));
    }
}

#[cfg(test)]
mod tests {
    use std::future::{Future, ready};

    use skyzen::header::HeaderValue;
    use skyzen::{Body, Endpoint, Method, Request, Response, StatusCode};

    use super::{
        FAULT_INDEX, FaultLog, OVERLOAD_EVENT, OverloadFault, OverloadFaults, RecordingFaultLog,
    };
    use crate::errors::GetArtifactError;
    use crate::stats::{AnalyticsConsent, NO_ANALYTICS_HEADER};

    type BoxError = Box<dyn skyzen::HttpError>;

    /// The fault point's shape: `#fault` index, `overloaded` kind, the
    /// shedding route as `blob2`, count 1.
    #[test]
    fn overload_point_shape() {
        // The rendered tuple is exercised by the wasm impl; here the
        // constants pin the wire contract the watchdog's query reads.
        assert_eq!(FAULT_INDEX, "#fault");
        assert_eq!(OVERLOAD_EVENT, "overloaded");
    }

    /// The recording stub captures the label; a denied consent writes
    /// nothing, exactly as `write_miss` behaves.
    #[test]
    fn recording_stub_and_consent() {
        let log = RecordingFaultLog::default();
        log.write_overload(AnalyticsConsent::ALLOWED, "/api/v1/enqueue");
        assert_eq!(
            log.points.lock().expect("points").as_slice(),
            [("/api/v1/enqueue".to_owned(), true)]
        );
        log.write_overload(AnalyticsConsent::DENIED, "/api/v1/enqueue");
        assert_eq!(log.points.lock().expect("points").len(), 1);
    }

    fn request() -> Request {
        let mut request = Request::new(Body::empty());
        *request.method_mut() = Method::GET;
        *request.uri_mut() = "/api/v1/enqueue".parse().expect("uri");
        request
    }

    /// An opted-out request — `x-stow-no-analytics: 1` is the consent
    /// the miss writer honours (stow#568).
    fn opted_out_request() -> Request {
        let mut request = request();
        request
            .headers_mut()
            .insert(NO_ANALYTICS_HEADER, HeaderValue::from_static("1"));
        request
    }

    /// A handler whose answer already carries the marker — the shape
    /// the queue-full arms in `api.rs` produce.
    struct MarkedEndpoint;

    impl skyzen::Endpoint for MarkedEndpoint {
        type Error = BoxError;

        fn respond(
            &mut self,
            _: &mut Request,
        ) -> impl Future<Output = Result<Response, Self::Error>> + Send {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
            response.extensions_mut().insert(OverloadFault);
            ready(Ok(response))
        }
    }

    /// A handler error — the platform-overload arm renders its own
    /// marked envelope; anything else passes up for `no_store`.
    struct FailsEndpoint(Option<GetArtifactError>);

    impl skyzen::Endpoint for FailsEndpoint {
        type Error = BoxError;

        fn respond(
            &mut self,
            _: &mut Request,
        ) -> impl Future<Output = Result<Response, Self::Error>> + Send {
            let error: BoxError = Box::new(self.0.take().expect("each test calls respond once"));
            ready(Err(error))
        }
    }

    /// A marked answer records exactly one point carrying the request's
    /// route — the only place a shed becomes a fault write.
    #[tokio::test]
    async fn a_marked_answer_records_one_point() {
        let log = RecordingFaultLog::default();
        let mut endpoint = OverloadFaults::new(MarkedEndpoint, log.clone());
        endpoint.respond(&mut request()).await.unwrap();
        assert_eq!(
            log.points.lock().expect("points").as_slice(),
            [("/api/v1/enqueue".to_owned(), true)]
        );
    }

    /// A `SchedulerOverloaded` error leaves as a marked 503 envelope
    /// and records one point; the client-visible status is untouched.
    #[tokio::test]
    async fn an_overloaded_error_marks_and_records() {
        let log = RecordingFaultLog::default();
        let mut endpoint = OverloadFaults::new(
            FailsEndpoint(Some(GetArtifactError::SchedulerOverloaded(
                "Durable Object is overloaded".to_owned(),
            ))),
            log.clone(),
        );
        let response = endpoint.respond(&mut request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.extensions().get::<OverloadFault>().is_some());
        assert_eq!(log.points.lock().expect("points").len(), 1);
    }

    /// An unmarked answer — a plain success and a non-overload error —
    /// records nothing.
    #[tokio::test]
    async fn unmarked_answers_record_nothing() {
        let log = RecordingFaultLog::default();
        let mut endpoint =
            OverloadFaults::new(FailsEndpoint(Some(GetArtifactError::NotFound)), log.clone());
        let error = endpoint
            .respond(&mut request())
            .await
            .expect_err("a non-overload error passes up untouched");
        assert_eq!(error.to_string(), "artifact not found");
        let mut endpoint = OverloadFaults::new(
            {
                struct Plain;
                impl skyzen::Endpoint for Plain {
                    type Error = BoxError;
                    fn respond(
                        &mut self,
                        _: &mut Request,
                    ) -> impl Future<Output = Result<Response, Self::Error>> + Send
                    {
                        ready(Ok(Response::new(Body::empty())))
                    }
                }
                Plain
            },
            log.clone(),
        );
        endpoint.respond(&mut request()).await.unwrap();
        assert!(log.points.lock().expect("points").is_empty());
    }

    /// `x-stow-no-analytics: 1` suppresses the write for a marked
    /// answer — the opt-out is honoured exactly as the miss writer's.
    #[tokio::test]
    async fn an_opted_out_request_records_nothing() {
        let log = RecordingFaultLog::default();
        let mut endpoint = OverloadFaults::new(MarkedEndpoint, log.clone());
        endpoint.respond(&mut opted_out_request()).await.unwrap();
        assert!(log.points.lock().expect("points").is_empty());
    }
}
