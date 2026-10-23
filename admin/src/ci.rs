//! `stow-admin`'s half of the one privileged CI interface (stow#877):
//! the [`CiTransport`] `stow_types::ci::CiInterface` drives on the
//! host. One zenwave call per prepared request — the shared layer's
//! status reads and dispatch sends land exactly as the scheduler's
//! wasm transport issues them.

use stow_types::ci::{CiRequest, CiResponse, CiTransport, DispatchError};
use zenwave::Client;

/// zenwave behind [`CiInterface`](stow_types::ci::CiInterface) — every
/// answer's status, headers and buffered body come back verbatim so
/// `Link`-driven pagination and rate-limit classification work as the
/// shared layer reads them.
#[derive(Debug, Clone, Copy)]
pub struct ZenwaveTransport;

impl CiTransport for ZenwaveTransport {
    async fn send(&self, request: CiRequest) -> Result<CiResponse, DispatchError> {
        let mut client = zenwave::client();
        let mut builder = match request.method {
            "GET" => client.get(&request.url),
            "POST" => client.post(&request.url),
            other => {
                return Err(DispatchError::Network(format!(
                    "unsupported method {other}"
                )));
            }
        }
        .map_err(|error| DispatchError::Network(error.to_string()))?;
        for (name, value) in &request.headers {
            builder = builder
                .header(name.as_str(), value.as_str())
                .map_err(|error| DispatchError::Network(error.to_string()))?;
        }
        if let Some(body) = request.body {
            builder = builder.bytes_body(body);
        }
        let (parts, body) = builder
            .await
            .map_err(|error| DispatchError::Network(error.to_string()))?
            .into_parts();
        let body = body
            .into_bytes()
            .await
            .map_err(|error| DispatchError::Response(error.to_string()))?;
        Ok(CiResponse {
            status: parts.status.as_u16(),
            headers: parts
                .headers
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.as_str().to_owned(), value.to_owned()))
                })
                .collect(),
            body: body.to_vec(),
        })
    }
}
