//! `HttpTimeout` — the `http.timeout`/`http.low-speed-limit` config pair.
//! `cargo::util::network::http` also configures a curl handle; the async
//! client configures its own transport, so only the data type is carried.

use crate::util::errors::CargoResult;
use std::time::Duration;

pub struct HttpTimeout {
    pub dur: Duration,
    pub low_speed_limit: u32,
}

impl HttpTimeout {
    pub fn new(gctx: &crate::GlobalContext) -> CargoResult<HttpTimeout> {
        let http_config = gctx.http_config()?;
        let low_speed_limit = http_config.low_speed_limit.unwrap_or(10);
        let seconds = http_config
            .timeout
            .or_else(|| {
                gctx.get_env("HTTP_TIMEOUT")
                    .ok()
                    .and_then(|s| s.parse().ok())
            })
            .unwrap_or(30);
        Ok(HttpTimeout {
            dur: Duration::new(seconds, 0),
            low_speed_limit,
        })
    }
}
