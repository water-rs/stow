use skyzen::js_sys::Uint8Array;
use skyzen::wasm_bindgen::JsValue;
use skyzen_cloudflare::CfDurableNamespace;
use skyzen_cloudflare::worker_sys::web_sys::{Headers, Request, RequestInit};
use stow_types::api::{EnqueueRequest, EnqueueSource};

use crate::crates_api::SubscribedCrate;

pub async fn enqueue_crate_updates(
    scheduler: &CfDurableNamespace,
    object_name: &str,
    targets: &[String],
    crates: &[SubscribedCrate],
) -> Result<(), String> {
    let payloads = crates
        .iter()
        .flat_map(|krate| {
            targets.iter().map(move |target| EnqueueRequest {
                crate_name: krate.name.clone(),
                version: krate.latest_version.clone(),
                target: target.clone(),
                downloads: krate.downloads,
                source: EnqueueSource::CrateUpdate,
            })
        })
        .collect::<Vec<_>>();

    send_enqueue_batch(scheduler, object_name, &payloads).await
}

pub async fn enqueue_rustc_refresh(
    scheduler: &CfDurableNamespace,
    object_name: &str,
    targets: &[String],
    crates: &[SubscribedCrate],
    rustc_version: &str,
) -> Result<(), String> {
    let payloads = crates
        .iter()
        .flat_map(|krate| {
            targets.iter().map(move |target| EnqueueRequest {
                crate_name: krate.name.clone(),
                version: krate.latest_version.clone(),
                target: target.clone(),
                downloads: krate.downloads,
                source: EnqueueSource::RustcUpdate,
            })
        })
        .collect::<Vec<_>>();

    tracing::info!(
        rustc_version,
        tasks = payloads.len(),
        "enqueueing rustc refresh batch"
    );
    send_enqueue_batch(scheduler, object_name, &payloads).await
}

async fn send_enqueue_batch(
    scheduler: &CfDurableNamespace,
    object_name: &str,
    payloads: &[EnqueueRequest],
) -> Result<(), String> {
    if payloads.is_empty() {
        return Ok(());
    }

    let stub = scheduler
        .get_by_name(object_name)
        .map_err(|error| format!("scheduler stub: {error}"))?;
    let request = enqueue_request(payloads)?;
    let response = stub
        .fetch(&request)
        .await
        .map_err(|error| format!("scheduler enqueue fetch: {error}"))?;

    if !response.ok() {
        return Err(format!(
            "scheduler enqueue returned HTTP {}",
            response.status()
        ));
    }

    Ok(())
}

fn enqueue_request(payloads: &[EnqueueRequest]) -> Result<Request, String> {
    let body = serde_json::to_vec(payloads)
        .map_err(|error| format!("serialize enqueue payloads: {error}"))?;
    let headers = Headers::new().map_err(js_error)?;
    headers
        .set("Content-Type", "application/json")
        .map_err(js_error)?;

    let init = RequestInit::new();
    init.set_method("POST");
    init.set_headers(&headers);

    let bytes = Uint8Array::from(body.as_slice());
    init.set_body(&JsValue::from(bytes));

    Request::new_with_str_and_init("https://scheduler.internal/enqueue", &init).map_err(js_error)
}

fn js_error(error: JsValue) -> String {
    format!("{error:?}")
}
