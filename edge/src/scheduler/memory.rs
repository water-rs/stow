//! The Wasm linear memory the scheduler's isolate holds, read for the
//! occupancy lines the wake and the budget probe log. Linear memory
//! never shrinks, so the reading is the isolate's high-water mark of
//! Wasm pages; it is not the JavaScript heap and not Cloudflare's
//! billed memory.

/// Bytes of Wasm linear memory; the host build has none to read, so the
/// log field is absent there (`None`).
#[cfg(target_arch = "wasm32")]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the host build returns None, and the log field takes the same Option"
)]
pub(super) fn linear_bytes() -> Option<u64> {
    use wasm_bindgen::JsCast as _;

    let memory = wasm_bindgen::memory()
        .dyn_into::<js_sys::WebAssembly::Memory>()
        .expect("the module exports WebAssembly.Memory");
    let buffer = memory
        .buffer()
        .dyn_into::<js_sys::ArrayBuffer>()
        .expect("the module uses unshared linear memory");
    Some(u64::from(buffer.byte_length()))
}

/// Bytes of Wasm linear memory; the host build has none to read, so the
/// log field is absent there (`None`).
#[cfg(not(target_arch = "wasm32"))]
pub(super) const fn linear_bytes() -> Option<u64> {
    None
}
