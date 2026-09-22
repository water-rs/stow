//! The `send_email` binding the dispatch freeze alerts through.
//!
//! worker-rs 0.7 has no email module, so the binding is resolved as a
//! plain object off `env` and its `send` method invoked over
//! `wasm_bindgen`. `send()` takes `EmailMessage | EmailMessageBuilder`
//! — the builder is the plain-object shape `{to, from, subject, text}`,
//! built here by `serde_wasm_bindgen` rather than a hand-written class
//! binding — and answers `Promise<EmailSendResult>`; rejections are
//! `Error` objects carrying a structured `code` (`E_*`) and `message`.
//!
//! A failed send is never an error to the caller: it is data. The
//! returned [`DispatchFreezeNotify`] is written onto the freeze record,
//! so the freeze engages and stays engaged even when the alert goes
//! nowhere — the freeze is the load-bearing action, the email is
//! notification, and a silent notification is something `stow-admin`
//! must be able to see.

use js_sys::Reflect;
use skyzen_cloudflare::worker::send::{IntoSendFuture as _, SendWrapper};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use stow_types::api::DispatchFreezeNotify;

use crate::{env_binding, freeze};

/// `[[send_email]]` binding name, declared in `Skyzen.toml` through
/// `cloudflare.raw`. Deliberately absent from the mock/local manifests
/// so those deployments resolve to `Disabled` and can never reach
/// Cloudflare's sending API.
const STOW_ALERT_EMAIL_BINDING: &str = "STOW_ALERT_EMAIL";
/// Sender-address var; [`freeze::DEFAULT_ALERT_FROM`] when unset.
const STOW_ALERT_FROM_BINDING: &str = "STOW_ALERT_FROM";
/// Recipient-address var; [`freeze::DEFAULT_ALERT_TO`] when unset.
const STOW_ALERT_TO_BINDING: &str = "STOW_ALERT_TO";

#[wasm_bindgen::prelude::wasm_bindgen]
extern "C" {
    /// The `send_email` binding object — a service-binding-style handle
    /// whose `send` method takes an `EmailMessage` or
    /// `EmailMessageBuilder` and returns `Promise<EmailSendResult>`.
    #[wasm_bindgen(extends = js_sys::Object)]
    type SendEmailBinding;

    /// `binding.send(message)`. A synchronous throw surfaces through
    /// `catch`; a rejection surfaces when the promise resolves.
    #[wasm_bindgen(method, catch)]
    fn send(this: &SendEmailBinding, message: &JsValue) -> Result<js_sys::Promise, JsValue>;
}

/// The resolved alert transport: the binding handle plus the addresses
/// the message is addressed with (shown to the renderer so the body
/// footer can name them). `SendWrapper` marks the JS handle Send-safe
/// (workers are single-threaded) so the config can live across `.await`
/// in the `Send` futures Skyzen requires of handlers.
pub struct AlertConfig {
    binding: SendWrapper<SendEmailBinding>,
    /// Sender — must sit on a domain onboarded under Compute → Email
    /// Service → Email Sending or `send` answers `E_SENDER_NOT_VERIFIED`.
    pub from: String,
    /// Recipient.
    pub to: String,
}

/// Resolve the binding and addresses. `Err` carries the `Disabled`
/// outcome naming the missing piece — for the mock/local deployments
/// that is the binding itself, by design.
pub fn alert_config(env: &JsValue) -> Result<AlertConfig, DispatchFreezeNotify> {
    let value =
        Reflect::get(env, &JsValue::from_str(STOW_ALERT_EMAIL_BINDING)).map_err(|error| {
            freeze::notify_disabled(format!(
                "reading binding '{STOW_ALERT_EMAIL_BINDING}': {error:?}"
            ))
        })?;
    if value.is_undefined() || value.is_null() {
        return Err(freeze::notify_disabled(format!(
            "'{STOW_ALERT_EMAIL_BINDING}' send_email binding is not declared"
        )));
    }
    let send = Reflect::get(&value, &JsValue::from_str("send"))
        .ok()
        .filter(JsValue::is_function);
    if send.is_none() {
        return Err(freeze::notify_disabled(format!(
            "'{STOW_ALERT_EMAIL_BINDING}' is not a send_email binding (no send method)"
        )));
    }
    Ok(AlertConfig {
        binding: SendWrapper::new(value.unchecked_into()),
        from: env_binding::optional_string(env, STOW_ALERT_FROM_BINDING)
            .unwrap_or_else(|| freeze::DEFAULT_ALERT_FROM.to_owned()),
        to: env_binding::optional_string(env, STOW_ALERT_TO_BINDING)
            .unwrap_or_else(|| freeze::DEFAULT_ALERT_TO.to_owned()),
    })
}

/// `send()` one text alert. Never returns `Err`: a synchronous throw, a
/// rejected promise, and a serialization failure all become
/// [`DispatchFreezeNotify::Failed`] with the structured code extracted
/// when the error object carries one.
pub async fn send_alert(config: &AlertConfig, subject: &str, text: &str) -> DispatchFreezeNotify {
    // The EmailMessageBuilder plain-object shape — `send()` takes
    // `EmailMessage | EmailMessageBuilder`; `serde_wasm_bindgen` produces
    // exactly the `{to, from, subject, text}` object literal the builder
    // describes, which is far less code than a class binding.
    #[derive(serde::Serialize)]
    struct EmailMessageBuilder<'a> {
        to: &'a str,
        from: &'a str,
        subject: &'a str,
        text: &'a str,
    }
    let message = match serde_wasm_bindgen::to_value(&EmailMessageBuilder {
        to: &config.to,
        from: &config.from,
        subject,
        text,
    }) {
        Ok(message) => message,
        Err(error) => {
            return freeze::notify_failed(None, format!("serialize EmailMessageBuilder: {error}"));
        }
    };
    let promise = match config.binding.send(&message) {
        Ok(promise) => promise,
        Err(error) => return send_error(&error),
    };
    match JsFuture::from(promise).into_send().await {
        Ok(result) => {
            let message_id = Reflect::get(&result, &JsValue::from_str("messageId"))
                .ok()
                .and_then(|value| value.as_string());
            freeze::notify_sent(message_id)
        }
        Err(error) => send_error(&error),
    }
}

/// Extract `{code, message}` off a rejected `send()` error object and
/// attach the known-code hint.
fn send_error(error: &JsValue) -> DispatchFreezeNotify {
    let code = Reflect::get(error, &JsValue::from_str("code"))
        .ok()
        .and_then(|value| value.as_string());
    let message = Reflect::get(error, &JsValue::from_str("message"))
        .ok()
        .and_then(|value| value.as_string())
        .unwrap_or_else(|| format!("{error:?}"));
    freeze::notify_failed(code, message)
}
