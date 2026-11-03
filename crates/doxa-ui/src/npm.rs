//! What `#[npm]` bindings convert through, and the error a JS call fails with.

use std::fmt;

/// A JS call that threw, rejected, or answered something that didn't convert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsError(String);

impl JsError {
    /// An error saying `message`.
    pub fn new(message: impl Into<String>) -> Self {
        JsError(message.into())
    }
}

impl fmt::Display for JsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for JsError {}

#[cfg(target_arch = "wasm32")]
pub(crate) mod convert {
    use super::JsError;
    use wasm_bindgen::{JsCast, JsValue};

    /// `value` as JS, JSON-compatible: maps become objects, `u64`s numbers.
    pub fn to_js<T: serde::Serialize + ?Sized>(value: &T) -> Result<JsValue, JsError> {
        value
            .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
            .map_err(|e| JsError(e.to_string()))
    }

    pub fn from_js<T: serde::de::DeserializeOwned>(value: JsValue) -> Result<T, JsError> {
        serde_wasm_bindgen::from_value(value).map_err(|e| JsError(e.to_string()))
    }

    pub fn js_error(message: &str) -> JsError {
        JsError(message.to_owned())
    }

    /// A thrown value's `message`, or the value itself as text.
    pub fn js_error_from(value: JsValue) -> JsError {
        let message = value
            .dyn_ref::<js_sys::Error>()
            .map(|e| String::from(e.message()))
            .or_else(|| value.as_string())
            .unwrap_or_else(|| format!("{value:?}"));
        JsError(message)
    }

    pub fn describe(e: JsError) -> String {
        e.0
    }

    pub async fn await_promise(value: JsValue) -> Result<JsValue, JsValue> {
        let promise: js_sys::Promise = value.unchecked_into();
        wasm_bindgen_futures::JsFuture::from(promise).await
    }
}
