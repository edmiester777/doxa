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

/// A Rust function a JS module can call, alive until this drops: built with
/// `JsCallback::<dyn Fn(String)>::new(f)`, passed to an `#[npm]` function by reference.
pub struct JsCallback<F: ?Sized> {
    #[cfg(target_arch = "wasm32")]
    closure: wasm_bindgen::closure::Closure<F>,
    #[cfg(not(target_arch = "wasm32"))]
    _f: std::marker::PhantomData<fn() -> std::rc::Rc<F>>,
}

/// What a JS module can pass to a [`JsCallback`].
#[cfg(target_arch = "wasm32")]
pub trait JsArg: wasm_bindgen::convert::FromWasmAbi + 'static {}
#[cfg(target_arch = "wasm32")]
impl<T: wasm_bindgen::convert::FromWasmAbi + 'static> JsArg for T {}
/// What a JS module can pass to a [`JsCallback`].
#[cfg(not(target_arch = "wasm32"))]
pub trait JsArg: 'static {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: 'static> JsArg for T {}

macro_rules! js_callback {
    ($($a:ident),*) => {
        impl<$($a: JsArg),*> JsCallback<dyn Fn($($a),*)> {
            /// Wrap `f`.
            #[cfg_attr(not(target_arch = "wasm32"), allow(unused_variables))]
            pub fn new(f: impl Fn($($a),*) + 'static) -> Self {
                JsCallback {
                    #[cfg(target_arch = "wasm32")]
                    closure: wasm_bindgen::closure::Closure::new(f),
                    #[cfg(not(target_arch = "wasm32"))]
                    _f: std::marker::PhantomData,
                }
            }
        }
    };
}

js_callback!();
js_callback!(A);
js_callback!(A, B);
js_callback!(A, B, C);
js_callback!(A, B, C, D);

#[cfg(target_arch = "wasm32")]
pub(crate) mod convert {
    use super::{JsCallback, JsError};
    use wasm_bindgen::{JsCast, JsValue};

    /// The JS function behind `f`.
    pub fn js_callback<F: ?Sized>(f: &JsCallback<F>) -> JsValue
    where
        F: wasm_bindgen::closure::WasmClosure,
    {
        let function: &JsValue = f.closure.as_ref();
        function.clone()
    }

    /// The browser node behind `node`.
    pub fn js_node(node: crate::NodeRef) -> Result<JsValue, JsError> {
        node.raw()
            .map(Into::into)
            .ok_or_else(|| JsError("the element has left the page".to_owned()))
    }

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
