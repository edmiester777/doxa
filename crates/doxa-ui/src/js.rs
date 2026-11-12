//! [`Js`]: a JS value Rust passes along without reading.

#[cfg(target_arch = "wasm32")]
type Raw = wasm_bindgen::JsValue;
#[cfg(not(target_arch = "wasm32"))]
type Raw = ();

/// A JS value Rust holds but doesn't read, e.g. a plugin or a class instance; empty natively.
///
/// Two are equal when they are the same JS value (`===`).
#[derive(Clone, Debug, PartialEq)]
pub struct Js(Raw);

impl Js {
    /// `value` as JS data, JSON-compatible: maps become objects.
    #[cfg_attr(not(target_arch = "wasm32"), allow(unused_variables))]
    pub fn json<T: serde::Serialize + ?Sized>(value: &T) -> Js {
        #[cfg(target_arch = "wasm32")]
        {
            let v = value
                .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
                .unwrap_or_else(|e| panic!("`Js::json` value doesn't serialize: {e}"));
            Js(v)
        }
        #[cfg(not(target_arch = "wasm32"))]
        Js(())
    }

    /// A JS array of `items`, e.g. a `[plugin, options]` pair.
    pub fn array(items: impl IntoIterator<Item = Js>) -> Js {
        #[cfg(target_arch = "wasm32")]
        {
            let a = js_sys::Array::new();
            for item in items {
                a.push(&item.0);
            }
            Js(a.into())
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            items.into_iter().for_each(drop);
            Js(())
        }
    }

    #[doc(hidden)]
    #[cfg(not(target_arch = "wasm32"))]
    pub fn native() -> Js {
        Js(())
    }
}

#[cfg(target_arch = "wasm32")]
impl From<wasm_bindgen::JsValue> for Js {
    fn from(v: wasm_bindgen::JsValue) -> Js {
        Js(v)
    }
}

#[cfg(target_arch = "wasm32")]
impl From<Js> for wasm_bindgen::JsValue {
    fn from(v: Js) -> wasm_bindgen::JsValue {
        v.0
    }
}

#[cfg(target_arch = "wasm32")]
impl AsRef<wasm_bindgen::JsValue> for Js {
    fn as_ref(&self) -> &wasm_bindgen::JsValue {
        &self.0
    }
}
