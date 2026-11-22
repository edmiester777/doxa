//! The page's bridge to the native shell it runs in: Tauri commands and events. Off wasm, every
//! call fails with [`Error::NoShell`], so shell builds of the same crate compile.

use std::fmt;

use serde::de::DeserializeOwned;
use serde::Serialize;

/// Why a native call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The page isn't running inside a native shell.
    NoShell,
    /// The command rejected, with its message.
    Command(String),
    /// The arguments or the result didn't (de)serialize.
    Json(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NoShell => f.write_str("not running in a native app"),
            Error::Command(m) => f.write_str(m),
            Error::Json(m) => write!(f, "native call: {m}"),
        }
    }
}

impl std::error::Error for Error {}

/// Whether the page is running inside a native shell.
pub fn available() -> bool {
    imp::available()
}

/// Calls a shell command: an app command by name, or a plugin's as `plugin:<name>|<command>`.
pub async fn invoke<T: DeserializeOwned>(cmd: &str, args: &impl Serialize) -> Result<T, Error> {
    let args = serde_json::to_string(args).map_err(|e| Error::Json(e.to_string()))?;
    let out = imp::invoke(cmd, &args).await?;
    serde_json::from_str(&out).map_err(|e| Error::Json(format!("{cmd}: {e}")))
}

/// Calls `f` with each payload of the shell's `event` until the returned [`Listener`] drops.
/// Payloads that don't deserialize as `T` are skipped.
pub fn listen<T: DeserializeOwned + 'static>(
    event: &str,
    mut f: impl FnMut(T) + 'static,
) -> Listener {
    Listener {
        _listening: imp::listen(
            event,
            Box::new(move |json: &str| {
                if let Ok(t) = serde_json::from_str(json) {
                    f(t)
                }
            }),
        ),
    }
}

/// Stops its listen when dropped.
#[must_use = "dropping it stops the listen"]
pub struct Listener {
    _listening: imp::Listening,
}

#[cfg(target_arch = "wasm32")]
mod imp {
    use std::cell::Cell;
    use std::rc::Rc;

    use js_sys::{Promise, Reflect, JSON};
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::JsFuture;

    use super::Error;

    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_namespace = ["window", "__TAURI_INTERNALS__"], js_name = invoke, catch)]
        fn tauri_invoke(cmd: &str, args: &JsValue) -> Result<Promise, JsValue>;
        #[wasm_bindgen(js_namespace = ["window", "__TAURI_INTERNALS__"], js_name = transformCallback)]
        fn transform_callback(cb: &Closure<dyn FnMut(JsValue)>, once: bool) -> u32;
    }

    fn internals() -> Option<JsValue> {
        let w = web_sys::window()?;
        Reflect::get(&w, &"__TAURI_INTERNALS__".into())
            .ok()
            .filter(|v| v.is_object())
    }

    pub fn available() -> bool {
        internals().is_some()
    }

    fn message(e: JsValue) -> String {
        e.as_string()
            .or_else(|| JSON::stringify(&e).ok().and_then(|s| s.as_string()))
            .unwrap_or_else(|| "the command failed".into())
    }

    async fn call(cmd: &str, args: &JsValue) -> Result<JsValue, Error> {
        if !available() {
            return Err(Error::NoShell);
        }
        let promise = tauri_invoke(cmd, args).map_err(|e| Error::Command(message(e)))?;
        JsFuture::from(promise)
            .await
            .map_err(|e| Error::Command(message(e)))
    }

    pub async fn invoke(cmd: &str, args: &str) -> Result<String, Error> {
        let args = JSON::parse(args).map_err(|e| Error::Json(message(e)))?;
        let out = call(cmd, &args).await?;
        if out.is_undefined() {
            return Ok("null".into());
        }
        JSON::stringify(&out)
            .ok()
            .and_then(|s| s.as_string())
            .ok_or_else(|| Error::Json(format!("{cmd}: a result JSON can't hold")))
    }

    pub struct Listening {
        event: String,
        /// The shell's id for the listen, once it answers; `dropped` covers dropping before.
        id: Rc<Cell<Option<f64>>>,
        dropped: Rc<Cell<bool>>,
        callback: u32,
        _closure: Closure<dyn FnMut(JsValue)>,
    }

    pub fn listen(event: &str, mut each: Box<dyn FnMut(&str)>) -> Listening {
        let closure = Closure::<dyn FnMut(JsValue)>::new(move |e: JsValue| {
            let payload = Reflect::get(&e, &"payload".into()).unwrap_or(JsValue::NULL);
            let json = match payload.is_undefined() {
                true => Some("null".to_owned()),
                false => JSON::stringify(&payload).ok().and_then(|s| s.as_string()),
            };
            if let Some(json) = json {
                each(&json)
            }
        });
        let (id, dropped) = (Rc::new(Cell::new(None)), Rc::new(Cell::new(false)));
        let callback = match available() {
            true => transform_callback(&closure, false),
            false => 0,
        };
        if callback != 0 {
            let args = js_sys::Object::new();
            let target = js_sys::Object::new();
            let _ = Reflect::set(&target, &"kind".into(), &"Any".into());
            let _ = Reflect::set(&args, &"event".into(), &event.into());
            let _ = Reflect::set(&args, &"target".into(), &target);
            let _ = Reflect::set(&args, &"handler".into(), &callback.into());
            let (id, dropped, event) = (id.clone(), dropped.clone(), event.to_owned());
            wasm_bindgen_futures::spawn_local(async move {
                if let Some(n) = call("plugin:event|listen", &args.into())
                    .await
                    .ok()
                    .and_then(|v| v.as_f64())
                {
                    match dropped.get() {
                        true => unlisten(&event, n),
                        false => id.set(Some(n)),
                    }
                }
            });
        }
        Listening {
            event: event.to_owned(),
            id,
            dropped,
            callback,
            _closure: closure,
        }
    }

    fn unlisten(event: &str, id: f64) {
        let args = js_sys::Object::new();
        let _ = Reflect::set(&args, &"event".into(), &event.into());
        let _ = Reflect::set(&args, &"eventId".into(), &id.into());
        wasm_bindgen_futures::spawn_local(async move {
            let _ = call("plugin:event|unlisten", &args.into()).await;
        });
    }

    impl Drop for Listening {
        fn drop(&mut self) {
            self.dropped.set(true);
            if let Some(id) = self.id.get() {
                unlisten(&self.event, id);
            }
            // Older shells lack it; their callback slot just stays unused.
            if let Some(f) = internals()
                .and_then(|i| Reflect::get(&i, &"unregisterCallback".into()).ok())
                .and_then(|f| f.dyn_into::<js_sys::Function>().ok())
            {
                let _ = f.call1(&JsValue::NULL, &self.callback.into());
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod imp {
    use super::Error;

    pub fn available() -> bool {
        false
    }

    pub async fn invoke(_cmd: &str, _args: &str) -> Result<String, Error> {
        Err(Error::NoShell)
    }

    pub struct Listening;

    pub fn listen(_event: &str, _each: Box<dyn FnMut(&str)>) -> Listening {
        Listening
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_wasm_there_is_no_shell() {
        assert!(!available());
        let r: Result<(), _> = crate::task::block_on(invoke("x", &()));
        assert_eq!(r, Err(Error::NoShell));
        let _l = listen::<u32>("e", |_| {});
    }
}
