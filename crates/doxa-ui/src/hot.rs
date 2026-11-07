//! Hot-patching under `doxa dev`: debug wasm renders through subsecond's jump table, and
//! each patch re-renders every live component with its state kept.

use std::any::Any;
use std::rc::Rc;

use crate::component::RenderFuture;

/// Call a component's render, through the latest patch of it if there is one.
pub(crate) fn render(f: fn(&Rc<dyn Any>) -> RenderFuture, props: &Rc<dyn Any>) -> RenderFuture {
    #[cfg(all(target_arch = "wasm32", debug_assertions))]
    return subsecond::HotFn::current(f).call((props,));
    #[cfg(not(all(target_arch = "wasm32", debug_assertions)))]
    f(props)
}

/// Call a story, through the latest patch of it if there is one.
pub(crate) fn story<S>(f: fn() -> S) -> S {
    #[cfg(all(target_arch = "wasm32", debug_assertions))]
    return subsecond::HotFn::current(f).call(());
    #[cfg(not(all(target_arch = "wasm32", debug_assertions)))]
    f()
}

/// Expose `globalThis.__doxa_hotpatch(jumpTable)` to the dev reload script, once.
pub(crate) fn install() {
    #[cfg(all(target_arch = "wasm32", debug_assertions))]
    web::install();
}

#[cfg(all(target_arch = "wasm32", debug_assertions))]
mod web {
    use std::cell::Cell;
    use std::sync::Arc;

    use wasm_bindgen::prelude::*;

    thread_local! {
        static INSTALLED: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn install() {
        if INSTALLED.with(|i| i.replace(true)) {
            return;
        }
        subsecond::register_handler(Arc::new(crate::runtime::rerender_all));
        let apply = Closure::<dyn Fn(String) -> Result<(), JsValue>>::new(|json: String| {
            let table: subsecond::JumpTable = serde_json::from_str(&json)
                .map_err(|e| JsValue::from_str(&format!("bad jump table: {e}")))?;
            // SAFETY: the table comes from `doxa dev`, built against this exact module.
            unsafe { subsecond::apply_patch(table) }.map_err(|e| JsValue::from_str(&e.to_string()))
        });
        let global = js_sys::global();
        let _ = js_sys::Reflect::set(&global, &"__doxa_hotpatch".into(), apply.as_ref());
        let pending = js_sys::Reflect::get(&global, &"__doxa_pending_patch".into())
            .ok()
            .and_then(|p| p.as_string());
        if let Some(json) = pending {
            let _ = apply
                .as_ref()
                .unchecked_ref::<js_sys::Function>()
                .call1(&global, &json.into());
        }
        apply.forget();
    }
}
