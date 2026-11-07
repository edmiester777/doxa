//! `#[component(export)]`: a doxa component a foreign React host mounts, one root per use.

use std::cell::RefCell;
use std::rc::Rc;

use crate::app::{App, RootHandle};
use crate::component::Component;
use crate::dom::{Dom, NodeId};
use crate::view::comp;

/// One mounted exported component: its root and the props it renders with.
pub struct Exported<C: Component> {
    props: Rc<RefCell<C::Props>>,
    root: RootHandle,
}

impl<C: Component> Exported<C> {
    /// Mount `C` at `at`, embedded: no router, its theme on `at`.
    pub fn mount_on(dom: Rc<dyn Dom>, at: NodeId, props: C::Props) -> Self {
        let cell = Rc::new(RefCell::new(props));
        let read = cell.clone();
        let root = App::embedded(move || comp::<C>(read.borrow().clone())).mount_on(dom, at);
        Exported { props: cell, root }
    }

    /// Render again with `props`.
    pub fn update(&self, props: C::Props) {
        *self.props.borrow_mut() = props;
        self.root.refresh();
    }

    /// Its root's id, which its islands are mounted under.
    pub fn root(&self) -> u64 {
        self.root.id()
    }
}

#[cfg(target_arch = "wasm32")]
pub use web::*;

#[cfg(target_arch = "wasm32")]
mod web {
    use std::any::Any;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use wasm_bindgen::prelude::*;

    use super::Exported;
    use crate::component::Component;
    use crate::dom::WebDom;
    use crate::runtime;
    use crate::Callback;

    /// The JS function behind each callback prop, so its [`Callback`] stays the same across
    /// updates while React passes a new closure each render.
    #[derive(Default)]
    pub struct Calls(RefCell<HashMap<&'static str, Call>>);

    struct Call {
        latest: Rc<RefCell<js_sys::Function>>,
        callback: Box<dyn Any>,
    }

    /// Read prop `key` of `props`.
    pub fn prop<T: DeserializeOwned>(props: &JsValue, key: &str) -> Result<T, JsError> {
        let v = js_sys::Reflect::get(props, &JsValue::from_str(key)).unwrap_or(JsValue::UNDEFINED);
        serde_wasm_bindgen::from_value(v).map_err(|e| JsError::new(&format!("prop `{key}`: {e}")))
    }

    /// A signature a JS function can stand behind: its arguments cross as JSON-compatible data.
    pub trait JsCallable: 'static {
        fn calling(latest: Rc<RefCell<js_sys::Function>>) -> Callback<Self>;
    }

    /// `null` for a value JS has no form for, so the function still gets its position.
    fn to_arg<T: Serialize>(arg: &T) -> JsValue {
        arg.serialize(&serde_wasm_bindgen::Serializer::json_compatible())
            .unwrap_or(JsValue::NULL)
    }

    impl JsCallable for dyn Fn() {
        fn calling(latest: Rc<RefCell<js_sys::Function>>) -> Callback<Self> {
            Callback::from(move || {
                let f = latest.borrow().clone();
                let _ = f.call0(&JsValue::NULL);
            })
        }
    }

    /// `()` and anything else serializing to nothing call the function with no arguments.
    impl<T: Serialize + 'static> JsCallable for dyn Fn(T) {
        fn calling(latest: Rc<RefCell<js_sys::Function>>) -> Callback<Self> {
            Callback::from(move |arg: T| {
                let f = latest.borrow().clone();
                let v = to_arg(&arg);
                let _ = if v.is_undefined() || v.is_null() {
                    f.call0(&JsValue::NULL)
                } else {
                    f.call1(&JsValue::NULL, &v)
                };
            })
        }
    }

    macro_rules! js_callable {
        ($($a:ident $v:ident),+) => {
            impl<$($a: Serialize + 'static),+> JsCallable for dyn Fn($($a),+) {
                fn calling(latest: Rc<RefCell<js_sys::Function>>) -> Callback<Self> {
                    Callback::from(move |$($v: $a),+| {
                        let f = latest.borrow().clone();
                        let args = js_sys::Array::new();
                        $(args.push(&to_arg(&$v));)+
                        let _ = f.apply(&JsValue::NULL, &args);
                    })
                }
            }
        };
    }

    js_callable!(A a, B b);
    js_callable!(A a, B b, C c);
    js_callable!(A a, B b, C c, D d);

    /// Prop `key` of `props`, a function called with the [`Callback`]'s arguments; missing is a no-op.
    pub fn callback<F: JsCallable + ?Sized>(
        calls: &Calls,
        props: &JsValue,
        key: &'static str,
    ) -> Result<Callback<F>, JsError> {
        let v = js_sys::Reflect::get(props, &JsValue::from_str(key)).unwrap_or(JsValue::UNDEFINED);
        let f: js_sys::Function = if v.is_undefined() || v.is_null() {
            js_sys::Function::new_no_args("")
        } else {
            v.dyn_into()
                .map_err(|_| JsError::new(&format!("prop `{key}` isn't a function")))?
        };
        let mut map = calls.0.borrow_mut();
        if let Some(call) = map.get(key) {
            if let Some(cb) = call.callback.downcast_ref::<Callback<F>>() {
                *call.latest.borrow_mut() = f;
                return Ok(cb.clone());
            }
        }
        let latest = Rc::new(RefCell::new(f));
        let cb = F::calling(latest.clone());
        map.insert(
            key,
            Call {
                latest,
                callback: Box::new(cb.clone()),
            },
        );
        Ok(cb)
    }

    trait Mounted {
        fn update(&self, props: &JsValue) -> Result<(), JsError>;
        fn root(&self) -> u64;
    }

    struct Live<C: Component> {
        exported: Exported<C>,
        calls: Calls,
        convert: Convert<C>,
    }

    type Convert<C> = fn(&Calls, &JsValue) -> Result<<C as Component>::Props, JsError>;

    impl<C: Component> Mounted for Live<C> {
        fn update(&self, props: &JsValue) -> Result<(), JsError> {
            self.exported.update((self.convert)(&self.calls, props)?);
            Ok(())
        }
        fn root(&self) -> u64 {
            self.exported.root()
        }
    }

    /// An exported component mounted by a host; `unmount()` when the host's element goes.
    #[wasm_bindgen]
    pub struct ExportHandle(Option<Box<dyn Mounted>>);

    #[wasm_bindgen]
    impl ExportHandle {
        /// Render again with `props`.
        pub fn update(&self, props: JsValue) -> Result<(), JsError> {
            match &self.0 {
                Some(m) => m.update(&props),
                None => Ok(()),
            }
        }

        /// The root its islands mount under.
        pub fn root(&self) -> f64 {
            self.0.as_ref().map_or(0.0, |m| m.root() as f64)
        }

        /// Unmount it: its effects stop and its nodes go.
        pub fn unmount(&mut self) {
            self.0.take();
        }
    }

    /// Mount `C` inside `host`, converting `props` with `convert`.
    pub fn mount<C: Component>(
        host: web_sys::Element,
        props: &JsValue,
        convert: Convert<C>,
    ) -> Result<ExportHandle, JsError> {
        let calls = Calls::default();
        let first = convert(&calls, props)?;
        let dom = runtime::try_dom().unwrap_or_else(|| Rc::new(WebDom::new()));
        let at = dom
            .adopt(host.into())
            .ok_or_else(|| JsError::new("the host element isn't in this document"))?;
        let exported = Exported::<C>::mount_on(dom, at, first);
        Ok(ExportHandle(Some(Box::new(Live {
            exported,
            calls,
            convert,
        }))))
    }

    thread_local! {
        static INVALIDATED: RefCell<Option<js_sys::Function>> = const { RefCell::new(None) };
    }

    /// Base URLs by client crate, a bearer token asked for per request, the host router's
    /// `navigate(to, { replace })`, and `invalidated(entities)` told of each cache invalidation.
    #[wasm_bindgen(js_name = "__doxa_configure")]
    pub fn configure(
        services: JsValue,
        token: Option<js_sys::Function>,
        navigate: Option<js_sys::Function>,
        invalidated: Option<js_sys::Function>,
    ) {
        if let Some(navigate) = navigate {
            crate::router::navigate_through(move |to, replace| {
                let options = js_sys::Object::new();
                let _ = js_sys::Reflect::set(&options, &"replace".into(), &replace.into());
                let _ = navigate.call2(&JsValue::NULL, &to.into(), &options);
            });
        }
        if let Some(f) = invalidated {
            let first = INVALIDATED.with(|i| i.borrow_mut().replace(f).is_none());
            if first {
                doxa_client::cache::on_invalidated(|entities| {
                    let list: js_sys::Array = entities.iter().map(|e| JsValue::from(*e)).collect();
                    if let Some(f) = INVALIDATED.with(|i| i.borrow().clone()) {
                        let _ = f.call1(&JsValue::NULL, &list);
                    }
                });
            }
        }
        if !services.is_undefined() && !services.is_null() {
            if let Some(global) = js_sys::global().dyn_ref::<js_sys::Object>() {
                let _ = js_sys::Reflect::set(global, &"__DOXA_SERVICES__".into(), &services);
            }
        }
        if let Some(token) = token {
            doxa_client::layers().push(doxa_client::layer::bearer(move || {
                token.call0(&JsValue::NULL).ok()?.as_string()
            }));
        }
    }

    /// Mark stale every cached query about any of `entities`, after a host's own mutation.
    #[wasm_bindgen(js_name = "__doxa_invalidate")]
    pub fn invalidate(entities: Vec<String>) {
        let entities: Vec<&str> = entities.iter().map(String::as_str).collect();
        doxa_client::cache::invalidate_entities(&entities);
    }
}
