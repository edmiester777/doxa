//! React components in doxa views, declared with `#[react]`. Each island is a
//! portal of one React root that a small JS runtime owns; `doxa build` ships it.

use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::component::RenderFuture;
use crate::dom::{NodeRef, Phase};
use crate::runtime::{self, Instance};
use crate::view::{el, Callback};
use crate::{IntoView, Thrown};

/// Where a `#[react]` component's JS lives.
#[derive(Debug)]
pub struct Island {
    /// The Rust name, for diagnostics.
    pub name: &'static str,
    /// The module specifier: an npm package, or `doxa-island:<path>` under the web crate.
    pub module: &'static str,
    /// The export: a name, or `default`.
    pub export: &'static str,
    /// Loaded on first mount, in its own chunk.
    pub lazy: bool,
    #[cfg(target_arch = "wasm32")]
    #[doc(hidden)]
    pub load: fn() -> wasm_bindgen::JsValue,
}

/// What `#[react]` implements on a props struct.
#[doc(hidden)]
pub trait IslandProps: Clone + 'static {
    const ISLAND: Island;
    /// Whether every non-event prop is equal, so React needn't see new props.
    fn same_data(&self, other: &Self) -> bool;
    fn data(&self, out: &mut Data);
    fn events(&self, out: &mut Events);
}

/// The non-event props, as a JSON object.
#[doc(hidden)]
#[derive(Default)]
pub struct Data(serde_json::Map<String, serde_json::Value>);

impl Data {
    pub fn set<T: Serialize + ?Sized>(&mut self, name: &'static str, value: &T) {
        let v = serde_json::to_value(value)
            .unwrap_or_else(|e| panic!("React prop `{name}` doesn't serialize: {e}"));
        self.0.insert(name.to_owned(), v);
    }

    /// Leave the prop out when `None`.
    pub fn opt<T: Serialize>(&mut self, name: &'static str, value: &Option<T>) {
        if let Some(v) = value {
            self.set(name, v);
        }
    }
}

/// An event handler as JS calls it: with the JSON of its first argument.
pub type EventFn = Rc<dyn Fn(&str)>;

/// The event props.
#[doc(hidden)]
pub struct Events {
    list: Vec<(&'static str, EventFn)>,
    owner: Weak<Instance>,
}

impl Events {
    pub fn event<T: DeserializeOwned + 'static>(&mut self, name: &'static str, cb: &Callback<T>) {
        let (cb, owner) = (cb.clone(), self.owner.clone());
        self.list.push((
            name,
            Rc::new(move |json: &str| match parse::<T>(json) {
                Ok(v) => cb.call(v),
                Err(e) => runtime::throw(
                    owner.upgrade().as_ref(),
                    Thrown::msg(format!("React event `{name}`: {e}")),
                ),
            }),
        ));
    }
}

/// `T` from `json`, or from `null` for handlers that ignore the argument.
fn parse<T: DeserializeOwned>(json: &str) -> serde_json::Result<T> {
    serde_json::from_str(json).or_else(|e| serde_json::from_str("null").map_err(|_| e))
}

/// The JS side of islands. [`set_bridge`] swaps it, e.g. for a fake in native tests.
pub trait Bridge {
    /// Render `island` into `host` with `props`, a JSON object, and `events`; returns its id.
    fn mount(
        &self,
        host: NodeRef,
        island: &Island,
        props: &str,
        events: Vec<(&'static str, EventFn)>,
    ) -> u32;
    /// Give a mounted island new non-event props.
    fn update(&self, id: u32, props: &str);
    /// Remove an island's portal.
    fn unmount(&self, id: u32);
}

thread_local! {
    static BRIDGE: RefCell<Option<Rc<dyn Bridge>>> = const { RefCell::new(None) };
}

/// Use `bridge` for islands mounted from now on, on this thread.
pub fn set_bridge(bridge: impl Bridge + 'static) {
    BRIDGE.with(|b| *b.borrow_mut() = Some(Rc::new(bridge)));
}

fn bridge() -> Rc<dyn Bridge> {
    BRIDGE.with(|b| b.borrow_mut().get_or_insert_with(default_bridge).clone())
}

#[cfg(target_arch = "wasm32")]
fn default_bridge() -> Rc<dyn Bridge> {
    Rc::new(web::WebBridge::default())
}

/// Natively nothing runs React, so islands render as their empty host.
#[cfg(not(target_arch = "wasm32"))]
fn default_bridge() -> Rc<dyn Bridge> {
    struct Inert;
    impl Bridge for Inert {
        fn mount(&self, _: NodeRef, _: &Island, _: &str, _: Vec<(&'static str, EventFn)>) -> u32 {
            0
        }
        fn update(&self, _: u32, _: &str) {}
        fn unmount(&self, _: u32) {}
    }
    Rc::new(Inert)
}

type Slot = Rc<RefCell<EventFn>>;

struct Live<P> {
    id: Cell<Option<u32>>,
    shown: RefCell<Option<P>>,
    events: RefCell<Vec<(&'static str, Slot)>>,
}

impl<P: IslandProps> Live<P> {
    /// Point each event's stable slot at this render's handler.
    fn retarget(&self, events: Vec<(&'static str, EventFn)>) {
        let mut slots = self.events.borrow_mut();
        for (name, f) in events {
            match slots.iter().find(|(n, _)| *n == name) {
                Some((_, slot)) => *slot.borrow_mut() = f,
                None => slots.push((name, Rc::new(RefCell::new(f)))),
            }
        }
    }

    fn on(&self, phase: Phase, host: NodeRef, props: &P) {
        match phase {
            Phase::Mounted => {
                let forwarders = self
                    .events
                    .borrow()
                    .iter()
                    .map(|(name, slot)| {
                        let slot = slot.clone();
                        let f: EventFn = Rc::new(move |json| {
                            let f = slot.borrow().clone();
                            f(json)
                        });
                        (*name, f)
                    })
                    .collect();
                let id = bridge().mount(host, &P::ISLAND, &json(props), forwarders);
                self.id.set(Some(id));
                *self.shown.borrow_mut() = Some(props.clone());
            }
            Phase::Patched => {
                let Some(id) = self.id.get() else { return };
                let same = self
                    .shown
                    .borrow()
                    .as_ref()
                    .is_some_and(|s| s.same_data(props));
                if !same {
                    bridge().update(id, &json(props));
                    *self.shown.borrow_mut() = Some(props.clone());
                }
            }
            Phase::Unmounting => {
                if let Some(id) = self.id.take() {
                    bridge().unmount(id);
                    self.shown.borrow_mut().take();
                }
            }
        }
    }
}

fn json<P: IslandProps>(props: &P) -> String {
    let mut d = Data::default();
    props.data(&mut d);
    serde_json::Value::Object(d.0).to_string()
}

/// The render of a `#[react]` component: an empty host the bridge renders into.
#[doc(hidden)]
pub fn render<P: IslandProps>(props: P) -> RenderFuture {
    let (inst, _, live) = crate::hooks::slot("island", || Live::<P> {
        id: Cell::new(None),
        shown: RefCell::new(None),
        events: RefCell::new(Vec::new()),
    });
    let mut events = Events {
        list: Vec::new(),
        owner: Rc::downgrade(&inst),
    };
    props.events(&mut events);
    live.retarget(events.list);
    let host = el("div")
        .attr("data-island", P::ISLAND.name)
        .attr("style", "display: contents")
        .lifecycle(move |phase, node| live.on(phase, node, &props));
    RenderFuture::ready(Ok(host.into_view()))
}

#[cfg(target_arch = "wasm32")]
mod web {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use wasm_bindgen::prelude::*;

    use super::{Bridge, EventFn, Island};
    use crate::dom::NodeRef;

    #[wasm_bindgen(module = "doxa-react:runtime")]
    extern "C" {
        #[wasm_bindgen(js_name = mount)]
        fn js_mount(
            host: &web_sys::Node,
            component: &JsValue,
            props: &str,
            events: &js_sys::Object,
        ) -> u32;
        #[wasm_bindgen(js_name = update)]
        fn js_update(id: u32, props: &str);
        #[wasm_bindgen(js_name = unmount)]
        fn js_unmount(id: u32);
    }

    type Handlers = Vec<Closure<dyn Fn(String)>>;

    /// Islands rendered by the shipped runtime, keeping each one's handlers alive.
    #[derive(Default)]
    pub(super) struct WebBridge(RefCell<HashMap<u32, Handlers>>);

    impl Bridge for WebBridge {
        fn mount(
            &self,
            host: NodeRef,
            island: &Island,
            props: &str,
            events: Vec<(&'static str, EventFn)>,
        ) -> u32 {
            let host = host.raw().expect("an island's host is in the document");
            let obj = js_sys::Object::new();
            let handlers: Handlers = events
                .into_iter()
                .map(|(name, f)| {
                    let c = Closure::<dyn Fn(String)>::new(move |json: String| f(&json));
                    let _ = js_sys::Reflect::set(&obj, &JsValue::from_str(name), c.as_ref());
                    c
                })
                .collect();
            let id = js_mount(&host, &(island.load)(), props, &obj);
            self.0.borrow_mut().insert(id, handlers);
            id
        }

        fn update(&self, id: u32, props: &str) {
            js_update(id, props);
        }

        fn unmount(&self, id: u32) {
            js_unmount(id);
            self.0.borrow_mut().remove(&id);
        }
    }
}
