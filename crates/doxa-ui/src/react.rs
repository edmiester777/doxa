//! React components in doxa views, declared with `#[react]`. Each island is a portal
//! inside the nearest island around it, or of one shared root, so React context flows
//! through doxa components; a small JS runtime that `doxa build` ships owns the root.

use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::component::RenderFuture;
use crate::dom::{NodeRef, Phase};
use crate::runtime::{self, Instance};
use crate::view::{el, Callback};
use crate::{IntoView, Thrown, View};

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
    /// A `children: View` prop, rendered by doxa into a host React adopts.
    fn children(&self) -> Option<View> {
        None
    }
}

/// An island's non-event props, by React prop name.
pub type Props = serde_json::Map<String, serde_json::Value>;

/// The non-event props, as a JSON object.
#[doc(hidden)]
#[derive(Default)]
pub struct Data(Props);

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

/// An island for the bridge to render.
pub struct Mount<'a> {
    /// Names it in `update` and `unmount`.
    pub id: u32,
    /// The nearest island around it in the doxa tree, whose React context it gets.
    pub parent: Option<u32>,
    /// The [root](crate::RootHandle::id) it is mounted under.
    pub root: u64,
    /// The element to render into.
    pub host: NodeRef,
    /// Its module and export.
    pub island: &'a Island,
    /// Its non-event props.
    pub props: &'a Props,
    /// Its event props.
    pub events: Vec<(&'static str, EventFn)>,
    /// doxa's render of its `View` children, for React to place as `children`.
    pub children: Option<NodeRef>,
    /// Call with a message when the island throws while React renders it.
    pub on_error: EventFn,
}

/// The JS side of islands. [`set_bridge`] swaps it, e.g. for a fake in native tests.
pub trait Bridge {
    /// Render an island; a child may mount before its parent.
    fn mount(&self, island: Mount<'_>);
    /// Give a mounted island new non-event props.
    fn update(&self, id: u32, props: &Props);
    /// Remove an island's portal.
    fn unmount(&self, id: u32);
}

/// Passed down the doxa tree so a nested island knows the island around it.
#[derive(Clone)]
struct Parent(u32);

fn next_id() -> u32 {
    thread_local!(static NEXT: Cell<u32> = const { Cell::new(0) });
    NEXT.with(|n| {
        n.set(n.get() + 1);
        n.get()
    })
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
        fn mount(&self, _: Mount<'_>) {}
        fn update(&self, _: u32, _: &Props) {}
        fn unmount(&self, _: u32) {}
    }
    Rc::new(Inert)
}

type Slot = Rc<RefCell<EventFn>>;

struct Live<P> {
    id: u32,
    parent: Option<u32>,
    root: u64,
    /// The island's instance, where a React error is thrown.
    owner: Weak<Instance>,
    mounted: Cell<bool>,
    children: Cell<Option<NodeRef>>,
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
                bridge().mount(Mount {
                    id: self.id,
                    parent: self.parent,
                    root: self.root,
                    host,
                    island: &P::ISLAND,
                    props: &data(props),
                    events: forwarders,
                    on_error: {
                        let (owner, name) = (self.owner.clone(), P::ISLAND.name);
                        Rc::new(move |message: &str| {
                            runtime::throw(
                                owner.upgrade().as_ref(),
                                Thrown::msg(format!("<{name}> threw in React: {message}")),
                            )
                        })
                    },
                    children: self.children.get(),
                });
                self.mounted.set(true);
                *self.shown.borrow_mut() = Some(props.clone());
            }
            Phase::Patched => {
                if !self.mounted.get() {
                    return;
                }
                let same = self
                    .shown
                    .borrow()
                    .as_ref()
                    .is_some_and(|s| s.same_data(props));
                if !same {
                    bridge().update(self.id, &data(props));
                    *self.shown.borrow_mut() = Some(props.clone());
                }
            }
            Phase::Unmounting => {
                if self.mounted.replace(false) {
                    bridge().unmount(self.id);
                    self.shown.borrow_mut().take();
                }
            }
        }
    }
}

fn data<P: IslandProps>(props: &P) -> Props {
    let mut d = Data::default();
    props.data(&mut d);
    d.0
}

/// The render of a `#[react]` component: an empty host the bridge renders into.
#[doc(hidden)]
pub fn render<P: IslandProps>(props: P) -> RenderFuture {
    let me = crate::runtime::current_or_panic("island");
    let (inst, _, live) = crate::hooks::slot("island", || Live::<P> {
        id: next_id(),
        parent: crate::hooks::try_context::<Parent>().map(|p| p.0),
        root: me.root_id(),
        owner: Rc::downgrade(&me),
        mounted: Cell::new(false),
        children: Cell::new(None),
        shown: RefCell::new(None),
        events: RefCell::new(Vec::new()),
    });
    crate::hooks::provide(Parent(live.id));
    let mut events = Events {
        list: Vec::new(),
        owner: Rc::downgrade(&inst),
    };
    props.events(&mut events);
    live.retarget(events.list);
    // The children host mounts before the island host, so its node is known by then.
    let children = props.children().map(|v| {
        let live = live.clone();
        el("div")
            .attr("data-island-children", true)
            .attr("style", "display: contents")
            .lifecycle(move |phase, node| {
                live.children
                    .set((phase != Phase::Unmounting).then_some(node))
            })
            .child(v)
    });
    let host = el("div")
        .attr("data-island", P::ISLAND.name)
        .attr("style", "display: contents")
        .child(children)
        .lifecycle(move |phase, node| live.on(phase, node, &props));
    RenderFuture::ready(Ok(host.into_view()))
}

#[cfg(target_arch = "wasm32")]
mod web {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use wasm_bindgen::prelude::*;

    use super::{Bridge, Mount, Props};
    use crate::dom::NodeRef;

    #[wasm_bindgen(module = "doxa-react:runtime")]
    extern "C" {
        #[wasm_bindgen(js_name = mount)]
        fn js_mount(
            id: u32,
            parent: Option<u32>,
            host: &web_sys::Node,
            component: &JsValue,
            props: &JsValue,
            events: &js_sys::Object,
            children: Option<web_sys::Node>,
            on_error: &JsValue,
        );
        #[wasm_bindgen(js_name = update)]
        fn js_update(id: u32, props: &JsValue);
        #[wasm_bindgen(js_name = unmount)]
        fn js_unmount(id: u32);
    }

    type Handlers = Vec<Closure<dyn Fn(String)>>;

    /// Plain objects, not ES `Map`s, so components read `props.name`.
    fn to_js(props: &Props) -> JsValue {
        use serde::Serialize;
        props
            .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
            .unwrap_or(JsValue::NULL)
    }

    /// Islands rendered by the shipped runtime, keeping each one's handlers alive.
    #[derive(Default)]
    pub(super) struct WebBridge(RefCell<HashMap<u32, Handlers>>);

    impl Bridge for WebBridge {
        fn mount(&self, m: Mount<'_>) {
            let host = m.host.raw().expect("an island's host is in the document");
            let children = m.children.and_then(NodeRef::raw);
            let obj = js_sys::Object::new();
            let mut handlers: Handlers = m
                .events
                .into_iter()
                .map(|(name, f)| {
                    let c = Closure::<dyn Fn(String)>::new(move |json: String| f(&json));
                    let _ = js_sys::Reflect::set(&obj, &JsValue::from_str(name), c.as_ref());
                    c
                })
                .collect();
            let on_error = m.on_error;
            let on_error = Closure::<dyn Fn(String)>::new(move |msg: String| on_error(&msg));
            let component = (m.island.load)();
            js_mount(
                m.id,
                m.parent,
                &host,
                &component,
                &to_js(m.props),
                &obj,
                children,
                on_error.as_ref(),
            );
            handlers.push(on_error);
            self.0.borrow_mut().insert(m.id, handlers);
        }

        fn update(&self, id: u32, props: &Props) {
            js_update(id, &to_js(props));
        }

        fn unmount(&self, id: u32) {
            js_unmount(id);
            self.0.borrow_mut().remove(&id);
        }
    }
}
