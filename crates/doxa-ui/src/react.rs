//! React components in doxa views, declared with `#[react]`. Each island is a portal
//! inside the nearest island around it, or of one shared root, so React context flows
//! through doxa components; a small JS runtime that `doxa build` ships owns the root.

use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::component::RenderFuture;
use crate::dom::{NodeRef, Phase};
use crate::portal::Portal;
use crate::runtime::{self, Instance};
use crate::view::{comp, el, Callback, Element, Handler, Node};
use crate::{Event, IntoView, Thrown, View};

/// Where a `#[react]` component's JS lives.
#[derive(Debug)]
pub struct Island {
    /// The Rust name, for diagnostics.
    pub name: &'static str,
    /// The module specifier: an npm package, or `doxa-island:<path>` under the web crate.
    pub module: &'static str,
    /// The export: a name, `default`, or a dotted path such as `Popover.Trigger`.
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
    /// Its `View` props: slots doxa renders, and elements React renders.
    fn views(&self, _out: &mut Views) {}
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

/// The `View` props.
#[doc(hidden)]
#[derive(Default)]
pub struct Views {
    slots: Vec<(&'static str, View)>,
    elements: Vec<(&'static str, View)>,
}

impl Views {
    /// doxa renders `view` into a host React places where the prop goes.
    pub fn slot(&mut self, name: &'static str, view: &View) {
        self.slots.push((name, view.clone()));
    }

    /// [`slot`](Self::slot), leaving the prop out when `None`.
    pub fn slot_opt(&mut self, name: &'static str, view: &Option<View>) {
        if let Some(v) = view {
            self.slot(name, v);
        }
    }

    /// React renders `view`'s element itself, and doxa its children inside it.
    pub fn element(&mut self, name: &'static str, view: &View) {
        self.elements.push((name, view.clone()));
    }
}

/// An element React renders for a `#[react(element)]` prop, from a doxa element's tag,
/// attributes and handlers; doxa renders its children into the node once React commits it.
#[derive(Clone)]
pub struct Shell {
    /// The React prop it is passed as.
    pub prop: &'static str,
    /// The tag.
    pub tag: &'static str,
    /// The attributes, with doxa names (`class`, not `className`).
    pub attrs: Vec<(&'static str, String)>,
    /// The handlers, by DOM event name; each is the same function on every render.
    pub events: Vec<(&'static str, ShellHandler)>,
    /// Call with the element React rendered, and with `None` when React removes it.
    pub node: NodeFn,
}

/// A shell's handler, called with the browser event.
pub type ShellHandler = Rc<dyn Fn(Event)>;

/// Told the element React rendered for a shell, or `None` once it's gone.
pub type NodeFn = Rc<dyn Fn(Option<NodeRef>)>;

impl Shell {
    fn same(&self, other: &Shell) -> bool {
        self.prop == other.prop
            && self.tag == other.tag
            && self.attrs == other.attrs
            && self
                .events
                .iter()
                .map(|e| e.0)
                .eq(other.events.iter().map(|e| e.0))
    }
}

/// What React renders for an island, on mount and on each update.
pub struct Content {
    /// The non-event props.
    pub props: Props,
    /// Hosts doxa renders each slot prop into, for React to place.
    pub slots: Vec<(&'static str, NodeRef)>,
    /// Elements for React to render.
    pub shells: Vec<Shell>,
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
    /// Its props.
    pub content: &'a Content,
    /// Its event props.
    pub events: Vec<(&'static str, EventFn)>,
    /// Call with a message when the island throws while React renders it.
    pub on_error: EventFn,
}

/// The JS side of islands. [`set_bridge`] swaps it, e.g. for a fake in native tests.
pub trait Bridge {
    /// Render an island; a child may mount before its parent.
    fn mount(&self, island: Mount<'_>);
    /// Give a mounted island new props.
    fn update(&self, id: u32, content: &Content);
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
        fn update(&self, _: u32, _: &Content) {}
        fn unmount(&self, _: u32) {}
    }
    Rc::new(Inert)
}

type Shared<T> = Rc<RefCell<T>>;
/// A shell handler's stable function and the cell it reads this render's handler from.
type ShellEvent = ((&'static str, &'static str), Shared<Handler>, Handler);

/// What React was last given, to skip updates that change nothing.
struct Sent<P> {
    props: P,
    slots: Vec<(&'static str, NodeRef)>,
    shells: Vec<Shell>,
}

struct Live<P> {
    id: u32,
    parent: Option<u32>,
    root: u64,
    /// The island's instance, where a React error is thrown.
    owner: Weak<Instance>,
    host: Cell<Option<NodeRef>>,
    events: RefCell<Vec<(&'static str, Shared<EventFn>)>>,
    shell_events: RefCell<Vec<ShellEvent>>,
    shell_nodes: RefCell<Vec<(&'static str, NodeFn)>>,
    slots: RefCell<Vec<(&'static str, NodeRef)>>,
    /// This render's props and shells.
    latest: RefCell<Option<(P, Vec<Shell>)>>,
    sent: RefCell<Option<Sent<P>>>,
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

    /// The stable function for a shell's handler, pointed at `h`.
    fn shell_handler(&self, key: (&'static str, &'static str), h: Handler) -> Handler {
        let mut all = self.shell_events.borrow_mut();
        if let Some((_, cell, f)) = all.iter().find(|(k, ..)| *k == key) {
            *cell.borrow_mut() = h;
            return f.clone();
        }
        let cell = Rc::new(RefCell::new(h));
        let c = cell.clone();
        let f: Handler = Rc::new(move |e| {
            let h = c.borrow().clone();
            h(e)
        });
        all.push((key, cell, f.clone()));
        f
    }

    fn shell_node(&self, prop: &'static str, make: impl FnOnce() -> NodeFn) -> NodeFn {
        let mut all = self.shell_nodes.borrow_mut();
        if let Some((_, f)) = all.iter().find(|(p, _)| *p == prop) {
            return f.clone();
        }
        let f = make();
        all.push((prop, f.clone()));
        f
    }

    fn content(&self) -> Option<(P, Content)> {
        let (props, shells) = self.latest.borrow().clone()?;
        let mut d = Data::default();
        props.data(&mut d);
        let content = Content {
            props: d.0,
            slots: self.slots.borrow().clone(),
            shells,
        };
        Some((props, content))
    }

    fn mount(&self, host: NodeRef) {
        let Some((props, content)) = self.content() else {
            return;
        };
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
        let (owner, name) = (self.owner.clone(), P::ISLAND.name);
        bridge().mount(Mount {
            id: self.id,
            parent: self.parent,
            root: self.root,
            host,
            island: &P::ISLAND,
            content: &content,
            events: forwarders,
            on_error: Rc::new(move |message: &str| {
                runtime::throw(
                    owner.upgrade().as_ref(),
                    Thrown::msg(format!("<{name}> threw in React: {message}")),
                )
            }),
        });
        self.host.set(Some(host));
        self.record(props, content);
    }

    fn record(&self, props: P, content: Content) {
        *self.sent.borrow_mut() = Some(Sent {
            props,
            slots: content.slots,
            shells: content.shells,
        });
    }

    /// Send React what changed since the last mount or update.
    fn resend(&self) {
        if self.host.get().is_none() {
            return;
        }
        let Some((props, content)) = self.content() else {
            return;
        };
        let same = self.sent.borrow().as_ref().is_some_and(|s| {
            s.props.same_data(&props)
                && s.slots == content.slots
                && s.shells.len() == content.shells.len()
                && s.shells.iter().zip(&content.shells).all(|(a, b)| a.same(b))
        });
        if !same {
            bridge().update(self.id, &content);
            self.record(props, content);
        }
    }

    fn on(&self, phase: Phase, host: NodeRef) {
        match phase {
            Phase::Mounted => self.mount(host),
            Phase::Patched => self.resend(),
            Phase::Unmounting => {
                if self.host.take().is_some() {
                    bridge().unmount(self.id);
                    self.sent.borrow_mut().take();
                }
            }
        }
    }

    fn on_slot(&self, name: &'static str, phase: Phase, node: NodeRef) {
        match phase {
            Phase::Mounted => self.slots.borrow_mut().push((name, node)),
            Phase::Unmounting => self.slots.borrow_mut().retain(|(n, _)| *n != name),
            Phase::Patched => return,
        }
        self.resend();
    }
}

/// `view` as one element, through any one-child fragments around it.
fn single_element(node: &Node) -> Option<Rc<Element>> {
    match node {
        Node::Element(e) => Some(e.clone()),
        Node::Fragment(f) if f.len() == 1 => single_element(&f[0]),
        _ => None,
    }
}

/// The render of a `#[react]` component: an empty host the bridge renders into.
#[doc(hidden)]
pub fn render<P: IslandProps>(props: P) -> RenderFuture {
    let me = crate::runtime::current_or_panic("island");
    let targets = crate::hooks::state(Vec::<(&'static str, NodeRef)>::new());
    let (inst, _, live) = crate::hooks::slot("island", || Live::<P> {
        id: next_id(),
        parent: crate::hooks::try_context::<Parent>().map(|p| p.0),
        root: me.root_id(),
        owner: Rc::downgrade(&me),
        host: Cell::new(None),
        events: RefCell::default(),
        shell_events: RefCell::default(),
        shell_nodes: RefCell::default(),
        slots: RefCell::default(),
        latest: RefCell::new(None),
        sent: RefCell::new(None),
    });
    crate::hooks::provide(Parent(live.id));
    let mut events = Events {
        list: Vec::new(),
        owner: Rc::downgrade(&inst),
    };
    props.events(&mut events);
    live.retarget(events.list);

    let mut views = Views::default();
    props.views(&mut views);
    let mut children: Vec<View> = Vec::new();
    // Slot hosts mount before the island host, so their nodes are known by then.
    for (name, view) in views.slots {
        let live = live.clone();
        // Keyed, so an optional slot appearing doesn't shift the hosts after it.
        let slot = el("div")
            .key(name)
            .attr("data-island-slot", name)
            .attr("style", "display: contents")
            .lifecycle(move |phase, node| live.on_slot(name, phase, node))
            .child(view);
        children.push(slot.into_view());
    }
    let mut shells = Vec::new();
    for (prop, view) in views.elements {
        let Some(e) = single_element(&view.0) else {
            return RenderFuture::ready(Err(Thrown::msg(format!(
                "<{}>: the `{prop}` element prop takes one element, e.g. `{{view! {{ <button/> }}}}`",
                P::ISLAND.name
            ))));
        };
        let node = live.shell_node(prop, || {
            Rc::new(move |n: Option<NodeRef>| {
                targets.update(|t| {
                    t.retain(|(p, _)| *p != prop);
                    t.extend(n.map(|n| (prop, n)));
                })
            })
        });
        shells.push(Shell {
            prop,
            tag: e.tag,
            attrs: e
                .attrs
                .iter()
                .filter_map(|(k, v)| Some((*k, v.clone()?)))
                .collect(),
            events: e
                .events
                .iter()
                .map(|(name, _, h)| (*name, live.shell_handler((prop, name), h.clone())))
                .collect(),
            node,
        });
        let at = targets.with(|t| t.iter().find(|(p, _)| *p == prop).map(|(_, n)| *n));
        if let Some(at) = at {
            let inner = View(Node::Fragment(e.children.clone().into()));
            let portal = Portal::props().to(at).children(inner).build();
            children.push(comp::<Portal>(portal).into_view());
        }
    }
    *live.latest.borrow_mut() = Some((props, shells));
    let host = el("div")
        .attr("data-island", P::ISLAND.name)
        .attr("style", "display: contents")
        .child(children.into_iter().collect::<View>())
        .lifecycle(move |phase, node| live.on(phase, node));
    RenderFuture::ready(Ok(host.into_view()))
}

/// A doxa event handed the browser event React's synthetic one wraps.
#[cfg(target_arch = "wasm32")]
fn web_event(e: web_sys::Event) -> Event {
    Event {
        inner: crate::dom::EventInner::Web(e),
    }
}

#[cfg(target_arch = "wasm32")]
mod web {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use wasm_bindgen::prelude::*;
    use wasm_bindgen::JsCast;

    use super::{Bridge, Content, Mount};
    use crate::dom::NodeRef;

    #[wasm_bindgen(module = "doxa-react:runtime")]
    extern "C" {
        #[wasm_bindgen(js_name = mount)]
        fn js_mount(
            id: u32,
            parent: Option<u32>,
            host: &web_sys::Node,
            component: &JsValue,
            content: &JsValue,
            events: &js_sys::Object,
            on_error: &JsValue,
        );
        #[wasm_bindgen(js_name = update)]
        fn js_update(id: u32, content: &JsValue);
        #[wasm_bindgen(js_name = unmount)]
        fn js_unmount(id: u32);
    }

    /// One island's JS functions, by key, so each is created once and React sees it unchanged.
    #[derive(Default)]
    struct Functions {
        events: Vec<Closure<dyn Fn(String)>>,
        shells: HashMap<String, JsValue>,
        keep: Vec<Box<dyn std::any::Any>>,
    }

    /// Islands rendered by the shipped runtime, keeping each one's functions alive.
    #[derive(Default)]
    pub(super) struct WebBridge(RefCell<HashMap<u32, Functions>>);

    fn set(obj: &JsValue, key: &str, value: &JsValue) {
        let _ = js_sys::Reflect::set(obj, &JsValue::from_str(key), value);
    }

    impl WebBridge {
        /// `{ props, slots: { name: node }, shells: [{ prop, tag, attrs, events, ref }] }`.
        fn to_js(&self, id: u32, c: &Content) -> JsValue {
            use serde::Serialize;
            let out: JsValue = js_sys::Object::new().into();
            let props = c
                .props
                .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
                .unwrap_or(JsValue::NULL);
            set(&out, "props", &props);
            let slots: JsValue = js_sys::Object::new().into();
            for (name, node) in &c.slots {
                if let Some(n) = node.raw() {
                    set(&slots, name, &n);
                }
            }
            set(&out, "slots", &slots);
            let mut all = self.0.borrow_mut();
            let f = all.entry(id).or_default();
            let shells = js_sys::Array::new();
            for s in &c.shells {
                let shell: JsValue = js_sys::Object::new().into();
                set(&shell, "prop", &s.prop.into());
                set(&shell, "tag", &s.tag.into());
                let attrs: JsValue = js_sys::Object::new().into();
                for (k, v) in &s.attrs {
                    set(&attrs, k, &v.as_str().into());
                }
                set(&shell, "attrs", &attrs);
                let events: JsValue = js_sys::Object::new().into();
                for (name, h) in &s.events {
                    let key = format!("{}:on:{name}", s.prop);
                    let js = f.shells.entry(key).or_insert_with(|| {
                        let h = h.clone();
                        let c = Closure::<dyn Fn(web_sys::Event)>::new(move |e: web_sys::Event| {
                            h(super::web_event(e))
                        });
                        let v = c.as_ref().clone();
                        f.keep.push(Box::new(c));
                        v
                    });
                    set(&events, name, js);
                }
                set(&shell, "events", &events);
                let key = format!("{}:ref", s.prop);
                let r = f.shells.entry(key).or_insert_with(|| {
                    let node = s.node.clone();
                    let c = Closure::<dyn Fn(JsValue)>::new(move |el: JsValue| {
                        let n = el.dyn_into::<web_sys::Node>().ok().and_then(|n| {
                            crate::runtime::try_dom()?.adopt(n).map(NodeRef::from_id)
                        });
                        node(n)
                    });
                    let v = c.as_ref().clone();
                    f.keep.push(Box::new(c));
                    v
                });
                set(&shell, "ref", r);
                shells.push(&shell);
            }
            set(&out, "shells", &shells);
            out
        }
    }

    impl Bridge for WebBridge {
        fn mount(&self, m: Mount<'_>) {
            let host = m.host.raw().expect("an island's host is in the document");
            let content = self.to_js(m.id, m.content);
            let obj = js_sys::Object::new();
            let mut events: Vec<_> = m
                .events
                .into_iter()
                .map(|(name, f)| {
                    let c = Closure::<dyn Fn(String)>::new(move |json: String| f(&json));
                    set(&obj, name, c.as_ref());
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
                &content,
                &obj,
                on_error.as_ref(),
            );
            events.push(on_error);
            self.0.borrow_mut().entry(m.id).or_default().events = events;
        }

        fn update(&self, id: u32, content: &Content) {
            js_update(id, &self.to_js(id, content));
        }

        fn unmount(&self, id: u32) {
            js_unmount(id);
            self.0.borrow_mut().remove(&id);
        }
    }
}
