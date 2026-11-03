//! The document the renderer writes to: the browser's, or one in memory for tests.

mod mem;
#[cfg(target_arch = "wasm32")]
mod web;

use std::cell::Cell;
use std::rc::Rc;

pub use mem::MemDom;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use mem::Peek;
#[cfg(target_arch = "wasm32")]
pub use web::WebDom;

/// A node in a [`Dom`].
pub type NodeId = u32;

/// A DOM property value set with `prop:name={…}`.
#[derive(Debug, Clone, PartialEq)]
pub enum Prop {
    /// A string.
    Str(String),
    /// A number.
    Num(f64),
    /// A boolean.
    Bool(bool),
    /// `undefined`.
    Unset,
}

/// What the renderer needs from a document.
pub trait Dom {
    /// A new element; `ns` is the namespace URI for SVG and MathML.
    fn create_element(&self, tag: &str, ns: Option<&str>) -> NodeId;
    /// A new text node.
    fn create_text(&self, text: &str) -> NodeId;
    /// A new comment node, used to mark where an empty view sits.
    fn create_anchor(&self) -> NodeId;
    /// Change a text node's text.
    fn set_text(&self, node: NodeId, text: &str);
    /// Set an attribute.
    fn set_attr(&self, node: NodeId, name: &str, value: &str);
    /// Remove an attribute.
    fn remove_attr(&self, node: NodeId, name: &str);
    /// Add or remove one class, leaving the others.
    fn toggle_class(&self, node: NodeId, class: &str, on: bool);
    /// Set one inline CSS property, or remove it with `None`.
    fn set_style(&self, node: NodeId, name: &str, value: Option<&str>);
    /// Set a DOM property.
    fn set_prop(&self, node: NodeId, name: &str, value: &Prop);
    /// Replace an element's children with parsed HTML.
    fn set_inner_html(&self, node: NodeId, html: &str);
    /// Insert `child` into `parent` before `before`, or at the end.
    fn insert(&self, parent: NodeId, child: NodeId, before: Option<NodeId>);
    /// Detach and forget `node` and everything under it.
    fn remove(&self, node: NodeId);
    /// The node after `node` under the same parent.
    fn next_sibling(&self, node: NodeId) -> Option<NodeId>;
    /// Call `handler` for every `event` on `node`.
    fn listen(&self, node: NodeId, event: &str, opts: Listen, handler: Rc<dyn Fn(Event)>);
    /// The element matching a CSS selector, for mounting.
    fn query(&self, selector: &str) -> Option<NodeId>;
    /// Call `handler` for every `event` on the window or document, until [`Dom::stop`].
    fn listen_global(
        &self,
        target: Global,
        event: &str,
        opts: Listen,
        handler: Rc<dyn Fn(Event)>,
    ) -> u32;
    /// Report `node`'s size or visibility to `f` as it changes, until [`Dom::stop`].
    fn observe(&self, node: NodeId, what: Observe, f: Rc<dyn Fn(Observed)>) -> u32;
    /// Whether a media query matches now.
    fn media_matches(&self, query: &str) -> bool;
    /// Call `f` whenever `query` starts or stops matching, until [`Dom::stop`].
    fn watch_media(&self, query: &str, f: Rc<dyn Fn(bool)>) -> u32;
    /// End a listener, observer or watch.
    fn stop(&self, id: u32);
    /// A `localStorage` value.
    fn storage_get(&self, key: &str) -> Option<String>;
    /// Set or, with `None`, remove a `localStorage` value.
    fn storage_set(&self, key: &str, value: Option<&str>);
    /// Ask the user to confirm `message`, as `window.confirm`.
    fn confirm(&self, message: &str) -> bool;
    /// The document's title.
    fn title(&self) -> String;
    /// Set the document's title.
    fn set_title(&self, title: &str);
    /// The browser node behind `node`.
    #[cfg(target_arch = "wasm32")]
    fn raw(&self, _node: NodeId) -> Option<web_sys::Node> {
        None
    }
    /// An id for a browser node something else created, e.g. React.
    #[cfg(target_arch = "wasm32")]
    fn adopt(&self, _node: web_sys::Node) -> Option<NodeId> {
        None
    }
}

/// An element the renderer placed, as [`Element::lifecycle`](crate::Element::lifecycle) sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeRef(pub(crate) NodeId);

impl NodeRef {
    /// The node `id` names in the current [`Dom`], e.g. one a test created.
    pub fn from_id(id: NodeId) -> NodeRef {
        NodeRef(id)
    }

    /// Its id in the current [`Dom`].
    pub fn id(self) -> NodeId {
        self.0
    }

    /// The browser node.
    #[cfg(target_arch = "wasm32")]
    pub fn raw(self) -> Option<web_sys::Node> {
        crate::runtime::dom().raw(self.0)
    }

    /// The browser node as `T`, e.g. `web_sys::HtmlInputElement`, if it is one.
    #[cfg(target_arch = "wasm32")]
    pub fn as_element<T: wasm_bindgen::JsCast>(self) -> Option<T> {
        wasm_bindgen::JsCast::dyn_into(self.raw()?).ok()
    }

    /// Give it keyboard focus.
    pub fn focus(self) {
        #[cfg(target_arch = "wasm32")]
        if let Some(el) = self.as_element::<web_sys::HtmlElement>() {
            let _ = el.focus();
        }
    }

    /// Take keyboard focus away from it.
    pub fn blur(self) {
        #[cfg(target_arch = "wasm32")]
        if let Some(el) = self.as_element::<web_sys::HtmlElement>() {
            let _ = el.blur();
        }
    }

    /// Scroll its nearest scrollable ancestors until it is visible.
    pub fn scroll_into_view(self) {
        #[cfg(target_arch = "wasm32")]
        if let Some(el) = self.as_element::<web_sys::Element>() {
            el.scroll_into_view();
        }
    }

    /// Where it is in the viewport, in CSS pixels; `None` without a browser layout.
    pub fn rect(self) -> Option<Rect> {
        #[cfg(target_arch = "wasm32")]
        {
            let r = self
                .as_element::<web_sys::Element>()?
                .get_bounding_client_rect();
            Some(Rect {
                x: r.x(),
                y: r.y(),
                width: r.width(),
                height: r.height(),
            })
        }
        #[cfg(not(target_arch = "wasm32"))]
        None
    }
}

/// How a listener is added: `on:scroll.passive`, `on:click.capture`, `on:keydown.once`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Listen {
    /// Run before handlers on the target's descendants.
    pub capture: bool,
    /// Promise never to call `prevent_default`, so scrolling needn't wait.
    pub passive: bool,
    /// Remove the listener after its first event.
    pub once: bool,
}

/// An event target outside the rendered tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Global {
    /// `window`.
    Window,
    /// `document`.
    Document,
}

/// What [`Dom::observe`] watches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observe {
    /// Size changes, as a `ResizeObserver`.
    Resize,
    /// Entering and leaving the viewport, as an `IntersectionObserver`.
    Intersection,
}

/// What an observer saw.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Observed {
    /// The element's box.
    pub rect: Rect,
    /// Whether any of it is in the viewport; only set for [`Observe::Intersection`].
    pub intersecting: bool,
}

/// An element's box in the viewport, in CSS pixels.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Rect {
    /// Left edge.
    pub x: f64,
    /// Top edge.
    pub y: f64,
    /// Width.
    pub width: f64,
    /// Height.
    pub height: f64,
}

/// Where an element is in its life, for [`Element::lifecycle`](crate::Element::lifecycle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Inserted, once the render that created it has committed.
    Mounted,
    /// Re-rendered in place, once that render has committed.
    Patched,
    /// About to be removed.
    Unmounting,
}

/// A DOM event, as a handler sees it.
pub struct Event {
    pub(crate) inner: EventInner,
}

pub(crate) enum EventInner {
    #[cfg(target_arch = "wasm32")]
    Web(web_sys::Event),
    Mem(MemEvent, Rc<Cell<bool>>),
}

/// An event dispatched into a [`MemDom`] by a test.
#[derive(Debug, Clone, Default)]
pub struct MemEvent {
    /// The target's `value`.
    pub value: String,
    /// The target's `checked`.
    pub checked: bool,
    /// For keyboard events, the key.
    pub key: String,
    /// For mouse events, the button: 0 is the primary one.
    pub button: i16,
    /// Whether Ctrl was held.
    pub ctrl_key: bool,
    /// Whether Meta (Cmd) was held.
    pub meta_key: bool,
    /// Whether Shift was held.
    pub shift_key: bool,
    /// Whether Alt was held.
    pub alt_key: bool,
    /// For mouse events, the pointer's viewport x.
    pub client_x: f64,
    /// For mouse events, the pointer's viewport y.
    pub client_y: f64,
    /// For wheel events, the vertical scroll amount.
    pub delta_y: f64,
    /// For keyboard and input events, whether an IME composition is in progress.
    pub is_composing: bool,
    /// The node the event was fired at; [`MemDom::dispatch`] fills it in.
    pub target: Option<NodeId>,
    /// For a `<select multiple>`, the chosen options' values.
    pub selected: Vec<String>,
}

impl Event {
    /// The target input's value.
    pub fn value(&self) -> String {
        match &self.inner {
            #[cfg(target_arch = "wasm32")]
            EventInner::Web(e) => web::target_value(e),
            EventInner::Mem(e, _) => e.value.clone(),
        }
    }

    /// The target checkbox's state.
    pub fn checked(&self) -> bool {
        match &self.inner {
            #[cfg(target_arch = "wasm32")]
            EventInner::Web(e) => web::target_checked(e),
            EventInner::Mem(e, _) => e.checked,
        }
    }

    /// For keyboard events, which key.
    pub fn key(&self) -> String {
        match &self.inner {
            #[cfg(target_arch = "wasm32")]
            EventInner::Web(e) => web::key(e),
            EventInner::Mem(e, _) => e.key.clone(),
        }
    }

    /// For mouse events, which button: 0 is the primary one.
    pub fn button(&self) -> i16 {
        match &self.inner {
            #[cfg(target_arch = "wasm32")]
            EventInner::Web(e) => web::button(e),
            EventInner::Mem(e, _) => e.button,
        }
    }

    /// Whether Ctrl was held.
    pub fn ctrl_key(&self) -> bool {
        self.modifier("ctrlKey", |e| e.ctrl_key)
    }

    /// Whether Meta (Cmd on macOS) was held.
    pub fn meta_key(&self) -> bool {
        self.modifier("metaKey", |e| e.meta_key)
    }

    /// Whether Shift was held.
    pub fn shift_key(&self) -> bool {
        self.modifier("shiftKey", |e| e.shift_key)
    }

    /// Whether Alt was held.
    pub fn alt_key(&self) -> bool {
        self.modifier("altKey", |e| e.alt_key)
    }

    /// For a `<select multiple>`, the chosen options' values.
    pub fn selected(&self) -> Vec<String> {
        match &self.inner {
            #[cfg(target_arch = "wasm32")]
            EventInner::Web(e) => web::selected(e),
            EventInner::Mem(e, _) => e.selected.clone(),
        }
    }

    /// Whether an IME composition is in progress, so Enter shouldn't submit.
    pub fn is_composing(&self) -> bool {
        self.modifier("isComposing", |e| e.is_composing)
    }

    /// For mouse events, the pointer's viewport x.
    pub fn client_x(&self) -> f64 {
        self.number("clientX", |e| e.client_x)
    }

    /// For mouse events, the pointer's viewport y.
    pub fn client_y(&self) -> f64 {
        self.number("clientY", |e| e.client_y)
    }

    /// For wheel events, the vertical scroll amount.
    pub fn delta_y(&self) -> f64 {
        self.number("deltaY", |e| e.delta_y)
    }

    /// The rendered node the event was fired at, if doxa placed it.
    pub fn target_ref(&self) -> Option<NodeRef> {
        match &self.inner {
            #[cfg(target_arch = "wasm32")]
            EventInner::Web(e) => web::target_id(e).map(NodeRef),
            EventInner::Mem(e, _) => e.target.map(NodeRef),
        }
    }

    /// The browser event as `T`, e.g. `web_sys::PointerEvent`, if it is one.
    #[cfg(target_arch = "wasm32")]
    pub fn as_<T: wasm_bindgen::JsCast + Clone>(&self) -> Option<T> {
        wasm_bindgen::JsCast::dyn_ref::<T>(self.raw()?).cloned()
    }

    #[cfg_attr(not(target_arch = "wasm32"), allow(unused_variables))]
    fn modifier(&self, name: &str, mem: fn(&MemEvent) -> bool) -> bool {
        match &self.inner {
            #[cfg(target_arch = "wasm32")]
            EventInner::Web(e) => web::flag(e, name),
            EventInner::Mem(e, _) => mem(e),
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), allow(unused_variables))]
    fn number(&self, name: &str, mem: fn(&MemEvent) -> f64) -> f64 {
        match &self.inner {
            #[cfg(target_arch = "wasm32")]
            EventInner::Web(e) => web::number(e, name),
            EventInner::Mem(e, _) => mem(e),
        }
    }

    /// Stop the browser's default action, e.g. a form submission.
    pub fn prevent_default(&self) {
        match &self.inner {
            #[cfg(target_arch = "wasm32")]
            EventInner::Web(e) => e.prevent_default(),
            EventInner::Mem(_, prevented) => prevented.set(true),
        }
    }

    /// Stop the event reaching ancestors.
    pub fn stop_propagation(&self) {
        #[cfg(target_arch = "wasm32")]
        if let EventInner::Web(e) = &self.inner {
            e.stop_propagation();
        }
    }

    /// The browser event.
    #[cfg(target_arch = "wasm32")]
    pub fn raw(&self) -> Option<&web_sys::Event> {
        match &self.inner {
            EventInner::Web(e) => Some(e),
            EventInner::Mem(..) => None,
        }
    }
}
