//! The document the renderer writes to: the browser's, or one in memory for tests.

mod mem;
#[cfg(target_arch = "wasm32")]
mod web;

use std::rc::Rc;

pub use mem::MemDom;
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
    fn listen(&self, node: NodeId, event: &str, handler: Rc<dyn Fn(Event)>);
    /// The element matching a CSS selector, for mounting.
    fn query(&self, selector: &str) -> Option<NodeId>;
    /// The browser node behind `node`.
    #[cfg(target_arch = "wasm32")]
    fn raw(&self, _node: NodeId) -> Option<web_sys::Node> {
        None
    }
}

/// An element the renderer placed, as [`Element::lifecycle`](crate::Element::lifecycle) sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeRef(pub(crate) NodeId);

impl NodeRef {
    /// Its id in the current [`Dom`].
    pub fn id(self) -> NodeId {
        self.0
    }

    /// The browser node.
    #[cfg(target_arch = "wasm32")]
    pub fn raw(self) -> Option<web_sys::Node> {
        crate::runtime::dom().raw(self.0)
    }
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
    Mem(MemEvent),
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
}

impl Event {
    /// The target input's value.
    pub fn value(&self) -> String {
        match &self.inner {
            #[cfg(target_arch = "wasm32")]
            EventInner::Web(e) => web::target_value(e),
            EventInner::Mem(e) => e.value.clone(),
        }
    }

    /// The target checkbox's state.
    pub fn checked(&self) -> bool {
        match &self.inner {
            #[cfg(target_arch = "wasm32")]
            EventInner::Web(e) => web::target_checked(e),
            EventInner::Mem(e) => e.checked,
        }
    }

    /// For keyboard events, which key.
    pub fn key(&self) -> String {
        match &self.inner {
            #[cfg(target_arch = "wasm32")]
            EventInner::Web(e) => web::key(e),
            EventInner::Mem(e) => e.key.clone(),
        }
    }

    /// Stop the browser's default action, e.g. a form submission.
    pub fn prevent_default(&self) {
        #[cfg(target_arch = "wasm32")]
        if let EventInner::Web(e) = &self.inner {
            e.prevent_default();
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
            EventInner::Mem(_) => None,
        }
    }
}
