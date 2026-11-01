//! The browser's document.

use std::cell::RefCell;
use std::rc::Rc;

use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};

use super::{Dom, Event, EventInner, NodeId, Prop};

thread_local! {
    static ID: JsValue = JsValue::from_str("__doxaNode");
}

struct Slot {
    node: web_sys::Node,
    listeners: Vec<Closure<dyn Fn(web_sys::Event)>>,
}

/// The browser [`Dom`], addressing nodes through a slab.
#[derive(Clone)]
pub struct WebDom {
    doc: web_sys::Document,
    nodes: Rc<RefCell<Vec<Option<Slot>>>>,
    free: Rc<RefCell<Vec<NodeId>>>,
}

impl Default for WebDom {
    fn default() -> Self {
        Self::new()
    }
}

impl WebDom {
    /// The current window's document.
    pub fn new() -> Self {
        let doc = web_sys::window()
            .and_then(|w| w.document())
            .expect("a browser document");
        Self {
            doc,
            nodes: Rc::default(),
            free: Rc::default(),
        }
    }

    fn add(&self, node: web_sys::Node) -> NodeId {
        let mut nodes = self.nodes.borrow_mut();
        let id = match self.free.borrow_mut().pop() {
            Some(id) => id,
            None => {
                nodes.push(None);
                (nodes.len() - 1) as NodeId
            }
        };
        let _ = js_sys::Reflect::set(&node, &ID.with(JsValue::clone), &JsValue::from(id));
        nodes[id as usize] = Some(Slot {
            node,
            listeners: Vec::new(),
        });
        id
    }

    fn node(&self, id: NodeId) -> Option<web_sys::Node> {
        self.nodes
            .borrow()
            .get(id as usize)?
            .as_ref()
            .map(|s| s.node.clone())
    }

    fn element(&self, id: NodeId) -> Option<web_sys::Element> {
        self.node(id)?.dyn_into().ok()
    }

    fn id_of(&self, node: &web_sys::Node) -> Option<NodeId> {
        let id = js_sys::Reflect::get(node, &ID.with(JsValue::clone))
            .ok()?
            .as_f64()? as NodeId;
        let nodes = self.nodes.borrow();
        let slot = nodes.get(id as usize)?.as_ref()?;
        (&slot.node == node).then_some(id)
    }

    fn forget(&self, node: &web_sys::Node) {
        if let Some(id) = self.id_of(node) {
            self.nodes.borrow_mut()[id as usize] = None;
            self.free.borrow_mut().push(id);
        }
        let children = node.child_nodes();
        for i in 0..children.length() {
            if let Some(c) = children.item(i) {
                self.forget(&c);
            }
        }
    }
}

impl Dom for WebDom {
    fn create_element(&self, tag: &str, ns: Option<&str>) -> NodeId {
        let el = match ns {
            Some(ns) => self.doc.create_element_ns(Some(ns), tag),
            None => self.doc.create_element(tag),
        }
        .expect("a valid tag name");
        self.add(el.into())
    }

    fn create_text(&self, text: &str) -> NodeId {
        self.add(self.doc.create_text_node(text).into())
    }

    fn create_anchor(&self) -> NodeId {
        self.add(self.doc.create_comment("").into())
    }

    fn set_text(&self, node: NodeId, text: &str) {
        if let Some(n) = self.node(node) {
            n.set_text_content(Some(text));
        }
    }

    fn set_attr(&self, node: NodeId, name: &str, value: &str) {
        if let Some(el) = self.element(node) {
            let _ = el.set_attribute(name, value);
        }
    }

    fn remove_attr(&self, node: NodeId, name: &str) {
        if let Some(el) = self.element(node) {
            let _ = el.remove_attribute(name);
        }
    }

    fn set_style(&self, node: NodeId, name: &str, value: Option<&str>) {
        let Some(el) = self
            .node(node)
            .and_then(|n| n.dyn_into::<web_sys::HtmlElement>().ok())
        else {
            return;
        };
        let style = el.style();
        let _ = match value {
            Some(v) => style.set_property(name, v),
            None => style.remove_property(name).map(drop),
        };
    }

    fn set_prop(&self, node: NodeId, name: &str, value: &Prop) {
        let Some(n) = self.node(node) else { return };
        let v = match value {
            Prop::Str(s) => JsValue::from_str(s),
            Prop::Num(x) => JsValue::from_f64(*x),
            Prop::Bool(b) => JsValue::from_bool(*b),
            Prop::Unset => JsValue::UNDEFINED,
        };
        let _ = js_sys::Reflect::set(&n, &JsValue::from_str(name), &v);
    }

    fn set_inner_html(&self, node: NodeId, html: &str) {
        if let Some(el) = self.element(node) {
            el.set_inner_html(html);
        }
    }

    fn insert(&self, parent: NodeId, child: NodeId, before: Option<NodeId>) {
        let (Some(p), Some(c)) = (self.node(parent), self.node(child)) else {
            return;
        };
        let b = before.and_then(|b| self.node(b));
        let _ = p.insert_before(&c, b.as_ref());
    }

    fn remove(&self, node: NodeId) {
        let Some(n) = self.node(node) else { return };
        if let Some(p) = n.parent_node() {
            let _ = p.remove_child(&n);
        }
        self.forget(&n);
    }

    fn next_sibling(&self, node: NodeId) -> Option<NodeId> {
        let next = self.node(node)?.next_sibling()?;
        self.id_of(&next)
    }

    fn listen(&self, node: NodeId, event: &str, handler: Rc<dyn Fn(Event)>) {
        let Some(n) = self.node(node) else { return };
        let closure = Closure::<dyn Fn(web_sys::Event)>::new(move |e: web_sys::Event| {
            handler(Event {
                inner: EventInner::Web(e),
            })
        });
        let _ = n.add_event_listener_with_callback(event, closure.as_ref().unchecked_ref());
        if let Some(Some(slot)) = self.nodes.borrow_mut().get_mut(node as usize) {
            slot.listeners.push(closure);
        }
    }

    fn query(&self, selector: &str) -> Option<NodeId> {
        let el = self.doc.query_selector(selector).ok()??;
        Some(self.add(el.into()))
    }

    fn raw(&self, node: NodeId) -> Option<web_sys::Node> {
        self.node(node)
    }
}

pub(crate) fn target_value(e: &web_sys::Event) -> String {
    let Some(t) = e.target() else {
        return String::new();
    };
    js_sys::Reflect::get(&t, &JsValue::from_str("value"))
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default()
}

pub(crate) fn target_checked(e: &web_sys::Event) -> bool {
    let Some(t) = e.target() else { return false };
    js_sys::Reflect::get(&t, &JsValue::from_str("checked"))
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

pub(crate) fn key(e: &web_sys::Event) -> String {
    e.dyn_ref::<web_sys::KeyboardEvent>()
        .map(|k| k.key())
        .unwrap_or_default()
}
