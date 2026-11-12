//! The browser's document.

use std::cell::RefCell;
use std::rc::Rc;

use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};

use super::{
    Dom, Event, EventInner, Global, Listen, NodeId, Observe, Observed, Prop, Rect, Scroll,
};

type Stops = Rc<RefCell<(u32, std::collections::HashMap<u32, Box<dyn FnOnce()>>)>>;

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
    stops: Stops,
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
            stops: Rc::default(),
        }
    }

    /// Remember how to undo a registration; [`Dom::stop`] runs it.
    fn keep(&self, stop: impl FnOnce() + 'static) -> u32 {
        let mut s = self.stops.borrow_mut();
        s.0 += 1;
        let id = s.0;
        s.1.insert(id, Box::new(stop));
        id
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

    fn toggle_class(&self, node: NodeId, class: &str, on: bool) {
        if let Some(el) = self.element(node) {
            let _ = el.class_list().toggle_with_force(class, on);
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
        let key = JsValue::from_str(name);
        // Writing an unchanged `value` still clears what the input is showing, such as the dot of
        // a half-typed `1.` that a number input reports as `1`.
        if let Ok(current) = js_sys::Reflect::get(&n, &key) {
            if js_sys::Object::is(&current, &v) {
                return;
            }
        }
        let _ = js_sys::Reflect::set(&n, &key, &v);
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

    fn parent(&self, node: NodeId) -> Option<NodeId> {
        let parent = self.node(node)?.parent_node()?;
        Some(self.id_of(&parent).unwrap_or_else(|| self.add(parent)))
    }

    fn listen(&self, node: NodeId, event: &str, opts: Listen, handler: Rc<dyn Fn(Event)>) {
        let Some(n) = self.node(node) else { return };
        let closure = add_listener(&n, event, opts, handler);
        if let Some(Some(slot)) = self.nodes.borrow_mut().get_mut(node as usize) {
            slot.listeners.push(closure);
        }
    }

    fn query(&self, selector: &str) -> Option<NodeId> {
        let el: web_sys::Node = self.doc.query_selector(selector).ok()??.into();
        Some(self.id_of(&el).unwrap_or_else(|| self.add(el)))
    }

    fn listen_global(
        &self,
        target: Global,
        event: &str,
        opts: Listen,
        handler: Rc<dyn Fn(Event)>,
    ) -> u32 {
        let t: web_sys::EventTarget = match target {
            Global::Window => web_sys::window().expect("a window").into(),
            Global::Document => self.doc.clone().into(),
        };
        let closure = add_listener(&t, event, opts, handler);
        let event = event.to_owned();
        self.keep(move || {
            let _ = t.remove_event_listener_with_callback_and_bool(
                &event,
                closure.as_ref().unchecked_ref(),
                opts.capture,
            );
        })
    }

    fn observe(&self, node: NodeId, what: Observe, f: Rc<dyn Fn(Observed)>) -> u32 {
        let Some(el) = self.element(node) else {
            return self.keep(|| {});
        };
        let target = el.clone();
        let cb = Closure::<dyn Fn(js_sys::Array)>::new(move |entries: js_sys::Array| {
            let r = target.get_bounding_client_rect();
            let entry = entries.at(-1);
            let intersecting = js_sys::Reflect::get(&entry, &"isIntersecting".into())
                .ok()
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let (width, height) = layout_size(&entry).unwrap_or((r.width(), r.height()));
            f(Observed {
                rect: Rect {
                    x: r.x(),
                    y: r.y(),
                    width,
                    height,
                },
                intersecting,
            })
        });
        let func: &js_sys::Function = cb.as_ref().unchecked_ref();
        match what {
            Observe::Resize => {
                let Ok(o) = web_sys::ResizeObserver::new(func) else {
                    return self.keep(|| {});
                };
                o.observe(&el);
                self.keep(move || {
                    o.disconnect();
                    drop(cb);
                })
            }
            Observe::Intersection => {
                let Ok(o) = web_sys::IntersectionObserver::new(func) else {
                    return self.keep(|| {});
                };
                o.observe(&el);
                self.keep(move || {
                    o.disconnect();
                    drop(cb);
                })
            }
        }
    }

    fn media_matches(&self, query: &str) -> bool {
        media(query).is_some_and(|m| m.matches())
    }

    fn watch_media(&self, query: &str, f: Rc<dyn Fn(bool)>) -> u32 {
        let Some(list) = media(query) else {
            return self.keep(|| {});
        };
        let l = list.clone();
        let cb = Closure::<dyn Fn()>::new(move || f(l.matches()));
        let _ = list.add_event_listener_with_callback("change", cb.as_ref().unchecked_ref());
        self.keep(move || {
            let _ = list.remove_event_listener_with_callback("change", cb.as_ref().unchecked_ref());
        })
    }

    fn stop(&self, id: u32) {
        let stop = self.stops.borrow_mut().1.remove(&id);
        if let Some(stop) = stop {
            stop();
        }
    }

    fn confirm(&self, message: &str) -> bool {
        web_sys::window()
            .and_then(|w| w.confirm_with_message(message).ok())
            .unwrap_or(true)
    }

    fn title(&self) -> String {
        self.doc.title()
    }

    fn set_title(&self, title: &str) {
        self.doc.set_title(title);
    }

    fn storage_get(&self, key: &str) -> Option<String> {
        local_storage()?.get_item(key).ok()?
    }

    fn storage_set(&self, key: &str, value: Option<&str>) {
        let Some(s) = local_storage() else { return };
        let _ = match value {
            Some(v) => s.set_item(key, v),
            None => s.remove_item(key),
        };
    }

    fn scroll(&self, node: NodeId) -> Scroll {
        self.element(node)
            .map_or_else(Scroll::default, |el| Scroll {
                top: f64::from(el.scroll_top()),
                height: f64::from(el.scroll_height()),
                client_height: f64::from(el.client_height()),
            })
    }

    fn scroll_to(&self, node: NodeId, top: f64, smooth: bool) {
        if let Some(el) = self.element(node) {
            let options = web_sys::ScrollToOptions::new();
            options.set_top(top);
            options.set_behavior(if smooth {
                web_sys::ScrollBehavior::Smooth
            } else {
                web_sys::ScrollBehavior::Instant
            });
            el.scroll_to_with_scroll_to_options(&options);
        }
    }

    fn reveal(&self, node: NodeId) {
        if let Some(el) = self.element(node) {
            let options = web_sys::ScrollIntoViewOptions::new();
            options.set_block(web_sys::ScrollLogicalPosition::Nearest);
            el.scroll_into_view_with_scroll_into_view_options(&options);
        }
    }

    fn query_all(&self, root: Option<NodeId>, selector: &str) -> Vec<NodeId> {
        let found = match root {
            Some(root) => self
                .element(root)
                .and_then(|el| el.query_selector_all(selector).ok()),
            None => self.doc.query_selector_all(selector).ok(),
        };
        let Some(found) = found else {
            return Vec::new();
        };
        (0..found.length())
            .filter_map(|i| found.item(i))
            .filter_map(|node| self.adopt(node))
            .collect()
    }

    fn closest(&self, node: NodeId, selector: &str) -> Option<NodeId> {
        let found = self.element(node)?.closest(selector).ok()??;
        self.adopt(found.into())
    }

    fn attribute(&self, node: NodeId, name: &str) -> Option<String> {
        self.element(node)?.get_attribute(name)
    }

    fn editable(&self, node: NodeId) -> bool {
        self.node(node)
            .and_then(|n| n.dyn_into::<web_sys::HtmlElement>().ok())
            .is_some_and(|el| {
                el.is_content_editable()
                    || matches!(el.tag_name().as_str(), "INPUT" | "TEXTAREA" | "SELECT")
            })
    }

    fn raw(&self, node: NodeId) -> Option<web_sys::Node> {
        self.node(node)
    }

    fn adopt(&self, node: web_sys::Node) -> Option<NodeId> {
        Some(self.id_of(&node).unwrap_or_else(|| self.add(node)))
    }
}

fn add_listener(
    target: &web_sys::EventTarget,
    event: &str,
    opts: Listen,
    handler: Rc<dyn Fn(Event)>,
) -> Closure<dyn Fn(web_sys::Event)> {
    let closure = Closure::<dyn Fn(web_sys::Event)>::new(move |e: web_sys::Event| {
        handler(Event {
            inner: EventInner::Web(e),
        })
    });
    let o = web_sys::AddEventListenerOptions::new();
    o.set_capture(opts.capture);
    o.set_passive(opts.passive);
    o.set_once(opts.once);
    let _ = target.add_event_listener_with_callback_and_add_event_listener_options(
        event,
        closure.as_ref().unchecked_ref(),
        &o,
    );
    closure
}

/// The border box before any CSS transform; `None` for an entry that isn't a resize.
fn layout_size(entry: &JsValue) -> Option<(f64, f64)> {
    let sizes = js_sys::Reflect::get(entry, &"borderBoxSize".into()).ok()?;
    let first = js_sys::Reflect::get(&sizes, &0.into()).ok()?;
    let side = |name: &str| js_sys::Reflect::get(&first, &name.into()).ok()?.as_f64();
    Some((side("inlineSize")?, side("blockSize")?))
}

fn media(query: &str) -> Option<web_sys::MediaQueryList> {
    web_sys::window()?.match_media(query).ok()?
}

fn local_storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok()?
}

pub(crate) fn target_id(e: &web_sys::Event) -> Option<NodeId> {
    let t = e.target()?;
    Some(
        js_sys::Reflect::get(&t, &ID.with(JsValue::clone))
            .ok()?
            .as_f64()? as NodeId,
    )
}

/// A numeric event field such as `clientX`, zero where the event has none.
pub(crate) fn number(e: &web_sys::Event, name: &str) -> f64 {
    js_sys::Reflect::get(e, &JsValue::from_str(name))
        .ok()
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0)
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

pub(crate) fn selected(e: &web_sys::Event) -> Vec<String> {
    let Some(t) = e.target() else {
        return Vec::new();
    };
    let options = js_sys::Reflect::get(&t, &JsValue::from_str("selectedOptions"))
        .unwrap_or(JsValue::UNDEFINED);
    js_sys::Array::from(&options)
        .iter()
        .filter_map(|o| {
            js_sys::Reflect::get(&o, &JsValue::from_str("value"))
                .ok()?
                .as_string()
        })
        .collect()
}

pub(crate) fn target_checked(e: &web_sys::Event) -> bool {
    let Some(t) = e.target() else { return false };
    js_sys::Reflect::get(&t, &JsValue::from_str("checked"))
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

pub(crate) fn button(e: &web_sys::Event) -> i16 {
    e.dyn_ref::<web_sys::MouseEvent>()
        .map_or(0, web_sys::MouseEvent::button)
}

/// A boolean event field such as `ctrlKey`, false where the event has none.
pub(crate) fn flag(e: &web_sys::Event, name: &str) -> bool {
    js_sys::Reflect::get(e, &JsValue::from_str(name))
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// `key` of a keyboard or `storage` event.
pub(crate) fn key(e: &web_sys::Event) -> String {
    js_sys::Reflect::get(e, &JsValue::from_str("key"))
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default()
}
