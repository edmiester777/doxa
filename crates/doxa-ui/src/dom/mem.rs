//! A document in memory, for rendering and driving components in native tests.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use super::{
    Dom, Event, EventInner, Global, Listen, MemEvent, NodeId, Observe, Observed, Prop, Rect, Scroll,
};

enum Kind {
    Element {
        tag: String,
        attrs: Vec<(String, String)>,
        props: Vec<(String, Prop)>,
    },
    Text(String),
    Anchor,
    Html(String),
}

type Listener = Rc<dyn Fn(Event)>;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) enum Peek {
    Element(String),
    Text(String),
    Other,
}

struct MemNode {
    kind: Kind,
    parent: Option<NodeId>,
    children: Vec<NodeId>,
    listeners: Vec<(String, Listen, Listener)>,
}

enum Watch {
    Global(Global, String, Listen, Listener),
    Observer(NodeId, Observe, Rc<dyn Fn(Observed)>),
    Media(String, Rc<dyn Fn(bool)>),
}

#[derive(Default)]
struct World {
    next: u32,
    watches: HashMap<u32, Watch>,
    media: HashMap<String, bool>,
    storage: HashMap<String, String>,
    /// What `confirm` answers; `None` answers yes.
    answer: Option<bool>,
    asked: Vec<String>,
    title: String,
    scrolls: HashMap<NodeId, Scroll>,
    revealed: Vec<NodeId>,
}

/// Whether one compound selector (`div.a#b[c="d"]`) matches an element.
fn compound_matches(compound: &str, tag: &str, attrs: &[(String, String)]) -> bool {
    let attr = |name: &str| {
        attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    let mut rest = compound;
    let name_end = rest.find(['.', '#', '[']).unwrap_or(rest.len());
    if !matches!(&rest[..name_end], "" | "*") && !rest[..name_end].eq_ignore_ascii_case(tag) {
        return false;
    }
    rest = &rest[name_end..];
    while !rest.is_empty() {
        if let Some(body) = rest.strip_prefix('[') {
            let Some(end) = body.find(']') else {
                return false;
            };
            let holds = match body[..end].split_once('=') {
                Some((k, v)) => attr(k) == Some(v.trim_matches(['"', '\''])),
                None => attr(&body[..end]).is_some(),
            };
            if !holds {
                return false;
            }
            rest = &body[end + 1..];
        } else {
            let (is_class, body) = (rest.starts_with('.'), &rest[1..]);
            let end = body.find(['.', '#', '[']).unwrap_or(body.len());
            let holds = if is_class {
                attr("class").is_some_and(|c| c.split_whitespace().any(|c| c == &body[..end]))
            } else {
                attr("id") == Some(&body[..end])
            };
            if !holds {
                return false;
            }
            rest = &body[end..];
        }
    }
    true
}

/// Whether a selector matches `node`, with commas and descendant combinators, the subset tests use.
fn selector_matches(nodes: &HashMap<NodeId, MemNode>, node: NodeId, selector: &str) -> bool {
    let element = |id: NodeId| match &nodes.get(&id)?.kind {
        Kind::Element { tag, attrs, .. } => Some((tag.as_str(), attrs.as_slice())),
        _ => None,
    };
    selector.split(',').any(|alternative| {
        let mut parts = alternative.split_whitespace().rev();
        let Some(last) = parts.next() else {
            return false;
        };
        let Some((tag, attrs)) = element(node) else {
            return false;
        };
        if !compound_matches(last, tag, attrs) {
            return false;
        }
        let mut at = nodes.get(&node).and_then(|n| n.parent);
        parts.all(|part| loop {
            let Some(id) = at else { return false };
            at = nodes.get(&id).and_then(|n| n.parent);
            if element(id).is_some_and(|(tag, attrs)| compound_matches(part, tag, attrs)) {
                return true;
            }
        })
    })
}

fn collect_matching(
    nodes: &HashMap<NodeId, MemNode>,
    at: NodeId,
    selector: &str,
    out: &mut Vec<NodeId>,
) {
    let Some(node) = nodes.get(&at) else { return };
    for child in &node.children {
        if selector_matches(nodes, *child, selector) {
            out.push(*child);
        }
        collect_matching(nodes, *child, selector, out);
    }
}

/// An in-memory [`Dom`]. Clone it to keep a handle after mounting.
#[derive(Clone, Default)]
pub struct MemDom {
    nodes: Rc<RefCell<HashMap<NodeId, MemNode>>>,
    next: Rc<RefCell<NodeId>>,
    world: Rc<RefCell<World>>,
    ops: Rc<Cell<usize>>,
    focused: Rc<Cell<Option<NodeId>>>,
}

impl MemDom {
    /// An empty document with a `<body>` root, on a manual clock (see [`MemDom::advance`]).
    pub fn new() -> Self {
        let dom = Self::default();
        let body = dom.create_element("body", None);
        debug_assert_eq!(body, 0);
        doxa_client::clock::manual();
        dom
    }

    /// How many changes the renderer has made to the document: nodes created, inserted or
    /// removed, and text, attributes and properties set.
    pub fn ops(&self) -> usize {
        self.ops.get()
    }

    /// Move this thread's clock forward, firing each timer due on the way.
    pub fn advance(&self, d: std::time::Duration) {
        doxa_client::clock::manual().advance(d);
    }

    /// Fire `event` at the window, as `window_event` hears it.
    pub fn dispatch_window(&self, event: &str, detail: MemEvent) -> bool {
        self.dispatch_global(Global::Window, event, detail)
    }

    /// Fire `event` at the document, as `document_event` hears it.
    pub fn dispatch_document(&self, event: &str, detail: MemEvent) -> bool {
        self.dispatch_global(Global::Document, event, detail)
    }

    fn dispatch_global(&self, target: Global, event: &str, detail: MemEvent) -> bool {
        let hit: Vec<(u32, Listen, Listener)> = self
            .world
            .borrow()
            .watches
            .iter()
            .filter_map(|(id, w)| match w {
                Watch::Global(t, e, o, h) if *t == target && e == event => {
                    Some((*id, *o, h.clone()))
                }
                _ => None,
            })
            .collect();
        let prevented = Rc::new(Cell::new(false));
        for (id, opts, h) in hit {
            if opts.once {
                self.stop(id);
            }
            h(Event {
                inner: EventInner::Mem(detail.clone(), prevented.clone()),
            });
        }
        !prevented.get()
    }

    /// Report a new box for `node` to its resize observers.
    pub fn resize(&self, node: NodeId, rect: Rect) {
        self.notify(
            node,
            Observe::Resize,
            Observed {
                rect,
                intersecting: false,
            },
        );
    }

    /// Report `node` entering or leaving the viewport to its intersection observers.
    pub fn intersect(&self, node: NodeId, intersecting: bool) {
        self.notify(
            node,
            Observe::Intersection,
            Observed {
                rect: Rect::default(),
                intersecting,
            },
        );
    }

    fn notify(&self, node: NodeId, what: Observe, seen: Observed) {
        let hit: Vec<_> = self
            .world
            .borrow()
            .watches
            .values()
            .filter_map(|w| match w {
                Watch::Observer(n, k, f) if *n == node && *k == what => Some(f.clone()),
                _ => None,
            })
            .collect();
        hit.iter().for_each(|f| f(seen));
    }

    /// Make `query` match or not, telling its watchers.
    pub fn set_media(&self, query: &str, matches: bool) {
        self.world
            .borrow_mut()
            .media
            .insert(query.to_owned(), matches);
        let hit: Vec<_> = self
            .world
            .borrow()
            .watches
            .values()
            .filter_map(|w| match w {
                Watch::Media(q, f) if q == query => Some(f.clone()),
                _ => None,
            })
            .collect();
        hit.iter().for_each(|f| f(matches));
    }

    /// A `localStorage` value.
    pub fn storage(&self, key: &str) -> Option<String> {
        self.storage_get(key)
    }

    /// Answer every later `confirm` with `yes`.
    pub fn answer_confirm(&self, yes: bool) {
        self.world.borrow_mut().answer = Some(yes);
    }

    /// The messages `confirm` was asked since the last call, oldest first.
    pub fn confirms(&self) -> Vec<String> {
        std::mem::take(&mut self.world.borrow_mut().asked)
    }

    /// The document's title.
    pub fn document_title(&self) -> String {
        self.title()
    }

    /// Change a `localStorage` value as another tab would, firing `storage` at the window.
    pub fn store_elsewhere(&self, key: &str, value: Option<&str>) {
        self.storage_set(key, value);
        self.dispatch_window(
            "storage",
            MemEvent {
                key: key.to_owned(),
                ..MemEvent::default()
            },
        );
    }

    /// The last thing `clipboard::write` wrote on this thread.
    pub fn clipboard(&self) -> Option<crate::browser::clipboard::Clip> {
        crate::browser::mem::clipboard()
    }

    /// Every `Download` passed to `save` on this thread, oldest first, draining them.
    pub fn downloads(&self) -> Vec<doxa_client::Download> {
        crate::browser::mem::downloads()
    }

    /// Let every node a directive holds in the document finish leaving now.
    pub fn finish_leaving(&self) {
        crate::reconcile::finish_leaving();
    }

    /// The `<body>` element.
    pub fn body(&self) -> NodeId {
        0
    }

    /// Lay `node` out so that it reports `scroll`.
    pub fn set_scroll(&self, node: NodeId, scroll: Scroll) {
        self.world.borrow_mut().scrolls.insert(node, scroll);
    }

    /// The nodes [`Dom::reveal`] has shown, oldest first.
    pub fn revealed(&self) -> Vec<NodeId> {
        self.world.borrow().revealed.clone()
    }

    fn add(&self, kind: Kind) -> NodeId {
        let mut next = self.next.borrow_mut();
        let id = *next;
        *next += 1;
        self.nodes.borrow_mut().insert(
            id,
            MemNode {
                kind,
                parent: None,
                children: Vec::new(),
                listeners: Vec::new(),
            },
        );
        id
    }

    /// The document as HTML, without comments.
    pub fn html(&self, node: NodeId) -> String {
        let nodes = self.nodes.borrow();
        let mut out = String::new();
        render(&nodes, node, &mut out, true);
        out
    }

    /// The HTML inside `node`.
    pub fn inner_html(&self, node: NodeId) -> String {
        let nodes = self.nodes.borrow();
        let mut out = String::new();
        if let Some(n) = nodes.get(&node) {
            for c in &n.children {
                render(&nodes, *c, &mut out, true);
            }
        }
        out
    }

    /// The text inside `node`.
    pub fn text(&self, node: NodeId) -> String {
        let nodes = self.nodes.borrow();
        let mut out = String::new();
        text(&nodes, node, &mut out);
        out
    }

    /// The first element, in document order, whose attribute `name` equals `value`.
    pub fn find(&self, name: &str, value: &str) -> Option<NodeId> {
        let nodes = self.nodes.borrow();
        find(&nodes, 0, &|n| match &n.kind {
            Kind::Element { attrs, .. } => attrs.iter().any(|(k, v)| k == name && v == value),
            _ => false,
        })
    }

    /// The first element, in document order, with tag `tag`.
    pub fn find_tag(&self, tag: &str) -> Option<NodeId> {
        let nodes = self.nodes.borrow();
        find(
            &nodes,
            0,
            &|n| matches!(&n.kind, Kind::Element { tag: t, .. } if t == tag),
        )
    }

    /// An element's attribute.
    pub fn attr(&self, node: NodeId, name: &str) -> Option<String> {
        let nodes = self.nodes.borrow();
        match &nodes.get(&node)?.kind {
            Kind::Element { attrs, .. } => attrs
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone()),
            _ => None,
        }
    }

    /// The value of a DOM property set with `prop:` or `bind:`.
    pub fn prop(&self, node: NodeId, name: &str) -> Option<Prop> {
        let nodes = self.nodes.borrow();
        match &nodes.get(&node)?.kind {
            Kind::Element { props, .. } => props
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone()),
            _ => None,
        }
    }

    /// Fire `event` at `node`, as a user would. Like the browser's
    /// `dispatchEvent`, false if a handler called `prevent_default`.
    pub fn dispatch(&self, node: NodeId, event: &str, mut detail: MemEvent) -> bool {
        detail.target.get_or_insert(node);
        let handlers: Vec<_> = self
            .nodes
            .borrow_mut()
            .get_mut(&node)
            .map(|n| {
                let hit = n
                    .listeners
                    .iter()
                    .filter(|(e, ..)| e == event)
                    .map(|(.., h)| h.clone())
                    .collect();
                n.listeners.retain(|(e, o, _)| !(o.once && e == event));
                hit
            })
            .unwrap_or_default();
        let prevented = Rc::new(Cell::new(false));
        for h in handlers {
            h(Event {
                inner: EventInner::Mem(detail.clone(), prevented.clone()),
            });
        }
        !prevented.get()
    }

    /// Give `node` focus, with no events. Removing it or an ancestor then fires its `blur`.
    pub fn focus(&self, node: NodeId) {
        self.focused.set(Some(node));
    }

    /// The focused node, if it is `node` or inside it.
    fn focus_within(&self, node: NodeId) -> Option<NodeId> {
        let focused = self.focused.get()?;
        let nodes = self.nodes.borrow();
        let mut at = Some(focused);
        while let Some(n) = at {
            if n == node {
                return Some(focused);
            }
            at = nodes.get(&n)?.parent;
        }
        None
    }

    /// Click `node` with the primary button; false if the default was prevented.
    pub fn click(&self, node: NodeId) -> bool {
        self.dispatch(node, "click", MemEvent::default())
    }

    /// Type `value` into `node`, firing `input`.
    pub fn input(&self, node: NodeId, value: &str) -> bool {
        self.dispatch(
            node,
            "input",
            MemEvent {
                value: value.to_owned(),
                ..MemEvent::default()
            },
        )
    }

    /// What `node` is, for `testing::Screen`'s queries.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn peek(&self, node: NodeId) -> Peek {
        match self.nodes.borrow().get(&node).map(|n| &n.kind) {
            Some(Kind::Element { tag, .. }) => Peek::Element(tag.clone()),
            Some(Kind::Text(t)) => Peek::Text(t.clone()),
            _ => Peek::Other,
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn children(&self, node: NodeId) -> Vec<NodeId> {
        self.nodes
            .borrow()
            .get(&node)
            .map(|n| n.children.clone())
            .unwrap_or_default()
    }

    fn watch(&self, w: Watch) -> u32 {
        let mut world = self.world.borrow_mut();
        world.next += 1;
        let id = world.next;
        world.watches.insert(id, w);
        id
    }

    fn detach(&self, node: NodeId) {
        let mut nodes = self.nodes.borrow_mut();
        let parent = nodes.get_mut(&node).and_then(|n| n.parent.take());
        if let Some(p) = parent.and_then(|p| nodes.get_mut(&p)) {
            p.children.retain(|c| *c != node);
        }
    }
}

fn find(
    nodes: &HashMap<NodeId, MemNode>,
    at: NodeId,
    pred: &dyn Fn(&MemNode) -> bool,
) -> Option<NodeId> {
    let n = nodes.get(&at)?;
    if pred(n) {
        return Some(at);
    }
    n.children.iter().find_map(|c| find(nodes, *c, pred))
}

fn text(nodes: &HashMap<NodeId, MemNode>, at: NodeId, out: &mut String) {
    let Some(n) = nodes.get(&at) else { return };
    match &n.kind {
        Kind::Text(t) => out.push_str(t),
        _ => n.children.iter().for_each(|c| text(nodes, *c, out)),
    }
}

fn render(nodes: &HashMap<NodeId, MemNode>, at: NodeId, out: &mut String, _top: bool) {
    let Some(n) = nodes.get(&at) else { return };
    match &n.kind {
        Kind::Text(t) => out.push_str(t),
        Kind::Anchor => {}
        Kind::Html(h) => out.push_str(h),
        Kind::Element { tag, attrs, .. } => {
            out.push('<');
            out.push_str(tag);
            for (k, v) in attrs {
                out.push_str(&format!(" {k}=\"{v}\""));
            }
            out.push('>');
            for c in &n.children {
                render(nodes, *c, out, false);
            }
            out.push_str(&format!("</{tag}>"));
        }
    }
}

impl Dom for MemDom {
    fn create_element(&self, tag: &str, _ns: Option<&str>) -> NodeId {
        self.ops.set(self.ops.get() + 1);
        self.add(Kind::Element {
            tag: tag.to_owned(),
            attrs: Vec::new(),
            props: Vec::new(),
        })
    }

    fn create_text(&self, text: &str) -> NodeId {
        self.ops.set(self.ops.get() + 1);
        self.add(Kind::Text(text.to_owned()))
    }

    fn create_anchor(&self) -> NodeId {
        self.ops.set(self.ops.get() + 1);
        self.add(Kind::Anchor)
    }

    fn set_text(&self, node: NodeId, text: &str) {
        self.ops.set(self.ops.get() + 1);
        if let Some(n) = self.nodes.borrow_mut().get_mut(&node) {
            n.kind = Kind::Text(text.to_owned());
        }
    }

    fn set_attr(&self, node: NodeId, name: &str, value: &str) {
        self.ops.set(self.ops.get() + 1);
        if let Some(Kind::Element { attrs, .. }) =
            self.nodes.borrow_mut().get_mut(&node).map(|n| &mut n.kind)
        {
            match attrs.iter_mut().find(|(k, _)| k == name) {
                Some(a) => a.1 = value.to_owned(),
                None => attrs.push((name.to_owned(), value.to_owned())),
            }
        }
    }

    fn remove_attr(&self, node: NodeId, name: &str) {
        self.ops.set(self.ops.get() + 1);
        if let Some(Kind::Element { attrs, .. }) =
            self.nodes.borrow_mut().get_mut(&node).map(|n| &mut n.kind)
        {
            attrs.retain(|(k, _)| k != name);
        }
    }

    fn toggle_class(&self, node: NodeId, class: &str, on: bool) {
        let old = self.attr(node, "class").unwrap_or_default();
        let mut list: Vec<&str> = old.split_whitespace().filter(|c| *c != class).collect();
        if on {
            list.push(class);
        }
        if list.is_empty() {
            self.remove_attr(node, "class");
        } else {
            self.set_attr(node, "class", &list.join(" "));
        }
    }

    fn set_style(&self, node: NodeId, name: &str, value: Option<&str>) {
        let old = self.attr(node, "style").unwrap_or_default();
        let mut decls: Vec<(String, String)> = old
            .split(';')
            .filter_map(|d| d.split_once(':'))
            .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
            .filter(|(k, _)| k != name)
            .collect();
        if let Some(v) = value {
            decls.push((name.to_owned(), v.to_owned()));
        }
        let style = decls
            .iter()
            .map(|(k, v)| format!("{k}: {v};"))
            .collect::<Vec<_>>()
            .join(" ");
        if style.is_empty() {
            self.remove_attr(node, "style");
        } else {
            self.set_attr(node, "style", &style);
        }
    }

    fn set_prop(&self, node: NodeId, name: &str, value: &Prop) {
        self.ops.set(self.ops.get() + 1);
        if let Some(Kind::Element { props, .. }) =
            self.nodes.borrow_mut().get_mut(&node).map(|n| &mut n.kind)
        {
            match props.iter_mut().find(|(k, _)| k == name) {
                Some(p) => p.1 = value.clone(),
                None => props.push((name.to_owned(), value.clone())),
            }
        }
    }

    fn set_inner_html(&self, node: NodeId, html: &str) {
        self.ops.set(self.ops.get() + 1);
        let old: Vec<NodeId> = self
            .nodes
            .borrow()
            .get(&node)
            .map(|n| n.children.clone())
            .unwrap_or_default();
        for c in old {
            self.remove(c);
        }
        let child = self.add(Kind::Html(html.to_owned()));
        self.insert(node, child, None);
    }

    fn insert(&self, parent: NodeId, child: NodeId, before: Option<NodeId>) {
        self.ops.set(self.ops.get() + 1);
        self.detach(child);
        let mut nodes = self.nodes.borrow_mut();
        if let Some(c) = nodes.get_mut(&child) {
            c.parent = Some(parent);
        }
        if let Some(p) = nodes.get_mut(&parent) {
            let at = before
                .and_then(|b| p.children.iter().position(|c| *c == b))
                .unwrap_or(p.children.len());
            p.children.insert(at, child);
        }
    }

    fn remove(&self, node: NodeId) {
        self.ops.set(self.ops.get() + 1);
        // A browser fires this synchronously, from inside `removeChild`.
        if let Some(focused) = self.focus_within(node) {
            self.focused.set(None);
            self.dispatch(focused, "blur", MemEvent::default());
        }
        self.detach(node);
        let mut stack = vec![node];
        let mut nodes = self.nodes.borrow_mut();
        while let Some(n) = stack.pop() {
            if let Some(gone) = nodes.remove(&n) {
                stack.extend(gone.children);
            }
        }
    }

    fn next_sibling(&self, node: NodeId) -> Option<NodeId> {
        let nodes = self.nodes.borrow();
        let parent = nodes.get(&node)?.parent?;
        let siblings = &nodes.get(&parent)?.children;
        let at = siblings.iter().position(|c| *c == node)?;
        siblings.get(at + 1).copied()
    }

    fn parent(&self, node: NodeId) -> Option<NodeId> {
        self.nodes.borrow().get(&node)?.parent
    }

    fn listen(&self, node: NodeId, event: &str, opts: Listen, handler: Rc<dyn Fn(Event)>) {
        if let Some(n) = self.nodes.borrow_mut().get_mut(&node) {
            n.listeners.push((event.to_owned(), opts, handler));
        }
    }

    fn query(&self, selector: &str) -> Option<NodeId> {
        match selector {
            "body" => Some(0),
            s => s.strip_prefix('#').and_then(|id| self.find("id", id)),
        }
    }

    fn scroll(&self, node: NodeId) -> Scroll {
        self.world
            .borrow()
            .scrolls
            .get(&node)
            .copied()
            .unwrap_or_default()
    }

    fn scroll_to(&self, node: NodeId, top: f64, _smooth: bool) {
        self.world.borrow_mut().scrolls.entry(node).or_default().top = top;
    }

    fn reveal(&self, node: NodeId) {
        self.world.borrow_mut().revealed.push(node);
    }

    fn query_all(&self, root: Option<NodeId>, selector: &str) -> Vec<NodeId> {
        let nodes = self.nodes.borrow();
        let mut out = Vec::new();
        collect_matching(&nodes, root.unwrap_or(0), selector, &mut out);
        out
    }

    fn closest(&self, node: NodeId, selector: &str) -> Option<NodeId> {
        let nodes = self.nodes.borrow();
        std::iter::successors(Some(node), |n| nodes.get(n)?.parent)
            .find(|n| selector_matches(&nodes, *n, selector))
    }

    fn attribute(&self, node: NodeId, name: &str) -> Option<String> {
        self.attr(node, name)
    }

    fn editable(&self, node: NodeId) -> bool {
        let nodes = self.nodes.borrow();
        matches!(
            nodes.get(&node).map(|n| &n.kind),
            Some(Kind::Element { tag, attrs, .. })
                if matches!(tag.as_str(), "input" | "textarea" | "select")
                    || attrs.iter().any(|(k, v)| k == "contenteditable" && v != "false")
        )
    }

    fn listen_global(
        &self,
        target: Global,
        event: &str,
        opts: Listen,
        handler: Rc<dyn Fn(Event)>,
    ) -> u32 {
        self.watch(Watch::Global(target, event.to_owned(), opts, handler))
    }

    fn observe(&self, node: NodeId, what: Observe, f: Rc<dyn Fn(Observed)>) -> u32 {
        self.watch(Watch::Observer(node, what, f))
    }

    fn media_matches(&self, query: &str) -> bool {
        self.world
            .borrow()
            .media
            .get(query)
            .copied()
            .unwrap_or(false)
    }

    fn watch_media(&self, query: &str, f: Rc<dyn Fn(bool)>) -> u32 {
        self.watch(Watch::Media(query.to_owned(), f))
    }

    fn stop(&self, id: u32) {
        let gone = self.world.borrow_mut().watches.remove(&id);
        drop(gone);
    }

    fn storage_get(&self, key: &str) -> Option<String> {
        self.world.borrow().storage.get(key).cloned()
    }

    fn storage_set(&self, key: &str, value: Option<&str>) {
        let mut w = self.world.borrow_mut();
        match value {
            Some(v) => w.storage.insert(key.to_owned(), v.to_owned()),
            None => w.storage.remove(key),
        };
    }

    fn confirm(&self, message: &str) -> bool {
        let mut w = self.world.borrow_mut();
        w.asked.push(message.to_owned());
        w.answer.unwrap_or(true)
    }

    fn title(&self) -> String {
        self.world.borrow().title.clone()
    }

    fn set_title(&self, title: &str) {
        self.world.borrow_mut().title = title.to_owned();
    }
}
