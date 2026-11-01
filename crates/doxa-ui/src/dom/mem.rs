//! A document in memory, for rendering and driving components in native tests.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use super::{Dom, Event, EventInner, MemEvent, NodeId, Prop};

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

struct MemNode {
    kind: Kind,
    parent: Option<NodeId>,
    children: Vec<NodeId>,
    listeners: Vec<(String, Listener)>,
}

/// An in-memory [`Dom`]. Clone it to keep a handle after mounting.
#[derive(Clone, Default)]
pub struct MemDom {
    nodes: Rc<RefCell<HashMap<NodeId, MemNode>>>,
    next: Rc<RefCell<NodeId>>,
}

impl MemDom {
    /// An empty document with a `<body>` root.
    pub fn new() -> Self {
        let dom = Self::default();
        let body = dom.create_element("body", None);
        debug_assert_eq!(body, 0);
        dom
    }

    /// The `<body>` element.
    pub fn body(&self) -> NodeId {
        0
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

    /// Fire `event` at `node`, as a user would.
    pub fn dispatch(&self, node: NodeId, event: &str, detail: MemEvent) {
        let handlers: Vec<_> = self
            .nodes
            .borrow()
            .get(&node)
            .map(|n| {
                n.listeners
                    .iter()
                    .filter(|(e, _)| e == event)
                    .map(|(_, h)| h.clone())
                    .collect()
            })
            .unwrap_or_default();
        for h in handlers {
            h(Event {
                inner: EventInner::Mem(detail.clone()),
            });
        }
    }

    /// Click `node`.
    pub fn click(&self, node: NodeId) {
        self.dispatch(node, "click", MemEvent::default());
    }

    /// Type `value` into `node`, firing `input`.
    pub fn input(&self, node: NodeId, value: &str) {
        self.dispatch(
            node,
            "input",
            MemEvent {
                value: value.to_owned(),
                ..MemEvent::default()
            },
        );
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
        self.add(Kind::Element {
            tag: tag.to_owned(),
            attrs: Vec::new(),
            props: Vec::new(),
        })
    }

    fn create_text(&self, text: &str) -> NodeId {
        self.add(Kind::Text(text.to_owned()))
    }

    fn create_anchor(&self) -> NodeId {
        self.add(Kind::Anchor)
    }

    fn set_text(&self, node: NodeId, text: &str) {
        if let Some(n) = self.nodes.borrow_mut().get_mut(&node) {
            n.kind = Kind::Text(text.to_owned());
        }
    }

    fn set_attr(&self, node: NodeId, name: &str, value: &str) {
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
        if let Some(Kind::Element { attrs, .. }) =
            self.nodes.borrow_mut().get_mut(&node).map(|n| &mut n.kind)
        {
            attrs.retain(|(k, _)| k != name);
        }
    }

    fn set_prop(&self, node: NodeId, name: &str, value: &Prop) {
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

    fn listen(&self, node: NodeId, event: &str, handler: Rc<dyn Fn(Event)>) {
        if let Some(n) = self.nodes.borrow_mut().get_mut(&node) {
            n.listeners.push((event.to_owned(), handler));
        }
    }

    fn query(&self, selector: &str) -> Option<NodeId> {
        match selector {
            "body" => Some(0),
            s => s.strip_prefix('#').and_then(|id| self.find("id", id)),
        }
    }
}
