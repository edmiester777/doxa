//! Turning a new view into the fewest DOM changes: same-kind nodes are patched,
//! keyed children are matched by key and moved along a longest increasing subsequence.

use std::cell::RefCell;
use std::rc::Rc;

use crate::dom::{Dom, NodeId, Prop};
use crate::runtime::{self, Instance};
use crate::view::{ComponentNode, Element, Handler, Key, Node};
use crate::View;

pub(crate) enum Mounted {
    Anchor(NodeId),
    Text {
        node: NodeId,
        text: Rc<str>,
    },
    Element(Box<MountedElement>),
    Component {
        inst: Rc<Instance>,
        key: Option<Key>,
    },
}

pub(crate) struct MountedElement {
    node: NodeId,
    tag: &'static str,
    key: Option<Key>,
    attrs: Vec<(&'static str, Option<String>)>,
    props: Vec<(&'static str, Prop)>,
    events: Vec<(&'static str, Rc<RefCell<Handler>>)>,
    inner_html: Option<String>,
    children: Vec<Mounted>,
}

impl Mounted {
    fn key(&self) -> Option<Key> {
        match self {
            Mounted::Element(e) => e.key,
            Mounted::Component { key, .. } => *key,
            _ => None,
        }
    }

    fn first_node(&self) -> Option<NodeId> {
        match self {
            Mounted::Anchor(n) | Mounted::Text { node: n, .. } => Some(*n),
            Mounted::Element(e) => Some(e.node),
            Mounted::Component { inst, .. } => {
                inst.region.borrow().first().and_then(Mounted::first_node)
            }
        }
    }

    fn last_node(&self) -> Option<NodeId> {
        match self {
            Mounted::Anchor(n) | Mounted::Text { node: n, .. } => Some(*n),
            Mounted::Element(e) => Some(e.node),
            Mounted::Component { inst, .. } => {
                inst.region.borrow().last().and_then(Mounted::last_node)
            }
        }
    }

    fn nodes(&self, out: &mut Vec<NodeId>) {
        match self {
            Mounted::Anchor(n) | Mounted::Text { node: n, .. } => out.push(*n),
            Mounted::Element(e) => out.push(e.node),
            Mounted::Component { inst, .. } => {
                inst.region.borrow().iter().for_each(|m| m.nodes(out))
            }
        }
    }
}

fn same_kind(old: &Mounted, new: &Node) -> bool {
    match (old, new) {
        (Mounted::Text { .. }, Node::Text(_)) => true,
        (Mounted::Element(o), Node::Element(n)) => o.tag == n.tag && o.key == n.key,
        (Mounted::Component { inst, key }, Node::Component(n)) => {
            inst.type_id == n.type_id && *key == n.key
        }
        _ => false,
    }
}

fn flatten(node: Node, out: &mut Vec<Node>) {
    match node {
        Node::Empty => {}
        Node::Fragment(items) => items.iter().cloned().for_each(|n| flatten(n, out)),
        other => out.push(other),
    }
}

/// Replace a component's region with `view`.
pub(crate) fn update_region(inst: &Rc<Instance>, view: View) {
    let dom = runtime::dom();
    let parent = inst.parent_node.get();
    let mut region = std::mem::take(&mut *inst.region.borrow_mut());
    let end = region
        .last()
        .and_then(Mounted::last_node)
        .and_then(|n| dom.next_sibling(n));
    let mut new = Vec::new();
    flatten(view.0, &mut new);
    reconcile(&*dom, inst, parent, &mut region, new, end);
    if region.is_empty() {
        let anchor = dom.create_anchor();
        dom.insert(parent, anchor, end);
        region.push(Mounted::Anchor(anchor));
    }
    *inst.region.borrow_mut() = region;
}

fn reconcile(
    dom: &dyn Dom,
    owner: &Rc<Instance>,
    parent: NodeId,
    old: &mut Vec<Mounted>,
    new: Vec<Node>,
    end: Option<NodeId>,
) {
    let keyed = new.iter().any(|n| node_key(n).is_some());
    if keyed {
        reconcile_keyed(dom, owner, parent, old, new, end);
        return;
    }
    let mut kept = Vec::with_capacity(new.len());
    let mut old_iter = std::mem::take(old).into_iter();
    let mut pending_tail: Vec<Node> = Vec::new();
    for n in new {
        match old_iter.next() {
            Some(mut m) if same_kind(&m, &n) => {
                patch(dom, owner, &mut m, n);
                kept.push(m);
            }
            Some(m) => {
                let before = m.first_node();
                let fresh = mount(dom, owner, parent, n, before);
                unmount(dom, m);
                kept.push(fresh);
            }
            None => pending_tail.push(n),
        }
    }
    for m in old_iter {
        unmount(dom, m);
    }
    for n in pending_tail {
        kept.push(mount(dom, owner, parent, n, end));
    }
    *old = kept;
}

fn node_key(n: &Node) -> Option<Key> {
    match n {
        Node::Element(e) => e.key,
        Node::Component(c) => c.key,
        _ => None,
    }
}

fn reconcile_keyed(
    dom: &dyn Dom,
    owner: &Rc<Instance>,
    parent: NodeId,
    old: &mut Vec<Mounted>,
    new: Vec<Node>,
    end: Option<NodeId>,
) {
    let mut previous: Vec<Option<Mounted>> = std::mem::take(old).into_iter().map(Some).collect();
    let mut placed: Vec<(Mounted, Option<usize>)> = Vec::with_capacity(new.len());
    for n in new {
        let found = node_key(&n).and_then(|k| {
            previous.iter().position(|m| {
                m.as_ref()
                    .is_some_and(|m| m.key() == Some(k) && same_kind(m, &n))
            })
        });
        match found {
            Some(i) => {
                let mut m = previous[i].take().expect("matched once");
                patch(dom, owner, &mut m, n);
                placed.push((m, Some(i)));
            }
            None => placed.push((mount(dom, owner, parent, n, end), None)),
        }
    }
    for m in previous.into_iter().flatten() {
        unmount(dom, m);
    }
    let order: Vec<usize> = placed.iter().filter_map(|(_, i)| *i).collect();
    let stay = lis(&order);
    let mut next = end;
    let mut nodes = Vec::new();
    for (m, i) in placed.iter().rev() {
        let stays = i.is_some_and(|i| stay.contains(&i));
        if !stays {
            nodes.clear();
            m.nodes(&mut nodes);
            for n in &nodes {
                dom.insert(parent, *n, next);
            }
        }
        next = m.first_node().or(next);
    }
    *old = placed.into_iter().map(|(m, _)| m).collect();
}

/// The values of a longest increasing subsequence of `seq`.
fn lis(seq: &[usize]) -> Vec<usize> {
    let mut tails: Vec<usize> = Vec::new();
    let mut prev = vec![usize::MAX; seq.len()];
    for i in 0..seq.len() {
        let at = tails.partition_point(|&t| seq[t] < seq[i]);
        if at > 0 {
            prev[i] = tails[at - 1];
        }
        if at == tails.len() {
            tails.push(i);
        } else {
            tails[at] = i;
        }
    }
    let mut out = Vec::with_capacity(tails.len());
    let mut at = tails.last().copied();
    while let Some(i) = at {
        out.push(seq[i]);
        at = (prev[i] != usize::MAX).then_some(prev[i]);
    }
    out
}

fn mount(
    dom: &dyn Dom,
    owner: &Rc<Instance>,
    parent: NodeId,
    node: Node,
    before: Option<NodeId>,
) -> Mounted {
    match node {
        Node::Empty | Node::Fragment(_) => {
            let n = dom.create_anchor();
            dom.insert(parent, n, before);
            Mounted::Anchor(n)
        }
        Node::Text(text) => {
            let n = dom.create_text(&text);
            dom.insert(parent, n, before);
            Mounted::Text { node: n, text }
        }
        Node::Element(e) => {
            let m = mount_element(dom, owner, &e);
            dom.insert(parent, m.node, before);
            Mounted::Element(Box::new(m))
        }
        Node::Component(c) => mount_component(dom, owner, parent, &c, before),
    }
}

fn mount_element(dom: &dyn Dom, owner: &Rc<Instance>, e: &Element) -> MountedElement {
    let node = dom.create_element(e.tag, e.ns);
    for (k, v) in &e.attrs {
        if let Some(v) = v {
            dom.set_attr(node, k, v);
        }
    }
    for (k, v) in &e.props {
        dom.set_prop(node, k, v);
    }
    let events = e
        .events
        .iter()
        .map(|(name, h)| (*name, listen(dom, node, name, h.clone())))
        .collect();
    let mut children = Vec::new();
    match &e.inner_html {
        Some(html) => dom.set_inner_html(node, html),
        None => {
            let mut flat = Vec::new();
            e.children
                .iter()
                .cloned()
                .for_each(|c| flatten(c, &mut flat));
            for c in flat {
                children.push(mount(dom, owner, node, c, None));
            }
        }
    }
    MountedElement {
        node,
        tag: e.tag,
        key: e.key,
        attrs: e.attrs.clone(),
        props: e.props.clone(),
        events,
        inner_html: e.inner_html.clone(),
        children,
    }
}

fn listen(dom: &dyn Dom, node: NodeId, event: &str, handler: Handler) -> Rc<RefCell<Handler>> {
    let cell = Rc::new(RefCell::new(handler));
    let current = cell.clone();
    dom.listen(
        node,
        event,
        Rc::new(move |ev| {
            let h = current.borrow().clone();
            h(ev);
        }),
    );
    cell
}

fn mount_component(
    dom: &dyn Dom,
    owner: &Rc<Instance>,
    parent: NodeId,
    c: &ComponentNode,
    before: Option<NodeId>,
) -> Mounted {
    let inst = Instance::new(
        c.name,
        c.type_id,
        Some(owner),
        c.render,
        c.props.clone(),
        parent,
    );
    let anchor = dom.create_anchor();
    dom.insert(parent, anchor, before);
    inst.region.borrow_mut().push(Mounted::Anchor(anchor));
    runtime::run(&inst);
    Mounted::Component { inst, key: c.key }
}

fn patch(dom: &dyn Dom, owner: &Rc<Instance>, old: &mut Mounted, new: Node) {
    match (old, new) {
        (Mounted::Text { node, text }, Node::Text(t)) => {
            if *text != t {
                dom.set_text(*node, &t);
                *text = t;
            }
        }
        (Mounted::Element(m), Node::Element(e)) => patch_element(dom, owner, m, &e),
        (Mounted::Component { inst, .. }, Node::Component(c)) => {
            let unchanged = c
                .same_props
                .is_some_and(|eq| eq(&inst.props.borrow(), &c.props));
            if !unchanged {
                *inst.props.borrow_mut() = c.props.clone();
                inst.caught.borrow_mut().take();
                runtime::run(inst);
            }
        }
        _ => unreachable!("patch is only called on nodes of the same kind"),
    }
}

fn patch_element(dom: &dyn Dom, owner: &Rc<Instance>, m: &mut MountedElement, e: &Element) {
    let node = m.node;
    for (k, v) in &e.attrs {
        let old = m.attrs.iter().find(|(ok, _)| ok == k).map(|(_, v)| v);
        if old != Some(v) {
            match v {
                Some(v) => dom.set_attr(node, k, v),
                None => dom.remove_attr(node, k),
            }
        }
    }
    for (k, _) in &m.attrs {
        if !e.attrs.iter().any(|(nk, _)| nk == k) {
            dom.remove_attr(node, k);
        }
    }
    m.attrs = e.attrs.clone();

    for (k, v) in &e.props {
        let old = m.props.iter().find(|(ok, _)| ok == k).map(|(_, v)| v);
        if old != Some(v) || matches!(*k, "value" | "checked") {
            dom.set_prop(node, k, v);
        }
    }
    m.props = e.props.clone();

    for (name, h) in &e.events {
        match m.events.iter().find(|(n, _)| n == name) {
            Some((_, cell)) => *cell.borrow_mut() = h.clone(),
            None => m.events.push((name, listen(dom, node, name, h.clone()))),
        }
    }
    for (name, cell) in &m.events {
        if !e.events.iter().any(|(n, _)| n == name) {
            *cell.borrow_mut() = Rc::new(|_| {});
        }
    }

    if e.inner_html.is_some() {
        if m.inner_html != e.inner_html {
            for c in std::mem::take(&mut m.children) {
                unmount(dom, c);
            }
            dom.set_inner_html(node, e.inner_html.as_deref().unwrap_or_default());
            m.inner_html = e.inner_html.clone();
        }
        return;
    }
    let mut flat = Vec::new();
    e.children
        .iter()
        .cloned()
        .for_each(|c| flatten(c, &mut flat));
    reconcile(dom, owner, node, &mut m.children, flat, None);
}

fn unmount(dom: &dyn Dom, m: Mounted) {
    match m {
        Mounted::Anchor(n) | Mounted::Text { node: n, .. } => dom.remove(n),
        Mounted::Element(e) => {
            kill_children(&e.children);
            dom.remove(e.node);
        }
        Mounted::Component { inst, .. } => {
            inst.kill();
            let region = std::mem::take(&mut *inst.region.borrow_mut());
            for m in region {
                unmount(dom, m);
            }
        }
    }
}

fn kill_children(children: &[Mounted]) {
    for c in children {
        match c {
            Mounted::Element(e) => kill_children(&e.children),
            Mounted::Component { inst, .. } => {
                inst.kill();
                kill_children(&inst.region.borrow());
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::lis;

    #[test]
    fn lis_keeps_the_longest_run() {
        assert_eq!(lis(&[0, 1, 2]), vec![2, 1, 0]);
        let mut kept = lis(&[2, 0, 1, 3]);
        kept.sort();
        assert_eq!(kept, vec![0, 1, 3]);
    }
}
