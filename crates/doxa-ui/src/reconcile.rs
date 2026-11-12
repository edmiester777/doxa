//! Turning a new view into the fewest DOM changes: same-kind nodes are patched,
//! keyed children are matched by key and moved along a longest increasing subsequence.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

use futures_util::future::LocalBoxFuture;

use crate::directive::{self, Proto};
use crate::dom::{Dom, Listen, NodeId, NodeRef, Prop};
use crate::portal::{PortalNode, PortalTarget};
use crate::runtime::{self, Cancel, Instance};
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
    /// Only `anchor` sits here; `content` renders into `target`, so moves never touch it.
    Portal {
        anchor: NodeId,
        target: NodeId,
        to: PortalTarget,
        content: Rc<Instance>,
    },
}

pub(crate) struct MountedElement {
    node: NodeId,
    tag: &'static str,
    key: Option<Key>,
    attrs: Vec<(&'static str, Option<String>)>,
    classes: Vec<(&'static str, bool)>,
    props: Vec<(&'static str, Prop)>,
    events: Vec<(&'static str, Listen, Rc<RefCell<Handler>>)>,
    inner_html: Option<String>,
    children: Vec<Mounted>,
    directives: Vec<directive::Live>,
    /// The type of each of `directives`.
    kinds: Vec<std::any::TypeId>,
}

impl MountedElement {
    /// Must precede `dom.remove`: a browser fires `blur` from inside `removeChild`, when the
    /// component owning the handler may already be dead.
    fn silence(&self) {
        for (.., handler) in &self.events {
            *handler.borrow_mut() = Rc::new(|_| {});
        }
    }
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
            Mounted::Portal { anchor, .. } => Some(*anchor),
            Mounted::Element(e) => Some(e.node),
            Mounted::Component { inst, .. } => {
                inst.region.borrow().first().and_then(Mounted::first_node)
            }
        }
    }

    fn last_node(&self) -> Option<NodeId> {
        match self {
            Mounted::Anchor(n) | Mounted::Text { node: n, .. } => Some(*n),
            Mounted::Portal { anchor, .. } => Some(*anchor),
            Mounted::Element(e) => Some(e.node),
            Mounted::Component { inst, .. } => {
                inst.region.borrow().last().and_then(Mounted::last_node)
            }
        }
    }

    /// The first element in this child, through components, with its directives.
    fn first_element(&self) -> Option<(NodeId, Vec<directive::Live>)> {
        match self {
            Mounted::Element(e) => Some((e.node, e.directives.clone())),
            Mounted::Component { inst, .. } => {
                inst.region.borrow().iter().find_map(Mounted::first_element)
            }
            _ => None,
        }
    }

    fn nodes(&self, out: &mut Vec<NodeId>) {
        match self {
            Mounted::Anchor(n) | Mounted::Text { node: n, .. } => out.push(*n),
            Mounted::Portal { anchor, .. } => out.push(*anchor),
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
        (Mounted::Portal { to, .. }, Node::Portal(p)) => *to == p.to,
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
    DEPTH.with(|d| d.set(d.get() + 1));
    reconcile(&*dom, inst, parent, &mut region, new, end);
    if region.is_empty() {
        let anchor = dom.create_anchor();
        dom.insert(parent, anchor, end);
        region.push(Mounted::Anchor(anchor));
    }
    *inst.region.borrow_mut() = region;
    if DEPTH.with(|d| d.replace(d.get() - 1)) == 1 {
        run_deferred();
    }
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
                unmount(dom, parent, m, true);
                kept.push(fresh);
            }
            None => pending_tail.push(n),
        }
    }
    for m in old_iter {
        unmount(dom, parent, m, true);
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
    // Measured before `patch` re-renders anything inside them.
    for (node, ds) in previous.iter().flatten().filter_map(Mounted::first_element) {
        ds.iter()
            .for_each(|d| d.borrow_mut().before_move(NodeRef(node)));
    }
    // Unkeyed children match the old unkeyed ones in order.
    let mut unkeyed = previous
        .iter()
        .enumerate()
        .filter(|(_, m)| m.as_ref().is_some_and(|m| m.key().is_none()))
        .map(|(i, _)| i)
        .collect::<Vec<_>>()
        .into_iter();
    let mut keyed: HashMap<Key, VecDeque<usize>> = HashMap::new();
    for (i, k) in previous
        .iter()
        .enumerate()
        .filter_map(|(i, m)| Some((i, m.as_ref()?.key()?)))
    {
        keyed.entry(k).or_default().push_back(i);
    }
    let mut placed: Vec<(Mounted, Option<usize>)> = Vec::with_capacity(new.len());
    for n in new {
        let found = match node_key(&n) {
            Some(k) => keyed.get_mut(&k).and_then(|at| {
                let j = at
                    .iter()
                    .position(|&i| previous[i].as_ref().is_some_and(|m| same_kind(m, &n)))?;
                at.remove(j)
            }),
            None => unkeyed
                .next()
                .filter(|&i| previous[i].as_ref().is_some_and(|m| same_kind(m, &n))),
        };
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
        unmount(dom, parent, m, true);
    }
    let order: Vec<usize> = placed.iter().filter_map(|(_, i)| *i).collect();
    let mut stay = vec![false; order.iter().max().map_or(0, |m| m + 1)];
    for i in lis(&order) {
        stay[i] = true;
    }
    let mut next = end;
    let mut nodes = Vec::new();
    for (m, i) in placed.iter().rev() {
        let stays = i.is_some_and(|i| stay[i]);
        if !stays {
            nodes.clear();
            m.nodes(&mut nodes);
            for n in &nodes {
                dom.insert(parent, *n, next);
            }
        }
        next = m.first_node().or(next);
    }
    let moved = placed.iter().filter(|(_, i)| i.is_some());
    for (node, ds) in moved.filter_map(|(m, _)| m.first_element()) {
        ds.iter()
            .for_each(|d| d.borrow_mut().after_move(NodeRef(node)));
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
        Node::Portal(p) => mount_portal(dom, owner, parent, &p, before),
    }
}

struct PortalContent;

fn mount_portal(
    dom: &dyn Dom,
    owner: &Rc<Instance>,
    parent: NodeId,
    p: &PortalNode,
    before: Option<NodeId>,
) -> Mounted {
    let (target, before_node) = match &p.to {
        PortalTarget::Node(n) => (n.id(), None),
        PortalTarget::Before(n) => (
            dom.parent(n.id())
                .expect("a `PortalTarget::Before` node is in the document"),
            Some(n.id()),
        ),
        PortalTarget::Selector(s) => (
            dom.query(s)
                .unwrap_or_else(|| panic!("no element matches `<Portal to={s:?}>`")),
            None,
        ),
    };
    let anchor = dom.create_anchor();
    dom.insert(parent, anchor, before);
    let content = Instance::new(
        "Portal",
        std::any::TypeId::of::<PortalContent>(),
        Some(owner),
        |v| {
            let view = v.downcast_ref::<View>().expect("portal content").clone();
            crate::RenderFuture::ready(Ok(view))
        },
        Rc::new(p.children.clone()),
        target,
    );
    let end = dom.create_anchor();
    dom.insert(target, end, before_node);
    content.region.borrow_mut().push(Mounted::Anchor(end));
    runtime::run(&content);
    Mounted::Portal {
        anchor,
        target,
        to: p.to.clone(),
        content,
    }
}

fn mount_element(dom: &dyn Dom, owner: &Rc<Instance>, e: &Element) -> MountedElement {
    let node = dom.create_element(e.tag, e.ns);
    for (k, v) in &e.attrs {
        if let Some(v) = v {
            dom.set_attr(node, k, v);
        }
    }
    for (c, on) in &e.classes {
        if *on {
            dom.toggle_class(node, c, true);
        }
    }
    for (k, v) in &e.props {
        dom.set_prop(node, k, v);
    }
    let events = e
        .events
        .iter()
        .map(|(name, o, h)| (*name, *o, listen(dom, node, name, *o, h.clone())))
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
    let directives: Vec<directive::Live> = e
        .directives
        .iter()
        .map(|p| Rc::new(RefCell::new(p.instance())))
        .collect();
    for d in &directives {
        defer(d.clone(), Hook::Mounted, node);
    }
    MountedElement {
        node,
        tag: e.tag,
        key: e.key,
        attrs: e.attrs.clone(),
        classes: e.classes.clone(),
        props: e.props.clone(),
        events,
        inner_html: e.inner_html.clone(),
        children,
        kinds: e.directives.iter().map(|p| p.kind()).collect(),
        directives,
    }
}

fn listen(
    dom: &dyn Dom,
    node: NodeId,
    event: &str,
    opts: Listen,
    handler: Handler,
) -> Rc<RefCell<Handler>> {
    let cell = Rc::new(RefCell::new(handler));
    let current = cell.clone();
    dom.listen(
        node,
        event,
        opts,
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
        (Mounted::Portal { content, .. }, Node::Portal(p)) => {
            *content.props.borrow_mut() = Rc::new(p.children.clone());
            runtime::run(content);
        }
        (Mounted::Component { inst, .. }, Node::Component(c)) => {
            inst.render.set(c.render);
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
    let mut class_rewritten = false;
    for (k, v) in &e.attrs {
        let old = m.attrs.iter().find(|(ok, _)| ok == k).map(|(_, v)| v);
        if old != Some(v) {
            class_rewritten |= *k == "class";
            match v {
                Some(v) => dom.set_attr(node, k, v),
                None => dom.remove_attr(node, k),
            }
        }
    }
    for (k, _) in &m.attrs {
        if !e.attrs.iter().any(|(nk, _)| nk == k) {
            class_rewritten |= *k == "class";
            dom.remove_attr(node, k);
        }
    }
    m.attrs = e.attrs.clone();

    // Rewriting `class` drops every toggle, so the ones on go back.
    for (c, on) in &e.classes {
        let old = m.classes.iter().find(|(oc, _)| oc == c).map(|(_, on)| *on);
        if class_rewritten {
            if *on {
                dom.toggle_class(node, c, true);
            }
        } else if old != Some(*on) {
            dom.toggle_class(node, c, *on);
        }
    }
    for (c, on) in &m.classes {
        if *on && !class_rewritten && !e.classes.iter().any(|(nc, _)| nc == c) {
            dom.toggle_class(node, c, false);
        }
    }
    m.classes = e.classes.clone();

    for (k, v) in &e.props {
        let old = m.props.iter().find(|(ok, _)| ok == k).map(|(_, v)| v);
        if old != Some(v) || matches!(*k, "value" | "checked") {
            dom.set_prop(node, k, v);
        }
    }
    m.props = e.props.clone();

    // The nth handler for an event takes over the nth listener for it.
    let mut taken = vec![false; m.events.len()];
    for (name, o, h) in &e.events {
        let free = (0..m.events.len())
            .find(|&i| !taken[i] && m.events[i].0 == *name && m.events[i].1 == *o);
        match free {
            Some(i) => {
                taken[i] = true;
                *m.events[i].2.borrow_mut() = h.clone();
            }
            None => {
                taken.push(true);
                m.events
                    .push((name, *o, listen(dom, node, name, *o, h.clone())));
            }
        }
    }
    for ((.., cell), taken) in m.events.iter().zip(taken) {
        if !taken {
            *cell.borrow_mut() = Rc::new(|_| {});
        }
    }

    patch_directives(m, &e.directives);

    if e.inner_html.is_some() {
        if m.inner_html != e.inner_html {
            for c in std::mem::take(&mut m.children) {
                unmount(dom, node, c, false);
            }
            dom.set_inner_html(node, e.inner_html.as_deref().unwrap_or_default());
            m.inner_html = e.inner_html.clone();
        }
        return;
    }
    if m.inner_html.take().is_some() {
        dom.set_inner_html(node, "");
    }
    let mut flat = Vec::new();
    e.children
        .iter()
        .cloned()
        .for_each(|c| flatten(c, &mut flat));
    reconcile(dom, owner, node, &mut m.children, flat, None);
}

/// The same directive kind at the same place takes this render's value; any other is
/// unmounted and the new one mounted.
fn patch_directives(m: &mut MountedElement, protos: &[Rc<dyn Proto>]) {
    let node = m.node;
    let old = std::mem::take(&mut m.directives);
    let mut old = old.into_iter();
    let mut kinds = std::mem::take(&mut m.kinds).into_iter();
    for p in protos {
        match (old.next(), kinds.next()) {
            (Some(d), Some(k)) if k == p.kind() => {
                d.borrow_mut().replace(p.value());
                defer(d.clone(), Hook::Updated, node);
                m.directives.push(d);
            }
            (gone, _) => {
                if let Some(d) = gone {
                    d.borrow_mut().unmounted(NodeRef(node));
                }
                let d: directive::Live = Rc::new(RefCell::new(p.instance()));
                defer(d.clone(), Hook::Mounted, node);
                m.directives.push(d);
            }
        }
        m.kinds.push(p.kind());
    }
    for d in old {
        d.borrow_mut().unmounted(NodeRef(node));
    }
}

#[derive(Clone, Copy)]
enum Hook {
    Mounted,
    Updated,
}

thread_local! {
    static DEPTH: Cell<usize> = const { Cell::new(0) };
    static DEFERRED: RefCell<Vec<(directive::Live, Hook, NodeId)>> = const { RefCell::new(Vec::new()) };
    /// Removed nodes a directive keeps in the document, under their DOM parent.
    static HELD: RefCell<Vec<Held>> = const { RefCell::new(Vec::new()) };
}

struct Held {
    parent: NodeId,
    node: NodeId,
    task: Cancel,
}

/// Queue a directive call for when the outermost region update finishes.
fn defer(d: directive::Live, hook: Hook, node: NodeId) {
    DEFERRED.with(|q| q.borrow_mut().push((d, hook, node)));
}

fn run_deferred() {
    let calls = DEFERRED.with(|d| std::mem::take(&mut *d.borrow_mut()));
    for (d, hook, node) in calls {
        let mut d = d.borrow_mut();
        match hook {
            Hook::Mounted => d.mounted(NodeRef(node)),
            Hook::Updated => d.updated(NodeRef(node)),
        }
    }
}

/// Unmount a whole root: stop its components and remove its nodes.
pub(crate) fn unmount_root(inst: &Rc<Instance>) {
    let dom = runtime::dom();
    inst.kill();
    let region = std::mem::take(&mut *inst.region.borrow_mut());
    for m in region {
        unmount(&*dom, inst.parent_node.get(), m, false);
    }
}

/// Remove `m` from under `parent`. With `hold`, an element's `leaving` futures keep it in
/// the document until they resolve; everything inside stops at once.
fn unmount(dom: &dyn Dom, parent: NodeId, m: Mounted, hold: bool) {
    match m {
        Mounted::Anchor(n) | Mounted::Text { node: n, .. } => dom.remove(n),
        Mounted::Element(e) => {
            e.silence();
            let node = NodeRef(e.node);
            let leaving: Vec<_> = if hold {
                e.directives
                    .iter()
                    .filter_map(|d| d.borrow_mut().leaving(node))
                    .collect()
            } else {
                Vec::new()
            };
            e.directives
                .iter()
                .for_each(|d| d.borrow_mut().unmounted(node));
            kill_children(dom, &e.children);
            release_held(dom, |h| h.parent == e.node);
            if leaving.is_empty() {
                dom.remove(e.node);
            } else {
                hold_node(parent, e.node, leaving);
            }
        }
        Mounted::Component { inst, .. } => {
            inst.kill();
            let region = std::mem::take(&mut *inst.region.borrow_mut());
            for m in region {
                unmount(dom, parent, m, hold);
            }
        }
        Mounted::Portal {
            anchor,
            target,
            content,
            ..
        } => {
            dom.remove(anchor);
            content.kill();
            let region = std::mem::take(&mut *content.region.borrow_mut());
            for m in region {
                unmount(dom, target, m, hold);
            }
        }
    }
}

fn hold_node(parent: NodeId, node: NodeId, leaving: Vec<LocalBoxFuture<'static, ()>>) {
    let task = runtime::spawn_cancellable(async move {
        futures_util::future::join_all(leaving).await;
        HELD.with(|h| h.borrow_mut().retain(|h| h.node != node));
        runtime::dom().remove(node);
    });
    HELD.with(|h| h.borrow_mut().push(Held { parent, node, task }));
}

/// Drop the futures holding the nodes `which` picks, and remove the nodes.
fn release_held(dom: &dyn Dom, which: impl Fn(&Held) -> bool) {
    let released: Vec<Held> = HELD.with(|h| {
        let mut h = h.borrow_mut();
        let (out, keep) = h.drain(..).partition(|x| which(x));
        *h = keep;
        out
    });
    for h in released {
        h.task.cancel();
        dom.remove(h.node);
    }
}

/// Remove every node a directive is holding, as if each had finished leaving.
pub(crate) fn finish_leaving() {
    if let Some(dom) = runtime::try_dom() {
        release_held(&*dom, |_| true);
    }
}

fn kill_children(dom: &dyn Dom, children: &[Mounted]) {
    for c in children {
        match c {
            Mounted::Element(e) => {
                e.silence();
                let node = NodeRef(e.node);
                e.directives
                    .iter()
                    .for_each(|d| d.borrow_mut().unmounted(node));
                kill_children(dom, &e.children);
                release_held(dom, |h| h.parent == e.node);
            }
            Mounted::Component { inst, .. } => {
                inst.kill();
                kill_children(dom, &inst.region.borrow());
            }
            // Its nodes live in another element, which an ancestor's removal won't reach.
            Mounted::Portal { content, .. } => {
                content.kill();
                let region = std::mem::take(&mut *content.region.borrow_mut());
                for m in region {
                    unmount(dom, content.parent_node.get(), m, false);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::any::{Any, TypeId};
    use std::cell::Cell;
    use std::rc::Rc;

    use super::lis;
    use crate::component::{Component, RenderFuture};
    use crate::testing::Screen;
    use crate::view::{comp, ComponentNode, IntoView, Node, View};

    thread_local! {
        static PATCHED: Cell<bool> = const { Cell::new(false) };
    }

    fn text(text: &'static str) -> RenderFuture {
        RenderFuture::ready(Ok(text.into_view()))
    }

    struct Child;

    /// Hands its child the pointer a patch's own table region would give it.
    struct Parent;

    impl Component for Parent {
        type Props = ();
        const NAME: &'static str = "Parent";

        fn render((): ()) -> RenderFuture {
            let render: fn(&Rc<dyn Any>) -> RenderFuture = if PATCHED.with(Cell::get) {
                |_| text("patched")
            } else {
                |_| text("base")
            };
            RenderFuture::ready(Ok(View(Node::Component(Rc::new(ComponentNode {
                type_id: TypeId::of::<Child>(),
                name: "Child",
                key: None,
                props: Rc::new(()),
                render,
                same_props: Some(|_, _| true),
            })))))
        }
    }

    #[test]
    fn a_matched_child_renders_through_the_pointer_its_parent_just_gave_it() {
        let screen = Screen::mount(|| comp::<Parent>(()).into_view());
        let shown = || {
            doxa_client::task::run_until_stalled();
            screen.dom().text(screen.dom().body())
        };
        assert_eq!(shown(), "base");
        PATCHED.with(|p| p.set(true));
        crate::runtime::rerender_all();
        assert_eq!(shown(), "patched");
    }

    #[test]
    fn lis_keeps_the_longest_run() {
        assert_eq!(lis(&[0, 1, 2]), vec![2, 1, 0]);
        let mut kept = lis(&[2, 0, 1, 3]);
        kept.sort();
        assert_eq!(kept, vec![0, 1, 3]);
    }
}
