//! What a component renders: a tree of elements, text, and child components.

use std::any::{Any, TypeId};
use std::cell::RefCell;
use std::hash::{Hash, Hasher};
use std::rc::Rc;

use crate::component::{Component, RenderFuture};
use crate::directive::{Directive, Lifecycle, Proto};
use crate::dom::{Event, NodeRef, Phase, Prop};

/// What a component renders. Build one with `view!`.
#[derive(Clone, Default)]
pub struct View(pub(crate) Node);

#[derive(Clone, Default)]
pub(crate) enum Node {
    #[default]
    Empty,
    Text(Rc<str>),
    Element(Rc<Element>),
    Component(Rc<ComponentNode>),
    Fragment(Rc<[Node]>),
    Portal(Rc<crate::portal::PortalNode>),
}

/// Identity of a child among its siblings, from `key={…}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key(u64);

impl Key {
    /// A key from any hashable value.
    pub fn of<K: Hash + ?Sized>(k: &K) -> Key {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        k.hash(&mut h);
        Key(h.finish())
    }
}

pub(crate) type Handler = Rc<dyn Fn(Event)>;

/// An element under construction. `view!` writes these calls.
#[derive(Clone)]
pub struct Element {
    pub(crate) tag: &'static str,
    pub(crate) ns: Option<&'static str>,
    pub(crate) key: Option<Key>,
    pub(crate) attrs: Vec<(&'static str, Option<String>)>,
    pub(crate) props: Vec<(&'static str, Prop)>,
    pub(crate) events: Vec<(&'static str, Handler)>,
    pub(crate) children: Vec<Node>,
    pub(crate) inner_html: Option<String>,
    pub(crate) directives: Vec<Rc<dyn Proto>>,
}

/// Start an element.
pub fn el(tag: &'static str) -> Element {
    let ns = match tag {
        "svg" | "path" | "g" | "circle" | "rect" | "line" | "polyline" | "polygon" | "ellipse"
        | "text" | "defs" | "use" | "symbol" | "clipPath" | "mask" | "linearGradient"
        | "radialGradient" | "stop" => Some("http://www.w3.org/2000/svg"),
        _ => None,
    };
    Element {
        tag,
        ns,
        key: None,
        attrs: Vec::new(),
        props: Vec::new(),
        events: Vec::new(),
        children: Vec::new(),
        inner_html: None,
        directives: Vec::new(),
    }
}

impl Element {
    /// Set an attribute: a string, a number, or a `bool` for presence.
    pub fn attr(mut self, name: &'static str, value: impl IntoAttr) -> Self {
        self.attrs.push((name, value.into_attr()));
        self
    }

    /// Set a URL attribute (`href`, `src`, `action`); only a [`SafeUrl`] is accepted.
    pub fn url(mut self, name: &'static str, value: impl Into<SafeUrl>) -> Self {
        self.attrs.push((name, Some(value.into().0.to_string())));
        self
    }

    /// Set a DOM property, as `prop:name={…}`.
    pub fn prop(mut self, name: &'static str, value: impl IntoProp) -> Self {
        self.props.push((name, value.into_prop()));
        self
    }

    /// Handle an event, as `on:click={…}`.
    pub fn on(mut self, event: &'static str, handler: impl Fn(Event) + 'static) -> Self {
        self.events.push((event, Rc::new(handler)));
        self
    }

    /// Handle an event with an async closure; an `Err` goes to the nearest `<Catch>`.
    pub fn on_async<F>(mut self, event: &'static str, handler: F) -> Self
    where
        F: AsyncFn(Event) -> crate::Result<()> + 'static,
    {
        let handler = Rc::new(handler);
        let owner = crate::runtime::current_instance();
        self.events.push((
            event,
            Rc::new(move |ev| {
                let handler = handler.clone();
                let owner = owner.clone();
                doxa_client::task::spawn(async move {
                    if let Err(e) = handler(ev).await {
                        crate::runtime::throw(owner.as_ref(), e);
                    }
                });
            }),
        ));
        self
    }

    /// Set the inner HTML. Only [`DangerousHtml`] is accepted.
    pub fn inner_html(mut self, html: DangerousHtml) -> Self {
        self.inner_html = Some(html.0);
        self
    }

    /// Append a child.
    pub fn child(mut self, child: impl IntoView) -> Self {
        self.children.push(child.into_view().0);
        self
    }

    /// Identify this element among its siblings.
    pub fn key(mut self, key: impl Hash) -> Self {
        self.key = Some(Key::of(&key));
        self
    }

    /// Run `f` with the element's node after it mounts or is patched, and before it is removed.
    pub fn lifecycle(self, f: impl Fn(Phase, NodeRef) + 'static) -> Self {
        self.directive(Lifecycle(Rc::new(f)))
    }

    /// Point `r` at this element, as `ref={r}`.
    pub fn node_ref(self, r: crate::ElementRef) -> Self {
        self.directive(r)
    }

    /// Attach a [`Directive`], as `use:name={value}`.
    pub fn directive(mut self, d: impl Directive) -> Self {
        self.directives.push(Rc::new(d));
        self
    }
}

/// A child component, with its props.
pub(crate) struct ComponentNode {
    pub type_id: TypeId,
    pub name: &'static str,
    pub key: Option<Key>,
    pub props: Rc<dyn Any>,
    pub render: fn(&Rc<dyn Any>) -> RenderFuture,
    pub same_props: Option<crate::component::SameProps>,
}

/// A child component, as `<Name prop={…}/>`.
pub fn comp<C: Component>(props: C::Props) -> ComponentView {
    ComponentView(ComponentNode {
        type_id: TypeId::of::<C>(),
        name: C::NAME,
        key: None,
        props: Rc::new(props),
        render: |p| {
            C::render(
                p.downcast_ref::<C::Props>()
                    .expect("props of this component")
                    .clone(),
            )
        },
        same_props: C::SAME_PROPS,
    })
}

/// A child component under construction.
pub struct ComponentView(ComponentNode);

impl ComponentView {
    /// Identify this component among its siblings; a new key remounts it.
    pub fn key(mut self, key: impl Hash) -> Self {
        self.0.key = Some(Key::of(&key));
        self
    }
}

/// Anything that can sit in a view: views, text, numbers, options and lists of them.
pub trait IntoView {
    /// Convert into a view.
    fn into_view(self) -> View;
}

impl IntoView for View {
    fn into_view(self) -> View {
        self
    }
}

impl IntoView for Element {
    fn into_view(self) -> View {
        View(Node::Element(Rc::new(self)))
    }
}

impl IntoView for ComponentView {
    fn into_view(self) -> View {
        View(Node::Component(Rc::new(self.0)))
    }
}

impl IntoView for () {
    fn into_view(self) -> View {
        View::default()
    }
}

impl IntoView for &str {
    fn into_view(self) -> View {
        View(Node::Text(self.into()))
    }
}

impl IntoView for String {
    fn into_view(self) -> View {
        View(Node::Text(self.into()))
    }
}

impl IntoView for &String {
    fn into_view(self) -> View {
        self.as_str().into_view()
    }
}

impl IntoView for Rc<str> {
    fn into_view(self) -> View {
        View(Node::Text(self))
    }
}

macro_rules! display_view {
    ($($t:ty),*) => {$(
        impl IntoView for $t {
            fn into_view(self) -> View {
                self.to_string().into_view()
            }
        }
    )*};
}

display_view!(i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize, f32, f64, char, bool);

impl<T: IntoView> IntoView for Option<T> {
    fn into_view(self) -> View {
        self.map(IntoView::into_view).unwrap_or_default()
    }
}

impl<T: IntoView> IntoView for Vec<T> {
    fn into_view(self) -> View {
        self.into_iter().collect()
    }
}

impl<T: IntoView> FromIterator<T> for View {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> View {
        View(Node::Fragment(
            iter.into_iter().map(|v| v.into_view().0).collect(),
        ))
    }
}

impl View {
    /// Several views side by side.
    pub fn fragment<const N: usize>(views: [View; N]) -> View {
        View(Node::Fragment(views.into_iter().map(|v| v.0).collect()))
    }

    /// Nothing.
    pub fn empty() -> View {
        View::default()
    }
}

/// What a `children` prop is built from: a [`View`], or its text.
#[doc(hidden)]
pub trait FromChildren {
    fn from_children(children: View) -> Self;
}

impl FromChildren for View {
    fn from_children(children: View) -> Self {
        children
    }
}

impl FromChildren for String {
    fn from_children(children: View) -> Self {
        fn text(node: &Node, out: &mut String) {
            match node {
                Node::Empty => {}
                Node::Text(t) => out.push_str(t),
                Node::Fragment(items) => items.iter().for_each(|n| text(n, out)),
                Node::Element(e) => panic!("this `children` prop takes text, not a <{}>", e.tag),
                Node::Component(c) => panic!("this `children` prop takes text, not a <{}>", c.name),
                Node::Portal(_) => panic!("this `children` prop takes text, not a <Portal>"),
            }
        }
        let mut out = String::new();
        text(&children.0, &mut out);
        out
    }
}

/// An attribute value.
pub trait IntoAttr {
    /// `None` removes the attribute.
    fn into_attr(self) -> Option<String>;
}

impl IntoAttr for &str {
    fn into_attr(self) -> Option<String> {
        Some(self.to_owned())
    }
}

impl IntoAttr for String {
    fn into_attr(self) -> Option<String> {
        Some(self)
    }
}

impl IntoAttr for &String {
    fn into_attr(self) -> Option<String> {
        Some(self.clone())
    }
}

impl IntoAttr for bool {
    fn into_attr(self) -> Option<String> {
        self.then(String::new)
    }
}

impl<T: IntoAttr> IntoAttr for Option<T> {
    fn into_attr(self) -> Option<String> {
        self.and_then(IntoAttr::into_attr)
    }
}

macro_rules! display_attr {
    ($($t:ty),*) => {$(
        impl IntoAttr for $t {
            fn into_attr(self) -> Option<String> {
                Some(self.to_string())
            }
        }
    )*};
}

display_attr!(i32, i64, u32, u64, usize, f32, f64);

/// A DOM property value.
pub trait IntoProp {
    /// Convert into a property.
    fn into_prop(self) -> Prop;
}

impl IntoProp for &str {
    fn into_prop(self) -> Prop {
        Prop::Str(self.to_owned())
    }
}

impl IntoProp for String {
    fn into_prop(self) -> Prop {
        Prop::Str(self)
    }
}

impl IntoProp for bool {
    fn into_prop(self) -> Prop {
        Prop::Bool(self)
    }
}

impl IntoProp for f64 {
    fn into_prop(self) -> Prop {
        Prop::Num(self)
    }
}

impl IntoProp for i32 {
    fn into_prop(self) -> Prop {
        Prop::Num(self.into())
    }
}

impl<T: IntoProp> IntoProp for Option<T> {
    fn into_prop(self) -> Prop {
        self.map_or(Prop::Unset, IntoProp::into_prop)
    }
}

/// A URL checked not to run script: no `javascript:`, `vbscript:` or `data:` scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeUrl(Rc<str>);

impl SafeUrl {
    /// Check `url`.
    pub fn parse(url: &str) -> Option<SafeUrl> {
        let squeezed: String = url
            .chars()
            .filter(|c| !c.is_whitespace() && !c.is_control())
            .take(16)
            .collect::<String>()
            .to_ascii_lowercase();
        let scripted = ["javascript:", "vbscript:", "data:"]
            .iter()
            .any(|scheme| squeezed.starts_with(scheme));
        (!scripted).then(|| SafeUrl(url.into()))
    }

    /// A literal written in the source; `view!` uses this for `href="…"`.
    pub fn literal(url: &'static str) -> SafeUrl {
        SafeUrl::parse(url).unwrap_or_else(|| panic!("`{url}` is not a safe URL"))
    }

    /// The URL.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// HTML you vouch for; the only thing `inner_html` takes.
pub struct DangerousHtml(String);

impl DangerousHtml {
    /// Trust `html` to be safe to insert as-is.
    pub fn trust(html: impl Into<String>) -> Self {
        DangerousHtml(html.into())
    }
}

/// A prop holding a handler: `on_select={move |id| …}`.
pub struct Callback<T = ()>(Rc<RefCell<Handle<T>>>);

type Handle<T> = Rc<dyn Fn(T)>;

impl<T> Clone for Callback<T> {
    fn clone(&self) -> Self {
        Callback(self.0.clone())
    }
}

impl<T> PartialEq for Callback<T> {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

impl<T> Callback<T> {
    /// Call the handler.
    pub fn call(&self, value: T) {
        let f = self.0.borrow().clone();
        f(value)
    }
}

impl<T, F: Fn(T) + 'static> From<F> for Callback<T> {
    fn from(f: F) -> Self {
        Callback(Rc::new(RefCell::new(Rc::new(f))))
    }
}
