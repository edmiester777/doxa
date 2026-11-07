//! What a component renders: a tree of elements, text, and child components.

use std::any::{Any, TypeId};
use std::cell::RefCell;
use std::hash::{Hash, Hasher};
use std::rc::Rc;

use crate::component::{Component, RenderFuture};
use crate::directive::{Directive, Lifecycle, Proto};
use crate::dom::{Event, Listen, NodeRef, Phase, Prop};

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
    /// `class:name={on}`, kept apart from `class` so a toggle patches only its own class.
    pub(crate) classes: Vec<(&'static str, bool)>,
    pub(crate) props: Vec<(&'static str, Prop)>,
    pub(crate) events: Vec<(&'static str, Listen, Handler)>,
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
        classes: Vec::new(),
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

    /// Add `class` when `on`, as `class:name={on}`.
    pub fn class_toggle(mut self, class: &'static str, on: bool) -> Self {
        self.classes.retain(|(c, _)| *c != class);
        self.classes.push((class, on));
        self
    }

    /// Its attributes with the toggled-on classes folded into `class`.
    #[cfg(feature = "react")]
    pub(crate) fn flat_attrs(&self) -> Vec<(&'static str, String)> {
        let mut out: Vec<(&'static str, String)> = self
            .attrs
            .iter()
            .filter_map(|(k, v)| Some((*k, v.clone()?)))
            .collect();
        let on: Vec<&str> = self
            .classes
            .iter()
            .filter(|(_, on)| *on)
            .map(|(c, _)| *c)
            .collect();
        if !on.is_empty() {
            match out.iter_mut().find(|(k, _)| *k == "class") {
                Some((_, v)) => {
                    for c in on {
                        v.push(' ');
                        v.push_str(c);
                    }
                }
                None => out.push(("class", on.join(" "))),
            }
        }
        out
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
    pub fn on(self, event: &'static str, handler: impl Fn(Event) + 'static) -> Self {
        self.on_with(event, Listen::default(), handler)
    }

    /// [`on`](Self::on) with listener options, as `on:scroll.passive={…}`.
    pub fn on_with(
        mut self,
        event: &'static str,
        opts: Listen,
        handler: impl Fn(Event) + 'static,
    ) -> Self {
        self.events.push((event, opts, Rc::new(handler)));
        self
    }

    /// Handle an event with an async closure; an `Err` goes to the nearest `<Catch>`.
    pub fn on_async<F, R>(self, event: &'static str, handler: F) -> Self
    where
        F: AsyncFn(Event) -> R + 'static,
        R: crate::Outcome,
    {
        self.on_async_with(event, Listen::default(), handler)
    }

    /// [`on_async`](Self::on_async) with listener options.
    pub fn on_async_with<F, R>(mut self, event: &'static str, opts: Listen, handler: F) -> Self
    where
        F: AsyncFn(Event) -> R + 'static,
        R: crate::Outcome,
    {
        self.events.push((event, opts, async_handler(handler)));
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

/// Spawn `handler` per event; an `Err` goes to the `<Catch>` around the instance rendering now.
pub(crate) fn async_handler<F, R>(handler: F) -> Handler
where
    F: AsyncFn(Event) -> R + 'static,
    R: crate::Outcome,
{
    let handler = Rc::new(handler);
    let owner = owner();
    Rc::new(move |ev| {
        let handler = handler.clone();
        owner.spawn(async move { handler(ev).await });
    })
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

    /// As an `Option<View>` prop takes it; only an `Option` can be absent.
    #[doc(hidden)]
    fn into_optional_view(self) -> Option<View>
    where
        Self: Sized,
    {
        Some(self.into_view())
    }
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

    fn into_optional_view(self) -> Option<View> {
        self.map(IntoView::into_view)
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
pub struct SafeUrl(pub(crate) Rc<str>);

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

impl From<SafeUrl> for String {
    fn from(url: SafeUrl) -> String {
        url.0.to_string()
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

/// What an `Option` prop over a component's own parameter takes: exactly `T`, so the tag
/// still infers the parameter, or an `Option` of it.
#[doc(hidden)]
#[diagnostic::on_unimplemented(
    message = "this `Option<{T}>` prop can't be given a `{Self}`",
    label = "pass a `{T}` or an `Option` of one"
)]
pub trait OptionOf<T> {
    fn into_option(self) -> Option<T>;
}

impl<T> OptionOf<T> for T {
    fn into_option(self) -> Option<T> {
        Some(self)
    }
}

impl<T> OptionOf<T> for Option<T> {
    fn into_option(self) -> Option<T> {
        self
    }
}

/// A function held in a prop, called like one: `on_move(id, 3)`. A component's signature
/// writes it `on_move: impl Fn(Uuid, i32)`; anywhere else it is `Callback<dyn Fn(Uuid, i32)>`.
pub struct Callback<F: ?Sized = dyn Fn()>(Rc<F>);

impl<F: ?Sized> Clone for Callback<F> {
    fn clone(&self) -> Self {
        Callback(self.0.clone())
    }
}

impl<F: ?Sized> PartialEq for Callback<F> {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

impl<F: ?Sized> std::ops::Deref for Callback<F> {
    type Target = F;
    fn deref(&self) -> &F {
        &self.0
    }
}

impl<F: ?Sized> Callback<F> {
    /// From a shared function, for a signature `From` doesn't cover, e.g. `Fn(&T, usize)`.
    pub fn from_rc(f: Rc<F>) -> Self {
        Callback(f)
    }
}

macro_rules! callback_arity {
    ($($a:ident $v:ident),*) => {
        impl<$($a: 'static,)* R: 'static, F: Fn($($a),*) -> R + 'static> From<F>
            for Callback<dyn Fn($($a),*) -> R>
        {
            fn from(f: F) -> Self {
                Callback(Rc::new(f))
            }
        }

        impl<$($a: 'static),*> Default for Callback<dyn Fn($($a),*)> {
            fn default() -> Self {
                Callback(Rc::new(|$(_: $a),*| {}))
            }
        }

        impl<$($a: 'static,)* F: Fn($($a),*) + 'static> crate::hooks::CallbackFn<($($a,)*)> for F {
            type Sig = dyn Fn($($a),*);

            fn shared(self) -> Rc<Self::Sig> {
                Rc::new(self)
            }

            fn forwarding(latest: Rc<RefCell<Rc<Self::Sig>>>) -> Rc<Self::Sig> {
                Rc::new(move |$($v: $a),*| {
                    let f = latest.borrow().clone();
                    f($($v),*)
                })
            }
        }

        impl<$($a: 'static),*> crate::hooks::StableCallback<dyn Fn($($a),*)> {
            /// Run the latest render's closure; nothing once the component has unmounted.
            pub fn call(&self, $($v: $a),*) {
                if let Some(f) = self.current() {
                    f($($v),*)
                }
            }
        }
    };
}

callback_arity!();
callback_arity!(A a);
callback_arity!(A a, B b);
callback_arity!(A a, B b, C c);
callback_arity!(A a, B b, C c, D d);
callback_arity!(A a, B b, C c, D d, E e);
callback_arity!(A a, B b, C c, D d, E e, G g);

/// The current component, so a callback's async closure throws to the `<Catch>` around it.
#[doc(hidden)]
pub struct Owner(Option<Rc<crate::runtime::Instance>>);

#[doc(hidden)]
pub fn owner() -> Owner {
    Owner(crate::runtime::current_instance())
}

impl Owner {
    pub fn spawn<R: crate::Outcome>(&self, run: impl std::future::Future<Output = R> + 'static) {
        let owner = self.0.clone();
        doxa_client::task::spawn(async move {
            if let Err(e) = run.await.into_result() {
                crate::runtime::throw(owner.as_ref(), e);
            }
        });
    }
}

/// Keeps [`IntoOptional`]'s two impls from overlapping.
#[doc(hidden)]
pub struct AsValue;
#[doc(hidden)]
pub struct AsOption;

/// What an `Option<T>` prop takes: `T`, what converts to it, or an `Option` of those.
#[doc(hidden)]
#[diagnostic::on_unimplemented(
    message = "this `Option<{T}>` prop can't be given a `{Self}`",
    label = "pass a `{T}`, something `Into<{T}>`, or an `Option` of one"
)]
pub trait IntoOptional<T, M> {
    fn into_optional(self) -> Option<T>;
}

impl<T, U: Into<T>> IntoOptional<T, AsValue> for U {
    fn into_optional(self) -> Option<T> {
        Some(self.into())
    }
}

impl<T, U: Into<T>> IntoOptional<T, AsOption> for Option<U> {
    fn into_optional(self) -> Option<T> {
        self.map(Into::into)
    }
}

/// What `bind:value={x}` reads and writes: a [`State`](crate::State) or a form field.
pub trait BindValue: Copy + 'static {
    /// The text to show.
    fn current(&self) -> String;
    /// The user typed `text`.
    fn input(&self, text: String);
    /// The user left the input.
    fn blur(&self) {}
}

/// A `State` of anything that parses: text that doesn't parse is dropped.
impl<V: Clone + std::str::FromStr + ToString + 'static> BindValue for crate::State<V> {
    fn current(&self) -> String {
        self.get().to_string()
    }

    fn input(&self, text: String) {
        if let Ok(v) = text.parse() {
            self.set(v);
        }
    }
}

/// What `bind:checked={x}` reads and writes.
pub trait BindChecked: Copy + 'static {
    /// Whether it is checked.
    fn checked(&self) -> bool;
    /// The user checked or unchecked it.
    fn set_checked(&self, on: bool);
}

impl BindChecked for crate::State<bool> {
    fn checked(&self) -> bool {
        self.get()
    }

    fn set_checked(&self, on: bool) {
        self.set(on);
    }
}

/// What `bind:selected={x}` on a `<select multiple>` reads and writes: the chosen values.
pub trait BindSelected: Copy + 'static {
    /// The chosen options' values.
    fn selected(&self) -> Vec<String>;
    /// The user changed the choice.
    fn set_selected(&self, values: Vec<String>);
}

impl BindSelected for crate::State<Vec<String>> {
    fn selected(&self) -> Vec<String> {
        self.get()
    }

    fn set_selected(&self, values: Vec<String>) {
        self.set(values);
    }
}

/// Keeps a `<select multiple>`'s options selected to match its binding.
#[derive(Clone)]
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
struct SelectSync(Vec<String>);

impl Directive for SelectSync {
    fn mounted(&mut self, node: NodeRef) {
        self.sync(node);
    }

    fn updated(&mut self, node: NodeRef) {
        self.sync(node);
    }
}

impl SelectSync {
    #[cfg_attr(not(target_arch = "wasm32"), allow(unused_variables))]
    fn sync(&self, node: NodeRef) {
        #[cfg(target_arch = "wasm32")]
        if let Some(sel) = node.as_element::<web_sys::HtmlSelectElement>() {
            for i in 0..sel.length() {
                if let Some(opt) = sel.item(i) {
                    let value = js_sys::Reflect::get(&opt, &"value".into())
                        .ok()
                        .and_then(|v| v.as_string())
                        .unwrap_or_default();
                    let on = self.0.contains(&value);
                    let _ = js_sys::Reflect::set(&opt, &"selected".into(), &on.into());
                }
            }
        }
    }
}

impl Element {
    /// `bind:value={x}`: show `x` and write what's typed back to it.
    pub fn bind_value(self, x: impl BindValue) -> Self {
        let current = x.current();
        self.prop("value", current)
            .on("input", move |e| x.input(e.value()))
            .on("blur", move |_| x.blur())
    }

    /// `bind:checked={x}`, for a checkbox.
    pub fn bind_checked(self, x: impl BindChecked) -> Self {
        let on = x.checked();
        self.prop("checked", on)
            .on("change", move |e| x.set_checked(e.checked()))
    }

    /// `bind:group={x}`, for a radio button whose `value` is `value`.
    pub fn bind_group(self, x: impl BindValue, value: impl ToString) -> Self {
        let value = value.to_string();
        let on = x.current() == value;
        self.prop("checked", on).on("change", move |e| {
            if e.checked() {
                x.input(value.clone());
                x.blur();
            }
        })
    }

    /// `bind:selected={x}`, for a `<select multiple>`.
    pub fn bind_selected(self, x: impl BindSelected) -> Self {
        let chosen = x.selected();
        self.directive(SelectSync(chosen))
            .on("change", move |e| x.set_selected(e.selected()))
    }
}
