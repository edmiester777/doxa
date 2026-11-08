//! React components in doxa views, declared with `#[react]`. Each island is a portal
//! inside the nearest island around it, or of one shared root, so React context flows
//! through doxa components; a small JS runtime that `doxa build` ships owns the root.

use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::component::RenderFuture;
use crate::dom::{NodeRef, Phase};
use crate::portal::Portal;
use crate::runtime::{self, Instance};
use crate::view::{comp, el, Callback, Element, Handler, Node};
use crate::{Event, IntoView, Js, Thrown, View};

/// Where a `#[react]` component's JS lives.
#[derive(Debug)]
pub struct Island {
    /// The Rust name, for diagnostics.
    pub name: &'static str,
    /// The module specifier: an npm package, or `doxa-island:<path>` under the web crate.
    pub module: &'static str,
    /// The export: a name, `default`, or a dotted path such as `Popover.Trigger`.
    pub export: &'static str,
    /// Loaded on first mount, in its own chunk.
    pub lazy: bool,
    #[cfg(target_arch = "wasm32")]
    #[doc(hidden)]
    pub load: fn() -> wasm_bindgen::JsValue,
}

/// What `#[react]` implements on a props struct.
#[doc(hidden)]
pub trait IslandProps: Clone + 'static {
    const ISLAND: Island;
    /// Whether every non-event prop is equal, so React needn't see new props.
    fn same_data(&self, other: &Self) -> bool;
    fn data(&self, out: &mut Data);
    fn events(&self, out: &mut Events);
    /// Its `View` props: slots doxa renders, and elements React renders.
    fn views(&self, _out: &mut Views) {}
    /// Where to publish React's `ref`, for a `#[react(handle = …)]` component given `handle={h}`.
    fn handle(&self) -> Option<HandleSink> {
        None
    }
}

/// An island's non-event props, by React prop name.
pub type Props = serde_json::Map<String, serde_json::Value>;

/// The non-event props: JSON values, raw arrays and feeds.
#[doc(hidden)]
#[derive(Default)]
pub struct Data {
    props: Props,
    raw: Vec<(&'static str, RawData)>,
    feeds: Vec<(&'static str, FeedFns)>,
    js: Vec<(&'static str, JsProp)>,
}

/// A `#[react(js)]` prop's value.
#[derive(Clone, Debug, PartialEq)]
pub enum JsProp {
    /// The value itself.
    One(Js),
    /// A JS array of them, the same array while they are the same values.
    Array(Vec<Js>),
}

/// What a `#[react(js)]` field can be: a [`Js`], a `Vec<Js>`, or an `Option` of one.
pub trait JsField {
    #[doc(hidden)]
    fn js_prop(&self) -> Option<JsProp>;
}

impl JsField for Js {
    fn js_prop(&self) -> Option<JsProp> {
        Some(JsProp::One(self.clone()))
    }
}

impl JsField for Vec<Js> {
    fn js_prop(&self) -> Option<JsProp> {
        Some(JsProp::Array(self.clone()))
    }
}

impl<T: JsField> JsField for Option<T> {
    fn js_prop(&self) -> Option<JsProp> {
        self.as_ref().and_then(T::js_prop)
    }
}

impl Data {
    pub fn set<T: Serialize + ?Sized>(&mut self, name: &'static str, value: &T) {
        let v = serde_json::to_value(value)
            .unwrap_or_else(|e| panic!("React prop `{name}` doesn't serialize: {e}"));
        self.props.insert(name.to_owned(), v);
    }

    /// Every field of `value`, a struct, as a prop of its own.
    pub fn spread<T: Serialize>(&mut self, value: &T) {
        match serde_json::to_value(value) {
            Ok(serde_json::Value::Object(fields)) => self.props.extend(fields),
            Ok(other) => panic!("React props must serialize to an object, not {other}"),
            Err(e) => panic!("React props don't serialize: {e}"),
        }
    }

    /// A `#[react(raw)]` array.
    pub fn raw(&mut self, name: &'static str, value: &impl RawArray) {
        self.raw.push((name, value.raw()));
    }

    /// A `#[react(feed)]` channel.
    pub fn feed<T: Serialize + Clone + 'static>(&mut self, name: &'static str, feed: &Feed<T>) {
        self.feeds.push((name, feed.fns()));
    }

    /// A `#[react(js)]` value, left out when `None`.
    pub fn js(&mut self, name: &'static str, value: &impl JsField) {
        self.js.extend(value.js_prop().map(|v| (name, v)));
    }

    /// Leave the prop out when `None`.
    pub fn opt<T: Serialize>(&mut self, name: &'static str, value: &Option<T>) {
        if let Some(v) = value {
            self.set(name, v);
        }
    }
}

/// An event handler as JS calls it: with the JSON of its first argument.
pub type EventFn = Rc<dyn Fn(&str)>;

/// The event, function and render props.
#[doc(hidden)]
pub struct Events {
    list: Vec<(&'static str, EventFn)>,
    funcs: Vec<(&'static str, FuncFn)>,
    async_funcs: Vec<(&'static str, AsyncFuncFn)>,
    renders: Vec<(&'static str, RenderView)>,
    /// The `renders` React gets as components.
    components: Vec<&'static str>,
    owner: Weak<Instance>,
}

/// A function React calls for a value: `#[react(func)] pub row_id: Func<Row, String>`.
///
/// JS passes one argument as `A`, several as a tuple. A Rust panic in it traps the whole wasm
/// instance, which no error boundary catches.
pub struct Func<A, R>(Rc<dyn Fn(A) -> R>);

impl<A, R> Clone for Func<A, R> {
    fn clone(&self) -> Self {
        Func(self.0.clone())
    }
}

impl<A, R, F: Fn(A) -> R + 'static> From<F> for Func<A, R> {
    fn from(f: F) -> Self {
        Func(Rc::new(f))
    }
}

impl<A, R> Func<A, R> {
    /// Call it from Rust.
    pub fn call(&self, a: A) -> R {
        (self.0)(a)
    }
}

type Pending<R> = futures_util::future::LocalBoxFuture<'static, crate::Result<R>>;

/// A function React awaits: JS gets a `Promise` of `R`, rejected with the error's message.
pub struct AsyncFunc<A, R>(Rc<dyn Fn(A) -> Pending<R>>);

impl<A, R> Clone for AsyncFunc<A, R> {
    fn clone(&self) -> Self {
        AsyncFunc(self.0.clone())
    }
}

impl<A: 'static, R: 'static, F: AsyncFn(A) -> crate::Result<R> + 'static> From<F>
    for AsyncFunc<A, R>
{
    fn from(f: F) -> Self {
        let f = Rc::new(f);
        AsyncFunc(Rc::new(move |a| {
            let f = f.clone();
            Box::pin(async move { f(a).await })
        }))
    }
}

/// A doxa view React places as an element: `#[react(render)] pub cell: Render<(Row, Column)>`.
///
/// It is mounted after React commits, inside this island, so context and `<Catch>` reach it.
pub struct Render<A>(Rc<dyn Fn(A) -> View>);

impl<A> Clone for Render<A> {
    fn clone(&self) -> Self {
        Render(self.0.clone())
    }
}

impl<A, V: IntoView, F: Fn(A) -> V + 'static> From<F> for Render<A> {
    fn from(f: F) -> Self {
        Render(Rc::new(move |a| f(a).into_view()))
    }
}

/// A `#[react(raw)]` array, by element type. Copied once per `Rc` into a JS-owned typed array:
/// a view into wasm memory would be detached the next time memory grows.
#[derive(Clone, Debug)]
pub enum RawData {
    /// `Float64Array`.
    F64(Rc<[f64]>),
    /// `Float32Array`.
    F32(Rc<[f32]>),
    /// `Int32Array`.
    I32(Rc<[i32]>),
    /// `Uint32Array`.
    U32(Rc<[u32]>),
    /// `Uint8Array`.
    U8(Rc<[u8]>),
}

impl RawData {
    /// Which allocation it is; a new one is copied again.
    pub fn id(&self) -> usize {
        match self {
            RawData::F64(r) => Rc::as_ptr(r).cast::<u8>() as usize,
            RawData::F32(r) => Rc::as_ptr(r).cast::<u8>() as usize,
            RawData::I32(r) => Rc::as_ptr(r).cast::<u8>() as usize,
            RawData::U32(r) => Rc::as_ptr(r).cast::<u8>() as usize,
            RawData::U8(r) => Rc::as_ptr(r).cast::<u8>() as usize,
        }
    }
}

/// What a `#[react(raw)]` field can be: an `Rc<[_]>` of numbers.
pub trait RawArray {
    #[doc(hidden)]
    fn raw(&self) -> RawData;
}

macro_rules! raw_array {
    ($($t:ty => $v:ident),*) => {$(
        impl RawArray for Rc<[$t]> {
            fn raw(&self) -> RawData {
                RawData::$v(self.clone())
            }
        }
    )*};
}

raw_array!(f64 => F64, f32 => F32, i32 => I32, u32 => U32, u8 => U8);

type Subscriber<T> = (u64, Rc<dyn Fn(&T)>);

struct FeedInner<T> {
    backlog: RefCell<std::collections::VecDeque<T>>,
    capacity: usize,
    subscribers: RefCell<Vec<Subscriber<T>>>,
    next: Cell<u64>,
}

/// An append-only stream into a React component, e.g. a terminal's output:
/// `#[react(feed)] pub output: Feed<String>`, read in JS as `props.output.subscribe(cb)`.
///
/// It keeps the last `capacity` items, which a new subscriber is given first.
pub struct Feed<T: 'static>(Rc<FeedInner<T>>);

impl<T> Clone for Feed<T> {
    fn clone(&self) -> Self {
        Feed(self.0.clone())
    }
}

impl<T> PartialEq for Feed<T> {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

impl<T: Clone + 'static> Feed<T> {
    /// A feed keeping the last `capacity` items.
    pub fn new(capacity: usize) -> Feed<T> {
        Feed(Rc::new(FeedInner {
            backlog: RefCell::default(),
            capacity,
            subscribers: RefCell::default(),
            next: Cell::new(0),
        }))
    }

    /// Send `item` to every subscriber now, and keep it for later ones.
    pub fn push(&self, item: T) {
        {
            let mut b = self.0.backlog.borrow_mut();
            b.push_back(item.clone());
            while b.len() > self.0.capacity {
                b.pop_front();
            }
        }
        let subs: Vec<_> = self
            .0
            .subscribers
            .borrow()
            .iter()
            .map(|(_, f)| f.clone())
            .collect();
        subs.iter().for_each(|f| f(&item));
    }

    /// Call `f` with the backlog, then with each new item, until [`unsubscribe`](Self::unsubscribe).
    pub fn subscribe(&self, f: impl Fn(&T) + 'static) -> u64 {
        let backlog: Vec<T> = self.0.backlog.borrow().iter().cloned().collect();
        backlog.iter().for_each(&f);
        let id = self.0.next.get() + 1;
        self.0.next.set(id);
        self.0.subscribers.borrow_mut().push((id, Rc::new(f)));
        id
    }

    /// Stop calling a subscriber.
    pub fn unsubscribe(&self, id: u64) {
        self.0.subscribers.borrow_mut().retain(|(i, _)| *i != id);
    }
}

impl<T: Serialize + Clone + 'static> Feed<T> {
    fn fns(&self) -> FeedFns {
        let (a, b) = (self.clone(), self.clone());
        FeedFns {
            id: Rc::as_ptr(&self.0).cast::<u8>() as usize,
            subscribe: Rc::new(move |f: FeedSink| {
                a.subscribe(move |item| {
                    if let Ok(v) = serde_json::to_value(item) {
                        f(v)
                    }
                })
            }),
            unsubscribe: Rc::new(move |id| b.unsubscribe(id)),
        }
    }
}

/// A feed that keeps the last `capacity` items, stable across renders.
#[track_caller]
pub fn feed<T: Clone + 'static>(capacity: usize) -> Feed<T> {
    let (_, _, f) = crate::hooks::slot("feed", || Feed::<T>::new(capacity));
    (*f).clone()
}

/// Where a feed subscriber is sent each item, as JSON.
pub type FeedSink = Rc<dyn Fn(serde_json::Value)>;

/// A [`Feed`] as JS subscribes to it, with items as JSON.
#[derive(Clone)]
pub struct FeedFns {
    /// Which feed it is; the same one keeps its JS subscriber object.
    pub id: usize,
    /// Start delivering items; returns the id to unsubscribe.
    pub subscribe: Rc<dyn Fn(FeedSink) -> u64>,
    /// Stop.
    pub unsubscribe: Rc<dyn Fn(u64)>,
}

/// What a bridge publishes as an island's handle: React's `ref.current`, a `JsValue` in the browser.
pub type RawHandle = Rc<dyn std::any::Any>;

/// Told an island's handle when React commits it, and `None` when it goes.
pub type HandleSink = Rc<dyn Fn(Option<RawHandle>)>;

/// A type `#[react(handle = T)]` can name: built from what React's `ref` points at.
pub trait IslandHandle: Clone + 'static {
    /// `None` if `raw` isn't one.
    fn from_raw(raw: &RawHandle) -> Option<Self>;
}

/// Any JS type, e.g. a `#[wasm_bindgen] extern "C" { type EditorApi; }`, read without an
/// `instanceof` check, since `ref.current` is usually a plain object.
#[cfg(target_arch = "wasm32")]
impl<T: wasm_bindgen::JsCast + Clone + 'static> IslandHandle for T {
    fn from_raw(raw: &RawHandle) -> Option<Self> {
        let v = raw.downcast_ref::<wasm_bindgen::JsValue>()?;
        Some(wasm_bindgen::JsCast::unchecked_into(v.clone()))
    }
}

/// Natively a test's fake bridge publishes the value itself.
#[cfg(not(target_arch = "wasm32"))]
impl<T: Clone + 'static> IslandHandle for T {
    fn from_raw(raw: &RawHandle) -> Option<Self> {
        raw.downcast_ref::<T>().cloned()
    }
}

/// A `#[react(handle = Api)]` component.
pub trait HasHandle {
    /// What its handle is.
    type Api: IslandHandle;
}

struct HandleCell<T> {
    value: Option<T>,
    waiters: Vec<std::task::Waker>,
}

/// An island's imperative handle, from [`handle`]; `Copy`, and reactive: readers re-render
/// when React publishes it.
pub struct Handle<T: 'static>(crate::State<HandleCell<T>>);

impl<T> Clone for Handle<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Handle<T> {}

/// A handle to pass as `handle={h}` to a `#[react(handle = …)]` component `C`.
#[track_caller]
pub fn handle<C: HasHandle>() -> Handle<C::Api> {
    Handle(crate::hooks::state(HandleCell {
        value: None,
        waiters: Vec::new(),
    }))
}

impl<T: IslandHandle> Handle<T> {
    /// The handle, once React has committed the island.
    pub fn get(&self) -> Option<T> {
        self.0.with(|c| c.value.clone())
    }

    /// Wait until React has committed the island, e.g. a lazy one that mounts late.
    pub fn ready(&self) -> impl std::future::Future<Output = T> + 'static {
        let state = self.0;
        std::future::poll_fn(move |cx| {
            let got = state.update_silently(|c| {
                if c.value.is_none() {
                    c.waiters.push(cx.waker().clone());
                }
                c.value.clone()
            });
            match got.flatten() {
                Some(v) => std::task::Poll::Ready(v),
                None => std::task::Poll::Pending,
            }
        })
    }

    #[doc(hidden)]
    pub fn sink(&self) -> HandleSink {
        let state = self.0;
        Rc::new(move |raw: Option<RawHandle>| {
            let value = raw.as_ref().and_then(T::from_raw);
            state.update(|c| {
                c.value = value;
                if c.value.is_some() {
                    c.waiters.drain(..).for_each(std::task::Waker::wake);
                }
            });
        })
    }
}

/// A [`Func`] as JS calls it, with the arguments as JSON.
pub type FuncFn = Rc<dyn Fn(serde_json::Value) -> Result<serde_json::Value, String>>;
/// An [`AsyncFunc`] as JS calls it.
pub type AsyncFuncFn = Rc<
    dyn Fn(
        serde_json::Value,
    ) -> futures_util::future::LocalBoxFuture<'static, Result<serde_json::Value, String>>,
>;
type RenderView = Rc<dyn Fn(serde_json::Value) -> Result<View, String>>;

/// A [`Render`] as JS drives it: a doxa view mounted into, updated in and removed from an element React owns.
#[derive(Clone)]
pub struct RenderFns {
    /// Render into `node` with these arguments; `key` names it after.
    pub mount: Rc<dyn Fn(u32, NodeRef, serde_json::Value)>,
    /// New arguments.
    pub update: Rc<dyn Fn(u32, serde_json::Value)>,
    /// React removed it.
    pub unmount: Rc<dyn Fn(u32)>,
    /// A `#[react(component)]`: React renders it as a component, with its props as the arguments.
    pub component: bool,
}

fn args<A: DeserializeOwned>(name: &str, v: serde_json::Value) -> Result<A, String> {
    serde_json::from_value(v)
        .map_err(|e| format!("React called `{name}` with the wrong arguments: {e}"))
}

impl Events {
    pub fn func<A: DeserializeOwned + 'static, R: Serialize + 'static>(
        &mut self,
        name: &'static str,
        f: &Func<A, R>,
    ) {
        let f = f.clone();
        self.funcs.push((
            name,
            Rc::new(move |v| {
                if runtime::current_instance().is_some() {
                    return Err(format!(
                        "`{name}` was called while doxa was rendering; call it from React instead"
                    ));
                }
                let out = f.call(args(name, v)?);
                serde_json::to_value(out).map_err(|e| format!("`{name}` returned {e}"))
            }),
        ));
    }

    pub fn async_func<A: DeserializeOwned + 'static, R: Serialize + 'static>(
        &mut self,
        name: &'static str,
        f: &AsyncFunc<A, R>,
    ) {
        let f = f.clone();
        self.async_funcs.push((
            name,
            Rc::new(move |v| {
                let call = args(name, v).map(|a| (f.0)(a));
                Box::pin(async move {
                    let out = call?.await.map_err(|e| e.to_string())?;
                    serde_json::to_value(out).map_err(|e| format!("`{name}` returned {e}"))
                })
            }),
        ));
    }

    pub fn render<A: DeserializeOwned + 'static>(&mut self, name: &'static str, r: &Render<A>) {
        let r = r.clone();
        self.renders
            .push((name, Rc::new(move |v| Ok((r.0)(args(name, v)?)))));
    }

    /// [`render`](Self::render), as a component React gives its props.
    pub fn component<P: DeserializeOwned + 'static>(&mut self, name: &'static str, r: &Render<P>) {
        self.render(name, r);
        self.components.push(name);
    }

    pub fn event(&mut self, name: &'static str, cb: &impl ReactEvent) {
        let (cb, owner) = (cb.clone(), self.owner.clone());
        self.list.push((
            name,
            Rc::new(move |json: &str| {
                if let Err(e) = cb.fire(json) {
                    runtime::throw(
                        owner.upgrade().as_ref(),
                        Thrown::msg(format!("React event `{name}`: {e}")),
                    );
                }
            }),
        ));
    }
}

/// A `Callback` React can call: with nothing, or one JSON value.
#[doc(hidden)]
pub trait ReactEvent: Clone + 'static {
    fn fire(&self, json: &str) -> serde_json::Result<()>;
}

impl ReactEvent for Callback<dyn Fn()> {
    fn fire(&self, _: &str) -> serde_json::Result<()> {
        self();
        Ok(())
    }
}

impl<T: DeserializeOwned + 'static> ReactEvent for Callback<dyn Fn(T)> {
    fn fire(&self, json: &str) -> serde_json::Result<()> {
        self(parse(json)?);
        Ok(())
    }
}

/// `T` from `json`, or from `null` for handlers that ignore the argument.
fn parse<T: DeserializeOwned>(json: &str) -> serde_json::Result<T> {
    serde_json::from_str(json).or_else(|e| serde_json::from_str("null").map_err(|_| e))
}

/// The `View` props.
#[doc(hidden)]
#[derive(Default)]
pub struct Views {
    slots: Vec<(&'static str, View)>,
    elements: Vec<(&'static str, View)>,
}

impl Views {
    /// doxa renders `view` into a host React places where the prop goes.
    pub fn slot(&mut self, name: &'static str, view: &View) {
        self.slots.push((name, view.clone()));
    }

    /// [`slot`](Self::slot), leaving the prop out when `None`.
    pub fn slot_opt(&mut self, name: &'static str, view: &Option<View>) {
        if let Some(v) = view {
            self.slot(name, v);
        }
    }

    /// React renders `view`'s element itself, and doxa its children inside it.
    pub fn element(&mut self, name: &'static str, view: &View) {
        self.elements.push((name, view.clone()));
    }
}

/// An element React renders for a `#[react(element)]` prop, from a doxa element's tag,
/// attributes and handlers; doxa renders its children into the node once React commits it.
#[derive(Clone)]
pub struct Shell {
    /// The React prop it is passed as.
    pub prop: &'static str,
    /// The tag.
    pub tag: &'static str,
    /// The attributes, with doxa names (`class`, not `className`).
    pub attrs: Vec<(&'static str, String)>,
    /// The handlers, by DOM event name; each is the same function on every render.
    pub events: Vec<(&'static str, ShellHandler)>,
    /// Call with the element React rendered, and with `None` when React removes it.
    pub node: NodeFn,
}

/// A shell's handler, called with the browser event.
pub type ShellHandler = Rc<dyn Fn(Event)>;

/// Told the element React rendered for a shell, or `None` once it's gone.
pub type NodeFn = Rc<dyn Fn(Option<NodeRef>)>;

impl Shell {
    fn same(&self, other: &Shell) -> bool {
        self.prop == other.prop
            && self.tag == other.tag
            && self.attrs == other.attrs
            && self
                .events
                .iter()
                .map(|e| e.0)
                .eq(other.events.iter().map(|e| e.0))
    }
}

/// What React renders for an island, on mount and on each update.
pub struct Content {
    /// The non-event props.
    pub props: Props,
    /// Hosts doxa renders each slot prop into, for React to place.
    pub slots: Vec<(&'static str, NodeRef)>,
    /// Elements for React to render.
    pub shells: Vec<Shell>,
    /// `#[react(raw)]` arrays, copied into JS typed arrays.
    pub raw: Vec<(&'static str, RawData)>,
    /// `#[react(feed)]` channels.
    pub feeds: Vec<(&'static str, FeedFns)>,
    /// `#[react(js)]` values.
    pub js: Vec<(&'static str, JsProp)>,
}

/// An island for the bridge to render.
pub struct Mount<'a> {
    /// Names it in `update` and `unmount`.
    pub id: u32,
    /// The nearest island around it in the doxa tree, whose React context it gets.
    pub parent: Option<u32>,
    /// The [root](crate::RootHandle::id) it is mounted under.
    pub root: u64,
    /// The element to render into.
    pub host: NodeRef,
    /// Its module and export.
    pub island: &'a Island,
    /// Its props.
    pub content: &'a Content,
    /// Its event props.
    pub events: Vec<(&'static str, EventFn)>,
    /// Call with a message when the island throws while React renders it.
    pub on_error: EventFn,
    /// Its [`Func`] props.
    pub funcs: Vec<(&'static str, FuncFn)>,
    /// Its [`AsyncFunc`] props.
    pub async_funcs: Vec<(&'static str, AsyncFuncFn)>,
    /// Its [`Render`] props.
    pub renders: Vec<(&'static str, RenderFns)>,
    /// Where to publish React's `ref.current`, if it was given a handle.
    pub on_handle: Option<HandleSink>,
}

/// The JS side of islands. [`set_bridge`] swaps it, e.g. for a fake in native tests.
pub trait Bridge {
    /// Render an island; a child may mount before its parent.
    fn mount(&self, island: Mount<'_>);
    /// Give a mounted island new props.
    fn update(&self, id: u32, content: &Content);
    /// Remove an island's portal.
    fn unmount(&self, id: u32);
}

/// Passed down the doxa tree so a nested island knows the island around it.
#[derive(Clone)]
struct Parent(u32);

fn next_id() -> u32 {
    thread_local!(static NEXT: Cell<u32> = const { Cell::new(0) });
    NEXT.with(|n| {
        n.set(n.get() + 1);
        n.get()
    })
}

thread_local! {
    static BRIDGE: RefCell<Option<Rc<dyn Bridge>>> = const { RefCell::new(None) };
}

/// Use `bridge` for islands mounted from now on, on this thread.
pub fn set_bridge(bridge: impl Bridge + 'static) {
    BRIDGE.with(|b| *b.borrow_mut() = Some(Rc::new(bridge)));
}

fn bridge() -> Rc<dyn Bridge> {
    BRIDGE.with(|b| b.borrow_mut().get_or_insert_with(default_bridge).clone())
}

#[cfg(target_arch = "wasm32")]
fn default_bridge() -> Rc<dyn Bridge> {
    Rc::new(web::WebBridge::default())
}

/// Natively nothing runs React, so islands render as their empty host.
#[cfg(not(target_arch = "wasm32"))]
fn default_bridge() -> Rc<dyn Bridge> {
    struct Inert;
    impl Bridge for Inert {
        fn mount(&self, _: Mount<'_>) {}
        fn update(&self, _: u32, _: &Content) {}
        fn unmount(&self, _: u32) {}
    }
    Rc::new(Inert)
}

type Shared<T> = Rc<RefCell<T>>;
/// A shell handler's stable function and the cell it reads this render's handler from.
type ShellEvent = ((&'static str, &'static str), Shared<Handler>, Handler);

/// What React was last given, to skip updates that change nothing.
struct Sent<P> {
    props: P,
    slots: Vec<(&'static str, NodeRef)>,
    shells: Vec<Shell>,
}

struct Live<P> {
    id: u32,
    parent: Option<u32>,
    root: u64,
    /// The island's instance, where a React error is thrown.
    owner: Weak<Instance>,
    host: Cell<Option<NodeRef>>,
    events: Targets<EventFn>,
    funcs: Targets<FuncFn>,
    async_funcs: Targets<AsyncFuncFn>,
    renders: Targets<RenderView>,
    components: RefCell<Vec<&'static str>>,
    /// Each `Render` React has mounted: its key, prop, element and arguments.
    rendered: crate::State<Vec<Rendered>>,
    shell_events: RefCell<Vec<ShellEvent>>,
    /// This render's `handle={…}`.
    handle: Shared<Option<HandleSink>>,
    shell_nodes: RefCell<Vec<(&'static str, NodeFn)>>,
    slots: RefCell<Vec<(&'static str, NodeRef)>>,
    /// This render's props and shells.
    latest: RefCell<Option<(P, Vec<Shell>)>>,
    sent: RefCell<Option<Sent<P>>>,
}

/// Stable cells, by prop, each pointed at this render's function.
type Targets<T> = RefCell<Vec<(&'static str, Shared<T>)>>;

type Rendered = (u32, &'static str, NodeRef, serde_json::Value);

struct Forwarders {
    funcs: Vec<(&'static str, FuncFn)>,
    async_funcs: Vec<(&'static str, AsyncFuncFn)>,
    renders: Vec<(&'static str, RenderFns)>,
}

fn retarget<T>(targets: &Targets<T>, list: Vec<(&'static str, T)>) {
    let mut slots = targets.borrow_mut();
    for (name, f) in list {
        match slots.iter().find(|(n, _)| *n == name) {
            Some((_, slot)) => *slot.borrow_mut() = f,
            None => slots.push((name, Rc::new(RefCell::new(f)))),
        }
    }
}

impl<P: IslandProps> Live<P> {
    fn retarget(&self, e: Events) {
        retarget(&self.events, e.list);
        retarget(&self.funcs, e.funcs);
        retarget(&self.async_funcs, e.async_funcs);
        retarget(&self.renders, e.renders);
        *self.components.borrow_mut() = e.components;
    }

    /// The functions React gets: each calls whichever function the latest render passed.
    fn forwarders(&self) -> Forwarders {
        let funcs = self
            .funcs
            .borrow()
            .iter()
            .map(|(name, cell)| {
                let cell = cell.clone();
                let f: FuncFn = Rc::new(move |v| {
                    let f = cell.borrow().clone();
                    f(v)
                });
                (*name, f)
            })
            .collect();
        let async_funcs = self
            .async_funcs
            .borrow()
            .iter()
            .map(|(name, cell)| {
                let cell = cell.clone();
                let f: AsyncFuncFn = Rc::new(move |v| {
                    let f = cell.borrow().clone();
                    f(v)
                });
                (*name, f)
            })
            .collect();
        let rendered = self.rendered;
        let components = self.components.borrow();
        let renders = self
            .renders
            .borrow()
            .iter()
            .map(|(name, _)| {
                let name = *name;
                let fns = RenderFns {
                    mount: Rc::new(move |key, node, args| {
                        rendered.update(|r| r.push((key, name, node, args)))
                    }),
                    update: Rc::new(move |key, args| {
                        let changed =
                            rendered.with(|r| r.iter().any(|e| e.0 == key && e.3 != args));
                        if changed {
                            rendered.update(|r| {
                                if let Some(e) = r.iter_mut().find(|e| e.0 == key) {
                                    e.3 = args;
                                }
                            })
                        }
                    }),
                    unmount: Rc::new(move |key| rendered.update(|r| r.retain(|e| e.0 != key))),
                    component: components.contains(&name),
                };
                (name, fns)
            })
            .collect();
        Forwarders {
            funcs,
            async_funcs,
            renders,
        }
    }

    /// The stable function for a shell's handler, pointed at `h`.
    fn shell_handler(&self, key: (&'static str, &'static str), h: Handler) -> Handler {
        let mut all = self.shell_events.borrow_mut();
        if let Some((_, cell, f)) = all.iter().find(|(k, ..)| *k == key) {
            *cell.borrow_mut() = h;
            return f.clone();
        }
        let cell = Rc::new(RefCell::new(h));
        let c = cell.clone();
        let f: Handler = Rc::new(move |e| {
            let h = c.borrow().clone();
            h(e)
        });
        all.push((key, cell, f.clone()));
        f
    }

    fn shell_node(&self, prop: &'static str, make: impl FnOnce() -> NodeFn) -> NodeFn {
        let mut all = self.shell_nodes.borrow_mut();
        if let Some((_, f)) = all.iter().find(|(p, _)| *p == prop) {
            return f.clone();
        }
        let f = make();
        all.push((prop, f.clone()));
        f
    }

    fn content(&self) -> Option<(P, Content)> {
        let (props, shells) = self.latest.borrow().clone()?;
        let mut d = Data::default();
        props.data(&mut d);
        let content = Content {
            props: d.props,
            slots: self.slots.borrow().clone(),
            shells,
            raw: d.raw,
            feeds: d.feeds,
            js: d.js,
        };
        Some((props, content))
    }

    fn mount(&self, host: NodeRef) {
        let Some((props, content)) = self.content() else {
            return;
        };
        let forwarders = self
            .events
            .borrow()
            .iter()
            .map(|(name, slot)| {
                let slot = slot.clone();
                let f: EventFn = Rc::new(move |json| {
                    let f = slot.borrow().clone();
                    f(json)
                });
                (*name, f)
            })
            .collect();
        let (owner, name) = (self.owner.clone(), P::ISLAND.name);
        let Forwarders {
            funcs,
            async_funcs,
            renders,
        } = self.forwarders();
        bridge().mount(Mount {
            id: self.id,
            parent: self.parent,
            root: self.root,
            host,
            island: &P::ISLAND,
            content: &content,
            events: forwarders,
            funcs,
            async_funcs,
            renders,
            on_handle: self.handle.borrow().is_some().then(|| {
                let cell = self.handle.clone();
                let sink: HandleSink = Rc::new(move |raw| {
                    let h = cell.borrow().clone();
                    if let Some(h) = h {
                        h(raw)
                    }
                });
                sink
            }),
            on_error: Rc::new(move |message: &str| {
                runtime::throw(
                    owner.upgrade().as_ref(),
                    Thrown::msg(format!("<{name}> threw in React: {message}")),
                )
            }),
        });
        self.host.set(Some(host));
        self.record(props, content);
    }

    fn record(&self, props: P, content: Content) {
        *self.sent.borrow_mut() = Some(Sent {
            props,
            slots: content.slots,
            shells: content.shells,
        });
    }

    /// Send React what changed since the last mount or update.
    fn resend(&self) {
        if self.host.get().is_none() {
            return;
        }
        let Some((props, content)) = self.content() else {
            return;
        };
        let same = self.sent.borrow().as_ref().is_some_and(|s| {
            s.props.same_data(&props)
                && s.slots == content.slots
                && s.shells.len() == content.shells.len()
                && s.shells.iter().zip(&content.shells).all(|(a, b)| a.same(b))
        });
        if !same {
            bridge().update(self.id, &content);
            self.record(props, content);
        }
    }

    fn on(&self, phase: Phase, host: NodeRef) {
        match phase {
            Phase::Mounted => self.mount(host),
            Phase::Patched => self.resend(),
            Phase::Unmounting => {
                if self.host.take().is_some() {
                    bridge().unmount(self.id);
                    self.sent.borrow_mut().take();
                }
            }
        }
    }

    fn on_slot(&self, name: &'static str, phase: Phase, node: NodeRef) {
        match phase {
            Phase::Mounted => self.slots.borrow_mut().push((name, node)),
            Phase::Unmounting => self.slots.borrow_mut().retain(|(n, _)| *n != name),
            Phase::Patched => return,
        }
        self.resend();
    }
}

/// `view` as one element, through any one-child fragments around it.
fn single_element(node: &Node) -> Option<Rc<Element>> {
    match node {
        Node::Element(e) => Some(e.clone()),
        Node::Fragment(f) if f.len() == 1 => single_element(&f[0]),
        _ => None,
    }
}

/// The render of a `#[react]` component: an empty host the bridge renders into.
#[doc(hidden)]
pub fn render<P: IslandProps>(props: P) -> RenderFuture {
    let me = crate::runtime::current_or_panic("island");
    let targets = crate::hooks::state(Vec::<(&'static str, NodeRef)>::new());
    let rendered = crate::hooks::state(Vec::<Rendered>::new());
    let (inst, _, live) = crate::hooks::slot("island", || Live::<P> {
        id: next_id(),
        parent: crate::hooks::try_context::<Parent>().map(|p| p.0),
        root: me.root_id(),
        owner: Rc::downgrade(&me),
        host: Cell::new(None),
        events: RefCell::default(),
        funcs: RefCell::default(),
        async_funcs: RefCell::default(),
        renders: RefCell::default(),
        components: RefCell::default(),
        rendered,
        shell_events: RefCell::default(),
        handle: Rc::default(),
        shell_nodes: RefCell::default(),
        slots: RefCell::default(),
        latest: RefCell::new(None),
        sent: RefCell::new(None),
    });
    crate::hooks::provide(Parent(live.id));
    let mut events = Events {
        list: Vec::new(),
        funcs: Vec::new(),
        async_funcs: Vec::new(),
        renders: Vec::new(),
        components: Vec::new(),
        owner: Rc::downgrade(&inst),
    };
    props.events(&mut events);
    live.retarget(events);
    *live.handle.borrow_mut() = props.handle();

    let mut views = Views::default();
    props.views(&mut views);
    let mut children: Vec<View> = Vec::new();
    // Each `Render` React mounted, as a portal into its element so it sits inside this island.
    for (key, prop, node, args) in rendered.get() {
        let f = live
            .renders
            .borrow()
            .iter()
            .find(|(n, _)| *n == prop)
            .map(|(_, c)| c.borrow().clone());
        let view = match f.map(|f| f(args)) {
            Some(Ok(v)) => v,
            Some(Err(e)) => return RenderFuture::ready(Err(Thrown::msg(e))),
            None => continue,
        };
        let portal = Portal::props().to(node).children(view).build();
        children.push(comp::<Portal>(portal).key(key).into_view());
    }
    // Slot hosts mount before the island host, so their nodes are known by then.
    for (name, view) in views.slots {
        let live = live.clone();
        // Keyed, so an optional slot appearing doesn't shift the hosts after it.
        // Hidden until the runtime adopts it: React may never render this prop.
        let slot = el("div")
            .key(name)
            .attr("data-island-slot", name)
            .attr("style", "display: none")
            .lifecycle(move |phase, node| live.on_slot(name, phase, node))
            .child(view);
        children.push(slot.into_view());
    }
    let mut shells = Vec::new();
    for (prop, view) in views.elements {
        let Some(e) = single_element(&view.0) else {
            return RenderFuture::ready(Err(Thrown::msg(format!(
                "<{}>: the `{prop}` element prop takes one element, e.g. `{{view! {{ <button/> }}}}`",
                P::ISLAND.name
            ))));
        };
        let node = live.shell_node(prop, || {
            Rc::new(move |n: Option<NodeRef>| {
                targets.update(|t| {
                    t.retain(|(p, _)| *p != prop);
                    t.extend(n.map(|n| (prop, n)));
                })
            })
        });
        shells.push(Shell {
            prop,
            tag: e.tag,
            attrs: e.flat_attrs(),
            events: e
                .events
                .iter()
                .map(|(name, _, h)| (*name, live.shell_handler((prop, name), h.clone())))
                .collect(),
            node,
        });
        let at = targets.with(|t| t.iter().find(|(p, _)| *p == prop).map(|(_, n)| *n));
        if let Some(at) = at {
            let inner = View(Node::Fragment(e.children.clone().into()));
            let portal = Portal::props().to(at).children(inner).build();
            children.push(comp::<Portal>(portal).into_view());
        }
    }
    *live.latest.borrow_mut() = Some((props, shells));
    let host = el("div")
        .attr("data-island", P::ISLAND.name)
        .attr("style", "display: contents")
        .child(children.into_iter().collect::<View>())
        .lifecycle(move |phase, node| live.on(phase, node));
    RenderFuture::ready(Ok(host.into_view()))
}

/// A doxa event handed the browser event React's synthetic one wraps.
#[cfg(target_arch = "wasm32")]
fn web_event(e: web_sys::Event) -> Event {
    Event {
        inner: crate::dom::EventInner::Web(e),
    }
}

#[cfg(target_arch = "wasm32")]
mod web {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use wasm_bindgen::prelude::*;
    use wasm_bindgen::JsCast;

    use std::rc::Rc;

    use super::{Bridge, Content, Mount};
    use crate::dom::NodeRef;

    #[wasm_bindgen(module = "doxa-react:runtime")]
    extern "C" {
        #[wasm_bindgen(js_name = mount)]
        fn js_mount(
            id: u32,
            parent: Option<u32>,
            host: &web_sys::Node,
            component: &JsValue,
            content: &JsValue,
            events: &js_sys::Object,
            on_error: &JsValue,
            calls: &JsValue,
            on_handle: &JsValue,
            root: f64,
        );
        #[wasm_bindgen(js_name = update)]
        fn js_update(id: u32, content: &JsValue);
        #[wasm_bindgen(js_name = unmount)]
        fn js_unmount(id: u32);
    }

    /// One island's JS functions, by key, so each is created once and React sees it unchanged.
    #[derive(Default)]
    struct Functions {
        events: Vec<Closure<dyn Fn(String)>>,
        shells: HashMap<String, JsValue>,
        /// Typed arrays and feed subscribers by prop, with the identity they were made from.
        made: HashMap<&'static str, (usize, JsValue)>,
        /// `#[react(js)]` arrays by prop, with the values they hold.
        arrays: HashMap<&'static str, (Vec<crate::Js>, JsValue)>,
        keep: Vec<Box<dyn std::any::Any>>,
    }

    fn typed(raw: &super::RawData) -> JsValue {
        use super::RawData;
        // Each `from` copies into memory JS owns.
        match raw {
            RawData::F64(r) => js_sys::Float64Array::from(&r[..]).into(),
            RawData::F32(r) => js_sys::Float32Array::from(&r[..]).into(),
            RawData::I32(r) => js_sys::Int32Array::from(&r[..]).into(),
            RawData::U32(r) => js_sys::Uint32Array::from(&r[..]).into(),
            RawData::U8(r) => js_sys::Uint8Array::from(&r[..]).into(),
        }
    }

    /// `{ subscribe(cb) }`, returning a function that unsubscribes.
    fn subscriber(fns: &super::FeedFns, keep: &mut Vec<Box<dyn std::any::Any>>) -> JsValue {
        let fns = fns.clone();
        let c = Closure::<dyn Fn(js_sys::Function) -> JsValue>::new(move |cb: js_sys::Function| {
            let id = (fns.subscribe)(Rc::new(move |v| {
                let _ = cb.call1(&JsValue::NULL, &to_value(&v));
            }));
            let unsubscribe = fns.unsubscribe.clone();
            Closure::once_into_js(move || unsubscribe(id))
        });
        let obj: JsValue = js_sys::Object::new().into();
        set(&obj, "subscribe", c.as_ref());
        keep.push(Box::new(c));
        obj
    }

    /// Islands rendered by the shipped runtime, keeping each one's functions alive.
    #[derive(Default)]
    pub(super) struct WebBridge(RefCell<HashMap<u32, Functions>>);

    fn set(obj: &JsValue, key: &str, value: &JsValue) {
        let _ = js_sys::Reflect::set(obj, &JsValue::from_str(key), value);
    }

    impl WebBridge {
        /// `{ props, slots: { name: node }, shells: [{ prop, tag, attrs, events, ref }] }`.
        fn to_js(&self, id: u32, c: &Content) -> JsValue {
            use serde::Serialize;
            let out: JsValue = js_sys::Object::new().into();
            let props = c
                .props
                .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
                .unwrap_or(JsValue::NULL);
            set(&out, "props", &props);
            let slots: JsValue = js_sys::Object::new().into();
            for (name, node) in &c.slots {
                if let Some(n) = node.raw() {
                    set(&slots, name, &n);
                }
            }
            set(&out, "slots", &slots);
            let mut all = self.0.borrow_mut();
            let f = all.entry(id).or_default();
            let shells = js_sys::Array::new();
            for s in &c.shells {
                let shell: JsValue = js_sys::Object::new().into();
                set(&shell, "prop", &s.prop.into());
                set(&shell, "tag", &s.tag.into());
                let attrs: JsValue = js_sys::Object::new().into();
                for (k, v) in &s.attrs {
                    set(&attrs, k, &v.as_str().into());
                }
                set(&shell, "attrs", &attrs);
                let events: JsValue = js_sys::Object::new().into();
                for (name, h) in &s.events {
                    let key = format!("{}:on:{name}", s.prop);
                    let js = f.shells.entry(key).or_insert_with(|| {
                        let h = h.clone();
                        let c = Closure::<dyn Fn(web_sys::Event)>::new(move |e: web_sys::Event| {
                            h(super::web_event(e))
                        });
                        let v = c.as_ref().clone();
                        f.keep.push(Box::new(c));
                        v
                    });
                    set(&events, name, js);
                }
                set(&shell, "events", &events);
                let key = format!("{}:ref", s.prop);
                let r = f.shells.entry(key).or_insert_with(|| {
                    let node = s.node.clone();
                    let c = Closure::<dyn Fn(JsValue)>::new(move |el: JsValue| {
                        let n = el.dyn_into::<web_sys::Node>().ok().and_then(|n| {
                            crate::runtime::try_dom()?.adopt(n).map(NodeRef::from_id)
                        });
                        node(n)
                    });
                    let v = c.as_ref().clone();
                    f.keep.push(Box::new(c));
                    v
                });
                set(&shell, "ref", r);
                shells.push(&shell);
            }
            set(&out, "shells", &shells);
            let raw: JsValue = js_sys::Object::new().into();
            for (name, data) in &c.raw {
                let id = data.id();
                let v = match f.made.get(name) {
                    Some((made, v)) if *made == id => v.clone(),
                    _ => {
                        let v = typed(data);
                        f.made.insert(name, (id, v.clone()));
                        v
                    }
                };
                set(&raw, name, &v);
            }
            set(&out, "raw", &raw);
            let feeds: JsValue = js_sys::Object::new().into();
            for (name, fns) in &c.feeds {
                let v = match f.made.get(name) {
                    Some((made, v)) if *made == fns.id => v.clone(),
                    _ => {
                        let v = subscriber(fns, &mut f.keep);
                        f.made.insert(name, (fns.id, v.clone()));
                        v
                    }
                };
                set(&feeds, name, &v);
            }
            set(&out, "feeds", &feeds);
            let js: JsValue = js_sys::Object::new().into();
            for (name, value) in &c.js {
                let v = match value {
                    super::JsProp::One(v) => v.as_ref().clone(),
                    super::JsProp::Array(items) => match f.arrays.get(name) {
                        Some((had, v)) if had == items => v.clone(),
                        _ => {
                            let v = JsValue::from(crate::Js::array(items.iter().cloned()));
                            f.arrays.insert(name, (items.clone(), v.clone()));
                            v
                        }
                    },
                };
                set(&js, name, &v);
            }
            set(&out, "js", &js);
            out
        }
    }

    fn to_value(v: &serde_json::Value) -> JsValue {
        use serde::Serialize;
        v.serialize(&serde_wasm_bindgen::Serializer::json_compatible())
            .unwrap_or(JsValue::UNDEFINED)
    }

    fn from_value(v: JsValue) -> serde_json::Value {
        serde_wasm_bindgen::from_value(v).unwrap_or(serde_json::Value::Null)
    }

    /// `{ funcs: { name: fn }, asyncFuncs: { name: fn }, renders: { name: { mount, update, unmount, component } } }`.
    fn calls(
        funcs: Vec<(&'static str, super::FuncFn)>,
        async_funcs: Vec<(&'static str, super::AsyncFuncFn)>,
        renders: Vec<(&'static str, super::RenderFns)>,
        keep: &mut Vec<Box<dyn std::any::Any>>,
    ) -> JsValue {
        let out: JsValue = js_sys::Object::new().into();
        let f: JsValue = js_sys::Object::new().into();
        for (name, func) in funcs {
            let c =
                Closure::<dyn Fn(JsValue) -> Result<JsValue, JsValue>>::new(move |v: JsValue| {
                    func(from_value(v))
                        .map(|r| to_value(&r))
                        .map_err(|e| js_sys::Error::new(&e).into())
                });
            set(&f, name, c.as_ref());
            keep.push(Box::new(c));
        }
        set(&out, "funcs", &f);
        let a: JsValue = js_sys::Object::new().into();
        for (name, func) in async_funcs {
            let c = Closure::<dyn Fn(JsValue) -> js_sys::Promise>::new(move |v: JsValue| {
                let fut = func(from_value(v));
                wasm_bindgen_futures::future_to_promise(async move {
                    fut.await
                        .map(|r| to_value(&r))
                        .map_err(|e| js_sys::Error::new(&e).into())
                })
            });
            set(&a, name, c.as_ref());
            keep.push(Box::new(c));
        }
        set(&out, "asyncFuncs", &a);
        let r: JsValue = js_sys::Object::new().into();
        for (name, fns) in renders {
            let o: JsValue = js_sys::Object::new().into();
            let mount = fns.mount;
            let c = Closure::<dyn Fn(u32, JsValue, JsValue)>::new(move |key, el: JsValue, args| {
                let node = el
                    .dyn_into::<web_sys::Node>()
                    .ok()
                    .and_then(|n| crate::runtime::try_dom()?.adopt(n));
                if let Some(n) = node {
                    mount(key, NodeRef::from_id(n), from_value(args));
                }
            });
            set(&o, "mount", c.as_ref());
            keep.push(Box::new(c));
            let update = fns.update;
            let c = Closure::<dyn Fn(u32, JsValue)>::new(move |key, args| {
                update(key, from_value(args))
            });
            set(&o, "update", c.as_ref());
            keep.push(Box::new(c));
            let unmount = fns.unmount;
            let c = Closure::<dyn Fn(u32)>::new(move |key| unmount(key));
            set(&o, "unmount", c.as_ref());
            keep.push(Box::new(c));
            set(&o, "component", &JsValue::from_bool(fns.component));
            set(&r, name, &o);
        }
        set(&out, "renders", &r);
        out
    }

    impl Bridge for WebBridge {
        fn mount(&self, m: Mount<'_>) {
            let host = m.host.raw().expect("an island's host is in the document");
            let content = self.to_js(m.id, m.content);
            let obj = js_sys::Object::new();
            let mut events: Vec<_> = m
                .events
                .into_iter()
                .map(|(name, f)| {
                    let c = Closure::<dyn Fn(String)>::new(move |json: String| f(&json));
                    set(&obj, name, c.as_ref());
                    c
                })
                .collect();
            let on_error = m.on_error;
            let on_error = Closure::<dyn Fn(String)>::new(move |msg: String| on_error(&msg));
            let mut keep: Vec<Box<dyn std::any::Any>> = Vec::new();
            let calls = calls(m.funcs, m.async_funcs, m.renders, &mut keep);
            let on_handle = match m.on_handle {
                Some(sink) => {
                    let c = Closure::<dyn Fn(JsValue)>::new(move |v: JsValue| {
                        let raw = (!v.is_null() && !v.is_undefined())
                            .then(|| Rc::new(v) as super::RawHandle);
                        sink(raw)
                    });
                    let f = c.as_ref().clone();
                    keep.push(Box::new(c));
                    f
                }
                None => JsValue::UNDEFINED,
            };
            let component = (m.island.load)();
            js_mount(
                m.id,
                m.parent,
                &host,
                &component,
                &content,
                &obj,
                on_error.as_ref(),
                &calls,
                &on_handle,
                m.root as f64,
            );
            events.push(on_error);
            self.0
                .borrow_mut()
                .entry(m.id)
                .or_default()
                .keep
                .extend(keep);
            self.0.borrow_mut().entry(m.id).or_default().events = events;
        }

        fn update(&self, id: u32, content: &Content) {
            js_update(id, &self.to_js(id, content));
        }

        fn unmount(&self, id: u32) {
            js_unmount(id);
            self.0.borrow_mut().remove(&id);
        }
    }
}
