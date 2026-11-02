//! Hooks onto the browser outside the rendered tree: window and document events, timers,
//! observers, storage, media queries, broadcast channels, and the clipboard, download and
//! fullscreen helpers. Each hook's registration ends when its component unmounts.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use doxa_client::Download;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub use doxa_client::clock::{now, sleep};

use crate::dom::{Event, Global, Listen, NodeRef, Observe, Observed, Rect};
use crate::hooks::{effect, slot, state, state_with, ElementRef, State};
use crate::{runtime, Result};

/// A registration with the current [`Dom`](crate::Dom), ended when dropped.
struct Registration(u32);

impl Drop for Registration {
    fn drop(&mut self) {
        if let Some(d) = runtime::try_dom() {
            d.stop(self.0);
        }
    }
}

/// Keep `r` until the effect holding this future is dropped.
async fn hold(r: Registration) -> Result<()> {
    let _r = r;
    std::future::pending::<()>().await;
    Ok(())
}

type Latest<A> = Rc<RefCell<Rc<dyn Fn(A)>>>;

/// This render's `f`, readable from callbacks registered on an earlier render.
#[track_caller]
fn latest<A: 'static>(f: Rc<dyn Fn(A)>) -> Latest<A> {
    let (_, _, cell) = slot("latest", || RefCell::new(f.clone()));
    *cell.borrow_mut() = f;
    cell
}

/// Call `handler` for every `event` on `window`, e.g. `keydown` for a shortcut.
#[track_caller]
pub fn window_event(event: &'static str, handler: impl Fn(Event) + 'static) {
    on_global(Global::Window, event, handler);
}

/// Call `handler` for every `event` on `document`, e.g. `visibilitychange`.
#[track_caller]
pub fn document_event(event: &'static str, handler: impl Fn(Event) + 'static) {
    on_global(Global::Document, event, handler);
}

#[track_caller]
fn on_global(target: Global, event: &'static str, handler: impl Fn(Event) + 'static) {
    let latest = latest::<Event>(Rc::new(handler));
    effect(&event, async move |event: &&'static str| {
        let call = Rc::new(move |e: Event| {
            let h = latest.borrow().clone();
            h(e)
        });
        let id = runtime::dom().listen_global(target, event, Listen::default(), call);
        hold(Registration(id)).await
    });
}

/// Call `f` every `every`, starting one period after mount.
#[track_caller]
pub fn interval(every: Duration, f: impl Fn() + 'static) {
    let f = latest::<()>(Rc::new(move |()| f()));
    effect(&every, async move |every: &Duration| -> Result<()> {
        loop {
            sleep(*every).await;
            let g = f.borrow().clone();
            g(());
        }
    });
}

/// `value`, once it has stayed the same for `wait`.
#[track_caller]
pub fn debounced<T: Clone + PartialEq + 'static>(value: T, wait: Duration) -> T {
    let out = state(value.clone());
    effect(&value, async move |v: &T| {
        sleep(wait).await;
        if out.with(|o| o != v) {
            out.set(v.clone());
        }
        Ok(())
    });
    out.get()
}

/// The element's box, updated as it resizes; `None` until the first report.
#[track_caller]
pub fn resize_observer(el: ElementRef) -> State<Option<Rect>> {
    let size = state(None);
    observe(el, Observe::Resize, move |o| {
        if size.get() != Some(o.rect) {
            size.set(Some(o.rect));
        }
    });
    size
}

/// Whether any of the element is in the viewport.
#[track_caller]
pub fn intersection(el: ElementRef) -> State<bool> {
    let seen = state(false);
    observe(el, Observe::Intersection, move |o| {
        if seen.get() != o.intersecting {
            seen.set(o.intersecting);
        }
    });
    seen
}

#[track_caller]
fn observe(el: ElementRef, what: Observe, f: impl Fn(Observed) + 'static) {
    let f: Rc<dyn Fn(Observed)> = Rc::new(f);
    effect(&el.get(), async move |node: &Option<NodeRef>| {
        let Some(n) = *node else { return Ok(()) };
        hold(Registration(runtime::dom().observe(n.id(), what, f))).await
    });
}

/// Whether a media query matches, e.g. `"(prefers-color-scheme: dark)"`.
#[track_caller]
pub fn media_query(query: &'static str) -> bool {
    let matches = state_with(|| runtime::dom().media_matches(query));
    effect(&query, async move |query: &&'static str| {
        let set = move |now: bool| {
            if matches.get() != now {
                matches.set(now);
            }
        };
        let dom = runtime::dom();
        set(dom.media_matches(query));
        hold(Registration(dom.watch_media(query, Rc::new(set)))).await
    });
    matches.get()
}

/// A [`State`] kept in `localStorage` as JSON, and updated when another tab changes it.
pub struct Stored<T: 'static> {
    state: State<T>,
    key: &'static str,
}

impl<T> Clone for Stored<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Stored<T> {}

/// State persisted under `key`; `init` is used when nothing valid is stored.
#[track_caller]
pub fn stored<T: Serialize + DeserializeOwned + 'static>(
    key: &'static str,
    init: impl FnOnce() -> T,
) -> Stored<T> {
    let state = state_with(|| read(key).unwrap_or_else(init));
    effect(&key, async move |key: &&'static str| {
        let key = *key;
        let changed = Rc::new(move |e: Event| {
            if e.key() == key {
                if let Some(v) = read(key) {
                    state.set(v);
                }
            }
        });
        let id =
            runtime::dom().listen_global(Global::Window, "storage", Listen::default(), changed);
        hold(Registration(id)).await
    });
    Stored { state, key }
}

fn read<T: DeserializeOwned>(key: &str) -> Option<T> {
    serde_json::from_str(&runtime::dom().storage_get(key)?).ok()
}

impl<T: Serialize + 'static> Stored<T> {
    /// Read the value without cloning it.
    pub fn with<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        self.state.with(f)
    }

    /// Replace the value, store it and re-render.
    pub fn set(&self, value: T) {
        self.store(&value);
        self.state.set(value);
    }

    /// Change the value in place, store it and re-render.
    pub fn update(&self, f: impl FnOnce(&mut T)) {
        self.state.update(f);
        self.state.with(|v| self.store(v));
    }

    fn store(&self, v: &T) {
        if let Ok(json) = serde_json::to_string(v) {
            runtime::dom().storage_set(self.key, Some(&json));
        }
    }
}

impl<T: Serialize + Clone + 'static> Stored<T> {
    /// A copy of the value.
    pub fn get(&self) -> T {
        self.state.get()
    }
}

/// Messages to and from every other [`broadcast`] of the same name, in any tab of this origin.
pub struct Broadcast<T: 'static> {
    last: State<Option<T>>,
    chan: Rc<Channel>,
}

impl<T> Clone for Broadcast<T> {
    fn clone(&self) -> Self {
        Broadcast {
            last: self.last,
            chan: self.chan.clone(),
        }
    }
}

/// A `BroadcastChannel` named `name`; the component re-renders on each message it receives.
#[track_caller]
pub fn broadcast<T: Serialize + DeserializeOwned + 'static>(name: &'static str) -> Broadcast<T> {
    let last = state(None::<T>);
    let (_, _, chan) = slot("broadcast", || {
        Channel::open(
            name,
            Rc::new(move |msg: &str| {
                if let Ok(v) = serde_json::from_str(msg) {
                    last.set(Some(v));
                }
            }),
        )
    });
    Broadcast { last, chan }
}

impl<T: Serialize + 'static> Broadcast<T> {
    /// Send `value` to the other channels; this one doesn't receive it.
    pub fn send(&self, value: &T) {
        if let Ok(json) = serde_json::to_string(value) {
            self.chan.post(json);
        }
    }
}

impl<T: Clone + 'static> Broadcast<T> {
    /// The latest message received.
    pub fn last(&self) -> Option<T> {
        self.last.get()
    }
}

type Deliver = Rc<dyn Fn(&str)>;
#[cfg(not(target_arch = "wasm32"))]
type Subscriber = (u64, &'static str, Deliver);
#[cfg(target_arch = "wasm32")]
type WebChannel = (
    web_sys::BroadcastChannel,
    wasm_bindgen::closure::Closure<dyn Fn(web_sys::MessageEvent)>,
);

#[cfg(not(target_arch = "wasm32"))]
thread_local! {
    static BUS: RefCell<(u64, Vec<Subscriber>)> = RefCell::default();
}

struct Channel {
    #[cfg(not(target_arch = "wasm32"))]
    id: u64,
    #[cfg(not(target_arch = "wasm32"))]
    name: &'static str,
    #[cfg(target_arch = "wasm32")]
    web: Option<WebChannel>,
}

impl Channel {
    #[cfg(not(target_arch = "wasm32"))]
    fn open(name: &'static str, deliver: Deliver) -> Channel {
        BUS.with(|b| {
            let mut b = b.borrow_mut();
            b.0 += 1;
            let id = b.0;
            b.1.push((id, name, deliver));
            Channel { id, name }
        })
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn post(&self, msg: String) {
        let to: Vec<Deliver> = BUS.with(|b| {
            b.borrow()
                .1
                .iter()
                .filter(|(id, n, _)| *id != self.id && *n == self.name)
                .map(|(.., d)| d.clone())
                .collect()
        });
        doxa_client::task::spawn(async move { to.iter().for_each(|d| d(&msg)) });
    }

    #[cfg(target_arch = "wasm32")]
    fn open(name: &'static str, deliver: Deliver) -> Channel {
        use wasm_bindgen::JsCast;
        let web = web_sys::BroadcastChannel::new(name).ok().map(|bc| {
            let cb = wasm_bindgen::closure::Closure::<dyn Fn(web_sys::MessageEvent)>::new(
                move |e: web_sys::MessageEvent| {
                    if let Some(s) = e.data().as_string() {
                        deliver(&s);
                    }
                },
            );
            bc.set_onmessage(Some(cb.as_ref().unchecked_ref()));
            (bc, cb)
        });
        Channel { web }
    }

    #[cfg(target_arch = "wasm32")]
    fn post(&self, msg: String) {
        if let Some((bc, _)) = &self.web {
            let _ = bc.post_message(&msg.into());
        }
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        #[cfg(not(target_arch = "wasm32"))]
        BUS.with(|b| b.borrow_mut().1.retain(|(id, ..)| *id != self.id));
        #[cfg(target_arch = "wasm32")]
        if let Some((bc, _)) = &self.web {
            bc.set_onmessage(None);
            bc.close();
        }
    }
}

/// Why a browser helper couldn't do its job, e.g. permission was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserError(pub String);

impl std::fmt::Display for BrowserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BrowserError {}

#[cfg(target_arch = "wasm32")]
impl From<wasm_bindgen::JsValue> for BrowserError {
    fn from(v: wasm_bindgen::JsValue) -> Self {
        BrowserError(v.as_string().unwrap_or_else(|| format!("{v:?}")))
    }
}

/// Writing to the system clipboard.
pub mod clipboard {
    use super::BrowserError;

    /// What to put on the clipboard: text, and optionally HTML for rich paste targets.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Clip {
        /// The `text/plain` form.
        pub text: String,
        /// The `text/html` form.
        pub html: Option<String>,
    }

    impl Clip {
        /// Plain text.
        pub fn text(text: impl Into<String>) -> Clip {
            Clip {
                text: text.into(),
                html: None,
            }
        }

        /// Add an HTML form.
        pub fn html(mut self, html: impl Into<String>) -> Clip {
            self.html = Some(html.into());
            self
        }
    }

    /// Put `clip` on the clipboard; browsers allow this only during a user gesture.
    pub async fn write(clip: Clip) -> Result<(), BrowserError> {
        #[cfg(target_arch = "wasm32")]
        {
            web::write(clip).await
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            super::mem::CLIP.with(|c| *c.borrow_mut() = Some(clip));
            Ok(())
        }
    }

    #[cfg(target_arch = "wasm32")]
    mod web {
        use js_sys::{Array, Function, Object, Promise, Reflect};
        use wasm_bindgen::{JsCast, JsValue};

        use super::{BrowserError, Clip};

        // The async Clipboard API is behind web-sys's unstable APIs.
        pub async fn write(clip: Clip) -> Result<(), BrowserError> {
            let nav = web_sys::window()
                .ok_or(BrowserError("no window".into()))?
                .navigator();
            let cb = Reflect::get(&nav, &"clipboard".into())?;
            let promise = match &clip.html {
                None => method(&cb, "writeText")?.call1(&cb, &clip.text.as_str().into())?,
                Some(html) => {
                    let types = Object::new();
                    Reflect::set(
                        &types,
                        &"text/plain".into(),
                        &blob(&clip.text, "text/plain")?,
                    )?;
                    Reflect::set(&types, &"text/html".into(), &blob(html, "text/html")?)?;
                    let ctor: Function =
                        Reflect::get(&js_sys::global(), &"ClipboardItem".into())?.dyn_into()?;
                    let item = Reflect::construct(&ctor, &Array::of1(&types))?;
                    method(&cb, "write")?.call1(&cb, &Array::of1(&item))?
                }
            };
            wasm_bindgen_futures::JsFuture::from(promise.dyn_into::<Promise>()?).await?;
            Ok(())
        }

        fn method(obj: &JsValue, name: &str) -> Result<Function, BrowserError> {
            Ok(Reflect::get(obj, &name.into())?.dyn_into()?)
        }

        fn blob(text: &str, ty: &str) -> Result<JsValue, BrowserError> {
            let bag = web_sys::BlobPropertyBag::new();
            bag.set_type(ty);
            Ok(
                web_sys::Blob::new_with_str_sequence_and_options(&Array::of1(&text.into()), &bag)?
                    .into(),
            )
        }
    }
}

/// Offer `file` to the user as a download, under its suggested name.
pub fn save(file: Download) -> std::result::Result<(), BrowserError> {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::JsCast;
        let bytes = js_sys::Uint8Array::from(file.bytes.as_slice());
        let bag = web_sys::BlobPropertyBag::new();
        if let Some(t) = &file.content_type {
            bag.set_type(t);
        }
        let blob = web_sys::Blob::new_with_u8_array_sequence_and_options(
            &js_sys::Array::of1(&bytes),
            &bag,
        )?;
        let url = web_sys::Url::create_object_url_with_blob(&blob)?;
        let doc = web_sys::window()
            .and_then(|w| w.document())
            .ok_or(BrowserError("no document".into()))?;
        let a: web_sys::HtmlAnchorElement = doc
            .create_element("a")?
            .dyn_into()
            .map_err(|_| BrowserError("no anchor element".into()))?;
        a.set_href(&url);
        a.set_download(file.filename.as_deref().unwrap_or("download"));
        a.click();
        // Revoking in the same task can cancel the download in some browsers.
        doxa_client::task::spawn(async move {
            sleep(Duration::from_secs(1)).await;
            let _ = web_sys::Url::revoke_object_url(&url);
        });
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        mem::SAVED.with(|s| s.borrow_mut().push(file));
        Ok(())
    }
}

/// Show `node` fullscreen; browsers allow this only during a user gesture.
pub async fn fullscreen(node: NodeRef) -> std::result::Result<(), BrowserError> {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::JsCast;
        let el = node
            .as_element::<web_sys::Element>()
            .ok_or(BrowserError("not an element".into()))?;
        let request: js_sys::Function =
            js_sys::Reflect::get(&el, &"requestFullscreen".into())?.dyn_into()?;
        let promise: js_sys::Promise = request.call0(&el)?.dyn_into()?;
        wasm_bindgen_futures::JsFuture::from(promise).await?;
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = node;
        Err(BrowserError("fullscreen needs a browser".into()))
    }
}

/// Leave fullscreen, if anything is fullscreen.
pub fn exit_fullscreen() {
    #[cfg(target_arch = "wasm32")]
    if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
        if doc.fullscreen_element().is_some() {
            doc.exit_fullscreen();
        }
    }
}

/// Where the native clipboard and downloads land, for [`MemDom`](crate::MemDom).
pub(crate) mod mem {
    use std::cell::RefCell;

    use doxa_client::Download;

    use super::clipboard::Clip;

    thread_local! {
        pub(super) static CLIP: RefCell<Option<Clip>> = const { RefCell::new(None) };
        pub(super) static SAVED: RefCell<Vec<Download>> = const { RefCell::new(Vec::new()) };
    }

    pub fn clipboard() -> Option<Clip> {
        CLIP.with(|c| c.borrow().clone())
    }

    pub fn downloads() -> Vec<Download> {
        SAVED.with(|s| std::mem::take(&mut *s.borrow_mut()))
    }
}
