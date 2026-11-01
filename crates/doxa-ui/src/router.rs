//! Pages and navigation: `#[page("/widgets/{name}")]`, `<Link>`, and `navigate`.

use std::cell::RefCell;
use std::future::IntoFuture;
use std::marker::PhantomData;
use std::rc::Rc;

use futures_util::future::LocalBoxFuture;
use percent_encoding_lite::{decode, encode};

use crate::component::{required, Component, RenderFuture, Set, Unset};
use crate::runtime::{self, Readers};
use crate::view::{comp, el, SafeUrl};
use crate::{IntoView, View};

/// A page: a component reached at a path. Write it with `#[page("/path/{param}")]`.
pub trait Page: Component {
    /// The path template.
    const PATH: &'static str;
    /// Props from the matched path, or `None` if a segment doesn't parse.
    fn parse(segments: &Segments) -> Option<Self::Props>;
    /// The page's data, fetched ahead of navigation by `<Link>`.
    fn load(_props: &Self::Props) -> Option<Prefetch> {
        None
    }
}

/// The matched path's parameters and query.
#[derive(Debug, Default, Clone)]
pub struct Segments {
    params: Vec<(String, String)>,
    query: Vec<(String, String)>,
}

impl Segments {
    /// A path parameter.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// A query parameter.
    pub fn query(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Match `path` against `template`.
pub fn match_path(template: &str, url: &str) -> Option<Segments> {
    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    let mut params = Vec::new();
    let mut t = template
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty());
    let mut p = path.trim_matches('/').split('/').filter(|s| !s.is_empty());
    loop {
        match (t.next(), p.next()) {
            (None, None) => break,
            (Some(seg), rest) if seg.starts_with("{*") => {
                let mut tail: Vec<&str> = rest.into_iter().collect();
                tail.extend(p.by_ref());
                params.push((seg[2..seg.len() - 1].to_owned(), decode(&tail.join("/"))));
                break;
            }
            (Some(seg), Some(actual)) if seg.starts_with('{') => {
                params.push((seg[1..seg.len() - 1].to_owned(), decode(actual)));
            }
            (Some(seg), Some(actual)) if seg == actual => {}
            _ => return None,
        }
    }
    let query = query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (decode(k), decode(v))
        })
        .collect();
    Some(Segments { params, query })
}

/// A concrete URL in the app, from `SomePage::route(…)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route(String);

impl Route {
    /// Fill `template` with `params` by name.
    pub fn fill(template: &str, params: &[(&str, &str)]) -> Route {
        let mut out = String::new();
        for seg in template.split('/').filter(|s| !s.is_empty()) {
            out.push('/');
            let name = seg
                .trim_start_matches('{')
                .trim_start_matches('*')
                .trim_end_matches('}');
            match params.iter().find(|(k, _)| *k == name) {
                Some((_, v)) if seg.starts_with('{') => out.push_str(&encode(v)),
                _ => out.push_str(seg),
            }
        }
        if out.is_empty() {
            out.push('/');
        }
        Route(out)
    }

    /// Add a query parameter.
    pub fn query(mut self, key: &str, value: &str) -> Route {
        self.0.push(if self.0.contains('?') { '&' } else { '?' });
        self.0.push_str(&encode(key));
        self.0.push('=');
        self.0.push_str(&encode(value));
        self
    }

    /// The URL.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<Route> for SafeUrl {
    fn from(r: Route) -> SafeUrl {
        SafeUrl::parse(&r.0).expect("app routes are relative paths")
    }
}

impl From<&str> for Route {
    fn from(s: &str) -> Route {
        Route(s.to_owned())
    }
}

/// Data a page needs, fetched ahead of time.
pub struct Prefetch(LocalBoxFuture<'static, ()>);

impl Prefetch {
    /// Prefetch by awaiting `call` and discarding the result; the cache keeps it.
    pub fn of<F: IntoFuture + 'static>(call: F) -> Prefetch {
        let fut = call.into_future();
        Prefetch(Box::pin(async move {
            let _ = fut.await;
        }))
    }
}

type Matcher = fn(&Segments) -> Option<(View, Option<Prefetch>)>;

/// The app's pages.
#[derive(Clone, Default)]
pub struct Router {
    pages: Vec<(&'static str, Matcher)>,
    not_found: Option<Rc<dyn Fn() -> View>>,
}

impl Router {
    /// No pages yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a page.
    pub fn page<P: Page>(mut self) -> Self {
        self.pages.push((P::PATH, |s| {
            let props = P::parse(s)?;
            let load = P::load(&props);
            // Keyed by params too, so `/w/a` → `/w/b` remounts rather than keeping a's state.
            let key = (P::PATH, &s.params);
            Some((comp::<P>(props).key(key).into_view(), load))
        }));
        self
    }

    /// What to show when no page matches.
    pub fn not_found<V: IntoView>(mut self, f: impl Fn() -> V + 'static) -> Self {
        self.not_found = Some(Rc::new(move || f().into_view()));
        self
    }

    fn resolve(&self, url: &str) -> Option<(View, Option<Prefetch>)> {
        self.pages
            .iter()
            .find_map(|(template, m)| match_path(template, url).and_then(|s| m(&s)))
    }

    pub(crate) fn view(&self) -> View {
        let url = location();
        match self.resolve(&url) {
            Some((view, _)) => view,
            None => self.not_found.as_ref().map(|f| f()).unwrap_or_default(),
        }
    }

    pub(crate) fn prefetch(&self, url: &str) {
        if let Some((_, Some(Prefetch(fut)))) = self.resolve(url) {
            doxa_client::task::spawn(fut);
        }
    }
}

struct LocationCell {
    url: String,
    readers: Readers,
}

thread_local! {
    static LOCATION: RefCell<LocationCell> = RefCell::new(LocationCell { url: initial_url(), readers: Readers::default() });
    static ROUTER: RefCell<Option<Router>> = const { RefCell::new(None) };
}

pub(crate) fn install(router: Router) {
    ROUTER.with(|r| *r.borrow_mut() = Some(router));
    #[cfg(target_arch = "wasm32")]
    web::listen_popstate();
}

pub(crate) fn installed() -> Option<Router> {
    ROUTER.with(|r| r.borrow().clone())
}

/// The current path and query; the calling component re-renders when it changes.
pub fn location() -> String {
    LOCATION.with(|l| {
        let mut l = l.borrow_mut();
        l.readers.track();
        l.url.clone()
    })
}

pub(crate) fn set_location(url: String) {
    let readers = LOCATION.with(|l| {
        let mut l = l.borrow_mut();
        l.url = url;
        l.readers.live()
    });
    runtime::schedule_all(readers);
}

/// Go to `to`, adding a history entry.
pub fn navigate(to: impl Into<Route>) {
    let to = to.into();
    #[cfg(target_arch = "wasm32")]
    web::push(&to.0);
    set_location(to.0);
}

fn initial_url() -> String {
    #[cfg(target_arch = "wasm32")]
    {
        web::current()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        "/".to_owned()
    }
}

#[cfg(target_arch = "wasm32")]
mod web {
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::JsCast;

    pub fn current() -> String {
        let loc = web_sys::window().map(|w| w.location());
        loc.map(|l| {
            format!(
                "{}{}",
                l.pathname().unwrap_or_default(),
                l.search().unwrap_or_default()
            )
        })
        .unwrap_or_else(|| "/".to_owned())
    }

    pub fn push(url: &str) {
        if let Some(h) = web_sys::window().and_then(|w| w.history().ok()) {
            let _ = h.push_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(url));
        }
    }

    pub fn listen_popstate() {
        let Some(w) = web_sys::window() else { return };
        let cb = Closure::<dyn Fn()>::new(|| super::set_location(current()));
        let _ = w.add_event_listener_with_callback("popstate", cb.as_ref().unchecked_ref());
        cb.forget();
    }
}

/// A link to a page that navigates without reloading and prefetches the page's data on hover.
pub struct Link;

/// Props of [`Link`].
#[derive(Clone)]
pub struct LinkProps {
    to: Route,
    class: Option<String>,
    children: View,
}

required!(
    Link_needs_to,
    "`<Link>` is missing the `to` prop",
    "add `to={{SomePage::route(…)}}` to the tag"
);

/// Builds [`LinkProps`].
pub struct LinkBuilder<T> {
    to: Option<Route>,
    class: Option<String>,
    children: View,
    _set: PhantomData<T>,
}

impl Link {
    /// Start building its props.
    pub fn props() -> LinkBuilder<Unset> {
        LinkBuilder {
            to: None,
            class: None,
            children: View::empty(),
            _set: PhantomData,
        }
    }
}

impl<T> LinkBuilder<T> {
    /// Where it goes.
    pub fn to(self, to: impl Into<Route>) -> LinkBuilder<Set> {
        LinkBuilder {
            to: Some(to.into()),
            class: self.class,
            children: self.children,
            _set: PhantomData,
        }
    }

    /// CSS classes for the `<a>`.
    pub fn class(mut self, class: impl Into<String>) -> Self {
        self.class = Some(class.into());
        self
    }

    /// The link text.
    pub fn children(mut self, children: View) -> Self {
        self.children = children;
        self
    }
}

impl<T> LinkBuilder<T> {
    /// Finish; every required prop must be given.
    pub fn build(self) -> LinkProps
    where
        T: Link_needs_to,
    {
        LinkProps {
            to: self.to.expect("set"),
            class: self.class,
            children: self.children,
        }
    }
}

impl Component for Link {
    type Props = LinkProps;
    const NAME: &'static str = "Link";

    fn render(props: LinkProps) -> RenderFuture {
        let to = props.to.clone();
        let hover = props.to.0.clone();
        let a = el("a")
            .url("href", props.to.clone())
            .attr("class", props.class.clone())
            .on("click", move |e| {
                // Modified and non-primary clicks open a new tab or window.
                if e.button() != 0 || e.ctrl_key() || e.meta_key() || e.shift_key() || e.alt_key() {
                    return;
                }
                e.prevent_default();
                navigate(to.clone());
            })
            .on("pointerenter", move |_| {
                if let Some(r) = installed() {
                    r.prefetch(&hover);
                }
            })
            .child(props.children);
        RenderFuture::ready(Ok(a.into_view()))
    }
}

mod percent_encoding_lite {
    pub fn encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char)
                }
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }

    pub fn decode(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'%' if i + 2 < bytes.len() => match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push(hi << 4 | lo);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                },
                b'+' => {
                    out.push(b' ');
                    i += 1;
                }
                b => {
                    out.push(b);
                    i += 1;
                }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn hex(b: u8) -> Option<u8> {
        (b as char).to_digit(16).map(|d| d as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_template_matches_and_captures() {
        let s = match_path("/widgets/{name}", "/widgets/a%20b?tab=x").unwrap();
        assert_eq!(s.get("name"), Some("a b"));
        assert_eq!(s.query("tab"), Some("x"));
        assert!(match_path("/widgets/{name}", "/widgets").is_none());
        assert!(match_path("/widgets/{name}", "/gadgets/x").is_none());
        let s = match_path("/files/{*path}", "/files/a/b/c").unwrap();
        assert_eq!(s.get("path"), Some("a/b/c"));
    }

    #[test]
    fn a_route_fills_its_template() {
        assert_eq!(
            Route::fill("/widgets/{name}", &[("name", "a b")]).as_str(),
            "/widgets/a%20b"
        );
        assert_eq!(Route::fill("/", &[]).as_str(), "/");
    }
}
