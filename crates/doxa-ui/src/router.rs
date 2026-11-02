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
    match_template(template, url, false)
}

/// `prefix`: `url` may continue past the end of `template`.
fn match_template(template: &str, url: &str, prefix: bool) -> Option<Segments> {
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
            (None, Some(_)) if prefix => break,
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
    Some(Segments {
        params,
        query: parse_query(query),
    })
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

impl From<String> for Route {
    fn from(s: String) -> Route {
        Route(s)
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

    fn both(a: Option<Prefetch>, b: Option<Prefetch>) -> Option<Prefetch> {
        match (a, b) {
            (Some(Prefetch(a)), Some(Prefetch(b))) => Some(Prefetch(Box::pin(async move {
                futures_util::future::join(a, b).await;
            }))),
            (a, b) => a.or(b),
        }
    }
}

type Resolved = Option<(View, Option<Prefetch>)>;
type Matcher = fn(&Segments) -> Resolved;
type Wrap = fn(&Segments, View) -> Resolved;
type Guard = Rc<dyn Fn(String) -> LocalBoxFuture<'static, Option<Route>>>;

#[derive(Clone)]
enum Entry {
    Page(&'static str, Matcher),
    Layout {
        prefix: &'static str,
        wrap: Wrap,
        inner: Router,
    },
    Redirect(&'static str, Route),
}

/// What stays on screen while the next page's data loads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Keep {
    /// Switch at once; the new page shows its own loading state.
    #[default]
    Nothing,
    /// Keep the current page until the next page's `load` resolves; see [`navigation`].
    Previous,
}

/// The app's pages.
#[derive(Clone, Default)]
pub struct Router {
    entries: Vec<Entry>,
    not_found: Option<Rc<dyn Fn() -> View>>,
    guards: Vec<Guard>,
    keep: Keep,
}

impl Router {
    /// No pages yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a page.
    pub fn page<P: Page>(mut self) -> Self {
        self.entries.push(Entry::Page(P::PATH, |s| {
            let props = P::parse(s)?;
            let load = P::load(&props);
            // Keyed by params too, so `/w/a` → `/w/b` remounts rather than keeping a's state.
            let key = (P::PATH, &s.params);
            Some((comp::<P>(props).key(key).into_view(), load))
        }));
        self
    }

    /// Add pages under `L`, a page whose path prefixes theirs and which shows them at `<Outlet/>`.
    /// `L` stays mounted while its children change, and remounts when its own params do.
    pub fn layout<L: Page>(mut self, children: impl FnOnce(Router) -> Router) -> Self {
        let inner = children(Router::new());
        for template in inner.templates() {
            assert!(
                under(L::PATH, template),
                "`{template}` isn't under the layout `{}` at `{}`",
                L::NAME,
                L::PATH
            );
        }
        self.entries.push(Entry::Layout {
            prefix: L::PATH,
            wrap: |s, child| {
                let props = L::parse(s)?;
                let load = L::load(&props);
                let inner = comp::<L>(props).into_view();
                let host = comp::<LayoutHost>(HostProps { inner, child });
                Some((host.key((L::PATH, &s.params)).into_view(), load))
            },
            inner,
        });
        self
    }

    /// Send `from` to `to`, replacing the history entry.
    pub fn redirect(mut self, from: &'static str, to: impl Into<Route>) -> Self {
        self.entries.push(Entry::Redirect(from, to.into()));
        self
    }

    /// Before showing any page of this router, ask `check`; a route it returns is gone to instead.
    pub fn guard<F>(mut self, check: F) -> Self
    where
        F: AsyncFn(&str) -> Option<Route> + 'static,
    {
        let check = Rc::new(check);
        self.guards.push(Rc::new(move |url: String| {
            let check = check.clone();
            Box::pin(async move { check(&url).await })
        }));
        self
    }

    /// What to show while the next page loads.
    pub fn transitions(mut self, keep: Keep) -> Self {
        self.keep = keep;
        self
    }

    fn templates(&self) -> Vec<&'static str> {
        self.entries
            .iter()
            .flat_map(|e| match e {
                Entry::Page(t, _) | Entry::Redirect(t, _) => vec![*t],
                Entry::Layout { prefix, inner, .. } => {
                    let mut all = vec![*prefix];
                    all.extend(inner.templates());
                    all
                }
            })
            .collect()
    }

    /// What to show when no page matches.
    pub fn not_found<V: IntoView>(mut self, f: impl Fn() -> V + 'static) -> Self {
        self.not_found = Some(Rc::new(move || f().into_view()));
        self
    }

    fn resolve(&self, url: &str) -> Resolved {
        self.entries.iter().find_map(|e| match e {
            Entry::Page(template, m) => match_path(template, url).and_then(|s| m(&s)),
            Entry::Layout {
                prefix,
                wrap,
                inner,
            } => {
                let s = match_template(prefix, url, true)?;
                let (child, load) = inner.resolve(url)?;
                let (view, own) = wrap(&s, child)?;
                Some((view, Prefetch::both(own, load)))
            }
            Entry::Redirect(..) => None,
        })
    }

    /// Where `url` redirects, following up to a few hops.
    fn redirected(&self, mut url: String) -> String {
        for _ in 0..8 {
            match self.redirect_of(&url) {
                Some(to) => url = to.0,
                None => break,
            }
        }
        url
    }

    fn redirect_of(&self, url: &str) -> Option<Route> {
        self.entries.iter().find_map(|e| match e {
            Entry::Redirect(from, to) => match_path(from, url).map(|_| to.clone()),
            Entry::Layout { prefix, inner, .. } => {
                match_template(prefix, url, true).and_then(|_| inner.redirect_of(url))
            }
            Entry::Page(..) => None,
        })
    }

    /// The guards of every router on the way to the page `url` shows.
    fn guards_for(&self, url: &str) -> Vec<Guard> {
        let mut out = self.guards.clone();
        for e in &self.entries {
            match e {
                Entry::Page(t, m) if match_path(t, url).and_then(|s| m(&s)).is_some() => break,
                Entry::Layout { prefix, inner, .. }
                    if match_template(prefix, url, true).is_some()
                        && inner.resolve(url).is_some() =>
                {
                    out.extend(inner.guards_for(url));
                    break;
                }
                _ => {}
            }
        }
        out
    }

    pub(crate) fn view(&self) -> View {
        let url = location();
        // Until the first URL's guards pass, nothing behind them shows.
        if NAV.with(|n| n.borrow().starting) {
            return View::empty();
        }
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

fn under(prefix: &str, template: &str) -> bool {
    let segments = |t: &str| {
        t.split('/')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    segments(template).starts_with(&segments(prefix))
}

/// Gives a layout's `<Outlet/>` the matched child.
struct LayoutHost;

#[derive(Clone)]
struct HostProps {
    inner: View,
    child: View,
}

#[derive(Clone)]
struct OutletChild(View);

impl Component for LayoutHost {
    type Props = HostProps;
    const NAME: &'static str = "Layout";

    fn render(props: HostProps) -> RenderFuture {
        crate::hooks::provide(OutletChild(props.child));
        RenderFuture::ready(Ok(props.inner))
    }
}

/// Where a layout shows the page under it; nothing outside a layout.
pub struct Outlet;

/// Props of [`Outlet`]: none.
#[derive(Clone)]
pub struct OutletProps;

/// Builds [`OutletProps`].
pub struct OutletBuilder;

impl Outlet {
    /// Start building its props.
    pub fn props() -> OutletBuilder {
        OutletBuilder
    }
}

impl OutletBuilder {
    /// Finish.
    pub fn build(self) -> OutletProps {
        OutletProps
    }
}

impl Component for Outlet {
    type Props = OutletProps;
    const NAME: &'static str = "Outlet";

    fn render(_: OutletProps) -> RenderFuture {
        let child = crate::hooks::try_context::<OutletChild>();
        RenderFuture::ready(Ok(child.map(|c| c.0).unwrap_or_default()))
    }
}

struct LocationCell {
    url: String,
    readers: Readers,
}

#[derive(Default)]
struct NavCell {
    to: Option<String>,
    generation: u64,
    /// The first URL's guards haven't answered yet.
    starting: bool,
    readers: Readers,
    blockers: Vec<(u64, &'static str)>,
    next_blocker: u64,
}

thread_local! {
    static LOCATION: RefCell<LocationCell> = RefCell::new(LocationCell { url: initial_url(), readers: Readers::default() });
    static ROUTER: RefCell<Option<Router>> = const { RefCell::new(None) };
    static NAV: RefCell<NavCell> = RefCell::default();
}

pub(crate) fn install(router: Router) {
    ROUTER.with(|r| *r.borrow_mut() = Some(router));
    #[cfg(target_arch = "wasm32")]
    web::listen_popstate();
    go(current_url(), Nav::replace(), Origin::Start);
}

fn current_url() -> String {
    LOCATION.with(|l| l.borrow().url.clone())
}

/// How [`navigate_with`] changes history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nav {
    replace: bool,
    keep_scroll: bool,
}

impl Nav {
    /// Add a history entry; the default.
    pub fn push() -> Nav {
        Nav {
            replace: false,
            keep_scroll: false,
        }
    }

    /// Replace the current history entry.
    pub fn replace() -> Nav {
        Nav {
            replace: true,
            keep_scroll: false,
        }
    }

    /// Leave the scroll position alone instead of going to the top.
    pub fn keep_scroll(mut self) -> Nav {
        self.keep_scroll = true;
        self
    }
}

#[derive(Debug, Clone, Copy)]
enum Origin {
    /// `navigate`: history hasn't moved yet.
    App,
    /// Back or forward: history already moved; restore this scroll position.
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    Pop(Option<f64>),
    /// The URL the app loaded at.
    Start,
}

/// Run redirects and guards, wait for the page if [`Keep::Previous`], then show `url`.
fn go(url: String, mut nav: Nav, origin: Origin) {
    let generation = NAV.with(|n| {
        let mut n = n.borrow_mut();
        n.generation += 1;
        n.generation
    });
    let Some(router) = installed() else {
        return commit(url, nav, origin);
    };
    let url = {
        let to = router.redirected(url.clone());
        nav.replace |= to != url;
        to
    };
    if router.guards_for(&url).is_empty() && router.keep == Keep::Nothing {
        return commit(url, nav, origin);
    }
    set_pending(Some(url.clone()), matches!(origin, Origin::Start));
    doxa_client::task::spawn(async move {
        let mut url = url;
        'hops: for _ in 0..8 {
            for g in router.guards_for(&url) {
                if let Some(to) = g(url.clone()).await {
                    url = router.redirected(to.0);
                    nav.replace = true;
                    continue 'hops;
                }
            }
            break;
        }
        let current = || NAV.with(|n| n.borrow().generation) == generation;
        if !current() {
            return;
        }
        if router.keep == Keep::Previous {
            if let Some((_, Some(Prefetch(load)))) = router.resolve(&url) {
                load.await;
            }
            if !current() {
                return;
            }
        }
        set_pending(None, false);
        commit(url, nav, origin);
    });
}

#[cfg_attr(not(target_arch = "wasm32"), allow(unused_variables))]
fn commit(url: String, nav: Nav, origin: Origin) {
    #[cfg(target_arch = "wasm32")]
    match origin {
        Origin::App => web::write(&url, nav.replace),
        Origin::Pop(_) | Origin::Start if url != web::current() => web::write(&url, true),
        _ => {}
    }
    set_location(url);
    #[cfg(target_arch = "wasm32")]
    web::scroll(match origin {
        Origin::Pop(y) => y,
        Origin::Start => None,
        Origin::App => (!nav.keep_scroll).then_some(0.0),
    });
}

fn set_pending(to: Option<String>, starting: bool) {
    let readers = NAV.with(|n| {
        let mut n = n.borrow_mut();
        n.to = to;
        n.starting = starting;
        n.readers.live()
    });
    runtime::schedule_all(readers);
}

/// Where the app is navigating to, while redirects, guards or [`Keep::Previous`] hold it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Navigation {
    to: Option<String>,
}

impl Navigation {
    /// Whether a navigation hasn't finished.
    pub fn pending(&self) -> bool {
        self.to.is_some()
    }

    /// The URL being gone to.
    pub fn to(&self) -> Option<&str> {
        self.to.as_deref()
    }
}

/// The navigation in progress; the calling component re-renders when it changes.
pub fn navigation() -> Navigation {
    NAV.with(|n| {
        let mut n = n.borrow_mut();
        n.readers.track();
        Navigation { to: n.to.clone() }
    })
}

/// While `when`, ask the user to confirm `message` before leaving: in-app, back/forward, or the tab.
#[track_caller]
pub fn block_navigation(when: bool, message: &'static str) {
    crate::hooks::effect(
        &(when, message),
        async move |&(when, message): &(bool, &'static str)| {
            if !when {
                return Ok(());
            }
            let id = NAV.with(|n| {
                let mut n = n.borrow_mut();
                n.next_blocker += 1;
                let id = n.next_blocker;
                n.blockers.push((id, message));
                id
            });
            let unload = runtime::dom().listen_global(
                crate::dom::Global::Window,
                "beforeunload",
                crate::dom::Listen::default(),
                Rc::new(|e: crate::Event| e.prevent_default()),
            );
            crate::browser::hold((Unblock(id), crate::browser::Registration(unload))).await
        },
    );
}

struct Unblock(u64);

impl Drop for Unblock {
    fn drop(&mut self) {
        let _ = NAV.try_with(|n| n.borrow_mut().blockers.retain(|(id, _)| *id != self.0));
    }
}

/// Whether leaving is allowed, asking the latest blocker if there is one.
fn allowed() -> bool {
    match NAV.with(|n| n.borrow().blockers.last().map(|(_, m)| *m)) {
        None => true,
        Some(message) => runtime::try_dom().is_none_or(|d| d.confirm(message)),
    }
}

/// Go to `to` instead: return `Err(redirect(to))` from a page. No `<Catch>` sees it.
pub fn redirect(to: impl Into<Route>) -> crate::Thrown {
    crate::Thrown::from(Redirect(to.into()))
}

#[derive(Debug)]
struct Redirect(Route);

impl std::fmt::Display for Redirect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "redirect to {}", self.0 .0)
    }
}

impl std::error::Error for Redirect {}

/// If `e` is a [`redirect`], go there and return true.
pub(crate) fn follow_redirect(e: &crate::Thrown) -> bool {
    let Some(Redirect(to)) = e.downcast_ref::<Redirect>() else {
        return false;
    };
    let to = to.0.clone();
    doxa_client::task::spawn(async move { go(to, Nav::replace(), Origin::App) });
    true
}

/// The current query, to edit with [`set_query`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query(Vec<(String, String)>);

impl Query {
    /// A parameter's value.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Set `key`, replacing any value it had.
    pub fn set(&mut self, key: &str, value: impl ToString) -> &mut Query {
        let value = value.to_string();
        match self.0.iter_mut().find(|(k, _)| k == key) {
            Some(kv) => kv.1 = value,
            None => self.0.push((key.to_owned(), value)),
        }
        self
    }

    /// Remove `key`.
    pub fn remove(&mut self, key: &str) -> &mut Query {
        self.0.retain(|(k, _)| k != key);
        self
    }
}

/// Edit the current URL's query in place, replacing the history entry and keeping the scroll.
pub fn set_query(edit: impl FnOnce(&mut Query) -> &mut Query) {
    let url = current_url();
    let (path, query) = url.split_once('?').unwrap_or((&url, ""));
    let mut q = Query(parse_query(query));
    edit(&mut q);
    let route =
        q.0.iter()
            .fold(Route(path.to_owned()), |r, (k, v)| r.query(k, v));
    navigate_with(route, Nav::replace().keep_scroll());
}

fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (decode(k), decode(v))
        })
        .collect()
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
    navigate_with(to, Nav::push());
}

/// Go to `to`, e.g. with `Nav::replace()`; a [`block_navigation`] may refuse.
pub fn navigate_with(to: impl Into<Route>, nav: Nav) {
    if allowed() {
        go(to.into().0, nav, Origin::App);
    }
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
    use wasm_bindgen::{JsCast, JsValue};

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

    const SCROLL: &str = "doxaScroll";

    /// Push or replace `url`, first recording the scroll position on the entry being left.
    pub fn write(url: &str, replace: bool) {
        let Some(w) = web_sys::window() else { return };
        let Ok(h) = w.history() else { return };
        if replace {
            let state = h.state().unwrap_or(JsValue::NULL);
            let _ = h.replace_state_with_url(&state, "", Some(url));
        } else {
            let here = js_sys::Object::new();
            let _ =
                js_sys::Reflect::set(&here, &SCROLL.into(), &w.scroll_y().unwrap_or(0.0).into());
            let _ = h.replace_state(&here, "");
            let _ = h.push_state_with_url(&JsValue::NULL, "", Some(url));
        }
    }

    /// After the next render, scroll to `y`.
    pub fn scroll(y: Option<f64>) {
        let Some(y) = y else { return };
        doxa_client::task::spawn(async move {
            if let Some(w) = web_sys::window() {
                w.scroll_to_with_x_and_y(0.0, y);
            }
        });
    }

    pub fn listen_popstate() {
        thread_local!(static LISTENING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) });
        if LISTENING.with(|l| l.replace(true)) {
            return;
        }
        let Some(w) = web_sys::window() else { return };
        if let Ok(h) = w.history() {
            let _ = js_sys::Reflect::set(&h, &"scrollRestoration".into(), &"manual".into());
        }
        let cb = Closure::<dyn Fn(web_sys::PopStateEvent)>::new(|e: web_sys::PopStateEvent| {
            if !super::allowed() {
                // Undo the move by putting the page we stayed on back on top.
                write(&super::current_url(), false);
                return;
            }
            let y = js_sys::Reflect::get(&e.state(), &SCROLL.into())
                .ok()
                .and_then(|v| v.as_f64());
            super::go(current(), super::Nav::replace(), super::Origin::Pop(y));
        });
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
