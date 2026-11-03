//! One service per client crate: its base URL, layers, cache, streams and session.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::{Rc, Weak};

use futures_util::future::LocalBoxFuture;

use crate::cache::{Cache, CacheConfig};
use crate::fetch::Fetch;
use crate::layer::{layers, Layers, Next};
use crate::sse::Hub;
use crate::transport::{Request, Response, Transport};

/// Where one client crate's routes are served, and everything tied to that server's session.
///
/// ```
/// use doxa_client::{layer::transport, service, transport::MockTransport};
///
/// let orders = service("orders-client");
/// orders.set_base("https://orders.example.com");
/// orders.layers().push(transport(MockTransport::new()));
/// ```
pub struct Service {
    package: &'static str,
    base: RefCell<String>,
    layers: Layers,
    transport: Rc<dyn Transport>,
    pub(crate) cache: Cache,
    epoch: RefCell<Option<String>>,
    /// Bumped on every session change; a response to an older one is dropped.
    session: Cell<u64>,
    on_session: RefCell<Vec<Rc<dyn Fn()>>>,
    streams: RefCell<HashMap<String, Weak<Hub>>>,
}

type AnySession = Rc<dyn Fn(&'static str)>;

thread_local! {
    static SERVICES: RefCell<HashMap<&'static str, Rc<Service>>> = RefCell::default();
    static ANY_SESSION: RefCell<Vec<AnySession>> = const { RefCell::new(Vec::new()) };
}

/// The service of client crate `package`, created on first use.
pub fn service(package: &'static str) -> Rc<Service> {
    SERVICES.with(|s| {
        s.borrow_mut()
            .entry(package)
            .or_insert_with(|| Rc::new(Service::new(package)))
            .clone()
    })
}

/// Run `f` on every service created so far.
#[cfg_attr(not(feature = "oidc"), allow(dead_code))]
pub(crate) fn each(f: impl Fn(&Service)) {
    let all: Vec<Rc<Service>> = SERVICES.with(|s| s.borrow().values().cloned().collect());
    all.iter().for_each(|s| f(s));
}

/// Run `f` with the package name whenever any service's session changes.
pub fn on_any_session_change(f: impl Fn(&'static str) + 'static) {
    ANY_SESSION.with(|a| a.borrow_mut().push(Rc::new(f)));
}

impl Service {
    fn new(package: &'static str) -> Self {
        Self {
            package,
            base: RefCell::new(configured_base(package)),
            layers: Layers::default(),
            transport: default_transport(),
            cache: Cache::default(),
            epoch: RefCell::new(None),
            session: Cell::new(0),
            on_session: RefCell::new(Vec::new()),
            streams: RefCell::default(),
        }
    }

    /// The client crate this service is for.
    pub fn package(&self) -> &'static str {
        self.package
    }

    /// The base URL requests go to; empty means the page's own origin.
    pub fn base(&self) -> String {
        self.base.borrow().clone()
    }

    /// Send requests to `base`, e.g. `https://orders.example.com`.
    pub fn set_base(&self, base: impl Into<String>) {
        *self.base.borrow_mut() = base.into();
    }

    /// This service's layers; they run after the [global ones](crate::layers).
    pub fn layers(&self) -> Layers {
        self.layers.clone()
    }

    /// How long this service's responses stay fresh.
    pub fn cache(&self, config: CacheConfig) {
        *self.cache.config.borrow_mut() = config;
    }

    /// Run `f` whenever the server reports a new session (sign-in, sign-out, tenant switch).
    pub fn on_session_change(&self, f: impl Fn() + 'static) {
        self.on_session.borrow_mut().push(Rc::new(f));
    }

    /// Requests that reached the network.
    pub fn requests_sent(&self) -> u64 {
        self.cache.requests()
    }

    /// Forget every cached response.
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// The open stream for `key`, if another caller already opened it.
    pub(crate) fn open_stream(&self, key: &str) -> Option<Rc<Hub>> {
        let mut streams = self.streams.borrow_mut();
        streams.retain(|_, hub| hub.upgrade().is_some_and(|h| h.is_open()));
        streams.get(key).and_then(Weak::upgrade)
    }

    pub(crate) fn share_stream(&self, key: String, hub: &Rc<Hub>) {
        self.streams.borrow_mut().insert(key, Rc::downgrade(hub));
    }

    /// Close `hub` with the session without offering it to other callers.
    pub(crate) fn own_stream(&self, hub: &Rc<Hub>) {
        let key = format!("once {:p}", Rc::as_ptr(hub));
        self.streams.borrow_mut().insert(key, Rc::downgrade(hub));
    }

    /// Send `request` under the base URL through the global layers, this service's, then
    /// the transport. Holds no borrow while it runs.
    pub(crate) fn send(
        &self,
        mut request: Request,
    ) -> LocalBoxFuture<'static, Result<Response, Fetch>> {
        if !request.url.contains("://") {
            request.url = format!("{}{}", self.base.borrow(), request.url);
        }
        let mut stack = layers().snapshot();
        stack.extend(self.layers.snapshot());
        Next::new(stack.into(), self.transport.clone()).run(request)
    }

    /// Send `request` through this service's layers and transport, skipping the global ones.
    #[cfg_attr(not(feature = "oidc"), allow(dead_code))]
    pub(crate) fn send_own(
        &self,
        request: Request,
    ) -> LocalBoxFuture<'static, Result<Response, Fetch>> {
        Next::new(self.layers.snapshot().into(), self.transport.clone()).run(request)
    }

    /// The session counter to tag a request with as it is sent.
    pub(crate) fn session(&self) -> u64 {
        self.session.get()
    }

    /// Whether a response to a request sent in session `sent` is still current.
    /// Clears everything tied to the old session when the server names a new one.
    pub(crate) fn observe_session(&self, response: &Response, sent: u64) -> bool {
        if sent != self.session.get() {
            return false;
        }
        let Some(epoch) = response.header(doxa_wire::SESSION_HEADER) else {
            return true;
        };
        let changed = {
            let mut current = self.epoch.borrow_mut();
            let changed = current.as_deref().is_some_and(|c| c != epoch);
            *current = Some(epoch.to_owned());
            changed
        };
        if changed {
            self.reset();
        }
        true
    }

    /// Drop everything tied to the session now (cache, streams, singletons) rather than on
    /// the next response; call it when signing out.
    pub fn end_session(&self) {
        *self.epoch.borrow_mut() = None;
        self.reset();
    }

    fn reset(&self) {
        self.session.set(self.session.get() + 1);
        self.cache.clear();
        let hubs: Vec<_> = self.streams.borrow_mut().drain().collect();
        for hub in hubs.iter().filter_map(|(_, h)| h.upgrade()) {
            hub.close();
        }
        let own: Vec<_> = self.on_session.borrow().clone();
        own.iter().for_each(|f| f());
        let any: Vec<_> = ANY_SESSION.with(|a| a.borrow().clone());
        any.iter().for_each(|f| f(self.package));
    }
}

#[cfg(target_arch = "wasm32")]
fn default_transport() -> Rc<dyn Transport> {
    Rc::new(crate::transport::BrowserFetch::default())
}

#[cfg(not(target_arch = "wasm32"))]
fn default_transport() -> Rc<dyn Transport> {
    Rc::new(crate::transport::Unconfigured)
}

/// The base URL `services.json` gives `package`, which the entry script loads before the wasm.
#[cfg(target_arch = "wasm32")]
fn configured_base(package: &str) -> String {
    use js_sys::Reflect;
    Reflect::get(&js_sys::global(), &"__DOXA_SERVICES__".into())
        .ok()
        .filter(|m| m.is_object())
        .and_then(|m| Reflect::get(&m, &package.into()).ok())
        .and_then(|v| v.as_string())
        .unwrap_or_default()
}

#[cfg(not(target_arch = "wasm32"))]
fn configured_base(_: &str) -> String {
    String::new()
}

/// Milliseconds since an arbitrary epoch.
pub(crate) fn now() -> f64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64() * 1000.0)
    }
}
