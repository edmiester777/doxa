//! The installed client: transport, credentials, cache, and session.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use crate::cache::{Cache, CacheConfig};
use std::collections::HashMap;
use std::rc::Weak;

use crate::sse::Hub;
use crate::transport::{Request, Response, Transport};

/// How a call proves who is making it.
#[derive(Clone, Default)]
enum Auth {
    #[default]
    None,
    Bearer(Rc<dyn Fn() -> Option<String>>),
    Cookies,
}

/// Everything a call needs that isn't one of its arguments.
///
/// ```
/// use doxa_client::{ClientConfig, transport::MockTransport};
///
/// ClientConfig::default()
///     .bearer(|| Some("token".to_owned()))
///     .transport(MockTransport::new())
///     .install();
/// ```
#[derive(Clone, Default)]
pub struct ClientConfig {
    transport: Option<Rc<dyn Transport>>,
    auth: Auth,
    cache: CacheConfig,
}

impl ClientConfig {
    /// Send `Authorization: Bearer <token>` with every call, asking `token` each time.
    pub fn bearer(mut self, token: impl Fn() -> Option<String> + 'static) -> Self {
        self.auth = Auth::Bearer(Rc::new(token));
        self
    }

    /// Authenticate with the browser's cookies, sending the CSRF header on every mutation.
    pub fn cookies(mut self) -> Self {
        self.auth = Auth::Cookies;
        self
    }

    /// Send calls through `transport` instead of `fetch`.
    pub fn transport(mut self, transport: impl Transport) -> Self {
        self.transport = Some(Rc::new(transport));
        self
    }

    /// How long responses stay fresh.
    pub fn cache(mut self, cache: CacheConfig) -> Self {
        self.cache = cache;
        self
    }

    /// Make this the client every call on this thread uses.
    pub fn install(self) -> Rc<Client> {
        let client = Rc::new(Client::new(self));
        CURRENT.with(|c| *c.borrow_mut() = Some(client.clone()));
        client
    }
}

/// An installed client. Calls use the current one unless told otherwise.
pub struct Client {
    pub(crate) transport: Rc<dyn Transport>,
    auth: Auth,
    pub(crate) cache: Cache,
    epoch: RefCell<Option<String>>,
    /// Bumped on every session change; a response to an older one is dropped.
    session: Cell<u64>,
    on_session: RefCell<Vec<Box<dyn Fn()>>>,
    streams: RefCell<HashMap<String, Weak<Hub>>>,
}

thread_local! {
    static CURRENT: RefCell<Option<Rc<Client>>> = const { RefCell::new(None) };
}

impl Client {
    pub(crate) fn new(config: ClientConfig) -> Self {
        let cache = Cache::default();
        *cache.config.borrow_mut() = config.cache;
        Self {
            transport: config.transport.unwrap_or_else(default_transport),
            auth: config.auth,
            cache,
            epoch: RefCell::new(None),
            session: Cell::new(0),
            on_session: RefCell::new(Vec::new()),
            streams: RefCell::default(),
        }
    }

    /// The client calls on this thread use, installing a default one if needed.
    pub fn current() -> Rc<Client> {
        CURRENT.with(|c| {
            c.borrow_mut()
                .get_or_insert_with(|| Rc::new(Client::new(ClientConfig::default())))
                .clone()
        })
    }

    /// Run `f` whenever the server reports a new session (sign-in, sign-out, tenant switch).
    pub fn on_session_change(&self, f: impl Fn() + 'static) {
        self.on_session.borrow_mut().push(Box::new(f));
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

    pub(crate) fn authorize(&self, request: &mut Request) {
        match &self.auth {
            Auth::None => {}
            Auth::Bearer(token) => {
                if let Some(token) = token() {
                    request
                        .headers
                        .push(("authorization".into(), format!("Bearer {token}")));
                }
            }
            Auth::Cookies => {
                request.credentials = true;
                if !request.method.is_safe() || request.header(doxa_wire::DRY_RUN_HEADER).is_some()
                {
                    request
                        .headers
                        .push((doxa_wire::CSRF_HEADER.into(), "1".into()));
                }
            }
        }
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
        for f in self.on_session.borrow().iter() {
            f();
        }
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
