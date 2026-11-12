//! `Call<R>`: one request to one route, awaited like any async fn.

use std::any::Any;
use std::future::{Future, IntoFuture};
use std::marker::PhantomData;
use std::rc::Rc;
use std::task::Poll;
use std::time::Duration;

use doxa_wire::{FieldErrors, Identity, RouteSpec, Validates};
use futures_util::future::LocalBoxFuture;
use serde_json::Value;

use crate::arg::{ArgFor, ClientArg, Outgoing};
use crate::cache::map_items;
use crate::cached::Cached;
use crate::fetch::Fetch;
use crate::response::{widen, FromResponse};
use crate::service::{now, service, Service};
use crate::sse::Hub;
use crate::transport::Request;

type Patch = Box<dyn FnOnce(&Service, Option<&Value>) -> Vec<(String, Rc<dyn Any>)>>;
type Settle = Box<dyn FnOnce(&Service, &dyn Any, Option<&Value>)>;

/// Why a call is refused before it is sent.
enum Refused {
    Encode(String),
    Invalid(FieldErrors),
}

/// A call to a route, built by the route's client stub. Await it.
///
/// ```ignore
/// let widget = get_widget(&key).await?; // a `Widget`
/// ```
#[must_use = "a call does nothing until it is awaited"]
pub struct Call<R> {
    route: &'static RouteSpec,
    out: Outgoing,
    refused: Option<Refused>,
    patch: Option<Patch>,
    settle: Option<Settle>,
    _response: PhantomData<fn() -> R>,
}

impl<R> Call<R> {
    /// A call to `route` with no arguments yet.
    pub fn new(route: &'static RouteSpec) -> Self {
        Self {
            route,
            out: Outgoing::new(route.path),
            refused: None,
            patch: None,
            settle: None,
            _response: PhantomData,
        }
    }

    /// The entity this route answers, when its stub finds one; other methods invalidate it.
    #[doc(hidden)]
    pub fn answers(self, entity: Option<&'static str>) -> Self {
        if let Some(entity) = entity {
            crate::cache::answers(self.route, entity);
        }
        self
    }

    /// Add the argument for a parameter the route reads with extractor `X`.
    pub fn arg<X, A: ArgFor<X>>(mut self, value: A) -> Self {
        if self.refused.is_none() {
            if let Err(e) = value.encode(&mut self.out) {
                self.refused = Some(Refused::Encode(e));
            }
        }
        self
    }

    /// Add an argument the route checks with `W`; if it fails, the call is refused unsent.
    #[doc(hidden)]
    pub fn checked<W, X>(mut self, value: W::Value) -> Self
    where
        W: Validates,
        X: ClientArg<Value = W::Value>,
    {
        if self.refused.is_none() {
            self.refused = match W::check(&value) {
                Err(fields) => Some(Refused::Invalid(fields)),
                Ok(()) => X::apply(value, &mut self.out).err().map(Refused::Encode),
            };
        }
        self
    }

    /// Send an extra header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.out.header(name, value);
        self
    }

    /// Answer from the cache for `ttl` after a response, sharing it with every caller
    /// of the same URL; a mutation about its entity drops it sooner.
    ///
    /// ```ignore
    /// let widget = get_widget(&key).cache(Duration::from_secs(60)).await?; // a `Cached<Widget>`
    /// ```
    pub fn cache(self, ttl: Duration) -> CachedCall<R> {
        CachedCall { call: self, ttl }
    }

    /// The route this call goes to.
    pub fn route(&self) -> &'static RouteSpec {
        self.route
    }

    /// The path and query this call requests.
    pub fn url(&self) -> Result<String, Fetch> {
        match &self.refused {
            Some(Refused::Encode(e)) => return Err(Fetch::Encode(e.clone())),
            Some(Refused::Invalid(f)) => return Err(Fetch::Invalid(f.clone())),
            None => {}
        }
        self.out.url().map_err(Fetch::Encode)
    }

    /// Patch now every cached `T` whose `#[identity(key = …)]` is the key this call sends; undone
    /// if it fails, replaced by a returned `T`.
    pub fn optimistic<T>(mut self, patch: impl Fn(&mut T) + 'static) -> Self
    where
        T: Identity + Clone + 'static,
    {
        self.patch = Some(Box::new(move |client, key| {
            let Some(key) = key.cloned() else {
                return Vec::new();
            };
            client.cache.patch(|value| {
                map_items::<T>(value, |t| t.route_key().as_ref() == Some(&key), &patch)
            })
        }));
        self.settle = Some(Box::new(|client, output, _| {
            let Some(next) = output.downcast_ref::<T>() else {
                return;
            };
            let id = next.identity();
            client.cache.patch(|value| {
                map_items::<T>(value, |t| t.identity() == id, &|t| *t = next.clone())
            });
        }));
        self
    }

    pub(crate) fn request(&self, url: String, accept: &str) -> Request {
        let mut headers = self.out.headers().to_vec();
        headers.push(("accept".into(), accept.into()));
        let body = self.out.body().map(|(content_type, payload)| {
            if let Some(t) = content_type {
                headers.push(("content-type".into(), t.clone()));
            }
            payload.clone()
        });
        Request {
            method: self.route.method,
            url,
            headers,
            body,
            credentials: false,
        }
    }
}

/// A GET awaited in a component's render takes that component's next hook slot, and the
/// next render gets the same answer back while the URL is unchanged.
impl<R: FromResponse> IntoFuture for Call<R> {
    type Output = Result<R::Output, Fetch<R::Error>>;
    type IntoFuture = LocalBoxFuture<'static, Self::Output>;

    #[track_caller]
    fn into_future(self) -> Self::IntoFuture {
        if R::STREAMS && self.route.method.is_safe() {
            Box::pin(subscribe(self))
        } else if R::STREAMS {
            Box::pin(open_once(self))
        } else if self.route.method.is_safe() {
            let slot = crate::cache::render_slot(std::panic::Location::caller());
            Box::pin(query(self, slot))
        } else {
            Box::pin(owned(mutate(self)))
        }
    }
}

/// A [`Call`] answered from the cache while its last response is fresh. Await it.
#[must_use = "a call does nothing until it is awaited"]
pub struct CachedCall<R> {
    call: Call<R>,
    ttl: Duration,
}

impl<R: FromResponse> IntoFuture for CachedCall<R> {
    type Output = Result<Cached<R::Output>, Fetch<R::Error>>;
    type IntoFuture = LocalBoxFuture<'static, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        let CachedCall { call, ttl } = self;
        if R::STREAMS || !call.route.method.is_safe() {
            // Streams and mutations aren't answers to keep.
            return Box::pin(async move { call.await.map(Cached::new) });
        }
        Box::pin(cached_query(call, ttl))
    }
}

/// Polled by the caller, but finished in the background if the caller drops it,
/// so an unmounted component can't lose a mutation's effects.
struct Owned<T: 'static> {
    inner: Option<LocalBoxFuture<'static, T>>,
}

fn owned<T: 'static>(fut: impl Future<Output = T> + 'static) -> Owned<T> {
    Owned {
        inner: Some(Box::pin(fut)),
    }
}

impl<T: 'static> Future for Owned<T> {
    type Output = T;

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<T> {
        let Some(inner) = self.inner.as_mut() else {
            return Poll::Pending;
        };
        let out = inner.as_mut().poll(cx);
        if out.is_ready() {
            self.inner = None;
        }
        out
    }
}

impl<T: 'static> Drop for Owned<T> {
    fn drop(&mut self) {
        if let Some(rest) = self.inner.take() {
            crate::task::spawn(async move {
                rest.await;
            });
        }
    }
}

enum Sent<R: FromResponse> {
    Value(R::Output, Vec<String>),
    Status(u16, Vec<u8>),
    Failed(Fetch),
}

impl<R: FromResponse> Sent<R> {
    fn into_result(self) -> Result<R::Output, Fetch<R::Error>> {
        match self {
            Sent::Value(v, _) => Ok(v),
            Sent::Status(code, body) => Err(Fetch::from_status(code, &body)),
            Sent::Failed(f) => Err(widen(f)),
        }
    }
}

/// What came back, and whether it still belongs to the current session.
async fn send<R: FromResponse>(client: &Service, request: Request) -> (Sent<R>, bool) {
    client.cache.count_request();
    let session = client.session();
    let response = match client.send(request).await {
        Ok(r) => r,
        Err(e) => {
            let current = client.session() == session;
            return (Sent::Failed(e), current);
        }
    };
    let current = client.observe_session(&response, session);
    (decode::<R>(response).await, current)
}

async fn decode<R: FromResponse>(response: crate::transport::Response) -> Sent<R> {
    let invalidates = invalidates(&response);
    let status = response.status;
    let headers = response.headers;
    match response.body.bytes().await {
        Ok(bytes) if status >= 400 => Sent::Status(status, bytes),
        Ok(bytes) => match R::decode(status, &headers, bytes) {
            Ok(v) => Sent::Value(v, invalidates),
            Err(e) => Sent::Failed(Fetch::Decode(e)),
        },
        Err(e) => Sent::Failed(Fetch::Network(e)),
    }
}

/// The extra entity types a response says it changed.
fn invalidates(response: &crate::transport::Response) -> Vec<String> {
    response
        .header(doxa_wire::INVALIDATE_HEADER)
        .map(|h| h.split(',').map(|s| s.trim().to_owned()).collect())
        .unwrap_or_default()
}

/// Join the open stream with the same route and arguments, or open it.
async fn subscribe<R: FromResponse>(call: Call<R>) -> Result<R::Output, Fetch<R::Error>> {
    let client = service(call.route.package);
    let url = call.url().map_err(widen)?;
    let key = format!("{} {}", call.route.method.as_str(), call.out.identity(&url));
    let request = call.request(url, "text/event-stream");
    let response = loop {
        if let Some(hub) = client.open_stream(&key) {
            return Ok(R::stream(hub));
        }
        client.cache.count_request();
        let session = client.session();
        let response = client.send(request.clone()).await.map_err(widen)?;
        if client.observe_session(&response, session) {
            break response;
        }
    };
    if response.status >= 400 {
        let body = response.body.bytes().await.map_err(Fetch::Network)?;
        return Err(Fetch::from_status(response.status, &body));
    }
    if let Some(hub) = client.open_stream(&key) {
        return Ok(R::stream(hub));
    }
    let hub = Rc::new(Hub::new(request, client.clone(), response.body));
    client.share_stream(key, &hub);
    Ok(R::stream(hub))
}

/// Send a mutating route's stream request exactly once: never shared, resent or reopened.
async fn open_once<R: FromResponse>(call: Call<R>) -> Result<R::Output, Fetch<R::Error>> {
    let client = service(call.route.package);
    let url = call.url().map_err(widen)?;
    let request = call.request(url, "text/event-stream");
    client.cache.count_request();
    let session = client.session();
    let response = client.send(request.clone()).await.map_err(widen)?;
    if !client.observe_session(&response, session) {
        return Err(Fetch::Stream("the session changed".into()));
    }
    if response.status >= 400 {
        let body = response.body.bytes().await.map_err(Fetch::Network)?;
        return Err(Fetch::from_status(response.status, &body));
    }
    let extra = invalidates(&response);
    let mut entities: Vec<&str> = affected(call.route);
    entities.extend(extra.iter().map(String::as_str));
    client.cache.invalidate(&entities);
    crate::cache::report(&entities);
    let hub = Rc::new(Hub::new(request, client.clone(), response.body));
    client.own_stream(&hub);
    Ok(R::stream(hub))
}

/// Resent when the session changes while it is in flight.
async fn query<R: FromResponse>(
    call: Call<R>,
    slot: Option<String>,
) -> Result<R::Output, Fetch<R::Error>> {
    let client = service(call.route.package);
    let url = call.url().map_err(widen)?;
    let Some(slot) = slot else {
        return send_current(&client, &call, &url).await.into_result();
    };
    let identity = call.out.identity(&url);
    let kept = client.cache.get_slot(&slot, &identity);
    if let Some(v) = kept.as_ref().and_then(|v| v.downcast_ref::<R::Output>()) {
        if let Some(v) = R::copy(v) {
            return Ok(v);
        }
    }
    let (route, route_key) = (call.route, call.out.first_key().cloned());
    let (pending, mine) = client.cache.pending(&slot, &identity);
    if mine {
        // Its own task, so a re-render cancelling this one doesn't drop the request.
        let (client, url, slot, pending) =
            (client.clone(), url.clone(), slot.clone(), pending.clone());
        crate::task::spawn(async move {
            let sent = send_current(&client, &call, &url).await;
            client.cache.end_pending(&slot, &pending);
            pending.finish(Box::new(sent));
        });
    }
    let taken = pending.take().await;
    let Some(sent) = taken.and_then(|s| s.downcast::<Sent<R>>().ok()) else {
        return Err(Fetch::Aborted);
    };
    if let Sent::Value(v, _) = &*sent {
        if let Some(kept) = R::copy(v) {
            client
                .cache
                .store_slot(slot, route, route_key, Rc::new(kept), identity);
        }
    }
    sent.into_result()
}

/// Send `call`, again whenever the session changes while it is in flight.
async fn send_current<R: FromResponse>(client: &Service, call: &Call<R>, url: &str) -> Sent<R> {
    loop {
        let request = call.request(url.to_owned(), "application/json");
        let (sent, current) = send::<R>(client, request).await;
        if current {
            return sent;
        }
    }
}

async fn cached_query<R: FromResponse>(
    call: Call<R>,
    ttl: Duration,
) -> Result<Cached<R::Output>, Fetch<R::Error>> {
    let client = service(call.route.package);
    let url = call.url().map_err(widen)?;
    let key = format!("GET {}", call.out.identity(&url));
    let found = |client: &Service| {
        let found = client.cache.get(&key, now())?;
        Some(
            found
                .downcast::<R::Output>()
                .map(Cached::from_rc)
                .map_err(|_| Fetch::Decode("cached value has another type".to_owned())),
        )
    };
    if let Some(found) = found(&client) {
        return found;
    }
    let slot = format!("cached {key}");
    let (pending, mine) = client.cache.pending(&slot, &key);
    if !mine {
        // Another caller is fetching it; a failure there leaves this one to send its own.
        pending.settled().await;
        if let Some(found) = found(&client) {
            return found;
        }
    }
    let _lead = mine.then(|| Lead {
        client: client.clone(),
        slot,
        pending,
    });
    loop {
        if let Some(found) = found(&client) {
            return found;
        }
        let request = call.request(url.clone(), "application/json");
        let (sent, current) = send::<R>(&client, request).await;
        if !current {
            continue;
        }
        let value = Rc::new(sent.into_result()?);
        let route_key = call.out.first_key().cloned();
        let stored: Rc<dyn Any> = value.clone();
        client
            .cache
            .store(key, call.route, route_key, stored, ttl, now());
        return Ok(Cached::from_rc(value));
    }
}

/// The caller fetching a cached query for the others; settles them however it ends.
struct Lead {
    client: Rc<Service>,
    slot: String,
    pending: Rc<crate::cache::Pending>,
}

impl Drop for Lead {
    fn drop(&mut self) {
        self.client.cache.end_pending(&self.slot, &self.pending);
        self.pending.finish(Box::new(()));
    }
}

/// The entities a successful call to `route` marks stale, before any the response names.
fn affected(route: &'static RouteSpec) -> Vec<&'static str> {
    match route.invalidates {
        true => crate::cache::about(route),
        false => Vec::new(),
    }
}

async fn mutate<R: FromResponse>(call: Call<R>) -> Result<R::Output, Fetch<R::Error>> {
    let client = service(call.route.package);
    let url = call.url().map_err(widen)?;
    let request = call.request(url, "application/json");
    let key = call.out.first_key().cloned();
    let previous = call.patch.map(|p| p(&client, key.as_ref()));
    // A mutation that outlived its session still reports, but leaves the new cache alone.
    let (sent, current) = send::<R>(&client, request).await;
    match sent {
        Sent::Value(v, extra) => {
            if !current {
                return Ok(v);
            }
            if let Some(settle) = call.settle {
                settle(&client, &v, key.as_ref());
            }
            let mut entities: Vec<&str> = affected(call.route);
            entities.extend(extra.iter().map(String::as_str));
            client.cache.invalidate(&entities);
            crate::cache::report(&entities);
            Ok(v)
        }
        other => {
            if let (Some(previous), true) = (previous, current) {
                client.cache.restore(previous);
            }
            other.into_result()
        }
    }
}
