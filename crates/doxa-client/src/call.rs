//! `Call<R>`: one request to one route, awaited like any async fn.

use std::any::Any;
use std::future::{Future, IntoFuture};
use std::marker::PhantomData;
use std::rc::Rc;
use std::task::Poll;

use doxa_wire::{FieldErrors, Identity, Method, RouteSpec, Validates};
use futures_util::future::LocalBoxFuture;
use serde_json::Value;

use crate::arg::{ArgFor, ClientArg, Outgoing};
use crate::cache::entity::Entity;
use crate::cache::{map_items, max_age, Lookup, Meta, Outcome, Revalidated, Revalidation, Slot};
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
/// let widget = get_widget(&key).await?; // a `Cached<Widget>`
/// ```
#[must_use = "a call does nothing until it is awaited"]
pub struct Call<R> {
    route: &'static RouteSpec,
    out: Outgoing,
    refused: Option<Refused>,
    fresh: bool,
    patch: Option<Patch>,
    settle: Option<Settle>,
    entity: Option<Entity>,
    _response: PhantomData<fn() -> R>,
}

impl<R> Call<R> {
    /// A call to `route` with no arguments yet.
    pub fn new(route: &'static RouteSpec) -> Self {
        Self {
            route,
            out: Outgoing::new(route.path),
            refused: None,
            fresh: false,
            patch: None,
            settle: None,
            entity: None,
            _response: PhantomData,
        }
    }

    /// The entity this route answers, when its stub finds one; GETs are cached under it and
    /// other methods invalidate it.
    #[doc(hidden)]
    pub fn answers(self, entity: Option<&'static str>) -> Self {
        if let Some(entity) = entity {
            crate::cache::answers(self.route, entity);
        }
        self
    }

    /// How the cache files this route's response by identity; set by the stub.
    #[doc(hidden)]
    pub fn entity(mut self, entity: Option<Entity>) -> Self {
        self.entity = entity;
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

    /// Skip the cache and ask the server, storing what comes back.
    pub fn fresh(mut self) -> Self {
        self.fresh = true;
        self
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

    /// Patch every cached `T` this call is about now; undone if the call fails.
    ///
    /// A cached `T` is about this call when its `#[identity(key = …)]` equals the
    /// key the call sends. A `T` coming back replaces the cached ones.
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

impl<R: FromResponse> IntoFuture for Call<R> {
    type Output = Result<R::Output, Fetch<R::Error>>;
    type IntoFuture = LocalBoxFuture<'static, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        if R::STREAMS && self.route.method.is_safe() {
            Box::pin(subscribe(self))
        } else if R::STREAMS {
            Box::pin(open_once(self))
        } else if self.route.method.is_safe() {
            Box::pin(query(self))
        } else {
            Box::pin(owned(mutate(self)))
        }
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
    Value(R::Output, Meta, Vec<String>),
    NotModified(Meta),
    Status(u16, Vec<u8>),
    Failed(Fetch),
}

/// What came back, and whether it still belongs to the current session.
async fn send<R: FromResponse>(
    client: &Service,
    mut request: Request,
    etag: Option<&str>,
) -> (Sent<R>, bool) {
    if let Some(etag) = etag {
        request.headers.push(("if-none-match".into(), etag.into()));
    }
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
    let mut meta = Meta {
        now: now(),
        max_age: max_age(response.header("cache-control")),
        etag: response.header("etag").map(str::to_owned),
        digest: None,
    };
    let invalidates = invalidates(&response);
    let status = response.status;
    if status == 304 {
        return Sent::NotModified(meta);
    }
    let headers = response.headers;
    match response.body.bytes().await {
        Ok(bytes) if status >= 400 => Sent::Status(status, bytes),
        Ok(bytes) => {
            meta.digest = Some(digest(&bytes));
            match R::decode(status, &headers, bytes) {
                Ok(v) => Sent::Value(v, meta, invalidates),
                Err(e) => Sent::Failed(Fetch::Decode(e)),
            }
        }
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

fn digest(bytes: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

fn not_modified<E>() -> Fetch<E> {
    Fetch::Status {
        code: 304,
        body: None,
    }
}

fn out_of<R: FromResponse>(value: &Rc<dyn Any>) -> Result<R::Output, Fetch<R::Error>> {
    R::load(value.clone()).ok_or_else(|| Fetch::Decode("cached value has another type".to_owned()))
}

fn from_outcome<R: FromResponse>(outcome: &Outcome) -> Result<R::Output, Fetch<R::Error>> {
    match outcome {
        Outcome::Value(v) => out_of::<R>(v),
        Outcome::Status(code, body) => Err(Fetch::from_status(*code, body)),
        Outcome::Failed(f) => Err(widen(f.clone())),
    }
}

/// Join the open stream with the same route and arguments, or open it.
async fn subscribe<R: FromResponse>(call: Call<R>) -> Result<R::Output, Fetch<R::Error>> {
    let client = service(call.route.package);
    let url = call.url().map_err(widen)?;
    let key = format!("{} {url}", call.route.method.as_str());
    let response = loop {
        if let Some(hub) = client.open_stream(&key) {
            return Ok(R::stream(hub));
        }
        let request = call.request(url.clone(), "text/event-stream");
        client.cache.count_request();
        let session = client.session();
        let response = client.send(request).await.map_err(widen)?;
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
    let request = call.request(url, "text/event-stream");
    let hub = Rc::new(Hub::new(request, client.clone(), response.body));
    client.share_stream(key, &hub);
    Ok(R::stream(hub))
}

/// Send a mutating route's stream request exactly once: never shared, resent or reopened.
async fn open_once<R: FromResponse>(call: Call<R>) -> Result<R::Output, Fetch<R::Error>> {
    let client = service(call.route.package);
    let url = call.url().map_err(widen)?;
    let request = call.request(url.clone(), "text/event-stream");
    client.cache.count_request();
    let session = client.session();
    let response = client.send(request).await.map_err(widen)?;
    if !client.observe_session(&response, session) {
        return Err(Fetch::Stream("the session changed".into()));
    }
    if response.status >= 400 {
        let body = response.body.bytes().await.map_err(Fetch::Network)?;
        return Err(Fetch::from_status(response.status, &body));
    }
    let extra = invalidates(&response);
    let mut entities: Vec<&str> = crate::cache::about(call.route);
    entities.extend(extra.iter().map(String::as_str));
    client.cache.invalidate(&entities);
    crate::cache::report(&entities);
    let request = call.request(url, "text/event-stream");
    let hub = Rc::new(Hub::new(request, client.clone(), response.body));
    client.own_stream(&hub);
    Ok(R::stream(hub))
}

async fn query<R: FromResponse>(call: Call<R>) -> Result<R::Output, Fetch<R::Error>> {
    let client = service(call.route.package);
    let url = call.url().map_err(widen)?;
    let key = format!("GET {url}");
    loop {
        if let Some(result) = query_once(&call, &client, &url, &key).await {
            return result;
        }
    }
}

/// One attempt; `None` when the session changed while it was in flight.
async fn query_once<R: FromResponse>(
    call: &Call<R>,
    client: &Rc<Service>,
    url: &str,
    key: &str,
) -> Option<Result<R::Output, Fetch<R::Error>>> {
    let request = call.request(url.to_owned(), "application/json");
    if !call.fresh {
        match client.cache.lookup(key, now()) {
            Lookup::Fresh(v) => return Some(out_of::<R>(&v)),
            Lookup::Revalidate(v, claim) => {
                revalidate::<R>(client, key.to_owned(), request, claim);
                return Some(out_of::<R>(&v));
            }
            Lookup::Pending(slot) => {
                let outcome = slot.wait().await;
                if !matches!(*outcome, Outcome::Failed(Fetch::Aborted)) {
                    client.cache.watch(key);
                    return Some(from_outcome::<R>(&outcome));
                }
                return None;
            }
            Lookup::Miss => {
                if let Some(found) = from_store(call, client, key) {
                    return Some(out_of::<R>(&found));
                }
            }
        }
    }

    let slot = client.cache.begin(key);
    let guard = Inflight {
        client,
        key,
        slot: &slot,
    };
    let (sent, current) = send::<R>(client, request, None).await;
    if !current {
        return None;
    }
    let result = match sent {
        Sent::Value(v, meta, _) => {
            match R::store(&v) {
                Some(stored) => {
                    let route_key = call.out.first_key().cloned();
                    client
                        .cache
                        .store(key.to_owned(), call.route, route_key, stored.clone(), meta);
                    slot.finish(Outcome::Value(stored));
                }
                None => slot.finish(Outcome::Failed(Fetch::Decode("not cacheable".into()))),
            }
            Ok(v)
        }
        Sent::NotModified(_) => {
            slot.finish(Outcome::Failed(not_modified()));
            Err(not_modified())
        }
        Sent::Status(code, body) => {
            let err = Fetch::from_status(code, &body);
            slot.finish(Outcome::Status(code, body.into()));
            Err(err)
        }
        Sent::Failed(f) => {
            slot.finish(Outcome::Failed(f.clone()));
            Err(widen(f))
        }
    };
    drop(guard);
    Some(result)
}

/// An instance route answered from a fresh list or response holding that instance,
/// filed under `key` with the age of what it came from.
fn from_store<R>(call: &Call<R>, client: &Service, key: &str) -> Option<Rc<dyn Any>> {
    let entity = call.entity?;
    let route_key = call.out.only_key()?;
    let (value, at) = client.cache.find(now(), |v| (entity.find)(v, route_key))?;
    let meta = Meta {
        now: at,
        max_age: None,
        etag: None,
        digest: None,
    };
    client.cache.store(
        key.to_owned(),
        call.route,
        Some(route_key.clone()),
        value.clone(),
        meta,
    );
    Some(value)
}

/// Ends an in-flight entry even if the caller drops the call, so waiters retry
/// rather than wait forever.
struct Inflight<'a> {
    client: &'a Service,
    key: &'a str,
    slot: &'a Slot,
}

impl Drop for Inflight<'_> {
    fn drop(&mut self) {
        if self.slot.outcome.borrow().is_none() {
            self.slot.finish(Outcome::Failed(Fetch::Aborted));
        }
        self.client.cache.end(self.key, self.slot);
    }
}

fn revalidate<R: FromResponse>(
    client: &Rc<Service>,
    key: String,
    request: Request,
    claim: Revalidation,
) {
    let client = client.clone();
    crate::task::spawn(async move {
        client.cache.count_request();
        let (sent, current) = send::<R>(&client, request, claim.etag.as_deref()).await;
        if !current {
            return;
        }
        let result = match sent {
            Sent::Value(v, meta, _) => match R::store(&v) {
                Some(stored) => Revalidated::Value(stored, meta),
                None => Revalidated::Failed,
            },
            Sent::NotModified(meta) => Revalidated::NotModified(meta.now),
            Sent::Status(401 | 403 | 404, _) => Revalidated::Gone,
            Sent::Status(..) | Sent::Failed(_) => Revalidated::Failed,
        };
        client.cache.revalidated(&key, claim, result);
    });
}

async fn mutate<R: FromResponse>(call: Call<R>) -> Result<R::Output, Fetch<R::Error>> {
    let client = service(call.route.package);
    let url = call.url().map_err(widen)?;
    let request = call.request(url.clone(), "application/json");
    let key = call.out.first_key().cloned();
    let previous = call.patch.map(|p| p(&client, key.as_ref()));
    client.cache.count_request();
    // A mutation that outlived its session still reports, but leaves the new cache alone.
    let (sent, current) = send::<R>(&client, request, None).await;
    match sent {
        Sent::Value(v, _, extra) => {
            if !current {
                return Ok(v);
            }
            let stored = R::store(&v);
            if let (Some(settle), Some(stored)) = (call.settle, &stored) {
                settle(&client, &**stored, key.as_ref());
            }
            let mut entities: Vec<&str> = crate::cache::about(call.route);
            entities.extend(extra.iter().map(String::as_str));
            client.cache.invalidate(&entities);
            crate::cache::report(&entities);
            // Filed after the invalidation, so the next read of this instance needs no request.
            if let (Some(entity), Some(stored)) = (call.entity, stored) {
                if call.route.method != Method::Delete {
                    let meta = Meta {
                        now: now(),
                        max_age: None,
                        etag: None,
                        digest: None,
                    };
                    let route_key = (entity.key)(&stored);
                    let at = format!("{} {url}", call.route.method.as_str());
                    client.cache.store(at, call.route, route_key, stored, meta);
                }
            }
            Ok(v)
        }
        other => {
            if let (Some(previous), true) = (previous, current) {
                client.cache.restore(previous);
            }
            Err(match other {
                Sent::Status(code, body) => Fetch::from_status(code, &body),
                Sent::Failed(f) => widen(f),
                _ => not_modified(),
            })
        }
    }
}
