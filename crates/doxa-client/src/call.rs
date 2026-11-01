//! `Call<R>`: one request to one route, awaited like any async fn.

use std::any::Any;
use std::future::{Future, IntoFuture};
use std::marker::PhantomData;
use std::rc::Rc;
use std::task::Poll;

use doxa_wire::{Identity, RouteSpec};
use futures_util::future::LocalBoxFuture;
use serde_json::Value;

use crate::arg::{ArgFor, Outgoing};
use crate::cache::{max_age, Lookup, Meta, Outcome};
use crate::client::{now, Client};
use crate::fetch::Fetch;
use crate::response::{widen, FromResponse};
use crate::sse::Source;
use crate::transport::Request;

type Patch = Box<dyn FnOnce(&Client, Option<&Value>) -> Vec<(String, Rc<dyn Any>)>>;
type Settle = Box<dyn FnOnce(&Client, &dyn Any, Option<&Value>)>;

/// A call to a route, built by the route's client stub. Await it.
///
/// ```ignore
/// let widget = get_widget(&key).await?;
/// ```
#[must_use = "a call does nothing until it is awaited"]
pub struct Call<R> {
    route: &'static RouteSpec,
    out: Outgoing,
    error: Option<String>,
    client: Option<Rc<Client>>,
    fresh: bool,
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
            error: None,
            client: None,
            fresh: false,
            patch: None,
            settle: None,
            _response: PhantomData,
        }
    }

    /// Add the argument for a parameter the route reads with extractor `X`.
    pub fn arg<X, A: ArgFor<X>>(mut self, value: A) -> Self {
        if self.error.is_none() {
            if let Err(e) = value.encode(&mut self.out) {
                self.error = Some(e);
            }
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

    /// Use `client` rather than the current one.
    pub fn via(mut self, client: &Rc<Client>) -> Self {
        self.client = Some(client.clone());
        self
    }

    /// The route this call goes to.
    pub fn route(&self) -> &'static RouteSpec {
        self.route
    }

    /// The path and query this call requests.
    pub fn url(&self) -> Result<String, Fetch> {
        if let Some(e) = &self.error {
            return Err(Fetch::Encode(e.clone()));
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

    pub(crate) fn request(&self, client: &Client, url: String, accept: &str) -> Request {
        let mut headers = self.out.headers().to_vec();
        headers.push(("accept".into(), accept.into()));
        let body = self.out.body().map(|(content_type, bytes)| {
            headers.push(("content-type".into(), (*content_type).into()));
            bytes.clone()
        });
        let mut request = Request {
            method: self.route.method,
            url,
            headers,
            body,
            credentials: false,
        };
        client.authorize(&mut request);
        request
    }
}

/// Apply `f` to every `T` in a cached `T`, `Vec<T>` or `Option<T>` that `hit` matches.
fn map_items<T: Clone + 'static>(
    value: &Rc<dyn Any>,
    hit: impl Fn(&T) -> bool,
    f: &dyn Fn(&mut T),
) -> Option<Rc<dyn Any>> {
    if let Some(t) = value.downcast_ref::<T>() {
        return hit(t).then(|| {
            let mut t = t.clone();
            f(&mut t);
            Rc::new(t) as Rc<dyn Any>
        });
    }
    if let Some(items) = value.downcast_ref::<Vec<T>>() {
        if !items.iter().any(&hit) {
            return None;
        }
        let mut items = items.clone();
        items.iter_mut().filter(|t| hit(t)).for_each(f);
        return Some(Rc::new(items));
    }
    if let Some(Some(t)) = value.downcast_ref::<Option<T>>() {
        return hit(t).then(|| {
            let mut t = t.clone();
            f(&mut t);
            Rc::new(Some(t)) as Rc<dyn Any>
        });
    }
    None
}

impl<R: FromResponse> IntoFuture for Call<R> {
    type Output = Result<R::Output, Fetch<R::Error>>;
    type IntoFuture = LocalBoxFuture<'static, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        if self.route.method.is_safe() {
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

async fn send<R: FromResponse>(
    client: &Client,
    mut request: Request,
    etag: Option<&str>,
) -> Sent<R> {
    if let Some(etag) = etag {
        request.headers.push(("if-none-match".into(), etag.into()));
    }
    let source = Source {
        request: request.clone(),
        transport: client.transport.clone(),
    };
    let response = match client.transport.send(request).await {
        Ok(r) => r,
        Err(e) => return Sent::Failed(Fetch::Network(e)),
    };
    client.observe_session(&response);
    let meta = Meta {
        now: now(),
        max_age: max_age(response.header("cache-control")),
        etag: response.header("etag").map(str::to_owned),
    };
    let invalidates = response
        .header(doxa_wire::INVALIDATE_HEADER)
        .map(|h| h.split(',').map(|s| s.trim().to_owned()).collect())
        .unwrap_or_default();
    let status = response.status;
    if status == 304 {
        return Sent::NotModified(meta);
    }
    if status >= 400 {
        return match response.body.bytes().await {
            Ok(bytes) => Sent::Status(status, bytes),
            Err(e) => Sent::Failed(Fetch::Network(e)),
        };
    }
    if R::STREAMS {
        return Sent::Value(R::stream(response.body, source), meta, invalidates);
    }
    match response.body.bytes().await {
        Ok(bytes) => match R::decode(status, bytes) {
            Ok(v) => Sent::Value(v, meta, invalidates),
            Err(e) => Sent::Failed(Fetch::Decode(e)),
        },
        Err(e) => Sent::Failed(Fetch::Network(e)),
    }
}

fn accept<R: FromResponse>() -> &'static str {
    if R::STREAMS {
        "text/event-stream"
    } else {
        "application/json"
    }
}

fn out_of<R: FromResponse>(value: &Rc<dyn Any>) -> Result<R::Output, Fetch<R::Error>> {
    value
        .downcast_ref::<R::Output>()
        .and_then(R::share)
        .ok_or_else(|| Fetch::Decode("cached value has another type".to_owned()))
}

fn from_outcome<R: FromResponse>(outcome: &Outcome) -> Result<R::Output, Fetch<R::Error>> {
    match outcome {
        Outcome::Value(v) => out_of::<R>(v),
        Outcome::Status(code, body) => Err(Fetch::from_status(*code, body)),
        Outcome::Failed(f) => Err(widen(f.clone())),
    }
}

async fn query<R: FromResponse>(call: Call<R>) -> Result<R::Output, Fetch<R::Error>> {
    let client = call.client.clone().unwrap_or_else(Client::current);
    let url = call.url().map_err(widen)?;
    let request = call.request(&client, url.clone(), accept::<R>());
    if R::STREAMS {
        return match send::<R>(&client, request, None).await {
            Sent::Value(v, ..) => Ok(v),
            Sent::NotModified(_) => Err(Fetch::Status {
                code: 304,
                body: None,
            }),
            Sent::Status(code, body) => Err(Fetch::from_status(code, &body)),
            Sent::Failed(f) => Err(widen(f)),
        };
    }

    let key = format!("GET {url}");
    if !call.fresh {
        match client.cache.lookup(&key, now()) {
            Lookup::Fresh(v) => return out_of::<R>(&v),
            Lookup::Stale(v, etag) => {
                revalidate::<R>(&client, key, request, etag);
                return out_of::<R>(&v);
            }
            Lookup::Pending(slot) => {
                let outcome = slot.wait().await;
                client.cache.watch(&key);
                return from_outcome::<R>(&outcome);
            }
            Lookup::Miss => {}
        }
    }

    let slot = client.cache.begin(&key);
    let result = match send::<R>(&client, request, None).await {
        Sent::Value(v, meta, _) => {
            match R::share(&v) {
                Some(copy) => {
                    let stored: Rc<dyn Any> = Rc::new(copy);
                    client
                        .cache
                        .store(key.clone(), call.route, stored.clone(), meta);
                    slot.finish(Outcome::Value(stored));
                }
                None => slot.finish(Outcome::Failed(Fetch::Decode("not cacheable".into()))),
            }
            Ok(v)
        }
        Sent::NotModified(_) => {
            slot.finish(Outcome::Failed(Fetch::Status {
                code: 304,
                body: None,
            }));
            Err(Fetch::Status {
                code: 304,
                body: None,
            })
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
    client.cache.end(&key);
    result
}

fn revalidate<R: FromResponse>(
    client: &Rc<Client>,
    key: String,
    request: Request,
    etag: Option<String>,
) {
    if !client.cache.claim_revalidation(&key) {
        return;
    }
    let client = client.clone();
    crate::task::spawn(async move {
        client.cache.count_request();
        match send::<R>(&client, request, etag.as_deref()).await {
            Sent::Value(v, meta, _) => {
                if let Some(copy) = R::share(&v) {
                    client.cache.replace(&key, Rc::new(copy), meta);
                }
            }
            Sent::NotModified(meta) => client.cache.touch(&key, meta.now),
            Sent::Status(..) | Sent::Failed(_) => {}
        }
        client.cache.release_revalidation(&key);
    });
}

async fn mutate<R: FromResponse>(call: Call<R>) -> Result<R::Output, Fetch<R::Error>> {
    let client = call.client.clone().unwrap_or_else(Client::current);
    let url = call.url().map_err(widen)?;
    let request = call.request(&client, url, accept::<R>());
    let key = call.out.first_key().cloned();
    let previous = call.patch.map(|p| p(&client, key.as_ref()));
    client.cache.count_request();
    match send::<R>(&client, request, None).await {
        Sent::Value(v, _, extra) => {
            if let Some(settle) = call.settle {
                settle(&client, &v as &dyn Any, key.as_ref());
            }
            let mut entities: Vec<&str> = call.route.entities.to_vec();
            entities.extend(extra.iter().map(String::as_str));
            client.cache.invalidate(&entities);
            Ok(v)
        }
        other => {
            if let Some(previous) = previous {
                client.cache.restore(previous);
            }
            Err(match other {
                Sent::Status(code, body) => Fetch::from_status(code, &body),
                Sent::Failed(f) => widen(f),
                _ => Fetch::Status {
                    code: 304,
                    body: None,
                },
            })
        }
    }
}
