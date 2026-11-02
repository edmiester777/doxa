//! Decoding a route's response into what the call returns.

use std::any::Any;
use std::marker::PhantomData;
use std::rc::Rc;

use serde::de::DeserializeOwned;

use crate::cached::Cached;
use crate::fetch::{Fetch, NoError};
use crate::sse::{EventStream, Hub, Once};

/// A route's return type, as the browser decodes it.
#[diagnostic::on_unimplemented(
    message = "`{Self}` can't be decoded by the browser",
    note = "a client-callable route returns `Json<T>`, `SseStream<E>`, `StatusCode`, `String` or `()`, \
            optionally in a `Result` whose error derives `Deserialize`; `T` must be `Deserialize + Clone`. \
            Otherwise set `client = false` on the route"
)]
pub trait FromResponse: 'static {
    /// What awaiting the call yields.
    type Output: 'static;
    /// The route's own error type.
    type Error: DeserializeOwned + 'static;
    #[doc(hidden)]
    const STREAMS: bool = false;
    /// Decode a buffered success response.
    #[doc(hidden)]
    fn decode(status: u16, body: Vec<u8>) -> Result<Self::Output, String>;
    /// Subscribe to a shared event stream; only called when `STREAMS`.
    #[doc(hidden)]
    fn stream(_hub: Rc<Hub>) -> Self::Output {
        unreachable!("only streaming responses are decoded as streams")
    }
    /// The output as the cache holds it, or `None` if it can't be cached.
    #[doc(hidden)]
    fn store(value: &Self::Output) -> Option<Rc<dyn Any>>;
    /// The output back from what [`store`](Self::store) kept.
    #[doc(hidden)]
    fn load(value: Rc<dyn Any>) -> Option<Self::Output>;
}

/// `axum::http::StatusCode`: the call yields the status.
pub struct StatusCode;
/// `SseStream<E, _>`: the call yields an [`EventStream`].
pub struct SseStream<E>(PhantomData<fn() -> E>);
/// `SseStream<E, _>` from a route that isn't a GET: the call yields a [`Once`].
pub struct SseOnce<E>(PhantomData<fn() -> E>);
/// A return type the browser can't decode. The route's stub refuses to be called.
pub struct Unsupported;
/// A one-argument `Result<T>` alias: the error type isn't visible, so it decodes as JSON.
pub struct AliasedResult<R>(PhantomData<fn() -> R>);

pub(crate) fn widen<E>(f: Fetch<NoError>) -> Fetch<E> {
    match f {
        Fetch::Api(body) => match body.error {},
        Fetch::NotFound(b) => Fetch::NotFound(b),
        Fetch::Unauthorized(b) => Fetch::Unauthorized(b),
        Fetch::Forbidden(b) => Fetch::Forbidden(b),
        Fetch::Status { code, body } => Fetch::Status { code, body },
        Fetch::Encode(m) => Fetch::Encode(m),
        Fetch::Decode(m) => Fetch::Decode(m),
        Fetch::Network(m) => Fetch::Network(m),
        Fetch::Stream(m) => Fetch::Stream(m),
        Fetch::Aborted => Fetch::Aborted,
    }
}

fn store_cached<T: 'static>(value: &Cached<T>) -> Option<Rc<dyn Any>> {
    Some(Cached::rc(value).clone())
}

fn load_cached<T: 'static>(value: Rc<dyn Any>) -> Option<Cached<T>> {
    value.downcast::<T>().ok().map(Cached::from_rc)
}

fn store_copy<T: Clone + 'static>(value: &T) -> Option<Rc<dyn Any>> {
    Some(Rc::new(value.clone()))
}

fn load_copy<T: Clone + 'static>(value: Rc<dyn Any>) -> Option<T> {
    value.downcast_ref::<T>().cloned()
}

impl<T: DeserializeOwned + Clone + 'static> FromResponse for crate::arg::Json<T> {
    type Output = Cached<T>;
    type Error = NoError;
    fn decode(_: u16, body: Vec<u8>) -> Result<Cached<T>, String> {
        serde_json::from_slice(&body)
            .map(Cached::new)
            .map_err(|e| e.to_string())
    }
    fn store(value: &Cached<T>) -> Option<Rc<dyn Any>> {
        store_cached(value)
    }
    fn load(value: Rc<dyn Any>) -> Option<Cached<T>> {
        load_cached(value)
    }
}

macro_rules! forward {
    () => {
        const STREAMS: bool = R::STREAMS;
        fn decode(status: u16, body: Vec<u8>) -> Result<Self::Output, String> {
            R::decode(status, body)
        }
        fn stream(hub: Rc<Hub>) -> Self::Output {
            R::stream(hub)
        }
        fn store(value: &Self::Output) -> Option<Rc<dyn Any>> {
            R::store(value)
        }
        fn load(value: Rc<dyn Any>) -> Option<Self::Output> {
            R::load(value)
        }
    };
}

impl<R, E> FromResponse for Result<R, E>
where
    R: FromResponse<Error = NoError>,
    E: DeserializeOwned + 'static,
{
    type Output = R::Output;
    type Error = E;
    forward!();
}

impl<R> FromResponse for AliasedResult<R>
where
    R: FromResponse<Error = NoError>,
{
    type Output = R::Output;
    type Error = serde_json::Value;
    forward!();
}

impl<R: FromResponse> FromResponse for (StatusCode, R) {
    type Output = R::Output;
    type Error = R::Error;
    forward!();
}

impl FromResponse for StatusCode {
    type Output = u16;
    type Error = NoError;
    fn decode(status: u16, _: Vec<u8>) -> Result<u16, String> {
        Ok(status)
    }
    fn store(value: &u16) -> Option<Rc<dyn Any>> {
        store_copy(value)
    }
    fn load(value: Rc<dyn Any>) -> Option<u16> {
        load_copy(value)
    }
}

impl FromResponse for () {
    type Output = ();
    type Error = NoError;
    fn decode(_: u16, _: Vec<u8>) -> Result<(), String> {
        Ok(())
    }
    fn store(value: &()) -> Option<Rc<dyn Any>> {
        store_copy(value)
    }
    fn load(value: Rc<dyn Any>) -> Option<()> {
        load_copy(value)
    }
}

impl FromResponse for String {
    type Output = Cached<String>;
    type Error = NoError;
    fn decode(_: u16, body: Vec<u8>) -> Result<Cached<String>, String> {
        String::from_utf8(body)
            .map(Cached::new)
            .map_err(|e| e.to_string())
    }
    fn store(value: &Cached<String>) -> Option<Rc<dyn Any>> {
        store_cached(value)
    }
    fn load(value: Rc<dyn Any>) -> Option<Cached<String>> {
        load_cached(value)
    }
}

impl<E: DeserializeOwned + 'static> FromResponse for SseStream<E> {
    type Output = EventStream<E>;
    type Error = NoError;
    const STREAMS: bool = true;
    fn decode(_: u16, _: Vec<u8>) -> Result<EventStream<E>, String> {
        Err("an event stream arrived buffered".to_owned())
    }
    fn stream(hub: Rc<Hub>) -> EventStream<E> {
        EventStream::subscribe(hub)
    }
    fn store(_: &EventStream<E>) -> Option<Rc<dyn Any>> {
        None
    }
    fn load(_: Rc<dyn Any>) -> Option<EventStream<E>> {
        None
    }
}

impl<E: DeserializeOwned + 'static> FromResponse for SseOnce<E> {
    type Output = Once<E>;
    type Error = NoError;
    const STREAMS: bool = true;
    fn decode(_: u16, _: Vec<u8>) -> Result<Once<E>, String> {
        Err("an event stream arrived buffered".to_owned())
    }
    fn stream(hub: Rc<Hub>) -> Once<E> {
        Once::subscribe(hub)
    }
    fn store(_: &Once<E>) -> Option<Rc<dyn Any>> {
        None
    }
    fn load(_: Rc<dyn Any>) -> Option<Once<E>> {
        None
    }
}

impl FromResponse for Unsupported {
    type Output = Unsupported;
    type Error = NoError;
    fn decode(_: u16, _: Vec<u8>) -> Result<Unsupported, String> {
        Err("this route's response isn't client-callable".to_owned())
    }
    fn store(_: &Unsupported) -> Option<Rc<dyn Any>> {
        None
    }
    fn load(_: Rc<dyn Any>) -> Option<Unsupported> {
        None
    }
}
