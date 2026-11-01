//! Decoding a route's response into what the call returns.

use std::marker::PhantomData;

use serde::de::DeserializeOwned;

use crate::fetch::{Fetch, NoError};
use crate::sse::{EventStream, Source};
use crate::transport::Body;

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
    /// Decode a streamed success response; only called when `STREAMS`.
    #[doc(hidden)]
    fn stream(_body: Body, _source: Source) -> Self::Output {
        unreachable!("only streaming responses are decoded as streams")
    }
    /// A copy for the cache, or `None` if the output can't be cached.
    #[doc(hidden)]
    fn share(value: &Self::Output) -> Option<Self::Output>;
}

/// `axum::http::StatusCode`: the call yields the status.
pub struct StatusCode;
/// `SseStream<E, _>`: the call yields an [`EventStream`].
pub struct SseStream<E>(PhantomData<fn() -> E>);
/// A return type the browser can't decode; calling such a route is a compile error.
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

impl<T: DeserializeOwned + Clone + 'static> FromResponse for crate::arg::Json<T> {
    type Output = T;
    type Error = NoError;
    fn decode(_: u16, body: Vec<u8>) -> Result<T, String> {
        serde_json::from_slice(&body).map_err(|e| e.to_string())
    }
    fn share(value: &T) -> Option<T> {
        Some(value.clone())
    }
}

impl<R, E> FromResponse for Result<R, E>
where
    R: FromResponse<Error = NoError>,
    E: DeserializeOwned + 'static,
{
    type Output = R::Output;
    type Error = E;
    const STREAMS: bool = R::STREAMS;
    fn decode(status: u16, body: Vec<u8>) -> Result<Self::Output, String> {
        R::decode(status, body)
    }
    fn stream(body: Body, source: Source) -> Self::Output {
        R::stream(body, source)
    }
    fn share(value: &R::Output) -> Option<R::Output> {
        R::share(value)
    }
}

impl<R> FromResponse for AliasedResult<R>
where
    R: FromResponse<Error = NoError>,
{
    type Output = R::Output;
    type Error = serde_json::Value;
    const STREAMS: bool = R::STREAMS;
    fn decode(status: u16, body: Vec<u8>) -> Result<Self::Output, String> {
        R::decode(status, body)
    }
    fn stream(body: Body, source: Source) -> Self::Output {
        R::stream(body, source)
    }
    fn share(value: &R::Output) -> Option<R::Output> {
        R::share(value)
    }
}

impl<R: FromResponse> FromResponse for (StatusCode, R) {
    type Output = R::Output;
    type Error = R::Error;
    const STREAMS: bool = R::STREAMS;
    fn decode(status: u16, body: Vec<u8>) -> Result<Self::Output, String> {
        R::decode(status, body)
    }
    fn stream(body: Body, source: Source) -> Self::Output {
        R::stream(body, source)
    }
    fn share(value: &R::Output) -> Option<R::Output> {
        R::share(value)
    }
}

impl FromResponse for StatusCode {
    type Output = u16;
    type Error = NoError;
    fn decode(status: u16, _: Vec<u8>) -> Result<u16, String> {
        Ok(status)
    }
    fn share(value: &u16) -> Option<u16> {
        Some(*value)
    }
}

impl FromResponse for () {
    type Output = ();
    type Error = NoError;
    fn decode(_: u16, _: Vec<u8>) -> Result<(), String> {
        Ok(())
    }
    fn share(_: &()) -> Option<()> {
        Some(())
    }
}

impl FromResponse for String {
    type Output = String;
    type Error = NoError;
    fn decode(_: u16, body: Vec<u8>) -> Result<String, String> {
        String::from_utf8(body).map_err(|e| e.to_string())
    }
    fn share(value: &String) -> Option<String> {
        Some(value.clone())
    }
}

impl<E: DeserializeOwned + 'static> FromResponse for SseStream<E> {
    type Output = EventStream<E>;
    type Error = NoError;
    const STREAMS: bool = true;
    fn decode(_: u16, _: Vec<u8>) -> Result<EventStream<E>, String> {
        Err("an event stream arrived buffered".to_owned())
    }
    fn stream(body: Body, source: Source) -> EventStream<E> {
        EventStream::new(body, source)
    }
    fn share(_: &EventStream<E>) -> Option<EventStream<E>> {
        None
    }
}
