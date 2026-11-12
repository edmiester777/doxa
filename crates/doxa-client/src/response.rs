//! Decoding a route's response into what the call returns.

use std::marker::PhantomData;
use std::rc::Rc;

use serde::de::DeserializeOwned;

use crate::fetch::{Fetch, NoError};
use crate::sse::{EventStream, Hub, Once};

/// A route's return type, as the browser decodes it.
#[diagnostic::on_unimplemented(
    message = "`{Self}` can't be decoded by the browser",
    note = "a client-callable route returns `Json<T>`, `SseStream<E>`, `Attachment`, `StatusCode`, `String` or `()`, \
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
    fn decode(
        status: u16,
        headers: &[(String, String)],
        body: Vec<u8>,
    ) -> Result<Self::Output, String>;
    /// Subscribe to a shared event stream; only called when `STREAMS`.
    #[doc(hidden)]
    fn stream(_hub: Rc<Hub>) -> Self::Output {
        unreachable!("only streaming responses are decoded as streams")
    }
    /// A copy for a render slot to hand the next render; `None` if it can't be reused.
    #[doc(hidden)]
    fn copy(_value: &Self::Output) -> Option<Self::Output> {
        None
    }
}

/// `axum::http::StatusCode`: the call yields the status.
pub struct StatusCode;
/// `SseStream<E, _>`: the call yields an [`EventStream`].
pub struct SseStream<E>(PhantomData<fn() -> E>);
/// `SseStream<E, _>` from a route that isn't a GET: the call yields a [`Once`].
pub struct SseOnce<E>(PhantomData<fn() -> E>);
/// `doxa::Attachment`: the call yields a [`Download`].
pub struct Attachment;
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
        Fetch::Invalid(f) => Fetch::Invalid(f),
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
    fn decode(_: u16, _: &[(String, String)], body: Vec<u8>) -> Result<T, String> {
        serde_json::from_slice(&body).map_err(|e| e.to_string())
    }
    fn copy(value: &T) -> Option<T> {
        Some(value.clone())
    }
}

macro_rules! forward {
    () => {
        const STREAMS: bool = R::STREAMS;
        fn decode(
            status: u16,
            headers: &[(String, String)],
            body: Vec<u8>,
        ) -> Result<Self::Output, String> {
            R::decode(status, headers, body)
        }
        fn stream(hub: Rc<Hub>) -> Self::Output {
            R::stream(hub)
        }
        fn copy(value: &Self::Output) -> Option<Self::Output> {
            R::copy(value)
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

/// The status the server chose, beside the body.
impl<R: FromResponse> FromResponse for (StatusCode, R) {
    type Output = (u16, R::Output);
    type Error = R::Error;
    const STREAMS: bool = R::STREAMS;
    fn decode(
        status: u16,
        headers: &[(String, String)],
        body: Vec<u8>,
    ) -> Result<Self::Output, String> {
        Ok((status, R::decode(status, headers, body)?))
    }
    fn stream(hub: Rc<Hub>) -> Self::Output {
        (200, R::stream(hub))
    }
    fn copy(value: &Self::Output) -> Option<Self::Output> {
        Some((value.0, R::copy(&value.1)?))
    }
}

impl FromResponse for StatusCode {
    type Output = u16;
    type Error = NoError;
    fn decode(status: u16, _: &[(String, String)], _: Vec<u8>) -> Result<u16, String> {
        Ok(status)
    }
    fn copy(value: &u16) -> Option<u16> {
        Some(*value)
    }
}

impl FromResponse for () {
    type Output = ();
    type Error = NoError;
    fn decode(_: u16, _: &[(String, String)], _: Vec<u8>) -> Result<(), String> {
        Ok(())
    }
    fn copy(_: &()) -> Option<()> {
        Some(())
    }
}

impl FromResponse for String {
    type Output = String;
    type Error = NoError;
    fn decode(_: u16, _: &[(String, String)], body: Vec<u8>) -> Result<String, String> {
        String::from_utf8(body).map_err(|e| e.to_string())
    }
    fn copy(value: &String) -> Option<String> {
        Some(value.clone())
    }
}

impl<E: DeserializeOwned + 'static> FromResponse for SseStream<E> {
    type Output = EventStream<E>;
    type Error = NoError;
    const STREAMS: bool = true;
    fn decode(_: u16, _: &[(String, String)], _: Vec<u8>) -> Result<EventStream<E>, String> {
        Err("an event stream arrived buffered".to_owned())
    }
    fn stream(hub: Rc<Hub>) -> EventStream<E> {
        EventStream::subscribe(hub)
    }
}

impl<E: DeserializeOwned + 'static> FromResponse for SseOnce<E> {
    type Output = Once<E>;
    type Error = NoError;
    const STREAMS: bool = true;
    fn decode(_: u16, _: &[(String, String)], _: Vec<u8>) -> Result<Once<E>, String> {
        Err("an event stream arrived buffered".to_owned())
    }
    fn stream(hub: Rc<Hub>) -> Once<E> {
        Once::subscribe(hub)
    }
}

/// A file a route sent: its bytes, type and suggested name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Download {
    /// The file's contents.
    pub bytes: Vec<u8>,
    /// `content-type`, if sent.
    pub content_type: Option<String>,
    /// The name `content-disposition` suggests saving it under.
    pub filename: Option<String>,
}

impl FromResponse for Attachment {
    type Output = Download;
    type Error = NoError;
    fn decode(_: u16, headers: &[(String, String)], bytes: Vec<u8>) -> Result<Download, String> {
        let header = |n: &str| {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(n))
                .map(|(_, v)| v.as_str())
        };
        Ok(Download {
            bytes,
            content_type: header("content-type").map(str::to_owned),
            filename: header("content-disposition").and_then(filename),
        })
    }
    fn copy(value: &Download) -> Option<Download> {
        Some(value.clone())
    }
}

/// The `filename*` (RFC 5987, UTF-8) or `filename` of a `content-disposition` value.
fn filename(disposition: &str) -> Option<String> {
    let params = || disposition.split(';').skip(1).map(str::trim);
    let extended = params().find_map(|p| p.strip_prefix("filename*="));
    if let Some(v) = extended.and_then(|v| v.split_once("''").map(|(_, v)| v)) {
        let decoded = percent_encoding::percent_decode_str(v).decode_utf8().ok()?;
        return Some(decoded.into_owned());
    }
    let v = params().find_map(|p| p.strip_prefix("filename="))?;
    Some(
        match v.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
            Some(q) => q.replace("\\\"", "\"").replace("\\\\", "\\"),
            None => v.to_owned(),
        },
    )
}

impl FromResponse for Unsupported {
    type Output = Unsupported;
    type Error = NoError;
    fn decode(_: u16, _: &[(String, String)], _: Vec<u8>) -> Result<Unsupported, String> {
        Err("this route's response isn't client-callable".to_owned())
    }
}

#[cfg(test)]
mod status_tests {
    use super::*;

    type Counted = (StatusCode, crate::arg::Json<u32>);

    #[test]
    fn a_status_and_body_decode_together() {
        let out = Counted::decode(202, &[], b"7".to_vec()).unwrap();
        assert_eq!(out, (202, 7));
    }
}
