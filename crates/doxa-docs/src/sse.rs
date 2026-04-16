//! Runtime support for Server-Sent Event streams typed by an event enum.
//!
//! A handler returning [`SseStream<E, S>`] produces an SSE response
//! whose event frames are named after the variant of `E` carried by
//! each stream item. The event name and JSON payload are derived from
//! the [`SseEventMeta`] trait, which the
//! [`SseEvent`](doxa_macros::SseEvent) derive implements
//! alongside [`utoipa::ToSchema`] for the same enum.
//!
//! The typed enum is the single source of truth for both the wire
//! format (variant → `event:` line + JSON `data:`) and the OpenAPI
//! description (`oneOf` of tagged variant objects under
//! `text/event-stream`). Handlers never construct
//! [`axum::response::sse::Event`] values directly — [`SseStream`]
//! owns that conversion so variants cannot drift out of sync with the
//! rendered documentation.
//!
//! # Example
//!
//! ```no_run
//! use doxa::{SseEventMeta, SseStream};
//! use futures_core::Stream;
//! use std::convert::Infallible;
//!
//! // Normally derived with `#[derive(doxa::SseEvent,
//! // serde::Serialize)]`; shown here as a hand-written impl for
//! // clarity.
//! #[derive(serde::Serialize)]
//! #[serde(tag = "event", content = "data", rename_all = "snake_case")]
//! enum BuildEvent {
//!     Started { id: u64 },
//!     Progress { done: u64, total: u64 },
//! }
//!
//! impl SseEventMeta for BuildEvent {
//!     fn event_name(&self) -> &'static str {
//!         match self {
//!             Self::Started { .. } => "started",
//!             Self::Progress { .. } => "progress",
//!         }
//!     }
//!
//!     fn all_event_names() -> &'static [&'static str] {
//!         &["started", "progress"]
//!     }
//! }
//!
//! async fn stream_handler(
//! ) -> SseStream<BuildEvent, impl Stream<Item = Result<BuildEvent, Infallible>>> {
//!     let events = futures::stream::iter(vec![
//!         Ok(BuildEvent::Started { id: 1 }),
//!         Ok(BuildEvent::Progress { done: 1, total: 10 }),
//!     ]);
//!     SseStream::new(events)
//! }
//! ```
//!
//! [`axum::response::sse::Event`]: https://docs.rs/axum/latest/axum/response/sse/struct.Event.html

use std::convert::Infallible;
use std::marker::PhantomData;

use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use futures_core::Stream;

/// Vendor-extension key marking a response's `text/event-stream`
/// content entry as an SSE stream for the builder's post-process to
/// recognize.
///
/// Emitted by the [`mark_sse_response`] helper (which the method-shortcut
/// macros call when they infer an `SseStream<E, …>` return type) and
/// stripped by the builder in both OpenAPI 3.1 and 3.2 output modes so
/// it never leaks to downstream consumers.
pub(crate) const SSE_STREAM_MARKER_KEY: &str = "x-sse-stream";

/// Tag `op`'s `200` response's `text/event-stream` content entry with
/// an `x-sse-stream: true` vendor extension. Invoked from the
/// [`crate::DocResponseBody`] impl for [`SseStream`] after it inserts
/// the response; the builder's spec-version post-process reads the
/// marker to decide whether to rewrite `schema` → `itemSchema`.
///
/// Idempotent: repeated calls with the same operation produce a
/// single marker entry.
pub(crate) fn mark_sse_response(op: &mut utoipa::openapi::path::Operation) {
    use utoipa::openapi::RefOr;

    let Some(resp) = op.responses.responses.get_mut("200") else {
        return;
    };
    let RefOr::T(resp) = resp else {
        return;
    };
    let Some(content) = resp.content.get_mut("text/event-stream") else {
        return;
    };

    // Round-trip through `serde_json::Value` because utoipa's
    // `Extensions` type does not expose its inner map by reference.
    let existing = content
        .extensions
        .as_ref()
        .and_then(|e| serde_json::to_value(e).ok());
    let already = matches!(
        existing.as_ref().and_then(|v| v.get(SSE_STREAM_MARKER_KEY)),
        Some(serde_json::Value::Bool(true))
    );
    if already {
        return;
    }

    let ext = utoipa::openapi::extensions::ExtensionsBuilder::new()
        .add(SSE_STREAM_MARKER_KEY, serde_json::Value::Bool(true))
        .build();
    match content.extensions.as_mut() {
        Some(existing) => existing.merge(ext),
        None => content.extensions = Some(ext),
    }
}

/// Per-variant metadata for a Server-Sent Event enum.
///
/// Implemented automatically by the
/// [`SseEvent`](doxa_macros::SseEvent) derive; hand-written
/// impls are supported but rare. The trait exposes two pieces of
/// information:
///
/// - [`Self::event_name`] — the event name emitted on the `event:` line of the
///   SSE frame for a specific value. Defaults to the snake-case form of the
///   variant name; overridable per variant via `#[sse(name = "…")]`.
/// - [`Self::all_event_names`] — the full set of event names the enum can
///   produce, in declaration order. Surfaced for documentation/testing; not
///   used on the hot path.
pub trait SseEventMeta {
    /// Return the SSE event name for the current variant.
    fn event_name(&self) -> &'static str;

    /// Return every event name this enum can produce, in variant
    /// declaration order.
    fn all_event_names() -> &'static [&'static str];
}

/// A typed SSE response stream.
///
/// Wraps a [`Stream`] of `Result<E, Err>` and produces an
/// [`axum::response::sse::Sse`] response on `IntoResponse`. Each
/// stream item is serialized to JSON and framed with the event name
/// returned by [`SseEventMeta::event_name`].
///
/// The [`SseStream`] newtype is what the
/// [`#[derive(SseEvent)]`](doxa_macros::SseEvent) integration
/// reads at documentation-generation time to attach the
/// `text/event-stream` response and its schema to the operation —
/// handlers that return `SseStream<E, _>` get the right OpenAPI
/// description for free.
///
/// Keep-alive comments are enabled by default so intermediaries do
/// not close idle connections; swap via [`Self::with_keep_alive`].
pub struct SseStream<E, S> {
    stream: S,
    keep_alive: Option<KeepAlive>,
    _event: PhantomData<fn() -> E>,
}

impl<E, S> SseStream<E, S> {
    /// Wrap a stream of events. Enables the default keep-alive.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            keep_alive: Some(KeepAlive::default()),
            _event: PhantomData,
        }
    }

    /// Replace the keep-alive configuration. Pass [`None`] to
    /// disable keep-alive frames entirely.
    pub fn with_keep_alive(mut self, keep_alive: Option<KeepAlive>) -> Self {
        self.keep_alive = keep_alive;
        self
    }
}

impl<E, S, Err> IntoResponse for SseStream<E, S>
where
    E: SseEventMeta + serde::Serialize + Send + 'static,
    S: Stream<Item = Result<E, Err>> + Send + Unpin + 'static,
    Err: std::error::Error + Send + Sync + 'static,
{
    fn into_response(self) -> Response {
        let mapped = EventMapStream {
            inner: self.stream,
            _event: PhantomData::<fn() -> E>,
        };
        // Apply a keep-alive unconditionally so the method chain stays
        // monomorphic (otherwise the `Sse<…>` generic argument diverges
        // between the two branches). Callers that pass
        // `with_keep_alive(None)` get a keep-alive with a one-day
        // interval — effectively disabled for any realistic request,
        // but it keeps the return type stable and avoids `Instant`
        // overflow that an actual `u64::MAX` interval would trigger.
        let ka = self.keep_alive.unwrap_or_else(|| {
            KeepAlive::new().interval(std::time::Duration::from_secs(60 * 60 * 24))
        });
        Sse::new(mapped).keep_alive(ka).into_response()
    }
}

// A thin adapter that maps each `Result<E, Err>` into the
// `Result<Event, Infallible>` shape axum's `Sse` expects. JSON
// serialization failures are logged and the frame is replaced with
// an `error` event — keeping the stream alive is more useful than
// dropping a whole subscription because one payload was malformed.
struct EventMapStream<E, S> {
    inner: S,
    _event: PhantomData<fn() -> E>,
}

impl<E, S, Err> Stream for EventMapStream<E, S>
where
    E: SseEventMeta + serde::Serialize,
    S: Stream<Item = Result<E, Err>> + Unpin,
    Err: std::error::Error,
{
    type Item = Result<Event, Infallible>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use std::task::Poll;
        match std::pin::Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(ev))) => Poll::Ready(Some(Ok(event_for(&ev)))),
            Poll::Ready(Some(Err(err))) => {
                tracing::warn!(error = %err, "sse upstream stream item failed");
                let frame = Event::default().event("error").data(err.to_string());
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<E, S> Unpin for EventMapStream<E, S> where S: Unpin {}

/// Build the [`Event`] for a single typed value. Logs and falls back
/// to an `error` frame if the JSON payload cannot be serialized.
fn event_for<E>(value: &E) -> Event
where
    E: SseEventMeta + serde::Serialize,
{
    let name = value.event_name();
    match Event::default().event(name).json_data(value) {
        Ok(ev) => ev,
        Err(err) => {
            tracing::error!(
                error = %err,
                event_name = name,
                "sse json_data serialization failed; emitting error frame",
            );
            Event::default().event("error").data(err.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use futures::stream;
    use http_body_util::BodyExt;

    #[derive(serde::Serialize)]
    #[serde(tag = "event", content = "data", rename_all = "snake_case")]
    enum Ev {
        Started { pipeline: String },
        Done,
    }

    impl SseEventMeta for Ev {
        fn event_name(&self) -> &'static str {
            match self {
                Self::Started { .. } => "started",
                Self::Done => "done",
            }
        }
        fn all_event_names() -> &'static [&'static str] {
            &["started", "done"]
        }
    }

    #[tokio::test]
    async fn into_response_sets_text_event_stream_content_type() {
        let s = SseStream::<Ev, _>::new(stream::iter(Vec::<Result<Ev, Infallible>>::new()));
        let resp: Response = s.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .unwrap();
        assert!(ct.to_str().unwrap().starts_with("text/event-stream"));
    }

    #[tokio::test]
    async fn emits_named_event_frame_with_json_data_for_each_item() {
        let items: Vec<Result<Ev, Infallible>> = vec![
            Ok(Ev::Started {
                pipeline: "p1".into(),
            }),
            Ok(Ev::Done),
        ];
        let s = SseStream::<Ev, _>::new(stream::iter(items)).with_keep_alive(None);

        let resp: Response = s.into_response();
        // Drain the response body and inspect the framed output.
        let body: Body = resp.into_body();
        let bytes = body.collect().await.unwrap().to_bytes();
        let text = std::str::from_utf8(&bytes).unwrap();

        assert!(text.contains("event: started"));
        assert!(text.contains(r#""event":"started""#));
        assert!(text.contains(r#""pipeline":"p1""#));
        assert!(text.contains("event: done"));
        assert!(text.contains(r#""event":"done""#));
    }
}
