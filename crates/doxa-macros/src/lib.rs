//! Procedural macros for [`doxa`](../doxa/index.html).
//!
//! # Derive macros
//!
//! - [`macro@ApiError`] — wires an error enum into both
//!   [`axum::response::IntoResponse`] and [`utoipa::IntoResponses`] from a
//!   single per-variant `#[api(...)]` declaration. Multiple variants sharing
//!   a status code are grouped into one OpenAPI response with distinct
//!   examples. An optional `outcome` attribute integrates with the audit
//!   trail.
//! - [`macro@SseEvent`] — implements
//!   [`SseEventMeta`](../doxa/trait.SseEventMeta.html) for a tagged enum
//!   so [`SseStream`](../doxa/struct.SseStream.html) names each SSE frame
//!   after the variant carrying it. Override names with `#[sse(name = "…")]`.
//!
//! # HTTP method attribute macros
//!
//! [`macro@get`], [`macro@post`], [`macro@put`], [`macro@patch`],
//! [`macro@delete`] delegate to [`utoipa::path`] with automatic inference
//! from the handler signature. Use [`macro@operation`] for custom or
//! multi-method routes.
//!
//! ## What the method macros infer
//!
//! - **`operation_id`** — defaults to the function name.
//! - **`request_body`** — detected from the first `Json<T>` parameter,
//!   including through transparent wrappers like `Valid<Json<T>>`.
//! - **Path parameters** — `{name}` segments in the route template are
//!   matched to `Path<T>` extractors (scalar, tuple, and struct forms).
//! - **Query parameters** — `Query<T>` extractors (including wrapped)
//!   contribute query parameters via trait dispatch.
//! - **Header parameters** — `Header<H>` extractors contribute header
//!   parameters. The `headers(H1, H2)` attribute documents headers
//!   without extracting them; both forms deduplicate.
//! - **Success response** — `Json<T>` → 200; `(StatusCode, Json<T>)` → 201;
//!   `SseStream<E, _>` → `text/event-stream` with per-variant event names.
//! - **Error responses** — the `E` from `Result<_, E>` is folded into
//!   `responses(...)` as an `IntoResponses` reference.
//! - **Tags** — `tag = "Name"` for a single tag, `tags("A", "B")` for
//!   multiple. Tags control grouping in documentation UIs.
//!
//! Explicit overrides always win: if you supply `request_body = ...`,
//! `params(...)`, or `responses(...)` by hand, inference for that field
//! is suppressed.
//!
//! # Capability attribute macro
//!
//! [`macro@capability`] declares a `Capable` marker type backed by a
//! `Capability` constant for use with `doxa_auth::Require<M>`.
//!
//! # Usage
//!
//! Consumers should depend on `doxa` (with the default `macros`
//! feature) and import these macros via `doxa::{get, post,
//! ApiError, SseEvent, …}` rather than depending on this crate
//! directly.
//!
//! # Tour
//!
//! Every macro the crate exports, exercised end-to-end. Compiles
//! under `cargo test --doc`.
//!
//! ```no_run
//! use axum::Json;
//! use doxa::{
//!     routes, ApiDocBuilder, ApiResult, DocumentedHeader, Header,
//!     MountDocsExt, MountOpts, OpenApiRouter, SseEventMeta, SseStream, ToSchema,
//! };
//! use doxa::{get, post, ApiError, SseEvent};
//! use futures_core::Stream;
//! use serde::{Deserialize, Serialize};
//! use std::convert::Infallible;
//!
//! // -- ApiError: multi-variant-per-status grouping --------------------------
//! #[derive(Debug, thiserror::Error, Serialize, ToSchema, ApiError)]
//! enum WidgetError {
//!     #[error("validation failed: {0}")]
//!     #[api(status = 400, code = "validation_error")]
//!     Validation(String),
//!
//!     // Second variant at the same status — the OpenAPI spec emits one
//!     // 400 response with two named examples.
//!     #[error("conflict: {0}")]
//!     #[api(status = 400, code = "conflict")]
//!     Conflict(String),
//!
//!     #[error("not found")]
//!     #[api(status = 404, code = "not_found")]
//!     NotFound,
//! }
//!
//! // -- SseEvent: variant-tagged event stream --------------------------------
//! #[derive(Serialize, ToSchema, SseEvent)]
//! #[serde(tag = "event", content = "data", rename_all = "snake_case")]
//! enum BuildEvent {
//!     Started { id: u64 },
//!     Progress { done: u64, total: u64 },
//!     // Override the default snake-case event name.
//!     #[sse(name = "finished")]
//!     Completed,
//! }
//!
//! // -- DocumentedHeader: typed header on the handler signature --------------
//! struct XApiKey;
//! impl DocumentedHeader for XApiKey {
//!     fn name() -> &'static str { "X-Api-Key" }
//!     fn description() -> &'static str { "Tenant API key" }
//! }
//!
//! // -- Method shortcuts: tags, request body, headers, Result return --------
//! #[derive(Debug, Serialize, ToSchema)]
//! struct Widget { id: u32, name: String }
//!
//! #[derive(Debug, Deserialize, ToSchema)]
//! struct CreateWidget { name: String }
//!
//! /// Single tag — forwarded to utoipa as `tag = "Widgets"`.
//! #[get("/widgets", tag = "Widgets")]
//! async fn list_widgets(
//!     Header(_key, ..): Header<XApiKey>,
//! ) -> ApiResult<Json<Vec<Widget>>, WidgetError> {
//!     Ok(Json(vec![]))
//! }
//!
//! /// Multiple tags — emitted as `tags = ["Widgets", "Public"]`.
//! /// Inferred request body (`Json<CreateWidget>`), inferred 201
//! /// success from `(StatusCode, Json<T>)`, error responses folded
//! /// in from the `Err` half of the return.
//! #[post("/widgets", tags("Widgets", "Public"))]
//! async fn create_widget(
//!     Json(req): Json<CreateWidget>,
//! ) -> ApiResult<(axum::http::StatusCode, Json<Widget>), WidgetError> {
//!     Ok((
//!         axum::http::StatusCode::CREATED,
//!         Json(Widget { id: 1, name: req.name }),
//!     ))
//! }
//!
//! /// Document a header without extracting its value — the marker is
//! /// listed under `headers(...)` and dedupes against any concurrent
//! /// `Header<H>` extractor on the same handler.
//! #[get("/health", headers(XApiKey))]
//! async fn health() -> &'static str { "ok" }
//!
//! /// SseStream<E, _> return is recognized by the macro and emitted as
//! /// a `text/event-stream` response with one `oneOf` branch per
//! /// `SseEvent` variant.
//! #[get("/builds/{id}/events", tag = "Builds")]
//! async fn stream_build(
//! ) -> SseStream<BuildEvent, impl Stream<Item = Result<BuildEvent, Infallible>>> {
//!     SseStream::new(futures::stream::iter(Vec::new()))
//! }
//!
//! # async fn run() {
//! let (router, openapi) = OpenApiRouter::<()>::new()
//!     .routes(routes!(list_widgets, create_widget, health))
//!     .routes(routes!(stream_build))
//!     .split_for_parts();
//!
//! let api_doc = ApiDocBuilder::new()
//!     .title("Tour")
//!     .version("1.0.0")
//!     .merge(openapi)
//!     .build();
//!
//! let app = router.mount_docs(api_doc, MountOpts::default());
//! # let _ = app;
//! # }
//! ```
//!
//! ## Header form equivalence
//!
//! The shortcut macros recognize two ways to declare a header on a
//! handler — the `Header<H>` extractor in the signature **and** the
//! `headers(H, …)` attribute. Both rely on the
//! [`DocumentedHeader`](../doxa/trait.DocumentedHeader.html)
//! trait, which exposes the wire name as a runtime fn so the same
//! marker can be reused on the layer side via
//! [`HeaderParam::typed`](../doxa/struct.HeaderParam.html#method.typed).
//! Both forms are interchangeable and dedupe against each other if
//! the same marker appears in both, so listing a header in
//! `headers(...)` while also extracting it never produces two spec
//! entries.
//!
//! See the `doxa` crate-level docs for the broader design.

use proc_macro::TokenStream;

mod api_error;
mod capability;
mod method;
mod sig;
mod sse_event;

/// Derive [`axum::response::IntoResponse`] and [`utoipa::IntoResponses`]
/// for an error enum from a single per-variant declaration.
///
/// Each variant is annotated with `#[api_error(status = N, code =
/// "string")]` where:
///
/// - `status` — the HTTP status code as a `u16` literal
/// - `code` — an application-level error code string written into the `code`
///   field of the
///   [`doxa::ApiErrorBody`](../doxa/struct.ApiErrorBody.html)
///   response body emitted by the generated `IntoResponse` impl
///
/// Multiple variants may share the same status code. The derive groups
/// them at expand time so the OpenAPI spec emits one `Response` per
/// status with each variant contributing a named example.
///
/// # Example
///
/// ```no_run
/// use doxa::{ApiError, ToSchema};
/// use serde::Serialize;
///
/// #[derive(Debug, thiserror::Error, Serialize, ToSchema, ApiError)]
/// pub enum MyError {
///     #[error("validation failed: {0}")]
///     #[api(status = 400, code = "validation_error")]
///     Validation(String),
///
///     #[error("query failed: {0}")]
///     #[api(status = 400, code = "query_error")]
///     Query(String),
///
///     #[error("not found: {0}")]
///     #[api(status = 404, code = "not_found")]
///     NotFound(String),
///
///     #[error("internal error")]
///     #[api(status = 500, code = "internal")]
///     Internal,
/// }
/// ```
///
/// The generated `IntoResponse` impl maps each variant to its declared
/// status and emits an `ApiErrorBody` envelope with the variant's
/// `code` and the variant's `Display` output as the `message`. The
/// `IntoResponses` impl groups `Validation` and `Query` under one
/// `400` response with two examples.
#[proc_macro_derive(ApiError, attributes(api, api_error, api_default))]
pub fn derive_api_error(input: TokenStream) -> TokenStream {
    api_error::expand(input.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Derive [`SseEventMeta`](../doxa/trait.SseEventMeta.html) for an
/// enum whose variants represent the events of a Server-Sent Event
/// stream.
///
/// Pair with upstream `serde::Serialize` and `utoipa::ToSchema` derives
/// plus `#[serde(tag = "event", content = "data", rename_all =
/// "snake_case")]` so the wire format and the OpenAPI schema stay
/// aligned. Each variant's event name defaults to its snake-case form;
/// override with `#[sse(name = "…")]`.
///
/// ```no_run
/// use doxa::SseEvent;
///
/// #[derive(serde::Serialize, utoipa::ToSchema, SseEvent)]
/// #[serde(tag = "event", content = "data", rename_all = "snake_case")]
/// enum MigrationEvent {
///     Started { pipeline: String },
///     Progress { done: u64, total: u64 },
///     #[sse(name = "finished")]
///     Completed,
///     Heartbeat,
/// }
/// ```
///
/// The derive does not implement `Serialize` or `ToSchema` itself —
/// that keeps serde's renaming rules authoritative and avoids
/// duplicating them in this crate.
#[proc_macro_derive(SseEvent, attributes(sse))]
pub fn derive_sse_event(input: TokenStream) -> TokenStream {
    sse_event::expand(input.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Shortcut for `#[utoipa::path(get, path = "...")]`.
///
/// Auto-fills `operation_id` from the function name when omitted. The
/// path string lives in exactly one place.
///
/// Supports `tag = "..."` for a single tag or `tags("A", "B")` for
/// multiple tags. Tags control how operations are grouped in
/// documentation UIs (Scalar, Swagger UI, Redoc) and code generators.
///
/// Additional `key = value` pairs are forwarded to `utoipa::path`
/// verbatim, so any feature accepted by the upstream macro (request
/// body, responses, security, params) works without modification.
///
/// # Tags
///
/// ```no_run
/// use doxa::get;
///
/// // Single tag (forwarded to utoipa as-is):
/// #[get("/api/v1/models", tag = "Models")]
/// async fn list_models() -> &'static str { "[]" }
///
/// // Multiple tags (extracted and emitted as `tags = [...]`):
/// #[get("/api/v2/models", tags("Models", "Public API"))]
/// async fn list_models_public() -> &'static str { "[]" }
/// ```
#[proc_macro_attribute]
pub fn get(args: TokenStream, item: TokenStream) -> TokenStream {
    method::expand("get", args.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// `#[post("/path", ...)]` shortcut for [`utoipa::path`]. See
/// [`macro@get`] for the inference rules.
#[proc_macro_attribute]
pub fn post(args: TokenStream, item: TokenStream) -> TokenStream {
    method::expand("post", args.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// `#[put("/path", ...)]` shortcut for [`utoipa::path`]. See
/// [`macro@get`] for the inference rules.
#[proc_macro_attribute]
pub fn put(args: TokenStream, item: TokenStream) -> TokenStream {
    method::expand("put", args.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// `#[patch("/path", ...)]` shortcut for [`utoipa::path`]. See
/// [`macro@get`] for the inference rules.
#[proc_macro_attribute]
pub fn patch(args: TokenStream, item: TokenStream) -> TokenStream {
    method::expand("patch", args.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// `#[delete("/path", ...)]` shortcut for [`utoipa::path`]. See
/// [`macro@get`] for the inference rules.
#[proc_macro_attribute]
pub fn delete(args: TokenStream, item: TokenStream) -> TokenStream {
    method::expand("delete", args.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Declare a `Capable` marker type backed by a `Capability` constant.
///
/// Generates the struct, a hidden `Capability` constant, and the
/// `Capable` impl so the marker can be used with
/// `doxa_auth::Require<M>` immediately. Requires `doxa-policy` in the
/// consumer's dependency tree.
///
/// # Attribute arguments
///
/// - `name = "scope.name"` — the stable client-facing capability identifier.
/// - `description = "Human-readable description"` — displayed in UI badges.
/// - `checks(action = "...", entity_type = "...", entity_id = "...")` — one or
///   more check blocks. All must pass for the capability to be granted.
///
/// # Example
///
/// ```no_run
/// use doxa::capability;
///
/// #[capability(
///     name = "widgets.read",
///     description = "Read widget definitions",
///     checks(action = "read", entity_type = "Widget", entity_id = "collection"),
/// )]
/// pub struct WidgetsRead;
/// ```
#[proc_macro_attribute]
pub fn capability(args: TokenStream, item: TokenStream) -> TokenStream {
    capability::expand(args.into(), item.into()).into()
}

/// Generic operation attribute for cases where the HTTP method must be
/// specified explicitly (multi-method routes, non-standard verbs).
///
/// `#[operation(get, "/path", ...)]` is equivalent to
/// `#[get("/path", ...)]`. Prefer the method-specific shortcuts for
/// clarity.
#[proc_macro_attribute]
pub fn operation(args: TokenStream, item: TokenStream) -> TokenStream {
    method::expand_operation(args.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
