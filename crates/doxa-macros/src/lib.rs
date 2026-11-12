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
//! # #[derive(Clone, doxa::State)] struct NoState;
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
//! #[derive(Serialize, SseEvent)]
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
use proc_macro2::TokenStream as TS2;

/// The expansion this crate's role needs: one of the two, or both behind `target_arch`.
fn by_role(
    server: impl FnOnce() -> syn::Result<TS2>,
    client: impl FnOnce() -> syn::Result<TS2>,
) -> TokenStream {
    use doxa_macro_support::Role;
    let out = match Role::current() {
        Role::Server => server(),
        Role::Client => client(),
        Role::Api => server().and_then(|s| client().map(|c| doxa_macro_support::split(s, c))),
    };
    out.unwrap_or_else(syn::Error::into_compile_error).into()
}

/// Fail if this option is already in `seen`, which collects across an item's attributes.
fn given_once(
    seen: &mut std::collections::HashSet<String>,
    meta: &syn::meta::ParseNestedMeta,
) -> syn::Result<()> {
    let key = quote::ToTokens::to_token_stream(&meta.path).to_string();
    if seen.insert(key.clone()) {
        Ok(())
    } else {
        Err(meta.error(format!("`{key}` is given twice")))
    }
}

mod actions;
mod api_error;
mod app;
mod asset;
mod capability;
mod client_stub;
mod dto;
mod entity;
mod grant;
mod method;
mod mirror;
mod policy_resource;
mod role;
mod sig;
mod sse_event;
mod ty;
mod validator;

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
///
/// `#[api(transparent)]` takes a variant's status, code and audit outcome from a nested error:
///
/// ```no_run
/// # use doxa::{ApiError, ToSchema};
/// # use serde::Serialize;
/// # #[derive(Debug, thiserror::Error, Serialize, ToSchema, ApiError)]
/// # pub enum ApiFault {
/// #     #[error("rate limited")]
/// #     #[api(status = 429, code = "rate_limited")]
/// #     RateLimited,
/// # }
/// #[derive(Debug, thiserror::Error, Serialize, ToSchema, ApiError)]
/// pub enum SyncError {
///     #[error("no such pipeline: {0}")]
///     #[api(status = 404, code = "pipeline_not_found")]
///     PipelineNotFound(String),
///
///     #[error(transparent)]
///     #[api(transparent)]
///     #[serde(untagged)]
///     Fault(ApiFault),
/// }
/// ```
///
/// Its responses merge into the outer enum's. `#[serde(untagged)]` (last variant) keeps the body
/// flat: `{"error": {"RateLimited": …}}`, not `{"error": {"Fault": {…}}}`.
///
/// `#[api(internal)]` marks the one variant `doxa::Internal` converts into:
///
/// ```
/// # use doxa::{ApiError, ToSchema};
/// #[derive(Debug, thiserror::Error, serde::Serialize, ToSchema, ApiError)]
/// pub enum E {
///     #[error("{0}")]
///     #[api(status = 500, internal)]
///     Internal(String),
/// }
/// let _: E = doxa::Internal("db down".into()).into();
/// ```
///
/// ```compile_fail
/// # use doxa::{ApiError, ToSchema};
/// #[derive(Debug, thiserror::Error, serde::Serialize, ToSchema, ApiError)]
/// pub enum E {
///     #[error("{0}")]
///     #[api(status = 500, internal)]
///     Internal(String),
///     #[error("again")]
///     #[api(status = 503, internal)]
///     Again,
/// }
/// ```
#[proc_macro_derive(ApiError, attributes(api, api_error, api_default))]
pub fn derive_api_error(input: TokenStream) -> TokenStream {
    by_role(|| api_error::expand(input.into()), || Ok(TS2::new()))
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
/// #[derive(serde::Serialize, SseEvent)]
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
/// The derive implements `ToSchema` for the enum — a discriminated `oneOf`
/// with one component per variant and an OpenAPI `discriminator` keyed on
/// the serde tag (utoipa's own derive can't express this for tagged enums).
/// It does **not** implement `Serialize`: pair it with serde's `Serialize`
/// derive, which stays authoritative for the wire format. Variants must be
/// unit, newtype, or named-struct (their fields must implement
/// `utoipa::PartialSchema`; wrap `chrono`/`uuid` fields in a payload type).
#[proc_macro_derive(SseEvent, attributes(sse))]
pub fn derive_sse_event(input: TokenStream) -> TokenStream {
    by_role(|| sse_event::expand(input.into()), || Ok(TS2::new()))
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
/// # #[derive(Clone, doxa::State)] struct NoState;
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

/// Cedar entity identity, for authorizing a type by instance with `Granted<R>`.
///
/// Fields take `#[resource(id)]`, `#[resource(attr)]` (`attr = "key"` renames) and
/// `#[resource(parent = "Folder")]`. `id_with = method` computes the id; `attrs_with = method`
/// merges extra attributes, panicking on a key a field already supplies.
///
/// ```ignore
/// #[derive(PolicyResource)]
/// #[resource(entity_type = "Widget")]
/// struct Widget {
///     #[resource(id)]              id: u32,
///     #[resource(attr)]            region: String,
///     #[resource(parent = "Folder")] folder_id: String,
///     name: String,
/// }
/// ```
///
/// With `policy-sea-orm`, `#[resource(scope)]` emits `ScopedTable` (every lookup confined to that
/// column) and `#[resource(key)]` adds `ScopedRow`, keyed on the column the route matches.
///
/// ```ignore
/// #[derive(DeriveEntityModel, PolicyResource)]
/// #[sea_orm(table_name = "connections")]
/// #[resource(entity_type = "Connection")]
/// pub struct Model {
///     #[sea_orm(primary_key)]        pub id: Uuid,
///     #[resource(id, attr, key)]     pub name: String,
///     #[resource(parent = "Tenant", scope)] pub tenant_id: String,
/// }
///
/// let row = Model::load_scoped("primary".to_owned(), &db, "acme").await?;
/// ```
///
/// `#[resource(key(FindByPair))]` on each column taking part emits a named `Lookup` marker:
///
/// ```ignore
/// #[resource(entity_type = "Revision")]
/// pub struct Model {
///     #[sea_orm(primary_key)]                        pub id: Uuid,
///     #[resource(id, key(FindByWidget, FindByPair))] pub widget: String,
///     #[resource(key(FindByPair))]                   pub revision: i64,
///     #[resource(scope)]                             pub tenant_id: String,
/// }
///
/// // …and the asset names the way in rather than the row:
/// #[asset(with = FindByPair, profile = AppGrants, actions = RevisionAction)]
/// pub struct RevisionByPair;
/// ```
///
/// A composite lookup gets a key struct (`FindByPairKey`) so same-typed segments can't transpose.
/// Every lookup is built on `ScopedTable::scoped`, so all stay confined to the scope.
///
/// `#[resource(filter = …)]`, repeatable and `AND`ed, adds a SeaORM condition to every query:
///
/// ```ignore
/// #[resource(entity_type = "Revision", filter = Column::DeletedAt.is_null())]
/// ```
#[proc_macro_derive(PolicyResource, attributes(resource))]
pub fn derive_policy_resource(input: TokenStream) -> TokenStream {
    by_role(|| policy_resource::expand(input.into()), || Ok(TS2::new()))
}

/// An asset's action vocabulary as one enum: a marker per variant, `impl ActionTable`, and
/// `ALL` / `as_static`. Every default but the audit category comes from the names:
///
/// | | Default | Override |
/// |---|---|---|
/// | Cedar action | `snake_case` of the variant | `#[action(name = …)]` |
/// | capability | `{prefix}.{action}` | `#[action(capability = …)]` |
/// | description | the variant's doc comment | `#[action(description = …)]` |
/// | resource noun | enum name less `Action`/`Actions` | `#[actions(resource = …)]` |
/// | capability prefix | `snake_case` of the resource | `#[actions(prefix = …)]` |
/// | check entity type | `{Resource}Collection` | `#[actions(entity_type = …)]` |
/// | check entity id | `"collection"` | `#[actions(entity_id = …)]` |
///
/// `event = …` takes a `&'static str` const expression, such as `EventType::X.as_static()`.
/// `capable = <path>` gates on an existing capability marker instead of declaring one:
///
/// ```ignore
/// #[derive(Actions)]
/// #[actions(resource = "Connection")]
/// pub enum ConnectionAction {
///     #[action(capable = catalog::ConnectionsRead, event = EventType::DataAccess.as_static())]
///     ReadConnection,
///     #[action(capable = catalog::ConnectionsWrite, event = EventType::AdminUpdate.as_static())]
///     WriteConnection,
/// }
/// ```
///
/// ```ignore
/// #[derive(Actions)]
/// pub enum WidgetAction {
///     /// List and view data source definitions.
///     #[action(event = EventType::DataAccess.as_static())]
///     Read,
///     /// Remove data source definitions.
///     #[action(event = EventType::AdminDelete.as_static())]
///     Delete,
///     /// Nothing coarse to check — the instance decides.
///     #[action(instance_only)]
///     Ping,
/// }
///
/// impl Granting for Source {
///     type Actions = WidgetAction;
///     // …
/// }
/// ```
#[proc_macro_derive(Actions, attributes(actions, action))]
pub fn derive_actions(input: TokenStream) -> TokenStream {
    actions::expand(input.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Declare a `Capable` marker type backed by a `Capability` constant.
///
/// Generates the struct, a hidden `Capability` constant, and the
/// `Capable` impl so the marker can be used with
/// `doxa_auth::Require<M>` immediately. Requires the `policy` feature
/// on `doxa` (which re-exports `doxa-policy` as `doxa::policy`).
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
    let item: TS2 = item.into();
    by_role(
        || Ok(capability::expand(args.into(), item.clone())),
        || Ok(item.clone()),
    )
}

/// One route's way into a resource: the `Granting` impl, from the application's profile and
/// the row's own [`fetch`] lookup.
///
/// [`fetch`]: https://docs.rs/doxa-policy/latest/doxa_policy/fetch/index.html
///
/// ```ignore
/// #[doxa::asset(profile = AppGrants, actions = WidgetAction)]
/// pub struct Source { /* … */ }
/// ```
///
/// A second route key over the same row is a unit struct naming the row, which keeps one identity:
///
/// ```ignore
/// #[doxa::asset(row = Source, key = Uuid, profile = AppGrants, actions = WidgetAction)]
/// pub struct WidgetById;
/// ```
///
/// | Option | Default |
/// |---|---|
/// | `profile` | required — the application's `GrantProfile` |
/// | `actions` | required — the enum deriving `Actions` |
/// | `row` | `Self` — or the lookup's, with `with` |
/// | `key` | `<Row as FetchByKey<State>>::Key`; `key = pk` for the row's own id |
/// | `with` | none — names a `Lookup`, which carries the row and the key |
/// | `list` | none — `list = tenant` adds a tenant-confined `Scoping` |
/// | `ctx` | the profile's |
/// | `source` | the profile's — and the state follows it |
/// | `error` | the profile's |
/// | `load_with` | `FetchByKey::fetch`, confined to the caller's tenant |
///
/// `load_with` is handed the whole `Ctx`, so confining it to the caller's tenant is its own job;
/// prefer `with`, whose lookup sees only the scope.
///
/// `list = tenant` confines a listing to the tenant and applies no other policy condition.
#[proc_macro_attribute]
pub fn asset(args: TokenStream, item: TokenStream) -> TokenStream {
    use doxa_macro_support::{tag, Role, Side};
    let (args, item): (TS2, TS2) = (args.into(), item.into());
    // An API crate's browser names entities, never assets.
    if Role::current() == Role::Api {
        return asset::expand(args, item)
            .map(|s| tag(Side::Server, s))
            .unwrap_or_else(syn::Error::into_compile_error)
            .into();
    }
    by_role(
        || asset::expand(args.clone(), item.clone()),
        || asset::expand_client(args.clone(), item.clone()),
    )
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

/// Bring in the prelude for this crate's role: server or client.
///
/// ```ignore
/// doxa::prelude!();
/// ```
#[proc_macro]
pub fn prelude(input: TokenStream) -> TokenStream {
    role::prelude(input.into(), proc_macro::Span::call_site().local_file())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// A server's handlers in this module and below, wrapped in one layer stack.
///
/// ```ignore
/// #[doxa::service(layers = admin)]
/// pub struct WidgetsAdmin;
/// ```
#[proc_macro_attribute]
pub fn service(args: TokenStream, item: TokenStream) -> TokenStream {
    app::service(args.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// A layer stack services share: `fn(Routes, &State) -> Routes`, documented by `docs`.
///
/// ```ignore
/// #[doxa::layers(docs = [doxa::auth::AuthDocs])]
/// pub fn protected(routes: Routes, state: &AppState) -> Routes { routes.layer(auth(state)) }
/// ```
#[proc_macro_attribute]
pub fn layers(args: TokenStream, item: TokenStream) -> TokenStream {
    app::layers(args.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// The state this crate's handlers are mounted under; a crate has one.
#[proc_macro_derive(State)]
pub fn derive_state(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    app::derive_state(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// A wire type: serde both ways, `ToSchema`, `Debug`, `PartialEq` and `Clone`, in both halves.
///
/// `#[dto(query)]` adds `IntoParams`; `#[dto(skip(Debug))]` drops a default. The client half
/// keeps serde and `Clone` whatever `skip` says, and strips derives it has no use for.
///
/// ```
/// doxa::prelude!();
///
/// #[dto]
/// pub struct Rename { pub name: String }
///
/// #[dto(query)]
/// pub struct Filter { pub contains: Option<String> }
///
/// let back: Rename = serde_json::from_str(&serde_json::to_string(&Rename { name: "a".into() }).unwrap()).unwrap();
/// assert_eq!(back, Rename { name: "a".into() });
/// ```
///
/// A `skip` it doesn't know is an error:
///
/// ```compile_fail
/// doxa::prelude!();
///
/// #[dto(skip(Hash))]
/// pub struct Rename { pub name: String }
/// ```
///
/// ```
/// doxa::prelude!();
///
/// #[dto(skip(Debug))]
/// pub struct Rename { pub name: String }
/// ```
///
/// `#[nullable]` on an `Option<Option<T>>` tells absent (`None`) from `null` (`Some(None)`);
/// `#[omit_none]` on an `Option<T>` leaves `None` out rather than sending `null`:
///
/// ```
/// doxa::prelude!();
///
/// #[dto]
/// pub struct Patch {
///     #[nullable] pub note: Option<Option<String>>,
///     #[omit_none] pub name: Option<String>,
/// }
///
/// let p: Patch = serde_json::from_str(r#"{"note":null}"#).unwrap();
/// assert_eq!(p, Patch { note: Some(None), name: None });
/// assert_eq!(serde_json::to_string(&Patch { note: None, name: None }).unwrap(), "{}");
/// ```
///
/// Each needs its shape:
///
/// ```compile_fail
/// doxa::prelude!();
///
/// #[dto]
/// pub struct Patch { #[nullable] pub note: Option<String> }
/// ```
///
/// ```
/// doxa::prelude!();
///
/// #[dto]
/// pub struct Patch { #[nullable] pub note: Option<Option<String>> }
/// ```
///
/// ```compile_fail
/// doxa::prelude!();
///
/// #[dto]
/// pub struct Patch { #[omit_none] pub name: String }
/// ```
///
/// ```
/// doxa::prelude!();
///
/// #[dto]
/// pub struct Patch { #[omit_none] pub name: Option<String> }
/// ```
#[proc_macro_attribute]
pub fn dto(args: TokenStream, item: TokenStream) -> TokenStream {
    let (args, item): (TS2, TS2) = (args.into(), item.into());
    by_role(
        || dto::expand(args.clone(), item.clone(), false),
        || dto::expand(args.clone(), item.clone(), true),
    )
}

/// The function that builds this server's OpenAPI document, which a generated client crate's
/// `build.rs` reads as `__doxa_spec()`. It must need no state or I/O.
///
/// ```ignore
/// #[doxa::spec]
/// pub fn api_doc() -> doxa::OpenApi {
///     let (_, api) = routes().split_for_parts();
///     ApiDocBuilder::new().title("Orders").merge(api).build()
/// }
/// ```
#[proc_macro_attribute]
pub fn spec(args: TokenStream, item: TokenStream) -> TokenStream {
    let expand = || -> syn::Result<proc_macro2::TokenStream> {
        if !args.is_empty() {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                "`#[spec]` takes no arguments",
            ));
        }
        let item: syn::ItemFn = syn::parse(item)?;
        if !item.sig.inputs.is_empty() {
            return Err(syn::Error::new_spanned(
                &item.sig.inputs,
                "a client's build script calls this with nothing, so it takes no arguments",
            ));
        }
        let name = &item.sig.ident;
        Ok(quote::quote! {
            #item

            /// This server's OpenAPI document, for a generated client crate's `build.rs`.
            #[doc(hidden)]
            pub fn __doxa_spec() -> ::doxa::OpenApi {
                ::doxa::__private::IntoSpec::into_spec(#name())
            }
        })
    };
    expand()
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// A type a route's `Grant<…>` guards, named by `key`: `#[entity(key = OrderKey)]`.
///
/// Its entity type is its name unless `name = "…"` says otherwise; a server asset guarding it
/// says `entity = …`, and both must agree on the name and the key's fields.
#[proc_macro_attribute]
pub fn entity(args: TokenStream, item: TokenStream) -> TokenStream {
    entity::expand(args.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// `From` both ways between this type and its wire copy: `#[mirror(api::OnError)]`.
///
/// Every field converts through `Into`; a field or variant only one side has doesn't compile.
#[proc_macro_attribute]
pub fn mirror(args: TokenStream, item: TokenStream) -> TokenStream {
    mirror::expand(args.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Keep this item only in the server half, e.g. `#[server] use sea_orm::DatabaseConnection;`.
#[proc_macro_attribute]
pub fn server(args: TokenStream, item: TokenStream) -> TokenStream {
    role::only(doxa_macro_support::Side::Server, args.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Keep this item only in the client half.
#[proc_macro_attribute]
pub fn client(args: TokenStream, item: TokenStream) -> TokenStream {
    role::only(doxa_macro_support::Side::Client, args.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Expand the routes inside as the client half whatever this crate's role, for doctests.
#[doc(hidden)]
#[proc_macro]
pub fn __as_client(input: TokenStream) -> TokenStream {
    method::expand_as_client(input.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// The files of the dist in `DOXA_DIST` at compile time, or none when it is unset, so an
/// `embed` build without `doxa build` still compiles. `option_env!` makes cargo track it.
#[doc(hidden)]
#[proc_macro]
pub fn __embedded_dist(_: TokenStream) -> TokenStream {
    let files = match std::env::var("DOXA_DIST") {
        Ok(dir) => {
            let file = format!("{}/embed.rs", dir.trim_end_matches('/'));
            quote::quote! { ::core::include!(#file) }
        }
        Err(_) => quote::quote! { &[] },
    };
    quote::quote! {{
        const _: ::core::option::Option<&str> = ::core::option_env!("DOXA_DIST");
        #files
    }}
    .into()
}

/// Keep these items only in the server half; unlike `#[server]`, works on `mod x;`.
///
/// ```ignore
/// doxa::server_only! {
///     mod store;
/// }
/// ```
#[proc_macro]
pub fn server_only(input: TokenStream) -> TokenStream {
    doxa_macro_support::tag(doxa_macro_support::Side::Server, input.into()).into()
}

/// Make these items `pub` in the client half, which is the crate's public API, and leave
/// them as written on the server.
///
/// ```ignore
/// doxa::client_pub! {
///     mod api;
/// }
/// ```
#[proc_macro]
pub fn client_pub(input: TokenStream) -> TokenStream {
    role::client_pub(input.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Keep these items only in the client half.
#[proc_macro]
pub fn client_only(input: TokenStream) -> TokenStream {
    doxa_macro_support::tag(doxa_macro_support::Side::Client, input.into()).into()
}

/// The id the client cache stores a value under.
///
/// `#[identity(entity = "Widget", id = id, key = WidgetKey { name })]`. `id` must
/// never change; `key` also writes `From<&Widget> for WidgetKey`. In the client half
/// it writes `From<Cached<Widget>> for Widget`, so the type must be `Clone`.
#[proc_macro_derive(Identity, attributes(identity))]
pub fn derive_identity(input: TokenStream) -> TokenStream {
    role::derive_identity(input.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// A validating extractor wrapper: in the server half, `Json`, `Form` and `Query` inside it are
/// extracted, checked by its [`Validates`](../doxa/wire/trait.Validates.html) impl, and refused
/// with a `422` per failing field.
///
/// ```ignore
/// #[derive(doxa::Validator)]
/// pub struct Valid<E>(pub E);
///
/// impl<T: validator::Validate> doxa::wire::Validates for Valid<Json<T>> {
///     type Value = T;
///     fn check(v: &T) -> Result<(), FieldErrors> { v.validate().map_err(FieldErrors::from) }
/// }
/// ```
#[proc_macro_derive(Validator)]
pub fn derive_validator(input: TokenStream) -> TokenStream {
    validator::expand(input.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// `ToSchema` in the client half, where there is no OpenAPI document to describe.
#[doc(hidden)]
#[proc_macro_derive(ClientToSchema, attributes(schema))]
pub fn derive_client_to_schema(_input: TokenStream) -> TokenStream {
    TokenStream::new()
}

/// `IntoParams` in the client half.
#[doc(hidden)]
#[proc_macro_derive(ClientIntoParams, attributes(param, into_params))]
pub fn derive_client_into_params(_input: TokenStream) -> TokenStream {
    TokenStream::new()
}
