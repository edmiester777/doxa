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

mod actions;
mod api_error;
mod asset;
mod capability;
mod grant;
mod method;
mod policy_resource;
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
///
/// # Sharing failure modes between enums
///
/// `#[api(transparent)]` delegates a variant's status, code and audit
/// outcome to a nested error type instead of declaring literals, so a
/// set of cross-cutting failure modes lives in one enum rather than
/// being copy-pasted into every endpoint's:
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
/// A transparent variant declares no `status` or `code` of its own —
/// there is only one right answer and the nested value has it. Its
/// statuses merge into the outer `IntoResponses` map, unioning the
/// `code` enum and the `error` `oneOf` at any status both declare, so
/// the document keeps every mode the endpoint can actually return.
///
/// Pair it with serde's `#[serde(untagged)]` (which requires the variant
/// to come last) to keep the emitted body flat — `{"error": {"RateLimited": …}}`
/// rather than `{"error": {"Fault": {"RateLimited": …}}}` — so
/// consolidating shared modes stays a non-breaking refactor rather than
/// an SDK-visible one.
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

/// Derive Cedar entity identity so a type can be authorized by instance
/// with `Granted<R>`.
///
/// `entity_type` is reused as the audit `resource_type`, so audit rows
/// join to the decisions that produced them. Fields opt into a role:
/// `#[resource(id)]` (exactly one, unless `id_with` supplies it),
/// `#[resource(attr)]` to expose a field to policies as
/// `resource.<name>` (`attr = "key"` renames), and
/// `#[resource(parent = "Folder")]` for `in` checks.
///
/// Not every identity is a field. `#[resource(id_with = method)]` names a
/// method that computes the Cedar id from several columns, and
/// `#[resource(attrs_with = method)]` merges a map of attributes no field
/// backs — a derived flag, say. Both take a method on the type; the
/// merged attributes win on a key collision, being the deliberate ones.
///
/// The route's OpenAPI parameter type comes from the key
/// (`RouteKey::SEGMENTS`), not from here — a resource is reached by
/// whatever segments the route names, which is not always its own id.
///
/// # Example
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
/// # The loader (`policy-sea-orm`)
///
/// On a SeaORM `Model`, `#[resource(scope)]` emits a `ScopedTable` impl
/// and `#[resource(key)]` adds `ScopedRow` on top of it — the query a route
/// runs before it can decide anything. `key` is the column the route's path
/// segment matches; `scope` is the column every lookup is confined to, so a
/// key belonging to another owner is indistinguishable from one that does
/// not exist.
///
/// `scope` alone is a table no column addresses — a name resolved through
/// logic rather than matched — and it is not the lesser half: listing, a
/// residual read and the primary-key lookup all live on `ScopedTable`, so
/// such a table still takes `list = tenant` and `key = pk`.
///
/// Both are independent of the Cedar id: a row reached by `{model_id}` and
/// the same row reached by `{name}` are one entity with two loaders.
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
/// Both roles require the `policy-sea-orm` feature; using one without it
/// is an error naming the feature rather than a missing impl at the route.
///
/// ## More ways in than one
///
/// `#[resource(key)]` is the *unnamed* lookup, and there is one per struct.
/// A row reached three ways — a uuid, a name, and a `(dataset, version)`
/// pair — runs out of it, and used to give the surplus to `#[asset]`'s
/// `load_with`, which is the one door that gives up the scope guarantee.
///
/// So name them. `#[resource(key(FindByPair))]` on every column that takes
/// part emits a `Lookup` marker of that name; a column may carry several
/// names, and several columns may carry one:
///
/// ```ignore
/// #[resource(entity_type = "Version")]
/// pub struct Model {
///     #[sea_orm(primary_key)]                      pub id: Uuid,
///     #[resource(id, key(FindByDataset, FindByPair))] pub dataset: String,
///     #[resource(key(FindByPair))]                 pub version: i64,
///     #[resource(scope)]                           pub tenant_id: String,
/// }
///
/// // …and the asset names the way in rather than the row:
/// #[asset(with = FindByPair, profile = AppGrants, actions = VersionAction)]
/// pub struct VersionByPair;
/// ```
///
/// A composite lookup also gets a key struct — `FindByPairKey` above, with
/// a field per column and a `RouteKey` impl that parses it out of the
/// route's path segments. It is a struct rather than a tuple because every
/// hand-written call site builds the key by position, and two segments of
/// the same type transpose silently. Route parsing stays positional, in
/// declaration order, because path segments are. A single-column lookup
/// keys on the bare scalar, exactly as `#[resource(key)]` does.
///
/// Named or not, every lookup is built on `ScopedTable::scoped`, so the
/// owning column reaches all of them: a second way in is not a way out.
///
/// ## A condition on every query
///
/// `#[resource(filter = …)]` adds a condition each query carries on top of
/// the scope — the soft-delete tombstone being the case it exists for:
///
/// ```ignore
/// #[resource(entity_type = "Version", filter = Column::DeletedAt.is_null())]
/// ```
///
/// Repeatable, and `AND`ed. The expression is spliced rather than
/// interpreted, so it is whatever SeaORM accepts in a `filter(…)` call and
/// there is no operator vocabulary here to fall behind theirs.
///
/// It lands on the table rather than on a lookup, which is what makes it
/// unforgettable: applied by hand it has to be applied to the key lookup,
/// the id lookup, the listing *and* the residual filter, and missing one is
/// not a compile error but a deleted row coming back on whichever route
/// used it.
#[proc_macro_derive(PolicyResource, attributes(resource))]
pub fn derive_policy_resource(input: TokenStream) -> TokenStream {
    policy_resource::expand(input.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Declare an asset's action vocabulary — every action it permits, and
/// what each one costs — as one enum.
///
/// Emits a capability marker per variant (each registering itself in the
/// catalog, exactly as `#[capability]` does), the `ACTIONS` table that
/// `Granting` requires, and `ALL` / `as_static` so the enum is usable as
/// a value.
///
/// Everything but the audit category is defaulted off the enum's own
/// name, so `#[action(…)]` appears only where a default is wrong:
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
/// The audit category has no default: what counts as one is the
/// application's to say, which is why `doxa_audit::AuditEventType` is a
/// trait rather than an enum. It takes any `&'static str` const
/// expression, so name a variant of that enum rather than spelling the
/// string — a typo is then a resolution error instead of a category
/// nothing reads.
///
/// # Gating on a capability that already exists
///
/// `capability = "…"` *declares* one. An application with a catalog of
/// its own already has the marker, and declaring a second over the same
/// action would catalogue an entry that no route names and that therefore
/// only looks enforced. `capable = <path>` gates on the existing marker
/// instead, and mints nothing:
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
/// When no variant declares a capability, no marker module is emitted.
///
/// # Example
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
///     const ACTIONS: &'static [Action] = WidgetAction::ACTIONS;
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
    capability::expand(args.into(), item.into()).into()
}

/// One route's way into a resource: the `Granting` impl, written from the
/// application's profile and the row's own lookup.
///
/// Six of `Granting`'s seven items are transcription. `Ctx`, `State`,
/// `Source` and `Error` are the application's and identical across its
/// assets; `Key` and `load` are the scoped lookup the row already declares
/// through [`fetch`]. Only the vocabulary is a fact about this asset.
///
/// [`fetch`]: https://docs.rs/doxa-policy/latest/doxa_policy/fetch/index.html
///
/// ```ignore
/// #[doxa::asset(profile = AppGrants, actions = WidgetAction)]
/// pub struct Source { /* … */ }
/// ```
///
/// A second route key over the same row is a unit struct naming it. The
/// row keeps one `PolicyResource` impl, so the two routes cannot come to
/// disagree about the object's Cedar identity — which a newtype per key
/// would allow, and which fails silently, as a policy that simply does not
/// match:
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
/// # No backend is assumed
///
/// The lookups are named through [`fetch`], which no backend owns, so
/// everything above reads the same whether the row is a SeaORM model, a
/// document behind an HTTP control plane or an entry in a map.
/// `#[derive(PolicyResource)]` answers those traits for a SeaORM model
/// from `#[resource(key)]` and `#[resource(scope)]`; anything else answers
/// them itself, which is one associated type and a method per lookup.
///
/// # A second way in
///
/// `with = FindByPair` names a `Lookup` — one of the markers
/// `#[resource(key(FindByPair))]` emits — for the row reached more ways
/// than its unnamed `FetchByKey` and `FetchById` can spell between them. A
/// marker carries its row and its key, so `with` is the whole declaration:
///
/// ```ignore
/// #[asset(with = FindByPair, profile = AppGrants, actions = VersionAction)]
/// pub struct VersionByPair;
/// ```
///
/// Reach for it before `load_with`, and for the reason below: a named
/// lookup is still handed a `&str` scope and nothing else, so it is a
/// second way in rather than a way out.
///
/// # `load_with`, and what taking the caller costs
///
/// `FetchByKey::fetch` is handed a `&str` scope and nothing else, which is
/// the guarantee rather than a thin signature: a lookup that cannot see
/// the caller cannot ignore the caller's tenant. `Lookup::fetch` takes the
/// same, which is why naming one costs nothing here.
///
/// `load_with` is handed the whole `Ctx`, and exists for the lookup that
/// needs more than the scope — one that varies by role, or reads the
/// assembled session. Those are the same fact. Taking the `Ctx` is what
/// makes such a lookup expressible, and it is what makes confinement
/// yours to write: a `load_with` that takes `_ctx` and means it compiles,
/// passes its tests, and serves one tenant's rows to another, with the
/// capability gate and the instance check both passing on the way.
///
/// Nothing else moves. The coarse gate still runs first and still costs no
/// load, the instance check still runs on whatever came back, and the
/// verdict still reaches the audit trail under the row's Cedar identity.
/// The scope is the only thing that becomes the loader's responsibility.
///
/// `source` is what a loader is handed and where it comes from, which move
/// together: `source = Extension<Txn>` means the guard extracts the
/// request's transaction and `load` receives `&Txn`. That is the case a
/// router-state loader cannot serve — a pool does not see rows the request
/// has written and not committed, so a lookup pinned to one answers `None`
/// for an object the caller is holding.
///
/// `key = pk` is a word rather than a type because it selects a different
/// lookup, not just a different key: `FetchById::fetch_by_id`, which keeps
/// the scope filter that a hand-written `Entity::find_by_id(id).one(db)`
/// silently drops. It reads `FetchById` and not `FetchByKey` deliberately
/// — an identifier belongs to the collection — so a row that declares no
/// `#[resource(key)]` still has an id route.
///
/// `list = tenant` names its filter for the same reason. The generated
/// `Scoping` confines the listing to the caller's tenant and applies **no
/// other policy condition** — it is not the policy's residual, which is
/// per-row and which this cannot see. An asset that needs the residual
/// writes `Scoping` itself, and without `list` there is no impl at all, so
/// `Granted<Many<…>>` over an asset that never asked to be listed does not
/// compile.
#[proc_macro_attribute]
pub fn asset(args: TokenStream, item: TokenStream) -> TokenStream {
    asset::expand(args.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
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
