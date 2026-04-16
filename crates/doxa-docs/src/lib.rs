//! # doxa
//!
//! Ergonomic OpenAPI documentation for axum services. Built on top of
//! [`utoipa`] and [`utoipa_axum`], this crate provides:
//!
//! - An [`ApiDocBuilder`] for assembling an OpenAPI document from a
//!   [`utoipa::openapi::OpenApi`] value, finalizing it into an in-memory
//!   [`ApiDoc`] whose serialized JSON is shared via a reference-counted
//!   [`bytes::Bytes`] buffer.
//! - A [`mount_docs`] helper that mounts `GET /openapi.json` plus an
//!   interactive documentation UI on an existing [`axum::Router`], all from
//!   memory — the spec is never written to disk.
//! - An RFC 7807 [`ProblemDetails`] response body usable as the default error
//!   schema across a project.
//!
//! All UI integrations are feature-gated independently. The default
//! feature set enables [`docs-scalar`](crate#features) which mounts
//! the Scalar API reference UI from a CDN-loaded HTML template,
//! rendered out of the box with the three-pane `modern` layout, dark
//! mode on, the schemas index hidden, the codegen sidebar suppressed,
//! and Scalar's paid product upsells (Agent / MCP) disabled. Every
//! one of those choices is overridable via [`ScalarConfig`] passed
//! through [`MountOpts::scalar`]. Scalar is preferred because it is
//! actively maintained, parses OpenAPI 3.2 natively, renders the
//! `x-badges` vendor extension, and surfaces required OAuth2 scopes
//! inline under each operation — covering per-operation permission
//! requirements produced by extractor-side [`DocOperationSecurity`]
//! impls.
//!
//! # Tour
//!
//! The full surface of the crate, end to end. Every macro, derive,
//! extractor, and builder method that ships in the default feature set
//! appears in the snippet below and the whole thing compiles under
//! `cargo test --doc`.
//!
//! ```no_run
//! use axum::Json;
//! use doxa::{
//!     routes, ApiDocBuilder, ApiErrorBody, ApiResult, DocumentedHeader, Header,
//!     MountDocsExt, MountOpts, OpenApiRouter, ScalarConfig, ScalarLayout, ScalarTheme,
//!     SseEvent, SseEventMeta, SseSpecVersion, SseStream, ToSchema,
//! };
//! use doxa::{get, post, ApiError};
//! use futures_core::Stream;
//! use serde::{Deserialize, Serialize};
//! use std::convert::Infallible;
//!
//! // ----- Typed error envelope ----------------------------------------------
//! //
//! // `#[derive(ApiError)]` wires both `IntoResponse` and `IntoResponses`
//! // from per-variant `#[api(status, code)]` attributes. Multiple
//! // variants may share a status — they are grouped into one OpenAPI
//! // response with separate examples.
//! #[derive(Debug, thiserror::Error, Serialize, ToSchema, ApiError)]
//! enum WidgetError {
//!     #[error("validation failed: {0}")]
//!     #[api(status = 400, code = "validation_error")]
//!     Validation(String),
//!
//!     #[error("conflict: {0}")]
//!     #[api(status = 400, code = "conflict")]
//!     Conflict(String),
//!
//!     #[error("not found")]
//!     #[api(status = 404, code = "not_found")]
//!     NotFound,
//!
//!     #[error("internal error")]
//!     #[api(status = 500, code = "internal")]
//!     Internal,
//! }
//!
//! // ----- Typed request / response bodies -----------------------------------
//! #[derive(Debug, Serialize, ToSchema)]
//! struct Widget { id: u32, name: String }
//!
//! #[derive(Debug, Deserialize, ToSchema)]
//! struct CreateWidget { name: String }
//!
//! // ----- Typed header extractor --------------------------------------------
//! //
//! // Implementing `DocumentedHeader` on a marker type lets the same
//! // marker drive both extraction (via `Header<XApiKey>`) and OpenAPI
//! // documentation. The macro recognizes `Header<H>` in the handler
//! // signature and emits the corresponding params block automatically.
//! struct XApiKey;
//! impl DocumentedHeader for XApiKey {
//!     fn name() -> &'static str { "X-Api-Key" }
//!     fn description() -> &'static str { "Tenant API key" }
//! }
//!
//! // ----- SSE event stream --------------------------------------------------
//! //
//! // `#[derive(SseEvent)]` provides the per-variant event name; pair
//! // it with `serde::Serialize` and `ToSchema` so the wire format and
//! // OpenAPI schema stay aligned. `SseStream<E, S>` is the response
//! // wrapper — handlers never construct axum's `Sse` directly.
//! #[derive(Serialize, ToSchema, SseEvent)]
//! #[serde(tag = "event", content = "data", rename_all = "snake_case")]
//! enum BuildEvent {
//!     Started { id: u64 },
//!     Progress { done: u64, total: u64 },
//!     #[sse(name = "finished")]
//!     Completed,
//! }
//!
//! // ----- Handlers ----------------------------------------------------------
//! /// Create a widget. The path uses the `#[post]` shortcut, takes a
//! /// typed JSON body and a typed header, and returns an
//! /// `ApiResult<Json<T>, E>` so successes and the full error
//! /// vocabulary both flow into the OpenAPI document.
//! #[post("/widgets", tag = "Widgets")]
//! async fn create_widget(
//!     Header(_key, ..): Header<XApiKey>,
//!     Json(req): Json<CreateWidget>,
//! ) -> ApiResult<(axum::http::StatusCode, Json<Widget>), WidgetError> {
//!     if req.name.is_empty() {
//!         return Err(WidgetError::Validation("name is required".into()));
//!     }
//!     Ok((
//!         axum::http::StatusCode::CREATED,
//!         Json(Widget { id: 42, name: req.name }),
//!     ))
//! }
//!
//! /// Stream build progress as Server-Sent Events. The macro
//! /// recognizes `SseStream<E, _>` and emits a `text/event-stream`
//! /// response with one `oneOf` branch per `SseEvent` variant.
//! #[get("/builds/{id}/events", tag = "Builds")]
//! async fn stream_build(
//! ) -> SseStream<BuildEvent, impl Stream<Item = Result<BuildEvent, Infallible>>> {
//!     let events = futures::stream::iter(vec![
//!         Ok(BuildEvent::Started { id: 1 }),
//!         Ok(BuildEvent::Progress { done: 1, total: 10 }),
//!         Ok(BuildEvent::Completed),
//!     ]);
//!     SseStream::new(events)
//! }
//!
//! // ----- Compose, finalize, mount -----------------------------------------
//! # async fn run() {
//! let (router, openapi) = OpenApiRouter::<()>::new()
//!     .routes(routes!(create_widget))
//!     .routes(routes!(stream_build))
//!     .split_for_parts();
//!
//! let api_doc = ApiDocBuilder::new()
//!     .title("Widgets API")
//!     .version("1.0.0")
//!     .description("Tour service")
//!     .bearer_security("bearerAuth")
//!     .tag_group("Core", ["Widgets"])
//!     .tag_group("Streaming", ["Builds"])
//!     // Use OpenAPI 3.2 `itemSchema` for SSE responses (the default).
//!     .sse_openapi_version(SseSpecVersion::V3_2)
//!     .merge(openapi)
//!     .build();
//!
//! // Customize the Scalar UI: classic single-column layout with a
//! // light theme, dark mode off. `MountOpts::default()` keeps the
//! // historical three-pane modern dark-mode appearance.
//! let app = router.mount_docs(
//!     api_doc,
//!     MountOpts::default()
//!         .scalar(
//!             ScalarConfig::default()
//!                 .layout(ScalarLayout::Classic)
//!                 .theme(ScalarTheme::Solarized)
//!                 .dark_mode(false),
//!         ),
//! );
//! # // The body envelope `ApiErrorBody` is the shape every error
//! # // response carries; reference it here so the import is exercised.
//! # let _: ApiErrorBody<()> = ApiErrorBody::new(500, "internal", "boom", ());
//! # let _ = app;
//! # }
//! ```
//!
//! The crate's public surface contains **no project-specific types** —
//! everything is generic over `utoipa`'s native types so it can be lifted
//! into any axum project.

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod builder;
mod contribution;
mod doc_params;
mod doc_responses;
mod doc_traits;
mod extractor;
mod handler_ops;
mod headers;
mod inner_schema;
mod mount;
mod private_dispatch;
mod problem;
mod router_ext;
mod routes_macro;
mod sse;
mod ui;

pub use builder::{ApiDoc, ApiDocBuilder, BuildError, SseSpecVersion};
pub use contribution::{
    apply_badge_to_operation, apply_contribution, record_required_permission, BadgeContribution,
    DocumentedLayer, LayerContribution, ResponseContribution, SecurityContribution,
};
pub use doc_params::DocHeaderEntry;
pub use doc_responses::DocResponseBody;
pub use doc_traits::{
    DocHeaderParams, DocOperationSecurity, DocPathParams, DocPathScalar, DocQueryParams,
    DocRequestBody, PathScalar,
};
pub use extractor::Header;
pub use handler_ops::{operation_for_method_mut, ApidocHandlerOps};
pub use headers::{DocumentedHeader, HeaderParam};
pub use inner_schema::{ApidocHandlerSchemas, InnerToSchema};
pub use mount::{mount_docs, MountDocsExt, MountOpts};
pub use problem::{ApiErrorBody, ProblemDetails};
pub use router_ext::OpenApiRouterExt;
pub use sse::{SseEventMeta, SseStream};

#[cfg(feature = "docs-scalar")]
pub use ui::{DeveloperTools, DocumentDownload, ScalarConfig, ScalarLayout, ScalarTheme};

// Re-export the companion proc-macro crate so consumers only need
// `doxa` on their dependency list to write an event-stream
// handler or derive `ApiError`. Gated on the `macros` feature
// (enabled by default) so the proc-macro compile cost can be opted
// out of when the derives aren't needed.
#[cfg(feature = "macros")]
pub use doxa_macros::{capability, delete, get, operation, patch, post, put, ApiError, SseEvent};

// Re-export the underlying utoipa types so consumers depend on a single
// crate. Each re-export is explicit (no glob) so the public surface is
// auditable from one place.
pub use utoipa::openapi::OpenApi;
pub use utoipa::{IntoParams, IntoResponses, ToSchema};
pub use utoipa_axum::router::OpenApiRouter;

// Our `routes!` macro wraps `utoipa_axum::routes!` and extends the
// collected schemas with those referenced by handler-argument types
// via [`ApidocHandlerSchemas`]. See [`routes_macro`] for the
// implementation.

/// Convenience alias for handler return types whose error half implements
/// [`IntoResponses`]. Equivalent to [`Result<T, E>`] but signals intent.
pub type ApiResult<T, E> = Result<T, E>;

/// Re-exports used exclusively by the `doxa-macros` proc-macro
/// crate. Not part of the public API — paths inside this module may
/// change between minor versions. The macros reference items here so
/// consumer crates do not need to depend on `tracing` directly just to
/// use `#[derive(ApiError)]`.
#[doc(hidden)]
pub mod __private {
    pub use tracing;

    /// Audit outcome attached to response extensions by
    /// `#[derive(ApiError)]`'s generated `IntoResponse` impl.
    ///
    /// Lives here so the macro can reference it without depending on
    /// `doxa-audit`. The `AuditLayer` reads this from response
    /// extensions and maps it to `doxa_audit::Outcome`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ResponseAuditOutcome {
        Allowed,
        Denied,
        Error,
    }

    /// Trait for error types that declare their audit outcome per variant.
    ///
    /// `#[derive(ApiError)]` generates this impl automatically. Each
    /// variant's outcome is declared via `#[api(outcome = "denied")]` —
    /// when omitted, the variant defaults to [`ResponseAuditOutcome::Error`].
    pub trait HasAuditOutcome {
        fn audit_outcome(&self) -> ResponseAuditOutcome;
    }

    // Autoref-specialized dispatch scaffolding referenced by the
    // method macro's generated per-handler `IntoParams` impls. Not
    // part of the public API.
    pub use crate::private_dispatch::{
        BareSchemaContribution, BareSchemaImplementedAdhoc, BareSchemaMissingAdhoc,
        HeaderParamContribution, HeaderParamsImplementedAdhoc, HeaderParamsMissingAdhoc,
        InnerSchemaContribution, InnerSchemaImplementedAdhoc, InnerSchemaMissingAdhoc,
        OpSecurityContribution, OpSecurityImplementedAdhoc, OpSecurityMissingAdhoc,
        PathParamContribution, PathParamsImplementedAdhoc, PathParamsMissingAdhoc,
        PathScalarContribution, PathScalarImplementedAdhoc, PathScalarMissingAdhoc,
        QueryParamContribution, QueryParamsImplementedAdhoc, QueryParamsMissingAdhoc,
        ResponseBodyContribution, ResponseBodyImplementedAdhoc, ResponseBodyMissingAdhoc,
    };

    // Re-export paste so our `routes!` macro can concatenate idents
    // (`__path_<fn>`) when the caller invokes it.
    pub use paste;

    // Re-export the upstream macro under a shadowed name so
    // `doxa::routes!` can call into it without requiring the
    // caller crate to declare `utoipa-axum` as a direct dependency.
    pub use utoipa_axum::routes as utoipa_axum_routes;
}
