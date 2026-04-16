//! Autoref-specialized dispatch used by the method macro to
//! unconditionally emit a parameter-contribution entry for every
//! handler argument. Types that do not implement the relevant role
//! trait silently no-op; types that do delegate to the trait impl.
//!
//! Not part of the public API — the paths inside this module may
//! change between minor versions. The method macro references items
//! here behind the crate's `__private` re-export.
//!
//! ## How the dispatch works
//!
//! We rely on Rust's method resolution rules: when a call like
//! `x.__collect()` has candidate methods at multiple autoref /
//! autoderef depths, the compiler picks the one requiring the fewest
//! adjustments to the receiver.
//!
//! For each role we define two traits with the same method name:
//! - A "implemented" trait whose impl requires `T: DocX` and targets receiver
//!   `Contribution<T>` directly (depth 0).
//! - A "missing" trait whose impl is unbounded and targets receiver
//!   `&Contribution<T>` (depth 1 via autoref).
//!
//! The call site constructs `Contribution::<T>::new()` and invokes
//! `__collect()`. If `T: DocX` holds, the depth-0 candidate wins;
//! otherwise the depth-1 fallback is chosen. In either case the
//! source text is identical, so the macro can emit the same call for
//! every argument and let the compiler route it.
//!
//! This is the same pattern used by `anyhow` to dispatch between
//! `std::error::Error` and bare `Display + Debug` inputs to `anyhow!`.

use std::marker::PhantomData;

use utoipa::openapi::path::{OperationBuilder, Parameter};
use utoipa::openapi::schema::Schema;
use utoipa::openapi::RefOr;

use crate::doc_responses::DocResponseBody;
use crate::doc_traits::{
    DocHeaderParams, DocOperationSecurity, DocPathParams, DocPathScalar, DocQueryParams,
};
use crate::inner_schema::InnerToSchema;

// ---------------------------------------------------------------------------
// Query parameter contribution
// ---------------------------------------------------------------------------

/// Zero-sized probe referenced from a per-handler
/// [`utoipa::IntoParams`] impl emitted by the method macro. The probe
/// contributes parameters only when `T: DocQueryParams`.
pub struct QueryParamContribution<T: ?Sized>(PhantomData<T>);

impl<T: ?Sized> QueryParamContribution<T> {
    /// Construct a zero-sized probe for `T`.
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T: ?Sized> Default for QueryParamContribution<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Autoref-specialization: depth-0 candidate when `T: DocQueryParams`.
pub trait QueryParamsImplementedAdhoc: Sized {
    /// Collect query parameters via the specialized impl.
    fn __collect(self) -> Vec<Parameter>;
}

impl<T: DocQueryParams + ?Sized> QueryParamsImplementedAdhoc for QueryParamContribution<T> {
    fn __collect(self) -> Vec<Parameter> {
        let mut op = OperationBuilder::new().build();
        T::describe(&mut op);
        op.parameters.unwrap_or_default()
    }
}

/// Autoref-specialization: depth-1 fallback that applies to every
/// `T`. Chosen only when the depth-0 impl above is unavailable.
pub trait QueryParamsMissingAdhoc: Sized {
    /// No-op fallback — returns an empty parameter list.
    fn __collect(self) -> Vec<Parameter>;
}

impl<T: ?Sized> QueryParamsMissingAdhoc for &QueryParamContribution<T> {
    fn __collect(self) -> Vec<Parameter> {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// Path parameter contribution (struct form only — scalar/tuple Path
// stays in the method macro's syntactic emission)
// ---------------------------------------------------------------------------

/// Path-parameter counterpart to [`QueryParamContribution`]. Used for
/// struct-form `Path<T>` only — scalar/tuple path extractors are
/// handled via the method macro's syntactic emission so their
/// URL-template parameter names are preserved.
pub struct PathParamContribution<T: ?Sized>(PhantomData<T>);

impl<T: ?Sized> PathParamContribution<T> {
    /// Construct a zero-sized probe for `T`.
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T: ?Sized> Default for PathParamContribution<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Depth-0 specialization.
pub trait PathParamsImplementedAdhoc: Sized {
    /// Collect path parameters via the specialized impl.
    fn __collect(self, path_param_names: &[&'static str]) -> Vec<Parameter>;
}

impl<T: DocPathParams + ?Sized> PathParamsImplementedAdhoc for PathParamContribution<T> {
    fn __collect(self, path_param_names: &[&'static str]) -> Vec<Parameter> {
        let mut op = OperationBuilder::new().build();
        T::describe(&mut op, path_param_names);
        op.parameters.unwrap_or_default()
    }
}

/// Depth-1 fallback.
pub trait PathParamsMissingAdhoc: Sized {
    /// No-op fallback — returns an empty parameter list.
    fn __collect(self, path_param_names: &[&'static str]) -> Vec<Parameter>;
}

impl<T: ?Sized> PathParamsMissingAdhoc for &PathParamContribution<T> {
    fn __collect(self, _path_param_names: &[&'static str]) -> Vec<Parameter> {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// Scalar / tuple path parameter contribution (parallel probe to the
// struct-form one above, routed through [`DocPathScalar`])
// ---------------------------------------------------------------------------

/// Scalar/tuple counterpart to [`PathParamContribution`]. The method
/// macro invokes both probes for every handler argument; at most one
/// impl applies for any given `T`.
pub struct PathScalarContribution<T: ?Sized>(PhantomData<T>);

impl<T: ?Sized> PathScalarContribution<T> {
    /// Construct a zero-sized probe for `T`.
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T: ?Sized> Default for PathScalarContribution<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Depth-0 specialization.
pub trait PathScalarImplementedAdhoc: Sized {
    /// Collect scalar / tuple path parameters via the specialized impl.
    fn __collect(self, path_param_names: &[&'static str]) -> Vec<Parameter>;
}

impl<T: DocPathScalar + ?Sized> PathScalarImplementedAdhoc for PathScalarContribution<T> {
    fn __collect(self, path_param_names: &[&'static str]) -> Vec<Parameter> {
        let mut op = OperationBuilder::new().build();
        T::describe_scalar(&mut op, path_param_names);
        op.parameters.unwrap_or_default()
    }
}

/// Depth-1 fallback.
pub trait PathScalarMissingAdhoc: Sized {
    /// No-op fallback — returns an empty parameter list.
    fn __collect(self, path_param_names: &[&'static str]) -> Vec<Parameter>;
}

impl<T: ?Sized> PathScalarMissingAdhoc for &PathScalarContribution<T> {
    fn __collect(self, _path_param_names: &[&'static str]) -> Vec<Parameter> {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// Header parameter contribution
// ---------------------------------------------------------------------------

/// Header-parameter counterpart to [`QueryParamContribution`].
pub struct HeaderParamContribution<T: ?Sized>(PhantomData<T>);

impl<T: ?Sized> HeaderParamContribution<T> {
    /// Construct a zero-sized probe for `T`.
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T: ?Sized> Default for HeaderParamContribution<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Depth-0 specialization.
pub trait HeaderParamsImplementedAdhoc: Sized {
    /// Collect header parameters via the specialized impl.
    fn __collect(self) -> Vec<Parameter>;
}

impl<T: DocHeaderParams + ?Sized> HeaderParamsImplementedAdhoc for HeaderParamContribution<T> {
    fn __collect(self) -> Vec<Parameter> {
        let mut op = OperationBuilder::new().build();
        T::describe(&mut op);
        op.parameters.unwrap_or_default()
    }
}

/// Depth-1 fallback.
pub trait HeaderParamsMissingAdhoc: Sized {
    /// No-op fallback — returns an empty parameter list.
    fn __collect(self) -> Vec<Parameter>;
}

impl<T: ?Sized> HeaderParamsMissingAdhoc for &HeaderParamContribution<T> {
    fn __collect(self) -> Vec<Parameter> {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// Schema registration probe
// ---------------------------------------------------------------------------

/// Zero-sized probe referenced from a per-handler
/// [`crate::ApidocHandlerSchemas`] impl emitted by the method macro.
/// Registers schemas for the arg's inner payload only when the type
/// implements [`InnerToSchema`]; silently no-ops otherwise.
///
/// Used for **extractor-wrapped** payloads (`Query<T>`, `Path<T>`,
/// `Json<T>`, and transparent wrappers thereof). For bare
/// `ToSchema` types (handler error types, success body types etc.),
/// use [`BareSchemaContribution`] instead — the two probes target
/// different trait receivers and together cover both shapes without
/// coherence conflicts.
pub struct InnerSchemaContribution<T: ?Sized>(PhantomData<T>);

impl<T: ?Sized> InnerSchemaContribution<T> {
    /// Construct a zero-sized probe for `T`.
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T: ?Sized> Default for InnerSchemaContribution<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Depth-0 specialization.
pub trait InnerSchemaImplementedAdhoc: Sized {
    /// Append referenced schemas to `out` via the specialized impl.
    fn __collect(self, out: &mut Vec<(String, RefOr<Schema>)>);
}

impl<T: InnerToSchema + ?Sized> InnerSchemaImplementedAdhoc for InnerSchemaContribution<T> {
    fn __collect(self, out: &mut Vec<(String, RefOr<Schema>)>) {
        T::inner_schemas(out);
    }
}

/// Depth-1 fallback.
pub trait InnerSchemaMissingAdhoc: Sized {
    /// No-op fallback — registers nothing.
    fn __collect(self, _out: &mut Vec<(String, RefOr<Schema>)>);
}

impl<T: ?Sized> InnerSchemaMissingAdhoc for &InnerSchemaContribution<T> {
    fn __collect(self, _out: &mut Vec<(String, RefOr<Schema>)>) {}
}

// ---------------------------------------------------------------------------
// Bare ToSchema probe (for error types, success body types, etc.)
// ---------------------------------------------------------------------------

/// Probes `T: ToSchema` directly. Used by the per-handler
/// [`crate::ApidocHandlerSchemas`] impl to register the handler's
/// error type — utoipa's own `IntoResponses`-based schema collection
/// does not walk these.
pub struct BareSchemaContribution<T: ?Sized>(PhantomData<T>);

impl<T: ?Sized> BareSchemaContribution<T> {
    /// Construct a zero-sized probe for `T`.
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T: ?Sized> Default for BareSchemaContribution<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Depth-0 specialization.
pub trait BareSchemaImplementedAdhoc: Sized {
    /// Append `T::schemas(out)` via the specialized impl.
    fn __collect(self, out: &mut Vec<(String, RefOr<Schema>)>);
}

impl<T: utoipa::ToSchema + ?Sized> BareSchemaImplementedAdhoc for BareSchemaContribution<T> {
    fn __collect(self, out: &mut Vec<(String, RefOr<Schema>)>) {
        <T as utoipa::ToSchema>::schemas(out);
    }
}

/// Depth-1 fallback.
pub trait BareSchemaMissingAdhoc: Sized {
    /// No-op fallback — registers nothing.
    fn __collect(self, _out: &mut Vec<(String, RefOr<Schema>)>);
}

impl<T: ?Sized> BareSchemaMissingAdhoc for &BareSchemaContribution<T> {
    fn __collect(self, _out: &mut Vec<(String, RefOr<Schema>)>) {}
}

// ---------------------------------------------------------------------------
// Per-operation security/permission contribution
// ---------------------------------------------------------------------------

/// Probe routed through [`DocOperationSecurity`]. Used by the
/// per-handler [`crate::ApidocHandlerOps`] impl to mutate operations
/// with security requirements declared by extractor types.
pub struct OpSecurityContribution<T: ?Sized>(PhantomData<T>);

impl<T: ?Sized> OpSecurityContribution<T> {
    /// Construct a zero-sized probe for `T`.
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T: ?Sized> Default for OpSecurityContribution<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Depth-0 specialization.
pub trait OpSecurityImplementedAdhoc: Sized {
    /// Apply the specialized impl, mutating `op` in place.
    fn __describe(self, op: &mut utoipa::openapi::path::Operation);
}

impl<T: DocOperationSecurity + ?Sized> OpSecurityImplementedAdhoc for OpSecurityContribution<T> {
    fn __describe(self, op: &mut utoipa::openapi::path::Operation) {
        T::describe(op);
    }
}

/// Depth-1 fallback.
pub trait OpSecurityMissingAdhoc: Sized {
    /// No-op fallback — does not mutate `op`.
    fn __describe(self, op: &mut utoipa::openapi::path::Operation);
}

impl<T: ?Sized> OpSecurityMissingAdhoc for &OpSecurityContribution<T> {
    fn __describe(self, _op: &mut utoipa::openapi::path::Operation) {}
}

// ---------------------------------------------------------------------------
// Response body contribution
// ---------------------------------------------------------------------------

/// Probe routed through [`DocResponseBody`]. The per-handler
/// [`crate::ApidocHandlerOps`] and [`crate::ApidocHandlerSchemas`]
/// impls invoke this probe once with the handler's return type; the
/// depth-0 impl applies when the return type implements
/// [`DocResponseBody`] (covering [`axum::Json`], [`crate::SseStream`],
/// [`Result<Ok, Err>`] where `Ok: DocResponseBody`, and any
/// user-defined wrappers), and the depth-1 fallback no-ops otherwise.
pub struct ResponseBodyContribution<T: ?Sized>(PhantomData<T>);

impl<T: ?Sized> ResponseBodyContribution<T> {
    /// Construct a zero-sized probe for `T`.
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T: ?Sized> Default for ResponseBodyContribution<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Depth-0 specialization.
pub trait ResponseBodyImplementedAdhoc: Sized {
    /// Apply [`DocResponseBody::describe`] via the specialized impl.
    fn __describe(
        self,
        op: &mut utoipa::openapi::path::Operation,
        schemas: &mut Vec<(String, RefOr<Schema>)>,
    );
}

impl<T: DocResponseBody + ?Sized> ResponseBodyImplementedAdhoc for ResponseBodyContribution<T> {
    fn __describe(
        self,
        op: &mut utoipa::openapi::path::Operation,
        schemas: &mut Vec<(String, RefOr<Schema>)>,
    ) {
        T::describe(op, schemas);
    }
}

/// Depth-1 fallback.
pub trait ResponseBodyMissingAdhoc: Sized {
    /// No-op fallback — does not mutate `op` or append schemas.
    fn __describe(
        self,
        op: &mut utoipa::openapi::path::Operation,
        schemas: &mut Vec<(String, RefOr<Schema>)>,
    );
}

impl<T: ?Sized> ResponseBodyMissingAdhoc for &ResponseBodyContribution<T> {
    fn __describe(
        self,
        _op: &mut utoipa::openapi::path::Operation,
        _schemas: &mut Vec<(String, RefOr<Schema>)>,
    ) {
    }
}
