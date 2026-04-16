//! [`InnerToSchema`] — transparent schema-registration trait for
//! extractor wrappers.
//!
//! utoipa's own path macro collects schemas only from `request_body`
//! and `responses`; schemas referenced transitively by `params(...)`
//! entries are **not** auto-registered into `components.schemas`.
//! That produces dangling `$ref`s whenever an `IntoParams`-derived
//! struct has fields of non-primitive types (enums, nested structs,
//! etc.).
//!
//! This trait closes the gap. Each extractor implements it to report
//! the schemas its inner payload references, and the method macro's
//! generated per-handler `IntoParams` struct carries a matching
//! [`ApidocHandlerSchemas`](crate::ApidocHandlerSchemas) impl that
//! walks every argument. The extended [`routes!`](crate::routes)
//! macro calls both, so the schemas land in the final spec
//! alongside what utoipa collects natively.
//!
//! ## Extension
//!
//! Transparent wrappers add one blanket impl, just like the role
//! traits in [`crate::doc_traits`]:
//!
//! ```ignore
//! impl<E: InnerToSchema> InnerToSchema for MyGuard<E> {
//!     fn inner_schemas(out: &mut Vec<(String, RefOr<Schema>)>) {
//!         E::inner_schemas(out)
//!     }
//! }
//! ```
//!
//! Non-transparent extractors either implement it against their
//! payload (`Query<T: ToSchema>` → `T::schemas(out)`) or leave it
//! unimplemented. The macro layer uses autoref specialization so
//! missing impls no-op rather than failing to compile.

use utoipa::openapi::schema::Schema;
use utoipa::openapi::RefOr;
use utoipa::ToSchema;

/// Contributes schemas referenced by an extractor's inner payload
/// into the OpenAPI document's component registry.
///
/// See the module-level docs for the motivation.
pub trait InnerToSchema {
    /// Append referenced schemas to `out`. Implementations typically
    /// forward to `T::schemas(out)` for a `ToSchema`-implementing
    /// inner type.
    fn inner_schemas(out: &mut Vec<(String, RefOr<Schema>)>);
}

impl<T: ToSchema> InnerToSchema for axum::extract::Query<T> {
    fn inner_schemas(out: &mut Vec<(String, RefOr<Schema>)>) {
        T::schemas(out);
    }
}

impl<T: ToSchema> InnerToSchema for axum::extract::Path<T> {
    fn inner_schemas(out: &mut Vec<(String, RefOr<Schema>)>) {
        T::schemas(out);
    }
}

impl<T: ToSchema> InnerToSchema for axum::Json<T> {
    fn inner_schemas(out: &mut Vec<(String, RefOr<Schema>)>) {
        T::schemas(out);
    }
}

// `Header<H>` has a fixed string schema — nothing to register.

// ---------------------------------------------------------------------------
// Handler-side trait: the per-handler dispatch struct implements this
// trait, iterating every arg type through the autoref probe.
// ---------------------------------------------------------------------------

/// Reports the full set of schemas a handler's arguments reference.
/// The method macro emits an impl for the dispatch struct; the
/// extended [`routes!`](crate::routes) macro calls it to extend the
/// OpenAPI router's schema collection before the router is merged.
pub trait ApidocHandlerSchemas {
    /// Append all schemas transitively referenced by the handler's
    /// arguments to `out`.
    fn collect(out: &mut Vec<(String, RefOr<Schema>)>);
}
