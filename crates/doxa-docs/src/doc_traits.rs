//! Role-based traits through which handler-argument types contribute
//! to an OpenAPI [`Operation`]. Mirrors how axum splits request
//! handling across [`FromRequestParts`][frp] / [`FromRequest`][fr]:
//! each extractor plays one or more documentation roles, and each
//! role is one trait.
//!
//! [frp]: https://docs.rs/axum/latest/axum/extract/trait.FromRequestParts.html
//! [fr]: https://docs.rs/axum/latest/axum/extract/trait.FromRequest.html
//!
//! ## Why separate traits per role
//!
//! A single unified trait would force every implementor to opt in or
//! out of every role up-front and would collide under coherence when
//! multiple blanket impls tried to cover overlapping wrapper types.
//! Splitting by role lets a transparent wrapper such as `Valid<T>`
//! forward each role independently without coupling them.
//!
//! ## Extension for third-party extractors
//!
//! A wrapper that is semantically transparent (forwards all behavior
//! to its inner extractor) adds one blanket impl per role it wants to
//! surface. For example:
//!
//! ```ignore
//! impl<T: DocQueryParams> DocQueryParams for MyValidator<T> {
//!     fn describe(op: &mut Operation) { T::describe(op) }
//! }
//! ```
//!
//! The method macro emits unconditional trait calls for every handler
//! argument via autoref-specialized dispatch (see
//! [`crate::__private`]); types that do not implement a given role
//! silently no-op instead of failing compilation.
//!
//! ## Path parameter names
//!
//! The method macro parses `{name}` segments from the route template
//! and passes them to [`DocPathParams::describe`] as the
//! `path_param_names` slice. Struct-form `Path<T: IntoParams>` ignores
//! the slice (names come from the struct). Scalar and tuple `Path<T>`
//! use the slice by index — a scalar `Path<Uuid>` takes names[0]; a
//! tuple `Path<(A, B)>` takes names[0] and names[1] — because the
//! URL-template segment names, not the handler's binding names, are
//! authoritative in OpenAPI.

use utoipa::openapi::path::{Operation, ParameterBuilder, ParameterIn};
use utoipa::openapi::schema::{KnownFormat, SchemaFormat};
use utoipa::openapi::{ObjectBuilder, RefOr, Required, Schema, Type};
use utoipa::{IntoParams, PartialSchema};

use crate::headers::DocumentedHeader;

/// Contributes query parameters to an operation.
///
/// Implemented by [`axum::extract::Query<T>`] for any `T: IntoParams`,
/// and by transparent wrappers (e.g. `Valid<Query<T>>`) via blanket
/// impls that forward to the inner type.
pub trait DocQueryParams {
    /// Append this extractor's query parameters to `op.parameters`.
    fn describe(op: &mut Operation);
}

/// Contributes path parameters to an operation.
///
/// Handles three shapes via separate impls:
/// - struct form — `Path<T: IntoParams>` with `#[into_params(parameter_in =
///   Path)]` on `T`; names come from the struct's field identifiers.
/// - scalar form — `Path<T: PathScalar>` for primitives; `names[0]` provides
///   the parameter name from the route template.
/// - tuple form — `Path<(T1, …, Tn)>` where every element is `PathScalar`;
///   `names[i]` provides the i-th parameter name.
pub trait DocPathParams {
    /// Append path parameters to `op.parameters`.
    ///
    /// `path_param_names` is the ordered list of `{name}` segments
    /// parsed from the route template.
    fn describe(op: &mut Operation, path_param_names: &[&'static str]);
}

/// Sealed trait for primitives usable as scalar `Path` parameters.
/// Implementations supply the OpenAPI schema for the parameter —
/// done manually (rather than via `utoipa::PartialSchema`) because
/// common scalar path types like `Uuid` are recognized by utoipa
/// only via token inspection in derives, not through a `PartialSchema`
/// impl.
pub trait PathScalar: sealed::Sealed {
    /// OpenAPI schema to embed for this scalar parameter.
    fn path_scalar_schema() -> RefOr<Schema>;
}

mod sealed {
    pub trait Sealed {}
}

/// Contributes header parameters to an operation.
pub trait DocHeaderParams {
    /// Append header parameters to `op.parameters`.
    fn describe(op: &mut Operation);
}

/// Contributes the request body schema to an operation.
///
/// Only one extractor per handler should implement this — a handler
/// with two request bodies is ill-formed.
pub trait DocRequestBody {
    /// Set `op.request_body` to describe the body this extractor consumes.
    fn describe(op: &mut Operation);
}

/// Extractor-side contribution of per-operation security/permission
/// metadata. Implemented by per-route guards (e.g. a permission
/// extractor that names the action it requires) so the resulting
/// OpenAPI operation documents the requirement.
///
/// Prefer this over [`crate::DocumentedLayer`] when the requirement
/// varies per handler — `DocumentedLayer` stamps the same contribution
/// on every operation a layer covers, which is the right tool for
/// blanket "must be authenticated" declarations but the wrong tool for
/// per-route permissions.
///
/// Implementations typically emit both a standard
/// [`SecurityRequirement`](utoipa::openapi::security::SecurityRequirement)
/// (so OpenAPI codegen sees the required scope) and an
/// `x-required-permissions` extension (so doc UIs surface a
/// human-readable badge). The
/// [`crate::record_required_permission`] helper does the dual write
/// in one call.
pub trait DocOperationSecurity {
    /// Append this extractor's security/permission metadata to `op`.
    fn describe(op: &mut Operation);
}

// ---------------------------------------------------------------------------
// Built-in extractor impls
// ---------------------------------------------------------------------------

impl<T: IntoParams> DocQueryParams for axum::extract::Query<T> {
    fn describe(op: &mut Operation) {
        let params = T::into_params(|| Some(ParameterIn::Query));
        if params.is_empty() {
            return;
        }
        op.parameters.get_or_insert_with(Vec::new).extend(params);
    }
}

/// Struct-form path impl — names come from `T::into_params`.
impl<T: IntoParams> DocPathParams for axum::extract::Path<T> {
    fn describe(op: &mut Operation, _path_param_names: &[&'static str]) {
        let params = T::into_params(|| Some(ParameterIn::Path));
        if params.is_empty() {
            return;
        }
        op.parameters.get_or_insert_with(Vec::new).extend(params);
    }
}

/// Helper: push one scalar path parameter built from schema `T` and a
/// route-template name.
fn push_scalar_path<T: PathScalar>(op: &mut Operation, name: &str) {
    let param = ParameterBuilder::new()
        .name(name)
        .parameter_in(ParameterIn::Path)
        .required(Required::True)
        .schema(Some(T::path_scalar_schema()))
        .build();
    op.parameters.get_or_insert_with(Vec::new).push(param);
}

/// Build an inline schema of a given OpenAPI [`Type`], optionally
/// with a known format hint (e.g. `int32`).
fn scalar_schema(ty: Type, fmt: Option<KnownFormat>) -> RefOr<Schema> {
    let mut b = ObjectBuilder::new().schema_type(ty);
    if let Some(f) = fmt {
        b = b.format(Some(SchemaFormat::KnownFormat(f)));
    }
    RefOr::T(Schema::Object(b.build()))
}

/// Fetch `path_param_names[index]` or fall back to a synthetic name.
/// The fallback keeps the spec syntactically valid when the handler's
/// pattern arity disagrees with the URL template.
fn name_at(names: &[&'static str], index: usize) -> String {
    names
        .get(index)
        .map(|s| (*s).to_string())
        .unwrap_or_else(|| format!("param{index}"))
}

// `PathScalar` impls for primitives and well-known types. Schemas
// mirror what utoipa emits for the same types in a struct-derived
// schema (see utoipa-gen `schema_type::SchemaTypeInner` for the
// reference set).
macro_rules! impl_path_scalar {
    ($($t:ty => ($ty_enum:expr, $fmt:expr)),* $(,)?) => {
        $(
            impl sealed::Sealed for $t {}
            impl PathScalar for $t {
                fn path_scalar_schema() -> RefOr<Schema> {
                    scalar_schema($ty_enum, $fmt)
                }
            }
        )*
    };
}

impl_path_scalar!(
    bool => (Type::Boolean, None),
    i8 => (Type::Integer, Some(KnownFormat::Int32)),
    i16 => (Type::Integer, Some(KnownFormat::Int32)),
    i32 => (Type::Integer, Some(KnownFormat::Int32)),
    i64 => (Type::Integer, Some(KnownFormat::Int64)),
    i128 => (Type::Integer, None),
    isize => (Type::Integer, None),
    u8 => (Type::Integer, Some(KnownFormat::Int32)),
    u16 => (Type::Integer, Some(KnownFormat::Int32)),
    u32 => (Type::Integer, Some(KnownFormat::Int32)),
    u64 => (Type::Integer, Some(KnownFormat::Int64)),
    u128 => (Type::Integer, None),
    usize => (Type::Integer, None),
    f32 => (Type::Number, Some(KnownFormat::Float)),
    f64 => (Type::Number, Some(KnownFormat::Double)),
    String => (Type::String, None),
);

impl sealed::Sealed for uuid::Uuid {}
impl PathScalar for uuid::Uuid {
    fn path_scalar_schema() -> RefOr<Schema> {
        scalar_schema(Type::String, Some(KnownFormat::Uuid))
    }
}

// Note: scalar `Path<T>` must NOT overlap with the struct-form impl
// `Path<T: IntoParams>` above. Rust coherence rejects two blanket
// impls with overlapping bounds, so we emit scalar and tuple impls
// via a separate trait [`DocPathParamsScalarOrTuple`] that
// `DocPathParams for &Path<...>` lifts — the autoref-specialization
// layer in [`crate::__private`] selects between them. The struct
// impl wins when `T: IntoParams`; the scalar/tuple impl wins
// otherwise via the probe's fallback chain.
//
// For now we provide scalar/tuple support via direct impls at a
// *different* receiver ref-depth than the struct impl, using a
// distinct trait below. The method macro's dispatch struct invokes
// both probes; at most one contributes.

/// Scalar/tuple path impl trait. Kept separate from
/// [`DocPathParams`] to avoid overlap with the struct-form impl.
pub trait DocPathScalar {
    /// Append scalar/tuple path parameter(s) to `op.parameters`.
    fn describe_scalar(op: &mut Operation, path_param_names: &[&'static str]);
}

impl<T: PathScalar> DocPathScalar for axum::extract::Path<T> {
    fn describe_scalar(op: &mut Operation, path_param_names: &[&'static str]) {
        let name = name_at(path_param_names, 0);
        push_scalar_path::<T>(op, &name);
    }
}

// Tuple arity impls via declarative macro — mirrors axum's
// `all_the_tuples!` pattern so new arities stay easy to add.
macro_rules! impl_tuple_path {
    ($($idx:tt => $T:ident),+ $(,)?) => {
        impl<$($T: PathScalar),+> DocPathScalar for axum::extract::Path<($($T,)+)> {
            fn describe_scalar(op: &mut Operation, path_param_names: &[&'static str]) {
                $(
                    let name = name_at(path_param_names, $idx);
                    push_scalar_path::<$T>(op, &name);
                )+
            }
        }
    };
}

impl_tuple_path!(0 => T1, 1 => T2);
impl_tuple_path!(0 => T1, 1 => T2, 2 => T3);
impl_tuple_path!(0 => T1, 1 => T2, 2 => T3, 3 => T4);
impl_tuple_path!(0 => T1, 1 => T2, 2 => T3, 3 => T4, 4 => T5);
impl_tuple_path!(0 => T1, 1 => T2, 2 => T3, 3 => T4, 4 => T5, 5 => T6);
impl_tuple_path!(0 => T1, 1 => T2, 2 => T3, 3 => T4, 4 => T5, 5 => T6, 6 => T7);
impl_tuple_path!(0 => T1, 1 => T2, 2 => T3, 3 => T4, 4 => T5, 5 => T6, 6 => T7, 7 => T8);

impl<H: DocumentedHeader> DocHeaderParams for crate::extractor::Header<H> {
    fn describe(op: &mut Operation) {
        use utoipa::openapi::path::{ParameterBuilder, ParameterIn as InLoc};
        use utoipa::openapi::{ObjectBuilder, RefOr, Required, Schema, Type};
        let mut b = ParameterBuilder::new()
            .name(H::name())
            .parameter_in(InLoc::Header)
            .required(Required::True)
            .schema(Some(RefOr::T(Schema::Object(
                ObjectBuilder::new().schema_type(Type::String).build(),
            ))));
        let desc = H::description();
        if !desc.is_empty() {
            b = b.description(Some(desc.to_string()));
        }
        if let Some(ex) = H::example() {
            b = b.example(Some(serde_json::Value::String(ex.to_string())));
        }
        op.parameters.get_or_insert_with(Vec::new).push(b.build());
    }
}

impl<T: utoipa::ToSchema + PartialSchema + 'static> DocRequestBody for axum::Json<T> {
    fn describe(op: &mut Operation) {
        use utoipa::openapi::request_body::RequestBodyBuilder;
        use utoipa::openapi::{ContentBuilder, Required};
        let content = ContentBuilder::new().schema(Some(T::schema())).build();
        let body = RequestBodyBuilder::new()
            .content("application/json", content)
            .required(Some(Required::True))
            .build();
        op.request_body = Some(body);
    }
}
