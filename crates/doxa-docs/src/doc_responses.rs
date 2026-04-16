//! Role trait through which a handler's return type contributes the
//! success response to an OpenAPI [`Operation`].
//!
//! Parallel to the per-argument role traits in [`crate::doc_traits`] —
//! query/path/header/request-body/security are per-argument, whereas
//! the response body is per-return-type. The method-shortcut macros
//! invoke the trait via autoref-specialized dispatch (see
//! [`crate::__private::ResponseBodyContribution`]) once per handler,
//! so types that do not implement [`DocResponseBody`] silently
//! contribute nothing instead of failing compilation.
//!
//! # Extension for third-party response wrappers
//!
//! Implement [`DocResponseBody`] on the type a handler returns. The
//! impl mutates the operation's 200 response to add the appropriate
//! content-type and schema reference, and optionally registers any
//! referenced schemas on the output vector so they land in
//! `components.schemas`.
//!
//! ```ignore
//! use doxa::DocResponseBody;
//! use utoipa::openapi::path::Operation;
//! use utoipa::openapi::{RefOr, Schema};
//!
//! pub struct Csv<T>(pub T);
//!
//! impl<T: utoipa::PartialSchema + 'static> DocResponseBody for Csv<T> {
//!     fn describe(op: &mut Operation, _: &mut Vec<(String, RefOr<Schema>)>) {
//!         // add a 200 / text/csv / $ref to T here
//!         let _ = op;
//!     }
//! }
//! ```

use utoipa::openapi::path::Operation;
use utoipa::openapi::response::ResponseBuilder;
use utoipa::openapi::{Content, RefOr, Schema};

/// Describe how a handler's return type contributes to its
/// OpenAPI operation's 200 response.
///
/// Invoked once per handler at spec-build time via the
/// [`crate::__private::ResponseBodyContribution`] autoref dispatch.
/// Implementors mutate `op.responses.responses` (typically inserting
/// an entry at `"200"`) and append any schema components the response
/// references to `schemas` so they can be registered on
/// `components.schemas` by the surrounding
/// [`crate::ApidocHandlerSchemas`] machinery.
///
/// The blanket impl on [`Result<Ok, Err>`] means handlers returning
/// `Result<Foo, MyError>` transparently defer to `Foo`'s impl; the
/// error half is handled separately by utoipa's
/// [`utoipa::IntoResponses`] from the macro's existing `responses(E)`
/// emission.
pub trait DocResponseBody {
    /// Add the success response entry to `op` and append any referenced
    /// schemas to `schemas`.
    fn describe(op: &mut Operation, schemas: &mut Vec<(String, RefOr<Schema>)>);
}

// ---------------------------------------------------------------------------
// axum::Json<T> — 200 application/json
// ---------------------------------------------------------------------------

impl<T> DocResponseBody for axum::Json<T>
where
    T: utoipa::PartialSchema + utoipa::ToSchema + 'static,
{
    fn describe(op: &mut Operation, schemas: &mut Vec<(String, RefOr<Schema>)>) {
        if looks_nominal::<T>() {
            // Nominal types (objects, enums) get a `$ref` to
            // `components.schemas.<name>` plus the schema registered
            // there — matches utoipa's native `body = T` output for
            // doc compactness.
            register_schema::<T>(schemas);
            insert_ref_json_200::<T>(op);
        } else {
            // Generic containers (Vec<T>, Option<T>, …) lack a nominal
            // component name of their own — render their schema
            // inline. utoipa's derived `PartialSchema::schema()`
            // already embeds `$ref`s to their nominal element types
            // where appropriate, so nested refs still resolve.
            insert_inline_json_200::<T>(op);
            <T as utoipa::ToSchema>::schemas(schemas);
        }
    }
}

// ---------------------------------------------------------------------------
// SseStream<E, S> — 200 text/event-stream with x-sse-stream marker
// ---------------------------------------------------------------------------

impl<E, S> DocResponseBody for crate::SseStream<E, S>
where
    E: utoipa::PartialSchema + utoipa::ToSchema + 'static,
{
    fn describe(op: &mut Operation, schemas: &mut Vec<(String, RefOr<Schema>)>) {
        insert_sse_200::<E>(op);
        register_schema::<E>(schemas);
    }
}

// ---------------------------------------------------------------------------
// Result<Ok, Err> — passthrough on the success side
// ---------------------------------------------------------------------------

impl<Ok, Err> DocResponseBody for Result<Ok, Err>
where
    Ok: DocResponseBody,
{
    fn describe(op: &mut Operation, schemas: &mut Vec<(String, RefOr<Schema>)>) {
        <Ok as DocResponseBody>::describe(op, schemas)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn insert_ref_json_200<T>(op: &mut Operation)
where
    T: utoipa::ToSchema,
{
    if op.responses.responses.contains_key("200") {
        // Caller supplied an explicit override via `responses(...)` —
        // don't overwrite.
        return;
    }
    let name = <T as utoipa::ToSchema>::name();
    let reference = RefOr::Ref(utoipa::openapi::Ref::new(format!(
        "#/components/schemas/{name}"
    )));
    let content = Content::new(Some(reference));
    let response = ResponseBuilder::new()
        .description("")
        .content("application/json", content)
        .build();
    op.responses
        .responses
        .insert("200".to_string(), RefOr::T(response));
}

fn insert_inline_json_200<T>(op: &mut Operation)
where
    T: utoipa::PartialSchema,
{
    if op.responses.responses.contains_key("200") {
        return;
    }
    let content = Content::new(Some(<T as utoipa::PartialSchema>::schema()));
    let response = ResponseBuilder::new()
        .description("")
        .content("application/json", content)
        .build();
    op.responses
        .responses
        .insert("200".to_string(), RefOr::T(response));
}

fn insert_sse_200<E>(op: &mut Operation)
where
    E: utoipa::PartialSchema + utoipa::ToSchema,
{
    if op.responses.responses.contains_key("200") {
        return;
    }
    // SSE responses use a `$ref` directly to the event enum by name —
    // the 3.2 post-process in `ApiDocBuilder::build` relies on that
    // shape to rewrite `schema` → `itemSchema`. Nominal tagged enums
    // always have a non-empty `ToSchema::name`.
    let name = <E as utoipa::ToSchema>::name();
    let schema = if name.is_empty() {
        <E as utoipa::PartialSchema>::schema()
    } else {
        RefOr::Ref(utoipa::openapi::Ref::new(format!(
            "#/components/schemas/{name}"
        )))
    };
    let content = Content::new(Some(schema));
    let response = ResponseBuilder::new()
        .description("")
        .content("text/event-stream", content)
        .build();
    op.responses
        .responses
        .insert("200".to_string(), RefOr::T(response));
    // Tag the text/event-stream content entry so
    // `ApiDocBuilder::build`'s post-process can rewrite it under the
    // selected `SseSpecVersion`. See `crate::sse::mark_sse_response`.
    crate::sse::mark_sse_response(op);
}

/// Runtime heuristic that distinguishes a "nominal" schema type
/// (struct, enum, union — user-derived with `#[derive(ToSchema)]`)
/// from a generic container type (`Vec<T>`, `Option<T>`, arrays, …).
///
/// utoipa's macro layer distinguishes these at compile time via type
/// tree analysis. At runtime we only have the schema value and the
/// name, so we serialize `T`'s schema and inspect its shape:
///
/// - `"type": "array"` → container, **not** nominal.
/// - `"$ref": "…"` → already a reference; treat as nominal.
/// - `"oneOf"` / `"allOf"` / `"anyOf"` → tagged enum / polymorphic → nominal.
/// - Otherwise (including `"type": "object"` and the absence of a `"type"` key)
///   → nominal.
///
/// Nominal types get a `$ref` response and are registered on
/// `components.schemas`; non-nominal types render inline.
fn looks_nominal<T: utoipa::PartialSchema + utoipa::ToSchema>() -> bool {
    if <T as utoipa::ToSchema>::name().is_empty() {
        return false;
    }
    let schema = <T as utoipa::PartialSchema>::schema();
    let Ok(value) = serde_json::to_value(&schema) else {
        return false;
    };
    let Some(obj) = value.as_object() else {
        return false;
    };
    if obj.contains_key("$ref") {
        return true;
    }
    !matches!(obj.get("type"), Some(serde_json::Value::String(s)) if s == "array")
}

/// Register a nominal type `T` under its [`utoipa::ToSchema::name`] in
/// the component-schemas collection, plus every schema transitively
/// referenced by it.
///
/// `ToSchema::schemas` walks transitive dependencies but does not
/// always include the root type itself (particularly for
/// `#[serde(tag, content)]` enums). We insert the root under its
/// name so `$ref`s resolve. Callers should only invoke this for
/// types that [`looks_nominal`] considers nominal — passing a
/// container like `Vec<T>` would register a bogus `Vec` component.
fn register_schema<T: utoipa::PartialSchema + utoipa::ToSchema>(
    out: &mut Vec<(String, RefOr<utoipa::openapi::Schema>)>,
) {
    let name = <T as utoipa::ToSchema>::name();
    if !name.is_empty() && !out.iter().any(|(n, _)| n == name.as_ref()) {
        out.push((name.into_owned(), <T as utoipa::PartialSchema>::schema()));
    }
    <T as utoipa::ToSchema>::schemas(out);
}
