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

use crate::sse::SseEventMeta;

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
            register_named_schema::<T>(schemas);
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
    E: utoipa::PartialSchema + utoipa::ToSchema + SseEventMeta + 'static,
{
    fn describe(op: &mut Operation, schemas: &mut Vec<(String, RefOr<Schema>)>) {
        insert_sse_200::<E>(op);
        register_named_schema::<E>(schemas);
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
    T: utoipa::PartialSchema + utoipa::ToSchema,
{
    if op.responses.responses.contains_key("200") {
        // Caller supplied an explicit override via `responses(...)` —
        // don't overwrite.
        return;
    }
    let name = schema_component_name::<T>();
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
    E: utoipa::PartialSchema + utoipa::ToSchema + SseEventMeta,
{
    if op.responses.responses.contains_key("200") {
        return;
    }
    // SSE responses use a `$ref` directly to the event enum by name —
    // the 3.2 post-process in `ApiDocBuilder::build` relies on that
    // shape to rewrite `schema` → `itemSchema`. Nominal tagged enums
    // always have a non-empty `ToSchema::name`.
    let name = schema_component_name::<E>();
    let schema = if name.is_empty() {
        <E as utoipa::PartialSchema>::schema()
    } else {
        RefOr::Ref(utoipa::openapi::Ref::new(format!(
            "#/components/schemas/{name}"
        )))
    };

    // The `itemSchema` only describes the JSON `data:` payload. Surface the
    // discrete `event:` frame names — which `SseEventMeta` already knows —
    // as an `x-sse-event-names` extension so a spec reader (and SDK codegen)
    // can see the full event vocabulary, not just the payload union. This
    // survives the spec-version post-process; only `x-sse-stream` is stripped.
    let event_names = E::all_event_names();
    let mut content = Content::new(Some(schema));
    content.extensions = Some(
        utoipa::openapi::extensions::ExtensionsBuilder::new()
            .add(
                "x-sse-event-names",
                serde_json::Value::Array(
                    event_names
                        .iter()
                        .map(|n| serde_json::Value::String((*n).to_owned()))
                        .collect(),
                ),
            )
            .build(),
    );

    let response = ResponseBuilder::new()
        .description(sse_response_description(event_names))
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

/// Human-readable description for an SSE 200 response that enumerates the
/// `event:` frame names. Rendered by docs UIs (Scalar, Swagger UI) so the
/// stream is self-explanatory without cross-referencing the event enum.
fn sse_response_description(event_names: &[&str]) -> String {
    if event_names.is_empty() {
        return "Server-Sent Event stream (`text/event-stream`).".to_owned();
    }
    let names = event_names
        .iter()
        .map(|n| format!("`{n}`"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "Server-Sent Event stream (`text/event-stream`). Each frame's `event:` field \
         is one of: {names}. The `data:` payload is the JSON for that event, described \
         by the schema below."
    )
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
///
/// Generic instantiations (detected via [`has_collision_prone_name`])
/// are still nominal, but they're registered under a composed name
/// — `Paginated_Inner` — to avoid the bare-ident collision that
/// would otherwise clobber sibling instantiations in
/// `components.schemas`. See [`composed_schema_name`] for the
/// naming rule, which mirrors utoipa's own per-field composition at
/// `utoipa-gen/src/component.rs` (the `format!("{}_{}", base,
/// children)` branch).
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

/// Detects generic instantiations whose [`utoipa::ToSchema::name`]
/// is the bare Rust ident (no per-instantiation suffix) — e.g.
/// `Paginated<A>` and `Paginated<B>` both report `"Paginated"`.
///
/// Returns `true` when [`std::any::type_name`] reveals Rust-level
/// generic arguments (`<…>`) that the schema name does not encode
/// (no `<` and no `_`-separated suffix). Callers compose a richer
/// name via [`composed_schema_name`] when this is true; types with
/// `#[schema(as = Path<Inner>)]` — which already encode the
/// instantiation — return `false` and register under their declared
/// name unchanged.
pub(crate) fn has_collision_prone_name<T: utoipa::ToSchema>() -> bool {
    let rust_name = std::any::type_name::<T>();
    if !rust_name.contains('<') {
        return false;
    }
    let schema_name = <T as utoipa::ToSchema>::name();
    !schema_name.contains('<') && !schema_name.contains('_')
}

/// Compose a per-instantiation schema name by joining `T`'s
/// [`utoipa::ToSchema::name`] with the inner generic argument names
/// parsed from [`std::any::type_name`], using the same
/// `{outer}_{inner}` convention utoipa uses for field-composed names
/// at `utoipa-gen/src/component.rs` (the `format!("{}_{}", base,
/// children)` path).
///
/// Example: `Paginated<datalake::SourceSummary>` →
/// `"Paginated_SourceSummary"`. Multi-argument generics join every
/// argument in declaration order:
/// `Map<Key, datalake::SourceSummary>` → `"Map_Key_SourceSummary"`.
///
/// Only used when [`has_collision_prone_name`] returns `true`. The
/// inner names are parsed from the type-name string rather than via
/// a trait lookup because Rust has no way to iterate type arguments
/// of an arbitrary generic type at runtime — but
/// [`std::any::type_name`] is guaranteed to contain the arguments
/// inside the outer `<…>`, which is enough for OpenAPI naming.
pub(crate) fn composed_schema_name<T: utoipa::ToSchema>() -> String {
    let rust_name = std::any::type_name::<T>();
    let outer = <T as utoipa::ToSchema>::name();
    let mut composed = String::from(outer.as_ref());
    for segment in split_top_level_generic_args(rust_name) {
        composed.push('_');
        composed.push_str(last_path_segment(segment));
    }
    composed
}

/// Extract the top-level generic arguments from a type-name string
/// produced by [`std::any::type_name`]. Respects angle-bracket
/// nesting so `Map<Key, Vec<Foo>>` yields `["Key", "Vec<Foo>"]`, not
/// three splits on the comma.
///
/// Returns an empty iterator if the type has no generic arguments
/// (no outer `<…>` in the type name).
fn split_top_level_generic_args(type_name: &str) -> Vec<&str> {
    let Some(open) = type_name.find('<') else {
        return Vec::new();
    };
    let Some(close) = type_name.rfind('>') else {
        return Vec::new();
    };
    if close <= open {
        return Vec::new();
    }
    let body = &type_name[open + 1..close];
    let mut out = Vec::new();
    let mut depth: i32 = 0;
    let mut start = 0;
    for (i, ch) in body.char_indices() {
        match ch {
            '<' => depth += 1,
            '>' => depth -= 1,
            ',' if depth == 0 => {
                out.push(body[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    let tail = body[start..].trim();
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

/// Return the last `::`-separated segment of a Rust path (the
/// trailing ident), plus any generic arguments attached to it. Used
/// to drop module prefixes when composing OpenAPI component names —
/// `datalake_server::api::Foo` becomes `Foo`.
fn last_path_segment(path: &str) -> &str {
    // Strip leading reference / whitespace noise that type_name
    // might include.
    let path = path.trim().trim_start_matches('&').trim();
    // Only look at the path prefix up to the first `<`, since the
    // segment inside generic args doesn't belong to the outer ident.
    let prefix_end = path.find('<').unwrap_or(path.len());
    let prefix = &path[..prefix_end];
    let last_sep = prefix.rfind("::").map(|i| i + 2).unwrap_or(0);
    &path[last_sep..]
}

/// Register a nominal type `T` under its [`utoipa::ToSchema::name`] in
/// the component-schemas collection, plus every schema transitively
/// referenced by it.
///
/// `ToSchema::schemas` walks transitive dependencies but does not
/// always include the root type itself (particularly for
/// `#[serde(tag, content)]` enums and for concrete instantiations of
/// generic types whose inner parameters never appear as a direct
/// return type elsewhere — see the
/// [`crate::__private::GenericArgSchemaContribution`] probe). We
/// insert the root under its name so `$ref`s resolve. Callers should
/// only invoke this for types that [`looks_nominal`] considers
/// nominal — passing a container like `Vec<T>` would register a bogus
/// `Vec` component.
///
/// Exposed at crate scope so the per-handler `ApidocHandlerSchemas`
/// probes generated by the method macros can compensate for utoipa's
/// generic-parameter gap: when a handler returns
/// `Json<Paginated<SourceSummary>>`, utoipa registers
/// `Paginated_SourceSummary` but leaves `SourceSummary` dangling
/// because the derive filters type-parameter fields into the
/// `generic_references` bucket that emits only the recursive
/// `<T as ToSchema>::schemas(out)` call and never pushes `T`'s own
/// `(name, schema)` pair. The method macro walks the return type's
/// nested generic arguments and routes each one through
/// `register_named_schema` via the autoref probe, closing the gap.
pub(crate) fn register_named_schema<T>(out: &mut Vec<(String, RefOr<utoipa::openapi::Schema>)>)
where
    T: utoipa::PartialSchema + utoipa::ToSchema,
{
    let name = schema_component_name::<T>();
    if !name.is_empty() && !out.iter().any(|(n, _)| *n == name) {
        out.push((name, <T as utoipa::PartialSchema>::schema()));
    }
    <T as utoipa::ToSchema>::schemas(out);
}

/// Resolve the OpenAPI component name used for a schema of type
/// `T` — either the plain [`utoipa::ToSchema::name`] or, for
/// collision-prone generic instantiations, the composed
/// `{outer}_{inner}` name produced by [`composed_schema_name`].
///
/// Callers that need to emit `$ref` pointers into
/// `components.schemas` should use this function so the `$ref`
/// target matches the key [`register_named_schema`] would push
/// under.
pub(crate) fn schema_component_name<T: utoipa::PartialSchema + utoipa::ToSchema>() -> String {
    if has_collision_prone_name::<T>() {
        composed_schema_name::<T>()
    } else {
        <T as utoipa::ToSchema>::name().into_owned()
    }
}
