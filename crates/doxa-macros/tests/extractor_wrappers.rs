//! Regression tests for trait-based extractor contribution.
//!
//! Verifies that handlers whose arguments are wrapped in
//! transparent extractors (the quintessential case is
//! `Valid<Query<T>>`) still get their parameters into the OpenAPI
//! document. Before the trait-based dispatch landed, the method
//! macro only recognized a hard-coded set of outer extractor names
//! (`Json` / `Path` / `Query` / `Header`) and silently dropped any
//! wrapped variant.
//!
//! The tests exercise:
//! - bare scalar `Path<Uuid>`
//! - tuple `Path<(u32, String)>`
//! - struct `Path<MyPathParams>` (`IntoParams`-derived)
//! - bare `Query<T>`
//! - `Valid<Query<T>>` — the direct regression scenario
//! - `Valid<Path<Uuid>>`
//! - a custom wrapper (`CustomGuard<T>`) that implements no doc traits — must
//!   compile and contribute nothing (graceful no-op via autoref)

#![allow(dead_code)]

use std::ops::Deref;

use axum::body::Body;
use axum::extract::{FromRequestParts, Path, Query};
use axum::http::request::Parts;
use axum::http::Request;
use axum::Router;
use doxa::{
    routes, ApiDocBuilder, DocHeaderParams, DocPathParams, DocQueryParams, DocRequestBody,
    MountDocsExt, MountOpts, OpenApiRouter,
};
use doxa_macros::get;
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use tower::ServiceExt;
use utoipa::openapi::path::Operation;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Test-local Valid<T> wrapper representative of a typical consumer's validation
// extractor. Keeping the definition local keeps the test self-contained.
// ---------------------------------------------------------------------------

struct Valid<E>(pub E);

impl<S, E> FromRequestParts<S> for Valid<E>
where
    S: Send + Sync,
    E: FromRequestParts<S>,
    E::Rejection: std::fmt::Display,
{
    type Rejection = (axum::http::StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let inner = E::from_request_parts(parts, state)
            .await
            .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?;
        Ok(Valid(inner))
    }
}

// Transparent forwards — the wrapper propagates documentation from the inner type.
impl<E: DocQueryParams> DocQueryParams for Valid<E> {
    fn describe(op: &mut Operation) {
        E::describe(op)
    }
}
impl<E: DocPathParams> DocPathParams for Valid<E> {
    fn describe(op: &mut Operation, names: &[&'static str]) {
        E::describe(op, names)
    }
}
impl<E: doxa::DocPathScalar> doxa::DocPathScalar for Valid<E> {
    fn describe_scalar(op: &mut Operation, names: &[&'static str]) {
        E::describe_scalar(op, names)
    }
}
impl<E: DocHeaderParams> DocHeaderParams for Valid<E> {
    fn describe(op: &mut Operation) {
        E::describe(op)
    }
}
impl<E: DocRequestBody> DocRequestBody for Valid<E> {
    fn describe(op: &mut Operation) {
        E::describe(op)
    }
}

// ---------------------------------------------------------------------------
// Custom wrapper that implements NO doc traits. Must compile and
// contribute nothing.
// ---------------------------------------------------------------------------

struct CustomGuard<E>(pub E);

impl<S, E> FromRequestParts<S> for CustomGuard<E>
where
    S: Send + Sync,
    E: FromRequestParts<S>,
    E::Rejection: std::fmt::Display,
{
    type Rejection = (axum::http::StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let inner = E::from_request_parts(parts, state)
            .await
            .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?;
        Ok(CustomGuard(inner))
    }
}

impl<E> Deref for CustomGuard<E> {
    type Target = E;
    fn deref(&self) -> &E {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Test types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
struct PageInput {
    /// Number of items to skip.
    offset: u64,
    /// Maximum items to return.
    limit: u64,
}

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Path)]
struct ThingPathParams {
    /// Thing tenant.
    tenant: String,
    /// Thing id.
    id: Uuid,
}

#[derive(Serialize, ToSchema)]
struct Reply {
    ok: bool,
}

// ---------------------------------------------------------------------------
// Handlers — each shape gets its own path so parameters can be
// inspected independently.
// ---------------------------------------------------------------------------

#[get("/scalar/{id}")]
async fn scalar_path(Path(_id): Path<Uuid>) -> &'static str {
    "ok"
}

#[get("/tuple/{a}/{b}")]
async fn tuple_path(Path((_a, _b)): Path<(u32, String)>) -> &'static str {
    "ok"
}

#[get("/struct-path/{tenant}/things/{id}")]
async fn struct_path(Path(_p): Path<ThingPathParams>) -> &'static str {
    "ok"
}

#[get("/query")]
async fn bare_query(Query(_p): Query<PageInput>) -> &'static str {
    "ok"
}

#[get("/valid-query")]
async fn valid_query(Valid(Query(_p)): Valid<Query<PageInput>>) -> &'static str {
    "ok"
}

#[get("/valid-scalar-path/{id}")]
async fn valid_scalar_path(Valid(Path(_id)): Valid<Path<Uuid>>) -> &'static str {
    "ok"
}

#[get("/custom")]
async fn custom_wrapper(CustomGuard(Query(_p)): CustomGuard<Query<PageInput>>) -> &'static str {
    "ok"
}

// ---------------------------------------------------------------------------
// Spec assembly helper
// ---------------------------------------------------------------------------

fn build_app() -> Router {
    let (router, openapi) = OpenApiRouter::<()>::new()
        .routes(routes!(scalar_path))
        .routes(routes!(tuple_path))
        .routes(routes!(struct_path))
        .routes(routes!(bare_query))
        .routes(routes!(valid_query))
        .routes(routes!(valid_scalar_path))
        .routes(routes!(custom_wrapper))
        .split_for_parts();
    let api_doc = ApiDocBuilder::new()
        .title("Extractor wrappers")
        .version("1.0.0")
        .merge(openapi)
        .build();
    router.mount_docs(api_doc, MountOpts::default())
}

async fn fetch_spec() -> serde_json::Value {
    let response = build_app()
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// Return the `parameters` array for a given path + method, or an empty
/// Vec if the operation declares none.
fn params_for<'a>(
    spec: &'a serde_json::Value,
    path: &str,
    method: &str,
) -> Vec<&'a serde_json::Value> {
    spec["paths"][path][method]["parameters"]
        .as_array()
        .map(|arr| arr.iter().collect())
        .unwrap_or_default()
}

fn name_and_in(p: &serde_json::Value) -> (&str, &str) {
    (
        p["name"].as_str().unwrap_or(""),
        p["in"].as_str().unwrap_or(""),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bare_scalar_path_uses_url_template_name() {
    let spec = fetch_spec().await;
    let params = params_for(&spec, "/scalar/{id}", "get");
    assert_eq!(params.len(), 1, "expected exactly one param");
    let (name, loc) = name_and_in(params[0]);
    assert_eq!(name, "id");
    assert_eq!(loc, "path");
}

#[tokio::test]
async fn tuple_path_emits_one_param_per_segment() {
    let spec = fetch_spec().await;
    let params = params_for(&spec, "/tuple/{a}/{b}", "get");
    assert_eq!(params.len(), 2);
    let names: Vec<_> = params.iter().map(|p| p["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"a"));
    assert!(names.contains(&"b"));
    for p in &params {
        assert_eq!(p["in"].as_str(), Some("path"));
    }
}

#[tokio::test]
async fn struct_path_pulls_names_from_into_params() {
    let spec = fetch_spec().await;
    let params = params_for(&spec, "/struct-path/{tenant}/things/{id}", "get");
    // Fields `tenant` and `id` come from ThingPathParams via IntoParams.
    let names: Vec<_> = params
        .iter()
        .map(|p| p["name"].as_str().unwrap().to_string())
        .collect();
    assert!(
        names.iter().any(|n| n == "tenant"),
        "tenant missing: {names:?}"
    );
    assert!(names.iter().any(|n| n == "id"), "id missing: {names:?}");
    for p in &params {
        assert_eq!(p["in"].as_str(), Some("path"));
    }
}

#[tokio::test]
async fn bare_query_emits_offset_and_limit() {
    let spec = fetch_spec().await;
    let params = params_for(&spec, "/query", "get");
    let names: Vec<_> = params
        .iter()
        .map(|p| p["name"].as_str().unwrap().to_string())
        .collect();
    assert!(names.contains(&"offset".to_string()), "got: {names:?}");
    assert!(names.contains(&"limit".to_string()), "got: {names:?}");
}

/// Direct regression test for the reported bug: `Valid<Query<T>>` was
/// silently dropped by the pre-trait-based inference layer.
#[tokio::test]
async fn valid_wrapped_query_emits_query_params() {
    let spec = fetch_spec().await;
    let params = params_for(&spec, "/valid-query", "get");
    assert!(!params.is_empty(), "Valid<Query<T>> produced no params");
    let names: Vec<_> = params
        .iter()
        .map(|p| p["name"].as_str().unwrap().to_string())
        .collect();
    assert!(names.contains(&"offset".to_string()));
    assert!(names.contains(&"limit".to_string()));
    for p in &params {
        assert_eq!(p["in"].as_str(), Some("query"));
    }
}

#[tokio::test]
async fn valid_wrapped_scalar_path_retains_url_name() {
    let spec = fetch_spec().await;
    let params = params_for(&spec, "/valid-scalar-path/{id}", "get");
    // The scalar/tuple path goes through syntactic emission so the
    // URL-template name survives even under a wrapper.
    assert!(
        params.iter().any(|p| name_and_in(p) == ("id", "path")),
        "expected id/path in {params:?}",
    );
}

/// Unknown wrapper that implements no doc traits must compile and
/// contribute no query params — the fallback no-op branch.
#[tokio::test]
async fn custom_wrapper_contributes_nothing() {
    let spec = fetch_spec().await;
    let params = params_for(&spec, "/custom", "get");
    // The scalar/tuple path inference doesn't apply (handler takes a
    // Query, not a Path). Without a DocQueryParams impl on
    // CustomGuard, the trait probe no-ops. So no params.
    let query_params: Vec<_> = params
        .iter()
        .filter(|p| p["in"].as_str() == Some("query"))
        .collect();
    assert!(
        query_params.is_empty(),
        "custom wrapper with no doc-trait impl must not emit query params, got: {query_params:?}",
    );
}

/// Regression guard for the params-schema registration follow-up:
/// every `$ref` that appears under a path's `parameters[*].schema`
/// must resolve against `components.schemas`. Without the extended
/// `routes!` macro that walks `InnerToSchema`, structs like
/// `ThingPathParams` would produce a dangling `$ref` to themselves
/// here (their ToSchema-derived `schemas()` is never called).
#[tokio::test]
async fn params_schema_refs_resolve() {
    const PREFIX: &str = "#/components/schemas/";
    let spec = fetch_spec().await;
    let components = spec["components"]["schemas"]
        .as_object()
        .cloned()
        .unwrap_or_default();

    let mut dangling: Vec<(String, String)> = Vec::new();
    fn walk(
        value: &serde_json::Value,
        path: &str,
        components: &serde_json::Map<String, serde_json::Value>,
        out: &mut Vec<(String, String)>,
    ) {
        match value {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    if k == "$ref" {
                        if let Some(s) = v.as_str() {
                            if let Some(name) = s.strip_prefix(PREFIX) {
                                if !components.contains_key(name) {
                                    out.push((path.to_string(), s.to_string()));
                                }
                            }
                        }
                    }
                    walk(v, &format!("{path}.{k}"), components, out);
                }
            }
            serde_json::Value::Array(arr) => {
                for (i, v) in arr.iter().enumerate() {
                    walk(v, &format!("{path}[{i}]"), components, out);
                }
            }
            _ => {}
        }
    }
    walk(&spec, "", &components, &mut dangling);
    assert!(
        dangling.is_empty(),
        "expected no dangling $refs, got:\n{dangling:#?}"
    );
}

/// Verify doc comments on struct fields flow through to parameter
/// descriptions — both for a bare extractor and for a `Valid<>` wrap.
#[tokio::test]
async fn doc_comments_preserved_through_valid_wrapper() {
    let spec = fetch_spec().await;
    for path in ["/query", "/valid-query"] {
        let params = params_for(&spec, path, "get");
        for p in &params {
            let name = p["name"].as_str().unwrap();
            let desc = p["description"].as_str().unwrap_or("");
            if name == "offset" {
                assert!(
                    desc.contains("skip"),
                    "{path}: offset description lost, got {desc:?}",
                );
            } else if name == "limit" {
                assert!(
                    desc.contains("return"),
                    "{path}: limit description lost, got {desc:?}",
                );
            }
        }
    }
}
