//! Regression test for the generic-wrapper schema gap.
//!
//! utoipa's `#[derive(ToSchema)]` filters type-parameter fields into
//! a `generic_references` bucket and emits only the recursive
//! `<T as ToSchema>::schemas(out)` call for them — never the
//! `(name, schema)` pair. For a concrete instantiation like
//! `Paginated<Summary>` where `Summary` is never returned directly
//! anywhere else, this used to leave a dangling
//! `$ref: #/components/schemas/Summary` in the final spec.
//!
//! The method macro now walks every handler's return type and routes
//! each nested generic argument through a
//! `GenericArgSchemaContribution` probe so the missing roots land on
//! `components.schemas`. This test asserts the fix.

#![allow(dead_code)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::{Json, Router};
use doxa::{routes, ApiDocBuilder, MountDocsExt, MountOpts, OpenApiRouter, ToSchema};
use doxa_macros::get;
use http_body_util::BodyExt;
use serde::Serialize;
use tower::ServiceExt;

#[derive(Serialize, ToSchema)]
struct Paginated<T: ToSchema> {
    items: Vec<T>,
    total: u64,
}

#[derive(Serialize, ToSchema)]
struct Summary {
    id: u64,
    name: String,
}

#[derive(Serialize, ToSchema)]
struct Widget {
    id: u64,
    label: String,
}

/// Returns a generic wrapper whose element type (`Summary`) is never
/// returned directly anywhere else — exactly the shape that used to
/// leave an unresolved `$ref`.
#[get("/items")]
async fn list_items() -> Json<Paginated<Summary>> {
    Json(Paginated {
        items: vec![],
        total: 0,
    })
}

/// Second list endpoint, different inner type. Exercises the
/// collision path: both `Paginated<Summary>` and `Paginated<Widget>`
/// report `ToSchema::name() == "Paginated"`, so pushing either under
/// that name would clobber the other. Both instantiations must
/// render inline in their respective responses.
#[get("/widgets")]
async fn list_widgets() -> Json<Paginated<Widget>> {
    Json(Paginated {
        items: vec![],
        total: 0,
    })
}

fn build_app() -> Router {
    let (router, openapi) = OpenApiRouter::<()>::new()
        .routes(routes!(list_items))
        .routes(routes!(list_widgets))
        .split_for_parts();
    let api_doc = ApiDocBuilder::new()
        .title("Generic wrapper test")
        .version("1.0.0")
        .merge(openapi)
        .build();
    router.mount_docs(api_doc, MountOpts::default())
}

async fn fetch_spec(app: Router) -> serde_json::Value {
    let response = app
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn inner_generic_types_are_registered() {
    let spec = fetch_spec(build_app()).await;
    let schemas = spec["components"]["schemas"]
        .as_object()
        .expect("components.schemas present");
    let keys: Vec<&String> = schemas.keys().collect();
    // Both inner types must be registered even though neither is
    // returned directly anywhere — they appear only inside
    // `Paginated<_>` wrappers.
    assert!(
        schemas.contains_key("Summary"),
        "Summary must be registered. Got: {keys:?}"
    );
    assert!(
        schemas.contains_key("Widget"),
        "Widget must be registered. Got: {keys:?}"
    );
}

#[tokio::test]
async fn generic_instantiations_register_under_composed_names() {
    let spec = fetch_spec(build_app()).await;
    let schemas = spec["components"]["schemas"]
        .as_object()
        .expect("components.schemas present");
    let keys: Vec<&String> = schemas.keys().collect();
    // Each instantiation must land under its own composed name —
    // matching utoipa's own `format!("{}_{}", base, children)`
    // convention for field-composed names — rather than clobbering
    // a shared `"Paginated"` entry.
    assert!(
        schemas.contains_key("Paginated_Summary"),
        "Paginated_Summary must be registered. Got: {keys:?}"
    );
    assert!(
        schemas.contains_key("Paginated_Widget"),
        "Paginated_Widget must be registered. Got: {keys:?}"
    );
    // A bare `"Paginated"` component under which both would collide
    // must NOT be present.
    assert!(
        !schemas.contains_key("Paginated"),
        "bare Paginated must not exist — it would collide across \
         instantiations. Got: {keys:?}"
    );
}

#[tokio::test]
async fn list_responses_ref_their_composed_schemas() {
    let spec = fetch_spec(build_app()).await;
    for (path, expected_ref) in [
        ("/items", "#/components/schemas/Paginated_Summary"),
        ("/widgets", "#/components/schemas/Paginated_Widget"),
    ] {
        let schema = &spec["paths"][path]["get"]["responses"]["200"]["content"]["application/json"]
            ["schema"];
        assert_eq!(
            schema["$ref"], expected_ref,
            "{path}: response must $ref its composed schema, got: {schema}"
        );
    }
}

#[tokio::test]
async fn no_dangling_refs_remain() {
    let spec = fetch_spec(build_app()).await;
    // Walk every $ref in the spec and confirm each target resolves.
    let schemas = spec["components"]["schemas"]
        .as_object()
        .expect("components.schemas present");
    let raw = serde_json::to_string(&spec).unwrap();
    let mut missing: Vec<String> = Vec::new();
    const PREFIX: &str = "\"$ref\":\"#/components/schemas/";
    let mut rest = raw.as_str();
    while let Some(idx) = rest.find(PREFIX) {
        let start = idx + PREFIX.len();
        let end_rel = rest[start..].find('"').expect("closing quote");
        let name = &rest[start..start + end_rel];
        if !schemas.contains_key(name) && !missing.contains(&name.to_string()) {
            missing.push(name.to_string());
        }
        rest = &rest[start + end_rel..];
    }
    assert!(
        missing.is_empty(),
        "spec contains dangling $refs: {missing:?}"
    );
}
