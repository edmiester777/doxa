//! Tests for the function-signature inference layer.
//!
//! These tests verify the macro-generated `#[utoipa::path]` attribute
//! picks up `request_body`, path parameters, success response, and
//! error responses from the handler signature without the caller
//! repeating any of it in the macro arguments.

#![allow(dead_code)]

use axum::body::Body;
use axum::extract::Path;
use axum::http::{Request, StatusCode};
use axum::{Json, Router};
use doxa::{routes, ApiDocBuilder, ApiResult, MountDocsExt, MountOpts, OpenApiRouter, ToSchema};
use doxa_macros::{get, post, ApiError};
extern crate thiserror;
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

#[derive(Serialize, ToSchema)]
struct Widget {
    id: u32,
    name: String,
}

#[derive(Deserialize, ToSchema)]
struct CreateWidget {
    name: String,
}

/// Error type for the widget API. Two variants share status 400 so
/// inference + grouping cooperate end-to-end.
#[derive(thiserror::Error, Debug, serde::Serialize, utoipa::ToSchema, ApiError)]
enum WidgetError {
    #[error("validation failed: {0}")]
    #[api(status = 400, code = "validation_error")]
    Validation(String),
    #[error("name too long: {0}")]
    #[api(status = 400, code = "name_too_long")]
    NameTooLong(String),
    #[error("not found")]
    #[api(status = 404, code = "not_found")]
    NotFound,
    #[error("internal")]
    #[api(status = 500, code = "internal")]
    Internal,
}

// --- handlers — NOTHING in the macro args except the path ---

/// List every widget. Inference: success response from `Json<Vec<Widget>>`.
#[get("/widgets")]
async fn list_widgets() -> Json<Vec<Widget>> {
    Json(vec![])
}

/// Fetch one widget. Inference: path param "id" of type u32, success
/// response from `Json<Widget>`, error responses from `WidgetError`.
#[get("/widgets/{id}")]
async fn get_widget(Path(id): Path<u32>) -> ApiResult<Json<Widget>, WidgetError> {
    Ok(Json(Widget {
        id,
        name: format!("widget-{id}"),
    }))
}

/// Create a widget. Inference: request body from `Json<CreateWidget>`,
/// success response from `Json<Widget>` (200 — callers who need 201
/// declare it explicitly via `responses(...)`), errors from
/// `WidgetError`.
#[post("/widgets")]
async fn create_widget(Json(req): Json<CreateWidget>) -> ApiResult<Json<Widget>, WidgetError> {
    Ok(Json(Widget {
        id: 1,
        name: req.name,
    }))
}

fn build_app() -> Router {
    let (router, openapi) = OpenApiRouter::<()>::new()
        .routes(routes!(list_widgets, create_widget))
        .routes(routes!(get_widget))
        .split_for_parts();
    let api_doc = ApiDocBuilder::new()
        .title("Inferred API")
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
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn list_widgets_response_body_inferred_from_return_type() {
    let spec = fetch_spec(build_app()).await;
    let response_200 = &spec["paths"]["/widgets"]["get"]["responses"]["200"];
    // Container types like `Vec<T>` lack a nominal OpenAPI component
    // name, so the `DocResponseBody` impl emits them inline (matching
    // utoipa's own `PartialSchema::schema()` output). Nominal element
    // types are still registered on `components.schemas` so consumers
    // that want a `$ref`-style response can declare it explicitly via
    // `responses(...)`.
    let schema = &response_200["content"]["application/json"]["schema"];
    assert_eq!(schema["type"], "array");
    let items = &schema["items"];
    assert_eq!(items["type"], "object");
    assert!(items["properties"]["id"].is_object());
    assert!(items["properties"]["name"].is_object());
}

#[tokio::test]
async fn widget_schema_registered_via_inference() {
    let spec = fetch_spec(build_app()).await;
    // The Widget schema must end up in components even though no
    // handler attribute mentioned `Widget` directly.
    assert!(spec["components"]["schemas"]["Widget"].is_object());
}

#[tokio::test]
async fn path_parameter_name_and_type_inferred_from_extractor() {
    let spec = fetch_spec(build_app()).await;
    let params = &spec["paths"]["/widgets/{id}"]["get"]["parameters"];
    let arr = params.as_array().expect("parameters array");
    let id_param = arr
        .iter()
        .find(|p| p["name"] == "id")
        .expect("id parameter present");
    assert_eq!(id_param["in"], "path");
    assert_eq!(id_param["required"], true);
    assert_eq!(id_param["schema"]["type"], "integer");
}

#[tokio::test]
async fn request_body_inferred_from_json_extractor() {
    let spec = fetch_spec(build_app()).await;
    let request_body = &spec["paths"]["/widgets"]["post"]["requestBody"];
    let schema = &request_body["content"]["application/json"]["schema"];
    assert_eq!(schema["$ref"], "#/components/schemas/CreateWidget");
}

#[tokio::test]
async fn create_widget_success_response_inferred_from_json_body() {
    let spec = fetch_spec(build_app()).await;
    // POST handlers returning `Json<T>` infer a 200 response. Callers
    // who need 201 (or any other status) write an explicit
    // `responses(...)` override; the `DocResponseBody` trait
    // dispatch does not second-guess the wire status from a
    // `(StatusCode, Json<T>)` tuple.
    let response_200 = &spec["paths"]["/widgets"]["post"]["responses"]["200"];
    assert!(
        response_200.is_object(),
        "expected 200 response, got: {response_200}"
    );
    let schema = &response_200["content"]["application/json"]["schema"];
    assert_eq!(schema["$ref"], "#/components/schemas/Widget");
}

#[tokio::test]
async fn error_responses_inherited_from_apierror_via_intoresponses() {
    let spec = fetch_spec(build_app()).await;
    let responses = &spec["paths"]["/widgets/{id}"]["get"]["responses"];
    // Three distinct status codes inherited from WidgetError, even
    // though four variants are declared (two share 400).
    assert!(responses["400"].is_object(), "missing 400 response");
    assert!(responses["404"].is_object(), "missing 404 response");
    assert!(responses["500"].is_object(), "missing 500 response");
}

#[tokio::test]
async fn grouped_400_response_lists_both_variants_as_examples() {
    let spec = fetch_spec(build_app()).await;
    let response_400 = &spec["paths"]["/widgets/{id}"]["get"]["responses"]["400"];
    let examples = &response_400["content"]["application/json"]["examples"];
    assert!(
        examples["validation_error"].is_object(),
        "validation_error example missing"
    );
    assert!(
        examples["name_too_long"].is_object(),
        "name_too_long example missing"
    );
}

#[tokio::test]
async fn handlers_remain_callable_after_inference_expansion() {
    let app = build_app();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/widgets/7")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["id"], 7);
}
