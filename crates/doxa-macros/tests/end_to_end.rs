//! End-to-end test: handlers decorated with the method shortcut and an
//! `ApiError`-derived error type are mounted on an `OpenApiRouter`,
//! finalized through `ApiDocBuilder` + `mount_docs`, and the served
//! `/openapi.json` contains everything we registered.
//!
//! This is the test that proves the whole pipeline (macros → utoipa →
//! axum → mount) works as one piece.

#![allow(dead_code)]

use axum::body::Body;
use axum::extract::Path;
use axum::http::{Request, StatusCode};
use axum::{Json, Router};
use doxa::{routes, ApiDocBuilder, ApiResult, MountDocsExt, MountOpts, OpenApiRouter, ToSchema};
use doxa_macros::{get, post, ApiError};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use tower::ServiceExt;
use utoipa::IntoResponses;

#[derive(Debug, Serialize, ToSchema)]
struct Widget {
    id: u32,
    name: String,
}

#[derive(Debug, Deserialize, ToSchema)]
struct CreateWidget {
    name: String,
}

#[derive(thiserror::Error, Debug, serde::Serialize, utoipa::ToSchema, ApiError)]
enum WidgetError {
    #[error("validation failed: {0}")]
    #[api(status = 400, code = "validation_error")]
    Validation(String),
    #[error("not found")]
    #[api(status = 404, code = "not_found")]
    NotFound,
    #[error("internal")]
    #[api(status = 500, code = "internal")]
    Internal,
}

// The MVP method shortcut is a thin wrapper over `#[utoipa::path]` —
// `request_body` and `responses` must be supplied explicitly until
// signature inference lands in a follow-up commit. This exercises the
// "extra arguments forward to utoipa::path" code path AND lets utoipa
// register the referenced schemas in `components.schemas`.

/// List every widget visible to the caller.
#[get("/widgets", responses((status = 200, body = [Widget])))]
async fn list_widgets() -> Json<Vec<Widget>> {
    Json(vec![Widget {
        id: 1,
        name: "first".into(),
    }])
}

/// Fetch a widget by id.
#[get(
    "/widgets/{id}",
    params(("id" = u32, Path, description = "widget id")),
    responses((status = 200, body = Widget))
)]
async fn get_widget(Path(id): Path<u32>) -> ApiResult<Json<Widget>, WidgetError> {
    if id == 0 {
        Err(WidgetError::NotFound)
    } else {
        Ok(Json(Widget {
            id,
            name: format!("widget-{id}"),
        }))
    }
}

/// Create a new widget.
#[post(
    "/widgets",
    request_body = CreateWidget,
    responses((status = 201, body = Widget))
)]
async fn create_widget(
    Json(req): Json<CreateWidget>,
) -> ApiResult<(StatusCode, Json<Widget>), WidgetError> {
    if req.name.is_empty() {
        Err(WidgetError::Validation("name is required".into()))
    } else {
        Ok((
            StatusCode::CREATED,
            Json(Widget {
                id: 42,
                name: req.name,
            }),
        ))
    }
}

fn build_app() -> Router {
    let (router, openapi) = OpenApiRouter::<()>::new()
        .routes(routes!(list_widgets, create_widget))
        .routes(routes!(get_widget))
        .split_for_parts();

    let api_doc = ApiDocBuilder::new()
        .title("Widgets API")
        .version("1.0.0")
        .description("End-to-end test service")
        .merge(openapi)
        .build();

    router.mount_docs(api_doc, MountOpts::default())
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn served_openapi_json_contains_all_registered_paths() {
    let app = build_app();
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
    let json = body_json(response).await;

    // Title and version flow through from ApiDocBuilder.
    assert_eq!(json["info"]["title"], "Widgets API");
    assert_eq!(json["info"]["version"], "1.0.0");

    // All three handlers' paths show up under the right HTTP methods.
    assert!(json["paths"]["/widgets"]["get"].is_object());
    assert!(json["paths"]["/widgets"]["post"].is_object());
    assert!(json["paths"]["/widgets/{id}"]["get"].is_object());

    // Operation IDs default to the function names.
    assert_eq!(
        json["paths"]["/widgets"]["get"]["operationId"],
        "list_widgets"
    );
    assert_eq!(
        json["paths"]["/widgets"]["post"]["operationId"],
        "create_widget"
    );
    assert_eq!(
        json["paths"]["/widgets/{id}"]["get"]["operationId"],
        "get_widget"
    );

    // Component schemas registered via ToSchema appear in the document.
    assert!(json["components"]["schemas"]["Widget"].is_object());
    assert!(json["components"]["schemas"]["CreateWidget"].is_object());
}

#[tokio::test]
async fn handlers_remain_callable_after_macro_expansion() {
    // The macro must not break the actual axum handler — exercise the
    // success path through the real router.
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
    let json = body_json(response).await;
    assert_eq!(json["id"], 7);
    assert_eq!(json["name"], "widget-7");
}

#[tokio::test]
async fn api_error_into_response_flows_through_handler() {
    // Exercise the error path: handler returns Err(WidgetError::NotFound),
    // axum converts it via IntoResponse, the client sees ApiErrorBody.
    let app = build_app();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/widgets/0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let json = body_json(response).await;
    assert_eq!(json["status"], 404);
    assert_eq!(json["code"], "not_found");
    assert_eq!(json["message"], "not found");
    assert_eq!(json["error"], "NotFound");
}

#[tokio::test]
async fn validation_error_carries_typed_payload_in_error_field() {
    let app = build_app();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/widgets")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"name":""}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let json = body_json(response).await;
    assert_eq!(json["status"], 400);
    assert_eq!(json["code"], "validation_error");
    assert_eq!(json["message"], "validation failed: name is required");
    // The typed `error` field carries the structured serde
    // serialization of the variant — clients can match on it.
    assert_eq!(json["error"]["Validation"], "name is required");
}

#[tokio::test]
async fn docs_route_is_mounted_when_scalar_feature_enabled() {
    let app = build_app();
    let response = app
        .oneshot(Request::builder().uri("/docs").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let ct = response.headers().get("content-type").unwrap();
    assert!(ct.to_str().unwrap().starts_with("text/html"));
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&bytes).unwrap();
    // Scalar HTML should reference our spec URL and our title.
    assert!(html.contains(r#"data-url="/openapi.json""#));
    assert!(html.contains("<title>Widgets API</title>"));
}

#[test]
fn widget_error_responses_use_typed_inline_envelope() {
    // Verify the macro-generated IntoResponses produces an inline
    // typed envelope schema (not a generic $ref to ApiErrorBody).
    let map = WidgetError::responses();
    let entry = serde_json::to_value(map.get("404").unwrap()).unwrap();
    let schema = &entry["content"]["application/json"]["schema"];

    // The schema is an inline object, not a $ref.
    assert!(schema.get("$ref").is_none());
    assert_eq!(schema["type"], "object");

    // Code is constrained to the single code at 404.
    let code_enum = &schema["properties"]["code"]["enum"];
    assert_eq!(code_enum, &serde_json::json!(["not_found"]));
}
