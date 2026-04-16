//! Integration tests for the `#[get]` / `#[post]` / `#[operation]`
//! method shortcut attributes.
//!
//! These tests verify that the shortcut expands to a working
//! `#[utoipa::path]` attribute by registering a handler with
//! `utoipa_axum::router::OpenApiRouter` and inspecting the resulting
//! OpenAPI document.

use axum::Json;
use doxa::{routes, OpenApiRouter, ToSchema};
use doxa_macros::{delete, get, operation, patch, post, put};
use serde::Serialize;

#[derive(Serialize, ToSchema)]
struct Hello {
    message: String,
}

/// A trivial GET endpoint used to verify path + operation_id wiring.
#[get("/hello")]
async fn hello() -> Json<Hello> {
    Json(Hello {
        message: "hi".to_string(),
    })
}

/// POST endpoint to verify the shortcut works for body-bearing methods.
#[post("/hello")]
async fn hello_post() -> Json<Hello> {
    Json(Hello {
        message: "posted".to_string(),
    })
}

#[put("/hello")]
async fn hello_put() -> Json<Hello> {
    Json(Hello {
        message: "put".to_string(),
    })
}

#[patch("/hello")]
async fn hello_patch() -> Json<Hello> {
    Json(Hello {
        message: "patched".to_string(),
    })
}

#[delete("/hello")]
async fn hello_delete() -> Json<Hello> {
    Json(Hello {
        message: "deleted".to_string(),
    })
}

#[operation(get, "/operation-form")]
async fn operation_form() -> Json<Hello> {
    Json(Hello {
        message: "ok".to_string(),
    })
}

#[test]
fn shortcut_registers_path_in_openapi() {
    let (_, openapi) = OpenApiRouter::<()>::new()
        .routes(routes!(hello))
        .split_for_parts();
    let json = serde_json::to_value(&openapi).unwrap();
    assert!(json["paths"]["/hello"]["get"].is_object());
}

#[test]
fn operation_id_defaults_to_function_name() {
    let (_, openapi) = OpenApiRouter::<()>::new()
        .routes(routes!(hello))
        .split_for_parts();
    let json = serde_json::to_value(&openapi).unwrap();
    assert_eq!(json["paths"]["/hello"]["get"]["operationId"], "hello");
}

#[test]
fn all_method_shortcuts_compile_and_register() {
    let (_, openapi) = OpenApiRouter::<()>::new()
        .routes(routes!(
            hello,
            hello_post,
            hello_put,
            hello_patch,
            hello_delete
        ))
        .split_for_parts();
    let json = serde_json::to_value(&openapi).unwrap();
    let methods = &json["paths"]["/hello"];
    assert!(methods["get"].is_object());
    assert!(methods["post"].is_object());
    assert!(methods["put"].is_object());
    assert!(methods["patch"].is_object());
    assert!(methods["delete"].is_object());
}

#[test]
fn operation_attribute_works_with_explicit_method() {
    let (_, openapi) = OpenApiRouter::<()>::new()
        .routes(routes!(operation_form))
        .split_for_parts();
    let json = serde_json::to_value(&openapi).unwrap();
    assert!(json["paths"]["/operation-form"]["get"].is_object());
    assert_eq!(
        json["paths"]["/operation-form"]["get"]["operationId"],
        "operation_form"
    );
}
