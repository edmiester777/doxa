//! Integration tests for `#[derive(ApiError)]`.
//!
//! These tests live outside the proc-macro crate so they can actually
//! invoke the derive and exercise the generated `IntoResponse` /
//! `IntoResponses` impls.

// `GroupedError` variants are not constructed by name in tests — only
// `IntoResponses::responses()` is called on the type — so dead-code
// analysis flags every variant. The warning is misleading: the variants
// are the SUT.
#![allow(dead_code)]

use axum::http::StatusCode;
use axum::response::IntoResponse;
use doxa::ApiErrorBody;
use doxa_macros::ApiError;
use http_body_util::BodyExt;
use utoipa::IntoResponses;

/// Error type with one variant per status code, exercising unit and
/// single-field shapes. Pairs `thiserror::Error` with `ApiError` —
/// thiserror provides the `Display` impl that ApiError reads to
/// populate the response `message` field, and `serde::Serialize`
/// provides the typed `error` field of the response body.
#[derive(thiserror::Error, Debug, serde::Serialize, utoipa::ToSchema, ApiError)]
enum SimpleError {
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

/// Error type where multiple variants share status codes — the
/// canonical "grouped-by-status" shape.
#[derive(thiserror::Error, Debug, serde::Serialize, utoipa::ToSchema, ApiError)]
enum GroupedError {
    #[error("validation failed: {0}")]
    #[api(status = 400, code = "validation_error")]
    Validation(String),

    #[error("query failed: {0}")]
    #[api(status = 400, code = "query_error")]
    Query(String),

    #[error("type cast failed: {0}")]
    #[api(status = 400, code = "type_cast_error")]
    TypeCast(String),

    #[error("model not found: {0}")]
    #[api(status = 404, code = "model_not_found")]
    ModelNotFound(String),

    #[error("source not found: {0}")]
    #[api(status = 404, code = "source_not_found")]
    SourceNotFound(String),

    #[error("internal")]
    #[api(status = 500, code = "internal")]
    Internal,
}

#[tokio::test]
async fn into_response_uses_declared_status_for_unit_variant() {
    let response = SimpleError::NotFound.into_response();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: ApiErrorBody = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed.status, 404);
    assert_eq!(parsed.code, "not_found");
    assert_eq!(parsed.message, "not found");
    // Unit variant serializes as a string under externally-tagged serde.
    assert_eq!(parsed.error, serde_json::json!("NotFound"));
}

#[tokio::test]
async fn into_response_folds_inner_field_into_message() {
    let response = SimpleError::Validation("name is required".to_string()).into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: ApiErrorBody = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed.status, 400);
    assert_eq!(parsed.code, "validation_error");
    assert_eq!(parsed.message, "validation failed: name is required");
    // Newtype variant with externally-tagged serde.
    assert_eq!(
        parsed.error,
        serde_json::json!({"Validation": "name is required"})
    );
}

#[tokio::test]
async fn into_response_handles_internal_500() {
    let response = SimpleError::Internal.into_response();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: ApiErrorBody = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed.status, 500);
    assert_eq!(parsed.code, "internal");
}

#[test]
fn into_responses_produces_one_entry_per_status() {
    let map = SimpleError::responses();
    assert_eq!(map.len(), 3);
    assert!(map.contains_key("400"));
    assert!(map.contains_key("404"));
    assert!(map.contains_key("500"));
}

#[test]
fn into_responses_groups_variants_sharing_a_status_code() {
    let map = GroupedError::responses();
    // Three distinct statuses despite six variants.
    assert_eq!(map.len(), 3);
    assert!(map.contains_key("400"));
    assert!(map.contains_key("404"));
    assert!(map.contains_key("500"));
}

#[test]
fn grouped_responses_describe_each_code_in_the_description() {
    let map = GroupedError::responses();
    let entry = map.get("400").unwrap();
    // The description for a grouped status lists each variant's code.
    let json = serde_json::to_value(entry).unwrap();
    let description = json["description"].as_str().unwrap();
    assert!(description.contains("validation_error"));
    assert!(description.contains("query_error"));
    assert!(description.contains("type_cast_error"));
}

#[test]
fn grouped_responses_emit_one_example_per_variant() {
    let map = GroupedError::responses();
    let entry = map.get("400").unwrap();
    let json = serde_json::to_value(entry).unwrap();
    let examples = &json["content"]["application/json"]["examples"];
    // All three 400-status variants must appear as named examples.
    assert!(examples.get("validation_error").is_some());
    assert!(examples.get("query_error").is_some());
    assert!(examples.get("type_cast_error").is_some());
}

#[test]
fn ungrouped_status_uses_single_code_as_description() {
    let map = SimpleError::responses();
    let entry = map.get("404").unwrap();
    let json = serde_json::to_value(entry).unwrap();
    assert_eq!(json["description"], "not_found");
}

#[test]
fn response_schema_has_typed_envelope_with_code_enum() {
    let map = SimpleError::responses();
    let entry = map.get("400").unwrap();
    let json = serde_json::to_value(entry).unwrap();
    let schema = &json["content"]["application/json"]["schema"];

    // Envelope has message, status, code, error as required properties.
    let required = schema["required"].as_array().unwrap();
    let required_strs: Vec<_> = required.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(required_strs.contains(&"message"));
    assert!(required_strs.contains(&"status"));
    assert!(required_strs.contains(&"code"));
    assert!(required_strs.contains(&"error"));

    // Code is constrained to the single code at this status.
    let code_enum = &schema["properties"]["code"]["enum"];
    assert_eq!(code_enum, &serde_json::json!(["validation_error"]));

    // Status is constrained to the literal value.
    let status_enum = &schema["properties"]["status"]["enum"];
    assert_eq!(status_enum, &serde_json::json!([400]));
}

#[test]
fn grouped_response_schema_has_multiple_code_enum_values() {
    let map = GroupedError::responses();
    let entry = map.get("400").unwrap();
    let json = serde_json::to_value(entry).unwrap();
    let schema = &json["content"]["application/json"]["schema"];

    let code_enum = schema["properties"]["code"]["enum"].as_array().unwrap();
    assert_eq!(code_enum.len(), 3);
    assert!(code_enum.contains(&serde_json::json!("validation_error")));
    assert!(code_enum.contains(&serde_json::json!("query_error")));
    assert!(code_enum.contains(&serde_json::json!("type_cast_error")));
}

#[test]
fn response_error_field_is_one_of_with_variant_schemas() {
    let map = GroupedError::responses();
    let entry = map.get("400").unwrap();
    let json = serde_json::to_value(entry).unwrap();
    let error_schema = &json["content"]["application/json"]["schema"]["properties"]["error"];

    // The error field should be a oneOf with three items (one per 400-variant).
    let one_of = error_schema["oneOf"].as_array().unwrap();
    assert_eq!(one_of.len(), 3);
}
