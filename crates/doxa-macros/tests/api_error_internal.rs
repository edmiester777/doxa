//! `#[api(internal)]`: the variant `doxa::Internal` converts into.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use doxa_macros::ApiError;

#[derive(thiserror::Error, Debug, PartialEq, serde::Serialize, utoipa::ToSchema, ApiError)]
enum WithMessage {
    #[error("not found")]
    #[api(status = 404)]
    _NotFound,
    #[error("internal: {0}")]
    #[api(status = 500, internal)]
    Internal(String),
}

#[derive(thiserror::Error, Debug, PartialEq, serde::Serialize, utoipa::ToSchema, ApiError)]
enum Bare {
    #[error("unavailable")]
    #[api(status = 503, code = "unavailable", internal)]
    Unavailable,
}

#[test]
fn an_internal_failure_becomes_the_internal_variant_with_its_message() {
    let e: WithMessage = doxa::Internal("db down".into()).into();
    assert_eq!(e, WithMessage::Internal("db down".into()));
    assert_eq!(
        e.into_response().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[test]
fn a_unit_internal_variant_drops_the_message() {
    let e: Bare = doxa::Internal("db down".into()).into();
    assert_eq!(e, Bare::Unavailable);
    assert_eq!(e.into_response().status(), StatusCode::SERVICE_UNAVAILABLE);
}
