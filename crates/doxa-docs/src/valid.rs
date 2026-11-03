//! What a validating extractor answers when the value fails its rules.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use doxa_wire::{FieldErrors, INVALID};

use crate::ApiErrorBody;

/// Why a validating extractor refused the request: the inner extractor's own rejection, or
/// invalid fields.
#[derive(Debug)]
pub enum ValidRejection<R> {
    /// The inner extractor refused.
    Inner(R),
    /// `422`, with each failing field.
    Invalid(FieldErrors),
}

impl<R: IntoResponse> IntoResponse for ValidRejection<R> {
    fn into_response(self) -> Response {
        match self {
            ValidRejection::Inner(r) => r.into_response(),
            ValidRejection::Invalid(fields) => {
                let body = ApiErrorBody::new(422, INVALID, fields.to_string(), fields);
                (StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response()
            }
        }
    }
}
