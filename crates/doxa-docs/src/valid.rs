//! What a validating extractor answers when the value fails its rules.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use doxa_wire::{FieldErrors, INVALID};
use serde_json::json;
use utoipa::openapi::path::Operation;
use utoipa::openapi::{RefOr, Response as DocResponse};

use crate::ApiErrorBody;

/// Add the `422` a validating extractor answers, beside any the route's own error declares.
pub fn document_invalid(op: &mut Operation) {
    let field = json!({
        "type": "object",
        "required": ["path", "message"],
        "properties": {
            "path": { "type": "string" },
            "message": { "type": "string" },
        },
    });
    let response = json!({
        "description": INVALID,
        "content": { "application/json": { "schema": {
            "type": "object",
            "required": ["message", "status", "code", "error"],
            "properties": {
                "message": { "type": "string" },
                "status": { "type": "integer", "format": "int32" },
                "code": { "type": "string", "enum": [INVALID] },
                "error": { "oneOf": [{ "type": "array", "items": field }] },
            },
        } } },
    });
    let Ok(response) = serde_json::from_value::<DocResponse>(response) else {
        return;
    };
    crate::error_responses::merge_response_maps(
        &mut op.responses.responses,
        [("422".to_string(), RefOr::T(response))].into(),
    );
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(op: &Operation) -> serde_json::Value {
        let doc = serde_json::to_value(op).unwrap();
        doc["responses"]["422"]["content"]["application/json"]["schema"]["properties"]["code"]
            ["enum"]
            .clone()
    }

    #[test]
    fn a_validating_route_documents_its_field_errors() {
        let mut op = Operation::new();
        document_invalid(&mut op);
        assert_eq!(codes(&op), json!(["invalid"]));
        let doc = serde_json::to_value(&op).unwrap();
        let error = &doc["responses"]["422"]["content"]["application/json"]["schema"]["properties"]
            ["error"];
        assert_eq!(error["oneOf"][0]["type"], "array");
    }

    #[test]
    fn a_route_s_own_422_keeps_its_code_beside_invalid() {
        let mut op = Operation::new();
        let own: DocResponse = serde_json::from_value(json!({
            "description": "config_error",
            "content": { "application/json": { "schema": {
                "type": "object",
                "properties": {
                    "code": { "type": "string", "enum": ["config_error"] },
                    "error": { "oneOf": [{ "type": "string" }] },
                },
            } } },
        }))
        .unwrap();
        op.responses
            .responses
            .insert("422".to_string(), RefOr::T(own));
        document_invalid(&mut op);
        document_invalid(&mut op);
        assert_eq!(codes(&op), json!(["config_error", "invalid"]));
        let doc = serde_json::to_value(&op).unwrap();
        let error = &doc["responses"]["422"]["content"]["application/json"]["schema"]["properties"]
            ["error"];
        assert_eq!(error["oneOf"].as_array().unwrap().len(), 2);
    }
}
