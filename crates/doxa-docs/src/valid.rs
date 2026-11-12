//! What a validating extractor answers when the value fails its rules.

use axum::extract::rejection::{FormRejection, JsonRejection, QueryRejection};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use doxa_wire::{FieldErrors, INVALID, MALFORMED};
use serde_json::{json, Value};
use utoipa::openapi::path::Operation;
use utoipa::openapi::{RefOr, Response as DocResponse};

use crate::ApiErrorBody;

/// Add the `400` and `422` a validating extractor answers, beside any the route's own error
/// declares.
pub fn document_rejections(op: &mut Operation) {
    let field = json!({
        "type": "object",
        "required": ["path", "message"],
        "properties": {
            "path": { "type": "string" },
            "message": { "type": "string" },
        },
    });
    // The inner extractor's own status is `malformed` too: axum's `Json` answers 415 and 422.
    let null = || json!({ "type": "null" });
    let responses = [
        ("400", MALFORMED, null()),
        ("415", MALFORMED, null()),
        ("422", MALFORMED, null()),
        ("422", INVALID, json!({ "type": "array", "items": field })),
    ];
    for (status, code, error) in responses {
        let Ok(response) = serde_json::from_value::<DocResponse>(envelope_doc(code, error)) else {
            continue;
        };
        let one = [(status.to_string(), RefOr::T(response))]
            .into_iter()
            .collect();
        crate::error_responses::merge_response_maps(&mut op.responses.responses, one);
    }
}

fn envelope_doc(code: &str, error: Value) -> Value {
    json!({
        "description": code,
        "content": { "application/json": { "schema": {
            "type": "object",
            "required": ["message", "status", "code", "error"],
            "properties": {
                "message": { "type": "string" },
                "status": { "type": "integer", "format": "int32" },
                "code": { "type": "string", "enum": [code] },
                "error": { "oneOf": [error] },
            },
        } } },
    })
}

/// An inner extractor's rejection, as the status and text its envelope carries.
pub trait InnerRejection {
    /// The status the inner extractor answers with.
    fn status(&self) -> StatusCode;
    /// Why it refused, for the envelope's `message`.
    fn body_text(&self) -> String;
}

macro_rules! inner_rejection {
    ($($ty:ty),*) => {$(
        impl InnerRejection for $ty {
            fn status(&self) -> StatusCode {
                <$ty>::status(self)
            }
            fn body_text(&self) -> String {
                <$ty>::body_text(self)
            }
        }
    )*};
}

inner_rejection!(JsonRejection, FormRejection, QueryRejection);

/// Why a validating extractor refused the request: the inner extractor's own rejection, or
/// invalid fields.
#[derive(Debug)]
pub enum ValidRejection<R> {
    /// The inner extractor refused.
    Inner(R),
    /// `422`, with each failing field.
    Invalid(FieldErrors),
}

impl<R: InnerRejection> IntoResponse for ValidRejection<R> {
    fn into_response(self) -> Response {
        match self {
            ValidRejection::Inner(r) => {
                let status = r.status();
                let body = ApiErrorBody::new(status.as_u16(), MALFORMED, r.body_text(), ());
                (status, Json(body)).into_response()
            }
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

    fn codes_at(op: &Operation, status: &str) -> serde_json::Value {
        let doc = serde_json::to_value(op).unwrap();
        doc["responses"][status]["content"]["application/json"]["schema"]["properties"]["code"]
            ["enum"]
            .clone()
    }

    fn codes(op: &Operation) -> serde_json::Value {
        codes_at(op, "422")
    }

    #[test]
    fn a_validating_route_documents_its_field_errors() {
        let mut op = Operation::new();
        document_rejections(&mut op);
        assert_eq!(codes(&op), json!(["malformed", "invalid"]));
        assert_eq!(codes_at(&op, "400"), json!(["malformed"]));
        assert_eq!(codes_at(&op, "415"), json!(["malformed"]));
        let doc = serde_json::to_value(&op).unwrap();
        let error = &doc["responses"]["422"]["content"]["application/json"]["schema"]["properties"]
            ["error"];
        assert!(error["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["type"] == "array"));
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
        document_rejections(&mut op);
        document_rejections(&mut op);
        assert_eq!(codes(&op), json!(["config_error", "malformed", "invalid"]));
        let doc = serde_json::to_value(&op).unwrap();
        let error = &doc["responses"]["422"]["content"]["application/json"]["schema"]["properties"]
            ["error"];
        assert_eq!(error["oneOf"].as_array().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn an_unparseable_query_answers_the_json_envelope_with_its_status() {
        use axum::extract::{FromRequestParts, Query};

        let (mut parts, ()) = axum::http::Request::get("/x?limit=abc")
            .body(())
            .unwrap()
            .into_parts();
        let rejection =
            Query::<std::collections::HashMap<String, u32>>::from_request_parts(&mut parts, &())
                .await
                .expect_err("`abc` is not a u32");
        let resp = ValidRejection::Inner(rejection).into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&body).expect("a JSON envelope");
        assert_eq!(body["code"], MALFORMED);
        assert_eq!(body["status"], 400);
        assert_eq!(body["error"], Value::Null);
        assert!(
            body["message"].as_str().unwrap().contains("limit"),
            "message names the field: {body}"
        );
    }
}
