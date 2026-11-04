//! The stop every route macro places after a handler's guards.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::__private::ResponseAuditOutcome;

/// Answers a dry run once the guards before it have passed, so the handler never runs.
pub struct AnswerDryRun;

impl<S: Send + Sync> FromRequestParts<S> for AnswerDryRun {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Response> {
        if !parts.headers.contains_key(doxa_wire::DRY_RUN_HEADER) {
            return Ok(Self);
        }
        let mut response = (
            StatusCode::NO_CONTENT,
            [
                (doxa_wire::DRY_RUN_HEADER, doxa_wire::DRY_RUN_OK),
                ("cache-control", "no-store"),
                ("vary", doxa_wire::DRY_RUN_HEADER),
            ],
        )
            .into_response();
        response
            .extensions_mut()
            .insert(ResponseAuditOutcome::Probe);
        Err(response)
    }
}
