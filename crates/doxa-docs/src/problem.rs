//! Default error response body for `#[derive(ApiError)]`.
//!
//! [`ApiErrorBody`] is the envelope shape every error response uses.
//! The type parameter `E` carries the typed error payload — when the
//! macro generates `IntoResponse`, it moves the error enum directly
//! into the envelope as `ApiErrorBody<MyError>`, giving the OpenAPI
//! spec a fully typed `error` field.
//!
//! The envelope holds:
//!
//! - **`message`** — human-readable text from the source error's
//!   [`std::fmt::Display`] impl (typically provided by `thiserror::Error`'s
//!   `#[error("...")]` template).
//! - **`error`** — the typed, machine-readable serialization of the error
//!   variant via [`serde::Serialize`]. Shape matches the enum's serde
//!   representation (externally tagged by default).
//! - **`status`** — the HTTP status mirrored into the body for clients that
//!   don't have easy access to the response status line.
//! - **`code`** — application-level error code string for client-side
//!   discrimination (e.g. `"validation_error"`, `"not_found"`).
//!
//! The default type parameter `serde_json::Value` is used by layer
//! contributions and backward-compatible call sites that don't have a
//! concrete error type.
//!
//! [`ProblemDetails`] is still exported for projects that prefer the
//! RFC 7807 envelope, but the macro no longer uses it by default.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub use doxa_wire::ApiErrorBody;

/// RFC 7807 problem details body.
///
/// Retained for projects that prefer the standard RFC 7807 envelope.
/// `#[derive(ApiError)]` no longer emits this by default — see
/// [`ApiErrorBody`] for the new default. Both types coexist; choose
/// whichever fits your client conventions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProblemDetails {
    /// A URI reference identifying the problem type. Defaults to
    /// `"about:blank"` per the RFC.
    #[serde(default = "default_type", rename = "type")]
    pub type_: String,
    /// Short human-readable summary of the problem type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// HTTP status code generated for this occurrence.
    pub status: u16,
    /// Human-readable explanation specific to this occurrence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// URI reference identifying the specific occurrence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// Application-level error code suitable for client discrimination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

fn default_type() -> String {
    "about:blank".to_string()
}

impl ProblemDetails {
    /// Construct with the required `status` field.
    pub fn new(status: u16) -> Self {
        Self {
            type_: default_type(),
            title: None,
            status,
            detail: None,
            instance: None,
            code: None,
        }
    }

    /// Set the title.
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }
    /// Set the detail message.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
    /// Set the application-level error code.
    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }
    /// Set the instance URI.
    pub fn with_instance(mut self, instance: impl Into<String>) -> Self {
        self.instance = Some(instance.into());
        self
    }
    /// Set the problem type URI.
    pub fn with_type(mut self, type_: impl Into<String>) -> Self {
        self.type_ = type_.into();
        self
    }
}

// No tests in this module — `ApiErrorBody` and `ProblemDetails` are
// straight serde-derived structs with no logic of our own. Their
// behavior is verified end-to-end through the macro-generated
// `IntoResponse` impls in `doxa-macros/tests/`. Pure round-trip
// tests on these types would just be testing serde, which the project
// rule `test-ownership.md` excludes.
