//! Auth-specific error types.
//!
//! [`AuthError`] covers the full range of authentication and authorization
//! failures — missing credentials, invalid/expired tokens, policy resolution
//! failures, and unsupported Cedar filter expressions.
//!
//! When the `axum` feature is enabled, `AuthError` derives
//! [`ApiError`](doxa_macros::ApiError) which generates both
//! `IntoResponse` and `IntoResponses` with typed per-status-code schemas.

/// Errors produced by the authentication and authorization pipeline.
#[derive(Debug, thiserror::Error)]
#[cfg_attr(
    feature = "axum",
    derive(serde::Serialize, doxa::ToSchema, doxa_macros::ApiError)
)]
pub enum AuthError {
    #[error("missing credentials")]
    #[cfg_attr(feature = "axum", api(status = 401, code = "missing_credentials"))]
    MissingCredentials,

    #[error("invalid token: {0}")]
    #[cfg_attr(feature = "axum", api(status = 401, code = "invalid_token"))]
    InvalidToken(String),

    #[error("token is inactive")]
    #[cfg_attr(feature = "axum", api(status = 401, code = "token_inactive"))]
    TokenInactive,

    #[error("forbidden")]
    #[cfg_attr(feature = "axum", api(status = 403, code = "forbidden"))]
    Forbidden,

    #[error("introspection failed: {0}")]
    #[cfg_attr(feature = "axum", api(status = 500, code = "introspection_failed"))]
    IntrospectionFailed(String),

    #[error("policy resolution failed: {0}")]
    #[cfg_attr(feature = "axum", api(status = 500, code = "policy_failed"))]
    PolicyFailed(String),

    #[error("JWKS fetch failed: {0}")]
    #[cfg_attr(feature = "axum", api(status = 500, code = "jwks_failed"))]
    JwksFailed(String),

    #[error("unsupported filter: {0}")]
    #[cfg_attr(feature = "axum", api(status = 403, code = "unsupported_filter"))]
    UnsupportedFilter(String),
}
