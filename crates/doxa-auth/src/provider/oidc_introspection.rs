//! Generic RFC 7662 token introspection resolver.
//!
//! - takes a fully-qualified `introspection_url` so the same code works against
//!   Keycloak's `/protocol/openid-connect/token/introspect`, Auth0's
//!   `/oauth/token_introspection`, or any other RFC 7662 endpoint;
//! - lets the deployment configure the *names* of the claims it should pluck
//!   out via [`OidcClaimConfig`], so provider-specific keys (`groups`,
//!   `usersRoles`, `cognito:groups`, …) never leak past the resolver boundary.

use std::collections::HashMap;

use async_trait::async_trait;
use serde_json::Value;

use doxa_policy::AuthError;
use doxa_protected::ProtectedString;

use super::{ClaimResolver, MinimalClaims};
use crate::claims::OidcClaims;
use crate::provider::local_jwt::OidcClaimConfig;

/// Constructor parameters for [`OidcIntrospector`].
#[derive(Debug, Clone)]
pub struct OidcIntrospectionOptions {
    /// Fully-qualified introspection endpoint URL.
    pub introspection_url: String,
    /// OAuth client id authorized to introspect.
    pub client_id: String,
    /// OAuth client secret used by the introspecting client.
    pub client_secret: ProtectedString,
    /// Names of the claims to pluck out of the introspection response.
    pub claims: OidcClaimConfig,
}

/// RFC 7662 token introspection resolver.
///
/// Each call to [`resolve`](Self::resolve) issues a `POST` against
/// `introspection_url` with `client_id`/`client_secret`/`token` form fields,
/// then maps the JSON response into [`OidcClaims`] using the configured
/// [`OidcClaimConfig`]. Caching is the responsibility of the layer above this
/// type — the resolver itself is stateless so multiple deployments can share
/// a single instance without interfering with each other.
#[derive(Clone)]
pub struct OidcIntrospector {
    introspection_url: String,
    client_id: String,
    client_secret: ProtectedString,
    claims: OidcClaimConfig,
    client: reqwest::Client,
}

impl OidcIntrospector {
    /// Build a new resolver. Does not perform any network calls.
    pub fn new(opts: OidcIntrospectionOptions) -> Self {
        Self {
            introspection_url: opts.introspection_url,
            client_id: opts.client_id,
            client_secret: opts.client_secret,
            claims: opts.claims,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl ClaimResolver<OidcClaims> for OidcIntrospector {
    #[tracing::instrument(skip_all, name = "token_introspect")]
    async fn resolve(
        &self,
        token: &str,
        _minimal: &MinimalClaims,
    ) -> Result<OidcClaims, AuthError> {
        let response = self
            .client
            .post(&self.introspection_url)
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.expose()),
                ("token", token),
            ])
            .send()
            .await
            .map_err(|e| AuthError::IntrospectionFailed(format!("HTTP request failed: {e}")))?;

        let body: HashMap<String, Value> = response
            .json()
            .await
            .map_err(|e| AuthError::IntrospectionFailed(format!("response parse failed: {e}")))?;

        parse_introspection_response(&body, &self.claims)
    }
}

/// Pure helper that maps a parsed introspection response into
/// [`OidcClaims`] using the configured claim names.
///
/// Returns [`AuthError::TokenInactive`] when `active = false`. The function
/// is `pub(super)` so the resolver tests can exercise every claim-mapping
/// permutation without spinning up an HTTP server.
pub(super) fn parse_introspection_response(
    body: &HashMap<String, Value>,
    mapping: &OidcClaimConfig,
) -> Result<OidcClaims, AuthError> {
    let active = body.get("active").and_then(Value::as_bool).unwrap_or(false);
    if !active {
        return Err(AuthError::TokenInactive);
    }

    let sub = read_string_claim(body, &mapping.sub_claim).unwrap_or_default();
    let scope = read_string_claim(body, &mapping.scope_claim);
    let roles = read_role_claim(body, &mapping.roles_claim);

    Ok(OidcClaims { sub, scope, roles })
}

/// Read a single string claim. Tolerates the claim being absent or being a
/// non-string JSON value (returns `None` rather than failing the request).
fn read_string_claim(body: &HashMap<String, Value>, key: &str) -> Option<String> {
    body.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// Read a roles claim. Accepts either a JSON array of strings (the common
/// case) or a single comma-separated string (the SCIM/legacy case).
fn read_role_claim(body: &HashMap<String, Value>, key: &str) -> Vec<String> {
    match body.get(key) {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        Some(Value::String(s)) => s
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body_from(value: Value) -> HashMap<String, Value> {
        value
            .as_object()
            .expect("object")
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    #[test]
    fn parses_keycloak_shaped_response() {
        let body = body_from(json!({
            "active": true,
            "sub": "user-keycloak",
            "tenant_id": "acme",
            "groups": ["admin", "analyst"]
        }));
        let mapping = OidcClaimConfig {
            sub_claim: "sub".into(),
            scope_claim: "tenant_id".into(),
            roles_claim: "groups".into(),
        };
        let claims = parse_introspection_response(&body, &mapping).expect("parsed");
        assert_eq!(claims.sub, "user-keycloak");
        assert_eq!(claims.scope.as_deref(), Some("acme"));
        assert_eq!(claims.roles, vec!["admin", "analyst"]);
    }

    #[test]
    fn parses_legacy_response_with_custom_claim_names() {
        // Mimics the IdentityServer4 / Duende shape the original code was
        // hard-coded against — verifies the new resolver can still consume
        // it via configurable claim names.
        let body = body_from(json!({
            "active": true,
            "sub": "user-legacy",
            "companyId": "acme",
            "usersRoles": ["data_scientist"]
        }));
        let mapping = OidcClaimConfig {
            sub_claim: "sub".into(),
            scope_claim: "companyId".into(),
            roles_claim: "usersRoles".into(),
        };
        let claims = parse_introspection_response(&body, &mapping).expect("parsed");
        assert_eq!(claims.scope.as_deref(), Some("acme"));
        assert_eq!(claims.roles, vec!["data_scientist"]);
    }

    #[test]
    fn parses_comma_separated_roles_string() {
        let body = body_from(json!({
            "active": true,
            "sub": "user-1",
            "roles": "admin, analyst, viewer"
        }));
        let claims =
            parse_introspection_response(&body, &OidcClaimConfig::default()).expect("parsed");
        assert_eq!(claims.roles, vec!["admin", "analyst", "viewer"]);
    }

    #[test]
    fn returns_token_inactive_when_active_false() {
        let body = body_from(json!({ "active": false }));
        let err =
            parse_introspection_response(&body, &OidcClaimConfig::default()).expect_err("inactive");
        assert!(matches!(err, AuthError::TokenInactive));
    }

    #[test]
    fn missing_active_field_treated_as_inactive() {
        let body = body_from(json!({ "sub": "user-1" }));
        let err =
            parse_introspection_response(&body, &OidcClaimConfig::default()).expect_err("inactive");
        assert!(matches!(err, AuthError::TokenInactive));
    }

    #[test]
    fn missing_optional_claims_yield_none() {
        let body = body_from(json!({ "active": true, "sub": "user-1" }));
        let claims =
            parse_introspection_response(&body, &OidcClaimConfig::default()).expect("parsed");
        assert_eq!(claims.sub, "user-1");
        assert!(claims.scope.is_none());
        assert!(claims.roles.is_empty());
    }

    #[test]
    fn non_string_claim_value_is_ignored() {
        // Numeric tenant id from a misconfigured IdP — fail soft, do not panic.
        let body = body_from(json!({ "active": true, "sub": "user-1", "tenant_id": 42 }));
        let claims =
            parse_introspection_response(&body, &OidcClaimConfig::default()).expect("parsed");
        assert!(claims.scope.is_none());
    }
}
