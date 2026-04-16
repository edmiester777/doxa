//! Resolver that reads claims directly from the validated JWT body.
//!
//! Use this when the IdP packs everything the application needs (tenant id,
//! roles / groups) into the access token itself and the deployment wants to
//! avoid an introspection round-trip on every request. This is the common
//! pattern for AWS Cognito, Auth0 (without the introspection extension),
//! Azure AD, and any other "claims-rich JWT" provider.
//!
//! ## Trade-off
//!
//! Skipping introspection trades token-revocation freshness for latency:
//! revocations only take effect at the next JWT expiry. Pair this resolver
//! with short JWT lifetimes when revocation latency matters.

use std::collections::HashMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use doxa_policy::AuthError;

use super::{ClaimResolver, MinimalClaims};
use crate::claims::OidcClaims;

/// Source-claim name mapping for the stock [`OidcClaims`] resolvers.
///
/// Declares which keys to pluck out of the IdP's payload to populate the
/// three fields on [`OidcClaims`]. Defaults to the names most common
/// across modern OIDC providers; override per-provider as needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcClaimConfig {
    /// Source claim for the principal subject id. Defaults to `"sub"`.
    #[serde(default = "default_sub_claim")]
    pub sub_claim: String,
    /// Source claim for the policy scope (tenant / organization).
    /// Defaults to `"tenant_id"`.
    #[serde(default = "default_scope_claim")]
    pub scope_claim: String,
    /// Source claim for roles / groups. Defaults to `"roles"`. The resolver
    /// accepts either a JSON string array or a single comma-separated string.
    #[serde(default = "default_roles_claim")]
    pub roles_claim: String,
}

impl Default for OidcClaimConfig {
    fn default() -> Self {
        Self {
            sub_claim: default_sub_claim(),
            scope_claim: default_scope_claim(),
            roles_claim: default_roles_claim(),
        }
    }
}

fn default_sub_claim() -> String {
    "sub".to_string()
}

fn default_scope_claim() -> String {
    "tenant_id".to_string()
}

fn default_roles_claim() -> String {
    "roles".to_string()
}

/// [`ClaimResolver`] that reads claims directly from the JWT body forwarded
/// by the validator (via [`MinimalClaims::extra`]).
#[derive(Debug, Clone, Default)]
pub struct LocalJwtClaimResolver {
    claims: OidcClaimConfig,
}

impl LocalJwtClaimResolver {
    /// Build a resolver that maps claim names according to `claims`.
    pub fn new(claims: OidcClaimConfig) -> Self {
        Self { claims }
    }
}

#[async_trait]
impl ClaimResolver<OidcClaims> for LocalJwtClaimResolver {
    #[tracing::instrument(skip_all, name = "local_jwt_claims")]
    async fn resolve(
        &self,
        _token: &str,
        minimal: &MinimalClaims,
    ) -> Result<OidcClaims, AuthError> {
        let body = &minimal.extra;

        // The validator has already enforced signature + expiry + issuer +
        // audience. If `sub` is missing here it means the validator did not
        // forward the JWT body — that's a programming error, not an auth
        // failure, so we surface it as `InvalidToken` for visibility.
        let sub = read_string(body, &self.claims.sub_claim)
            .or_else(|| minimal.sub.clone())
            .ok_or_else(|| AuthError::InvalidToken("JWT body missing subject claim".to_string()))?;

        let scope = read_string(body, &self.claims.scope_claim);
        let roles = read_roles(body, &self.claims.roles_claim);

        Ok(OidcClaims { sub, scope, roles })
    }
}

fn read_string(body: &HashMap<String, Value>, key: &str) -> Option<String> {
    body.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn read_roles(body: &HashMap<String, Value>, key: &str) -> Vec<String> {
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

    fn minimal_with(extra: Value) -> MinimalClaims {
        let extra = extra
            .as_object()
            .expect("object")
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        MinimalClaims {
            sub: None,
            exp: None,
            extra,
        }
    }

    #[tokio::test]
    async fn reads_cognito_shaped_claims() {
        // Cognito puts groups in `cognito:groups` and the tenant in a custom
        // attribute namespace. The resolver lets the operator point at both.
        let resolver = LocalJwtClaimResolver::new(OidcClaimConfig {
            sub_claim: "sub".into(),
            scope_claim: "custom:tenant".into(),
            roles_claim: "cognito:groups".into(),
        });
        let minimal = minimal_with(json!({
            "sub": "cognito-user",
            "custom:tenant": "acme",
            "cognito:groups": ["admin", "viewer"]
        }));
        let claims = resolver
            .resolve("ignored", &minimal)
            .await
            .expect("resolved");
        assert_eq!(claims.sub, "cognito-user");
        assert_eq!(claims.scope.as_deref(), Some("acme"));
        assert_eq!(claims.roles, vec!["admin", "viewer"]);
    }

    #[tokio::test]
    async fn reads_default_claim_names() {
        let resolver = LocalJwtClaimResolver::new(OidcClaimConfig::default());
        let minimal = minimal_with(json!({
            "sub": "user-1",
            "tenant_id": "acme",
            "roles": ["admin"]
        }));
        let claims = resolver
            .resolve("ignored", &minimal)
            .await
            .expect("resolved");
        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.scope.as_deref(), Some("acme"));
        assert_eq!(claims.roles, vec!["admin"]);
    }

    #[tokio::test]
    async fn falls_back_to_minimal_sub_when_body_missing_sub() {
        let resolver = LocalJwtClaimResolver::new(OidcClaimConfig::default());
        let minimal = MinimalClaims {
            sub: Some("from-validator".into()),
            exp: None,
            extra: HashMap::new(),
        };
        let claims = resolver
            .resolve("ignored", &minimal)
            .await
            .expect("resolved");
        assert_eq!(claims.sub, "from-validator");
        assert!(claims.scope.is_none());
        assert!(claims.roles.is_empty());
    }

    #[tokio::test]
    async fn returns_invalid_token_when_sub_unavailable() {
        let resolver = LocalJwtClaimResolver::new(OidcClaimConfig::default());
        let minimal = MinimalClaims::default();
        let err = resolver
            .resolve("ignored", &minimal)
            .await
            .expect_err("missing");
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    #[tokio::test]
    async fn parses_comma_separated_roles_string() {
        let resolver = LocalJwtClaimResolver::new(OidcClaimConfig::default());
        let minimal = minimal_with(json!({
            "sub": "user-1",
            "roles": "admin, analyst"
        }));
        let claims = resolver
            .resolve("ignored", &minimal)
            .await
            .expect("resolved");
        assert_eq!(claims.roles, vec!["admin", "analyst"]);
    }
}
