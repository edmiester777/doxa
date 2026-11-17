//! Resolver that reads claims from the validated JWT body, for IdPs that pack
//! tenant and roles into the access token (Cognito, Auth0, Azure AD). No network
//! call, but a revocation only takes effect at the token's expiry.

use async_trait::async_trait;

use doxa_policy::AuthError;

use super::{ClaimResolver, MinimalClaims};
use crate::claims::{Claims, OidcClaims};
use crate::config::ClaimMapping;

/// [`ClaimResolver`] reading the JWT body the validator forwards in [`MinimalClaims::extra`].
#[derive(Debug, Clone, Default)]
pub struct LocalJwtClaimResolver {
    claims: ClaimMapping,
}

impl LocalJwtClaimResolver {
    /// Build a resolver that maps claim names according to `claims`.
    pub fn new(claims: ClaimMapping) -> Self {
        Self { claims }
    }
}

#[async_trait]
impl<C> ClaimResolver<C> for LocalJwtClaimResolver
where
    C: Claims + TryFrom<OidcClaims>,
    C::Error: Into<AuthError>,
{
    #[tracing::instrument(skip_all, name = "local_jwt_claims")]
    async fn resolve(&self, _token: &str, minimal: &MinimalClaims) -> Result<C, AuthError> {
        let mapped = self.claims.read(&minimal.extra);
        // A missing sub means the validator forwarded no body: a wiring bug, surfaced as a refusal.
        let sub = mapped
            .sub
            .or_else(|| minimal.sub.clone())
            .ok_or_else(|| AuthError::InvalidToken("JWT body missing subject claim".to_string()))?;
        let claims = OidcClaims {
            sub,
            scope: mapped.scope,
            roles: mapped.roles,
        };
        C::try_from(claims).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::{json, Value};

    use super::*;

    fn minimal_with(extra: Value) -> MinimalClaims {
        MinimalClaims {
            sub: None,
            exp: None,
            extra: serde_json::from_value(extra).expect("object"),
        }
    }

    /// A claim type that refuses a token without a tenant.
    #[derive(Debug, Clone)]
    struct Tenanted {
        sub: String,
        tenant: String,
    }

    impl Claims for Tenanted {
        fn sub(&self) -> &str {
            &self.sub
        }
        fn scope(&self) -> Option<&str> {
            Some(&self.tenant)
        }
        fn roles(&self) -> &[String] {
            &[]
        }
    }

    impl TryFrom<OidcClaims> for Tenanted {
        type Error = AuthError;
        fn try_from(claims: OidcClaims) -> Result<Self, AuthError> {
            let tenant = claims
                .scope
                .ok_or_else(|| AuthError::InvalidToken("no tenant".into()))?;
            Ok(Self {
                sub: claims.sub,
                tenant,
            })
        }
    }

    #[tokio::test]
    async fn reads_cognito_shaped_claims() {
        let resolver = LocalJwtClaimResolver::new(ClaimMapping {
            sub: "sub".into(),
            tenant_id: "custom:tenant".into(),
            roles: "cognito:groups".into(),
        });
        let minimal = minimal_with(json!({
            "sub": "cognito-user",
            "custom:tenant": "acme",
            "cognito:groups": ["admin", "viewer"]
        }));
        let claims: OidcClaims = resolver
            .resolve("ignored", &minimal)
            .await
            .expect("resolved");
        assert_eq!(claims.sub, "cognito-user");
        assert_eq!(claims.scope.as_deref(), Some("acme"));
        assert_eq!(claims.roles, vec!["admin", "viewer"]);
    }

    #[tokio::test]
    async fn falls_back_to_minimal_sub_when_body_missing_sub() {
        let resolver = LocalJwtClaimResolver::default();
        let minimal = MinimalClaims {
            sub: Some("from-validator".into()),
            exp: None,
            extra: HashMap::new(),
        };
        let claims: OidcClaims = resolver
            .resolve("ignored", &minimal)
            .await
            .expect("resolved");
        assert_eq!(claims.sub, "from-validator");
        assert!(claims.scope.is_none());
    }

    #[tokio::test]
    async fn returns_invalid_token_when_sub_unavailable() {
        let resolver = LocalJwtClaimResolver::default();
        let err =
            ClaimResolver::<OidcClaims>::resolve(&resolver, "ignored", &MinimalClaims::default())
                .await
                .expect_err("missing");
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    #[tokio::test]
    async fn resolves_a_custom_claim_type() {
        let resolver = LocalJwtClaimResolver::default();
        let minimal = minimal_with(json!({ "sub": "u", "tenant_id": "acme" }));
        let claims: Tenanted = resolver
            .resolve("ignored", &minimal)
            .await
            .expect("resolved");
        assert_eq!((claims.sub.as_str(), claims.tenant.as_str()), ("u", "acme"));
    }

    #[tokio::test]
    async fn a_custom_claim_types_refusal_is_returned() {
        let resolver = LocalJwtClaimResolver::default();
        let minimal = minimal_with(json!({ "sub": "u" }));
        let err = ClaimResolver::<Tenanted>::resolve(&resolver, "ignored", &minimal)
            .await
            .expect_err("no tenant");
        assert!(matches!(err, AuthError::InvalidToken(m) if m == "no tenant"));
    }
}
