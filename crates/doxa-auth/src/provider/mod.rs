//! Provider-agnostic authentication primitives.
//!
//! This module defines the trait surface that lets `doxa-auth` integrate
//! with any identity provider — Keycloak, Auth0, Cognito, Okta, Azure AD, or
//! any RFC 6749/7662/7519-compliant OIDC server — without baking
//! provider-specific assumptions into the middleware.
//!
//! ## Two-stage pipeline
//!
//! Authentication is split into two clearly separated stages so that each can
//! be swapped independently:
//!
//! 1. **Validation** ([`TokenValidator`]) — cryptographically verify the
//!    credential and return the bare minimum needed to identify the principal.
//!    For OIDC this is a JWT signature/expiry check against a JWKS keyset.
//! 2. **Resolution** ([`ClaimResolver`]) — produce the claim struct the rest of
//!    the system consumes. The resolver is generic over a consumer-defined
//!    claim type `C: Claims`, so deployments own the full claim vocabulary
//!    without needing to fit it into a library-supplied shape.
//!
//! Splitting the two stages means a deployment can pair a single
//! [`TokenValidator`] with any [`ClaimResolver`] (e.g. JWKS validation +
//! local-claim parsing for cloud IdPs that don't expose introspection).
//!
//! ## Provided implementations
//!
//! - [`OidcJwksValidator`] — RFC 7519 JWT validation against a JWKS keyset
//!   fetched from a configurable URL.
//! - [`OidcIntrospector`] — RFC 7662 token introspection resolver that produces
//!   [`OidcClaims`](crate::claims::OidcClaims) from the introspection response.
//! - [`LocalJwtClaimResolver`] — reads claims directly from the validated JWT
//!   body forwarded by the validator, producing
//!   [`OidcClaims`](crate::claims::OidcClaims).

use std::collections::HashMap;

use async_trait::async_trait;
use serde_json::Value;

use doxa_policy::AuthError;

use crate::claims::Claims;

pub mod local_jwt;
pub mod oidc_introspection;
pub mod oidc_jwks;

pub use local_jwt::{LocalJwtClaimResolver, OidcClaimConfig};
pub use oidc_introspection::{OidcIntrospectionOptions, OidcIntrospector};
pub use oidc_jwks::{parse_algorithms, OidcJwksOptions, OidcJwksValidator};

/// Output of [`TokenValidator::validate`].
///
/// Carries only the fields the middleware itself needs after a successful
/// signature check. Anything richer (tenant id, roles, custom claims) is the
/// job of [`ClaimResolver`].
///
/// `extra` lets a validator forward already-decoded JWT claims into the
/// resolver stage so a [`ClaimResolver`] implementation that reads claims
/// locally (no introspection round-trip) does not have to decode the JWT a
/// second time.
#[derive(Debug, Clone, Default)]
pub struct MinimalClaims {
    /// The `sub` claim from the credential, if present. Optional because some
    /// validators (e.g. opaque-token validators) cannot extract it without
    /// introspection.
    pub sub: Option<String>,
    /// Expiry timestamp (seconds since epoch) if known.
    pub exp: Option<u64>,
    /// Pre-decoded JWT claim payload, if the validator decoded one. Used by
    /// [`ClaimResolver`] implementations that read claims directly from the
    /// JWT body to avoid a second decode.
    pub extra: HashMap<String, Value>,
}

/// Stage 1: cryptographically verify a credential.
///
/// Implementations must be cheap to call repeatedly — the middleware invokes
/// `validate` on every authenticated request. Cache JWKS keysets, connection
/// pools, and any other expensive state inside the implementation.
///
/// Errors should map to [`AuthError::InvalidToken`] for malformed/expired
/// credentials and [`AuthError::JwksFailed`] for upstream key-fetch problems.
#[async_trait]
pub trait TokenValidator: Send + Sync {
    /// Validate `token` and return its [`MinimalClaims`] on success.
    async fn validate(&self, token: &str) -> Result<MinimalClaims, AuthError>;
}

/// Stage 2: enrich a validated credential into a consumer-defined claim
/// struct `C`.
///
/// Implementations may make a network call (RFC 7662 introspection, LDAP
/// lookup, …) or operate purely on the [`MinimalClaims`] forwarded by the
/// validator. The middleware does not care which strategy is used.
///
/// `token` is forwarded so introspection-based resolvers can pass the bearer
/// credential to the IdP. Resolvers that do not need it should ignore the
/// argument.
#[async_trait]
pub trait ClaimResolver<C: Claims>: Send + Sync {
    /// Resolve the rich claim set for an already-validated credential.
    async fn resolve(&self, token: &str, minimal: &MinimalClaims) -> Result<C, AuthError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::OidcClaims;

    /// Stand-in validator that returns a fixed claim set. Verifies the trait
    /// can be implemented and dispatched as `dyn TokenValidator`.
    struct StaticValidator(MinimalClaims);

    #[async_trait]
    impl TokenValidator for StaticValidator {
        async fn validate(&self, _token: &str) -> Result<MinimalClaims, AuthError> {
            Ok(self.0.clone())
        }
    }

    /// Stand-in resolver that copies the validator's `sub` into the
    /// resolved claim set. Verifies that resolvers can consume the
    /// validator's output without re-fetching the token.
    struct EchoResolver;

    #[async_trait]
    impl ClaimResolver<OidcClaims> for EchoResolver {
        async fn resolve(
            &self,
            _token: &str,
            minimal: &MinimalClaims,
        ) -> Result<OidcClaims, AuthError> {
            Ok(OidcClaims {
                sub: minimal.sub.clone().unwrap_or_default(),
                ..OidcClaims::default()
            })
        }
    }

    #[tokio::test]
    async fn validator_and_resolver_can_be_chained_via_trait_objects() {
        let validator: Box<dyn TokenValidator> = Box::new(StaticValidator(MinimalClaims {
            sub: Some("user-42".into()),
            exp: Some(9_999_999_999),
            extra: HashMap::new(),
        }));
        let resolver: Box<dyn ClaimResolver<OidcClaims>> = Box::new(EchoResolver);

        let minimal = validator.validate("ignored").await.expect("validate");
        assert_eq!(minimal.sub.as_deref(), Some("user-42"));

        let resolved = resolver
            .resolve("ignored", &minimal)
            .await
            .expect("resolve");
        assert_eq!(resolved.sub, "user-42");
        assert!(resolved.scope.is_none());
    }

    #[tokio::test]
    async fn echo_resolver_returns_empty_sub_when_minimal_lacks_one() {
        let resolver = EchoResolver;
        let resolved = resolver
            .resolve("token", &MinimalClaims::default())
            .await
            .expect("resolve");
        assert_eq!(resolved.sub, "");
    }
}
