//! Declarative configuration for the stock validators and resolvers, and the
//! builders that turn it into the [`AuthState`](crate::AuthState) stages.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use doxa_policy::AuthError;
use doxa_protected::ProtectedString;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::claims::{Claims, OidcClaims};
use crate::provider::{
    parse_algorithms, ClaimResolver, LocalJwtClaimResolver, OidcIntrospectionOptions,
    OidcIntrospector, OidcJwksOptions, OidcJwksValidator, TokenValidator,
    DEFAULT_INTROSPECTION_CACHE_TTL,
};

fn default_cache_ttl_secs() -> u64 {
    DEFAULT_INTROSPECTION_CACHE_TTL.as_secs()
}

fn default_true() -> bool {
    true
}

fn default_jwt_algorithms() -> Vec<String> {
    vec!["RS256".to_string()]
}

fn default_sub_claim() -> String {
    "sub".to_string()
}

fn default_tenant_claim() -> String {
    "tenant_id".to_string()
}

fn default_roles_claim() -> String {
    "roles".to_string()
}

/// Provider-agnostic auth provider configuration.
///
/// Every URL and claim name is explicit, so the same config works against any
/// RFC 6749 / 7519 / 7662 IdP. LDAP deployments put Keycloak or Authentik in front.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthProviderConfig {
    /// Whether the auth pipeline is enabled. Defaults to `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Stage 1 — credential validation.
    pub validator: ValidatorConfig,
    /// Stage 2 — claim enrichment.
    pub resolver: ResolverConfig,
}

/// Stage 1 — how a credential is cryptographically validated.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ValidatorConfig {
    /// Validate JWTs against the JWKS keyset at `jwks_uri` (no discovery).
    OidcJwks {
        /// Fully-qualified JWKS URL.
        jwks_uri: String,
        /// Expected `iss` claim. `None` disables issuer validation.
        #[serde(default)]
        issuer: Option<String>,
        /// Acceptable `aud` claims. Empty disables audience validation.
        #[serde(default)]
        audience: Vec<String>,
        /// Allowed signing algorithms, pinned against alg confusion. Defaults to `["RS256"]`.
        #[serde(default = "default_jwt_algorithms")]
        algorithms: Vec<String>,
    },
}

impl ValidatorConfig {
    /// The validator this config describes; fetches the JWKS keyset before returning.
    pub async fn build(&self) -> Result<Arc<dyn TokenValidator>, AuthError> {
        match self {
            Self::OidcJwks {
                jwks_uri,
                issuer,
                audience,
                algorithms,
            } => {
                let validator = OidcJwksValidator::new(OidcJwksOptions {
                    jwks_uri: jwks_uri.clone(),
                    issuer: issuer.clone(),
                    audience: audience.clone(),
                    algorithms: parse_algorithms(algorithms)?,
                })
                .await?;
                Ok(Arc::new(validator))
            }
        }
    }
}

/// Stage 2 — how validated credentials are enriched into rich claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResolverConfig {
    /// RFC 7662 token introspection against `introspection_url`.
    OidcIntrospection {
        /// Fully-qualified introspection endpoint URL.
        introspection_url: String,
        /// OAuth client id authorized to introspect.
        client_id: String,
        /// OAuth client secret used by the introspecting client.
        client_secret: ProtectedString,
        /// Which claims to read from the introspection response.
        #[serde(default)]
        claims: ClaimMapping,
        /// Seconds an introspection result is reused, so a revocation can take this long to
        /// apply. `0` introspects every request. Defaults to 300.
        #[serde(default = "default_cache_ttl_secs")]
        cache_ttl_secs: u64,
    },
    /// Read claims from the validated JWT body: no network call, but revocation
    /// only takes effect at the token's expiry.
    LocalJwtClaims {
        /// Which claims to read from the JWT body.
        #[serde(default)]
        claims: ClaimMapping,
    },
}

impl ResolverConfig {
    /// The resolver this config describes, producing any claim type built from [`OidcClaims`].
    pub fn build<C>(&self) -> Arc<dyn ClaimResolver<C>>
    where
        C: Claims + TryFrom<OidcClaims>,
        C::Error: Into<AuthError>,
    {
        match self {
            Self::OidcIntrospection {
                introspection_url,
                client_id,
                client_secret,
                claims,
                cache_ttl_secs,
            } => Arc::new(OidcIntrospector::new(OidcIntrospectionOptions {
                introspection_url: introspection_url.clone(),
                client_id: client_id.clone(),
                client_secret: client_secret.clone(),
                claims: claims.clone(),
                cache_ttl: Duration::from_secs(*cache_ttl_secs),
            })),
            Self::LocalJwtClaims { claims } => Arc::new(LocalJwtClaimResolver::new(claims.clone())),
        }
    }
}

/// Names of the IdP claims the stock resolvers read into [`OidcClaims`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimMapping {
    /// Source claim for the subject. Defaults to `"sub"`.
    #[serde(default = "default_sub_claim")]
    pub sub: String,
    /// Source claim for [`OidcClaims::scope`]. Defaults to `"tenant_id"`.
    #[serde(default = "default_tenant_claim")]
    pub tenant_id: String,
    /// Source claim for roles: a string array or one comma-separated string. Defaults to `"roles"`.
    #[serde(default = "default_roles_claim")]
    pub roles: String,
}

impl Default for ClaimMapping {
    fn default() -> Self {
        Self {
            sub: default_sub_claim(),
            tenant_id: default_tenant_claim(),
            roles: default_roles_claim(),
        }
    }
}

/// What a [`ClaimMapping`] found in a claim payload.
pub(crate) struct Mapped {
    pub(crate) sub: Option<String>,
    pub(crate) scope: Option<String>,
    pub(crate) roles: Vec<String>,
}

impl ClaimMapping {
    /// Read the mapped claims; an absent or non-string value reads as `None`.
    pub(crate) fn read(&self, body: &HashMap<String, Value>) -> Mapped {
        let string = |key: &str| body.get(key).and_then(Value::as_str).map(str::to_owned);
        let roles = match body.get(&self.roles) {
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
        };
        Mapped {
            sub: string(&self.sub),
            scope: string(&self.tenant_id),
            roles,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body(value: Value) -> HashMap<String, Value> {
        serde_json::from_value(value).expect("object")
    }

    #[test]
    fn reads_default_claim_names() {
        let mapped = ClaimMapping::default().read(&body(json!({
            "sub": "user-1", "tenant_id": "acme", "roles": ["admin", "viewer"]
        })));
        assert_eq!(mapped.sub.as_deref(), Some("user-1"));
        assert_eq!(mapped.scope.as_deref(), Some("acme"));
        assert_eq!(mapped.roles, vec!["admin", "viewer"]);
    }

    #[test]
    fn reads_custom_claim_names() {
        let mapping = ClaimMapping {
            sub: "uid".into(),
            tenant_id: "custom:tenant".into(),
            roles: "cognito:groups".into(),
        };
        let mapped = mapping.read(&body(json!({
            "uid": "u", "custom:tenant": "acme", "cognito:groups": ["editor"]
        })));
        assert_eq!(mapped.sub.as_deref(), Some("u"));
        assert_eq!(mapped.scope.as_deref(), Some("acme"));
        assert_eq!(mapped.roles, vec!["editor"]);
    }

    #[test]
    fn reads_comma_separated_roles() {
        let mapped = ClaimMapping::default().read(&body(json!({ "roles": "admin, analyst,," })));
        assert_eq!(mapped.roles, vec!["admin", "analyst"]);
    }

    #[test]
    fn absent_and_non_string_claims_read_as_none() {
        let mapped = ClaimMapping::default().read(&body(json!({ "tenant_id": 42 })));
        assert!(mapped.sub.is_none());
        assert!(mapped.scope.is_none());
        assert!(mapped.roles.is_empty());
    }

    #[test]
    fn introspection_cache_ttl_defaults_and_old_keys_are_ignored() {
        let config: ResolverConfig = serde_json::from_value(json!({
            "kind": "oidc_introspection",
            "introspection_url": "http://idp/introspect",
            "client_id": "api",
            "client_secret": "s",
            "claims": { "project_id": "legacy" }
        }))
        .expect("parses");
        let ResolverConfig::OidcIntrospection {
            cache_ttl_secs,
            claims,
            ..
        } = config
        else {
            panic!("introspection variant");
        };
        assert_eq!(cache_ttl_secs, 300);
        assert_eq!(claims.tenant_id, "tenant_id");
    }

    #[tokio::test]
    async fn validator_build_rejects_an_unknown_algorithm() {
        let config = ValidatorConfig::OidcJwks {
            jwks_uri: "http://127.0.0.1:0/jwks".into(),
            issuer: None,
            audience: Vec::new(),
            algorithms: vec!["none".into()],
        };
        assert!(config.build().await.is_err());
    }
}
