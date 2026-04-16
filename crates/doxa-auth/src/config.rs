//! Declarative configuration types for the auth provider pipeline.
//!
//! These types describe how the library's stock validators and
//! resolvers are wired up from a YAML / JSON configuration file.
//! They live here (rather than in a downstream crate) so that
//! `doxa-auth` owns its full configuration surface and can be
//! published as a standalone crate with no additional configuration
//! dependencies.
//!
//! Consumers that build their own validators or resolvers can ignore
//! these types entirely — they exist to serve the quick-start
//! [`OidcJwksValidator`](crate::provider::OidcJwksValidator) /
//! [`OidcIntrospector`](crate::provider::OidcIntrospector) /
//! [`LocalJwtClaimResolver`](crate::provider::LocalJwtClaimResolver)
//! path.

use doxa_protected::ProtectedString;
use serde::{Deserialize, Serialize};

const DEFAULT_CACHE_TTL_SECS: u64 = 300;

fn default_cache_ttl_secs() -> u64 {
    DEFAULT_CACHE_TTL_SECS
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

fn default_project_claim() -> String {
    "project_id".to_string()
}

fn default_roles_claim() -> String {
    "roles".to_string()
}

/// Provider-agnostic auth provider configuration.
///
/// Carries no provider-specific assumptions: every URL and every claim name
/// is declared explicitly so the same code works against Keycloak, Auth0,
/// Cognito, Okta, Azure AD, or any RFC 6749 / 7519 / 7662 compliant IdP.
///
/// LDAP / Active Directory deployments are expected to put Keycloak or
/// Authentik in front and consume the resulting OIDC tokens — there is no
/// native LDAP-bind authenticator and there are no plans to add one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthProviderConfig {
    /// Whether the auth pipeline is enabled. Defaults to `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// TTL for the introspection / claims cache, in seconds.
    #[serde(default = "default_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
    /// Stage 1 — credential validation.
    pub validator: ValidatorConfig,
    /// Stage 2 — claim enrichment.
    pub resolver: ResolverConfig,
}

/// Stage 1 — how a credential is cryptographically validated.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ValidatorConfig {
    /// Validate JWTs against a JWKS keyset fetched from `jwks_uri`.
    ///
    /// No `.well-known/openid-configuration` discovery is performed; the URI
    /// is given explicitly so the same code works against any IdP that
    /// publishes a JWKS document.
    OidcJwks {
        /// Fully-qualified JWKS URL.
        jwks_uri: String,
        /// Expected `iss` claim. `None` disables issuer validation — set this
        /// in production unless your IdP omits the claim.
        #[serde(default)]
        issuer: Option<String>,
        /// Acceptable `aud` claims. An empty list disables audience
        /// validation entirely.
        #[serde(default)]
        audience: Vec<String>,
        /// Allowed signing algorithms. Defaults to `["RS256"]`. Pinning the
        /// algorithm list mitigates the classic JWT alg-confusion family of
        /// attacks.
        #[serde(default = "default_jwt_algorithms")]
        algorithms: Vec<String>,
    },
}

/// Stage 2 — how validated credentials are enriched into rich claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResolverConfig {
    /// RFC 7662 token introspection against a fully-specified URL with
    /// configurable claim mapping.
    ///
    /// Use this when the IdP exposes a standard introspection endpoint and
    /// you want token-revocation semantics enforced on every request (subject
    /// to the cache TTL).
    OidcIntrospection {
        /// Fully-qualified introspection endpoint URL.
        introspection_url: String,
        /// OAuth client id authorized to introspect.
        client_id: String,
        /// OAuth client secret used by the introspecting client.
        client_secret: ProtectedString,
        /// Names of the claims this resolver should pluck out of the
        /// introspection response.
        #[serde(default)]
        claims: ClaimMapping,
    },
    /// Read claims directly from the validated JWT body. No network call.
    ///
    /// Use this when the IdP packs everything the application needs (tenant,
    /// roles) into the access token itself and you want to avoid an
    /// introspection round-trip on every request. Trades token-revocation
    /// freshness for latency: revocations only take effect at the next JWT
    /// expiry, so pair with short token lifetimes.
    LocalJwtClaims {
        /// Names of the claims this resolver should read out of the JWT body.
        #[serde(default)]
        claims: ClaimMapping,
    },
}

/// IdP-neutral claim-name mapping consumed by the stock resolvers.
///
/// Each field is the *name of the claim* in the IdP's payload that should
/// be mapped to the corresponding logical field. The defaults pick the
/// names most common across modern OIDC providers; override per-provider
/// as needed.
///
/// Consumers that write their own [`ClaimResolver`](crate::ClaimResolver)
/// can ignore this type — it's only used by the stock OIDC resolvers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimMapping {
    /// Source claim for the principal subject id. Defaults to `"sub"`.
    #[serde(default = "default_sub_claim")]
    pub sub: String,
    /// Source claim for the tenant id. Defaults to `"tenant_id"`.
    #[serde(default = "default_tenant_claim")]
    pub tenant_id: String,
    /// Source claim for the project id. Defaults to `"project_id"`.
    #[serde(default = "default_project_claim")]
    pub project_id: String,
    /// Source claim for roles / groups. Defaults to `"roles"`. The resolver
    /// accepts either a JSON string array or a single comma-separated string.
    #[serde(default = "default_roles_claim")]
    pub roles: String,
}

impl Default for ClaimMapping {
    fn default() -> Self {
        Self {
            sub: default_sub_claim(),
            tenant_id: default_tenant_claim(),
            project_id: default_project_claim(),
            roles: default_roles_claim(),
        }
    }
}
