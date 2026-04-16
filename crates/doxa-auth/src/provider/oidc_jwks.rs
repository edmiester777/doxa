//! Generic OIDC JWT validator backed by a JWKS keyset.
//!
//! Makes **no** assumption about how the JWKS is published — the caller
//! passes a fully-qualified `jwks_uri` directly. There is no
//! `.well-known/openid-configuration` discovery, so the same code works
//! against Keycloak, Auth0, Cognito, Okta, Azure AD, or any other provider
//! that publishes a JWKS document at a known URL.
//!
//! Issuer, audience, and the allowed signing-algorithm list are all
//! configurable per-deployment. Pinning the algorithm list is the standard
//! mitigation for the JWT alg-confusion attack family.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::RwLock;

use doxa_policy::AuthError;

use super::{MinimalClaims, TokenValidator};

/// Constructor parameters for [`OidcJwksValidator`]. These are the raw
/// inputs the validator needs at construction time; deployments that load
/// configuration from YAML translate from their own config type into
/// these options at startup.
#[derive(Debug, Clone)]
pub struct OidcJwksOptions {
    /// Fully-qualified JWKS URL.
    pub jwks_uri: String,
    /// Expected `iss` claim. `None` disables issuer validation.
    pub issuer: Option<String>,
    /// Acceptable `aud` claims. Empty disables audience validation.
    pub audience: Vec<String>,
    /// Allowed signing algorithms (e.g. `["RS256", "ES256"]`).
    pub algorithms: Vec<Algorithm>,
}

/// Validates JWTs against a JWKS keyset fetched from a configurable URL.
///
/// JWKS keysets are cached in memory and refreshed on `kid` cache miss
/// (rate-limited to one refresh per minute) so a key rotation by the IdP is
/// picked up automatically without restarting the process.
#[derive(Clone)]
pub struct OidcJwksValidator {
    jwks_uri: String,
    issuer: Option<String>,
    audience: Vec<String>,
    algorithms: Vec<Algorithm>,
    jwks: Arc<RwLock<CachedJwks>>,
    client: reqwest::Client,
}

struct CachedJwks {
    keyset: Option<JwkSet>,
    last_refresh: Instant,
}

/// Raw JWT body claims pulled out by `jsonwebtoken::decode`. Only the fields
/// the middleware needs are typed; everything else is captured in `extra` so
/// downstream resolvers (e.g. `LocalJwtClaimResolver`) can read provider
/// claims without re-decoding the token.
#[derive(Debug, Deserialize)]
struct JwtBody {
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    exp: Option<u64>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

impl OidcJwksValidator {
    /// Build a validator and eagerly fetch the keyset.
    ///
    /// Returns [`AuthError::JwksFailed`] if the initial fetch fails so
    /// startup observably blocks on a misconfigured `jwks_uri` instead of
    /// silently degrading to per-request failures.
    pub async fn new(opts: OidcJwksOptions) -> Result<Self, AuthError> {
        let validator = Self {
            jwks_uri: opts.jwks_uri,
            issuer: opts.issuer,
            audience: opts.audience,
            algorithms: opts.algorithms,
            jwks: Arc::new(RwLock::new(CachedJwks {
                keyset: None,
                last_refresh: Instant::now() - Duration::from_secs(7200),
            })),
            client: reqwest::Client::new(),
        };
        validator.refresh_jwks().await?;
        Ok(validator)
    }

    #[tracing::instrument(skip_all, name = "jwks_refresh", fields(jwks_uri = %self.jwks_uri))]
    async fn refresh_jwks(&self) -> Result<(), AuthError> {
        let jwks: JwkSet = self
            .client
            .get(&self.jwks_uri)
            .send()
            .await
            .map_err(|e| AuthError::JwksFailed(format!("JWKS fetch failed: {e}")))?
            .json()
            .await
            .map_err(|e| AuthError::JwksFailed(format!("JWKS parse failed: {e}")))?;

        let key_count = jwks.keys.len();
        let mut cache = self.jwks.write().await;
        cache.keyset = Some(jwks);
        cache.last_refresh = Instant::now();

        tracing::info!(key_count, "JWKS refreshed");
        Ok(())
    }

    fn try_validate_with_keyset(
        &self,
        token: &str,
        kid: Option<&str>,
        alg: Algorithm,
        keyset: &JwkSet,
    ) -> Option<Result<JwtBody, AuthError>> {
        if !self.algorithms.contains(&alg) {
            return Some(Err(AuthError::InvalidToken(format!(
                "JWT signing algorithm {alg:?} not in allow-list"
            ))));
        }

        for jwk in &keyset.keys {
            if let (Some(token_kid), Some(jwk_kid)) = (kid, &jwk.common.key_id) {
                if token_kid != jwk_kid {
                    continue;
                }
            }

            let key = match DecodingKey::from_jwk(jwk) {
                Ok(k) => k,
                Err(_) => continue,
            };

            let mut validation = Validation::new(alg);
            validation.validate_exp = true;
            if !self.audience.is_empty() {
                validation.set_audience(&self.audience);
            } else {
                validation.validate_aud = false;
            }
            if let Some(ref iss) = self.issuer {
                validation.set_issuer(&[iss]);
            }

            match decode::<JwtBody>(token, &key, &validation) {
                Ok(data) => return Some(Ok(data.claims)),
                Err(e) => {
                    if kid.is_some() {
                        return Some(Err(AuthError::InvalidToken(format!(
                            "JWT validation failed: {e}"
                        ))));
                    }
                    continue;
                }
            }
        }
        None
    }
}

#[async_trait]
impl TokenValidator for OidcJwksValidator {
    #[tracing::instrument(skip_all, name = "jwt_validate")]
    async fn validate(&self, token: &str) -> Result<MinimalClaims, AuthError> {
        let header = decode_header(token)
            .map_err(|e| AuthError::InvalidToken(format!("malformed JWT header: {e}")))?;
        let kid = header.kid.as_deref();
        let alg = header.alg;

        // First attempt against the cached keyset.
        let attempt = {
            let cache = self.jwks.read().await;
            cache
                .keyset
                .as_ref()
                .and_then(|keyset| self.try_validate_with_keyset(token, kid, alg, keyset))
        };

        if let Some(result) = attempt {
            return result.map(into_minimal);
        }

        // kid miss against a stale keyset → rate-limited refresh and retry.
        {
            let cache = self.jwks.read().await;
            let stale = cache.last_refresh.elapsed() > Duration::from_secs(60);
            drop(cache);
            if stale {
                if let Err(e) = self.refresh_jwks().await {
                    tracing::warn!(error = %e, "JWKS refresh failed");
                }
            }
        }

        let cache = self.jwks.read().await;
        if let Some(ref keyset) = cache.keyset {
            if let Some(result) = self.try_validate_with_keyset(token, kid, alg, keyset) {
                return result.map(into_minimal);
            }
        }

        Err(AuthError::InvalidToken(
            "no matching key found in JWKS".to_string(),
        ))
    }
}

fn into_minimal(body: JwtBody) -> MinimalClaims {
    MinimalClaims {
        sub: body.sub,
        exp: body.exp,
        extra: body.extra,
    }
}

/// Parse algorithm names from config strings.
///
/// Returns [`AuthError::InvalidToken`] for unrecognized algorithms — failing
/// loudly at config-parse time is preferable to silently accepting an
/// unsupported algorithm and rejecting every token at runtime.
pub fn parse_algorithms(names: &[String]) -> Result<Vec<Algorithm>, AuthError> {
    names
        .iter()
        .map(|name| {
            Algorithm::from_str(name)
                .map_err(|_| AuthError::InvalidToken(format!("unknown JWT algorithm: {name}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_algorithms_recognizes_common_names() {
        let parsed = parse_algorithms(&[
            "RS256".to_string(),
            "ES256".to_string(),
            "HS256".to_string(),
        ])
        .expect("recognized");
        assert_eq!(
            parsed,
            vec![Algorithm::RS256, Algorithm::ES256, Algorithm::HS256]
        );
    }

    #[test]
    fn parse_algorithms_rejects_unknown_names() {
        let err = parse_algorithms(&["banana".to_string()]).expect_err("rejected");
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    #[test]
    fn into_minimal_forwards_extra_claims() {
        let mut extra = HashMap::new();
        extra.insert(
            "groups".to_string(),
            Value::Array(vec![Value::String("admin".into())]),
        );
        let body = JwtBody {
            sub: Some("user-1".into()),
            exp: Some(123),
            extra,
        };
        let minimal = into_minimal(body);
        assert_eq!(minimal.sub.as_deref(), Some("user-1"));
        assert_eq!(minimal.exp, Some(123));
        assert!(minimal.extra.contains_key("groups"));
    }
}
