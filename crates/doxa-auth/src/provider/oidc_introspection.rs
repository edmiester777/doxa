//! RFC 7662 token introspection against any endpoint (Keycloak, Auth0, …), with claim
//! names from a [`ClaimMapping`] and an optional per-token result cache.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use cached::stores::TimedSizedCache;
use cached::Cached;
use serde_json::Value;
use sha2::{Digest, Sha256};

use doxa_policy::AuthError;
use doxa_protected::ProtectedString;

use super::{ClaimResolver, MinimalClaims};
use crate::claims::{Claims, OidcClaims};
use crate::config::ClaimMapping;

/// How long an introspection result is reused unless configured otherwise.
pub const DEFAULT_INTROSPECTION_CACHE_TTL: Duration = Duration::from_secs(300);

/// Tokens whose introspection results are held at once.
pub const DEFAULT_INTROSPECTION_CACHE_CAPACITY: usize = 1024;

/// Constructor parameters for [`OidcIntrospector`].
#[derive(Debug, Clone)]
pub struct OidcIntrospectionOptions {
    /// Fully-qualified introspection endpoint URL.
    pub introspection_url: String,
    /// OAuth client id authorized to introspect.
    pub client_id: String,
    /// OAuth client secret used by the introspecting client.
    pub client_secret: ProtectedString,
    /// Names of the claims to read from the introspection response.
    pub claims: ClaimMapping,
    /// How long a result is reused, so a revocation can take this long to apply. Zero disables it.
    pub cache_ttl: Duration,
}

/// RFC 7662 introspection resolver. Results, inactive ones included, are cached per token for
/// `cache_ttl` and never past the token's `exp`; concurrent first lookups each introspect.
#[derive(Clone)]
pub struct OidcIntrospector {
    introspection_url: String,
    client_id: String,
    client_secret: ProtectedString,
    claims: ClaimMapping,
    client: reqwest::Client,
    cache: Option<ClaimCache>,
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
            cache: (!opts.cache_ttl.is_zero()).then(|| ClaimCache::new(opts.cache_ttl)),
        }
    }

    /// The endpoint's verdict and the token's `exp`, if it sent one.
    async fn introspect(&self, token: &str) -> Result<(Lookup, Option<u64>), AuthError> {
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
            .map_err(|e| AuthError::IntrospectionFailed(format!("HTTP request failed: {e}")))?
            .error_for_status()
            .map_err(|e| {
                AuthError::IntrospectionFailed(format!("introspection endpoint returned {e}"))
            })?;

        let body: HashMap<String, Value> = response
            .json()
            .await
            .map_err(|e| AuthError::IntrospectionFailed(format!("response parse failed: {e}")))?;

        let exp = body
            .get("exp")
            .and_then(|v| v.as_u64().or_else(|| v.as_f64().map(|f| f as u64)));
        Ok((parse_introspection_response(&body, &self.claims), exp))
    }
}

#[async_trait]
impl<C> ClaimResolver<C> for OidcIntrospector
where
    C: Claims + TryFrom<OidcClaims>,
    C::Error: Into<AuthError>,
{
    #[tracing::instrument(skip_all, name = "token_introspect")]
    async fn resolve(&self, token: &str, minimal: &MinimalClaims) -> Result<C, AuthError> {
        let now = unix_now();
        let key = ClaimCache::key(token);
        let hit = self.cache.as_ref().and_then(|cache| cache.get(&key, now));
        let lookup = match hit {
            Some(lookup) => lookup,
            None => {
                let (lookup, exp) = self.introspect(token).await?;
                if let Some(cache) = &self.cache {
                    let exp = [exp, minimal.exp].into_iter().flatten().min();
                    cache.insert(key, lookup.clone(), exp, now);
                }
                lookup
            }
        };
        let claims = lookup.map_err(|Inactive| AuthError::TokenInactive)?;
        C::try_from(claims).map_err(Into::into)
    }
}

/// The endpoint reported the token inactive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Inactive;

type Lookup = Result<OidcClaims, Inactive>;

/// Map a parsed introspection response into [`OidcClaims`]; a missing `active` reads as inactive.
fn parse_introspection_response(body: &HashMap<String, Value>, mapping: &ClaimMapping) -> Lookup {
    if !body.get("active").and_then(Value::as_bool).unwrap_or(false) {
        return Err(Inactive);
    }
    let mapped = mapping.read(body);
    Ok(OidcClaims {
        sub: mapped.sub.unwrap_or_default(),
        scope: mapped.scope,
        roles: mapped.roles,
    })
}

/// Seconds since the epoch; a clock set before it reads as `0`.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[derive(Clone)]
struct Entry {
    lookup: Lookup,
    /// Unix seconds.
    expires_at: u64,
}

/// Introspection results keyed by the token's SHA-256, so no token is held.
#[derive(Clone)]
struct ClaimCache {
    inner: Arc<Mutex<TimedSizedCache<[u8; 32], Entry>>>,
    ttl_secs: u64,
}

impl ClaimCache {
    fn new(ttl: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TimedSizedCache::with_size_and_lifespan(
                DEFAULT_INTROSPECTION_CACHE_CAPACITY,
                ttl,
            ))),
            ttl_secs: ttl.as_secs(),
        }
    }

    fn key(token: &str) -> [u8; 32] {
        Sha256::digest(token.as_bytes()).into()
    }

    fn lock(&self) -> MutexGuard<'_, TimedSizedCache<[u8; 32], Entry>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn get(&self, key: &[u8; 32], now: u64) -> Option<Lookup> {
        let mut cache = self.lock();
        let fresh = cache
            .cache_get(key)
            .map(|entry| (entry.expires_at > now).then(|| entry.lookup.clone()))?;
        if fresh.is_none() {
            cache.cache_remove(key);
        }
        fresh
    }

    fn insert(&self, key: [u8; 32], lookup: Lookup, exp: Option<u64>, now: u64) {
        let ttl_end = now.saturating_add(self.ttl_secs);
        let expires_at = exp.map_or(ttl_end, |exp| exp.min(ttl_end));
        if expires_at > now {
            self.lock().cache_set(key, Entry { lookup, expires_at });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body_from(value: Value) -> HashMap<String, Value> {
        serde_json::from_value(value).expect("object")
    }

    fn claims(sub: &str) -> OidcClaims {
        OidcClaims {
            sub: sub.into(),
            ..OidcClaims::default()
        }
    }

    #[test]
    fn parses_keycloak_shaped_response() {
        let body = body_from(json!({
            "active": true,
            "sub": "user-keycloak",
            "tenant_id": "acme",
            "groups": ["admin", "analyst"]
        }));
        let mapping = ClaimMapping {
            roles: "groups".into(),
            ..ClaimMapping::default()
        };
        let claims = parse_introspection_response(&body, &mapping).expect("parsed");
        assert_eq!(claims.sub, "user-keycloak");
        assert_eq!(claims.scope.as_deref(), Some("acme"));
        assert_eq!(claims.roles, vec!["admin", "analyst"]);
    }

    #[test]
    fn active_false_or_missing_is_inactive() {
        for body in [json!({ "active": false }), json!({ "sub": "user-1" })] {
            let lookup = parse_introspection_response(&body_from(body), &ClaimMapping::default());
            assert_eq!(lookup.unwrap_err(), Inactive);
        }
    }

    #[test]
    fn a_missing_sub_defaults_to_empty() {
        let body = body_from(json!({ "active": true }));
        let claims = parse_introspection_response(&body, &ClaimMapping::default()).expect("parsed");
        assert_eq!(claims.sub, "");
    }

    #[test]
    fn a_cached_claim_and_a_cached_inactive_are_hits() {
        let cache = ClaimCache::new(Duration::from_secs(300));
        cache.insert(ClaimCache::key("a"), Ok(claims("a")), None, 1_000);
        cache.insert(ClaimCache::key("b"), Err(Inactive), None, 1_000);
        let hit = cache.get(&ClaimCache::key("a"), 1_001).expect("hit");
        assert_eq!(hit.expect("active").sub, "a");
        assert!(matches!(
            cache.get(&ClaimCache::key("b"), 1_001),
            Some(Err(Inactive))
        ));
        assert!(cache.get(&ClaimCache::key("c"), 1_001).is_none());
    }

    #[test]
    fn an_entry_expires_at_the_tokens_exp_before_the_ttl() {
        let cache = ClaimCache::new(Duration::from_secs(300));
        let key = ClaimCache::key("t");
        cache.insert(key, Ok(claims("t")), Some(1_010), 1_000);
        assert!(cache.get(&key, 1_009).is_some());
        assert!(cache.get(&key, 1_010).is_none());
        assert_eq!(cache.lock().cache_size(), 0, "an expired hit is removed");
    }

    #[test]
    fn an_already_expired_token_is_not_stored() {
        let cache = ClaimCache::new(Duration::from_secs(300));
        cache.insert(ClaimCache::key("t"), Ok(claims("t")), Some(1_000), 1_000);
        assert_eq!(cache.lock().cache_size(), 0);
    }

    #[test]
    fn a_zero_ttl_builds_no_cache() {
        let introspector = OidcIntrospector::new(OidcIntrospectionOptions {
            introspection_url: String::new(),
            client_id: String::new(),
            client_secret: ProtectedString::from(String::new()),
            claims: ClaimMapping::default(),
            cache_ttl: Duration::ZERO,
        });
        assert!(introspector.cache.is_none());
    }

    #[cfg(feature = "axum")]
    mod endpoint {
        use axum::extract::State;
        use axum::http::StatusCode;
        use axum::response::{IntoResponse, Response};
        use axum::routing::post;
        use axum::{Form, Json, Router};

        use super::*;

        type Hits = Arc<Mutex<HashMap<String, usize>>>;

        /// Answers by token: `good`, `revoked`, `boom` (500 with JSON), `unauth` (401), `garbage`.
        async fn idp(
            State(hits): State<Hits>,
            Form(form): Form<HashMap<String, String>>,
        ) -> Response {
            let token = form.get("token").cloned().unwrap_or_default();
            *hits.lock().unwrap().entry(token.clone()).or_default() += 1;
            match token.as_str() {
                "good" => {
                    Json(json!({ "active": true, "sub": "u", "tenant_id": "acme" })).into_response()
                }
                "revoked" => Json(json!({ "active": false })).into_response(),
                "boom" => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "x" })),
                )
                    .into_response(),
                "unauth" => (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "error": "invalid_client" })),
                )
                    .into_response(),
                _ => "not json".into_response(),
            }
        }

        async fn introspector() -> (OidcIntrospector, Hits) {
            let hits = Hits::default();
            let app = Router::new()
                .route("/introspect", post(idp))
                .with_state(hits.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/introspect", listener.local_addr().unwrap());
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let introspector = OidcIntrospector::new(OidcIntrospectionOptions {
                introspection_url: url,
                client_id: "api".into(),
                client_secret: ProtectedString::from("secret".to_string()),
                claims: ClaimMapping::default(),
                cache_ttl: DEFAULT_INTROSPECTION_CACHE_TTL,
            });
            (introspector, hits)
        }

        async fn twice(
            introspector: &OidcIntrospector,
            token: &str,
        ) -> Result<OidcClaims, AuthError> {
            let minimal = MinimalClaims::default();
            let _: Result<OidcClaims, _> = introspector.resolve(token, &minimal).await;
            introspector.resolve(token, &minimal).await
        }

        fn hits(hits: &Hits, token: &str) -> usize {
            hits.lock().unwrap().get(token).copied().unwrap_or(0)
        }

        #[tokio::test]
        async fn an_active_token_is_introspected_once() {
            let (introspector, counts) = introspector().await;
            let claims = twice(&introspector, "good").await.expect("active");
            assert_eq!(claims.scope.as_deref(), Some("acme"));
            assert_eq!(hits(&counts, "good"), 1);
        }

        #[tokio::test]
        async fn an_inactive_token_is_introspected_once() {
            let (introspector, counts) = introspector().await;
            let err = twice(&introspector, "revoked").await.expect_err("inactive");
            assert!(matches!(err, AuthError::TokenInactive));
            assert_eq!(hits(&counts, "revoked"), 1);
        }

        #[tokio::test]
        async fn endpoint_failures_are_never_cached() {
            let (introspector, counts) = introspector().await;
            for token in ["boom", "unauth", "garbage"] {
                let err = twice(&introspector, token).await.expect_err(token);
                assert!(
                    matches!(err, AuthError::IntrospectionFailed(_)),
                    "{token}: {err:?}"
                );
                assert_eq!(hits(&counts, token), 2, "{token} retried");
            }
        }
    }
}
