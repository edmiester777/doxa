//! [`AuthLayer`] — proper tower [`Layer`] implementation of the auth
//! pipeline previously expressed as `from_fn_with_state(auth_middleware)`.
//!
//! The pipeline body extracts `Authorization: Bearer`, validates, resolves
//! claims into the consumer-defined `C: Claims` type, runs the policy
//! engine, injects [`AuthContext<S, C>`] into request extensions, and
//! forwards to the inner service.
//!
//! Pairs with [`crate::openapi::auth_contribution`] — the
//! [`doxa::DocumentedLayer`] impl just delegates.

use std::borrow::Cow;
use std::convert::Infallible;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::Request;
use axum::response::{IntoResponse, Response};
use tower::{Layer, Service};

use doxa_policy::{AuthError, CapabilityChecker};

use crate::claims::Claims;
use crate::context::{AuthContext, CapabilityContext};
use crate::middleware::AuthState;

// The audit wiring is feature-gated. When the `audit` feature is
// enabled, `audit_support::Session` is a real thin wrapper around
// [`doxa_audit::AuditEventBuilder`]. When it's disabled, the type
// collapses to a zero-sized no-op so the main pipeline body stays free
// of `#[cfg]` attributes.
use audit_support::AuditSession;

#[cfg(feature = "audit")]
mod audit_support {
    use axum::body::Body;
    use axum::http::Request;
    use doxa_audit::{AuditEventBuilder, EventType, Outcome};

    use crate::claims::Claims;
    use crate::middleware::AuthState;

    /// Per-request audit scope. Wraps an optional
    /// [`AuditEventBuilder`] that is `Some` when either:
    /// - [`AuditLayer`](doxa_audit::AuditLayer) already injected a
    ///   builder into request extensions (preferred), or
    /// - The [`AuthState`] was configured with a logger (fallback for
    ///   backward compatibility when `AuditLayer` is not in the stack).
    pub struct AuditSession(Option<AuditEventBuilder>);

    impl AuditSession {
        pub fn start<S, C>(auth: &AuthState<S, C>, request: &Request<Body>) -> Self
        where
            S: Send + Sync + 'static,
            C: Claims,
        {
            // Prefer the builder injected by AuditLayer — it shares
            // state with the layer's auto-emit handle.
            if let Some(existing) = request.extensions().get::<AuditEventBuilder>() {
                return Self(Some(existing.clone()));
            }

            // Fallback: create from AuthState's logger (backward compat
            // when AuditLayer is not in the middleware stack).
            Self(auth.audit.as_ref().map(|logger| {
                let builder = AuditEventBuilder::new(logger.clone());
                builder.set_request_metadata(request.headers());
                builder
            }))
        }

        /// Emit a terminal auth-failure event if the session is active.
        pub fn emit_failure(&mut self, action: &str, error: &str) {
            if let Some(builder) = self.0.take() {
                builder.set_event(EventType::AuthFailure, action);
                builder.set_outcome(Outcome::Denied);
                builder.set_error(error);
                builder.emit();
            }
        }

        /// Stamp resolved actor info onto the pending builder and hand
        /// it back so the caller can drop it into request extensions
        /// for handler-layer enrichment.
        pub fn take_with_actor<C: Claims>(&mut self, claims: &C) -> Option<AuditEventBuilder> {
            let builder = self.0.take()?;
            builder.set_actor(Some(claims.sub()), claims.roles(), claims.audit_attrs());
            Some(builder)
        }
    }
}

#[cfg(not(feature = "audit"))]
mod audit_support {
    use axum::body::Body;
    use axum::http::Request;

    use crate::claims::Claims;
    use crate::middleware::AuthState;

    /// No-op audit session used when the `audit` feature is disabled.
    /// Every method is a constant-folded nothing so the pipeline
    /// body stays structurally identical across feature flavors.
    pub struct AuditSession;

    impl AuditSession {
        pub fn start<S, C>(_: &AuthState<S, C>, _: &Request<Body>) -> Self
        where
            S: Send + Sync + 'static,
            C: Claims,
        {
            Self
        }

        pub fn emit_failure(&mut self, _action: &str, _error: &str) {}

        pub fn take_with_actor<C: Claims>(&mut self, _claims: &C) -> Option<()> {
            None
        }
    }
}

/// Tower [`Layer`] that runs the auth pipeline (validate → resolve →
/// policy) and injects an [`AuthContext<S, C>`](crate::AuthContext) into
/// request extensions for downstream handlers. Equivalent to the
/// previous `from_fn_with_state(auth_middleware)` form but with a
/// nameable type so it can implement
/// [`doxa::DocumentedLayer`].
///
/// Construct via [`AuthLayer::new`]; clone is cheap (just an
/// `Arc::clone` of the shared [`AuthState`]).
pub struct AuthLayer<S: Clone + Send + Sync + 'static, C: Claims> {
    state: Arc<AuthState<S, C>>,
    scheme_name: Cow<'static, str>,
    /// Optional capability checker (typically a
    /// [`PolicyRouter`](doxa_policy::PolicyRouter)) inserted into request
    /// extensions so ship-ready extractors like `Require<M>` can enforce
    /// per-route capabilities without being generic over the consumer's
    /// [`PolicyExtension`](doxa_policy::PolicyExtension) type.
    checker: Option<Arc<dyn CapabilityChecker>>,
}

impl<S: Clone + Send + Sync + 'static, C: Claims> Clone for AuthLayer<S, C> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            scheme_name: self.scheme_name.clone(),
            checker: self.checker.clone(),
        }
    }
}

impl<S: Clone + Send + Sync + 'static, C: Claims> AuthLayer<S, C> {
    /// Build a new [`AuthLayer`] sharing the supplied [`AuthState`]. The
    /// OpenAPI security scheme name defaults to `"bearer"`; override via
    /// [`AuthLayer::with_scheme_name`] if the consumer has registered the
    /// scheme under a different name on their [`doxa::ApiDocBuilder`].
    pub fn new(state: Arc<AuthState<S, C>>) -> Self {
        Self {
            state,
            scheme_name: Cow::Borrowed("bearer"),
            checker: None,
        }
    }

    /// Override the OpenAPI security scheme name this layer contributes.
    pub fn with_scheme_name(mut self, scheme_name: impl Into<Cow<'static, str>>) -> Self {
        self.scheme_name = scheme_name.into();
        self
    }

    /// Attach a [`CapabilityChecker`] (typically an
    /// `Arc<PolicyRouter<E>>`) so that `Require<M>`-style extractors can
    /// enforce capabilities without consumer-defined state plumbing.
    ///
    /// The layer inserts the checker into request extensions as
    /// `Arc<dyn CapabilityChecker>` after the auth pipeline resolves
    /// successfully. Extractors that need it read through this type-
    /// erased handle; none of them need to be generic over the
    /// consumer's [`PolicyExtension`](doxa_policy::PolicyExtension).
    pub fn with_capability_checker(mut self, checker: Arc<dyn CapabilityChecker>) -> Self {
        self.checker = Some(checker);
        self
    }

    /// The OpenAPI security scheme name this layer contributes.
    pub fn scheme_name(&self) -> &str {
        self.scheme_name.as_ref()
    }
}

impl<S, C, Inner> Layer<Inner> for AuthLayer<S, C>
where
    S: Clone + Send + Sync + 'static,
    C: Claims,
    Inner: Service<Request<Body>, Response = Response, Error = Infallible> + Clone + Send + 'static,
    Inner::Future: Send + 'static,
{
    type Service = AuthService<S, C, Inner>;
    fn layer(&self, inner: Inner) -> Self::Service {
        AuthService {
            state: Arc::clone(&self.state),
            checker: self.checker.clone(),
            inner,
            _claims: PhantomData,
        }
    }
}

impl<S: Clone + Send + Sync + 'static, C: Claims> doxa::DocumentedLayer for AuthLayer<S, C> {
    fn contribution(&self) -> doxa::LayerContribution {
        crate::openapi::auth_contribution(self.scheme_name.clone().into_owned())
    }
}

/// Service produced by [`AuthLayer`]. Runs the auth pipeline on
/// every request and forwards to `inner` on success; on failure,
/// renders the [`AuthError`] as an HTTP response and short-circuits.
pub struct AuthService<S: Clone + Send + Sync + 'static, C: Claims, Inner> {
    state: Arc<AuthState<S, C>>,
    checker: Option<Arc<dyn CapabilityChecker>>,
    inner: Inner,
    _claims: PhantomData<fn() -> C>,
}

impl<S, C, Inner> Clone for AuthService<S, C, Inner>
where
    S: Clone + Send + Sync + 'static,
    C: Claims,
    Inner: Clone,
{
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            checker: self.checker.clone(),
            inner: self.inner.clone(),
            _claims: PhantomData,
        }
    }
}

impl<S, C, Inner> Service<Request<Body>> for AuthService<S, C, Inner>
where
    S: Clone + Send + Sync + 'static,
    C: Claims,
    Inner: Service<Request<Body>, Response = Response, Error = Infallible> + Clone + Send + 'static,
    Inner::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let state = Arc::clone(&self.state);
        let checker = self.checker.clone();
        // Canonical clone-and-swap pattern from the tower::Service
        // docs: poll_ready was called on `self.inner`, so we must
        // call `inner` (the readied one) inside the future and leave
        // a fresh clone in `self` for any subsequent poll_ready cycle.
        let inner_clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner_clone);
        Box::pin(async move {
            match run_auth_pipeline::<S, C>(&state, checker, req).await {
                Ok(req) => inner.call(req).await,
                Err(err) => Ok(err.into_response()),
            }
        })
    }
}

/// Body of the auth pipeline. Returns the modified [`Request<Body>`] (with
/// [`AuthContext`] injected into extensions) on success; the caller is
/// responsible for invoking the inner service.
#[tracing::instrument(skip_all, name = "auth")]
async fn run_auth_pipeline<S, C>(
    auth: &AuthState<S, C>,
    checker: Option<Arc<dyn CapabilityChecker>>,
    mut request: Request<Body>,
) -> Result<Request<Body>, AuthError>
where
    S: Clone + Send + Sync + 'static,
    C: Claims,
{
    // Start the audit session. Collapses to a no-op when the `audit`
    // feature is off — the main pipeline body never branches on the
    // feature flag.
    let mut audit = AuditSession::start(auth, &request);

    // 1. Extract Bearer token from Authorization header
    let token = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            tracing::warn!("missing or malformed Authorization header");
            audit.emit_failure(
                "missing_credentials",
                "Missing or malformed Authorization header",
            );
            AuthError::MissingCredentials
        })?;

    // 2. Stage 1 — cryptographic credential validation.
    let minimal = auth.validator.validate(token).await.inspect_err(|e| {
        tracing::warn!(error = %e, "credential validation failed");
        audit.emit_failure("invalid_token", &e.to_string());
    })?;

    // 3. Stage 2 — enrich into consumer-defined claims.
    let claims: C = auth
        .resolver
        .resolve(token, &minimal)
        .await
        .inspect_err(|e| {
            tracing::warn!(error = %e, "claim resolution failed");
            let action = match e {
                AuthError::TokenInactive => "token_inactive",
                _ => "claim_resolution_failed",
            };
            audit.emit_failure(action, &e.to_string());
        })?;

    // Record scope on the parent http_request span for log correlation.
    if let Some(scope) = claims.scope() {
        tracing::Span::current().record("company_id", scope);
    }

    // 4. Resolve RBAC: roles → session output via the configured policy. Tenant
    //    scoping (forced filters, etc.) is the PolicyExtension's responsibility —
    //    not the middleware's.
    let session = auth
        .policy
        .resolve(claims.scope(), claims.roles())
        .await
        .inspect_err(|e| {
            tracing::warn!(error = %e, "policy resolution failed");
            audit.emit_failure("policy_resolution_failed", &e.to_string());
        })?;

    // Stamp actor info onto the builder, pass it downstream via
    // extensions. No-op when the `audit` feature is off.
    #[cfg(feature = "audit")]
    if let Some(builder) = audit.take_with_actor(&claims) {
        request.extensions_mut().insert(builder);
    }
    #[cfg(not(feature = "audit"))]
    let _ = audit.take_with_actor(&claims);

    // 5. Insert AuthContext into request extensions so handlers and
    //    permission extractors can reach it.
    //
    //    Also stamp a type-erased `CapabilityContext` so the ship-ready
    //    `Require<M>` extractor can read tenant + roles without being
    //    generic over the consumer's `S` / `C`. The typed
    //    `AuthContext<S, C>` stays available for handlers that want
    //    claim-level access.
    let cap_ctx = CapabilityContext {
        tenant_id: claims.scope().map(str::to_owned),
        roles: claims.roles().to_vec(),
    };
    request.extensions_mut().insert(cap_ctx);
    if let Some(checker) = checker {
        request.extensions_mut().insert(checker);
    }
    request.extensions_mut().insert(AuthContext {
        claims,
        session,
        is_admin: false,
    });

    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::claims::OidcClaims;
    use crate::provider::{ClaimResolver, MinimalClaims, TokenValidator};
    use doxa_policy::Policy;

    /// Stub validator that accepts a fixed token and rejects everything
    /// else with `InvalidToken`.
    struct StubValidator {
        accept: &'static str,
    }
    #[async_trait]
    impl TokenValidator for StubValidator {
        async fn validate(&self, token: &str) -> Result<MinimalClaims, AuthError> {
            if token == self.accept {
                Ok(MinimalClaims {
                    sub: Some("test-sub".to_string()),
                    exp: None,
                    extra: Default::default(),
                })
            } else {
                Err(AuthError::InvalidToken("bad token".to_string()))
            }
        }
    }

    /// Stub resolver that returns a fixed OidcClaims.
    struct StubResolver;
    #[async_trait]
    impl ClaimResolver<OidcClaims> for StubResolver {
        async fn resolve(
            &self,
            _token: &str,
            _minimal: &MinimalClaims,
        ) -> Result<OidcClaims, AuthError> {
            Ok(OidcClaims {
                sub: "test-sub".to_string(),
                scope: Some("tenant-1".to_string()),
                roles: vec!["reader".to_string()],
            })
        }
    }

    /// Stub policy that returns the unit type as the session output.
    struct StubPolicy;
    #[async_trait]
    impl Policy<()> for StubPolicy {
        async fn resolve(&self, _scope: Option<&str>, _roles: &[String]) -> Result<(), AuthError> {
            Ok(())
        }
    }

    fn make_state(accept_token: &'static str) -> Arc<AuthState<(), OidcClaims>> {
        Arc::new(AuthState {
            validator: Arc::new(StubValidator {
                accept: accept_token,
            }),
            resolver: Arc::new(StubResolver),
            policy: Box::new(StubPolicy),
            #[cfg(feature = "audit")]
            audit: None,
        })
    }

    /// Build the layered service: AuthLayer → noop inner that
    /// returns 200 and asserts AuthContext is present.
    fn build_service<F>(
        state: Arc<AuthState<(), OidcClaims>>,
        inner: F,
    ) -> impl Service<Request<Body>, Response = Response, Error = Infallible> + Clone
    where
        F: Fn(Request<Body>) -> Response + Clone + Send + 'static,
    {
        let inner = tower::service_fn(move |req: Request<Body>| {
            let resp = inner(req);
            async move { Ok::<_, Infallible>(resp) }
        });
        AuthLayer::new(state).layer(inner)
    }

    #[tokio::test]
    async fn auth_layer_returns_401_when_authorization_header_missing() {
        let state = make_state("good");
        let svc = build_service(state, |_req| {
            Response::builder().body(Body::empty()).unwrap()
        });
        let req = Request::builder().uri("/x").body(Body::empty()).unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_layer_returns_401_when_token_validation_fails() {
        let state = make_state("good");
        let svc = build_service(state, |_req| {
            Response::builder().body(Body::empty()).unwrap()
        });
        let req = Request::builder()
            .uri("/x")
            .header("authorization", "Bearer wrong")
            .body(Body::empty())
            .unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_layer_injects_auth_context_on_success() {
        let state = make_state("good");
        let svc = build_service(state, |req| {
            // Assert AuthContext is in extensions and carries the
            // expected claims.
            let ctx = req
                .extensions()
                .get::<AuthContext<(), OidcClaims>>()
                .expect("AuthContext present");
            assert_eq!(ctx.claims.sub, "test-sub");
            assert_eq!(ctx.claims.scope.as_deref(), Some("tenant-1"));
            assert_eq!(ctx.claims.roles, vec!["reader".to_string()]);
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from("ok"))
                .unwrap()
        });
        let req = Request::builder()
            .uri("/x")
            .header("authorization", "Bearer good")
            .body(Body::empty())
            .unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"ok");
    }

    #[tokio::test]
    async fn auth_layer_implements_documented_layer_with_expected_contribution() {
        use doxa::DocumentedLayer;
        let layer = AuthLayer::new(make_state("good"));
        let c = layer.contribution();
        assert!(!c.is_empty());
    }
}
