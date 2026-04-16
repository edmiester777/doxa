//! Shared auth state injected into the auth pipeline.
//!
//! Historically this module also held the closure-based
//! `auth_middleware` function consumed by
//! `axum::middleware::from_fn_with_state`. That function has been
//! lifted into [`crate::layer::AuthLayer`] as a proper tower
//! [`Layer`](tower::Layer) so it can implement
//! [`doxa::DocumentedLayer`] and have its OpenAPI contract
//! inferred at router-build time. The pipeline body is unchanged.

use std::sync::Arc;

#[cfg(feature = "audit")]
use doxa_audit::AuditLogger;
use doxa_policy::Policy;

use crate::claims::Claims;
use crate::provider::{ClaimResolver, TokenValidator};

/// Shared auth state held by [`crate::layer::AuthLayer`].
///
/// Generic over:
///
/// - `S` — the session output type produced by the configured
///   [`Policy<S>`](doxa_policy::Policy).
/// - `C` — the consumer-defined claim type implementing [`Claims`].
///
/// Built once at startup and cloned per request via [`Arc`].
pub struct AuthState<S: Send + Sync + 'static, C: Claims> {
    /// Stage 1 — credential validation.
    pub validator: Arc<dyn TokenValidator>,
    /// Stage 2 — claim enrichment into the consumer's `C` type.
    pub resolver: Arc<dyn ClaimResolver<C>>,
    /// Cedar (or other) policy engine resolving roles into a session
    /// output of type `S`.
    pub policy: Box<dyn Policy<S>>,
    /// Audit logger. `None` when auditing is disabled. Present only
    /// when the `audit` feature is enabled.
    #[cfg(feature = "audit")]
    pub audit: Option<AuditLogger>,
}
