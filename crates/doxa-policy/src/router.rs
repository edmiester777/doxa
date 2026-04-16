//! Centralized policy enforcement point (PEP) for slow-path checks.
//!
//! [`PolicyRouter`] is the single place where handlers ask "is this caller
//! allowed to perform `action` on `resource`?" against a Cedar policy set
//! loaded via a [`PolicyStore`](crate::store::PolicyStore). It is
//! intentionally minimal: it knows nothing about session caches, resource
//! taxonomies, or fast-path optimizations. Consumers that need fast-path
//! evaluation against a pre-resolved session should wrap the router in a
//! domain-specific enforcer that consults the session first and falls
//! through to [`PolicyRouter::check`] for cache misses.
//!
//! The action name and resource UID are passed as raw Cedar primitives, so
//! the router does not constrain consumers to any particular action vocabulary
//! or resource hierarchy.
//!
//! Router instances own their own [`TenantStoreCache`]; call
//! [`PolicyRouter::with_cache`] to share one with a
//! [`CedarPolicy`](crate::policy::cedar::CedarPolicy) so both see the same
//! cache entries (and invalidations).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use crate::capability::{Capability, CapabilityChecker};
use crate::cedar_core::{CedarEvaluator, TenantStoreCache};
use crate::error::AuthError;
use crate::extension::PolicyExtension;
use crate::store::SharedPolicyStore;

/// Outcome of a [`PolicyRouter::check`] call.
#[derive(Debug, Clone)]
pub struct AccessDecision {
    /// Whether the action is permitted.
    pub allowed: bool,
    /// Human-readable rationale, populated for denials so callers can
    /// surface a useful error message and emit it to the audit log.
    pub reason: Option<String>,
}

impl AccessDecision {
    /// An unconditional allow with no rationale.
    pub fn allow() -> Self {
        Self {
            allowed: true,
            reason: None,
        }
    }

    /// A deny with a human-readable reason.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            reason: Some(reason.into()),
        }
    }

    /// Convenience: convert a denial into [`AuthError::Forbidden`] so handlers
    /// can use the `?` operator without manual mapping.
    pub fn into_result(self) -> Result<(), AuthError> {
        if self.allowed {
            Ok(())
        } else {
            Err(AuthError::Forbidden)
        }
    }
}

/// Slow-path Cedar enforcement point.
///
/// Construct once at startup with the same
/// [`PolicyStore`](crate::store::PolicyStore) and [`PolicyExtension`] used by
/// [`CedarPolicy`](crate::policy::cedar::CedarPolicy). Cheap to clone — the
/// inner state is just an [`Arc`]-able handle.
///
/// Each call to [`check`](Self::check) loads the tenant's Cedar artifacts
/// (cached via the router's [`TenantStoreCache`]) and performs a single
/// `is_authorized_partial` evaluation against the supplied action and
/// resource UID.
pub struct PolicyRouter<E: PolicyExtension> {
    store: SharedPolicyStore,
    extension: Arc<E>,
    cache: TenantStoreCache,
}

impl<E: PolicyExtension> Clone for PolicyRouter<E> {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            extension: Arc::clone(&self.extension),
            cache: self.cache.clone(),
        }
    }
}

impl<E: PolicyExtension + 'static> PolicyRouter<E> {
    /// Build a new router with a fresh tenant-store cache at the default
    /// TTL.
    ///
    /// The extension is wrapped in [`Arc`] so the router can be cloned
    /// without re-instantiating it.
    pub fn new(store: SharedPolicyStore, extension: E) -> Self {
        Self {
            store,
            extension: Arc::new(extension),
            cache: TenantStoreCache::default(),
        }
    }

    /// Override the tenant-store cache TTL.
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache = TenantStoreCache::with_ttl(ttl);
        self
    }

    /// Attach an externally-owned tenant-store cache. Use this to share
    /// one cache between a
    /// [`CedarPolicy`](crate::policy::cedar::CedarPolicy) and this router.
    pub fn with_cache(mut self, cache: TenantStoreCache) -> Self {
        self.cache = cache;
        self
    }

    /// Current tenant-store cache TTL.
    pub fn cache_ttl(&self) -> Duration {
        self.cache.ttl()
    }

    /// Handle to the tenant-store cache.
    pub fn cache(&self) -> TenantStoreCache {
        self.cache.clone()
    }

    /// Check whether `roles` may perform `action` on `resource` for the
    /// given tenant.
    ///
    /// Loads the tenant's policy set via the
    /// [`PolicyStore`](crate::store::PolicyStore) (cache hit on the warm
    /// path) and runs a single `is_authorized` query against it. The action
    /// name is the raw Cedar action identifier and the resource is a
    /// fully-qualified [`cedar_policy::EntityUid`] — consumers are
    /// responsible for constructing both via whatever typed helpers their
    /// domain prefers.
    #[tracing::instrument(skip_all, fields(tenant_id, action))]
    pub async fn check(
        &self,
        tenant_id: &str,
        roles: &[String],
        action: &str,
        resource: cedar_policy::EntityUid,
    ) -> Result<AccessDecision, AuthError> {
        if tenant_id.is_empty() {
            return Ok(AccessDecision::deny(
                "no tenant context — cannot evaluate action",
            ));
        }

        let store = self.cache.get_or_load(&self.store, tenant_id).await?;
        let evaluator = CedarEvaluator::new(&store, tenant_id, roles, self.extension.as_ref())?;
        let allowed = evaluator.check_action(action, resource.clone())?;

        Ok(AccessDecision {
            allowed,
            reason: (!allowed).then(|| format!("policy denied {action} on {resource}")),
        })
    }

    /// Evaluate a single [`Capability`] against the tenant's policies.
    ///
    /// Returns `Ok(true)` only if every underlying [`CapabilityCheck`]
    /// resolves to `Allow`. Cedar UID construction is delegated to
    /// [`PolicyExtension::build_resource_uid`] so each consumer's UID
    /// hierarchy is honored — an `(action, entity_type, entity_id)`
    /// triple in the catalog produces the same UID a hand-rolled
    /// [`check`](Self::check) call would.
    ///
    /// [`CapabilityCheck`]: crate::capability::CapabilityCheck
    #[tracing::instrument(skip_all, fields(tenant_id, capability = cap.name))]
    pub async fn check_capability(
        &self,
        tenant_id: &str,
        roles: &[String],
        cap: &Capability,
    ) -> Result<bool, AuthError> {
        for check in cap.checks {
            let resource =
                self.extension
                    .build_resource_uid(tenant_id, check.entity_type, check.entity_id)?;
            let decision = self.check(tenant_id, roles, check.action, resource).await?;
            if !decision.allowed {
                return Ok(false);
            }
        }
        Ok(true)
    }

    // `check_capability` is also the core of the type-erased
    // `CapabilityChecker` impl below — the impl just delegates so
    // external callers carrying `Arc<dyn CapabilityChecker>` go through
    // the same evaluator path without touching the `E` type parameter.

    /// Evaluate a slice of capabilities and return a stable
    /// `name → allowed` map.
    ///
    /// The returned [`BTreeMap`] is keyed by capability name (which is
    /// part of the public API contract) so the iteration order is
    /// deterministic regardless of how the catalog is laid out.
    pub async fn evaluate_capabilities(
        &self,
        tenant_id: &str,
        roles: &[String],
        caps: &[Capability],
    ) -> Result<BTreeMap<&'static str, bool>, AuthError> {
        let mut out = BTreeMap::new();
        for cap in caps {
            let allowed = self.check_capability(tenant_id, roles, cap).await?;
            out.insert(cap.name, allowed);
        }
        Ok(out)
    }
}

/// Type-erased capability checking. Allows axum extractors and other
/// glue to hold an `Arc<dyn CapabilityChecker>` without exposing the
/// consumer's [`PolicyExtension`] type parameter.
#[async_trait::async_trait]
impl<E: PolicyExtension + 'static> CapabilityChecker for PolicyRouter<E> {
    async fn check(
        &self,
        tenant_id: &str,
        roles: &[String],
        cap: &Capability,
    ) -> Result<bool, AuthError> {
        self.check_capability(tenant_id, roles, cap).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilityCheck;
    use crate::test_support::{build_failing_uid_router, build_stub_router};

    // Each router now owns its own tenant-store cache, so tests no longer
    // have to use unique tenant ids to avoid process-wide cache pollution.

    macro_rules! read_cap {
        ($entity_id:literal) => {
            Capability {
                name: "models.read",
                description: "list models",
                checks: &[CapabilityCheck {
                    action: "read_model",
                    entity_type: "ModelCollection",
                    entity_id: $entity_id,
                }],
            }
        };
    }

    macro_rules! write_cap {
        ($entity_id:literal) => {
            Capability {
                name: "models.write",
                description: "edit models",
                checks: &[CapabilityCheck {
                    action: "write_model",
                    entity_type: "ModelCollection",
                    entity_id: $entity_id,
                }],
            }
        };
    }

    macro_rules! full_cap {
        ($entity_id:literal) => {
            Capability {
                name: "models.full",
                description: "read and write",
                checks: &[
                    CapabilityCheck {
                        action: "read_model",
                        entity_type: "ModelCollection",
                        entity_id: $entity_id,
                    },
                    CapabilityCheck {
                        action: "write_model",
                        entity_type: "ModelCollection",
                        entity_id: $entity_id,
                    },
                ],
            }
        };
    }

    #[tokio::test]
    async fn check_capability_returns_true_when_all_checks_allow() {
        let policy = r#"
            permit(
                principal in Role::"viewer",
                action == Action::"read_model",
                resource == ModelCollection::"router_t1"
            );
        "#;
        let router = build_stub_router(policy);
        let allowed = router
            .check_capability(
                "router_t1",
                &["viewer".to_string()],
                &read_cap!("router_t1"),
            )
            .await
            .expect("router ok");
        assert!(allowed);
    }

    #[tokio::test]
    async fn check_capability_returns_false_on_first_deny() {
        // Read is permitted but write is not — the all-of semantic
        // means the multi-check capability is denied.
        let policy = r#"
            permit(
                principal in Role::"viewer",
                action == Action::"read_model",
                resource == ModelCollection::"router_t2"
            );
        "#;
        let router = build_stub_router(policy);
        let allowed = router
            .check_capability(
                "router_t2",
                &["viewer".to_string()],
                &full_cap!("router_t2"),
            )
            .await
            .expect("router ok");
        assert!(!allowed);
    }

    #[tokio::test]
    async fn check_capability_returns_false_with_no_matching_policy() {
        let router = build_stub_router("");
        let allowed = router
            .check_capability(
                "router_t3",
                &["viewer".to_string()],
                &read_cap!("router_t3"),
            )
            .await
            .expect("router ok");
        assert!(!allowed);
    }

    #[tokio::test]
    async fn check_capability_propagates_uid_build_error() {
        let router = build_failing_uid_router();
        let err = router
            .check_capability(
                "router_t4",
                &["viewer".to_string()],
                &read_cap!("router_t4"),
            )
            .await
            .expect_err("uid construction failure should propagate");
        match err {
            AuthError::PolicyFailed(msg) => assert!(msg.contains("forced uid failure")),
            other => panic!("expected PolicyFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn evaluate_capabilities_preserves_all_names() {
        let router = build_stub_router("");
        let map = router
            .evaluate_capabilities(
                "router_t5",
                &["viewer".to_string()],
                &[
                    read_cap!("router_t5"),
                    write_cap!("router_t5"),
                    full_cap!("router_t5"),
                ],
            )
            .await
            .expect("router ok");
        assert_eq!(map.len(), 3);
        assert!(map.contains_key("models.read"));
        assert!(map.contains_key("models.write"));
        assert!(map.contains_key("models.full"));
        // Empty policy set → every capability denied.
        assert!(map.values().all(|allowed| !allowed));
    }

    #[tokio::test]
    async fn evaluate_capabilities_returns_partial_grants_independently() {
        let policy = r#"
            permit(
                principal in Role::"viewer",
                action == Action::"read_model",
                resource == ModelCollection::"router_t6"
            );
            permit(
                principal in Role::"editor",
                action == Action::"write_model",
                resource == ModelCollection::"router_t6"
            );
        "#;
        let router = build_stub_router(policy);

        // Viewer role: only the read capability should be granted.
        let viewer = router
            .evaluate_capabilities(
                "router_t6",
                &["viewer".to_string()],
                &[read_cap!("router_t6"), write_cap!("router_t6")],
            )
            .await
            .expect("router ok");
        assert_eq!(viewer.get("models.read"), Some(&true));
        assert_eq!(viewer.get("models.write"), Some(&false));

        // Editor role: only the write capability should be granted.
        let editor = router
            .evaluate_capabilities(
                "router_t6",
                &["editor".to_string()],
                &[read_cap!("router_t6"), write_cap!("router_t6")],
            )
            .await
            .expect("router ok");
        assert_eq!(editor.get("models.read"), Some(&false));
        assert_eq!(editor.get("models.write"), Some(&true));

        // Both roles together → the multi-check capability passes
        // because every individual check is granted.
        let combined = router
            .evaluate_capabilities(
                "router_t6",
                &["viewer".to_string(), "editor".to_string()],
                &[full_cap!("router_t6")],
            )
            .await
            .expect("router ok");
        assert_eq!(combined.get("models.full"), Some(&true));
    }

    #[tokio::test]
    async fn check_capability_with_empty_tenant_returns_false() {
        // The router's `check` method already denies on empty tenants;
        // capability evaluation must propagate that denial unchanged.
        let router = build_stub_router("");
        let allowed = router
            .check_capability("", &["viewer".to_string()], &read_cap!("ignored"))
            .await
            .expect("router ok");
        assert!(!allowed);
    }
}
