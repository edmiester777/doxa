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
use crate::resource::ResourceEntity;
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

    /// Check `action` against one concrete object.
    ///
    /// Unlike [`check_capability`](Self::check_capability), whose
    /// resource ids are constants or the tenant, this evaluates against
    /// the instance the request actually touches — and injects its
    /// attributes into the entity set, so a `when { resource.<attr> … }`
    /// clause resolves instead of collapsing to a residual denial.
    #[tracing::instrument(skip_all, fields(tenant_id, action))]
    pub async fn check_instance(
        &self,
        tenant_id: &str,
        roles: &[String],
        action: &str,
        resource: &ResourceEntity,
    ) -> Result<AccessDecision, AuthError> {
        if tenant_id.is_empty() {
            return Ok(AccessDecision::deny(
                "no tenant context — cannot evaluate action",
            ));
        }

        let uid = self.extension.build_resource_uid(
            tenant_id,
            &resource.entity_type,
            &resource.entity_id,
        )?;

        let store = self.cache.get_or_load(&self.store, tenant_id).await?;
        let evaluator = CedarEvaluator::new_with_resource(
            &store,
            tenant_id,
            roles,
            self.extension.as_ref(),
            Some(resource),
        )?;
        let allowed = evaluator.check_action(action, uid.clone())?;

        Ok(AccessDecision {
            allowed,
            reason: (!allowed).then(|| format!("policy denied {action} on {uid}")),
        })
    }

    /// Check `action` against several concrete objects, in one pass.
    ///
    /// [`check_instance`](Self::check_instance) assembles an entity set,
    /// then evaluates. The set does not depend on which object is being
    /// asked about, so N objects asked separately is N identical
    /// assemblies — the cost a handler pays for a request body naming
    /// several references. Here the hierarchy is built once and every
    /// resource is evaluated against it.
    ///
    /// Verdicts come back positionally, one per resource. An empty slice
    /// answers with an empty vector without loading the tenant at all.
    #[tracing::instrument(skip_all, fields(tenant_id, action, count = resources.len()))]
    pub async fn check_instance_many(
        &self,
        tenant_id: &str,
        roles: &[String],
        action: &str,
        resources: &[ResourceEntity],
    ) -> Result<Vec<AccessDecision>, AuthError> {
        if resources.is_empty() {
            return Ok(Vec::new());
        }
        if tenant_id.is_empty() {
            return Ok(resources
                .iter()
                .map(|_| AccessDecision::deny("no tenant context — cannot evaluate action"))
                .collect());
        }

        // Resolved before the evaluator is built, so a resource whose id
        // cannot become a UID fails the whole call rather than being
        // silently absent from the answers.
        let uids = resources
            .iter()
            .map(|resource| {
                self.extension.build_resource_uid(
                    tenant_id,
                    &resource.entity_type,
                    &resource.entity_id,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        let store = self.cache.get_or_load(&self.store, tenant_id).await?;
        let borrowed: Vec<&ResourceEntity> = resources.iter().collect();
        let evaluator = CedarEvaluator::new_with_resources(
            &store,
            tenant_id,
            roles,
            self.extension.as_ref(),
            &borrowed,
        )?;

        uids.into_iter()
            .map(|uid| {
                let allowed = evaluator.check_action(action, uid.clone())?;
                Ok(AccessDecision {
                    allowed,
                    reason: (!allowed).then(|| format!("policy denied {action} on {uid}")),
                })
            })
            .collect()
    }

    /// The [`PolicyExtension`] this router evaluates through.
    ///
    /// Exposed so a wrapper that has to consult the extension before
    /// reaching the policy — a session that already holds the answer, an
    /// admin shortcut — can do so without being handed a second copy to
    /// keep in step. [`SessionChecker`](crate::session::SessionChecker) is
    /// the one in the box.
    pub fn extension(&self) -> &E {
        &self.extension
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
            // Resolved here, so `build_resource_uid` is handed a real id.
            // It is the consumer's hook for the consumer's UID hierarchy;
            // asking it to decode a marker doxa invented, using a value
            // doxa passed it in the same call, was a round trip through
            // consumer code that consulted nothing about the consumer.
            let resource = self.extension.build_resource_uid(
                tenant_id,
                check.entity_type,
                check.entity_id.resolve(tenant_id),
            )?;
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

    async fn check_instance(
        &self,
        tenant_id: &str,
        roles: &[String],
        action: &str,
        resource: &ResourceEntity,
    ) -> Result<bool, AuthError> {
        // Disambiguated: the inherent method shares this name.
        Ok(
            PolicyRouter::check_instance(self, tenant_id, roles, action, resource)
                .await?
                .allowed,
        )
    }

    /// Overridden rather than left to the default loop: the router is
    /// exactly the implementation that can hoist the entity-set assembly
    /// out of the per-resource question.
    async fn check_instance_many(
        &self,
        tenant_id: &str,
        roles: &[String],
        action: &str,
        resources: &[ResourceEntity],
    ) -> Result<Vec<bool>, AuthError> {
        Ok(
            PolicyRouter::check_instance_many(self, tenant_id, roles, action, resources)
                .await?
                .into_iter()
                .map(|decision| decision.allowed)
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{CapabilityCheck, ResourceId};
    use crate::test_support::{
        build_failing_uid_router, build_stub_router, build_stub_router_with_entities,
    };

    // Each router now owns its own tenant-store cache, so tests no longer
    // have to use unique tenant ids to avoid process-wide cache pollution.

    macro_rules! read_cap {
        ($entity_id:expr) => {
            Capability {
                name: "widgets.read",
                description: "list widgets",
                checks: &[CapabilityCheck {
                    action: "read_widget",
                    entity_type: "WidgetCollection",
                    entity_id: $entity_id,
                }],
            }
        };
    }

    macro_rules! write_cap {
        ($entity_id:expr) => {
            Capability {
                name: "widgets.write",
                description: "edit widgets",
                checks: &[CapabilityCheck {
                    action: "write_widget",
                    entity_type: "WidgetCollection",
                    entity_id: $entity_id,
                }],
            }
        };
    }

    macro_rules! full_cap {
        ($entity_id:expr) => {
            Capability {
                name: "widgets.full",
                description: "read and write",
                checks: &[
                    CapabilityCheck {
                        action: "read_widget",
                        entity_type: "WidgetCollection",
                        entity_id: $entity_id,
                    },
                    CapabilityCheck {
                        action: "write_widget",
                        entity_type: "WidgetCollection",
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
                action == Action::"read_widget",
                resource == WidgetCollection::"router_t1"
            );
        "#;
        let router = build_stub_router(policy);
        let allowed = router
            .check_capability(
                "router_t1",
                &["viewer".to_string()],
                &read_cap!(ResourceId::Literal("router_t1")),
            )
            .await
            .expect("router ok");
        assert!(allowed);
    }

    /// The substitution, and the whole point of it: the stub extension
    /// ignores the tenant it is passed and builds a UID straight from the
    /// id (`test_support.rs:52`), so the only way this policy can match
    /// is if `Tenant` was resolved before the hook was reached.
    ///
    /// That is what an extension no longer has to do — it now receives an
    /// id rather than a marker naming an argument it was already holding.
    #[tokio::test]
    async fn the_tenant_is_substituted_before_the_extension_sees_it() {
        let policy = r#"
            permit(
                principal in Role::"viewer",
                action == Action::"read_widget",
                resource == WidgetCollection::"router_t7"
            );
        "#;
        let router = build_stub_router(policy);

        let allowed = router
            .check_capability(
                "router_t7",
                &["viewer".to_string()],
                &read_cap!(ResourceId::Tenant),
            )
            .await
            .expect("router ok");

        assert!(allowed);
    }

    /// And it is the *asking* tenant, not a constant baked into the
    /// catalog: the same capability evaluated in another tenant asks
    /// about that tenant's collection and is refused.
    #[tokio::test]
    async fn a_tenant_id_follows_the_request_rather_than_the_declaration() {
        let policy = r#"
            permit(
                principal in Role::"viewer",
                action == Action::"read_widget",
                resource == WidgetCollection::"router_t8"
            );
        "#;
        let router = build_stub_router(policy);

        let allowed = router
            .check_capability(
                "router_t9",
                &["viewer".to_string()],
                &read_cap!(ResourceId::Tenant),
            )
            .await
            .expect("router ok");

        assert!(
            !allowed,
            "the policy names router_t8, the request is router_t9"
        );
    }

    #[tokio::test]
    async fn check_capability_returns_false_on_first_deny() {
        // Read is permitted but write is not — the all-of semantic
        // means the multi-check capability is denied.
        let policy = r#"
            permit(
                principal in Role::"viewer",
                action == Action::"read_widget",
                resource == WidgetCollection::"router_t2"
            );
        "#;
        let router = build_stub_router(policy);
        let allowed = router
            .check_capability(
                "router_t2",
                &["viewer".to_string()],
                &full_cap!(ResourceId::Literal("router_t2")),
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
                &read_cap!(ResourceId::Literal("router_t3")),
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
                &read_cap!(ResourceId::Literal("router_t4")),
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
                    read_cap!(ResourceId::Literal("router_t5")),
                    write_cap!(ResourceId::Literal("router_t5")),
                    full_cap!(ResourceId::Literal("router_t5")),
                ],
            )
            .await
            .expect("router ok");
        assert_eq!(map.len(), 3);
        assert!(map.contains_key("widgets.read"));
        assert!(map.contains_key("widgets.write"));
        assert!(map.contains_key("widgets.full"));
        // Empty policy set → every capability denied.
        assert!(map.values().all(|allowed| !allowed));
    }

    #[tokio::test]
    async fn evaluate_capabilities_returns_partial_grants_independently() {
        let policy = r#"
            permit(
                principal in Role::"viewer",
                action == Action::"read_widget",
                resource == WidgetCollection::"router_t6"
            );
            permit(
                principal in Role::"editor",
                action == Action::"write_widget",
                resource == WidgetCollection::"router_t6"
            );
        "#;
        let router = build_stub_router(policy);

        // Viewer role: only the read capability should be granted.
        let viewer = router
            .evaluate_capabilities(
                "router_t6",
                &["viewer".to_string()],
                &[
                    read_cap!(ResourceId::Literal("router_t6")),
                    write_cap!(ResourceId::Literal("router_t6")),
                ],
            )
            .await
            .expect("router ok");
        assert_eq!(viewer.get("widgets.read"), Some(&true));
        assert_eq!(viewer.get("widgets.write"), Some(&false));

        // Editor role: only the write capability should be granted.
        let editor = router
            .evaluate_capabilities(
                "router_t6",
                &["editor".to_string()],
                &[
                    read_cap!(ResourceId::Literal("router_t6")),
                    write_cap!(ResourceId::Literal("router_t6")),
                ],
            )
            .await
            .expect("router ok");
        assert_eq!(editor.get("widgets.read"), Some(&false));
        assert_eq!(editor.get("widgets.write"), Some(&true));

        // Both roles together → the multi-check capability passes
        // because every individual check is granted.
        let combined = router
            .evaluate_capabilities(
                "router_t6",
                &["viewer".to_string(), "editor".to_string()],
                &[full_cap!(ResourceId::Literal("router_t6"))],
            )
            .await
            .expect("router ok");
        assert_eq!(combined.get("widgets.full"), Some(&true));
    }

    #[tokio::test]
    async fn check_capability_with_empty_tenant_returns_false() {
        // The router's `check` method already denies on empty tenants;
        // capability evaluation must propagate that denial unchanged.
        let router = build_stub_router("");
        let allowed = router
            .check_capability(
                "",
                &["viewer".to_string()],
                &read_cap!(ResourceId::Literal("ignored")),
            )
            .await
            .expect("router ok");
        assert!(!allowed);
    }

    // ── Instance-level checks ───────────────────────────────

    /// Grants only when the object's own `region` attribute matches, so
    /// the decision is unreachable without the entity in scope.
    const REGION_POLICY: &str = r#"
        permit(principal in Role::"viewer", action == Action::"read", resource)
        when { resource.region == "us" };
    "#;

    fn widget(id: &str, region: &str) -> ResourceEntity {
        let mut attrs = serde_json::Map::new();
        attrs.insert("region".into(), serde_json::json!(region));
        ResourceEntity::new("Widget", id).with_attrs(attrs)
    }

    #[tokio::test]
    async fn attribute_policy_allows_when_the_instance_matches() {
        let router = build_stub_router(REGION_POLICY);
        let decision = router
            .check_instance(
                "inst_t1",
                &["viewer".to_string()],
                "read",
                &widget("w-1", "us"),
            )
            .await
            .expect("router ok");
        assert!(decision.allowed, "matching attribute should grant access");
    }

    #[tokio::test]
    async fn attribute_policy_denies_when_the_instance_differs() {
        let router = build_stub_router(REGION_POLICY);
        let decision = router
            .check_instance(
                "inst_t2",
                &["viewer".to_string()],
                "read",
                &widget("w-2", "eu"),
            )
            .await
            .expect("router ok");
        assert!(!decision.allowed, "non-matching attribute should deny");
        assert!(decision.reason.is_some(), "denials carry a reason");
    }

    #[tokio::test]
    async fn attribute_policy_denies_without_the_entity_in_scope() {
        // The same policy through the capability path, whose resource
        // has no attributes: `resource.region` cannot be dereferenced,
        // the clause survives as a residual, and the residual reads as
        // a denial. This is what instance checks exist to fix.
        let router = build_stub_router(REGION_POLICY);
        let uid = crate::uid::build_uid("Widget", "w-1").expect("uid");
        let decision = router
            .check("inst_t3", &["viewer".to_string()], "read", uid)
            .await
            .expect("router ok");
        assert!(
            !decision.allowed,
            "an attribute clause with no entity to read must not grant",
        );
    }

    #[tokio::test]
    async fn instance_check_denies_on_empty_tenant() {
        let router = build_stub_router(REGION_POLICY);
        let decision = router
            .check_instance("", &["viewer".to_string()], "read", &widget("w-1", "us"))
            .await
            .expect("router ok");
        assert!(!decision.allowed);
    }

    /// A store that already persists an entity for the checked UID must
    /// not produce two entries — Cedar rejects the duplicate and the
    /// check would error instead of deciding.
    #[tokio::test]
    async fn stored_entity_for_the_same_uid_is_merged_not_duplicated() {
        let stored = serde_json::json!({
            "uid": {"type": "Widget", "id": "w-1"},
            "attrs": {"region": "eu"},
            "parents": [],
        });
        let router = build_stub_router_with_entities(REGION_POLICY, vec![stored]);

        let decision = router
            .check_instance(
                "inst_t4",
                &["viewer".to_string()],
                "read",
                &widget("w-1", "us"),
            )
            .await
            .expect("a stored entity must not turn the check into an error");
        assert!(
            decision.allowed,
            "the live attribute is authoritative over the stored one",
        );
    }

    /// The stored entity carries the hierarchy tenant policies are
    /// written against; a loaded resource declaring no parents must not
    /// drop it.
    #[tokio::test]
    async fn stored_parents_survive_the_merge() {
        const TENANT_POLICY: &str = r#"
            permit(principal in Role::"viewer", action == Action::"read", resource)
            when { resource in Tenant::"acme" && resource.region == "us" };
        "#;
        let entities = vec![
            serde_json::json!({
                "uid": {"type": "Tenant", "id": "acme"}, "attrs": {}, "parents": [],
            }),
            serde_json::json!({
                "uid": {"type": "Widget", "id": "w-1"},
                "attrs": {},
                "parents": [{"type": "Tenant", "id": "acme"}],
            }),
        ];
        let router = build_stub_router_with_entities(TENANT_POLICY, entities);

        let decision = router
            .check_instance(
                "acme",
                &["viewer".to_string()],
                "read",
                &widget("w-1", "us"),
            )
            .await
            .expect("router ok");
        assert!(
            decision.allowed,
            "membership from the stored entity must still hold after the merge",
        );
    }

    // ── Batched instance checks ─────────────────────────────

    /// The whole point: several resources, one entity hierarchy, one
    /// verdict each — and each verdict about its own resource, not about
    /// the set.
    #[tokio::test]
    async fn a_batch_decides_each_resource_on_its_own_attributes() {
        let router = build_stub_router(REGION_POLICY);

        let decisions = router
            .check_instance_many(
                "batch_t1",
                &["viewer".to_string()],
                "read",
                &[
                    widget("w-1", "us"),
                    widget("w-2", "eu"),
                    widget("w-3", "us"),
                ],
            )
            .await
            .expect("router ok");

        assert_eq!(
            decisions.iter().map(|d| d.allowed).collect::<Vec<_>>(),
            vec![true, false, true],
        );
        assert!(decisions[1].reason.is_some(), "denials carry a reason");
    }

    /// Batching is an optimization, so it has to be invisible: the same
    /// question asked either way must reach the same verdict. A shared
    /// entity set that let one resource's attributes leak into another's
    /// decision would show up here and nowhere else.
    #[tokio::test]
    async fn a_batch_agrees_with_the_checks_it_replaces() {
        let router = build_stub_router(REGION_POLICY);
        let resources = [widget("w-1", "us"), widget("w-2", "eu")];

        let batched = router
            .check_instance_many("batch_t2", &["viewer".to_string()], "read", &resources)
            .await
            .expect("router ok");

        for (resource, batched) in resources.iter().zip(batched) {
            let singular = router
                .check_instance("batch_t2", &["viewer".to_string()], "read", resource)
                .await
                .expect("router ok");
            assert_eq!(
                singular.allowed, batched.allowed,
                "{} disagreed",
                resource.entity_id,
            );
        }
    }

    /// The duplicate-UID case, in the plural. One overlapping resource
    /// sends the whole batch down the merge path, and every resource in it
    /// — overlapping or not — must still be decided on its own attributes.
    #[tokio::test]
    async fn a_batch_containing_a_stored_uid_still_merges() {
        let stored = serde_json::json!({
            "uid": {"type": "Widget", "id": "w-1"},
            "attrs": {"region": "eu"},
            "parents": [],
        });
        let router = build_stub_router_with_entities(REGION_POLICY, vec![stored]);

        let decisions = router
            .check_instance_many(
                "batch_t3",
                &["viewer".to_string()],
                "read",
                &[widget("w-1", "us"), widget("w-2", "eu")],
            )
            .await
            .expect("a stored entity must not turn the batch into an error");

        assert_eq!(
            decisions.iter().map(|d| d.allowed).collect::<Vec<_>>(),
            vec![true, false],
            "the live attribute wins for the stored UID, and its neighbour is unaffected",
        );
    }

    /// A body may name one object twice — `sales.orders` and the bare
    /// `orders` resolving to one row — so the batch has to tolerate two
    /// entries for one UID. Cedar refuses a duplicate in an entity set, so
    /// without folding them this is a `500` rather than two answers.
    #[tokio::test]
    async fn a_batch_naming_one_resource_twice_answers_twice() {
        let router = build_stub_router(REGION_POLICY);

        let decisions = router
            .check_instance_many(
                "batch_t6",
                &["viewer".to_string()],
                "read",
                &[widget("w-1", "us"), widget("w-1", "us")],
            )
            .await
            .expect("one resource named twice is not an error");

        assert_eq!(
            decisions.iter().map(|d| d.allowed).collect::<Vec<_>>(),
            vec![true, true],
        );
    }

    /// Two snapshots of one row disagreeing about an attribute is still one
    /// object, and Cedar decides about objects — so the two slots have to
    /// carry one verdict rather than one each. Which snapshot's attributes
    /// survive the fold is not specified; that they agree is, because an
    /// object both granted and refused in one answer is not a verdict a
    /// caller can act on.
    #[tokio::test]
    async fn one_uid_gets_one_verdict_however_often_it_is_named() {
        let router = build_stub_router(REGION_POLICY);

        let decisions = router
            .check_instance_many(
                "batch_t7",
                &["viewer".to_string()],
                "read",
                &[widget("w-1", "us"), widget("w-1", "eu")],
            )
            .await
            .expect("conflicting snapshots of one row are not an error");

        assert_eq!(decisions[0].allowed, decisions[1].allowed);
    }

    #[tokio::test]
    async fn an_empty_batch_asks_nothing() {
        let router = build_failing_uid_router();

        assert!(router
            .check_instance_many("batch_t4", &[], "read", &[])
            .await
            .expect("nothing to build a uid for")
            .is_empty());
    }

    #[tokio::test]
    async fn a_batch_denies_on_empty_tenant() {
        let router = build_stub_router(REGION_POLICY);

        let decisions = router
            .check_instance_many("", &["viewer".to_string()], "read", &[widget("w-1", "us")])
            .await
            .expect("router ok");

        assert_eq!(decisions.len(), 1);
        assert!(!decisions[0].allowed);
    }

    /// A resource whose id cannot become a UID fails the call rather than
    /// being quietly missing from the answers — a short vector would line
    /// the remaining verdicts up against the wrong rows.
    #[tokio::test]
    async fn a_batch_propagates_a_uid_failure() {
        let router = build_failing_uid_router();

        assert!(router
            .check_instance_many(
                "batch_t5",
                &[],
                "read",
                &[ResourceEntity::new("Widget", "w-1")],
            )
            .await
            .is_err());
    }
}
