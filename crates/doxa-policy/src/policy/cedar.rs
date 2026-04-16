//! Cedar-based authorization policy implementation.
//!
//! Loads Cedar policies, entities, and resources via a pluggable
//! [`PolicyStore`](crate::store::PolicyStore) and evaluates per-resource
//! authorization using Cedar's partial evaluation. The post-evaluation step
//! (annotation extraction, residual translation, session assembly) is delegated
//! to a [`PolicyExtension`].
//!
//! ## Caching
//!
//! Each [`CedarPolicy`] owns a [`TenantStoreCache`] that memoizes per-tenant
//! parsed [`PolicySet`](cedar_policy::PolicySet)s, raw entity JSONs, and
//! resource enumerations, keyed by `tenant_id`. The default TTL is
//! [`DEFAULT_TENANT_CACHE_TTL`] (5 minutes); override via
//! [`CedarPolicy::with_cache_ttl`] or construct an explicit
//! [`TenantStoreCache`] and pass it to [`CedarPolicy::with_cache`]. CRUD
//! mutations on a tenant's policies call [`Policy::invalidate_tenant`] to
//! clear the entry.
//!
//! To share the same cache across a [`CedarPolicy`] and a
//! [`PolicyRouter`](crate::router::PolicyRouter), build one
//! [`TenantStoreCache`] and hand it to both via `with_cache` — cloning the
//! cache is cheap and aliases the underlying storage.
//!
//! L2 caching of the resolved session output is the consumer's responsibility.
//!
//! ## Tenant-Scoped Resolution
//!
//! Roles are mapped through the extension's
//! [`build_role_uid`](PolicyExtension::build_role_uid) — typically into
//! Cedar role entities like `Role::"analyst"`. The extension owns the
//! mapping policy.

use std::time::Duration;

use async_trait::async_trait;

use super::Policy;
use crate::cedar_core::{CedarEvaluator, TenantStoreCache, DEFAULT_TENANT_CACHE_TTL};
use crate::error::AuthError;
use crate::extension::PolicyExtension;
use crate::store::SharedPolicyStore;

// ---------------------------------------------------------------------------
// CedarPolicy: generic production Policy implementation
// ---------------------------------------------------------------------------

/// Cedar-based [`Policy`] implementation parameterized by a
/// [`PolicyExtension`].
///
/// Construct via [`CedarPolicy::new`] with a
/// [`PolicyStore`](crate::store::PolicyStore) and the consumer's extension.
/// Policies, entities, and resources are loaded from the store on first access
/// and cached per-tenant (default 5 minutes). CRUD mutations trigger targeted
/// invalidation via [`Policy::invalidate_tenant`].
///
/// The extension controls what happens after Cedar evaluates each resource:
/// which annotations to read, how to translate residual `when` clauses, and
/// what session output type to produce.
pub struct CedarPolicy<E: PolicyExtension> {
    store: SharedPolicyStore,
    extension: E,
    cache: TenantStoreCache,
}

impl<E: PolicyExtension> CedarPolicy<E> {
    /// Create a new Cedar-based policy resolver with a fresh tenant-store
    /// cache at the default TTL ([`DEFAULT_TENANT_CACHE_TTL`]).
    pub fn new(store: SharedPolicyStore, extension: E) -> Self {
        Self {
            store,
            extension,
            cache: TenantStoreCache::default(),
        }
    }

    /// Override the tenant-store cache TTL. Replaces the default-constructed
    /// cache; any entries loaded under the previous TTL are dropped.
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache = TenantStoreCache::with_ttl(ttl);
        self
    }

    /// Attach an externally-owned tenant-store cache, typically so the same
    /// cache can be shared with a
    /// [`PolicyRouter`](crate::router::PolicyRouter) constructed from the
    /// same store.
    pub fn with_cache(mut self, cache: TenantStoreCache) -> Self {
        self.cache = cache;
        self
    }

    /// Current tenant-store cache TTL.
    pub fn cache_ttl(&self) -> Duration {
        self.cache.ttl()
    }

    /// Handle to the tenant-store cache. Clone and pass to a
    /// [`PolicyRouter`](crate::router::PolicyRouter) to share the cache.
    pub fn cache(&self) -> TenantStoreCache {
        self.cache.clone()
    }
}

#[async_trait]
impl<E: PolicyExtension + 'static> Policy<E::SessionOutput> for CedarPolicy<E>
where
    E::SessionOutput: Clone,
{
    async fn flush_cache(&self) {
        self.cache.flush().await;
    }

    async fn invalidate_tenant(&self, tenant_id: Option<&str>) {
        match tenant_id {
            Some(id) => self.cache.invalidate(id).await,
            None => self.cache.flush().await,
        }
    }

    #[tracing::instrument(skip_all, name = "cedar_resolve", fields(tenant_id, role_count = roles.len()))]
    async fn resolve(
        &self,
        tenant_id: Option<&str>,
        roles: &[String],
    ) -> Result<E::SessionOutput, AuthError> {
        let tenant_id = match tenant_id {
            Some(id) if !id.is_empty() => id,
            _ => {
                if roles.iter().any(|r| self.extension.is_admin_role(r)) {
                    return self.extension.admin_session();
                }
                return Ok(self.extension.deny_all());
            }
        };

        let store = self.cache.get_or_load(&self.store, tenant_id).await?;
        let evaluator = CedarEvaluator::new(&store, tenant_id, roles, &self.extension)?;
        evaluator.evaluate_session(tenant_id)
    }
}

// Silence unused-import when the policy doesn't need the const at top-level,
// but we want to reference it in rustdoc for discoverability.
#[allow(dead_code)]
const _: Duration = DEFAULT_TENANT_CACHE_TTL;

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::test_support::{StubExtension, StubStore};

    fn build_policy() -> CedarPolicy<StubExtension> {
        let store: SharedPolicyStore = Arc::new(StubStore { policy_text: "" });
        CedarPolicy::new(store, StubExtension)
    }

    #[test]
    fn new_uses_default_ttl() {
        let policy = build_policy();
        assert_eq!(policy.cache_ttl(), DEFAULT_TENANT_CACHE_TTL);
    }

    #[test]
    fn with_cache_ttl_overrides_default() {
        let policy = build_policy().with_cache_ttl(Duration::from_secs(42));
        assert_eq!(policy.cache_ttl(), Duration::from_secs(42));
    }

    // Extension that treats any role matching a custom predicate as admin.
    struct CustomAdminExtension;

    impl crate::extension::PolicyExtension for CustomAdminExtension {
        type ResourceAttrs = ();
        type SessionOutput = &'static str;

        fn extract_allowed_attrs(
            &self,
            _: &cedar_policy::Policy,
        ) -> Result<Self::ResourceAttrs, AuthError> {
            Ok(())
        }
        fn extract_residual_attrs(
            &self,
            _: &cedar_policy::Policy,
            _: Option<&serde_json::Value>,
        ) -> Result<Self::ResourceAttrs, AuthError> {
            Ok(())
        }
        fn merge_resource_attrs(
            &self,
            _: Vec<Self::ResourceAttrs>,
        ) -> Result<Self::ResourceAttrs, AuthError> {
            Ok(())
        }
        fn build_resource_uid(
            &self,
            _: &str,
            entity_type: &str,
            resource_id: &str,
        ) -> Result<cedar_policy::EntityUid, AuthError> {
            crate::uid::build_uid(entity_type, resource_id)
        }
        fn build_role_uid(
            &self,
            _: &str,
            role_name: &str,
        ) -> Result<cedar_policy::EntityUid, AuthError> {
            crate::uid::build_uid("Role", role_name)
        }
        fn assemble_session(
            &self,
            _: &str,
            _: crate::extension::ResourceGrants<Self::ResourceAttrs>,
        ) -> Result<Self::SessionOutput, AuthError> {
            Ok("session")
        }
        fn deny_all(&self) -> Self::SessionOutput {
            "denied"
        }
        fn admin_session(&self) -> Result<Self::SessionOutput, AuthError> {
            Ok("admin")
        }

        fn is_admin_role(&self, role: &str) -> bool {
            role == "system:admin"
        }

        fn principal_entity_type(&self) -> &'static str {
            "Principal"
        }

        fn synthetic_principal_id(&self) -> &'static str {
            "__session__"
        }
    }

    #[tokio::test]
    async fn resolve_uses_custom_is_admin_role() {
        use crate::policy::Policy;
        let store: SharedPolicyStore = Arc::new(StubStore { policy_text: "" });
        let policy = CedarPolicy::new(store, CustomAdminExtension);

        // Custom admin role triggers admin_session().
        let out = policy
            .resolve(None, &["system:admin".to_string()])
            .await
            .unwrap();
        assert_eq!(out, "admin");

        // The old literal "admin" no longer short-circuits.
        let out = policy.resolve(None, &["admin".to_string()]).await.unwrap();
        assert_eq!(out, "denied");
    }

    #[test]
    fn extension_principal_overrides_propagate_to_uid() {
        let ext = CustomAdminExtension;
        let uid = crate::uid::build_uid(
            <CustomAdminExtension as crate::extension::PolicyExtension>::principal_entity_type(
                &ext,
            ),
            <CustomAdminExtension as crate::extension::PolicyExtension>::synthetic_principal_id(
                &ext,
            ),
        )
        .unwrap();
        assert_eq!(uid.to_string(), r#"Principal::"__session__""#);
    }

    #[test]
    fn cache_handle_is_cheap_to_clone_and_shareable() {
        let policy = build_policy().with_cache_ttl(Duration::from_secs(7));
        let cache = policy.cache();
        assert_eq!(cache.ttl(), Duration::from_secs(7));

        // Building a second policy with the same cache produces a policy
        // whose ttl matches (the cache carries its own ttl value).
        let store: SharedPolicyStore = Arc::new(StubStore { policy_text: "" });
        let policy2 = CedarPolicy::new(store, StubExtension).with_cache(cache);
        assert_eq!(policy2.cache_ttl(), Duration::from_secs(7));
    }
}
