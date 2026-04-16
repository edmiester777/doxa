//! Reusable Cedar evaluation infrastructure.
//!
//! Contains the tenant store (pre-parsed Cedar artifacts), a shareable
//! [`TenantStoreCache`] for memoizing per-tenant loads, and the generic
//! Cedar evaluator that drives per-resource authorization and delegates
//! post-evaluation interpretation to a [`PolicyExtension`].
//!
//! This module is extension-agnostic — it handles Cedar mechanics (entity
//! assembly, `is_authorized_partial`, residual extraction) without knowing
//! what the consumer does with the results. Persistence is delegated to
//! the [`PolicyStore`](crate::store::PolicyStore) trait.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use cached::{Cached, TimedCache};
use cedar_policy::{Authorizer, Context, Decision, Entities, PolicySet, Request};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::error::AuthError;
use crate::extension::{PolicyExtension, ResourceAccess, ResourceGrants};
use crate::store::SharedPolicyStore;
use crate::uid::{action_uid, principal_uid};

// ---------------------------------------------------------------------------
// Cached store: pre-parsed Cedar artifacts loaded from a PolicyStore
// ---------------------------------------------------------------------------

/// Pre-parsed Cedar artifacts loaded from a
/// [`PolicyStore`](crate::store::PolicyStore) for a single tenant.
///
/// The [`policy_set`](CedarStore::policy_set) contains only policies belonging
/// to this tenant. Entity JSONs are kept raw so that a synthetic per-request
/// user entity can be prepended before parsing into [`Entities`]. The
/// [`resources`](CedarStore::resources) map enumerates the tenant's resources
/// grouped by Cedar entity type, driving the per-session evaluation loop.
pub(crate) struct CedarStore {
    pub(crate) policy_set: PolicySet,
    pub(crate) entity_jsons: Vec<Value>,
    pub(crate) resources: HashMap<String, Vec<String>>,
}

/// Default per-tenant cache TTL when no override is supplied.
pub const DEFAULT_TENANT_CACHE_TTL: Duration = Duration::from_secs(300);

// ---------------------------------------------------------------------------
// Tenant store cache — shareable between CedarPolicy and PolicyRouter
// ---------------------------------------------------------------------------

/// Shareable cache of per-tenant Cedar artifacts with a configurable TTL.
///
/// Construct via [`TenantStoreCache::with_ttl`] (or [`Default`] for the
/// [`DEFAULT_TENANT_CACHE_TTL`]). Cheap to clone — the inner state is an
/// [`Arc`], so a single cache can be shared across both
/// [`CedarPolicy`](crate::policy::cedar::CedarPolicy) and
/// [`PolicyRouter`](crate::router::PolicyRouter) to avoid double-loading
/// the same tenant through two different entry points.
///
/// Misses load through the supplied [`SharedPolicyStore`]; only successful
/// loads are cached so transient store errors are retried on the next
/// request.
#[derive(Clone)]
pub struct TenantStoreCache {
    inner: Arc<Mutex<TimedCache<String, Arc<CedarStore>>>>,
    ttl: Duration,
}

impl TenantStoreCache {
    /// Build a cache with the given TTL.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TimedCache::with_lifespan(ttl))),
            ttl,
        }
    }

    /// The TTL this cache was constructed with.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Drop every entry.
    pub async fn flush(&self) {
        self.inner.lock().await.cache_clear();
    }

    /// Drop a single tenant's entry.
    pub async fn invalidate(&self, tenant_id: &str) {
        self.inner.lock().await.cache_remove(&tenant_id.to_string());
    }

    /// Look up (or load, on miss) the tenant's store.
    pub(crate) async fn get_or_load(
        &self,
        store: &SharedPolicyStore,
        tenant_id: &str,
    ) -> Result<Arc<CedarStore>, AuthError> {
        {
            let mut guard = self.inner.lock().await;
            if let Some(hit) = guard.cache_get(&tenant_id.to_string()) {
                return Ok(Arc::clone(hit));
            }
        }
        let loaded = load_tenant_store(store, tenant_id).await?;
        self.inner
            .lock()
            .await
            .cache_set(tenant_id.to_string(), Arc::clone(&loaded));
        Ok(loaded)
    }
}

impl Default for TenantStoreCache {
    fn default() -> Self {
        Self::with_ttl(DEFAULT_TENANT_CACHE_TTL)
    }
}

/// Load and assemble Cedar artifacts for a single tenant, without caching.
///
/// Consumers typically go through [`TenantStoreCache::get_or_load`] instead;
/// this is exposed for tests and for callers that explicitly want to bypass
/// caching.
pub(crate) async fn load_tenant_store(
    store: &SharedPolicyStore,
    tenant_id: &str,
) -> Result<Arc<CedarStore>, AuthError> {
    let policy_set = store.load_policy_set(tenant_id).await?;
    let entity_jsons = store.load_entity_jsons(tenant_id).await?;
    let resources = store.list_resources(tenant_id).await?;

    Ok(Arc::new(CedarStore {
        policy_set,
        entity_jsons,
        resources,
    }))
}

// ---------------------------------------------------------------------------
// Generic Cedar evaluator
// ---------------------------------------------------------------------------

/// Generic Cedar evaluator parameterized by a [`PolicyExtension`].
///
/// Handles the Cedar evaluation loop (iterate per-tenant resources, call
/// `is_authorized_partial`) and delegates post-evaluation interpretation
/// to the extension. All Cedar evaluation is synchronous and CPU-only.
pub(crate) struct CedarEvaluator<'a, E: PolicyExtension> {
    authorizer: Authorizer,
    store: &'a CedarStore,
    entities: Entities,
    principal: cedar_policy::EntityUid,
    extension: &'a E,
}

impl<'a, E: PolicyExtension> CedarEvaluator<'a, E> {
    /// Build a new evaluator for a single tenant + role set.
    ///
    /// Constructs the ephemeral user entity with role parents (resolved
    /// through the extension's
    /// [`build_role_uid`](PolicyExtension::build_role_uid)) and parses all
    /// entities (store + user) into a Cedar [`Entities`] set. The entity
    /// type and id of the synthetic principal are resolved through
    /// [`PolicyExtension::principal_entity_type`] and
    /// [`PolicyExtension::synthetic_principal_id`].
    pub(crate) fn new(
        store: &'a CedarStore,
        tenant_id: &str,
        roles: &[String],
        extension: &'a E,
    ) -> Result<Self, AuthError> {
        let principal_type = extension.principal_entity_type();
        let principal_id = extension.synthetic_principal_id();
        let principal = principal_uid(principal_type, principal_id)?;
        let role_parents = build_role_parents(extension, tenant_id, roles)?;

        let user_entity_json = serde_json::json!({
            "uid": { "type": principal_type, "id": principal_id },
            "attrs": {},
            "parents": role_parents
        });

        let mut all_entities = store.entity_jsons.clone();
        all_entities.push(user_entity_json);
        let entities = Entities::from_json_value(Value::Array(all_entities), None)
            .map_err(|e| AuthError::PolicyFailed(format!("entity parse error: {e}")))?;

        Ok(Self {
            authorizer: Authorizer::new(),
            store,
            entities,
            principal,
            extension,
        })
    }

    /// Evaluate a single resource and return [`ResourceAccess`] with extension
    /// attrs.
    ///
    /// Calls Cedar's `is_authorized_partial` and dispatches to the extension's
    /// `extract_allowed_attrs` / `extract_residual_attrs` based on the
    /// decision.
    fn evaluate_resource(
        &self,
        action_name: &str,
        resource: cedar_policy::EntityUid,
    ) -> Result<ResourceAccess<E::ResourceAttrs>, AuthError> {
        let action = action_uid(self.extension.action_entity_type(), action_name)?;
        let request = Request::new(
            self.principal.clone(),
            action,
            resource,
            Context::empty(),
            None,
        )
        .map_err(|e| AuthError::PolicyFailed(format!("request build error: {e}")))?;

        let response =
            self.authorizer
                .is_authorized_partial(&request, &self.store.policy_set, &self.entities);

        match response.decision() {
            Some(Decision::Allow) => {
                let mut attrs = Vec::new();
                for policy in response.definitely_satisfied() {
                    attrs.push(self.extension.extract_allowed_attrs(&policy)?);
                }
                let merged = self.extension.merge_resource_attrs(attrs)?;
                Ok(ResourceAccess::Allowed(merged))
            }
            None => {
                // Residual: resource conditionally allowed — extract from both
                // definitely satisfied and nontrivial residual policies.
                let mut attrs = Vec::new();
                for policy in response.definitely_satisfied() {
                    attrs.push(self.extension.extract_allowed_attrs(&policy)?);
                }
                for policy in response.nontrivial_residuals() {
                    let body = extract_condition_body(&policy)?;
                    attrs.push(
                        self.extension
                            .extract_residual_attrs(&policy, body.as_ref())?,
                    );
                }
                let merged = self.extension.merge_resource_attrs(attrs)?;
                Ok(ResourceAccess::Allowed(merged))
            }
            Some(Decision::Deny) => Ok(ResourceAccess::Denied),
        }
    }

    /// Pure allow/deny check for an arbitrary action / resource pair.
    ///
    /// Used by [`PolicyRouter`](crate::router::PolicyRouter) for slow-path
    /// permission checks. Unlike [`evaluate_resource`](Self::evaluate_resource)
    /// this never extracts policy attributes — the caller only cares whether
    /// the action is permitted.
    pub(crate) fn check_action(
        &self,
        action_name: &str,
        resource: cedar_policy::EntityUid,
    ) -> Result<bool, AuthError> {
        let action = action_uid(self.extension.action_entity_type(), action_name)?;
        let request = Request::new(
            self.principal.clone(),
            action,
            resource,
            Context::empty(),
            None,
        )
        .map_err(|e| AuthError::PolicyFailed(format!("request build error: {e}")))?;

        let response =
            self.authorizer
                .is_authorized_partial(&request, &self.store.policy_set, &self.entities);

        Ok(matches!(response.decision(), Some(Decision::Allow)))
    }

    /// Iterate every `(entity_type, resource_id)` pair from the tenant
    /// store, evaluate each one against the action returned by the
    /// extension's
    /// [`action_for_resource_type`](PolicyExtension::action_for_resource_type),
    /// and hand the assembled grants map to
    /// [`assemble_session`](PolicyExtension::assemble_session).
    pub(crate) fn evaluate_session(&self, tenant_id: &str) -> Result<E::SessionOutput, AuthError> {
        let mut grants: ResourceGrants<E::ResourceAttrs> = HashMap::new();

        for (entity_type, resource_ids) in &self.store.resources {
            let Some(action_name) = self.extension.action_for_resource_type(entity_type) else {
                continue;
            };
            let mut entries = Vec::with_capacity(resource_ids.len());
            for resource_id in resource_ids {
                let uid = self
                    .extension
                    .build_resource_uid(tenant_id, entity_type, resource_id)?;
                let access = self.evaluate_resource(action_name, uid)?;
                entries.push((resource_id.clone(), access));
            }
            grants.insert(entity_type.clone(), entries);
        }

        self.extension.assemble_session(tenant_id, grants)
    }
}

// ---------------------------------------------------------------------------
// Residual condition extraction (extension-agnostic)
// ---------------------------------------------------------------------------

/// Extract condition bodies from a residual policy as a single merged JSON
/// value.
///
/// Returns `Ok(None)` if there are no conditions or all conditions are
/// trivially true. Returns the merged body for the extension to interpret.
fn extract_condition_body(policy: &cedar_policy::Policy) -> Result<Option<Value>, AuthError> {
    let json = policy
        .to_json()
        .map_err(|e| AuthError::PolicyFailed(format!("residual JSON error: {e}")))?;

    let conditions = match json.get("conditions") {
        Some(c) => c,
        None => return Ok(None),
    };
    let arr = match conditions.as_array() {
        Some(a) => a,
        None => return Ok(None),
    };

    let mut bodies = Vec::new();
    for cond in arr {
        if let Some(body) = cond.get("body") {
            // Skip trivially true conditions
            if body.get("Value").and_then(|v| v.as_bool()) == Some(true) {
                continue;
            }
            bodies.push(body.clone());
        }
    }

    match bodies.len() {
        0 => Ok(None),
        1 => Ok(Some(bodies.into_iter().next().unwrap())),
        _ => {
            // Merge multiple condition bodies into a single AND expression
            let mut result = bodies.pop().unwrap();
            for body in bodies.into_iter().rev() {
                result = serde_json::json!({
                    "&&": { "left": body, "right": result }
                });
            }
            Ok(Some(result))
        }
    }
}

// ---------------------------------------------------------------------------
// Role helpers
// ---------------------------------------------------------------------------

/// Build Cedar parent entity references for the user's roles, delegating UID
/// construction to the extension so consumers can choose their own role
/// hierarchy (per-tenant prefixed, flat namespace, etc.).
fn build_role_parents<E: PolicyExtension>(
    extension: &E,
    tenant_id: &str,
    roles: &[String],
) -> Result<Vec<Value>, AuthError> {
    roles
        .iter()
        .map(|role_name| {
            let uid = extension.build_role_uid(tenant_id, role_name)?;
            Ok(serde_json::json!({
                "type": uid.type_name().basename(),
                "id": uid.id().escaped()
            }))
        })
        .collect()
}
