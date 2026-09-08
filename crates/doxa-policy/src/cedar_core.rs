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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use cached::stores::TimedSizedCache;
use cached::Cached;
use cedar_policy::{Authorizer, Context, Decision, Entities, PolicySet, Request};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::error::AuthError;
use crate::extension::{PolicyExtension, ResourceAccess, ResourceGrants};
use crate::resource::ResourceEntity;
use crate::store::SharedPolicyStore;
use crate::uid::{action_uid, principal_uid};

// ---------------------------------------------------------------------------
// Cached store: pre-parsed Cedar artifacts loaded from a PolicyStore
// ---------------------------------------------------------------------------

/// Pre-parsed Cedar artifacts loaded from a
/// [`PolicyStore`](crate::store::PolicyStore) for a single tenant.
///
/// The [`policy_set`](CedarStore::policy_set) contains only policies belonging
/// to this tenant. The [`resources`](CedarStore::resources) map enumerates the
/// tenant's resources grouped by Cedar entity type, driving the per-session
/// evaluation loop.
///
/// ## Why the entities are held twice
///
/// [`entities`](CedarStore::entities) is the tenant's entity set already
/// parsed. Every check has to add a synthetic principal — and an instance
/// check its resource — so the set an evaluation runs against is never
/// exactly this one; but Cedar holds its entities behind [`Arc`], so
/// cloning this and adding two is a hash-map copy and a refcount bump per
/// entity, where re-parsing is a JSON deserialize plus an expression parse
/// per attribute. Building it once per tenant rather than once per check is
/// the difference between a lookup and a load.
///
/// [`entity_jsons`](CedarStore::entity_jsons) is kept for the one case that
/// cannot use the parsed set: a consumer that persists an entity for a
/// resource it *also* loads live has two entries for one UID, which Cedar
/// refuses. Folding them together is a merge of the raw JSON, so that path
/// still parses from scratch — and [`stored_uids`](CedarStore::stored_uids)
/// is what tells the two apart without a scan.
pub(crate) struct CedarStore {
    pub(crate) policy_set: PolicySet,
    pub(crate) entity_jsons: Vec<Value>,
    pub(crate) entities: Entities,
    pub(crate) stored_uids: HashSet<String>,
    pub(crate) resources: HashMap<String, Vec<String>>,
}

/// Default per-tenant cache TTL when no override is supplied.
pub const DEFAULT_TENANT_CACHE_TTL: Duration = Duration::from_secs(300);

/// Default number of tenants held at once.
///
/// Generous enough that a typical deployment never reaches it, and a
/// ceiling either way: a tenant's artifacts are held by the cache, so an
/// unbounded one grows with every tenant the process has ever served
/// rather than with the ones it is serving.
pub const DEFAULT_TENANT_CACHE_CAPACITY: usize = 1024;

// ---------------------------------------------------------------------------
// Tenant store cache — shareable between CedarPolicy and PolicyRouter
// ---------------------------------------------------------------------------

/// Shareable cache of per-tenant Cedar artifacts, bounded by both age and
/// count.
///
/// Construct via [`TenantStoreCache::with_ttl`],
/// [`with_capacity_and_ttl`](TenantStoreCache::with_capacity_and_ttl), or
/// [`Default`] for [`DEFAULT_TENANT_CACHE_TTL`] and
/// [`DEFAULT_TENANT_CACHE_CAPACITY`]. Cheap to clone — the inner state is
/// an [`Arc`], so a single cache can be shared across both
/// [`CedarPolicy`](crate::policy::cedar::CedarPolicy) and
/// [`PolicyRouter`](crate::router::PolicyRouter) to avoid double-loading
/// the same tenant through two different entry points.
///
/// Misses load through the supplied [`SharedPolicyStore`]; only successful
/// loads are cached so transient store errors are retried on the next
/// request.
///
/// ## What the bound is for
///
/// Expiry alone does not reclaim anything: nothing sweeps, so an entry is
/// only dropped when its key is next touched. A tenant seen once and
/// never again would be held for the life of the process. The count bound
/// evicts least-recently-used entries, so memory tracks the working set.
///
/// [`len`](Self::len) against [`capacity`](Self::capacity) is how you tell
/// whether the bound is biting — a cache pinned at capacity is evicting
/// tenants it is about to be asked for again, and wants raising.
///
/// ## One load per tenant
///
/// Concurrent misses for the same tenant wait for the first rather than
/// each running their own. A load is three round-trips to the store, so
/// without this a TTL expiry under load costs a burst of identical
/// queries — worst exactly when the process is busiest. Different tenants
/// still load concurrently.
#[derive(Clone)]
pub struct TenantStoreCache {
    inner: Arc<Mutex<TimedSizedCache<String, Arc<CedarStore>>>>,
    /// One gate per tenant currently being loaded, dropped as soon as
    /// nobody is waiting on it — so this tracks concurrent misses, not
    /// tenants.
    loading: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    ttl: Duration,
    capacity: usize,
}

impl TenantStoreCache {
    /// Build a cache with the given TTL and the default capacity.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self::with_capacity_and_ttl(DEFAULT_TENANT_CACHE_CAPACITY, ttl)
    }

    /// Build a cache holding at most `capacity` tenants, each for `ttl`.
    ///
    /// # Panics
    ///
    /// If `capacity` is zero. A cache that can hold nothing would reload
    /// the tenant on every request, which is never what was meant.
    pub fn with_capacity_and_ttl(capacity: usize, ttl: Duration) -> Self {
        assert!(
            capacity > 0,
            "a TenantStoreCache holding no tenants would reload on every request",
        );
        Self {
            inner: Arc::new(Mutex::new(TimedSizedCache::with_size_and_lifespan(
                capacity, ttl,
            ))),
            loading: Arc::new(Mutex::new(HashMap::new())),
            ttl,
            capacity,
        }
    }

    /// The TTL this cache was constructed with.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// The most tenants this cache will hold at once.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// How many tenants it is holding now, expired entries included —
    /// they occupy a slot until evicted.
    pub async fn len(&self) -> usize {
        self.inner.lock().await.cache_size()
    }

    /// Whether it is holding nothing.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Drop every entry.
    pub async fn flush(&self) {
        self.inner.lock().await.cache_clear();
    }

    /// Drop a single tenant's entry.
    pub async fn invalidate(&self, tenant_id: &str) {
        self.inner.lock().await.cache_remove(&tenant_id.to_string());
    }

    /// A live entry, if there is one. Never holds the lock across an
    /// await — a single mutex in front of every policy check must not be
    /// held over I/O.
    async fn get(&self, tenant_id: &str) -> Option<Arc<CedarStore>> {
        self.inner
            .lock()
            .await
            .cache_get(&tenant_id.to_string())
            .map(Arc::clone)
    }

    /// Look up (or load, on miss) the tenant's store.
    pub(crate) async fn get_or_load(
        &self,
        store: &SharedPolicyStore,
        tenant_id: &str,
    ) -> Result<Arc<CedarStore>, AuthError> {
        if let Some(hit) = self.get(tenant_id).await {
            return Ok(hit);
        }

        // Take this tenant's gate. Whoever gets it does the load; the
        // rest queue here rather than issuing their own.
        let gate = {
            let mut loading = self.loading.lock().await;
            Arc::clone(
                loading
                    .entry(tenant_id.to_owned())
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        let permit = gate.lock().await;

        let result = match self.get(tenant_id).await {
            // Someone loaded it while we queued, which is the whole
            // point — take theirs.
            Some(hit) => Ok(hit),
            None => match load_tenant_store(store, tenant_id).await {
                Ok(loaded) => {
                    self.inner
                        .lock()
                        .await
                        .cache_set(tenant_id.to_string(), Arc::clone(&loaded));
                    Ok(loaded)
                }
                // Deliberately not cached: a transient store failure
                // should be retried, not remembered.
                Err(error) => Err(error),
            },
        };

        drop(permit);
        self.retire(&gate, tenant_id).await;
        result
    }

    /// Drop a tenant's gate once nobody else holds it, so the map tracks
    /// in-flight loads rather than growing with every tenant ever seen.
    ///
    /// The count is only meaningful under the lock, which is also the
    /// only place a new reference can be taken: two means the map's and
    /// ours, so no waiter is left to hand it to.
    async fn retire(&self, gate: &Arc<Mutex<()>>, tenant_id: &str) {
        let mut loading = self.loading.lock().await;
        if Arc::strong_count(gate) <= 2 {
            loading.remove(tenant_id);
        }
    }
}

impl Default for TenantStoreCache {
    fn default() -> Self {
        Self::with_capacity_and_ttl(DEFAULT_TENANT_CACHE_CAPACITY, DEFAULT_TENANT_CACHE_TTL)
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

    // Parsed here rather than per check. `.partial()` so an absent entity
    // dereferences to a residual — see the note in `new_with_resources`,
    // which re-applies it after adding, so the property does not depend on
    // `add_entities` preserving the mode.
    let entities = Entities::from_json_value(Value::Array(entity_jsons.clone()), None)
        .map_err(|e| AuthError::PolicyFailed(format!("entity parse error: {e}")))?
        .partial();

    // Only the UIDs, and only to answer "does the store already hold this
    // one" in O(1) when a live resource is injected.
    let stored_uids = entity_jsons
        .iter()
        .filter_map(|entity| entity_uid_of(entity).ok())
        .map(|uid| uid.to_string())
        .collect();

    Ok(Arc::new(CedarStore {
        policy_set,
        entity_jsons,
        entities,
        stored_uids,
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
        Self::new_with_resource(store, tenant_id, roles, extension, None)
    }

    /// Build an evaluator with one ad-hoc resource entity in scope.
    ///
    /// The entity's UID is resolved through
    /// [`build_resource_uid`](PolicyExtension::build_resource_uid) — the
    /// same call the check itself makes — so the attributes land on
    /// exactly the UID the policy is evaluated against.
    pub(crate) fn new_with_resource(
        store: &'a CedarStore,
        tenant_id: &str,
        roles: &[String],
        extension: &'a E,
        resource: Option<&ResourceEntity>,
    ) -> Result<Self, AuthError> {
        let resources: Vec<&ResourceEntity> = resource.into_iter().collect();
        Self::new_with_resources(store, tenant_id, roles, extension, &resources)
    }

    /// Build an evaluator with several ad-hoc resource entities in scope.
    ///
    /// One entity set serves every one of them: a request naming twenty
    /// objects asks twenty questions of the *same* hierarchy, and building
    /// it per question is the cost that made a body-named reference
    /// expensive. Each check still names its own resource UID, so what the
    /// caller gets back is one decision per resource, not one for the set.
    pub(crate) fn new_with_resources(
        store: &'a CedarStore,
        tenant_id: &str,
        roles: &[String],
        extension: &'a E,
        resources: &[&ResourceEntity],
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

        let injected = resources
            .iter()
            .map(|resource| resource_entity_json(extension, tenant_id, resource))
            .collect::<Result<Vec<_>, _>>()?;

        // Cedar refuses two entries for one UID, so a resource the store
        // also persists has to be folded into the stored entry rather than
        // added beside it — and folding is a merge of the raw JSON. That is
        // the only case that re-parses; everything else clones the set the
        // tenant load already parsed.
        let overlaps = injected.iter().any(|entity| {
            entity_uid_of(entity).is_ok_and(|uid| store.stored_uids.contains(&uid.to_string()))
        });

        // `.partial()` makes an absent resource entity dereference to a Cedar
        // residual instead of erroring, so a `when { resource.<field> == … }`
        // clause survives partial evaluation as a residual the consumer can
        // translate into a row filter. Without it the residual branch of
        // `evaluate_resource` is unreachable — a missing entity errors and the
        // policy is dropped, collapsing every conditional grant to a denial.
        // Applied here rather than relied on from the cached set, so the
        // property holds however the set was assembled.
        let entities = if overlaps {
            let mut all_entities = store.entity_jsons.clone();
            all_entities.push(user_entity_json);
            for entity in injected {
                merge_resource_entity(&mut all_entities, entity)?;
            }
            Entities::from_json_value(Value::Array(all_entities), None)
                .map_err(|e| AuthError::PolicyFailed(format!("entity parse error: {e}")))?
                .partial()
        } else {
            let mut added = Vec::with_capacity(injected.len() + 1);
            added.push(user_entity_json);
            added.extend(injected);
            store
                .entities
                .clone()
                .add_entities_from_json_value(Value::Array(added), None)
                .map_err(|e| AuthError::PolicyFailed(format!("entity parse error: {e}")))?
                .partial()
        };

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
/// Render a [`ResourceEntity`] as Cedar entity JSON.
///
/// UIDs round-trip through [`EntityUid::to_json_value`] rather than
/// being rebuilt from `(type, id)` strings, so a namespaced type or an
/// id the extension rewrote still names the entity the check queries.
fn resource_entity_json<E: PolicyExtension>(
    extension: &E,
    tenant_id: &str,
    resource: &ResourceEntity,
) -> Result<Value, AuthError> {
    let uid_json = |ty: &str, id: &str| -> Result<Value, AuthError> {
        extension
            .build_resource_uid(tenant_id, ty, id)?
            .to_json_value()
            .map_err(|e| AuthError::PolicyFailed(format!("entity uid serialize error: {e}")))
    };

    let parents = resource
        .parents
        .iter()
        .map(|(ty, id)| uid_json(ty, id))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(serde_json::json!({
        "uid": uid_json(&resource.entity_type, &resource.entity_id)?,
        "attrs": Value::Object(resource.attrs.clone()),
        "parents": parents,
    }))
}

/// Add `injected` to `entities`, folding it into any stored entity that
/// already claims the same UID.
///
/// Cedar rejects two entries for one UID, so a consumer that persists an
/// entity for a resource it also loads live would otherwise get a policy
/// error instead of a decision. Live attributes win; parents are unioned
/// so the stored hierarchy (tenant membership, groups) still applies.
fn merge_resource_entity(entities: &mut Vec<Value>, injected: Value) -> Result<(), AuthError> {
    let uid = entity_uid_of(&injected)?;
    let stored = entities
        .iter()
        .position(|e| entity_uid_of(e).is_ok_and(|u| u == uid));

    match stored {
        Some(index) => entities[index] = merge_entity_json(&entities[index], &injected),
        None => entities.push(injected),
    }
    Ok(())
}

/// Parse the `uid` field of an entity JSON object.
fn entity_uid_of(entity: &Value) -> Result<cedar_policy::EntityUid, AuthError> {
    let uid = entity
        .get("uid")
        .ok_or_else(|| AuthError::PolicyFailed("entity json has no `uid`".into()))?;
    cedar_policy::EntityUid::from_json(uid.clone())
        .map_err(|e| AuthError::PolicyFailed(format!("entity uid parse error: {e}")))
}

/// Overlay `injected` onto `stored`: attributes are merged key-wise with
/// `injected` winning, parents are concatenated (Cedar collects them into
/// a set, so repeats collapse).
fn merge_entity_json(stored: &Value, injected: &Value) -> Value {
    let object = |v: &Value, key: &str| {
        v.get(key)
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default()
    };
    let array = |v: &Value, key: &str| {
        v.get(key)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };

    let mut attrs = object(stored, "attrs");
    attrs.extend(object(injected, "attrs"));

    let mut parents = array(stored, "parents");
    parents.extend(array(injected, "parents"));

    serde_json::json!({
        "uid": injected.get("uid").cloned().unwrap_or(Value::Null),
        "attrs": Value::Object(attrs),
        "parents": Value::Array(parents),
    })
}

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

#[cfg(test)]
mod cache_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use cedar_policy::PolicySet;

    use super::*;
    use crate::store::PolicyStore;

    /// A store that counts loads, and can be made slow so concurrent
    /// misses genuinely overlap.
    struct CountingStore {
        loads: AtomicUsize,
        delay: Duration,
        fail: bool,
    }

    impl CountingStore {
        fn new() -> Arc<Self> {
            Arc::new(CountingStore {
                loads: AtomicUsize::new(0),
                delay: Duration::ZERO,
                fail: false,
            })
        }

        fn slow(delay: Duration) -> Arc<Self> {
            Arc::new(CountingStore {
                loads: AtomicUsize::new(0),
                delay,
                fail: false,
            })
        }

        fn failing() -> Arc<Self> {
            Arc::new(CountingStore {
                loads: AtomicUsize::new(0),
                delay: Duration::ZERO,
                fail: true,
            })
        }

        fn loads(&self) -> usize {
            self.loads.load(Ordering::SeqCst)
        }

        async fn tick(&self) -> Result<(), AuthError> {
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            if self.fail {
                return Err(AuthError::PolicyFailed("store unavailable".into()));
            }
            Ok(())
        }
    }

    #[async_trait]
    impl PolicyStore for CountingStore {
        async fn list_resources(&self, _: &str) -> Result<HashMap<String, Vec<String>>, AuthError> {
            Ok(HashMap::new())
        }

        async fn load_policy_set(&self, _: &str) -> Result<PolicySet, AuthError> {
            // The first of the three calls, so it is the one that counts
            // a load and the one that fails.
            self.loads.fetch_add(1, Ordering::SeqCst);
            self.tick().await?;
            Ok(PolicySet::new())
        }

        async fn load_entity_jsons(&self, _: &str) -> Result<Vec<Value>, AuthError> {
            Ok(Vec::new())
        }
    }

    fn shared(store: &Arc<CountingStore>) -> SharedPolicyStore {
        Arc::clone(store) as SharedPolicyStore
    }

    #[tokio::test]
    async fn a_hit_does_not_reach_the_store() {
        let store = CountingStore::new();
        let cache = TenantStoreCache::default();

        for _ in 0..5 {
            cache.get_or_load(&shared(&store), "acme").await.unwrap();
        }

        assert_eq!(store.loads(), 1);
        assert_eq!(cache.len().await, 1);
    }

    /// The bound is the point: an unbounded cache holds every tenant the
    /// process has ever served, because nothing sweeps expired entries.
    #[tokio::test]
    async fn the_capacity_bound_evicts() {
        let store = CountingStore::new();
        let cache = TenantStoreCache::with_capacity_and_ttl(2, Duration::from_secs(300));

        for tenant in ["a", "b", "c", "d"] {
            cache.get_or_load(&shared(&store), tenant).await.unwrap();
        }

        assert_eq!(cache.capacity(), 2);
        assert!(cache.len().await <= 2, "held more than it was allowed");
        assert_eq!(store.loads(), 4);

        // `a` was evicted, so it loads again rather than being served
        // stale.
        cache.get_or_load(&shared(&store), "a").await.unwrap();
        assert_eq!(store.loads(), 5);
    }

    #[tokio::test]
    async fn an_expired_entry_reloads() {
        let store = CountingStore::new();
        let cache = TenantStoreCache::with_capacity_and_ttl(8, Duration::from_millis(30));

        cache.get_or_load(&shared(&store), "acme").await.unwrap();
        assert_eq!(store.loads(), 1);

        tokio::time::sleep(Duration::from_millis(60)).await;

        cache.get_or_load(&shared(&store), "acme").await.unwrap();
        assert_eq!(store.loads(), 2);
    }

    /// A load is three round-trips to the store. Without the gate, a TTL
    /// expiry under load costs one burst of those per concurrent
    /// request — worst exactly when the process is busiest.
    #[tokio::test]
    async fn concurrent_misses_load_once() {
        let store = CountingStore::slow(Duration::from_millis(50));
        let cache = TenantStoreCache::default();

        let waiters: Vec<_> = (0..16)
            .map(|_| {
                let cache = cache.clone();
                let store = shared(&store);
                tokio::spawn(async move { cache.get_or_load(&store, "acme").await.map(|_| ()) })
            })
            .collect();

        for waiter in waiters {
            waiter.await.unwrap().unwrap();
        }

        assert_eq!(store.loads(), 1, "one loader, fifteen waiters");
    }

    /// Different tenants must not queue behind each other — the gate is
    /// per tenant, not one lock over the cache.
    #[tokio::test]
    async fn different_tenants_still_load_concurrently() {
        let store = CountingStore::slow(Duration::from_millis(50));
        let cache = TenantStoreCache::default();

        let started = std::time::Instant::now();
        let waiters: Vec<_> = ["a", "b", "c", "d"]
            .into_iter()
            .map(|tenant| {
                let cache = cache.clone();
                let store = shared(&store);
                tokio::spawn(async move { cache.get_or_load(&store, tenant).await.map(|_| ()) })
            })
            .collect();

        for waiter in waiters {
            waiter.await.unwrap().unwrap();
        }

        assert_eq!(store.loads(), 4);
        assert!(
            started.elapsed() < Duration::from_millis(150),
            "four 50ms loads took {:?} — they serialized",
            started.elapsed(),
        );
    }

    /// The gate map tracks in-flight loads. If it were keyed by tenant
    /// for the life of the process it would be the unbounded growth the
    /// capacity bound exists to prevent, moved one map across.
    #[tokio::test]
    async fn the_gate_map_does_not_grow_with_tenants() {
        let store = CountingStore::new();
        let cache = TenantStoreCache::default();

        for tenant in ["a", "b", "c", "d", "e"] {
            cache.get_or_load(&shared(&store), tenant).await.unwrap();
        }

        assert!(
            cache.loading.lock().await.is_empty(),
            "gates outlived their loads",
        );
    }

    /// A transient store failure is retried rather than remembered, and
    /// takes its gate with it.
    #[tokio::test]
    async fn a_failed_load_is_not_cached() {
        let store = CountingStore::failing();
        let cache = TenantStoreCache::default();

        assert!(cache.get_or_load(&shared(&store), "acme").await.is_err());
        assert!(cache.get_or_load(&shared(&store), "acme").await.is_err());

        assert_eq!(store.loads(), 2, "the failure was cached");
        assert!(cache.is_empty().await);
        assert!(cache.loading.lock().await.is_empty());
    }

    #[tokio::test]
    async fn invalidate_drops_one_tenant_and_flush_drops_all() {
        let store = CountingStore::new();
        let cache = TenantStoreCache::default();

        cache.get_or_load(&shared(&store), "a").await.unwrap();
        cache.get_or_load(&shared(&store), "b").await.unwrap();
        assert_eq!(cache.len().await, 2);

        cache.invalidate("a").await;
        assert_eq!(cache.len().await, 1);

        cache.flush().await;
        assert!(cache.is_empty().await);
    }

    #[test]
    #[should_panic(expected = "reload on every request")]
    fn a_zero_capacity_cache_is_refused() {
        let _ = TenantStoreCache::with_capacity_and_ttl(0, DEFAULT_TENANT_CACHE_TTL);
    }
}
