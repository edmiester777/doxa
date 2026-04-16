//! Pluggable storage backend for Cedar policies and entities.
//!
//! [`PolicyStore`] decouples [`CedarPolicy`](crate::policy::cedar::CedarPolicy)
//! and [`PolicyRouter`](crate::router::PolicyRouter) from any specific
//! persistence layer. Implementations may load policies from a relational
//! database, an in-memory map, an HTTP control plane, an S3 bucket, or any
//! other backend that can produce a tenant-scoped [`cedar_policy::PolicySet`]
//! and entity hierarchy.
//!
//! ## Tenant Resources
//!
//! [`PolicyStore::list_resources`] returns a [`HashMap`] keyed by Cedar entity
//! type (e.g. `"Document"`, `"Folder"`, `"User"`, `"Organization"` — whatever
//! resource taxonomy the consumer's schema declares). The Cedar evaluator
//! iterates this map when assembling a session, evaluating each
//! `(entity_type, resource_id)` pair against the loaded policy set. The
//! taxonomy is **not** baked into this crate — consumers may declare any set
//! of entity types they like and the engine will faithfully evaluate them.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use cedar_policy::PolicySet;
use serde_json::Value;

use crate::error::AuthError;

/// A pluggable backend that supplies Cedar policies and entities for a
/// single tenant.
///
/// Implementations are expected to be cheap to clone (typically wrapping an
/// `Arc` of internal state) and safe to call concurrently. The Cedar
/// evaluator caches the loaded artifacts per tenant, so each method should
/// perform the underlying I/O at most once per cache window.
///
/// # Example: in-memory store
///
/// ```ignore
/// use std::collections::HashMap;
/// use std::sync::Arc;
/// use cedar_policy::PolicySet;
/// use doxa_policy::store::PolicyStore;
/// use doxa_policy::AuthError;
///
/// pub struct InMemoryStore {
///     policies: PolicySet,
///     entities: Vec<serde_json::Value>,
///     resources: HashMap<String, Vec<String>>,
/// }
///
/// #[async_trait::async_trait]
/// impl PolicyStore for InMemoryStore {
///     async fn list_resources(&self, _tenant_id: &str)
///         -> Result<HashMap<String, Vec<String>>, AuthError>
///     { Ok(self.resources.clone()) }
///
///     async fn load_policy_set(&self, _tenant_id: &str)
///         -> Result<PolicySet, AuthError>
///     { Ok(self.policies.clone()) }
///
///     async fn load_entity_jsons(&self, _tenant_id: &str)
///         -> Result<Vec<serde_json::Value>, AuthError>
///     { Ok(self.entities.clone()) }
/// }
/// ```
#[async_trait]
pub trait PolicyStore: Send + Sync {
    /// Enumerate every resource the tenant owns, grouped by Cedar entity type.
    ///
    /// The outer key is the Cedar entity type (`"Document"`, `"Folder"`,
    /// `"User"`, …). The inner [`Vec`] holds the resource ids of that
    /// type. The Cedar evaluator iterates this map and evaluates each
    /// `(entity_type, id)` pair when assembling a session.
    ///
    /// Returning an empty map means "this tenant has no resources" — the
    /// resulting session will be empty (no allowed resources).
    async fn list_resources(
        &self,
        tenant_id: &str,
    ) -> Result<HashMap<String, Vec<String>>, AuthError>;

    /// Load every Cedar policy that applies to this tenant, parsed into a
    /// single [`PolicySet`].
    ///
    /// Implementations are responsible for combining tenant-scoped and
    /// system-wide policies into one set. Parse errors should be surfaced
    /// as [`AuthError::PolicyFailed`].
    async fn load_policy_set(&self, tenant_id: &str) -> Result<PolicySet, AuthError>;

    /// Load the raw Cedar entity JSON documents that apply to this tenant.
    ///
    /// Each entry is a Cedar entity in the standard JSON entity format:
    /// `{ "uid": ..., "attrs": {...}, "parents": [...] }`. The evaluator
    /// prepends a synthetic per-request user entity before parsing the full
    /// set into [`cedar_policy::Entities`].
    async fn load_entity_jsons(&self, tenant_id: &str) -> Result<Vec<Value>, AuthError>;
}

/// Convenience alias for the trait object form, since most consumers store a
/// store behind an [`Arc`] for sharing across tasks.
pub type SharedPolicyStore = Arc<dyn PolicyStore>;
