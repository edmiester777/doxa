//! Policy extension trait for customizing post-Cedar-evaluation behavior.
//!
//! After Cedar evaluates a request and returns Allow/Deny/Residual, consumers
//! need to extract domain-specific data from the result. The
//! [`PolicyExtension`] trait parameterizes this post-evaluation step —
//! different consumers extract different annotations, translate residuals to
//! different predicate types, and assemble different session output types.
//!
//! ## Extension Points
//!
//! | Method | Purpose |
//! |--------|---------|
//! | [`PolicyExtension::extract_allowed_attrs`] | Read annotations from definitively-satisfied policies |
//! | [`PolicyExtension::extract_residual_attrs`] | Interpret `when` clause residuals (Cedar JSON EST) |
//! | [`PolicyExtension::merge_resource_attrs`] | Combine attributes from multiple policies on one resource |
//! | [`PolicyExtension::assemble_session`] | Build the final session output from per-resource results |
//!
//! ## Resource Access
//!
//! [`ResourceAccess`] is the per-resource authorization result — either
//! [`Allowed`](ResourceAccess::Allowed) with extension-defined attributes or
//! [`Denied`](ResourceAccess::Denied).

use std::collections::HashMap;

use serde_json::Value;

use crate::error::AuthError;

/// Result of authorizing a single resource, parameterized by extension
/// attributes.
///
/// Returned by the Cedar evaluator for each resource. The `A` type parameter
/// holds consumer-defined attributes extracted from satisfied and residual
/// policies (e.g., hidden fields + forced filters for a query engine, rate
/// limits for an API gateway, feature flags for a feature-flag service).
#[derive(Debug, Clone)]
pub enum ResourceAccess<A> {
    /// Access granted with extension-defined attributes.
    Allowed(A),
    /// Access denied.
    Denied,
}

/// Per-resource grant collection passed to
/// [`PolicyExtension::assemble_session`].
///
/// Outer key is the Cedar entity type (`"Model"`, `"Source"`, `"Document"`,
/// `"Feature"` — whatever the consumer's schema declares). Each entry is a
/// list of `(resource_id, ResourceAccess)` pairs for that type.
pub type ResourceGrants<A> = HashMap<String, Vec<(String, ResourceAccess<A>)>>;

/// Extension point for customizing what happens after Cedar evaluation.
///
/// Consumers implement this trait to control:
/// - What data is extracted from policy annotations (e.g., `@hidden_fields`,
///   `@rate_limit`, `@features`)
/// - How Cedar residual conditions are translated (e.g., to SQL filters,
///   Elasticsearch queries, or ignored entirely)
/// - What per-resource and per-session output types are produced
///
/// # Associated Types
///
/// - [`ResourceAttrs`](PolicyExtension::ResourceAttrs): Per-resource data
///   extracted from Cedar policies (annotations + residual translations)
/// - [`SessionOutput`](PolicyExtension::SessionOutput): Final session-level
///   output assembled from all per-resource results
///
/// # Residual Handling
///
/// When a Cedar policy has a `when` clause that cannot be fully evaluated
/// at authorization time (because it references runtime context), Cedar
/// produces a **residual** — a partially-evaluated condition in JSON EST
/// format. The
/// [`extract_residual_attrs`](PolicyExtension::extract_residual_attrs)
/// method receives this raw JSON so the consumer can translate it to their
/// domain-specific predicate type.
///
/// For example, given a policy:
/// ```cedar
/// permit(...) when { resource.region == principal.region };
/// ```
///
/// The residual body might be:
/// ```json
/// {"==": {"left": {".": {"left": {"Var": "resource"}, "attr": "region"}}, "right": {"Value": "US"}}}
/// ```
///
/// A query engine consumer might translate this to a SQL `WHERE` clause.
/// An Elasticsearch consumer might translate it to a `term` query.
/// A rate-limiting consumer might ignore it entirely.
pub trait PolicyExtension: Send + Sync {
    /// Per-resource attributes extracted from satisfied/residual policies.
    ///
    /// This type holds whatever the consumer needs from each authorized
    /// resource — hidden fields, forced filters, rate limits, feature flags,
    /// etc.
    type ResourceAttrs: Send + Sync + Clone;

    /// Final session output assembled from all per-resource results.
    ///
    /// This is the top-level type returned by
    /// [`Policy::resolve`](crate::policy::Policy::resolve).
    type SessionOutput: Send + Sync + Clone;

    /// The Cedar action name to use when evaluating each resource type.
    ///
    /// Returns `None` to skip evaluation of that resource type entirely.
    /// The default implementation returns `Some("query")` for all types,
    /// matching the most common case (read-only resource gating).
    fn action_for_resource_type(&self, _entity_type: &str) -> Option<&'static str> {
        Some("query")
    }

    /// Extract attributes from a definitively-satisfied policy.
    ///
    /// Called once per policy in Cedar's `definitely_satisfied()` set — these
    /// are policies where the decision is concrete `Allow` with no residual
    /// conditions.
    fn extract_allowed_attrs(
        &self,
        policy: &cedar_policy::Policy,
    ) -> Result<Self::ResourceAttrs, AuthError>;

    /// Extract attributes from a residual (conditionally-satisfied) policy.
    ///
    /// Called once per policy in Cedar's `nontrivial_residuals()` set.
    /// `condition_body` is the JSON EST body from the policy's `when` clause
    /// after partial evaluation. Consumers translate this to their own
    /// predicate type or ignore it.
    ///
    /// Returns `Err` if the residual contains expressions the consumer
    /// cannot handle (fail-safe denial).
    fn extract_residual_attrs(
        &self,
        policy: &cedar_policy::Policy,
        condition_body: Option<&Value>,
    ) -> Result<Self::ResourceAttrs, AuthError>;

    /// Merge attributes from multiple policies contributing to one resource.
    ///
    /// When multiple policies grant access to the same resource (e.g., one
    /// from a role grant and one from a direct grant), their attributes are
    /// collected and merged via this method.
    fn merge_resource_attrs(
        &self,
        attrs: Vec<Self::ResourceAttrs>,
    ) -> Result<Self::ResourceAttrs, AuthError>;

    /// Build a Cedar [`EntityUid`](cedar_policy::EntityUid) for the given
    /// `(entity_type, resource_id)` pair.
    ///
    /// Consumers control how their resource ids are mapped into Cedar's
    /// hierarchical UID space — for example, a tenant-scoped extension
    /// might use `{tenant_id}::{resource_name}` while a flat-namespace
    /// extension might use just `{resource_id}`.
    fn build_resource_uid(
        &self,
        tenant_id: &str,
        entity_type: &str,
        resource_id: &str,
    ) -> Result<cedar_policy::EntityUid, AuthError>;

    /// Build the parent `EntityUid` list for a given role on the given
    /// tenant. The Cedar evaluator uses this to construct the synthetic
    /// per-request user entity's role parents.
    fn build_role_uid(
        &self,
        tenant_id: &str,
        role_name: &str,
    ) -> Result<cedar_policy::EntityUid, AuthError>;

    /// Assemble the final session output from per-resource results.
    ///
    /// `grants` is keyed by Cedar entity type, with each entry holding the
    /// list of `(resource_id, access)` pairs for that type. Consumers read
    /// whichever entity types they care about (e.g. a document service
    /// reads `grants["Document"]` and `grants["Folder"]`) and produce their
    /// service-specific session output.
    fn assemble_session(
        &self,
        tenant_id: &str,
        grants: ResourceGrants<Self::ResourceAttrs>,
    ) -> Result<Self::SessionOutput, AuthError>;

    /// Build a deny-all session output (empty allowlists, no grants).
    fn deny_all(&self) -> Self::SessionOutput;

    /// Build an unrestricted admin session output.
    fn admin_session(&self) -> Result<Self::SessionOutput, AuthError>;

    /// Cedar entity type used for the synthetic per-request principal.
    ///
    /// The Cedar evaluator constructs a synthetic principal entity on each
    /// request and attaches the caller's roles as its parents. The returned
    /// value is used verbatim as the entity type portion of the principal's
    /// Cedar [`EntityUid`](cedar_policy::EntityUid) (e.g. `User::"..."`).
    ///
    /// Default: `"User"`. Override if your policy schema uses a different
    /// principal type name (for example `"Principal"`, or a namespaced
    /// type).
    fn principal_entity_type(&self) -> &'static str {
        "User"
    }

    /// Cedar entity type used for action UIDs.
    ///
    /// Default: `"Action"`. Override if your policy schema namespaces
    /// actions (e.g. `"Svc::Action"`) or uses a different convention.
    fn action_entity_type(&self) -> &'static str {
        "Action"
    }

    /// Cedar entity id used for the synthetic per-request principal.
    ///
    /// Combined with [`principal_entity_type`](Self::principal_entity_type)
    /// to form the full Cedar UID (e.g. `User::"_session"`). Most
    /// deployments can leave this at its default; override if the id
    /// collides with real principals in your schema.
    ///
    /// Default: `"_session"`.
    fn synthetic_principal_id(&self) -> &'static str {
        "_session"
    }

    /// Whether the given role name should short-circuit Cedar evaluation
    /// and produce an admin session via [`admin_session`](Self::admin_session).
    ///
    /// The Cedar policy implementation calls this for each role on the
    /// principal; if any match, evaluation is skipped and
    /// `admin_session()` is returned directly.
    ///
    /// Default: exact match on `"admin"`. Override to recognize role
    /// conventions like `"system:admin"`, `"ROLE_ADMIN"`, or SCIM group
    /// names, or to disable the fast path entirely by always returning
    /// `false`.
    fn is_admin_role(&self, role: &str) -> bool {
        role == "admin"
    }
}
