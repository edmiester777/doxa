//! Shared test fixtures for `router`, `http`, and capability tests.
//!
//! Gated on `cfg(test)` so they never appear in non-test builds. The
//! stubs intentionally model the smallest possible [`PolicyExtension`]
//! and [`PolicyStore`] — they care only about routing decisions, not
//! per-resource attributes — so a single set of fixtures works for every
//! suite that needs to spin up a [`PolicyRouter`].

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use cedar_policy::{EntityUid, PolicySet};
use serde_json::Value;

use crate::error::AuthError;
use crate::extension::{PolicyExtension, ResourceGrants};
use crate::router::PolicyRouter;
use crate::store::{PolicyStore, SharedPolicyStore};
use crate::uid::build_uid;

/// Minimal `PolicyExtension` impl for routing/capability tests.
///
/// Returns `()` for both associated types — the suites that use this
/// stub care only about whether decisions are `Allow` / `Deny`, not what
/// per-resource data the extension would extract.
pub(crate) struct StubExtension;

impl PolicyExtension for StubExtension {
    type ResourceAttrs = ();
    type SessionOutput = ();

    fn extract_allowed_attrs(
        &self,
        _: &cedar_policy::Policy,
    ) -> Result<Self::ResourceAttrs, AuthError> {
        Ok(())
    }
    fn extract_residual_attrs(
        &self,
        _: &cedar_policy::Policy,
        _: Option<&Value>,
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
        _tenant: &str,
        entity_type: &str,
        resource_id: &str,
    ) -> Result<EntityUid, AuthError> {
        build_uid(entity_type, resource_id)
    }
    fn build_role_uid(&self, _tenant: &str, role_name: &str) -> Result<EntityUid, AuthError> {
        build_uid("Role", role_name)
    }
    fn assemble_session(
        &self,
        _: &str,
        _: ResourceGrants<Self::ResourceAttrs>,
    ) -> Result<Self::SessionOutput, AuthError> {
        Ok(())
    }
    fn deny_all(&self) -> Self::SessionOutput {}
    fn admin_session(&self) -> Result<Self::SessionOutput, AuthError> {
        Ok(())
    }
}

/// Variant of [`StubExtension`] whose `build_resource_uid` always fails.
///
/// Used to verify that capability evaluation propagates UID-construction
/// errors through `?` rather than swallowing them.
pub(crate) struct FailingUidExtension;

impl PolicyExtension for FailingUidExtension {
    type ResourceAttrs = ();
    type SessionOutput = ();

    fn extract_allowed_attrs(
        &self,
        _: &cedar_policy::Policy,
    ) -> Result<Self::ResourceAttrs, AuthError> {
        Ok(())
    }
    fn extract_residual_attrs(
        &self,
        _: &cedar_policy::Policy,
        _: Option<&Value>,
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
        _tenant: &str,
        _entity_type: &str,
        _resource_id: &str,
    ) -> Result<EntityUid, AuthError> {
        Err(AuthError::PolicyFailed("forced uid failure".into()))
    }
    fn build_role_uid(&self, _tenant: &str, role_name: &str) -> Result<EntityUid, AuthError> {
        build_uid("Role", role_name)
    }
    fn assemble_session(
        &self,
        _: &str,
        _: ResourceGrants<Self::ResourceAttrs>,
    ) -> Result<Self::SessionOutput, AuthError> {
        Ok(())
    }
    fn deny_all(&self) -> Self::SessionOutput {}
    fn admin_session(&self) -> Result<Self::SessionOutput, AuthError> {
        Ok(())
    }
}

/// In-memory `PolicyStore` returning a fixed Cedar policy text. An empty
/// policy set means Cedar denies every request by default.
pub(crate) struct StubStore {
    pub policy_text: &'static str,
    /// Persisted entities, as a consumer's own store would return them.
    pub entities: Vec<Value>,
}

#[async_trait]
impl PolicyStore for StubStore {
    async fn list_resources(&self, _: &str) -> Result<HashMap<String, Vec<String>>, AuthError> {
        Ok(HashMap::new())
    }
    async fn load_policy_set(&self, _: &str) -> Result<PolicySet, AuthError> {
        if self.policy_text.trim().is_empty() {
            Ok(PolicySet::new())
        } else {
            self.policy_text
                .parse()
                .map_err(|e| AuthError::PolicyFailed(format!("test parse: {e}")))
        }
    }
    async fn load_entity_jsons(&self, _: &str) -> Result<Vec<Value>, AuthError> {
        Ok(self.entities.clone())
    }
}

/// Build a router backed by the [`StubExtension`] and a [`StubStore`]
/// holding the supplied Cedar policy text.
pub(crate) fn build_stub_router(policy_text: &'static str) -> Arc<PolicyRouter<StubExtension>> {
    build_stub_router_with_entities(policy_text, Vec::new())
}

/// Variant whose store also persists `entities`, for the case where a
/// stored entity and a live instance check name the same UID.
pub(crate) fn build_stub_router_with_entities(
    policy_text: &'static str,
    entities: Vec<Value>,
) -> Arc<PolicyRouter<StubExtension>> {
    let store: SharedPolicyStore = Arc::new(StubStore {
        policy_text,
        entities,
    });
    Arc::new(PolicyRouter::new(store, StubExtension))
}

/// What a resolved session holds, for the [`SessionChecker`] suite.
///
/// [`SessionExtension`] enumerates exactly one action — `read_widget` —
/// which is what makes the fall-through case testable: any other action is
/// one the session never recorded, so it has to reach the policy.
///
/// [`SessionChecker`]: crate::session::SessionChecker
#[derive(Clone, Default)]
pub(crate) struct SessionFlags {
    /// Bypasses the policy entirely, as an administrator's session does.
    pub is_admin: bool,
    /// Widget ids the session recorded a `read_widget` grant for.
    pub allowed: Vec<String>,
    /// Tenant the session was resolved under, when the session is the
    /// authority for it.
    pub tenant: Option<String>,
}

/// Extension whose session is a decision rather than a description —
/// the shape [`SessionChecker`](crate::session::SessionChecker) exists for.
pub(crate) struct SessionExtension;

impl PolicyExtension for SessionExtension {
    type ResourceAttrs = ();
    type SessionOutput = SessionFlags;

    fn extract_allowed_attrs(
        &self,
        _: &cedar_policy::Policy,
    ) -> Result<Self::ResourceAttrs, AuthError> {
        Ok(())
    }
    fn extract_residual_attrs(
        &self,
        _: &cedar_policy::Policy,
        _: Option<&Value>,
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
        _tenant: &str,
        entity_type: &str,
        resource_id: &str,
    ) -> Result<EntityUid, AuthError> {
        build_uid(entity_type, resource_id)
    }
    fn build_role_uid(&self, _tenant: &str, role_name: &str) -> Result<EntityUid, AuthError> {
        build_uid("Role", role_name)
    }
    fn assemble_session(
        &self,
        _: &str,
        _: ResourceGrants<Self::ResourceAttrs>,
    ) -> Result<Self::SessionOutput, AuthError> {
        Ok(SessionFlags::default())
    }
    fn deny_all(&self) -> Self::SessionOutput {
        SessionFlags::default()
    }
    fn admin_session(&self) -> Result<Self::SessionOutput, AuthError> {
        Ok(SessionFlags {
            is_admin: true,
            ..SessionFlags::default()
        })
    }

    fn session_is_admin(&self, session: &Self::SessionOutput) -> bool {
        session.is_admin
    }

    fn decide_from_session(
        &self,
        session: &Self::SessionOutput,
        action: &str,
        resource: &crate::ResourceEntity,
    ) -> Option<bool> {
        // Only the pair `assemble_session` would have enumerated. Anything
        // else is `None`, and reaches the policy.
        (action == "read_widget" && resource.entity_type == "Widget")
            .then(|| session.allowed.iter().any(|id| id == &resource.entity_id))
    }

    fn session_tenant<'a>(&self, session: &'a Self::SessionOutput) -> Option<&'a str> {
        session.tenant.as_deref()
    }
}

/// A [`SessionExtension`] router over a permit-everything policy, so a
/// check that reaches the policy is allowed and one refused by the session
/// is visibly the session's doing.
pub(crate) fn session_extension_router() -> PolicyRouter<SessionExtension> {
    let store: SharedPolicyStore = Arc::new(StubStore {
        policy_text: "permit(principal, action, resource);",
        entities: Vec::new(),
    });
    PolicyRouter::new(store, SessionExtension)
}

/// Build a router whose extension's `build_resource_uid` always fails.
pub(crate) fn build_failing_uid_router() -> Arc<PolicyRouter<FailingUidExtension>> {
    let store: SharedPolicyStore = Arc::new(StubStore {
        policy_text: "",
        entities: Vec::new(),
    });
    Arc::new(PolicyRouter::new(store, FailingUidExtension))
}
