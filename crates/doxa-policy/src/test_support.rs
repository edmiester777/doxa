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
        Ok(Vec::new())
    }
}

/// Build a router backed by the [`StubExtension`] and a [`StubStore`]
/// holding the supplied Cedar policy text.
pub(crate) fn build_stub_router(policy_text: &'static str) -> Arc<PolicyRouter<StubExtension>> {
    let store: SharedPolicyStore = Arc::new(StubStore { policy_text });
    Arc::new(PolicyRouter::new(store, StubExtension))
}

/// Build a router whose extension's `build_resource_uid` always fails.
pub(crate) fn build_failing_uid_router() -> Arc<PolicyRouter<FailingUidExtension>> {
    let store: SharedPolicyStore = Arc::new(StubStore { policy_text: "" });
    Arc::new(PolicyRouter::new(store, FailingUidExtension))
}
