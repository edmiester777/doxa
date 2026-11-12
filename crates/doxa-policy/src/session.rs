//! [`SessionChecker`]: the guard's checker, answering from the caller's assembled session where
//! the extension's [`session_is_admin`] or [`decide_from_session`] can, else the router.
//!
//! ```ignore
//! let checker = SessionChecker::new(Arc::clone(&router), session.clone());
//! request.extensions_mut().insert(checker.into_extension());
//! ```
//!
//! [`session_is_admin`]: PolicyExtension::session_is_admin
//! [`decide_from_session`]: PolicyExtension::decide_from_session

use std::sync::Arc;

use crate::capability::{Capability, CapabilityChecker};
use crate::error::AuthError;
use crate::extension::PolicyExtension;
use crate::resource::ResourceEntity;
use crate::router::PolicyRouter;

/// A shared [`PolicyRouter`] bound to one caller's session. Asks admin, then the session's
/// verdict (instance checks only), then refuses an empty tenant, then the router.
pub struct SessionChecker<E: PolicyExtension> {
    router: Arc<PolicyRouter<E>>,
    session: E::SessionOutput,
}

impl<E: PolicyExtension + 'static> SessionChecker<E> {
    /// Bind `router` to the session resolved for this request.
    pub fn new(router: Arc<PolicyRouter<E>>, session: E::SessionOutput) -> Self {
        Self { router, session }
    }

    /// The session this checker answers from.
    pub fn session(&self) -> &E::SessionOutput {
        &self.session
    }

    /// Erase to the trait object a guard reads out of request extensions.
    pub fn into_extension(self) -> Arc<dyn CapabilityChecker> {
        Arc::new(self)
    }
}

#[async_trait::async_trait]
impl<E: PolicyExtension + 'static> CapabilityChecker for SessionChecker<E> {
    async fn check(
        &self,
        tenant_id: &str,
        roles: &[String],
        cap: &Capability,
    ) -> Result<bool, AuthError> {
        if self.router.extension().session_is_admin(&self.session) {
            return Ok(true);
        }
        // A capability isn't a resource the session enumerated, so no `decide_from_session`.
        if tenant_id.is_empty() {
            return Ok(false);
        }
        self.router.check_capability(tenant_id, roles, cap).await
    }

    async fn check_instance(
        &self,
        tenant_id: &str,
        roles: &[String],
        action: &str,
        resource: &ResourceEntity,
    ) -> Result<bool, AuthError> {
        let extension = self.router.extension();
        if extension.session_is_admin(&self.session) {
            return Ok(true);
        }
        if let Some(decided) = extension.decide_from_session(&self.session, action, resource) {
            return Ok(decided);
        }
        if tenant_id.is_empty() {
            return Ok(false);
        }
        Ok(self
            .router
            .check_instance(tenant_id, roles, action, resource)
            .await?
            .allowed)
    }

    /// What the session knows is filled in; the rest reaches the router as one batch.
    async fn check_instance_many(
        &self,
        tenant_id: &str,
        roles: &[String],
        action: &str,
        resources: &[ResourceEntity],
    ) -> Result<Vec<bool>, AuthError> {
        let extension = self.router.extension();
        if extension.session_is_admin(&self.session) {
            return Ok(vec![true; resources.len()]);
        }

        let mut answers: Vec<Option<bool>> = resources
            .iter()
            .map(|resource| extension.decide_from_session(&self.session, action, resource))
            .collect();

        let pending: Vec<ResourceEntity> = resources
            .iter()
            .zip(&answers)
            .filter(|(_, answered)| answered.is_none())
            .map(|(resource, _)| resource.clone())
            .collect();

        if !pending.is_empty() {
            let decided = if tenant_id.is_empty() {
                vec![false; pending.len()]
            } else {
                self.router
                    .check_instance_many(tenant_id, roles, action, &pending)
                    .await?
                    .into_iter()
                    .map(|decision| decision.allowed)
                    .collect()
            };
            let mut decided = decided.into_iter();
            for answer in answers.iter_mut() {
                if answer.is_none() {
                    *answer = decided.next();
                }
            }
        }

        // Every slot is filled; a surviving `None` refuses rather than grants.
        Ok(answers
            .into_iter()
            .map(|answer| answer.unwrap_or(false))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{CapabilityCheck, ResourceId};
    use crate::test_support::{session_extension_router, SessionFlags};

    const READ: Capability = Capability {
        name: "widgets.read",
        description: "read widgets",
        checks: &[CapabilityCheck {
            action: "read_widget",
            entity_type: "Widget",
            entity_id: ResourceId::Literal("collection"),
        }],
    };

    fn widget(id: &str) -> ResourceEntity {
        ResourceEntity::new("Widget", id)
    }

    fn checker(flags: SessionFlags) -> SessionChecker<crate::test_support::SessionExtension> {
        SessionChecker::new(Arc::new(session_extension_router()), flags)
    }

    /// The shortcut the trait signature could not carry: an admin session
    /// is allowed without a tenant and without a policy call.
    #[tokio::test]
    async fn an_admin_session_is_allowed_before_anything_else() {
        let checker = checker(SessionFlags {
            is_admin: true,
            ..SessionFlags::default()
        });

        assert!(checker.check("", &[], &READ).await.expect("checker ok"));
        assert!(checker
            .check_instance("", &[], "read_widget", &widget("w-1"))
            .await
            .expect("checker ok"));
    }

    /// The session's refusal stands even though the stub policy permits everything.
    #[tokio::test]
    async fn the_sessions_own_verdict_answers_without_the_policy() {
        let checker = checker(SessionFlags {
            allowed: vec!["w-1".into()],
            ..SessionFlags::default()
        });

        assert!(checker
            .check_instance("acme", &[], "read_widget", &widget("w-1"))
            .await
            .expect("checker ok"));
        assert!(!checker
            .check_instance("acme", &[], "read_widget", &widget("w-2"))
            .await
            .expect("checker ok"));
    }

    #[tokio::test]
    async fn an_unenumerated_action_reaches_the_policy() {
        let checker = checker(SessionFlags {
            allowed: vec!["w-1".into()],
            ..SessionFlags::default()
        });

        assert!(
            checker
                .check_instance("acme", &[], "write_widget", &widget("w-2"))
                .await
                .expect("checker ok"),
            "the stub policy permits everything it is actually asked",
        );
    }

    /// Without a tenant there is nothing to evaluate against, and a
    /// non-admin caller is refused rather than evaluated against no tenant.
    #[tokio::test]
    async fn a_tenantless_non_admin_is_refused() {
        let checker = checker(SessionFlags::default());

        assert!(!checker.check("", &[], &READ).await.expect("checker ok"));
        assert!(!checker
            .check_instance("", &[], "write_widget", &widget("w-1"))
            .await
            .expect("checker ok"));
    }

    /// Refused without a tenant however much the session holds.
    #[tokio::test]
    async fn a_populated_session_does_not_supply_a_missing_tenant() {
        let checker = checker(SessionFlags {
            allowed: vec!["w-1".into()],
            ..SessionFlags::default()
        });

        assert!(
            !checker
                .check_instance("", &[], "write_widget", &widget("w-1"))
                .await
                .expect("checker ok"),
            "an absent tenant is a refusal, not something the session fills in",
        );
        assert!(
            checker
                .check_instance("acme", &[], "write_widget", &widget("w-1"))
                .await
                .expect("checker ok"),
            "and the same call with a tenant reaches the policy",
        );
    }

    /// `w-1` allowed and `w-2` refused by the session; the unenumerated action by the policy.
    #[tokio::test]
    async fn the_batch_mixes_session_answers_and_policy_answers() {
        let checker = checker(SessionFlags {
            allowed: vec!["w-1".into()],
            ..SessionFlags::default()
        });

        assert_eq!(
            checker
                .check_instance_many(
                    "acme",
                    &[],
                    "read_widget",
                    &[widget("w-1"), widget("w-2"), widget("w-3")],
                )
                .await
                .expect("checker ok"),
            vec![true, false, false],
        );
        assert_eq!(
            checker
                .check_instance_many("acme", &[], "write_widget", &[widget("w-1"), widget("w-2")])
                .await
                .expect("checker ok"),
            vec![true, true],
            "an unenumerated action is the policy's to answer, for every resource",
        );
    }

    /// The batch and the singular must not disagree: the same question
    /// asked either way is the same verdict, whichever tier answered it.
    #[tokio::test]
    async fn the_batch_agrees_with_the_singular() {
        let checker = checker(SessionFlags {
            allowed: vec!["w-1".into()],
            ..SessionFlags::default()
        });
        let resources = [widget("w-1"), widget("w-2")];

        let batched = checker
            .check_instance_many("acme", &[], "read_widget", &resources)
            .await
            .expect("checker ok");

        for (resource, batched) in resources.iter().zip(batched) {
            let singular = checker
                .check_instance("acme", &[], "read_widget", resource)
                .await
                .expect("checker ok");
            assert_eq!(singular, batched, "{} disagreed", resource.entity_id);
        }
    }
}
