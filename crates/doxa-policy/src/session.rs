//! The checker a guard reaches, bound to the session the policy already
//! assembled.
//!
//! [`CapabilityChecker`] sees a tenant and a set of roles, because that is
//! all a *generic* check needs. A service whose policy resolves into a
//! session up front needs more: the allow-lists that resolution produced
//! are frequently the answer, and an administrator's session bypasses the
//! question entirely. Neither fact is reachable from tenant and roles.
//!
//! The usual response is a per-request checker written by hand, closing
//! over the session and delegating everything else. [`SessionChecker`] is
//! that object, written once. What it asks the session comes off the
//! [`PolicyExtension`] — [`session_is_admin`] and [`decide_from_session`]
//! — so the shortcuts stay the extension's to define while the wiring
//! stops being the consumer's to write.
//!
//! The tenant is not among them. It arrives from the guard, which read it
//! from the auth layer, and a deployment whose callers carry no tenant
//! claim configures that layer to supply one rather than teaching the
//! policy a second place to look.
//!
//! ```ignore
//! let checker = SessionChecker::new(Arc::clone(&router), session.clone());
//! request.extensions_mut().insert(checker.into_extension());
//! ```
//!
//! Nothing here decides anything the policy would not. A shortcut is an
//! assertion that the session already asked, and the extension is where
//! that assertion is made.
//!
//! [`session_is_admin`]: PolicyExtension::session_is_admin
//! [`decide_from_session`]: PolicyExtension::decide_from_session

use std::sync::Arc;

use crate::capability::{Capability, CapabilityChecker};
use crate::error::AuthError;
use crate::extension::PolicyExtension;
use crate::resource::ResourceEntity;
use crate::router::PolicyRouter;

/// A shared [`PolicyRouter`] bound to one caller's assembled session.
///
/// Built per request — the router is shared, the session is not — and
/// erased to `Arc<dyn CapabilityChecker>` for the extensions map through
/// [`into_extension`](Self::into_extension), which is the key every guard
/// looks under.
///
/// ## The order it asks in
///
/// 1. [`PolicyExtension::session_is_admin`] — allowed, nothing else runs.
/// 2. [`PolicyExtension::decide_from_session`] — the session's own verdict
///    for this `(action, resource)`, when it holds one. Instance checks
///    only; a capability is not a pair the session enumerated.
/// 3. The tenant the guard passed. Empty is a refusal rather than an
///    evaluation against no tenant.
/// 4. The router.
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
        // No `decide_from_session` here: a capability names an action on a
        // collection or a singleton, which is not one of the resources
        // `assemble_session` enumerated, so the session has no recorded
        // verdict to offer.
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

    /// The two shortcuts answer per resource, so the batch splits: what
    /// the session already knows is filled in without a policy call, and
    /// only what is left reaches the router — as one evaluation rather
    /// than one each.
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

        // Every slot was either answered from the session or filled from
        // the router, and both produce exactly one verdict per resource —
        // but a `None` surviving here would read as a grant if defaulted,
        // so it refuses instead.
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

    /// A verdict the session holds is authoritative, in both directions —
    /// so a resource the session refused stays refused even though the
    /// stub policy permits everything.
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

    /// An action the session does not enumerate falls through to the
    /// policy, which is what keeps the shortcut a shortcut rather than a
    /// second, narrower policy.
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

    /// The tenant is the guard's and the extension has no say in it, so a
    /// caller who arrives without one is refused however much the session
    /// holds. A deployment whose callers carry no tenant claim gives the
    /// auth layer a default; it does not teach the policy a second place to
    /// look, which is how the two would come to disagree about which
    /// partition a request was decided in.
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

    /// The batch answers positionally, mixing both sources: `w-1` from the
    /// session's allow-list, `w-2` refused by it, and the unenumerated
    /// action from the policy.
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
