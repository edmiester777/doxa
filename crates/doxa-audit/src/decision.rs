//! What an authorization guard decided, on its way to the audit event.
//!
//! A guard knows four things nothing else on the request can work out:
//! which action was checked, against which resource, under which domain
//! event category, and — when it refused — why. Everything else on the
//! event is already covered by a layer: the actor and tenant by the auth
//! middleware, the method, path, status, duration and the emission itself
//! by [`AuditService`](crate::AuditService).
//!
//! So a guard does not build an event and does not emit one. It deposits
//! a [`Decision`] with
//! [`record_decision`](crate::AuditEventBuilder::record_decision) and
//! returns. The decision is folded into the event at emit time, filling
//! only fields the request never named — which is what makes the guard
//! and the handler independent of each other's order. A handler that
//! names its own domain event simply names it; there is no "stamp before
//! you set" rule to remember, and nothing to guard on.

use std::borrow::Cow;

use crate::event::{AuditEventType, Outcome};

/// One authorization decision: what was checked, on what, and how it
/// went.
///
/// Built by a guard and deposited on the request's
/// [`AuditEventBuilder`](crate::AuditEventBuilder). See the
/// [module docs](self) for why it is a deposit rather than a set of
/// setter calls.
#[derive(Debug, Clone)]
pub struct Decision {
    /// Domain event category, when the guard's subject declares one.
    /// A refusal always carries [`EventType::AuthFailure`](crate::EventType::AuthFailure).
    pub(crate) event_type: Option<Cow<'static, str>>,
    /// Capability name for a coarse gate, Cedar action for an instance
    /// check.
    pub(crate) action: Cow<'static, str>,
    /// Cedar entity type the decision concerned.
    pub(crate) resource_type: Cow<'static, str>,
    /// Cedar entity id the decision concerned.
    pub(crate) resource_id: Cow<'static, str>,
    /// Short reason, set only on a refusal. Used verbatim as the event's
    /// error text so it and the guard's log line cannot disagree.
    pub(crate) reason: Option<Cow<'static, str>>,
    /// `Denied` on a refusal, `None` on a grant — a grant leaves the
    /// outcome to the response, which is the only thing that knows
    /// whether the handler went on to succeed.
    pub(crate) outcome: Option<Outcome>,
}

impl Decision {
    /// A guard let the request through.
    ///
    /// Carries no outcome: passing the gate says nothing about how the
    /// handler behind it ended, and
    /// [`auto_emit`](crate::AuditEventBuilder::auto_emit) already
    /// defaults to [`Outcome::Allowed`] for a response that raised
    /// nothing.
    pub fn granted(
        action: impl Into<Cow<'static, str>>,
        resource_type: impl Into<Cow<'static, str>>,
        resource_id: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            event_type: None,
            action: action.into(),
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
            reason: None,
            outcome: None,
        }
    }

    /// A guard refused the request.
    ///
    /// Files the event under
    /// [`EventType::AuthFailure`](crate::EventType::AuthFailure) and
    /// carries [`Outcome::Denied`], which the fold applies unconditionally
    /// — a refused request must never reach the trail looking allowed.
    pub fn denied(
        action: impl Into<Cow<'static, str>>,
        resource_type: impl Into<Cow<'static, str>>,
        resource_id: impl Into<Cow<'static, str>>,
        reason: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            event_type: Some(Cow::Borrowed(
                crate::event::EventType::AuthFailure.as_static(),
            )),
            action: action.into(),
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
            reason: Some(reason.into()),
            outcome: Some(Outcome::Denied),
        }
    }

    /// File the decision under a domain event category.
    ///
    /// Takes anything implementing [`AuditEventType`], so an asset names
    /// a variant of its own event enum rather than a loose string.
    pub fn with_event_type(mut self, event_type: impl AuditEventType) -> Self {
        self.event_type = Some(Cow::Owned(event_type.as_str().to_owned()));
        self
    }

    /// File the decision under a category already known as a `'static`
    /// string.
    ///
    /// [`with_event_type`](Self::with_event_type) without the copy, for
    /// the common case of an enum whose `as_str` is a literal — see
    /// [`EventType::as_static`](crate::EventType::as_static).
    pub fn with_event_name(mut self, event_type: &'static str) -> Self {
        self.event_type = Some(Cow::Borrowed(event_type));
        self
    }

    /// Whether this decision was a refusal.
    pub fn is_denial(&self) -> bool {
        self.outcome == Some(Outcome::Denied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_grant_leaves_the_outcome_to_the_response() {
        let decision = Decision::granted("read", "Widget", "7");
        assert!(!decision.is_denial());
        assert!(decision.outcome.is_none());
        assert!(decision.reason.is_none());
        assert!(
            decision.event_type.is_none(),
            "an asset that declares no category leaves the field for the handler",
        );
    }

    #[test]
    fn a_refusal_files_itself_under_auth_failure() {
        let decision =
            Decision::denied("widgets.read", "Widget", "collection", "capability denied");
        assert!(decision.is_denial());
        assert_eq!(decision.event_type.as_deref(), Some("auth_failure"));
        assert_eq!(decision.reason.as_deref(), Some("capability denied"));
    }

    #[test]
    fn an_event_type_can_be_named_from_an_enum() {
        let decision =
            Decision::granted("read", "Widget", "7").with_event_type(crate::EventType::DataAccess);
        assert_eq!(decision.event_type.as_deref(), Some("data_access"));
    }
}
