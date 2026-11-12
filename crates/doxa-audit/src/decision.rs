//! A guard's verdict, deposited with
//! [`record_decision`](crate::AuditEventBuilder::record_decision) and folded into the fields the
//! request left blank when the event is sent.

use std::borrow::Cow;

use crate::event::{AuditEventType, Outcome};

/// One authorization decision: what was checked, on what, and how it went.
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
    /// `Denied` on a refusal; `None` on a grant, which leaves the outcome to the response.
    pub(crate) outcome: Option<Outcome>,
}

impl Decision {
    /// A guard let the request through; it carries no outcome.
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

    /// A guard refused the request: `AuthFailure`, and an [`Outcome::Denied`] that always lands.
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
    pub fn with_event_type(mut self, event_type: impl AuditEventType) -> Self {
        self.event_type = Some(Cow::Owned(event_type.as_str().to_owned()));
        self
    }

    /// [`with_event_type`](Self::with_event_type) for a `'static` name, without the copy.
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
