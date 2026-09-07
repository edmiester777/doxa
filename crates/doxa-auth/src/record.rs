//! The shared audit path for the authorization guards.
//!
//! [`Require`](crate::Require) and [`Granted`](crate::Granted) both reach
//! a verdict the request's audit event should carry, and both reach it
//! before the handler runs. Neither builds the event: they deposit a
//! [`Decision`](doxa_audit::Decision) naming what was checked and on what,
//! and the audit layer folds it in after the response — alongside the
//! status, the outcome and a duration measured through response
//! completion, none of which a guard is in a position to know.
//!
//! Routing both verdicts through here keeps them symmetric. A refusal
//! additionally writes one `warn`, reading from the same values as the
//! audit row so the log line and the trail cannot drift; when each guard
//! owned its own deny branch, both drifted to nothing and a refusal left
//! no trace but the 403 the client received.
//!
//! Every function here is a no-op without an audit builder in extensions,
//! and the whole audit half compiles out under `--no-default-features`.

use http::Extensions;

/// A guard let the request through: what was checked, and on what.
///
/// Unlike [`Denial`] nothing here feeds a log line — a granted check is
/// the ordinary case — so with the `audit` feature off every field is
/// genuinely unread.
#[cfg_attr(not(feature = "audit"), allow(dead_code))]
pub(crate) struct Grant {
    /// Domain event category the subject declares for this action, if
    /// any.
    pub event_type: Option<&'static str>,
    /// Capability name for a coarse gate, Cedar action for an instance
    /// check.
    pub action: std::borrow::Cow<'static, str>,
    /// Cedar entity type of the authorized resource.
    pub resource_type: std::borrow::Cow<'static, str>,
    /// Cedar entity id of the authorized resource.
    pub resource_id: std::borrow::Cow<'static, str>,
}

/// One refusal: what was attempted, on what, and why it was turned down.
pub(crate) struct Denial<'a> {
    /// Tenant the check ran against. `None` for an unscoped caller.
    pub tenant: Option<&'a str>,
    /// Capability name for a coarse gate, Cedar action for an instance
    /// check.
    pub action: &'a str,
    /// Cedar entity type of the refused resource.
    pub resource_type: &'a str,
    /// Cedar entity id of the refused resource.
    pub resource_id: &'a str,
    /// Short reason, used verbatim as the log field and the audit
    /// event's error text so the two cannot disagree.
    pub reason: &'static str,
}

/// Deposit an authorization the request may go on to use.
///
/// Nothing is logged: a granted check is the ordinary case, and the trail
/// is where it belongs.
pub(crate) fn grant(extensions: &Extensions, grant: Grant) {
    deposit_grant(extensions, grant);
}

/// Log the refusal and deposit it on the request's audit builder.
///
/// Safe to call without an audit layer in the stack — the log line is
/// unconditional and the audit half is skipped when no builder is
/// present.
pub(crate) fn record(extensions: &Extensions, denial: Denial<'_>) {
    tracing::warn!(
        tenant_id = denial.tenant.unwrap_or("-"),
        action = denial.action,
        resource = %format_args!("{}/{}", denial.resource_type, denial.resource_id),
        reason = denial.reason,
        "authorization denied",
    );
    deposit_denial(extensions, denial);
}

#[cfg(feature = "audit")]
fn deposit_grant(extensions: &Extensions, grant: Grant) {
    let Some(audit) = extensions.get::<doxa_audit::AuditEventBuilder>() else {
        return;
    };

    let mut decision =
        doxa_audit::Decision::granted(grant.action, grant.resource_type, grant.resource_id);
    if let Some(event_type) = grant.event_type {
        decision = decision.with_event_name(event_type);
    }

    audit.record_decision(decision);
}

#[cfg(feature = "audit")]
fn deposit_denial(extensions: &Extensions, denial: Denial<'_>) {
    let Some(audit) = extensions.get::<doxa_audit::AuditEventBuilder>() else {
        return;
    };

    audit.record_decision(doxa_audit::Decision::denied(
        denial.action.to_owned(),
        denial.resource_type.to_owned(),
        denial.resource_id.to_owned(),
        denial.reason,
    ));

    // Under an `AuditLayer` this is a no-op and the fold happens after the
    // response. Without one — an `AuthLayer` carrying its own logger, and
    // nothing above it — this builder is never terminated by anyone else,
    // so close it out here. Every refusal recorded becomes an
    // `AuthError::Forbidden`, so the status is already known.
    audit.settle(403);
}

#[cfg(not(feature = "audit"))]
fn deposit_grant(_extensions: &Extensions, _grant: Grant) {}

#[cfg(not(feature = "audit"))]
fn deposit_denial(_extensions: &Extensions, _denial: Denial<'_>) {}
