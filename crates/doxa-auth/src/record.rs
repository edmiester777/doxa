//! Where every guard's verdict goes: a [`Decision`](doxa_audit::Decision) deposited on the
//! request's audit builder, which the audit layer folds into the event after the response.
//! A refusal also logs one `warn` from the same values.

use http::Extensions;

/// A guard let the request through: what was checked, and on what.
#[cfg_attr(not(feature = "audit"), allow(dead_code))]
pub(crate) struct Grant {
    /// The audit category the action declares, if any.
    pub event_type: Option<&'static str>,
    /// Capability name for a coarse gate, Cedar action for an instance check.
    pub action: std::borrow::Cow<'static, str>,
    /// Cedar entity type of the authorized resource.
    pub resource_type: std::borrow::Cow<'static, str>,
    /// Cedar entity id of the authorized resource.
    pub resource_id: std::borrow::Cow<'static, str>,
}

/// One refusal: what was attempted, on what, and why it was turned down.
pub(crate) struct Denied<'a> {
    /// Tenant the check ran against. `None` for an unscoped caller.
    pub tenant: Option<&'a str>,
    /// Capability name for a coarse gate, Cedar action for an instance check.
    pub action: &'a str,
    /// Cedar entity type of the refused resource.
    pub resource_type: &'a str,
    /// Cedar entity id of the refused resource.
    pub resource_id: &'a str,
    /// The log field and the audit event's error text.
    pub reason: &'static str,
    /// The status the refusal answers with.
    pub status: u16,
}

/// Deposit a granted check; nothing is logged.
pub(crate) fn grant(extensions: &Extensions, grant: Grant) {
    deposit_grant(extensions, grant);
}

/// Log the refusal and deposit it on the request's audit builder, if there is one.
pub(crate) fn record(extensions: &Extensions, denial: Denied<'_>) {
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
fn deposit_denial(extensions: &Extensions, denial: Denied<'_>) {
    let Some(audit) = extensions.get::<doxa_audit::AuditEventBuilder>() else {
        return;
    };

    audit.record_decision(doxa_audit::Decision::denied(
        denial.action.to_owned(),
        denial.resource_type.to_owned(),
        denial.resource_id.to_owned(),
        denial.reason,
    ));

    // Emits only when no `AuditLayer` will close the builder after the response.
    audit.settle(denial.status);
}

#[cfg(not(feature = "audit"))]
fn deposit_grant(_extensions: &Extensions, _grant: Grant) {}

#[cfg(not(feature = "audit"))]
fn deposit_denial(_extensions: &Extensions, _denial: Denied<'_>) {}
