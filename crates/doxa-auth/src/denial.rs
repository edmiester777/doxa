//! The shared refusal path for the authorization guards.
//!
//! [`Require`](crate::Require) and [`Granted`](crate::Granted) both end a
//! denied request the same way: one `warn` naming what was refused, and
//! one audit event recording it. Routing every refusal through [`record`]
//! keeps the log line and the audit row reading from the same values —
//! when each guard owned its own deny branch, both drifted to nothing and
//! a refusal left no trace but the 403 the client received.

use http::Extensions;

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

/// Log the refusal and record it on the request's audit builder.
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
    emit(extensions, denial);
}

#[cfg(feature = "audit")]
fn emit(extensions: &Extensions, denial: Denial<'_>) {
    let Some(audit) = extensions.get::<doxa_audit::AuditEventBuilder>() else {
        return;
    };

    // Emitting takes the builder, so `AuditService` never gets to stamp
    // the status off the response. Every refusal recorded here becomes an
    // `AuthError::Forbidden`, so the guard already knows what that status
    // is going to be.
    audit.set_http_status(403);

    // Borrowed rather than removed: the builder enforces exactly-once
    // emission behind its own `Arc`, so the layer's later `auto_emit` is
    // already a no-op. Taking it out of extensions would buy nothing and
    // hide it from everything downstream.
    audit.emit_permission_denied(
        doxa_audit::EventType::AuthFailure,
        denial.action,
        denial.resource_type,
        denial.resource_id,
        denial.reason,
    );
}

#[cfg(not(feature = "audit"))]
fn emit(_extensions: &Extensions, _denial: Denial<'_>) {}
