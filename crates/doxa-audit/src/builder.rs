//! Mutable builder that accumulates audit context across request layers.
//!
//! [`AuditEventBuilder`] is stored in axum request extensions so each layer
//! (auth middleware, handler, post-execution) can push what it knows without
//! coupling to other layers.
//!
//! The builder **auto-emits** when paired with [`AuditLayer`](crate::AuditLayer):
//! after the response completes, the layer calls [`auto_emit`](AuditEventBuilder::auto_emit)
//! which sends whatever context has been accumulated with [`Outcome::Allowed`]
//! as the default. Handlers on the happy path can simply enrich the builder and
//! return — the event is recorded automatically. Use the explicit terminal
//! methods ([`emit_denied`](AuditEventBuilder::emit_denied),
//! [`emit_error`](AuditEventBuilder::emit_error)) only when the outcome
//! diverges from success.
//!
//! Exactly-once emission is guaranteed even when the builder is cloned (as
//! axum's [`Extension`](axum::extract::Extension) extractor does): all clones
//! share state behind an [`Arc`], and the first caller to emit takes the inner
//! state — subsequent attempts are no-ops.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::http::HeaderMap;

use crate::event::{AuditEvent, AuditEventType, Outcome};
use crate::logger::AuditLogger;

/// Private inner state that holds all accumulated audit fields.
///
/// Wrapped in `Arc<Mutex<Option<…>>>` by [`AuditEventBuilder`] so that
/// clones share state and exactly-once emission is enforced.
struct BuilderInner {
    logger: AuditLogger,
    start: Instant,

    // Auth layer
    actor_sub: Option<String>,
    actor_roles: Option<Vec<String>>,
    actor_attrs: serde_json::Value,
    source_ip: Option<String>,
    user_agent: Option<String>,
    request_id: Option<String>,

    // Handler layer
    event_type: Option<String>,
    action: Option<String>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    request_body: Option<serde_json::Value>,

    // HTTP context (auto-populated by AuditLayer)
    http_method: Option<String>,
    http_path: Option<String>,
    http_status: Option<u16>,

    // Post-execution layer
    outcome: Option<Outcome>,
    response_summary: Option<serde_json::Value>,
    duration_ms: Option<i64>,
    error_message: Option<String>,
}

/// Mutable builder that accumulates audit context as a request flows through
/// middleware, handler, and post-execution layers.
///
/// Stored in axum request extensions so each layer can push what it knows
/// without coupling to other layers.
///
/// # Auto-emit
///
/// When paired with [`AuditLayer`](crate::AuditLayer), the builder
/// auto-emits with [`Outcome::Allowed`] after the response completes.
/// Handlers on the happy path only need to enrich the builder — no
/// terminal call required.
///
/// All clones share an [`Arc`]-backed inner state so that exactly one
/// emission occurs, regardless of how many clones exist.
#[derive(Clone)]
pub struct AuditEventBuilder {
    inner: Arc<Mutex<Option<BuilderInner>>>,
}

impl AuditEventBuilder {
    /// Create a new builder backed by the given [`AuditLogger`].
    pub fn new(logger: AuditLogger) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(BuilderInner {
                logger,
                start: Instant::now(),
                actor_sub: None,
                actor_roles: None,
                actor_attrs: serde_json::Value::Null,
                source_ip: None,
                user_agent: None,
                request_id: None,
                event_type: None,
                action: None,
                resource_type: None,
                resource_id: None,
                request_body: None,
                http_method: None,
                http_path: None,
                http_status: None,
                outcome: None,
                response_summary: None,
                duration_ms: None,
                error_message: None,
            }))),
        }
    }

    /// Lock the inner state and apply `f` if not yet emitted.
    fn with_inner(&self, f: impl FnOnce(&mut BuilderInner)) {
        if let Some(inner) = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_mut()
        {
            f(inner);
        }
    }

    // ── Auth layer ──────────────────────────────────────────

    /// Populate actor fields directly from the consumer's resolved claims.
    ///
    /// `sub` and `roles` become first-class columns on the audit event for
    /// query-friendly actor lookups. `attrs` is an opaque JSON value that
    /// the consumer populates from whatever additional fields its claim
    /// type exposes — `Value::Null` leaves the column empty. Audit
    /// persistence makes no assumptions about the shape of `attrs`.
    pub fn set_actor(&self, sub: Option<&str>, roles: &[String], attrs: serde_json::Value) {
        self.with_inner(|inner| {
            inner.actor_sub = sub.map(str::to_owned);
            inner.actor_roles = Some(roles.to_vec());
            inner.actor_attrs = attrs;
        });
    }

    /// Extract source_ip, user_agent, and request_id from HTTP headers.
    pub fn set_request_metadata(&self, headers: &HeaderMap) {
        self.with_inner(|inner| {
            inner.source_ip = headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.split(',').next().unwrap_or("").trim().to_string());

            inner.user_agent = headers
                .get("user-agent")
                .and_then(|v| v.to_str().ok())
                .map(String::from);

            inner.request_id = headers
                .get("x-request-id")
                .and_then(|v| v.to_str().ok())
                .map(String::from);
        });
    }

    // ── HTTP context (auto-populated by AuditLayer) ─────────

    /// Record the HTTP method and path from the request.
    ///
    /// Called automatically by [`AuditService`](crate::AuditService) —
    /// handlers do not need to call this.
    pub fn set_http_request(&self, method: &str, path: &str) {
        let m = method.to_owned();
        let p = path.to_owned();
        self.with_inner(|inner| {
            inner.http_method = Some(m);
            inner.http_path = Some(p);
        });
    }

    /// Record the HTTP response status code.
    ///
    /// Called automatically by [`AuditService`](crate::AuditService) —
    /// handlers do not need to call this.
    pub fn set_http_status(&self, status: u16) {
        self.with_inner(|inner| {
            inner.http_status = Some(status);
        });
    }

    // ── Handler layer ───────────────────────────────────────

    /// Set the event category and specific action name.
    ///
    /// Accepts any [`AuditEventType`] implementor. Most applications will
    /// define their own event-type enum; the built-in
    /// [`EventType`](crate::EventType) is a minimal reference
    /// implementation provided for quick starts.
    pub fn set_event(&self, event_type: impl AuditEventType, action: impl Into<String>) {
        let event_str = event_type.as_str().to_owned();
        let action_str = action.into();
        self.with_inner(|inner| {
            inner.event_type = Some(event_str);
            inner.action = Some(action_str);
        });
    }

    /// Identify the resource being accessed or modified.
    pub fn set_resource(&self, resource_type: impl Into<String>, resource_id: impl Into<String>) {
        let rt = resource_type.into();
        let ri = resource_id.into();
        self.with_inner(|inner| {
            inner.resource_type = Some(rt);
            inner.resource_id = Some(ri);
        });
    }

    /// Attach a sanitized copy of the request payload. Must never contain
    /// raw secrets.
    pub fn set_request_body(&self, body: serde_json::Value) {
        self.with_inner(|inner| {
            inner.request_body = Some(body);
        });
    }

    // ── Post-execution layer ────────────────────────────────

    /// Record whether the operation was allowed, denied, or errored.
    pub fn set_outcome(&self, outcome: Outcome) {
        self.with_inner(|inner| {
            inner.outcome = Some(outcome);
        });
    }

    /// Returns `true` if an outcome has already been set on this builder.
    pub fn has_outcome(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|inner| inner.outcome.is_some())
    }

    /// Attach response metadata (record counts, etc.) — never raw data.
    pub fn set_response_summary(&self, summary: serde_json::Value) {
        self.with_inner(|inner| {
            inner.response_summary = Some(summary);
        });
    }

    /// Explicitly set duration; otherwise [`emit`](Self::emit) calculates it
    /// from the builder's creation time.
    pub fn set_duration_ms(&self, ms: i64) {
        self.with_inner(|inner| {
            inner.duration_ms = Some(ms);
        });
    }

    /// Attach an error message (relevant when outcome is `denied` or `error`).
    pub fn set_error(&self, message: impl Into<String>) {
        let msg = message.into();
        self.with_inner(|inner| {
            inner.error_message = Some(msg);
        });
    }

    // ── Convenience terminals ───────────────────────────────

    /// Set outcome to [`Outcome::Allowed`] and emit the event.
    pub fn emit_allowed(&self) {
        self.with_inner(|inner| {
            inner.outcome = Some(Outcome::Allowed);
        });
        self.emit();
    }

    /// Set outcome to [`Outcome::Denied`] with an error message and emit.
    pub fn emit_denied(&self, error: &str) {
        let err = error.to_owned();
        self.with_inner(|inner| {
            inner.outcome = Some(Outcome::Denied);
            inner.error_message = Some(err);
        });
        self.emit();
    }

    /// Set outcome to [`Outcome::Error`] with an error message and emit.
    pub fn emit_error(&self, error: &str) {
        let err = error.to_owned();
        self.with_inner(|inner| {
            inner.outcome = Some(Outcome::Error);
            inner.error_message = Some(err);
        });
        self.emit();
    }

    /// Record a permission denial with full context and emit.
    ///
    /// Stamps the given `event_type` (typically your own `AuthFailure`
    /// variant, or [`EventType::AuthFailure`](crate::EventType::AuthFailure)
    /// from the reference enum), populates the resource fields, and emits
    /// with [`Outcome::Denied`].
    pub fn emit_permission_denied(
        &self,
        event_type: impl AuditEventType,
        action: &str,
        resource_type: &str,
        resource_id: &str,
        reason: &str,
    ) {
        self.set_event(event_type, action);
        self.set_resource(resource_type, resource_id);
        self.emit_denied(reason);
    }

    // ── Terminal ────────────────────────────────────────────

    /// Take the inner state and send the event to the background writer.
    ///
    /// Auto-calculates `duration_ms` from the builder's creation instant
    /// if not explicitly set via [`set_duration_ms`](Self::set_duration_ms).
    ///
    /// Safe to call multiple times — only the first call emits; subsequent
    /// calls are no-ops.
    pub fn emit(&self) {
        self.take_and_send(None);
    }

    /// Emit with [`Outcome::Allowed`] if no prior emission has occurred.
    ///
    /// Called by [`AuditService`](crate::AuditService) after the inner
    /// service returns. If the handler (or auth layer) already emitted
    /// explicitly, or if an `ApiError` outcome was attached to response
    /// extensions, this is a no-op.
    pub fn auto_emit(&self) {
        self.take_and_send(Some(Outcome::Allowed));
    }

    /// Take the inner state, apply a default outcome if none was set, and
    /// send the event to the logger. No-ops if the inner was already taken.
    fn take_and_send(&self, default_outcome: Option<Outcome>) {
        let taken = self.inner.lock().unwrap_or_else(|e| e.into_inner()).take();

        let Some(mut inner) = taken else { return };

        if inner.duration_ms.is_none() {
            inner.duration_ms = Some(inner.start.elapsed().as_millis() as i64);
        }

        let outcome = inner
            .outcome
            .or(default_outcome)
            .unwrap_or(Outcome::Allowed);

        inner.logger.log(AuditEvent {
            event_type: inner.event_type.unwrap_or_default(),
            action: inner.action.unwrap_or_default(),
            outcome,
            actor_sub: inner.actor_sub,
            actor_roles: inner.actor_roles,
            actor_attrs: inner.actor_attrs,
            resource_type: inner.resource_type,
            resource_id: inner.resource_id,
            request_body: inner.request_body,
            response_summary: inner.response_summary,
            source_ip: inner.source_ip,
            user_agent: inner.user_agent,
            request_id: inner.request_id,
            http_method: inner.http_method,
            http_path: inner.http_path,
            http_status: inner.http_status,
            duration_ms: inner.duration_ms,
            error_message: inner.error_message,
        });
    }
}
