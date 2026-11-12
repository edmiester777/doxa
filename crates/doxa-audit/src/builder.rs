//! [`AuditEventBuilder`], kept in request extensions so each layer adds what it knows. Under
//! [`AuditLayer`](crate::AuditLayer) the layer sends the event after the response and the
//! terminals only record. Clones share state, and the event is sent once. Setters are
//! last-write-wins; a guard's [`Decision`] is deposited and only fills blanks.

use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::http::HeaderMap;

use crate::decision::Decision;
use crate::event::{AuditEvent, AuditEventType, Outcome};
use crate::logger::AuditLogger;

/// Private inner state that holds all accumulated audit fields.
///
/// Wrapped in `Arc<Mutex<Option<…>>>` by [`AuditEventBuilder`] so that
/// clones share state and exactly-once emission is enforced.
struct BuilderInner {
    logger: AuditLogger,
    start: Instant,

    /// An [`AuditLayer`](crate::AuditLayer) sends this event after the response.
    layered: bool,

    /// A guard's verdict, folded into the blanks at send time.
    decision: Option<Decision>,

    // Auth layer
    tenant_id: Option<String>,
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
    /// A builder the caller must emit itself.
    pub fn new(logger: AuditLogger) -> Self {
        Self::build(logger, false)
    }

    /// A builder an [`AuditLayer`](crate::AuditLayer) sends after the response.
    pub fn layered(logger: AuditLogger) -> Self {
        Self::build(logger, true)
    }

    fn build(logger: AuditLogger, layered: bool) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(BuilderInner {
                logger,
                start: Instant::now(),
                layered,
                decision: None,
                tenant_id: None,
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

    /// The indexed `tenant_id` column. `AuthLayer` sets it from `Claims::scope()`.
    pub fn set_tenant(&self, tenant_id: Option<&str>) {
        self.with_inner(|inner| {
            inner.tenant_id = tenant_id.map(str::to_owned);
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

    /// The socket peer as `source_ip`, unless `x-forwarded-for` already supplied one.
    pub fn set_source_ip_fallback(&self, addr: SocketAddr) {
        self.with_inner(|inner| {
            if inner.source_ip.is_none() {
                inner.source_ip = Some(addr.ip().to_string());
            }
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

    /// Set the action without touching the event category.
    pub fn set_action(&self, action: impl Into<String>) {
        let action_str = action.into();
        self.with_inner(|inner| {
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

    // ── Guard layer ─────────────────────────────────────────

    /// Deposit a guard's verdict; it fills only fields nothing else set. The first deposit
    /// stands, except that a denial displaces a grant.
    pub fn record_decision(&self, decision: Decision) {
        self.with_inner(|inner| {
            let displaces = match &inner.decision {
                None => true,
                Some(existing) => decision.is_denial() && !existing.is_denial(),
            };
            if displaces {
                inner.decision = Some(decision);
            }
        });
    }

    /// For a request ended before its handler: emit at `status`, unless a layer will send it.
    pub fn settle(&self, status: u16) {
        if self.is_layered() {
            return;
        }
        self.set_http_status(status);
        self.emit();
    }

    /// Whether an [`AuditLayer`](crate::AuditLayer) will terminate this
    /// builder after the response.
    pub fn is_layered(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|inner| inner.layered)
    }

    /// Attach a sanitized copy of the request payload. Must never contain
    /// raw secrets.
    pub fn set_request_body(&self, body: serde_json::Value) {
        self.with_inner(|inner| {
            inner.request_body = Some(body);
        });
    }

    // ── Post-execution layer ────────────────────────────────

    /// Last writer wins; [`AuditService`](crate::AuditService) writes last, from an `ApiError`'s
    /// outcome. A deposited denial still overrides it.
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

    /// Send the event once. Under an [`AuditLayer`](crate::AuditLayer) this only records, so
    /// the layer can still stamp the status and full duration; later writes still land.
    pub fn emit(&self) {
        if self.defer_to_layer() {
            return;
        }
        self.take_and_send(None);
    }

    /// Send with a default of [`Outcome::Allowed`], unless already sent; the layer's terminal.
    pub fn auto_emit(&self) {
        self.take_and_send(Some(Outcome::Allowed));
    }

    /// Whether an explicit emit should stand aside for the layer.
    fn defer_to_layer(&self) -> bool {
        let deferring = self.is_layered();

        if deferring {
            tracing::debug!(
                "audit event emitted from inside the request; \
                 deferring to AuditLayer so the response status and \
                 duration survive — the call can be removed",
            );
        }
        deferring
    }

    /// Take the inner state, apply a default outcome if none was set, and
    /// send the event to the logger. No-ops if the inner was already taken.
    fn take_and_send(&self, default_outcome: Option<Outcome>) {
        let taken = self.inner.lock().unwrap_or_else(|e| e.into_inner()).take();

        let Some(mut inner) = taken else { return };

        fold_decision(&mut inner);

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
            tenant_id: inner.tenant_id,
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

/// Fold a guard's [`Decision`] into the blanks. A denial's outcome alone overrides, so a route
/// that masks a refusal (a 404, `outcome = "allowed"`) still records it.
fn fold_decision(inner: &mut BuilderInner) {
    let Some(decision) = inner.decision.take() else {
        return;
    };

    if inner.event_type.is_none() {
        inner.event_type = decision.event_type.map(Cow::into_owned);
    }

    if inner.action.is_none() {
        inner.action = Some(decision.action.into_owned());
    }

    // Type and id move together; the type marks the pair claimed.
    if inner.resource_type.is_none() {
        inner.resource_type = Some(decision.resource_type.into_owned());
        inner.resource_id = Some(decision.resource_id.into_owned());
    }

    if inner.error_message.is_none() {
        inner.error_message = decision.reason.map(Cow::into_owned);
    }

    if decision.outcome == Some(Outcome::Denied) {
        inner.outcome = Some(Outcome::Denied);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventType;

    fn builder() -> (AuditEventBuilder, tokio::sync::mpsc::Receiver<AuditEvent>) {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        (AuditEventBuilder::new(AuditLogger::from_sender(tx)), rx)
    }

    fn layered() -> (AuditEventBuilder, tokio::sync::mpsc::Receiver<AuditEvent>) {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        (AuditEventBuilder::layered(AuditLogger::from_sender(tx)), rx)
    }

    // ── Folding a guard's decision ──────────────────────────

    /// The point of the whole arrangement: a handler that does nothing
    /// still gets an event naming what was authorized.
    #[tokio::test]
    async fn a_deposited_grant_fills_an_untouched_event() {
        let (b, mut rx) = builder();
        b.record_decision(Decision::granted("read", "Widget", "7").with_event_name("data_access"));
        b.auto_emit();

        let event = rx.recv().await.expect("emitted");
        assert_eq!(event.event_type, "data_access");
        assert_eq!(event.action, "read");
        assert_eq!(event.resource_type.as_deref(), Some("Widget"));
        assert_eq!(event.resource_id.as_deref(), Some("7"));
        assert_eq!(event.outcome, Outcome::Allowed);
    }

    /// A deposit never overwrites a handler's field, whichever ran first.
    #[tokio::test]
    async fn a_handler_outranks_a_deposit_whichever_ran_first() {
        for handler_first in [true, false] {
            let (b, mut rx) = builder();
            let deposit =
                || b.record_decision(Decision::granted("read", "Widget", "7").with_event_name("x"));
            let handler = || {
                b.set_event(EventType::AdminDelete, "purge_widget");
                b.set_resource("Tombstone", "7");
            };

            if handler_first {
                handler();
                deposit();
            } else {
                deposit();
                handler();
            }
            b.auto_emit();

            let event = rx.recv().await.expect("emitted");
            assert_eq!(
                event.event_type, "admin_delete",
                "handler_first={handler_first}"
            );
            assert_eq!(event.action, "purge_widget");
            assert_eq!(event.resource_type.as_deref(), Some("Tombstone"));
            assert_eq!(event.resource_id.as_deref(), Some("7"));
        }
    }

    /// Resource type and id travel together — folding an id under a type
    /// the handler chose would name an object that does not exist.
    #[tokio::test]
    async fn a_handler_claiming_the_resource_takes_both_halves() {
        let (b, mut rx) = builder();
        b.set_resource("Tombstone", "7");
        b.record_decision(Decision::granted("read", "Widget", "99"));
        b.auto_emit();

        let event = rx.recv().await.expect("emitted");
        assert_eq!(event.resource_type.as_deref(), Some("Tombstone"));
        assert_eq!(
            event.resource_id.as_deref(),
            Some("7"),
            "the id must not be folded in under the handler's type",
        );
    }

    /// The route's own subject is authorized before the body is parsed,
    /// so a dependency checked later does not displace it.
    #[tokio::test]
    async fn between_two_grants_the_first_stands() {
        let (b, mut rx) = builder();
        b.record_decision(Decision::granted("update", "Pipeline", "nightly"));
        b.record_decision(Decision::granted("read", "Source", "payroll"));
        b.auto_emit();

        let event = rx.recv().await.expect("emitted");
        assert_eq!(event.resource_type.as_deref(), Some("Pipeline"));
        assert_eq!(event.resource_id.as_deref(), Some("nightly"));
    }

    /// A request that ends on a denial is about that denial, whatever it
    /// was allowed to touch on the way there.
    #[tokio::test]
    async fn a_refusal_displaces_an_earlier_grant() {
        let (b, mut rx) = builder();
        b.record_decision(Decision::granted("update", "Pipeline", "nightly"));
        b.record_decision(Decision::denied(
            "read",
            "Source",
            "payroll",
            "reference denied",
        ));
        b.auto_emit();

        let event = rx.recv().await.expect("emitted");
        assert_eq!(event.outcome, Outcome::Denied);
        assert_eq!(event.resource_type.as_deref(), Some("Source"));
        assert_eq!(event.resource_id.as_deref(), Some("payroll"));
        assert_eq!(event.error_message.as_deref(), Some("reference denied"));
        assert_eq!(event.event_type, "auth_failure");
    }

    /// A deposited denial outranks the request's outcome.
    #[tokio::test]
    async fn a_refusal_outranks_an_allowed_outcome() {
        let (b, mut rx) = builder();
        b.record_decision(Decision::denied("read", "Widget", "7", "instance denied"));
        b.set_outcome(Outcome::Allowed);
        b.auto_emit();

        let event = rx.recv().await.expect("emitted");
        assert_eq!(event.outcome, Outcome::Denied);
    }

    // ── Emit protection ─────────────────────────────────────

    /// Emitting from inside a request would take the builder before the
    /// response exists, so under a layer it records and stands aside.
    #[tokio::test]
    async fn an_emit_under_a_layer_defers_to_the_layer() {
        let (b, mut rx) = layered();
        b.set_event(EventType::DataAccess, "read");
        b.emit();

        assert!(
            rx.try_recv().is_err(),
            "nothing sent from inside the request"
        );

        // What the layer does once the response exists.
        b.set_http_status(200);
        b.auto_emit();

        let event = rx.recv().await.expect("the layer sends it");
        assert_eq!(event.action, "read");
        assert_eq!(
            event.http_status,
            Some(200),
            "the status the early send would have cost",
        );
    }

    /// Deferring must not lose what the caller was recording.
    #[tokio::test]
    async fn a_deferred_terminal_still_carries_its_outcome() {
        let (b, mut rx) = layered();
        b.emit_denied("quota exceeded");
        b.auto_emit();

        let event = rx.recv().await.expect("emitted");
        assert_eq!(event.outcome, Outcome::Denied);
        assert_eq!(event.error_message.as_deref(), Some("quota exceeded"));
    }

    /// With nothing above it to send the event, an explicit emit is the
    /// only emit — it must still work exactly as it always did.
    #[tokio::test]
    async fn an_emit_without_a_layer_sends_immediately() {
        let (b, mut rx) = builder();
        b.set_event(EventType::DataAccess, "read");
        b.emit();

        let event = rx.try_recv().expect("sent right away");
        assert_eq!(event.action, "read");

        // And the builder is spent, as before.
        b.set_resource("Widget", "late");
        b.auto_emit();
        assert!(rx.try_recv().is_err(), "exactly once");
    }

    /// A deferred emit does not freeze the builder. That is the intent:
    /// one event, sent at the end, carrying everything anyone knew.
    #[tokio::test]
    async fn a_deferred_emit_leaves_the_builder_writable() {
        let (b, mut rx) = layered();
        b.emit_allowed();
        b.set_response_summary(serde_json::json!({ "rows": 3 }));
        b.auto_emit();

        let event = rx.recv().await.expect("emitted");
        assert_eq!(
            event.response_summary,
            Some(serde_json::json!({ "rows": 3 })),
        );
    }

    /// An error variant's `outcome = "allowed"` lands over the handler's outcome.
    #[tokio::test]
    async fn an_allowed_annotation_overrides_what_the_handler_assumed() {
        let (b, mut rx) = layered();
        b.emit_denied("no such document");

        // What AuditService does with the response's ResponseAuditOutcome.
        b.set_outcome(Outcome::Allowed);
        b.auto_emit();

        let event = rx.recv().await.expect("emitted");
        assert_eq!(event.outcome, Outcome::Allowed);
    }

    /// The response has the last word on every outcome, not just that
    /// one, or the layer could never correct an optimistic guess.
    #[tokio::test]
    async fn the_response_outcome_wins_over_a_handler() {
        let (b, mut rx) = layered();
        b.set_outcome(Outcome::Allowed);
        b.set_outcome(Outcome::Error);
        b.auto_emit();

        let event = rx.recv().await.expect("emitted");
        assert_eq!(event.outcome, Outcome::Error);
    }

    /// A route that masks a refusal as a 404 still records the denial.
    #[tokio::test]
    async fn a_masked_refusal_is_still_recorded_as_a_refusal() {
        let (b, mut rx) = layered();
        b.record_decision(Decision::denied(
            "read",
            "Document",
            "secret",
            "instance denied",
        ));

        // The route renders it as a NotFound annotated `outcome = "allowed"`.
        b.set_outcome(Outcome::Allowed);
        b.set_http_status(404);
        b.auto_emit();

        let event = rx.recv().await.expect("emitted");
        assert_eq!(event.outcome, Outcome::Denied);
        assert_eq!(event.resource_id.as_deref(), Some("secret"));
        assert_eq!(
            event.http_status,
            Some(404),
            "the client is told nothing; the trail is told everything",
        );
    }

    // ── Settling ────────────────────────────────────────────

    /// Under a layer, `settle` leaves the sending to it.
    #[tokio::test]
    async fn settling_under_a_layer_leaves_the_event_for_the_layer() {
        let (b, mut rx) = layered();
        b.record_decision(Decision::denied("read", "Widget", "7", "instance denied"));
        b.settle(403);

        assert!(rx.try_recv().is_err(), "nothing emitted yet");

        // What the layer does after the response.
        b.set_http_status(403);
        b.auto_emit();
        let event = rx.recv().await.expect("the layer emits");
        assert_eq!(event.outcome, Outcome::Denied);
        assert_eq!(event.http_status, Some(403));
    }

    /// With no layer the guard is the last thing to touch the event, so
    /// it has to close it out or the refusal is lost.
    #[tokio::test]
    async fn settling_without_a_layer_emits_the_refusal() {
        let (b, mut rx) = builder();
        b.record_decision(Decision::denied("read", "Widget", "7", "instance denied"));
        b.settle(403);

        let event = rx.recv().await.expect("the guard emits");
        assert_eq!(event.outcome, Outcome::Denied);
        assert_eq!(event.resource_id.as_deref(), Some("7"));
        assert_eq!(event.http_status, Some(403));
    }
}
