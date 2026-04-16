//! SOC 2 Type II compliant audit logging for data access events.
//!
//! Provides an append-only audit trail capturing who accessed what data, when,
//! from where, and the outcome. Events are buffered through an async channel
//! and persisted by a background writer — query execution is never blocked by
//! audit persistence.
//!
//! # Quick Start
//!
//! ```ignore
//! let logger = doxa_audit::spawn_audit_writer(db, 4096);
//! ```
//!
//! # Architecture
//!
//! ```text
//! Request flow (with AuditLayer):
//!   AuditLayer  →  Auth middleware  →  Handler  →  auto-emit
//!   ┌──────────┐  ┌───────────────┐  ┌──────────┐  ┌──────────┐
//!   │ create   │  │ actor_sub     │  │ event    │  │ emit     │
//!   │ builder  │  │ actor_roles   │  │ action   │  │ Allowed  │
//!   │ inject   │  │ actor_attrs   │  │ resource │  │ (if not  │
//!   │ metadata │  │ source_ip     │  │ req_body │  │  already │
//!   └──────────┘  │ user_agent    │  └──────────┘  │  done)   │
//!                 │ request_id    │                 └──────────┘
//!                 └───────────────┘
//! ```
//!
//! `actor_attrs` is a consumer-defined JSON map — the audit crate has
//! no built-in notion of tenant, project, or any other identity
//! dimension beyond `sub` and `roles`.

pub mod builder;
#[cfg(feature = "sea-orm")]
pub mod entity;
pub mod event;
pub mod layer;
pub mod logger;
#[cfg(feature = "sea-orm")]
mod sea_orm_impls;

pub use builder::AuditEventBuilder;
pub use event::{AuditEvent, AuditEventType, AuditOutcome, EventType, Outcome};
pub use layer::{AuditLayer, AuditService};
pub use logger::AuditLogger;

#[cfg(feature = "sea-orm")]
pub use logger::spawn_audit_writer;

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc;

    use super::*;

    fn make_logger(buffer: usize) -> (AuditLogger, mpsc::Receiver<AuditEvent>) {
        let (tx, rx) = mpsc::channel(buffer);
        (AuditLogger { tx }, rx)
    }

    #[tokio::test]
    async fn log_sends_event_through_channel() {
        let (logger, mut rx) = make_logger(16);

        logger.log(AuditEvent {
            event_type: "data_access".to_owned(),
            action: "read".into(),
            outcome: Outcome::Allowed,
            actor_sub: Some("user-123".into()),
            actor_roles: Some(vec!["viewer".into()]),
            actor_attrs: serde_json::Value::Null,
            resource_type: Some("document".into()),
            resource_id: Some("doc-42".into()),
            request_body: None,
            response_summary: None,
            source_ip: Some("10.0.0.1".into()),
            user_agent: None,
            request_id: None,
            duration_ms: Some(42),
            http_method: None,
            http_path: None,
            http_status: None,
            error_message: None,
        });

        let event = rx.recv().await.expect("should receive event");
        assert_eq!(event.event_type, "data_access");
        assert_eq!(event.action, "read");
        assert_eq!(event.outcome, Outcome::Allowed);
        assert_eq!(event.actor_sub.as_deref(), Some("user-123"));
        assert_eq!(event.resource_id.as_deref(), Some("doc-42"));
        assert_eq!(event.duration_ms, Some(42));
    }

    #[tokio::test]
    async fn log_drops_when_channel_full() {
        let (logger, _rx) = make_logger(1);

        let make_event = || AuditEvent {
            event_type: "data_access".to_owned(),
            action: "test".into(),
            outcome: Outcome::Allowed,
            actor_sub: None,
            actor_roles: None,
            actor_attrs: serde_json::Value::Null,
            resource_type: None,
            resource_id: None,
            request_body: None,
            response_summary: None,
            source_ip: None,
            user_agent: None,
            request_id: None,
            duration_ms: None,
            http_method: None,
            http_path: None,
            http_status: None,
            error_message: None,
        };

        // Fill the single-slot channel
        logger.log(make_event());
        // This should drop gracefully without blocking
        logger.log(make_event());
    }

    #[tokio::test]
    async fn builder_set_actor_populates_fields() {
        let (logger, mut rx) = make_logger(16);
        let builder = AuditEventBuilder::new(logger);

        builder.set_actor(
            Some("sub-abc"),
            &["admin".to_string(), "viewer".to_string()],
            serde_json::json!({ "tenant": "acme", "project": "research" }),
        );
        builder.set_event(EventType::DataAccess, "test");
        builder.emit_allowed();

        let event = rx.recv().await.expect("should receive event");
        assert_eq!(event.actor_sub.as_deref(), Some("sub-abc"));
        assert_eq!(
            event.actor_roles.as_deref(),
            Some(&["admin".to_string(), "viewer".to_string()][..])
        );
        assert_eq!(event.outcome, Outcome::Allowed);
    }

    #[tokio::test]
    async fn builder_set_actor_with_none_sub() {
        let (logger, mut rx) = make_logger(16);
        let builder = AuditEventBuilder::new(logger);

        builder.set_actor(None, &[], serde_json::Value::Null);
        builder.set_event(EventType::DataAccess, "test");
        builder.emit();

        let event = rx.recv().await.expect("should receive event");
        assert!(event.actor_sub.is_none());
    }

    #[tokio::test]
    async fn builder_emit_sends_to_channel() {
        let (logger, mut rx) = make_logger(16);
        let builder = AuditEventBuilder::new(logger);

        builder.set_event(EventType::AdminCreate, "create_role");
        builder.set_resource("role", "my-role");
        builder.set_outcome(Outcome::Allowed);
        builder.emit();

        let event = rx.recv().await.expect("should receive event");
        assert_eq!(event.event_type, "admin_create");
        assert_eq!(event.action, "create_role");
        assert_eq!(event.outcome, Outcome::Allowed);
        assert_eq!(event.resource_type.as_deref(), Some("role"));
        assert_eq!(event.resource_id.as_deref(), Some("my-role"));
        assert!(event.duration_ms.unwrap() >= 0);
    }

    #[tokio::test]
    async fn builder_emit_uses_explicit_duration_when_set() {
        let (logger, mut rx) = make_logger(16);
        let builder = AuditEventBuilder::new(logger);

        builder.set_event(EventType::DataAccess, "read");
        builder.set_outcome(Outcome::Allowed);
        builder.set_duration_ms(999);
        builder.emit();

        let event = rx.recv().await.expect("should receive event");
        assert_eq!(event.duration_ms, Some(999));
    }

    #[tokio::test]
    async fn set_request_metadata_parses_headers() {
        let (logger, mut rx) = make_logger(16);
        let builder = AuditEventBuilder::new(logger);

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "203.0.113.50, 70.41.3.18".parse().unwrap(),
        );
        headers.insert("user-agent", "test-agent/1.0".parse().unwrap());
        headers.insert("x-request-id", "req-abc-123".parse().unwrap());

        builder.set_request_metadata(&headers);
        builder.set_event(EventType::DataAccess, "test");
        builder.emit_allowed();

        let event = rx.recv().await.expect("should receive event");
        assert_eq!(event.source_ip.as_deref(), Some("203.0.113.50"));
        assert_eq!(event.user_agent.as_deref(), Some("test-agent/1.0"));
        assert_eq!(event.request_id.as_deref(), Some("req-abc-123"));
    }

    #[test]
    fn event_type_display() {
        assert_eq!(EventType::DataAccess.to_string(), "data_access");
        assert_eq!(EventType::AdminCreate.to_string(), "admin_create");
        assert_eq!(EventType::AdminUpdate.to_string(), "admin_update");
        assert_eq!(EventType::AdminDelete.to_string(), "admin_delete");
        assert_eq!(EventType::AuthFailure.to_string(), "auth_failure");
    }

    #[test]
    fn outcome_display() {
        assert_eq!(Outcome::Allowed.to_string(), "allowed");
        assert_eq!(Outcome::Denied.to_string(), "denied");
        assert_eq!(Outcome::Error.to_string(), "error");
    }

    // ── Exactly-once emission ───────────────────────────────

    #[tokio::test]
    async fn emit_is_exactly_once() {
        let (logger, mut rx) = make_logger(16);
        let builder = AuditEventBuilder::new(logger);

        builder.set_event(EventType::DataAccess, "read");
        builder.emit();
        builder.emit(); // second call should be a no-op

        let event = rx.recv().await.expect("first event");
        assert_eq!(event.action, "read");

        // Channel should be empty — no second event
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn clone_shares_state_exactly_once() {
        let (logger, mut rx) = make_logger(16);
        let builder = AuditEventBuilder::new(logger);
        let clone = builder.clone();

        builder.set_event(EventType::AdminDelete, "delete");
        clone.set_resource("widget", "w-1"); // enriches the SAME inner

        builder.emit();
        clone.emit(); // no-op — inner already taken by builder.emit()

        let event = rx.recv().await.expect("one event");
        assert_eq!(event.action, "delete");
        assert_eq!(event.resource_id.as_deref(), Some("w-1"));

        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn auto_emit_defaults_to_allowed() {
        let (logger, mut rx) = make_logger(16);
        let builder = AuditEventBuilder::new(logger);

        builder.set_event(EventType::DataAccess, "list");
        builder.auto_emit();

        let event = rx.recv().await.expect("auto-emitted event");
        assert_eq!(event.outcome, Outcome::Allowed);
        assert_eq!(event.action, "list");
    }

    #[tokio::test]
    async fn auto_emit_noop_after_explicit_emit() {
        let (logger, mut rx) = make_logger(16);
        let builder = AuditEventBuilder::new(logger);

        builder.set_event(EventType::AuthFailure, "invalid_token");
        builder.emit_denied("bad token");
        builder.auto_emit(); // should be a no-op

        let event = rx.recv().await.expect("denied event");
        assert_eq!(event.outcome, Outcome::Denied);
        assert_eq!(event.error_message.as_deref(), Some("bad token"));

        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn setters_noop_after_emit() {
        let (logger, mut rx) = make_logger(16);
        let builder = AuditEventBuilder::new(logger);

        builder.set_event(EventType::DataAccess, "read");
        builder.emit_allowed();

        // These should silently no-op
        builder.set_resource("widget", "w-99");
        builder.set_error("late error");

        let event = rx.recv().await.expect("event");
        assert!(event.resource_id.is_none());
        assert!(event.error_message.is_none());
    }
}
