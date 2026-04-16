//! Audit event channel and background persistence.
//!
//! [`AuditLogger`] is a cloneable sender that enqueues events for background
//! persistence. The writer loop drains the channel and inserts rows into
//! `doxa_audit_log` via SeaORM (behind the `sea-orm` feature).

use tokio::sync::mpsc;

use crate::event::AuditEvent;

/// Cloneable handle for sending audit events to the background writer.
///
/// Uses `try_send` to avoid blocking request execution. If the channel is
/// full, the event is dropped with a warning — audit persistence must never
/// degrade query latency.
///
/// `AuditLogger` itself does not depend on SeaORM — it's a plain
/// [`mpsc::Sender`] wrapper. Downstream crates that want to own the
/// channel but ship events to a non-SeaORM sink can disable the
/// `sea-orm` feature on this crate and still use `AuditLogger` and
/// [`AuditEventBuilder`](crate::AuditEventBuilder).
#[derive(Clone, Debug)]
pub struct AuditLogger {
    pub(crate) tx: mpsc::Sender<AuditEvent>,
}

impl AuditLogger {
    /// Wrap an existing [`mpsc::Sender`] as an [`AuditLogger`].
    ///
    /// Use this when you want to consume audit events with a custom
    /// backend instead of the built-in SeaORM writer. The sender end
    /// of the channel becomes the logger; you own the receiver and
    /// drain it however you like.
    pub fn from_sender(tx: mpsc::Sender<AuditEvent>) -> Self {
        Self { tx }
    }

    /// Send an event to the background writer. Drops silently (with a warning
    /// log) if the channel buffer is full.
    pub fn log(&self, event: AuditEvent) {
        if let Err(mpsc::error::TrySendError::Full(dropped)) = self.tx.try_send(event) {
            tracing::warn!(
                dropped_event_type = %dropped.event_type,
                dropped_action = %dropped.action,
                "audit channel full — dropping event",
            );
        }
    }
}

#[cfg(feature = "sea-orm")]
pub use sea_orm_writer::spawn_audit_writer;

#[cfg(feature = "sea-orm")]
mod sea_orm_writer {
    use sea_orm::{ActiveModelTrait, ActiveValue::Set, DatabaseConnection};
    use tokio::sync::mpsc;
    use uuid::Uuid;

    use super::AuditLogger;
    use crate::entity::doxa_audit_log;
    use crate::event::AuditEvent;

    /// Spawns a background task that drains audit events from the
    /// channel and persists them to `doxa_audit_log` via SeaORM.
    ///
    /// Returns the [`AuditLogger`] handle for sending events.
    pub fn spawn_audit_writer(db: DatabaseConnection, buffer_size: usize) -> AuditLogger {
        let (tx, rx) = mpsc::channel(buffer_size);
        let span = tracing::info_span!("audit_writer", buffer_size);
        tokio::spawn(tracing::Instrument::instrument(
            audit_writer_loop(db, rx),
            span,
        ));
        AuditLogger { tx }
    }

    async fn audit_writer_loop(db: DatabaseConnection, mut rx: mpsc::Receiver<AuditEvent>) {
        while let Some(event) = rx.recv().await {
            if let Err(e) = persist_event(&db, &event).await {
                tracing::error!(
                    error = %e,
                    event_type = %event.event_type,
                    action = %event.action,
                    "failed to persist audit event",
                );
            }
        }
        tracing::info!("audit writer shutting down — channel closed");
    }

    async fn persist_event(
        db: &DatabaseConnection,
        event: &AuditEvent,
    ) -> Result<(), sea_orm::DbErr> {
        let roles_json = event.actor_roles.as_ref().map(|r| {
            serde_json::Value::Array(
                r.iter()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .collect(),
            )
        });

        let model = doxa_audit_log::ActiveModel {
            id: Set(Uuid::new_v4()),
            event_type: Set(event.event_type.clone()),
            action: Set(event.action.clone()),
            outcome: Set(event.outcome),
            actor_sub: Set(event.actor_sub.clone()),
            actor_roles: Set(roles_json),
            actor_attrs: Set(event.actor_attrs.clone()),
            resource_type: Set(event.resource_type.clone()),
            resource_id: Set(event.resource_id.clone()),
            request_body: Set(event.request_body.clone()),
            response_summary: Set(event.response_summary.clone()),
            source_ip: Set(event.source_ip.clone()),
            user_agent: Set(event.user_agent.clone()),
            request_id: Set(event.request_id.clone()),
            http_method: Set(event.http_method.clone()),
            http_path: Set(event.http_path.clone()),
            http_status: Set(event.http_status.map(|s| s as i16)),
            duration_ms: Set(event.duration_ms),
            error_message: Set(event.error_message.clone()),
            created_at: Set(chrono::Utc::now().fixed_offset()),
        };

        model.insert(db).await?;
        Ok(())
    }
}
