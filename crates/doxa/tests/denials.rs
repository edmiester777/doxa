//! A refusal is the event an audit trail exists for, so every guard
//! records one: which capability or action was refused, on which
//! resource, with an outcome of `Denied` — and it does so whether the
//! audit builder arrives from an `AuditLayer` or from an auth layer
//! carrying its own logger.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde::Serialize;
use tower::ServiceExt;

use doxa::audit::{AuditEvent, AuditEventBuilder, AuditLayer, AuditLogger, Outcome};
use doxa::auth::{CapabilityContext, Granted, Granting, Require};
use doxa::policy::{
    AuthError, Capability, CapabilityCheck, CapabilityChecker, Capable, ResourceEntity,
};
use doxa::{get, routes, OpenApiRouter, PolicyResource, ToSchema};

// ---- domain -----------------------------------------------------------------

const WIDGETS_READ: Capability = Capability {
    name: "widgets.read",
    description: "Read widget definitions",
    checks: &[CapabilityCheck {
        action: "read",
        entity_type: "Widget",
        entity_id: "collection",
    }],
};

struct WidgetsRead;
impl Capable for WidgetsRead {
    const CAPABILITY: &'static Capability = &WIDGETS_READ;
}

#[derive(Debug, Clone, Serialize, ToSchema, PolicyResource)]
#[resource(entity_type = "Widget")]
struct Widget {
    #[resource(id)]
    id: u32,
    name: String,
}

/// No coarse capability, so the chain goes straight to the instance
/// check — this file is about what an *instance* denial records.
impl Granting for Widget {
    type Key = u32;
    type Ctx = CapabilityContext;
    type State = ();
    type Error = StatusCode;
    type Filter = ();

    async fn load(
        id: u32,
        _state: &(),
        _ctx: &CapabilityContext,
    ) -> Result<Option<Self>, StatusCode> {
        Ok(Some(Widget {
            id,
            name: "sprocket".into(),
        }))
    }
}

#[get("/widgets", tag = "Widgets")]
async fn list_widgets(_: Require<WidgetsRead>) -> &'static str {
    "ok"
}

#[get("/widgets/{id}", tag = "Widgets")]
async fn get_widget(widget: Granted<Widget>) -> &'static str {
    let _ = widget.into_inner();
    "ok"
}

// ---- policy stub ------------------------------------------------------------

/// Refuses everything, so both guards take their deny path.
struct DenyAll;

#[async_trait]
impl CapabilityChecker for DenyAll {
    async fn check(&self, _: &str, _: &[String], _: &Capability) -> Result<bool, AuthError> {
        Ok(false)
    }

    async fn check_instance(
        &self,
        _: &str,
        _: &[String],
        _: &str,
        _: &ResourceEntity,
    ) -> Result<bool, AuthError> {
        Ok(false)
    }
}

// ---- harness ----------------------------------------------------------------

fn caller(request: &mut Request<Body>) {
    request.extensions_mut().insert(CapabilityContext {
        tenant_id: Some("acme".into()),
        roles: vec!["viewer".into()],
    });
    let checker: Arc<dyn CapabilityChecker> = Arc::new(DenyAll);
    request.extensions_mut().insert(checker);
}

/// The documented wiring: `AuditLayer` creates the builder and would
/// auto-emit if no guard had already spoken.
async fn with_audit_layer(path: &str) -> (StatusCode, AuditEvent) {
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let (router, _) = OpenApiRouter::<()>::new()
        .routes(routes!(list_widgets))
        .routes(routes!(get_widget))
        .split_for_parts();

    let app = router
        .layer(axum::middleware::from_fn(
            |mut request: Request<Body>, next: axum::middleware::Next| async move {
                caller(&mut request);
                next.run(request).await
            },
        ))
        .layer(AuditLayer::new(AuditLogger::from_sender(tx)));

    let response = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .expect("request");
    let status = response.status();
    let event = rx.recv().await.expect("a denial is always recorded");
    (status, event)
}

// ---- runtime ----------------------------------------------------------------

#[tokio::test]
async fn a_capability_denial_names_the_capability() {
    let (status, event) = with_audit_layer("/widgets").await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(event.outcome, Outcome::Denied);
    assert_eq!(
        event.action, "widgets.read",
        "the trail must say which capability was refused",
    );
    assert_eq!(event.event_type, "auth_failure");
    assert_eq!(event.resource_type.as_deref(), Some("Widget"));
    assert_eq!(
        event.resource_id.as_deref(),
        Some("collection"),
        "the capability's first check is the one that short-circuits",
    );
    assert_eq!(event.error_message.as_deref(), Some("capability denied"));
    assert_eq!(
        event.http_status,
        Some(403),
        "emitting early must not cost the status",
    );
    assert_eq!(event.http_path.as_deref(), Some("/widgets"));
}

#[tokio::test]
async fn an_instance_denial_names_the_object() {
    let (status, event) = with_audit_layer("/widgets/7").await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(event.outcome, Outcome::Denied);
    assert_eq!(event.action, "read", "the action comes from the verb");
    assert_eq!(event.resource_type.as_deref(), Some("Widget"));
    assert_eq!(event.resource_id.as_deref(), Some("7"));
    assert_eq!(event.error_message.as_deref(), Some("instance denied"));
    assert_eq!(event.http_status, Some(403));
}

/// Without `AuditLayer` nothing terminates the builder after the
/// response, so before this fix a denial in this wiring emitted nothing
/// whatsoever. The guard emits it directly, so the trail survives.
#[tokio::test]
async fn a_denial_is_recorded_without_an_audit_layer() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let logger = AuditLogger::from_sender(tx);
    let (router, _) = OpenApiRouter::<()>::new()
        .routes(routes!(list_widgets))
        .split_for_parts();

    // Stands in for an `AuthLayer` built with a logger but no
    // `AuditLayer` above it: it puts a builder in extensions and nothing
    // else ever emits.
    let app = router.layer(axum::middleware::from_fn(
        move |mut request: Request<Body>, next: axum::middleware::Next| {
            let logger = logger.clone();
            async move {
                caller(&mut request);
                request
                    .extensions_mut()
                    .insert(AuditEventBuilder::new(logger));
                next.run(request).await
            }
        },
    ));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/widgets")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let event = rx.try_recv().expect("the guard emits without a layer");
    assert_eq!(event.outcome, Outcome::Denied);
    assert_eq!(event.action, "widgets.read");
}

/// A guard with no audit builder in extensions must still refuse
/// cleanly — the log line is unconditional, the audit half is not.
#[tokio::test]
async fn a_denial_without_any_audit_wiring_still_refuses() {
    let (router, _) = OpenApiRouter::<()>::new()
        .routes(routes!(list_widgets))
        .split_for_parts();
    let app = router.layer(axum::middleware::from_fn(
        |mut request: Request<Body>, next: axum::middleware::Next| async move {
            caller(&mut request);
            next.run(request).await
        },
    ));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/widgets")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
