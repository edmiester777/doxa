//! The grant half of `denials.rs`: handlers take only the guard, and the trail still names
//! the action, object and category, with status and outcome from the layer.

mod common;
use common::AllowAll;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde::Serialize;
use tower::ServiceExt;

use doxa::audit::{AuditEvent, AuditLayer, AuditLogger, EventType, Outcome};
use doxa::auth::{Cap, CapabilityContext, FromState, Granted, Granting, Many, Scoping};
use doxa::policy::{
    AuthError, Capability, CapabilityCheck, CapabilityChecker, Capable, ResourceId,
};
use doxa::{delete, get, routes, Actions, OpenApiRouter, PolicyResource, ToSchema};

// ---- domain -----------------------------------------------------------------

const WIDGETS_FLUSH: Capability = Capability {
    name: "widgets.flush",
    description: "Flush the widget cache",
    checks: &[CapabilityCheck {
        action: "flush",
        entity_type: "WidgetCache",
        entity_id: ResourceId::Literal("all"),
    }],
};

struct WidgetsFlush;
impl Capable for WidgetsFlush {
    const CAPABILITY: &'static Capability = &WIDGETS_FLUSH;
}

#[derive(Debug, Clone, Serialize, ToSchema, PolicyResource)]
#[resource(entity_type = "Widget")]
struct Widget {
    #[resource(id)]
    id: u32,
    name: String,
}

doxa::auth::route_key!(pub WidgetKey { id: u32 });

#[derive(Actions)]
#[actions(resource = "Widget")]
pub enum WidgetActions {
    #[action(verb = get, instance_only, event = EventType::DataAccess.as_static())]
    Read,
    #[action(verb = delete, instance_only, event = EventType::AdminDelete.as_static())]
    Delete,
}

impl Granting for Widget {
    type Row = Self;
    type Key = WidgetKey;
    type Ctx = CapabilityContext;
    type State = ();
    type Source = FromState<()>;
    type Error = StatusCode;

    type Actions = WidgetActions;

    async fn load(
        WidgetKey { id }: WidgetKey,
        _state: &(),
        _ctx: &CapabilityContext,
    ) -> Result<Option<Self>, StatusCode> {
        Ok(Some(Widget {
            id,
            name: "sprocket".into(),
        }))
    }
}

impl Scoping for Widget {
    type Filter = ();

    fn scope(_action: &str, _ctx: &CapabilityContext) -> Result<Option<()>, AuthError> {
        Ok(Some(()))
    }
}

// ---- routes: the guard and nothing else -------------------------------------

/// The subject through `Deref`, the caller through the inherent accessor that outranks it.
#[get("/widgets/{id}", tag = "Widgets")]
async fn get_widget(widget: Granted<Widget>) -> &'static str {
    // Deref: no unwrapping to read a field.
    assert_eq!(widget.id, 7);
    assert_eq!(widget.name, "sprocket");
    // Inherent, so it wins over anything Deref would reach.
    assert_eq!(widget.caller().tenant_id.as_deref(), Some("acme"));
    "ok"
}

#[get("/widgets", tag = "Widgets")]
async fn list_widgets(widgets: Granted<Many<Widget>>) -> &'static str {
    widgets.into_inner();
    "ok"
}

/// Both halves by value, through the pattern, with no clone.
#[delete("/widgets/{id}", tag = "Widgets")]
async fn delete_widget(Granted(caller, widget): Granted<Widget>) -> &'static str {
    assert_eq!(caller.tenant_id.as_deref(), Some("acme"));
    assert_eq!(widget.id, 7);
    "ok"
}

#[get("/flush", tag = "Widgets")]
async fn flush(_: Granted<Cap<WidgetsFlush>>) -> &'static str {
    "ok"
}

/// The one handler that does say something, to prove the deposit yields
/// rather than overwrites.
#[get("/widgets/{id}/rename", tag = "Widgets")]
async fn rename_widget(
    widget: Granted<Widget>,
    audit: axum::Extension<doxa::audit::AuditEventBuilder>,
) -> &'static str {
    audit.set_event(EventType::AdminUpdate, "rename_widget");
    audit.set_resource("WidgetName", "sprocket");
    let _ = widget.into_inner();
    "ok"
}

#[derive(Debug, thiserror::Error, Serialize, ToSchema, doxa::ApiError)]
enum WidgetError {
    #[error("the widget store is unreachable")]
    #[api(status = 500, code = "store_unreachable")]
    Unreachable,

    /// A miss is not an audit-worthy failure, and the annotation is how
    /// an author says so.
    #[error("no such widget")]
    #[api(status = 404, code = "not_found", outcome = "allowed")]
    NotFound,
}

/// Its error declares itself benign, and that must outlast the guard's deposit.
#[get("/widgets/{id}/missing", tag = "Widgets")]
async fn missing_widget(widget: Granted<Widget>) -> Result<&'static str, WidgetError> {
    let _ = widget.into_inner();
    Err(WidgetError::NotFound)
}

/// Emits from inside the handler; the layer must still set the status.
#[get("/widgets/{id}/eager", tag = "Widgets")]
async fn eager_emit(
    widget: Granted<Widget>,
    audit: axum::Extension<doxa::audit::AuditEventBuilder>,
) -> Result<&'static str, WidgetError> {
    let _ = widget.into_inner();

    audit.set_outcome(Outcome::Allowed);
    audit.emit();

    // The work the old early emit had already vouched for.
    Err(WidgetError::Unreachable)
}

// ---- policy stub ------------------------------------------------------------

// ---- harness ----------------------------------------------------------------

async fn call(method: &str, path: &str) -> (StatusCode, AuditEvent) {
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let (router, _) = OpenApiRouter::<()>::new()
        .routes(routes!(get_widget))
        .routes(routes!(list_widgets))
        .routes(routes!(delete_widget))
        .routes(routes!(flush))
        .routes(routes!(rename_widget))
        .routes(routes!(eager_emit))
        .routes(routes!(missing_widget))
        .split_for_parts();

    let app = router
        .layer(axum::middleware::from_fn(
            |mut request: Request<Body>, next: axum::middleware::Next| async move {
                request.extensions_mut().insert(CapabilityContext {
                    tenant_id: Some("acme".into()),
                    roles: vec!["viewer".into()],
                });
                let checker: Arc<dyn CapabilityChecker> = Arc::new(AllowAll);
                request.extensions_mut().insert(checker);
                next.run(request).await
            },
        ))
        .layer(AuditLayer::new(AuditLogger::from_sender(tx)));

    let response = app
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request");

    let status = response.status();
    let event = rx.recv().await.expect("a grant is recorded too");
    (status, event)
}

// ---- runtime ----------------------------------------------------------------

#[tokio::test]
async fn an_instance_grant_names_the_object_the_policy_saw() {
    let (status, event) = call("GET", "/widgets/7").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(event.outcome, Outcome::Allowed);
    assert_eq!(event.action, "read", "the action comes from the verb");
    assert_eq!(event.resource_type.as_deref(), Some("Widget"));
    assert_eq!(event.resource_id.as_deref(), Some("7"));
    assert_eq!(
        event.event_type, "data_access",
        "the category comes from the asset, not the handler",
    );
    assert_eq!(
        event.http_status,
        Some(200),
        "the layer stamps the real status, because nothing emitted early",
    );
    assert_eq!(event.http_path.as_deref(), Some("/widgets/7"));
    assert!(event.error_message.is_none());
}

/// The verb picks the category from the asset's own mapping.
#[tokio::test]
async fn the_verb_picks_the_category() {
    let (_, event) = call("DELETE", "/widgets/7").await;

    assert_eq!(event.action, "delete");
    assert_eq!(event.event_type, "admin_delete");
    assert_eq!(event.resource_id.as_deref(), Some("7"));
}

/// A listing names no object, so it records the same collection id its
/// refusal would — one resource covers both halves of the trail.
#[tokio::test]
async fn a_collection_grant_names_the_collection() {
    let (status, event) = call("GET", "/widgets").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(event.outcome, Outcome::Allowed);
    assert_eq!(event.resource_type.as_deref(), Some("Widget"));
    assert_eq!(event.resource_id.as_deref(), Some("collection"));
    assert_eq!(event.event_type, "data_access");
}

/// A bare capability has no asset behind it, so it records the check
/// that would have short-circuited had it been refused.
#[tokio::test]
async fn a_capability_grant_names_the_capability_check() {
    let (status, event) = call("GET", "/flush").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(event.outcome, Outcome::Allowed);
    assert_eq!(event.action, "widgets.flush");
    assert_eq!(event.resource_type.as_deref(), Some("WidgetCache"));
    assert_eq!(event.resource_id.as_deref(), Some("all"));
    assert_eq!(
        event.event_type, "",
        "a capability has no asset to declare a category",
    );
}

/// The deposit fills blanks and never overwrites, whatever the order.
#[tokio::test]
async fn a_handler_that_names_the_event_itself_wins() {
    let (status, event) = call("GET", "/widgets/7/rename").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(event.event_type, "admin_update");
    assert_eq!(event.action, "rename_widget");
    assert_eq!(event.resource_type.as_deref(), Some("WidgetName"));
    assert_eq!(event.resource_id.as_deref(), Some("sprocket"));
}

/// An emit inside the request defers, so the layer still sets the real status.
#[tokio::test]
async fn an_eager_emit_no_longer_costs_the_status_or_the_outcome() {
    let (status, event) = call("GET", "/widgets/7/eager").await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        event.http_status,
        Some(500),
        "the layer stamps the response it actually sent",
    );
    assert_eq!(
        event.outcome,
        Outcome::Error,
        "the handler vouched for a success it never reached",
    );
    assert_eq!(
        event.resource_id.as_deref(),
        Some("7"),
        "the guard's deposit survives the handler's emit",
    );
}

/// `outcome = "allowed"` is the last word, whatever the guard deposited.
#[tokio::test]
async fn an_allowed_annotation_reaches_the_event() {
    let (status, event) = call("GET", "/widgets/7/missing").await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        event.outcome,
        Outcome::Allowed,
        "the variant declared itself benign",
    );
    assert_eq!(event.http_status, Some(404));
    assert_eq!(
        event.resource_id.as_deref(),
        Some("7"),
        "and the trail still says what was reached for",
    );
}

#[derive(Clone, doxa::State)]
struct NoState;

impl axum::extract::FromRef<NoState> for () {
    fn from_ref(_: &NoState) {}
}
