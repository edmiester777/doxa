//! End-to-end coverage for the instance-level `Permitted<R, S>` guard:
//! the resource's attributes reach the policy check, denials are
//! recorded against the object that was refused, and the operation
//! documents the parameter and the statuses the guard can return.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Json;
use serde::Serialize;
use serde_json::json;
use tower::ServiceExt;

use doxa::audit::{AuditEvent, AuditLayer, AuditLogger, Outcome};
use doxa::auth::{authorize_instance, CapabilityContext, LoadResource, Permitted};
use doxa::policy::{AuthError, Capability, CapabilityChecker, ResourceEntity};
use doxa::{get, routes, OpenApiRouter, PolicyResource, ToSchema};

// ---- domain -----------------------------------------------------------------

#[derive(Debug, Clone, Serialize, ToSchema, PolicyResource)]
#[resource(entity_type = "Widget")]
struct Widget {
    #[resource(id)]
    id: u32,
    name: String,
    #[resource(attr)]
    region: String,
    #[resource(parent = "Folder")]
    folder: String,
}

impl LoadResource for Widget {
    type State = ();
    type Error = StatusCode;

    async fn load(
        id: u32,
        _state: &(),
        caller: &CapabilityContext,
    ) -> Result<Option<Self>, StatusCode> {
        assert_eq!(
            caller.tenant_id.as_deref(),
            Some("acme"),
            "the loader must be able to scope by tenant",
        );
        Ok(match id {
            1 => Some(Widget {
                id: 1,
                name: "sprocket".into(),
                region: "us".into(),
                folder: "shared".into(),
            }),
            2 => Some(Widget {
                id: 2,
                name: "cog".into(),
                region: "eu".into(),
                folder: "shared".into(),
            }),
            _ => None,
        })
    }
}

/// `#[param]` names the parameter; the `get` verb supplies the action.
/// The route has two path parameters, so the annotation is required.
#[get("/folders/{fid}/widgets/{id}", tag = "Widgets")]
async fn get_widget(#[param("id")] widget: Permitted<Widget>) -> Json<Widget> {
    Json(widget.into_inner())
}

// ---- policy stub ------------------------------------------------------------

/// Grants `read` only on widgets whose injected `region` attribute is
/// `us`, so a wrong decision means the attributes never arrived.
struct RegionChecker;

#[async_trait]
impl CapabilityChecker for RegionChecker {
    async fn check(&self, _: &str, _: &[String], _: &Capability) -> Result<bool, AuthError> {
        Ok(true)
    }

    async fn check_instance(
        &self,
        _tenant_id: &str,
        _roles: &[String],
        action: &str,
        resource: &ResourceEntity,
    ) -> Result<bool, AuthError> {
        assert_eq!(action, "read", "action comes from the site marker");
        assert_eq!(resource.entity_type, "Widget");
        assert_eq!(
            resource.parents,
            vec![("Folder".to_string(), "shared".to_string())],
            "parents must survive the trip to the checker",
        );
        Ok(resource.attrs.get("region") == Some(&json!("us")))
    }
}

// ---- harness ----------------------------------------------------------------

fn app() -> (axum::Router, tokio::sync::mpsc::Receiver<AuditEvent>) {
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let (router, _) = OpenApiRouter::<()>::new()
        .routes(routes!(get_widget))
        .split_for_parts();

    let app = router
        .layer(axum::middleware::from_fn(inject_auth))
        .layer(AuditLayer::new(AuditLogger::from_sender(tx)));
    (app, rx)
}

/// Stands in for `AuthLayer`, which needs a full OIDC setup.
async fn inject_auth(
    mut request: Request<Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    request.extensions_mut().insert(CapabilityContext {
        tenant_id: Some("acme".into()),
        roles: vec!["viewer".into()],
    });
    let checker: Arc<dyn CapabilityChecker> = Arc::new(RegionChecker);
    request.extensions_mut().insert(checker);
    next.run(request).await
}

async fn call(path: &str) -> (StatusCode, AuditEvent) {
    let (app, mut rx) = app();
    let response = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .expect("request");
    let status = response.status();
    let event = rx.recv().await.expect("an audit event per request");
    (status, event)
}

// ---- runtime ----------------------------------------------------------------

#[tokio::test]
async fn allowed_instance_reaches_the_handler() {
    let (status, event) = call("/folders/f1/widgets/1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(event.outcome, Outcome::Allowed);
    assert_eq!(event.resource_type.as_deref(), Some("Widget"));
    assert_eq!(event.resource_id.as_deref(), Some("1"));
    assert_eq!(event.action, "read");
}

#[tokio::test]
async fn denied_instance_is_recorded_against_the_object() {
    let (status, event) = call("/folders/f1/widgets/2").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        event.outcome,
        Outcome::Denied,
        "a policy denial is not a system error",
    );
    assert_eq!(
        event.resource_id.as_deref(),
        Some("2"),
        "the denial must name the object that was refused",
    );
}

#[tokio::test]
async fn missing_instance_is_a_404_that_still_records_the_attempt() {
    let (status, event) = call("/folders/f1/widgets/99").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        event.resource_id.as_deref(),
        Some("99"),
        "stamping happens before the load, so the attempt is logged",
    );
}

#[tokio::test]
async fn unparseable_id_is_rejected_before_any_policy_call() {
    let (status, _) = call("/folders/f1/widgets/not-a-number").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unauthenticated_requests_never_reach_the_loader() {
    // No `inject_auth`, so nothing puts a `CapabilityContext` in
    // extensions. A 404 here would tell an anonymous caller which ids
    // exist.
    let (tx, _rx) = tokio::sync::mpsc::channel(16);
    let (router, _) = OpenApiRouter::<()>::new()
        .routes(routes!(get_widget))
        .split_for_parts();
    let app = router.layer(AuditLayer::new(AuditLogger::from_sender(tx)));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/folders/f1/widgets/1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ---- inline authorization ---------------------------------------------------

/// Extensions as `AuthLayer` would leave them, with no request around
/// them — the position a handler is in when the id it needs came out of
/// a request body.
fn caller_extensions() -> axum::http::Extensions {
    let mut ext = axum::http::Extensions::new();
    ext.insert(CapabilityContext {
        tenant_id: Some("acme".into()),
        roles: vec!["viewer".into()],
    });
    let checker: Arc<dyn CapabilityChecker> = Arc::new(RegionChecker);
    ext.insert(checker);
    ext
}

/// An id no extractor can see still gets the guard's decision, not a
/// bare lookup.
#[tokio::test]
async fn inline_authorization_reaches_the_same_verdicts() {
    let ext = caller_extensions();

    let allowed = authorize_instance::<Widget>(1, "read", &(), &ext)
        .await
        .expect("region us is granted");
    assert_eq!(allowed.name, "sprocket");

    // Same policy, same checker — the attributes decide, exactly as they
    // do through the extractor.
    let denied = authorize_instance::<Widget>(2, "read", &(), &ext)
        .await
        .expect_err("region eu is denied");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let missing = authorize_instance::<Widget>(99, "read", &(), &ext)
        .await
        .expect_err("no such widget");
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

/// Without a caller in extensions there is nothing to authorize against,
/// and a body-named id must not become a lookup oracle either.
#[tokio::test]
async fn inline_authorization_without_a_caller_is_unauthorized() {
    let err = authorize_instance::<Widget>(1, "read", &(), &axum::http::Extensions::new())
        .await
        .expect_err("no capability context");
    assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
}

// ---- openapi ----------------------------------------------------------------

fn operation() -> utoipa::openapi::path::Operation {
    let (_, openapi) = OpenApiRouter::<()>::new()
        .routes(routes!(get_widget))
        .split_for_parts();
    openapi.paths.paths["/folders/{fid}/widgets/{id}"]
        .get
        .as_ref()
        .expect("get operation")
        .clone()
}

#[test]
fn guard_documents_the_named_path_parameter() {
    let op = operation();
    let params = op.parameters.expect("parameters");
    let id = params
        .iter()
        .find(|p| p.name == "id")
        .expect("`id` documented from PermitSite::PARAM, not by position");
    assert!(matches!(
        id.parameter_in,
        utoipa::openapi::path::ParameterIn::Path
    ));
    assert!(
        !params.iter().any(|p| p.name == "fid"),
        "the guard documents only its own parameter",
    );

    // The derive infers `ID_TYPE` from the `u32` id field.
    let schema = serde_json::to_value(id.schema.as_ref().expect("schema")).expect("json");
    assert_eq!(schema["type"], "integer", "got {schema}");
}

#[test]
fn guard_documents_its_rejection_statuses() {
    let op = operation();
    let statuses: Vec<&str> = op.responses.responses.keys().map(String::as_str).collect();
    for expected in ["400", "401", "403", "404"] {
        assert!(
            statuses.contains(&expected),
            "missing {expected}, got {statuses:?}",
        );
    }
}

#[test]
fn guard_records_the_instance_permission() {
    let op = operation();
    let ext = serde_json::to_value(op.extensions.expect("extensions")).expect("json");
    let perms = ext["x-required-permissions"]
        .as_array()
        .expect("x-required-permissions");
    assert!(
        perms
            .iter()
            .any(|p| p.as_str() == Some("read on Widget (instance)")),
        "got {perms:?}",
    );
}
