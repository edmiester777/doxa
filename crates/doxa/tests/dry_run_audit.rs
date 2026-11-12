//! A dry run runs every guard, in whatever order, then stops short of the handler. The header
//! is the caller's to set, so the trail says `probe` only when that is what happened.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Json;
use doxa::audit::{AuditEvent, AuditLayer, AuditLogger, Outcome};
use doxa::auth::{CapabilityContext, FromState, GrantSite, Granted, Granting, One, Require};
use doxa::policy::{
    AuthError, Capability, CapabilityCheck, CapabilityChecker, Capable, ResourceEntity, ResourceId,
};
use doxa::{delete, get, post, routes, Actions, OpenApiRouter, PolicyResource, ToSchema};
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

const GADGETS_ADMIN: Capability = Capability {
    name: "gadgets.admin",
    description: "Administer gadgets",
    checks: &[CapabilityCheck {
        action: "admin",
        entity_type: "Gadget",
        entity_id: ResourceId::Literal("collection"),
    }],
};

struct GadgetsAdmin;
impl Capable for GadgetsAdmin {
    const CAPABILITY: &'static Capability = &GADGETS_ADMIN;
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PolicyResource)]
#[resource(entity_type = "Gadget")]
struct Gadget {
    #[resource(id)]
    id: u32,
}

doxa::auth::route_key!(pub GadgetKey { id: u32 });

#[derive(Actions)]
#[actions(resource = "Gadget")]
pub enum GadgetActions {
    #[action(verb = get, instance_only)]
    Read,
    #[action(verb = delete, instance_only)]
    Delete,
}

impl Granting for Gadget {
    type Row = Self;
    type Key = GadgetKey;
    type Ctx = CapabilityContext;
    type State = ();
    type Source = FromState<()>;
    type Error = StatusCode;
    type Actions = GadgetActions;

    async fn load(
        GadgetKey { id }: GadgetKey,
        _: &(),
        _: &CapabilityContext,
    ) -> Result<Option<Self>, StatusCode> {
        Ok(Some(Gadget { id }))
    }
}

#[derive(Clone, doxa::State)]
struct NoState;

impl axum::extract::FromRef<NoState> for () {
    fn from_ref(_: &NoState) {}
}

struct MySite;
impl GrantSite for MySite {}

/// Handlers that ran. Nothing here should, under the header.
static RAN: AtomicUsize = AtomicUsize::new(0);

fn ran() -> StatusCode {
    RAN.fetch_add(1, Ordering::SeqCst);
    StatusCode::OK
}

#[get("/generated/{id}")]
async fn generated(_: Granted<Gadget>) -> StatusCode {
    ran()
}

#[get("/sited/{id}")]
async fn sited(_: Granted<One<Gadget, gadget_actions::Read, MySite>>) -> StatusCode {
    ran()
}

#[delete("/required")]
async fn required(_: Require<GadgetsAdmin>) -> StatusCode {
    ran()
}

#[delete("/granted-first/{id}")]
async fn granted_first(_: Granted<Gadget>, _: Require<GadgetsAdmin>) -> StatusCode {
    ran()
}

#[delete("/required-first/{id}")]
async fn required_first(_: Require<GadgetsAdmin>, _: Granted<Gadget>) -> StatusCode {
    ran()
}

#[post("/bodied")]
async fn bodied(_: Require<GadgetsAdmin>, Json(_): Json<Gadget>) -> StatusCode {
    ran()
}

#[post("/open")]
async fn open() -> StatusCode {
    ran()
}

/// One answer per kind of check, so a test can refuse just the guard it means.
struct Policy {
    capability: bool,
    instance: bool,
}

#[async_trait]
impl CapabilityChecker for Policy {
    async fn check(&self, _: &str, _: &[String], _: &Capability) -> Result<bool, AuthError> {
        Ok(self.capability)
    }

    async fn check_instance(
        &self,
        _: &str,
        _: &[String],
        _: &str,
        _: &ResourceEntity,
    ) -> Result<bool, AuthError> {
        Ok(self.instance)
    }
}

const ALLOW: (bool, bool) = (true, true);

async fn probe(
    method: &str,
    path: &str,
    (capability, instance): (bool, bool),
) -> (StatusCode, bool, AuditEvent) {
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let (router, _) = OpenApiRouter::<()>::new()
        .routes(routes!(generated))
        .routes(routes!(sited))
        .routes(routes!(required))
        .routes(routes!(granted_first))
        .routes(routes!(required_first))
        .routes(routes!(bodied))
        .routes(routes!(open))
        .split_for_parts();
    let app = router
        .layer(axum::middleware::from_fn(
            move |mut request: Request<Body>, next: axum::middleware::Next| async move {
                request.extensions_mut().insert(CapabilityContext {
                    tenant_id: Some("acme".into()),
                    roles: vec!["viewer".into()],
                });
                let checker: Arc<dyn CapabilityChecker> = Arc::new(Policy {
                    capability,
                    instance,
                });
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
                .header(doxa::wire::DRY_RUN_HEADER, "1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let echoed = response
        .headers()
        .get(doxa::wire::DRY_RUN_HEADER)
        .is_some_and(|v| v == doxa::wire::DRY_RUN_OK);
    (
        response.status(),
        echoed,
        rx.recv().await.expect("an event"),
    )
}

async fn assert_answered(method: &str, path: &str) {
    let before = RAN.load(Ordering::SeqCst);
    let (status, echoed, event) = probe(method, path, ALLOW).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{path}");
    assert!(echoed, "{path}");
    assert_eq!(event.outcome, Outcome::Probe, "{path}");
    assert_eq!(RAN.load(Ordering::SeqCst), before, "{path} ran its handler");
}

async fn assert_refused(method: &str, path: &str, policy: (bool, bool)) {
    let before = RAN.load(Ordering::SeqCst);
    let (status, echoed, event) = probe(method, path, policy).await;
    // An instance denial hides the row; a capability denial says so.
    let refused = match policy.0 {
        true => StatusCode::NOT_FOUND,
        false => StatusCode::FORBIDDEN,
    };
    assert_eq!(status, refused, "{path}");
    assert!(!echoed, "{path}");
    assert_eq!(event.outcome, Outcome::Denied, "{path}");
    assert_eq!(RAN.load(Ordering::SeqCst), before, "{path} ran its handler");
}

#[tokio::test]
async fn no_handler_runs_whatever_guards_it_has() {
    assert_answered("GET", "/generated/7").await;
    assert_answered("GET", "/sited/7").await;
    assert_answered("DELETE", "/required").await;
    assert_answered("DELETE", "/granted-first/7").await;
    assert_answered("DELETE", "/required-first/7").await;
    assert_answered("POST", "/open").await;
}

#[tokio::test]
async fn a_required_body_does_not_stop_the_answer() {
    assert_answered("POST", "/bodied").await;
}

/// Either guard can refuse, wherever it sits.
#[tokio::test]
async fn every_guard_is_asked_in_either_order() {
    for path in ["/granted-first/7", "/required-first/7"] {
        assert_refused("DELETE", path, (false, true)).await;
        assert_refused("DELETE", path, (true, false)).await;
    }
}

#[tokio::test]
async fn a_refused_dry_run_is_recorded_as_denied() {
    assert_refused("GET", "/generated/7", (true, false)).await;
    assert_refused("GET", "/sited/7", (true, false)).await;
    assert_refused("DELETE", "/required", (false, true)).await;
}
