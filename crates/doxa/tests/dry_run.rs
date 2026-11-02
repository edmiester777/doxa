//! A `<Can>` dry run is answered by the route's guard, and never reaches an unguarded handler.

use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use doxa::auth::Require;
use doxa::policy::{Capability, CapabilityCheck, Capable, ResourceId};
use doxa::{get, post, routes, OpenApiRouter};
use tower::ServiceExt;

static RAN: AtomicUsize = AtomicUsize::new(0);

pub const NOTES_READ: Capability = Capability {
    name: "notes.read",
    description: "Read notes",
    checks: &[CapabilityCheck {
        action: "read",
        entity_type: "Note",
        entity_id: ResourceId::Literal("collection"),
    }],
};

pub struct NotesRead;
impl Capable for NotesRead {
    const CAPABILITY: &'static Capability = &NOTES_READ;
}

#[get("/notes")]
async fn list_notes(_: Require<NotesRead>) -> &'static str {
    RAN.fetch_add(1, Ordering::SeqCst);
    "[]"
}

static PINGED: AtomicUsize = AtomicUsize::new(0);

#[post("/ping")]
async fn ping() -> StatusCode {
    PINGED.fetch_add(1, Ordering::SeqCst);
    StatusCode::ACCEPTED
}

#[cfg(feature = "client-router")]
mod client {
    doxa::client::__as_client! {
        #[post("/ping")]
        pub async fn ping() -> StatusCode { unreachable!() }
    }
}

#[cfg(feature = "client-router")]
#[tokio::test]
async fn a_probe_never_reaches_an_unguarded_route() {
    use doxa::client::transport::RouterTransport;
    use doxa::client::{layer::transport, service, Permission};

    let router = axum::Router::new().route("/ping", axum::routing::post(ping));
    service("doxa")
        .layers()
        .push(transport(RouterTransport::new(router)));
    assert_eq!(client::ping::can().await, Permission::Unknown);
    assert_eq!(PINGED.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_guarded_route_is_left_to_its_guard() {
    let (router, _) = OpenApiRouter::<()>::new()
        .routes(routes!(list_notes))
        .split_for_parts();
    let req = Request::get("/notes")
        .header(doxa::wire::DRY_RUN_HEADER, "1")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(resp.headers().get(doxa::wire::DRY_RUN_HEADER).is_none());
}
