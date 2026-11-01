//! `routes!` answers a `<Can>` dry run of an unguarded route without running it,
//! and leaves a guarded one to its guard.

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

#[post("/notes")]
async fn add_note(axum::Json(_note): axum::Json<String>) -> StatusCode {
    RAN.fetch_add(1, Ordering::SeqCst);
    StatusCode::CREATED
}

#[get("/notes")]
async fn list_notes(_: Require<NotesRead>) -> &'static str {
    RAN.fetch_add(1, Ordering::SeqCst);
    "[]"
}

async fn send(method: &str, dry_run: bool) -> axum::response::Response {
    let (router, _) = OpenApiRouter::<()>::new()
        .routes(routes!(add_note, list_notes))
        .split_for_parts();
    let mut req = Request::builder().method(method).uri("/notes");
    if dry_run {
        req = req.header(doxa::wire::DRY_RUN_HEADER, "1");
    }
    let req = req
        .header("content-type", "application/json")
        .body(Body::from("\"hi\""))
        .unwrap();
    router.oneshot(req).await.unwrap()
}

#[tokio::test]
async fn an_unguarded_route_answers_without_running() {
    let before = RAN.load(Ordering::SeqCst);
    let resp = send("POST", true).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        resp.headers()[doxa::wire::DRY_RUN_HEADER],
        doxa::wire::DRY_RUN_OK
    );
    assert_eq!(resp.headers()["cache-control"], "no-store");
    assert_eq!(RAN.load(Ordering::SeqCst), before);

    assert_eq!(send("POST", false).await.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn a_guarded_route_is_left_to_its_guard() {
    let resp = send("GET", true).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(resp.headers().get(doxa::wire::DRY_RUN_HEADER).is_none());
}
