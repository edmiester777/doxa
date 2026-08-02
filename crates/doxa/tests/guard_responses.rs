//! Guard extractors document the statuses they reject with.
//!
//! Response inference reads only the handler's `Err` type, so without a
//! `DocOperationContribution` impl a `Require<M>` handler advertises a
//! spec in which it can only succeed.

use doxa::auth::Require;
use doxa::policy::{Capability, CapabilityCheck, Capable};
use doxa::{get, routes, OpenApiRouter};

pub const WIDGETS_READ: Capability = Capability {
    name: "widgets.read",
    description: "Read widget definitions",
    checks: &[CapabilityCheck {
        action: "read",
        entity_type: "Widget",
        entity_id: "collection",
    }],
};

pub struct WidgetsRead;
impl Capable for WidgetsRead {
    const CAPABILITY: &'static Capability = &WIDGETS_READ;
}

/// Infallible return type — every documented error status has to come
/// from the guard, not from the handler.
#[get("/widgets", tag = "Widgets")]
async fn list_widgets(_: Require<WidgetsRead>) -> &'static str {
    "[]"
}

#[get("/health", tag = "Ops")]
async fn health() -> &'static str {
    "ok"
}

fn spec() -> utoipa::openapi::OpenApi {
    let (_, openapi) = OpenApiRouter::<()>::new()
        .routes(routes!(list_widgets))
        .routes(routes!(health))
        .split_for_parts();
    openapi
}

fn operation(openapi: &utoipa::openapi::OpenApi, path: &str) -> utoipa::openapi::path::Operation {
    openapi.paths.paths[path]
        .get
        .as_ref()
        .expect("get operation")
        .clone()
}

#[test]
fn guarded_handler_documents_rejection_statuses() {
    let op = operation(&spec(), "/widgets");
    let statuses: Vec<&str> = op.responses.responses.keys().map(String::as_str).collect();

    assert!(
        statuses.contains(&"401"),
        "missing credentials must be documented, got {statuses:?}",
    );
    assert!(
        statuses.contains(&"403"),
        "capability denial must be documented, got {statuses:?}",
    );
    assert!(
        statuses.contains(&"500"),
        "policy evaluation failure must be documented, got {statuses:?}",
    );
}

#[test]
fn denial_description_names_the_capability() {
    let op = operation(&spec(), "/widgets");
    let forbidden = match &op.responses.responses["403"] {
        utoipa::openapi::RefOr::T(r) => r.clone(),
        utoipa::openapi::RefOr::Ref(_) => panic!("403 should be inline"),
    };
    assert!(
        forbidden.description.contains("widgets.read"),
        "description should name the capability, got {:?}",
        forbidden.description,
    );
}

#[test]
fn unguarded_handler_gains_no_error_responses() {
    let op = operation(&spec(), "/health");
    let statuses: Vec<&str> = op.responses.responses.keys().map(String::as_str).collect();

    assert!(
        !statuses.contains(&"401") && !statuses.contains(&"403"),
        "a handler with no guard should not advertise auth failures, got {statuses:?}",
    );
}
