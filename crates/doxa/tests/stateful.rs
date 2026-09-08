//! A router that carries state, and rows keyed by UUID.
//!
//! Both are the ordinary case for a control plane and neither used to
//! work. A `Uuid` key needed a newtype, because `RouteKey` and
//! `uuid::Uuid` are both foreign to the consumer; and `Granted<Cap<M>>`
//! could only be mounted on a stateless router, because the capability
//! form named `()` as its state and nothing produces a `()` from an
//! `AppState`.
//!
//! Everything below is written the way a consumer writes it — no newtype
//! for the key, no `FromRef` impl for the capability route — so most of
//! what this file asserts, it asserts by compiling.

#![cfg(feature = "full")]

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::FromRef;
use axum::http::{Request, StatusCode};
use serde::Serialize;
use serde_json::json;
use tower::ServiceExt;

use doxa::auth::{Action, Cap, CapabilityContext, FromState, Granted, Granting, Many, Scoping};
use doxa::policy::{
    AuthError, Capability, CapabilityCheck, CapabilityChecker, Capable, ResourceEntity, ResourceId,
};
use doxa::{get, routes, OpenApiRouter, PolicyResource, ToSchema};

// ---- state ------------------------------------------------------------------

/// What the router carries. The loader wants only the handle, so the
/// asset names `Store` and reaches it through `FromRef` — the ordinary
/// axum arrangement, and the one the capability form has to coexist with.
#[derive(Clone)]
struct AppState {
    store: Store,
}

#[derive(Clone)]
struct Store {
    known: uuid::Uuid,
}

impl FromRef<AppState> for Store {
    fn from_ref(state: &AppState) -> Self {
        state.store.clone()
    }
}

// ---- domain -----------------------------------------------------------------

const DOCUMENTS_READ: Capability = Capability {
    name: "documents.read",
    description: "Read documents",
    checks: &[CapabilityCheck {
        action: "read",
        entity_type: "DocumentCollection",
        entity_id: ResourceId::Literal("collection"),
    }],
};

const DOCUMENTS_REINDEX: Capability = Capability {
    name: "documents.reindex",
    description: "Rebuild the document index",
    checks: &[CapabilityCheck {
        action: "reindex",
        entity_type: "DocumentIndex",
        entity_id: ResourceId::Literal("all"),
    }],
};

struct DocumentsReindex;
impl Capable for DocumentsReindex {
    const CAPABILITY: &'static Capability = &DOCUMENTS_REINDEX;
}

#[derive(Debug, Clone, Serialize, ToSchema, PolicyResource)]
#[resource(entity_type = "Document")]
struct Document {
    #[resource(id)]
    id: uuid::Uuid,
}

impl Granting for Document {
    type Row = Self;
    /// The whole point: `uuid::Uuid` directly, with no local newtype
    /// standing between the route segment and the loader.
    type Key = uuid::Uuid;
    type Ctx = CapabilityContext;
    type State = Store;
    type Source = FromState<Store>;
    type Error = StatusCode;

    const ACTIONS: &'static [Action] = &[Action::new("read").capability(&DOCUMENTS_READ)];

    async fn load(
        id: uuid::Uuid,
        store: &Store,
        _ctx: &CapabilityContext,
    ) -> Result<Option<Self>, StatusCode> {
        Ok((id == store.known).then_some(Document { id }))
    }
}

impl Scoping for Document {
    type Filter = &'static str;

    fn scope(_action: &str, _ctx: &CapabilityContext) -> Result<Option<&'static str>, AuthError> {
        Ok(Some("tenant = acme"))
    }
}

// ---- routes -----------------------------------------------------------------

#[get("/documents/{id}", tag = "Documents")]
async fn get_document(document: Granted<Document>) -> String {
    document.id.to_string()
}

#[get("/documents", tag = "Documents")]
async fn list_documents(documents: Granted<Many<Document>>) -> &'static str {
    documents.into_inner()
}

/// The route that could not be written before: a bare capability gate on
/// a router that carries state. `Cap` reaches nothing out of `AppState`,
/// and now it does not have to pretend otherwise.
#[get("/reindex", tag = "Documents")]
async fn reindex(_: Granted<Cap<DocumentsReindex>>) -> &'static str {
    "ok"
}

// ---- policy stub ------------------------------------------------------------

struct AllowAll;

#[async_trait]
impl CapabilityChecker for AllowAll {
    async fn check(&self, _: &str, _: &[String], _: &Capability) -> Result<bool, AuthError> {
        Ok(true)
    }

    async fn check_instance(
        &self,
        _: &str,
        _: &[String],
        _: &str,
        _: &ResourceEntity,
    ) -> Result<bool, AuthError> {
        Ok(true)
    }
}

// ---- harness ----------------------------------------------------------------

/// The known row, so a request can name something the loader resolves.
fn known() -> uuid::Uuid {
    uuid::Uuid::from_u128(0x0192_38ab_cdef_4567_89ab_cdef_0123_4567)
}

fn api() -> utoipa::openapi::OpenApi {
    let (_router, api) = OpenApiRouter::<AppState>::new()
        .routes(routes!(get_document))
        .routes(routes!(list_documents))
        .routes(routes!(reindex))
        .split_for_parts();
    api
}

async fn call(uri: &str) -> (StatusCode, String) {
    let app = OpenApiRouter::<AppState>::new()
        .routes(routes!(get_document))
        .routes(routes!(list_documents))
        .routes(routes!(reindex))
        .split_for_parts()
        .0
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
        .with_state(AppState {
            store: Store { known: known() },
        });

    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .expect("request");

    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

// ---- a uuid segment binds without a newtype ---------------------------------

#[tokio::test]
async fn a_uuid_key_reaches_the_loader_as_itself() {
    let (status, body) = call(&format!("/documents/{}", known())).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, known().to_string(), "the loader compared UUIDs");
}

/// Parsing is the key's own job, so a malformed segment is a 400 from the
/// guard rather than a lookup that cannot match.
#[tokio::test]
async fn a_malformed_uuid_is_rejected_before_the_loader() {
    let (status, _) = call("/documents/not-a-uuid").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// A well-formed id for a row that is not there is the ordinary miss.
#[tokio::test]
async fn an_unknown_uuid_is_a_miss() {
    let (status, _) = call(&format!("/documents/{}", uuid::Uuid::nil())).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// `format: uuid` survives into the document, which is what a generated
/// client needs to type the parameter — a bare `String` key would flatten
/// it to an unformatted string.
#[test]
fn the_uuid_segment_keeps_its_format() {
    let api = api();
    let op = api
        .paths
        .paths
        .get("/documents/{id}")
        .expect("routed")
        .get
        .clone()
        .expect("operation");

    let params = op.parameters.expect("the key is declared");
    assert_eq!(params.len(), 1);
    assert_eq!(params[0].name, "id");

    let schema = serde_json::to_value(params[0].schema.as_ref().expect("typed")).unwrap();
    assert_eq!(schema["type"], json!("string"));
    assert_eq!(schema["format"], json!("uuid"));
}

// ---- and a capability gate mounts on a stateful router -----------------------

/// Compiling is most of the assertion: before `NoState`, mounting this
/// route on an `OpenApiRouter<AppState>` required the consumer to write
/// `impl FromRef<AppState> for ()`.
#[tokio::test]
async fn a_capability_gate_mounts_on_a_stateful_router() {
    let (status, body) = call("/reindex").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");
}

/// The other two forms share the router with it, so the state the
/// capability form ignores is still the state the loader receives.
#[tokio::test]
async fn the_asset_forms_still_reach_the_real_state() {
    let (status, body) = call("/documents").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "tenant = acme");
}
