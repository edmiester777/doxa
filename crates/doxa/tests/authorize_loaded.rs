//! `AuthorizeLoaded`: deciding about a row the handler already holds, recorded as the guard
//! records. The asset panics in `load`, so nothing here may reload it.

#![cfg(feature = "full")]

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde::Serialize;
use serde_json::json;

use doxa::audit::{AuditEvent, AuditEventBuilder, AuditLogger, Outcome};
use doxa::auth::{
    Action, ActionTable, AuthorizeLoaded, CapabilityContext, DeclaredAction, Denial, FromState,
    Granting,
};
use doxa::policy::{
    AuthError, Capability, CapabilityCheck, CapabilityChecker, ResourceEntity, ResourceId,
};
use doxa::{PolicyResource, ToSchema};

// ---- domain -----------------------------------------------------------------

const SOURCES_READ: Capability = Capability {
    name: "sources.read",
    description: "Read data sources",
    checks: &[CapabilityCheck {
        action: "read_source",
        entity_type: "SourceCollection",
        entity_id: ResourceId::Literal("collection"),
    }],
};

/// `tenant_parent`: the tenant comes from the request, not a column.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema, PolicyResource)]
#[resource(entity_type = "Source", tenant_parent = "Tenant")]
struct Source {
    #[resource(id)]
    name: String,
    #[resource(attr)]
    region: String,
}

doxa::auth::route_key!(pub SourceKey { name: String });

/// What `#[derive(Actions)]` would emit, written out.
const READ_SOURCE: Action = Action::new("read_source")
    .capability(&SOURCES_READ)
    .event("data_access");

pub enum SourceActions {}

impl ActionTable for SourceActions {
    const ACTIONS: &'static [Action] = &[READ_SOURCE];
}

impl Granting for Source {
    type Row = Self;
    type Key = SourceKey;
    type Ctx = CapabilityContext;
    type State = ();
    type Source = FromState<()>;
    type Error = StatusCode;
    type Actions = SourceActions;

    async fn load(
        SourceKey { name: _ }: SourceKey,
        _state: &(),
        _ctx: &CapabilityContext,
    ) -> Result<Option<Self>, StatusCode> {
        panic!("`AuthorizeLoaded` must not load: the object is already in hand");
    }
}

/// The marker `#[derive(Actions)]` would generate; `Table` ties it to this asset.
struct ReadSource;

impl DeclaredAction for ReadSource {
    type Table = SourceActions;
    const ROW: &'static Action = &READ_SOURCE;
}

fn source(region: &str) -> Source {
    Source {
        name: "primary".to_owned(),
        region: region.to_owned(),
    }
}

// ---- policy stub ------------------------------------------------------------

/// Coarse by role, instance by region — two independent answers, which is
/// what lets a test hold one and not the other.
struct Regional;

#[async_trait]
impl CapabilityChecker for Regional {
    async fn check(&self, _: &str, roles: &[String], cap: &Capability) -> Result<bool, AuthError> {
        Ok(roles.iter().any(|role| role == cap.name))
    }

    async fn check_instance(
        &self,
        tenant: &str,
        _: &[String],
        _: &str,
        resource: &ResourceEntity,
    ) -> Result<bool, AuthError> {
        // Asserted directly: a missing parent would still let every test below pass.
        assert_eq!(
            resource.parents,
            [("Tenant".to_owned(), tenant.to_owned())],
            "`tenant_parent` should reach the policy",
        );

        Ok(resource.attrs.get("region") == Some(&json!("us")))
    }
}

// ---- harness ----------------------------------------------------------------

/// Request parts as `AuthLayer` leaves them, with an audit builder only this path writes to.
fn parts(
    roles: &[&str],
) -> (
    axum::http::request::Parts,
    tokio::sync::mpsc::Receiver<AuditEvent>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let mut request = Request::builder().uri("/").body(Body::empty()).unwrap();

    request.extensions_mut().insert(CapabilityContext {
        tenant_id: Some("acme".into()),
        roles: roles.iter().map(|role| (*role).to_owned()).collect(),
    });
    let checker: Arc<dyn CapabilityChecker> = Arc::new(Regional);
    request.extensions_mut().insert(checker);
    request
        .extensions_mut()
        .insert(AuditEventBuilder::new(AuditLogger::from_sender(tx)));

    let (parts, _) = request.into_parts();
    (parts, rx)
}

/// The event the audit layer would emit after the response.
fn emitted(
    parts: &axum::http::request::Parts,
    rx: &mut tokio::sync::mpsc::Receiver<AuditEvent>,
) -> AuditEvent {
    parts
        .extensions
        .get::<AuditEventBuilder>()
        .expect("the harness installed one")
        .auto_emit();
    rx.try_recv().expect("the decision was recorded")
}

// ---- the whole check --------------------------------------------------------

/// The object comes back, so an unauthorized binding never exists: the
/// value the handler goes on to use is the one the policy passed.
#[tokio::test]
async fn the_authorized_object_comes_back() {
    let (parts, _rx) = parts(&["sources.read"]);

    let authorized = source("us")
        .authorize::<Source, _>(ReadSource, &parts.extensions)
        .await
        .expect("holds the capability, and the region is granted");

    assert_eq!(authorized, source("us"));
}

/// `authorize` runs the coarse half too, as `Granted<One<R>>` does.
#[tokio::test]
async fn the_coarse_gate_still_runs() {
    let (parts, _rx) = parts(&[]);

    let refusal = source("us")
        .authorize::<Source, _>(ReadSource, &parts.extensions)
        .await
        .expect_err("does not hold sources.read");

    let Denial::Denied {
        action,
        resource_type,
        resource_id,
        reason,
    } = refusal
    else {
        panic!("the capability was refused, so this is a denial");
    };

    // The trail names the capability the caller failed, not the object.
    assert_eq!(action, "sources.read");
    assert_eq!(resource_type, "SourceCollection");
    assert_eq!(resource_id, "collection");
    assert_eq!(reason, "capability denied");
}

// ---- the dependency half ----------------------------------------------------

/// `authorize_dependency` skips the coarse question this caller would fail.
#[tokio::test]
async fn a_dependency_skips_the_coarse_gate() {
    let (parts, _rx) = parts(&[]);

    let authorized = source("us")
        .authorize_dependency::<Source, _>(ReadSource, &parts.extensions)
        .await
        .expect("the instance check is the only one that applies");

    assert_eq!(authorized, source("us"));
}

/// Skipping the coarse gate is the *only* thing it skips. The policy
/// still decides about the object, and a refusal names the object.
#[tokio::test]
async fn a_dependency_is_still_held_to_the_instance_check() {
    let (parts, _rx) = parts(&["sources.read"]);

    let refusal = source("eu")
        .authorize_dependency::<Source, _>(ReadSource, &parts.extensions)
        .await
        .expect_err("the region is not granted");

    let Denial::Denied {
        resource_type,
        resource_id,
        reason,
        ..
    } = refusal
    else {
        panic!("the instance was refused, so this is a denial");
    };

    assert_eq!(resource_type, "Source");
    assert_eq!(resource_id, "primary");
    assert_eq!(reason, "instance denied");
}

/// Another vocabulary's action doesn't compile on `Source`'s doors; the `compile_fail`
/// doctests on `AuthorizeLoaded::authorize` pin that.
///
/// ```ignore
/// source("us").authorize::<Source, _>(Purge, &parts.extensions).await
/// source("us").authorize_dependency::<Source, _>(Purge, &parts.extensions).await
/// ```
const PURGE: Action = Action::new("purge");

pub enum OtherActions {}

impl ActionTable for OtherActions {
    const ACTIONS: &'static [Action] = &[PURGE];
}

#[allow(dead_code)]
struct Purge;

impl DeclaredAction for Purge {
    type Table = OtherActions;
    const ROW: &'static Action = &PURGE;
}

/// No auth layer above, so there is no caller to decide about. A missing
/// checker must not read as a permissive one.
#[tokio::test]
async fn an_unauthenticated_request_reaches_no_verdict() {
    let extensions = axum::http::Extensions::new();

    let refusal = source("us")
        .authorize_dependency::<Source, _>(ReadSource, &extensions)
        .await
        .expect_err("nothing installed a caller");

    assert!(matches!(
        refusal,
        Denial::Auth(AuthError::MissingCredentials),
    ));
}

// ---- what the trail says ----------------------------------------------------

/// Recorded exactly as the extractor records, category from the asset's `Action` row.
#[tokio::test]
async fn a_grant_is_recorded_like_the_guard_would() {
    let (parts, mut rx) = parts(&["sources.read"]);

    source("us")
        .authorize::<Source, _>(ReadSource, &parts.extensions)
        .await
        .expect("granted");

    let event = emitted(&parts, &mut rx);

    assert_eq!(event.outcome, Outcome::Allowed);
    assert_eq!(event.action, "read_source");
    assert_eq!(event.resource_type.as_deref(), Some("Source"));
    assert_eq!(event.resource_id.as_deref(), Some("primary"));
    assert_eq!(
        event.event_type, "data_access",
        "the category comes off `Granting::ACTIONS`, as it does for a guard",
    );
}

#[tokio::test]
async fn a_dependency_grant_is_recorded_too() {
    let (parts, mut rx) = parts(&[]);

    source("us")
        .authorize_dependency::<Source, _>(ReadSource, &parts.extensions)
        .await
        .expect("granted");

    let event = emitted(&parts, &mut rx);

    assert_eq!(event.outcome, Outcome::Allowed);
    assert_eq!(event.action, "read_source");
    assert_eq!(event.resource_id.as_deref(), Some("primary"));
}

/// The event keeps the route's own subject over a later dependency.
#[tokio::test]
async fn a_dependency_does_not_displace_the_route_s_own_subject() {
    let (parts, mut rx) = parts(&["sources.read"]);

    source("us")
        .authorize::<Source, _>(ReadSource, &parts.extensions)
        .await
        .expect("the route's subject");
    Source {
        name: "replica".to_owned(),
        region: "us".to_owned(),
    }
    .authorize_dependency::<Source, _>(ReadSource, &parts.extensions)
    .await
    .expect("something its body referred to");

    let event = emitted(&parts, &mut rx);

    assert_eq!(
        event.resource_id.as_deref(),
        Some("primary"),
        "the first decision stands",
    );
}

/// Unless the later one is a refusal.
#[tokio::test]
async fn a_refused_dependency_displaces_the_grant() {
    let (parts, mut rx) = parts(&["sources.read"]);

    source("us")
        .authorize::<Source, _>(ReadSource, &parts.extensions)
        .await
        .expect("the route's subject");
    Source {
        name: "replica".to_owned(),
        region: "eu".to_owned(),
    }
    .authorize_dependency::<Source, _>(ReadSource, &parts.extensions)
    .await
    .expect_err("the region is not granted");

    let event = emitted(&parts, &mut rx);

    assert_eq!(event.outcome, Outcome::Denied);
    assert_eq!(event.resource_id.as_deref(), Some("replica"));
    assert_eq!(event.error_message.as_deref(), Some("instance denied"));
}
