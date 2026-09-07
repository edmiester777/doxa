//! Authorizing an object the guard never saw.
//!
//! A guard runs in `FromRequestParts`, before a body exists, and it
//! *loads* through `Granting::State`. Neither fits a row the handler
//! already holds — one it resolved inside an open transaction that the
//! state's own connection cannot see. `AuthorizeLoaded` decides about
//! such a row without loading it, and records the verdict through the
//! same path the guard does.
//!
//! The asset below panics in `load`, so every test here is also an
//! assertion that nothing on this path goes back to the database.

#![cfg(feature = "full")]

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde::Serialize;
use serde_json::json;

use doxa::audit::{AuditEvent, AuditEventBuilder, AuditLogger, Outcome};
use doxa::auth::{Action, AuthorizeLoaded, CapabilityContext, Granting, Refusal};
use doxa::policy::{AuthError, Capability, CapabilityCheck, CapabilityChecker, ResourceEntity};
use doxa::{PolicyResource, ToSchema};

// ---- domain -----------------------------------------------------------------

const SOURCES_READ: Capability = Capability {
    name: "sources.read",
    description: "Read data sources",
    checks: &[CapabilityCheck {
        action: "read_source",
        entity_type: "SourceCollection",
        entity_id: "collection",
    }],
};

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema, PolicyResource)]
#[resource(entity_type = "Source")]
struct Source {
    #[resource(id)]
    name: String,
    #[resource(attr)]
    region: String,
}

impl Granting for Source {
    type Key = String;
    type Ctx = CapabilityContext;
    type State = ();
    type Error = StatusCode;

    const ACTIONS: &'static [Action] = &[Action::new("read_source")
        .capability(&SOURCES_READ)
        .event("data_access")];

    /// The panic is the point. `AuthorizeLoaded` decides about a row the
    /// caller already has, so reaching for `State` — which for a real
    /// consumer is a pool that cannot see the request's open transaction
    /// — would be the defect this whole path exists to avoid.
    async fn load(
        _key: String,
        _state: &(),
        _ctx: &CapabilityContext,
    ) -> Result<Option<Self>, StatusCode> {
        panic!("`AuthorizeLoaded` must not load: the object is already in hand");
    }
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
        _: &str,
        _: &[String],
        _: &str,
        resource: &ResourceEntity,
    ) -> Result<bool, AuthError> {
        Ok(resource.attrs.get("region") == Some(&json!("us")))
    }
}

// ---- harness ----------------------------------------------------------------

/// Request parts as `AuthLayer` would leave them, with an audit builder
/// nothing else writes to — so whatever the event ends up saying, this
/// path said it.
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
        .authorize("read_source", &parts.extensions)
        .await
        .expect("holds the capability, and the region is granted");

    assert_eq!(authorized, source("us"));
}

/// `authorize` is the same check `Granted<One<R>>` runs, coarse half
/// included — so a handler reaching for it on an unguarded route is not
/// quietly getting less than the extractor would have given it.
#[tokio::test]
async fn the_coarse_gate_still_runs() {
    let (parts, _rx) = parts(&[]);

    let refusal = source("us")
        .authorize("read_source", &parts.extensions)
        .await
        .expect_err("does not hold sources.read");

    let Refusal::Denied {
        action,
        resource_type,
        resource_id,
        reason,
    } = refusal
    else {
        panic!("the capability was refused, so this is a denial");
    };

    // The capability's own check, not the object: the caller was turned
    // away before the object was ever considered, and the trail should
    // say which question they failed.
    assert_eq!(action, "sources.read");
    assert_eq!(resource_type, "SourceCollection");
    assert_eq!(resource_id, "collection");
    assert_eq!(reason, "capability denied");
}

// ---- the dependency half ----------------------------------------------------

/// The reason `authorize_dependency` exists. This caller may not *list*
/// sources, and the route they are on never asked them to — its own guard
/// answered a different coarse question. Asking this one would refuse a
/// caller who is plainly permitted on the object itself.
#[tokio::test]
async fn a_dependency_skips_the_coarse_gate() {
    let (parts, _rx) = parts(&[]);

    let authorized = source("us")
        .authorize_dependency("read_source", &parts.extensions)
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
        .authorize_dependency("read_source", &parts.extensions)
        .await
        .expect_err("the region is not granted");

    let Refusal::Denied {
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

/// `Granting::ACTIONS` is the asset's vocabulary either way. A verb it
/// never declared cannot be smuggled past the gate by calling the
/// dependency form, which would otherwise be a way to authorize something
/// the asset does not admit doing at all.
#[tokio::test]
async fn an_undeclared_action_is_refused_through_either_door() {
    for door in ["authorize", "authorize_dependency"] {
        let (parts, _rx) = parts(&["sources.read"]);

        let refusal = match door {
            "authorize" => source("us").authorize("purge", &parts.extensions).await,
            _ => {
                source("us")
                    .authorize_dependency("purge", &parts.extensions)
                    .await
            }
        }
        .expect_err("`purge` is not in ACTIONS");

        let Refusal::Denied { action, reason, .. } = refusal else {
            panic!("{door}: an undeclared action is a denial");
        };

        assert_eq!(action, "purge", "{door}");
        assert_eq!(reason, "action not declared", "{door}");
    }
}

/// No auth layer above, so there is no caller to decide about. A missing
/// checker must not read as a permissive one.
#[tokio::test]
async fn an_unauthenticated_request_reaches_no_verdict() {
    let extensions = axum::http::Extensions::new();

    let refusal = source("us")
        .authorize_dependency("read_source", &extensions)
        .await
        .expect_err("nothing installed a caller");

    assert!(matches!(
        refusal,
        Refusal::Auth(AuthError::MissingCredentials),
    ));
}

// ---- what the trail says ----------------------------------------------------

/// A decision reached here is indistinguishable in the trail from one the
/// extractor reached — same action, same object, and the category off the
/// asset's own `Action` row rather than anything the handler said.
#[tokio::test]
async fn a_grant_is_recorded_like_the_guard_would() {
    let (parts, mut rx) = parts(&["sources.read"]);

    source("us")
        .authorize("read_source", &parts.extensions)
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

/// The dependency form records too. Skipping the coarse gate is not
/// permission to skip the trail — a check that left no row would be
/// exactly the hole the sealed chain was built to close.
#[tokio::test]
async fn a_dependency_grant_is_recorded_too() {
    let (parts, mut rx) = parts(&[]);

    source("us")
        .authorize_dependency("read_source", &parts.extensions)
        .await
        .expect("granted");

    let event = emitted(&parts, &mut rx);

    assert_eq!(event.outcome, Outcome::Allowed);
    assert_eq!(event.action, "read_source");
    assert_eq!(event.resource_id.as_deref(), Some("primary"));
}

/// One request may authorize several things, and an event names one
/// resource. The route's own subject is decided first, so it is the one
/// the event keeps — a dependency checked afterwards does not displace
/// it, and the handler coordinates nothing to get that.
#[tokio::test]
async fn a_dependency_does_not_displace_the_route_s_own_subject() {
    let (parts, mut rx) = parts(&["sources.read"]);

    source("us")
        .authorize("read_source", &parts.extensions)
        .await
        .expect("the route's subject");
    Source {
        name: "replica".to_owned(),
        region: "us".to_owned(),
    }
    .authorize_dependency("read_source", &parts.extensions)
    .await
    .expect("something its body referred to");

    let event = emitted(&parts, &mut rx);

    assert_eq!(
        event.resource_id.as_deref(),
        Some("primary"),
        "the first decision stands",
    );
}

/// Except when the later one is a refusal. A request that ends on a
/// denial is about that denial, whatever it was allowed to touch getting
/// there.
#[tokio::test]
async fn a_refused_dependency_displaces_the_grant() {
    let (parts, mut rx) = parts(&["sources.read"]);

    source("us")
        .authorize("read_source", &parts.extensions)
        .await
        .expect("the route's subject");
    Source {
        name: "replica".to_owned(),
        region: "eu".to_owned(),
    }
    .authorize_dependency("read_source", &parts.extensions)
    .await
    .expect_err("the region is not granted");

    let event = emitted(&parts, &mut rx);

    assert_eq!(event.outcome, Outcome::Denied);
    assert_eq!(event.resource_id.as_deref(), Some("replica"));
    assert_eq!(event.error_message.as_deref(), Some("instance denied"));
}
