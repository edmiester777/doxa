//! `#[derive(Actions)]`: one enum, and the asset's whole vocabulary.
//!
//! What this file is really testing is how little is written above the
//! line — the enum below replaces three `#[capability]` blocks, a
//! `capability(action)` match, an `event_type(action)` match and a
//! catalog entry per action, and none of those can now disagree with
//! each other because there is only one of them.

#![cfg(feature = "full")]

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use doxa::audit::EventType;
use doxa::auth::{
    Action, Cap, CapabilityContext, GrantSite, Granted, Granting, Many, One, Scoping,
};
use doxa::policy::{AuthError, Capability, CapabilityChecker, Capable, ResourceEntity};
use doxa::{capability, Actions, PolicyResource, ToSchema};
use serde::Serialize;

/// A capability the application already declared — the shape of an app
/// with a catalog of its own, written before any action table existed.
#[capability(
    name = "sources.archive",
    description = "Archive data source definitions",
    checks(
        action = "archive",
        entity_type = "SourceCollection",
        entity_id = "collection"
    )
)]
pub struct SourcesArchive;

/// The whole declaration. `Source` comes off the enum name, the Cedar
/// action off each variant, the capability off the two together, and the
/// description off the doc comment.
#[derive(Debug, Clone, Copy, Actions)]
#[actions(prefix = "sources")]
pub enum SourceAction {
    /// List and view data source definitions.
    // The category is a const expression rather than a string, so a
    // misspelling is a resolution error instead of an audit row filed
    // under a category nothing reads. Not a doc comment: that is the
    // capability's description, which `the_description_comes_off_the_doc_comment`
    // pins.
    #[action(event = EventType::DataAccess.as_static())]
    Read,

    /// Remove data source definitions.
    #[action(event = EventType::AdminDelete.as_static())]
    Delete,

    /// A name that is not the variant's, because Cedar already had one.
    #[action(name = "run_query", event = EventType::DataAccess.as_static())]
    Query,

    /// Gated on the capability declared above rather than a fresh one,
    /// so the catalog keeps one entry for `sources.archive`.
    #[action(capable = SourcesArchive, event = EventType::AdminUpdate.as_static())]
    Archive,

    /// No coarse gate: the instance check alone decides it.
    #[action(instance_only)]
    Ping,
}

#[derive(Debug, Clone, Serialize, ToSchema, PolicyResource)]
#[resource(entity_type = "Source")]
struct Source {
    #[resource(id)]
    id: u32,
}

impl Granting for Source {
    type Key = u32;
    type Ctx = CapabilityContext;
    type State = ();
    type Error = StatusCode;

    /// The one line that wires the vocabulary to the asset.
    const ACTIONS: &'static [Action] = SourceAction::ACTIONS;

    async fn load(
        id: u32,
        _state: &(),
        _ctx: &CapabilityContext,
    ) -> Result<Option<Self>, StatusCode> {
        Ok(Some(Source { id }))
    }
}

impl Scoping for Source {
    type Filter = &'static str;

    fn scope(action: &str, _ctx: &CapabilityContext) -> Result<Option<&'static str>, AuthError> {
        Ok(match action {
            "read" => Some("tenant = acme"),
            _ => None,
        })
    }
}

// ---- what the derive worked out ---------------------------------------------

#[test]
fn the_action_names_come_off_the_variants() {
    assert_eq!(SourceAction::Read.as_static(), "read");
    assert_eq!(SourceAction::Delete.as_static(), "delete");
    assert_eq!(SourceAction::Ping.as_static(), "ping");
    // Overridden, because Cedar already had a name for it.
    assert_eq!(SourceAction::Query.as_static(), "run_query");

    assert_eq!(SourceAction::ALL.len(), 5);
}

/// `capable` gates on a marker that already exists. The row points at
/// that very constant — not a copy, and not a second declaration that
/// would sit in the catalog looking enforced while no route named it.
#[test]
fn an_existing_capability_is_referenced_rather_than_redeclared() {
    let archive = SourceAction::ACTIONS
        .iter()
        .find(|a| a.name == "archive")
        .expect("declared");

    assert!(std::ptr::eq(
        archive.capability.expect("gated"),
        SourcesArchive::CAPABILITY,
    ));
    assert_eq!(archive.event_type, Some(EventType::AdminUpdate.as_static()));
}

#[test]
fn the_capability_names_come_off_the_prefix_and_the_action() {
    assert_eq!(source_action::Read::CAPABILITY.name, "sources.read");
    assert_eq!(source_action::Delete::CAPABILITY.name, "sources.delete");
    // The overridden action name carries through to the capability.
    assert_eq!(source_action::Query::CAPABILITY.name, "sources.run_query");
}

#[test]
fn the_description_comes_off_the_doc_comment() {
    assert_eq!(
        source_action::Read::CAPABILITY.description,
        "List and view data source definitions",
    );
}

/// The check's entity is the collection, defaulted from the resource
/// noun — which is what a coarse gate asks about, there being no instance
/// yet. The tenant is not in here: it reaches `build_resource_uid` as its
/// own argument.
#[test]
fn the_check_defaults_to_the_collection() {
    let check = source_action::Delete::CAPABILITY.checks[0];
    assert_eq!(check.action, "delete");
    assert_eq!(check.entity_type, "SourceCollection");
    assert_eq!(check.entity_id, "collection");
}

#[test]
fn an_instance_only_action_declares_no_capability() {
    let ping = SourceAction::ACTIONS
        .iter()
        .find(|a| a.name == "ping")
        .expect("declared");
    assert!(ping.capability.is_none());
    assert!(ping.event_type.is_none());
}

#[test]
fn the_table_carries_the_capability_and_the_category() {
    let read = SourceAction::ACTIONS
        .iter()
        .find(|a| a.name == "read")
        .expect("declared");

    assert!(std::ptr::eq(
        read.capability.expect("gated"),
        source_action::Read::CAPABILITY,
    ));
    assert_eq!(read.event_type, Some(EventType::DataAccess.as_static()));
}

/// The table the derive produced names each action once, which is what
/// makes the gate's "first row wins" lookup unambiguous. Routes are held
/// to it — `Subject::SITE_DECLARED` asserts the same thing at build time
/// for every asset a route guards.
#[test]
fn the_generated_table_declares_each_action_once() {
    assert!(doxa::auth::distinct(SourceAction::ACTIONS));
}

/// The same check on a hand-written table, which no derive vets. Two
/// rows over one Cedar action leave the second's capability declared and
/// never checked — enforcement that reads as real and is not.
#[test]
fn a_table_that_repeats_an_action_is_not_distinct() {
    const REPEATED: &[Action] = &[
        Action::new("admin_write").event("admin_update"),
        Action::new("read"),
        Action::new("admin_write").event("admin_delete"),
    ];

    assert!(!doxa::auth::distinct(REPEATED));
    assert!(doxa::auth::distinct(&REPEATED[..2]));
}

/// Every generated marker is a capability declaration like any other, so
/// it reaches the catalog without being listed anywhere.
///
/// `sources.archive` appears exactly once despite an action gating on it:
/// `capable` references the marker rather than minting a second one. A
/// duplicate here would be a catalog entry advertised to clients that no
/// route ever checks.
#[test]
fn the_generated_capabilities_reach_the_catalog() {
    let names: Vec<_> = doxa::policy::capabilities()
        .into_iter()
        .map(|cap| cap.name)
        .collect();

    assert_eq!(
        names,
        [
            "sources.archive",
            "sources.delete",
            "sources.read",
            "sources.run_query",
        ],
        "three declared by the derive, one referenced, and `Ping` declared none",
    );
}

// ---- and it authorizes ------------------------------------------------------

struct Allow;

#[async_trait]
impl CapabilityChecker for Allow {
    async fn check(&self, _: &str, roles: &[String], cap: &Capability) -> Result<bool, AuthError> {
        Ok(roles.iter().any(|role| role == cap.name))
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

fn parts(roles: &[&str]) -> axum::http::request::Parts {
    let mut request = Request::builder().uri("/").body(Body::empty()).unwrap();
    request.extensions_mut().insert(CapabilityContext {
        tenant_id: Some("acme".into()),
        roles: roles.iter().map(|r| (*r).to_owned()).collect(),
    });
    request
        .extensions_mut()
        .insert(std::sync::Arc::new(Allow) as std::sync::Arc<dyn CapabilityChecker>);
    request.into_parts().0
}

struct Listing;
impl GrantSite for Listing {
    const PARAMS: &'static [&'static str] = &[];
    const ACTION: &'static str = "read";
}

struct Purging;
impl GrantSite for Purging {
    const PARAMS: &'static [&'static str] = &[];
    const ACTION: &'static str = "delete";
}

/// The generated capability is the one the coarse gate actually asks
/// about — a caller holding `sources.read` may list, and the same caller
/// is refused a delete because that action's row names a different one.
#[tokio::test]
async fn the_generated_capability_is_what_the_gate_checks() {
    let mut listing = parts(&["sources.read"]);
    let granted = Granted::<Many<Source, Listing>>::from_request_parts(&mut listing, &())
        .await
        .expect("holds sources.read");
    assert_eq!(granted.1, "tenant = acme");

    let mut purging = parts(&["sources.read"]);
    let refused = Granted::<Many<Source, Purging>>::from_request_parts(&mut purging, &())
        .await
        .err()
        .expect("does not hold sources.delete");
    assert_eq!(refused.into_response().status(), StatusCode::FORBIDDEN);
}

/// A marker the derive generated is a `Capable` like any other, so it
/// works as a bare gate.
#[tokio::test]
async fn a_generated_marker_is_a_bare_gate() {
    let mut parts = parts(&["sources.delete"]);
    Granted::<Cap<source_action::Delete>>::from_request_parts(&mut parts, &())
        .await
        .expect("holds sources.delete");
}

/// `Ping` declares no capability, so nothing coarse stands between the
/// caller and the instance check.
#[tokio::test]
async fn an_instance_only_action_skips_the_coarse_gate() {
    let parts = parts(&[]);
    doxa::auth::authorize::<One<Source>>(1, "ping", &(), &parts.extensions)
        .await
        .expect("no capability to hold");
}
