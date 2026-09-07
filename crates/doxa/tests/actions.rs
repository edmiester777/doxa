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
use doxa::auth::{Action, Cap, CapabilityContext, GrantSite, Granted, Granting, Many, One};
use doxa::policy::{AuthError, Capability, CapabilityChecker, Capable, ResourceEntity};
use doxa::{Actions, PolicyResource, ToSchema};
use serde::Serialize;

/// The whole declaration. `Source` comes off the enum name, the Cedar
/// action off each variant, the capability off the two together, and the
/// description off the doc comment.
#[derive(Debug, Clone, Copy, Actions)]
#[actions(prefix = "sources")]
pub enum SourceAction {
    /// List and view data source definitions.
    #[action(event = "data_access")]
    Read,

    /// Remove data source definitions.
    #[action(event = "admin_delete")]
    Delete,

    /// A name that is not the variant's, because Cedar already had one.
    #[action(name = "run_query", event = "data_access")]
    Query,

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
    type Filter = &'static str;

    /// The one line that wires the vocabulary to the asset.
    const ACTIONS: &'static [Action] = SourceAction::ACTIONS;

    async fn load(
        id: u32,
        _state: &(),
        _ctx: &CapabilityContext,
    ) -> Result<Option<Self>, StatusCode> {
        Ok(Some(Source { id }))
    }

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

    assert_eq!(SourceAction::ALL.len(), 4);
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

/// Every generated marker is a capability declaration like any other, so
/// it reaches the catalog without being listed anywhere.
#[test]
fn the_generated_capabilities_reach_the_catalog() {
    let names: Vec<_> = doxa::policy::capabilities()
        .into_iter()
        .map(|cap| cap.name)
        .collect();

    assert_eq!(
        names,
        ["sources.delete", "sources.read", "sources.run_query"],
        "three declared, three registered, and `Ping` declared none",
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
