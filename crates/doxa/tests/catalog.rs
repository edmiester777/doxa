//! The capability catalog assembles itself.
//!
//! Nothing here maintains a list. Each `#[capability]` registers as it
//! declares, and [`doxa::policy::capabilities`] answers — which is what a
//! `/me`-style endpoint and an OAuth2 scope vocabulary both need and
//! neither can name.
//!
//! The test that matters is the one asserting a count: a hand-written
//! catalog fails *silently* when someone forgets a line, and the
//! capability goes on working everywhere it is named in code while
//! quietly vanishing from what the client is told it has.

#![cfg(feature = "full")]

use doxa::capability;
use doxa::policy::Capable;

#[capability(
    name = "widgets.read",
    description = "List and view widgets",
    checks(action = "read", entity_type = "Widget", entity_id = "collection")
)]
pub struct WidgetsRead;

#[capability(
    name = "widgets.delete",
    description = "Remove widgets",
    checks(action = "delete", entity_type = "Widget", entity_id = "collection")
)]
pub struct WidgetsDelete;

/// Two checks, and no resource of its own — the shape a hand-written
/// catalog is most likely to drop, because nothing else in the codebase
/// refers to it.
#[capability(
    name = "widgets.admin",
    description = "Administer the widget subsystem",
    checks(action = "read", entity_type = "Widget", entity_id = "collection"),
    checks(action = "admin", entity_type = "AdminConfig", entity_id = "singleton")
)]
pub struct WidgetsAdmin;

#[test]
fn every_declaration_reaches_the_catalog() {
    let all = doxa::policy::capabilities();

    let names: Vec<_> = all.iter().map(|cap| cap.name).collect();
    assert_eq!(
        names,
        ["widgets.admin", "widgets.delete", "widgets.read"],
        "sorted by name, and nothing had to enumerate them",
    );
}

/// Link order is unspecified, so the catalog sorts. A published OpenAPI
/// document whose scope list reshuffled between builds would be
/// unreadable in review.
#[test]
fn the_catalog_is_ordered_by_name() {
    let all = doxa::policy::capabilities();
    let mut sorted = all.clone();
    sorted.sort_by_key(|cap| cap.name);
    assert_eq!(
        all.iter().map(|c| c.name).collect::<Vec<_>>(),
        sorted.iter().map(|c| c.name).collect::<Vec<_>>(),
    );
}

/// Registration is additional to what `#[capability]` already did, not
/// instead of it.
#[test]
fn a_marker_still_resolves_to_its_capability() {
    assert_eq!(WidgetsRead::CAPABILITY.name, "widgets.read");
    assert_eq!(WidgetsAdmin::CAPABILITY.checks.len(), 2);

    let from_catalog = doxa::policy::capabilities()
        .into_iter()
        .find(|cap| cap.name == "widgets.read")
        .expect("declared");

    assert!(
        std::ptr::eq(from_catalog, WidgetsRead::CAPABILITY),
        "the catalog holds the same const the marker does, not a copy",
    );
}
