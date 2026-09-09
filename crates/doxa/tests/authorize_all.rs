//! Authorizing several objects a request named at once.
//!
//! A body that names its references names more than one of them. Decided
//! a row at a time that is one policy call each, and each one rebuilds the
//! same entity hierarchy before evaluating anything. `AuthorizeLoadedAll`
//! asks once, through
//! [`CapabilityChecker::check_instance_many`](doxa::policy::CapabilityChecker::check_instance_many)
//! — and the checker below records what it was asked, so these tests are
//! also the assertion that it really is one call.
//!
//! What must *not* change is the verdict or the trail: a refusal still
//! names the row that caused it, and a grant is still filed per row. That
//! is the difference from `AuthorizeScope`, which answers about a
//! collection.

#![cfg(feature = "full")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde::Serialize;
use serde_json::json;

use doxa::audit::{AuditEvent, AuditEventBuilder, AuditLogger, Outcome};
use doxa::auth::{
    Action, ActionTable, AuthorizeLoadedAll, CapabilityContext, DeclaredAction, Denial, FromState,
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

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema, PolicyResource)]
#[resource(entity_type = "Source", tenant_parent = "Tenant")]
struct Source {
    #[resource(id)]
    name: String,
    #[resource(attr)]
    region: String,
}

/// A descriptor over the row rather than the row itself, which is the
/// shape an entity crate forces and the one the plural door has to work
/// with: the rows arrive already loaded, so nothing here is `Self`.
struct SourceByName;

doxa::auth::route_key!(pub SourceKey { name: String });

impl Granting for SourceByName {
    type Row = Source;
    type Key = SourceKey;
    type Ctx = CapabilityContext;
    type State = ();
    type Source = FromState<()>;
    type Error = StatusCode;

    type Actions = SourceActions;

    /// As in the singular case: reaching the state would mean going back
    /// to a pool that cannot see the caller's open transaction, which is
    /// the whole reason this door exists.
    async fn load(
        SourceKey { name: _ }: SourceKey,
        _state: &(),
        _ctx: &CapabilityContext,
    ) -> Result<Option<Source>, StatusCode> {
        panic!("`AuthorizeLoadedAll` must not load: the objects are already in hand");
    }
}

/// The vocabulary written out, as `#[derive(Actions)]` would emit it.
const READ_SOURCE: Action = Action::new("read_source")
    .capability(&SOURCES_READ)
    .event("data_access");

pub enum SourceActions {}

impl ActionTable for SourceActions {
    const ACTIONS: &'static [Action] = &[READ_SOURCE];
}

struct ReadSource;

impl DeclaredAction for ReadSource {
    type Table = SourceActions;
    const ROW: &'static Action = &READ_SOURCE;
}

fn source(name: &str, region: &str) -> Source {
    Source {
        name: name.to_owned(),
        region: region.to_owned(),
    }
}

// ---- policy stub ------------------------------------------------------------

/// Coarse by role, instance by region — and counting both, so a test can
/// assert that N rows cost one batch rather than N checks.
#[derive(Default)]
struct Regional {
    batches: AtomicUsize,
    singles: AtomicUsize,
}

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
        self.singles.fetch_add(1, Ordering::Relaxed);
        assert_eq!(
            resource.parents,
            [("Tenant".to_owned(), tenant.to_owned())],
            "`tenant_parent` should reach the policy",
        );
        Ok(resource.attrs.get("region") == Some(&json!("us")))
    }

    /// Overridden, as a real router's is, so the count distinguishes the
    /// batch from the default loop over `check_instance`.
    async fn check_instance_many(
        &self,
        tenant: &str,
        _: &[String],
        _: &str,
        resources: &[ResourceEntity],
    ) -> Result<Vec<bool>, AuthError> {
        self.batches.fetch_add(1, Ordering::Relaxed);
        Ok(resources
            .iter()
            .map(|resource| {
                assert_eq!(
                    resource.parents,
                    [("Tenant".to_owned(), tenant.to_owned())],
                    "`tenant_parent` should reach the policy",
                );
                resource.attrs.get("region") == Some(&json!("us"))
            })
            .collect())
    }
}

/// A checker whose batch answers a different number of verdicts than it
/// was asked about — the one failure that cannot be lined up with the
/// rows.
struct Miscounting;

#[async_trait]
impl CapabilityChecker for Miscounting {
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
    async fn check_instance_many(
        &self,
        _: &str,
        _: &[String],
        _: &str,
        _: &[ResourceEntity],
    ) -> Result<Vec<bool>, AuthError> {
        Ok(vec![true])
    }
}

// ---- harness ----------------------------------------------------------------

fn parts_with(
    roles: &[&str],
    checker: Arc<dyn CapabilityChecker>,
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
    request.extensions_mut().insert(checker);
    request
        .extensions_mut()
        .insert(AuditEventBuilder::new(AuditLogger::from_sender(tx)));

    let (parts, _) = request.into_parts();
    (parts, rx)
}

fn parts(
    roles: &[&str],
) -> (
    axum::http::request::Parts,
    tokio::sync::mpsc::Receiver<AuditEvent>,
    Arc<Regional>,
) {
    let regional = Arc::new(Regional::default());
    let (parts, rx) = parts_with(roles, Arc::clone(&regional) as Arc<dyn CapabilityChecker>);
    (parts, rx, regional)
}

/// Everything the audit builder collected, in order.
fn recorded(
    parts: &axum::http::request::Parts,
    rx: &mut tokio::sync::mpsc::Receiver<AuditEvent>,
) -> Vec<AuditEvent> {
    parts
        .extensions
        .get::<AuditEventBuilder>()
        .expect("the harness installed one")
        .auto_emit();

    let mut events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }
    events
}

// ---- the whole check --------------------------------------------------------

/// The rows come back, in the order they went in — a handler that zips
/// them against what it asked for would otherwise pair the wrong name
/// with the wrong row.
#[tokio::test]
async fn the_authorized_rows_come_back_in_order() {
    let (parts, _rx, _checker) = parts(&["sources.read"]);

    let authorized = vec![source("a", "us"), source("b", "us"), source("c", "us")]
        .authorize_all::<SourceByName, _>(ReadSource, &parts.extensions)
        .await
        .expect("holds the capability, and every region is granted");

    assert_eq!(
        authorized,
        vec![source("a", "us"), source("b", "us"), source("c", "us")],
    );
}

/// The reason the door exists: N rows are one question, not N.
#[tokio::test]
async fn several_rows_cost_one_pass_through_the_policy() {
    let (parts, _rx, checker) = parts(&["sources.read"]);

    vec![source("a", "us"), source("b", "us"), source("c", "us")]
        .authorize_all::<SourceByName, _>(ReadSource, &parts.extensions)
        .await
        .expect("granted");

    assert_eq!(checker.batches.load(Ordering::Relaxed), 1);
    assert_eq!(
        checker.singles.load(Ordering::Relaxed),
        0,
        "the plural door must not fall back to asking one at a time",
    );
}

/// A refusal still names the row that caused it. This is the whole reason
/// to reach for this rather than a scope filter, which can only say that
/// *something* was outside the caller's subset.
#[tokio::test]
async fn the_refusal_names_the_row_that_caused_it() {
    let (parts, _rx, _checker) = parts(&["sources.read"]);

    let refusal = vec![source("a", "us"), source("b", "eu"), source("c", "us")]
        .authorize_all::<SourceByName, _>(ReadSource, &parts.extensions)
        .await
        .expect_err("`b` is not in the granted region");

    let Denial::Denied {
        resource_type,
        resource_id,
        reason,
        ..
    } = refusal
    else {
        panic!("the instance check refused, so this is a denial");
    };

    assert_eq!(resource_type, "Source");
    assert_eq!(resource_id, "b");
    assert_eq!(reason, "instance denied");
}

/// One request carries one decision, and a refusal outranks any grant
/// deposited before it — so the event names the row that was refused,
/// which is the one worth naming.
#[tokio::test]
async fn the_refused_row_is_what_the_trail_carries() {
    let (parts, mut rx, _checker) = parts(&["sources.read"]);

    vec![source("a", "us"), source("b", "eu"), source("c", "us")]
        .authorize_all::<SourceByName, _>(ReadSource, &parts.extensions)
        .await
        .expect_err("`b` is refused");

    let events = recorded(&parts, &mut rx);
    assert_eq!(events.len(), 1, "one request, one event");
    assert_eq!(events[0].outcome, Outcome::Denied);
    assert_eq!(events[0].resource_type.as_deref(), Some("Source"));
    assert_eq!(
        events[0].resource_id.as_deref(),
        Some("b"),
        "the trail must name the row that caused the refusal, not the set",
    );
}

/// A permitted set is filed as a grant on this asset, under the action's
/// own category — the same entry a single authorized row would leave.
#[tokio::test]
async fn a_granted_set_is_recorded_as_a_grant_on_the_asset() {
    let (parts, mut rx, _checker) = parts(&["sources.read"]);

    vec![source("a", "us"), source("b", "us")]
        .authorize_all::<SourceByName, _>(ReadSource, &parts.extensions)
        .await
        .expect("granted");

    let events = recorded(&parts, &mut rx);
    assert_eq!(events.len(), 1);
    assert_ne!(events[0].outcome, Outcome::Denied);
    assert_eq!(events[0].action, "read_source");
    assert_eq!(events[0].resource_type.as_deref(), Some("Source"));
    assert_eq!(
        events[0].resource_id.as_deref(),
        Some("a"),
        "the builder keeps the first grant, as it does for a loop of the singular door",
    );
}

/// The coarse gate is a question about the asset, so it runs once for the
/// set rather than once per row — and refusing it refuses everything
/// before any row is considered.
#[tokio::test]
async fn the_coarse_gate_runs_once_for_the_set() {
    let (parts, _rx, checker) = parts(&[]);

    let refusal = vec![source("a", "us"), source("b", "us")]
        .authorize_all::<SourceByName, _>(ReadSource, &parts.extensions)
        .await
        .expect_err("does not hold sources.read");

    let Denial::Denied { action, reason, .. } = refusal else {
        panic!("the capability was refused, so this is a denial");
    };
    assert_eq!(action, "sources.read");
    assert_eq!(reason, "capability denied");
    assert_eq!(
        checker.batches.load(Ordering::Relaxed),
        0,
        "no row should be considered once the coarse question is refused",
    );
}

/// The dependency form skips the coarse gate and nothing else, for the
/// reason the singular one does: a caller who may write a pipeline naming
/// sources they may read should not be refused because they may not
/// *list* sources.
#[tokio::test]
async fn the_dependency_form_skips_only_the_coarse_gate() {
    let (granted, _rx, _checker) = parts(&[]);
    let authorized = vec![source("a", "us")]
        .authorize_all_dependency::<SourceByName, _>(ReadSource, &granted.extensions)
        .await
        .expect("the coarse question is not this route's");
    assert_eq!(authorized, vec![source("a", "us")]);

    let (refused, _rx, _checker) = parts(&[]);
    vec![source("a", "eu")]
        .authorize_all_dependency::<SourceByName, _>(ReadSource, &refused.extensions)
        .await
        .expect_err("the instance check still runs");
}

/// Nothing named is nothing decided. Depositing a grant here would file a
/// verdict about rows that do not exist — the request's event still gets
/// emitted, it just carries no decision about this asset.
#[tokio::test]
async fn an_empty_set_decides_and_records_nothing() {
    let (parts, mut rx, checker) = parts(&["sources.read"]);

    let authorized = Vec::<Source>::new()
        .authorize_all::<SourceByName, _>(ReadSource, &parts.extensions)
        .await
        .expect("nothing to refuse");

    assert!(authorized.is_empty());
    assert_eq!(checker.batches.load(Ordering::Relaxed), 0);
    assert!(
        recorded(&parts, &mut rx)
            .iter()
            .all(|event| event.resource_id.is_none()),
        "no row was decided, so none should be named",
    );
}

/// A checker that answers a different number of verdicts than it was asked
/// about cannot be lined up with the rows, and pairing them anyway is how
/// a grant lands on the wrong object. Refuse instead.
#[tokio::test]
async fn a_miscounted_batch_is_an_error_rather_than_a_guess() {
    let (parts, _rx) = parts_with(&["sources.read"], Arc::new(Miscounting));

    let refusal = vec![source("a", "us"), source("b", "us")]
        .authorize_all::<SourceByName, _>(ReadSource, &parts.extensions)
        .await
        .expect_err("one verdict for two rows cannot be matched up");

    assert!(
        matches!(refusal, Denial::Auth(_)),
        "a checker that answered wrong is this server's fault, not the caller's",
    );
}

/// The plural door and the singular one are the same decision. A shared
/// entity set that let one row's attributes bleed into another's verdict
/// would show up here.
#[tokio::test]
async fn the_plural_door_agrees_with_the_singular() {
    use doxa::auth::AuthorizeLoaded;

    for region in ["us", "eu"] {
        let (one, _rx, _checker) = parts(&["sources.read"]);
        let singular = source("a", region)
            .authorize::<SourceByName, _>(ReadSource, &one.extensions)
            .await
            .is_ok();

        let (many, _rx, _checker) = parts(&["sources.read"]);
        let plural = vec![source("a", region)]
            .authorize_all::<SourceByName, _>(ReadSource, &many.extensions)
            .await
            .is_ok();

        assert_eq!(singular, plural, "{region} disagreed");
    }
}
