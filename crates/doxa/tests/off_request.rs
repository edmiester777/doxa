//! Authorizing where there is no request: a job, a queue consumer, a task.
//!
//! Nothing about the chain needed a request — it reads a caller, a checker
//! and a state, and a worker has all three. What it did not have was
//! anywhere to put them, so every consumer assembled `http::Extensions` by
//! hand and the one that left the audit builder out authorized successfully
//! and recorded nothing.
//!
//! These tests are mostly about that last part. The verdicts are the easy
//! half; what is worth pinning is that a grant reaches the trail with
//! nothing called to make it, that a refusal does the same, and that the
//! event says who did the work rather than trailing off at the tenant.

#![cfg(all(feature = "full", feature = "policy-sea-orm"))]

use std::sync::Arc;

use async_trait::async_trait;
use doxa::audit::{AuditEvent, AuditLogger, Outcome};
use doxa::auth::{
    AuthorizeLoaded, CapabilityContext, DeclaredAction, FromState, GrantProfile, OffRequest, One,
    Refusal,
};
use doxa::policy::{AuthError, Capability, CapabilityChecker, Fetch, FetchByKey, ResourceEntity};
use doxa::{asset, Actions, PolicyResource};
use tokio::sync::mpsc::Receiver;

// ---- the row ----------------------------------------------------------------

/// Not a SeaORM model: a job's state is whatever the job holds, and this
/// file has no database. The neutral fetch traits are the whole contract.
#[derive(Debug, Clone, PartialEq, Eq, PolicyResource)]
#[resource(entity_type = "Dataset")]
pub struct Dataset {
    #[resource(id)]
    pub name: String,
    pub tenant: String,
}

/// The job's own store, standing in for a connection.
pub struct Catalog(Vec<Dataset>);

impl Fetch<Catalog> for Dataset {
    type Error = std::convert::Infallible;
}

impl FetchByKey<Catalog> for Dataset {
    type Key = String;

    async fn fetch(key: String, src: &Catalog, scope: &str) -> Result<Option<Self>, Self::Error> {
        Ok(src
            .0
            .iter()
            .find(|row| row.name == key && row.tenant == scope)
            .cloned())
    }
}

fn catalog() -> Catalog {
    Catalog(vec![
        Dataset {
            name: "sales".to_owned(),
            tenant: "acme".to_owned(),
        },
        // The same name under another tenant, so a lookup that ignored the
        // scope would still find *a* row and pass.
        Dataset {
            name: "sales".to_owned(),
            tenant: "globex".to_owned(),
        },
    ])
}

/// The derive declares the `datasets.read` capability alongside the `read`
/// action and gates one on the other, so the coarse half of the chain is
/// exercised without a capability written out here.
#[derive(Debug, Clone, Copy, Actions)]
#[actions(resource = "Dataset", prefix = "datasets")]
pub enum DatasetAction {
    /// Read one dataset.
    Read,
}

struct Read;
impl DeclaredAction for Read {
    const ACTION: &'static str = "read";
}

pub struct JobGrants;

impl GrantProfile for JobGrants {
    type Ctx = CapabilityContext;
    type State = Catalog;
    type Source = FromState<Catalog>;
    type Error = std::convert::Infallible;
}

#[asset(row = Dataset, profile = JobGrants, actions = DatasetAction)]
pub struct DatasetByName;

// ---- the checker ------------------------------------------------------------

/// Grants on a role, and refuses the coarse capability to anyone without
/// it — so the two halves of the chain can be exercised separately.
struct Roles;

#[async_trait]
impl CapabilityChecker for Roles {
    async fn check(
        &self,
        _tenant: &str,
        roles: &[String],
        capability: &Capability,
    ) -> Result<bool, AuthError> {
        Ok(roles.iter().any(|role| role == capability.name))
    }

    async fn check_instance(
        &self,
        _tenant: &str,
        roles: &[String],
        _action: &str,
        _resource: &ResourceEntity,
    ) -> Result<bool, AuthError> {
        Ok(roles.iter().any(|role| role == "datasets.read"))
    }
}

// ---- harness ----------------------------------------------------------------

fn caller(tenant: &str, roles: &[&str]) -> CapabilityContext {
    CapabilityContext {
        tenant_id: Some(tenant.to_owned()),
        roles: roles.iter().map(|role| (*role).to_owned()).collect(),
    }
}

/// A handle and the channel its events arrive on.
fn work(tenant: &str, roles: &[&str]) -> (OffRequest<CapabilityContext>, Receiver<AuditEvent>) {
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let checker: Arc<dyn CapabilityChecker> = Arc::new(Roles);
    (
        OffRequest::new(caller(tenant, roles), checker, AuditLogger::from_sender(tx)),
        rx,
    )
}

// ---- the verdicts -----------------------------------------------------------

/// The whole point: the same chain, no request, and the state handed over
/// rather than extracted.
///
/// `LoaderSource` and the `FromRequestParts` half of the guard are the
/// request's business — a worker already holds its connection, and this
/// call proves it never has to wrap it in anything to be allowed to use it.
#[tokio::test]
async fn a_job_authorizes_against_the_state_it_already_holds() {
    let (work, _rx) = work("acme", &["datasets.read"]);

    let dataset = work
        .authorize::<One<DatasetByName>>("sales".to_owned(), "read", &catalog())
        .await
        .expect("granted");

    assert_eq!(dataset.tenant, "acme");
}

/// The scope reaches the lookup, so a job running as one tenant does not
/// reach another's row even where the name exists under both.
#[tokio::test]
async fn a_job_is_confined_to_its_callers_tenant() {
    let (work, _rx) = work("globex", &["datasets.read"]);

    let dataset = work
        .authorize::<One<DatasetByName>>("sales".to_owned(), "read", &catalog())
        .await
        .expect("granted");

    assert_eq!(dataset.tenant, "globex", "the other tenant's row came back");
}

// ---- and they are recorded --------------------------------------------------

/// A grant reaches the trail with nothing called to make it happen.
///
/// This is the hole the type exists to close. Hand-assembled extensions
/// that omit the audit builder authorize exactly as well as these do, and
/// deposit the decision into nothing — so the failure is invisible at the
/// call site and the trail is simply missing rows nobody knows to look for.
#[tokio::test]
async fn a_grant_reaches_the_trail_with_no_request_anywhere() {
    let (work, mut rx) = work("acme", &["datasets.read"]);

    work.authorize::<One<DatasetByName>>("sales".to_owned(), "read", &catalog())
        .await
        .expect("granted");

    // Dropping is the terminal, exactly as a response is under an
    // `AuditLayer`. Nothing was called to arrange it.
    drop(work);

    let event = rx.recv().await.expect("an event was emitted");
    assert_eq!(event.outcome, Outcome::Allowed);
    assert_eq!(event.action, "read");
    assert_eq!(event.resource_type.as_deref(), Some("Dataset"));
    assert_eq!(event.resource_id.as_deref(), Some("sales"));
    assert_eq!(event.tenant_id.as_deref(), Some("acme"));
}

/// A refusal settles itself, so the trail has the denial even if the job
/// never reaches its own terminal.
#[tokio::test]
async fn a_refused_job_is_recorded_before_anything_else_runs() {
    let (work, mut rx) = work("acme", &[]);

    let refusal = work
        .authorize::<One<DatasetByName>>("sales".to_owned(), "read", &catalog())
        .await
        .expect_err("the capability is not held");

    assert!(matches!(refusal, Refusal::Denied { .. }), "{refusal:?}");

    let event = rx.recv().await.expect("an event was emitted");
    assert_eq!(event.outcome, Outcome::Denied);
    assert_eq!(
        event.action, "datasets.read",
        "the capability, not the verb"
    );
    assert_eq!(event.error_message.as_deref(), Some("capability denied"));
}

/// The event names the principal the work ran as.
///
/// There is no token here for a subject to have come from, so the actor is
/// whatever the application calls its job. Left unset it would be roles and
/// no subject — honest, and not much use when the trail is queried later.
#[tokio::test]
async fn the_actor_names_the_job_that_did_the_work() {
    let (work, mut rx) = work("acme", &["datasets.read"]);
    let work = work.actor("job:reindex");

    work.authorize::<One<DatasetByName>>("sales".to_owned(), "read", &catalog())
        .await
        .expect("granted");
    drop(work);

    let event = rx.recv().await.expect("an event was emitted");
    assert_eq!(event.actor_sub.as_deref(), Some("job:reindex"));
    // Naming the actor does not cost the roles, which `set_actor` replaces
    // wholesale — the reason `actor` restates them.
    assert_eq!(
        event.actor_roles.as_deref(),
        Some(&["datasets.read".to_owned()][..]),
    );
}

/// A job that fails after being authorized says so, and the drop terminal
/// does not overwrite it with `Allowed`.
#[tokio::test]
async fn a_job_that_fails_after_authorizing_records_the_failure() {
    let (work, mut rx) = work("acme", &["datasets.read"]);

    work.authorize::<One<DatasetByName>>("sales".to_owned(), "read", &catalog())
        .await
        .expect("granted");

    work.event().emit_error("reindex failed: disk full");
    drop(work);

    let event = rx.recv().await.expect("an event was emitted");
    assert_eq!(event.outcome, Outcome::Error);
    assert_eq!(
        event.error_message.as_deref(),
        Some("reindex failed: disk full"),
    );
    assert!(
        rx.try_recv().is_err(),
        "the drop terminal must not send a second event",
    );
}

// ---- the other door ---------------------------------------------------------

/// `AuthorizeLoaded` through the same handle, which is the door a worker
/// usually wants: a job loads its own rows, and this decides about one
/// already in hand without a `Response` anywhere in the error type.
#[tokio::test]
async fn a_row_already_in_hand_is_decided_through_the_extensions() {
    let (work, mut rx) = work("acme", &["datasets.read"]);

    let dataset = Dataset {
        name: "sales".to_owned(),
        tenant: "acme".to_owned(),
    };

    let dataset = dataset
        .authorize::<DatasetByName, _>(Read, work.extensions())
        .await
        .expect("granted");

    assert_eq!(dataset.name, "sales");
    drop(work);

    let event = rx.recv().await.expect("an event was emitted");
    assert_eq!(event.outcome, Outcome::Allowed);
    assert_eq!(event.resource_id.as_deref(), Some("sales"));
}

/// The caller shape is a type parameter, so a handle only authorizes
/// subjects whose `Ctx` it actually carries.
///
/// Through the request path the same mismatch is a `401` at run time,
/// because extensions cannot be typed that way. Here the bound is what this
/// function's existence proves: it will not instantiate for a subject whose
/// caller shape differs from the handle's.
#[test]
fn the_handle_only_serves_subjects_that_want_its_caller() {
    fn accepts<C, T>()
    where
        C: doxa::auth::FromAuthExtensions,
        T: doxa::auth::Subject<Ctx = C>,
    {
    }

    accepts::<CapabilityContext, One<DatasetByName>>();
}
