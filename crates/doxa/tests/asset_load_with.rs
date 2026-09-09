//! `load_with`: what the door keeps, and the one thing it drops.
//!
//! Every other loader `#[asset]` writes is a `FetchByKey`, which is handed
//! a `&str` scope and nothing else — it *cannot* ignore the caller's
//! tenant, because it cannot see anything about the caller except that.
//! `load_with` is the door for a lookup that needs more than the scope,
//! and it is handed the whole `Ctx`. Both halves of that sentence matter:
//! it is the only way to write such a lookup, and it is the only loader
//! that can get confinement wrong.
//!
//! So this file pins the boundary. Everything the chain does *around* the
//! loader is unchanged — the capability gate still runs first and still
//! costs no load, the instance check still runs after, the audit verdict
//! is still recorded with the row's Cedar identity — and confinement is
//! the single thing that becomes the consumer's to write.
//!
//! The last test asserts that an unconfined loader really does serve
//! another tenant's row. That is not an endorsement; it is the security
//! boundary written down. If something later starts catching this, that
//! test fails and says the documentation is stale.

#![cfg(feature = "full")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::FromRef;
use axum::http::StatusCode;
use axum::{body::Body, http::Request};
use serde::Serialize;
use tower::ServiceExt;

use doxa::audit::{AuditEvent, AuditLayer, AuditLogger, Outcome};
use doxa::auth::{CapabilityContext, FromAuthExtensions, FromState, GrantProfile, Granted, One};
use doxa::policy::{AuthError, Capability, CapabilityChecker, ResourceEntity};
use doxa::{asset, get, routes, Actions, OpenApiRouter, PolicyResource, ToSchema};

// ---- domain -----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema, PolicyResource)]
#[resource(entity_type = "Widget")]
pub struct Widget {
    #[resource(id)]
    pub name: String,
    pub tenant: String,
}

/// `prefix` gives every action a capability, which is what makes the gate
/// below something to observe rather than a pass-through.
#[derive(Debug, Clone, Copy, Actions)]
#[actions(resource = "Widget", prefix = "widgets")]
pub enum WidgetAction {
    /// View widgets.
    #[action(verb = get)]
    Read,
}

/// Rows, and a count of how many times a loader was entered. The counter
/// is per-request rather than a static so the tests below can run in
/// parallel and still each observe their own request.
#[derive(Clone)]
pub struct Catalog {
    rows: Arc<Vec<Widget>>,
    loads: Arc<AtomicUsize>,
}

impl Catalog {
    fn seeded() -> Self {
        Catalog {
            rows: Arc::new(vec![
                Widget {
                    name: "alpha".into(),
                    tenant: "acme".into(),
                },
                Widget {
                    name: "beta".into(),
                    tenant: "globex".into(),
                },
            ]),
            loads: Arc::new(AtomicUsize::new(0)),
        }
    }
}

// ---- the two loaders --------------------------------------------------------

doxa::auth::route_key!(
    /// What the route's `{name}` segment parses into. A `load_with` row
    /// has no `FetchByKey` impl to read a key off, so the key is declared
    /// here and named on the asset.
    pub WidgetKey { name: String }
);

/// Written the way the attribute's own loader is: read the tenant, refuse
/// to guess when there is none, confine the lookup to it.
///
/// This is what a `load_with` owes, and there is nothing in the signature
/// that says so — which is the whole reason the generated path exists.
async fn confined(
    key: WidgetKey,
    catalog: &Catalog,
    ctx: &CapabilityContext,
) -> Result<Option<Widget>, StatusCode> {
    catalog.loads.fetch_add(1, Ordering::SeqCst);

    let Some(scope) = FromAuthExtensions::tenant(ctx) else {
        return Ok(None);
    };
    Ok(catalog
        .rows
        .iter()
        .find(|widget| widget.name == key.name && widget.tenant == scope)
        .cloned())
}

/// The same lookup with the tenant left out — the shape of every
/// hand-written loader that takes `_ctx` and means it.
///
/// It compiles, and nothing downstream catches it. See the last test.
async fn unconfined(
    key: WidgetKey,
    catalog: &Catalog,
    _ctx: &CapabilityContext,
) -> Result<Option<Widget>, StatusCode> {
    catalog.loads.fetch_add(1, Ordering::SeqCst);

    Ok(catalog
        .rows
        .iter()
        .find(|widget| widget.name == key.name)
        .cloned())
}

// ---- the assets -------------------------------------------------------------

pub struct AppGrants;

impl GrantProfile for AppGrants {
    type Ctx = CapabilityContext;
    type State = Catalog;
    type Source = FromState<Catalog>;
    type Error = StatusCode;
}

/// `key = WidgetKey` is not optional here, and the reason is worth
/// knowing: the key still defaults to `<Row as FetchByKey<State>>::Key`,
/// and a row reached only by a `load_with` has no `FetchByKey` impl to
/// read it from. The error names the trait, but naming the key is the
/// answer — and naming it is also what tells the route that its segment
/// is called `name`.
#[asset(
    row = Widget,
    key = WidgetKey,
    profile = AppGrants,
    actions = WidgetAction,
    load_with = confined
)]
pub struct WidgetConfined;

#[asset(
    row = Widget,
    key = WidgetKey,
    profile = AppGrants,
    actions = WidgetAction,
    load_with = unconfined
)]
pub struct WidgetUnconfined;

// ---- routes -----------------------------------------------------------------

#[get("/strict/{name}", tag = "Widgets")]
async fn strict(widget: Granted<One<WidgetConfined>>) -> String {
    format!("{}@{}", widget.name, widget.tenant)
}

#[get("/loose/{name}", tag = "Widgets")]
async fn loose(widget: Granted<One<WidgetUnconfined>>) -> String {
    format!("{}@{}", widget.name, widget.tenant)
}

// ---- harness ----------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    catalog: Catalog,
}

impl FromRef<AppState> for Catalog {
    fn from_ref(state: &AppState) -> Self {
        state.catalog.clone()
    }
}

/// Which half of the chain says no, so each can be observed on its own.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Allow,
    DenyCapability,
    DenyInstance,
}

struct Checker(Verdict);

#[async_trait]
impl CapabilityChecker for Checker {
    async fn check(&self, _: &str, _: &[String], _: &Capability) -> Result<bool, AuthError> {
        Ok(self.0 != Verdict::DenyCapability)
    }

    async fn check_instance(
        &self,
        _: &str,
        _: &[String],
        _: &str,
        _: &ResourceEntity,
    ) -> Result<bool, AuthError> {
        Ok(self.0 != Verdict::DenyInstance)
    }
}

/// The load count comes back alongside the response, which is how the
/// "costs no load" half of the gate is observable at all.
struct Call {
    status: StatusCode,
    body: String,
    event: AuditEvent,
    loads: usize,
}

async fn call(uri: &str, tenant: Option<&str>, verdict: Verdict) -> Call {
    let tenant = tenant.map(str::to_owned);
    let catalog = Catalog::seeded();
    let loads = Arc::clone(&catalog.loads);

    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let app = OpenApiRouter::<AppState>::new()
        .routes(routes!(strict))
        .routes(routes!(loose))
        .split_for_parts()
        .0
        .layer(axum::middleware::from_fn(
            move |mut request: Request<Body>, next: axum::middleware::Next| {
                let tenant = tenant.clone();
                async move {
                    request.extensions_mut().insert(CapabilityContext {
                        tenant_id: tenant,
                        roles: vec!["viewer".into()],
                    });
                    let checker: Arc<dyn CapabilityChecker> = Arc::new(Checker(verdict));
                    request.extensions_mut().insert(checker);
                    next.run(request).await
                }
            },
        ))
        .layer(AuditLayer::new(AuditLogger::from_sender(tx)))
        .with_state(AppState {
            catalog: catalog.clone(),
        });

    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .expect("request");

    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    Call {
        status,
        body: String::from_utf8(bytes.to_vec()).unwrap(),
        event: rx.recv().await.expect("a verdict is recorded either way"),
        loads: loads.load(Ordering::SeqCst),
    }
}

// ---- what the door keeps ----------------------------------------------------

/// A confined `load_with` is indistinguishable from a generated loader,
/// which is the baseline the rest of the file measures against.
#[tokio::test]
async fn a_confined_loader_behaves_like_a_generated_one() {
    let call = call("/strict/alpha", Some("acme"), Verdict::Allow).await;

    assert_eq!(call.status, StatusCode::OK);
    assert_eq!(call.body, "alpha@acme");
    assert_eq!(call.loads, 1);
}

/// …including the miss. Another tenant's row is absent, not refused, so
/// the route answers 404 rather than confirming it exists with a 403.
#[tokio::test]
async fn a_confined_loader_still_answers_absent_for_another_tenant() {
    let call = call("/strict/beta", Some("acme"), Verdict::Allow).await;

    assert_eq!(call.status, StatusCode::NOT_FOUND);
    assert!(!call.body.contains("globex"), "{}", call.body);
}

/// The coarse capability runs *before* the loader, and a caller who fails
/// it costs no load at all. That is the property `gate` exists for, and
/// `load_with` does not move it: a bespoke loader is still behind the same
/// door as a generated one.
#[tokio::test]
async fn the_capability_gate_still_runs_first_and_costs_no_load() {
    let call = call("/loose/alpha", Some("acme"), Verdict::DenyCapability).await;

    assert_eq!(call.status, StatusCode::FORBIDDEN);
    assert_eq!(
        call.loads, 0,
        "the gate refused before anything was fetched",
    );
}

/// And the instance check still runs after it, on the row the bespoke
/// loader returned — so `load_with` does not skip the half of the chain
/// that reads the object's own attributes.
#[tokio::test]
async fn the_instance_check_still_runs_on_the_loaded_row() {
    let call = call("/loose/alpha", Some("acme"), Verdict::DenyInstance).await;

    assert_eq!(call.status, StatusCode::FORBIDDEN);
    assert_eq!(call.loads, 1, "the row was loaded, then refused");
}

/// The verdict reaches the audit trail with the row's Cedar identity,
/// exactly as a generated loader's would. Nothing about the trail is the
/// handler's or the loader's business either way.
#[tokio::test]
async fn the_grant_is_recorded_with_the_rows_cedar_identity() {
    let call = call("/strict/alpha", Some("acme"), Verdict::Allow).await;

    assert_eq!(call.event.outcome, Outcome::Allowed);
    assert_eq!(call.event.action, "read");
    assert_eq!(call.event.resource_type.as_deref(), Some("Widget"));
    assert_eq!(
        call.event.resource_id.as_deref(),
        Some("alpha"),
        "the id the policy saw, not the key the route parsed",
    );
}

/// A refusal is recorded too, so a bespoke loader cannot end up behind a
/// denial that leaves no trail.
#[tokio::test]
async fn a_denial_over_a_bespoke_loader_is_recorded() {
    let call = call("/loose/alpha", Some("acme"), Verdict::DenyCapability).await;

    assert_eq!(call.event.outcome, Outcome::Denied);
    assert_eq!(
        call.event.resource_type.as_deref(),
        Some("WidgetCollection")
    );
}

// ---- and the one thing it drops ---------------------------------------------

/// The boundary, written down.
///
/// `beta` belongs to globex. An `acme` caller asking for it gets it —
/// through the capability gate, through the instance check, into the
/// response, and recorded in the trail as a legitimate grant. Every other
/// mechanism in the chain did its job; none of them is the one that was
/// supposed to catch this, because the only thing that catches it is the
/// loader reading `ctx`, and this loader does not.
///
/// The generated path cannot express this: `FetchByKey::fetch` is handed
/// `&str` and has nothing else to consult. That is why `load_with` takes
/// the whole `Ctx` and why taking it is the cost of the door.
#[tokio::test]
async fn an_unconfined_loader_reaches_another_tenants_row_and_nothing_stops_it() {
    let call = call("/loose/beta", Some("acme"), Verdict::Allow).await;

    assert_eq!(
        call.status,
        StatusCode::OK,
        "no part of the chain confines a bespoke loader",
    );
    assert_eq!(call.body, "beta@globex", "acme was served globex's row");
    assert_eq!(
        call.event.outcome,
        Outcome::Allowed,
        "and the trail records it as a grant, because as far as the \
         policy was concerned it was one",
    );
}

/// The same asset with no tenant at all. The generated loader answers
/// `None` here; this one has no reason to, and does not.
#[tokio::test]
async fn an_unconfined_loader_serves_a_caller_with_no_tenant() {
    let call = call("/loose/alpha", None, Verdict::Allow).await;

    assert_eq!(call.status, StatusCode::OK);
    assert_eq!(call.body, "alpha@acme");
}

/// Where the confined one refuses, as the generated loader would.
#[tokio::test]
async fn a_confined_loader_answers_none_for_a_caller_with_no_tenant() {
    let call = call("/strict/alpha", None, Verdict::Allow).await;

    assert_eq!(call.status, StatusCode::NOT_FOUND);
}
