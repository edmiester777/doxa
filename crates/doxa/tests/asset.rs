//! `#[asset]`: the whole of an application's authorization wiring.
//!
//! What this file is really testing is what is *not* written below. An
//! asset used to declare a key, a caller shape, a state type, an error, a
//! vocabulary and a loader — six items, of which three were the same in
//! every asset of the service and two were the lookup the row had already
//! declared. Here the profile is stated once and each asset names its
//! vocabulary, and there is no other wiring.

#![cfg(all(feature = "full", feature = "policy-sea-orm"))]

use axum::http::StatusCode;
use doxa::auth::{ActionTable, CapabilityContext, GrantProfile, Granted, Granting, One};
use doxa::policy::{
    AuthError, Capability, CapabilityChecker, DbLoadError, PolicyResource, ResourceEntity,
    ScopedRow,
};
use doxa::{asset, Actions, PolicyResource, ToSchema};
use sea_orm::entity::prelude::*;
use sea_orm::{DatabaseBackend, DatabaseConnection, MockDatabase};
use serde::{Deserialize, Serialize};

// ---- the row ----------------------------------------------------------------

#[derive(
    Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize, ToSchema, PolicyResource,
)]
#[sea_orm(table_name = "widgets")]
#[resource(entity_type = "Widget")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,

    /// The route's key and the Cedar id both.
    #[resource(id, attr, key)]
    pub name: String,

    /// Every lookup is confined to this.
    #[resource(parent = "Tenant", scope)]
    pub tenant_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Debug, Clone, Copy, Actions)]
#[actions(resource = "Widget", prefix = "widgets")]
pub enum WidgetAction {
    /// List and view data widgets.
    Read,
    /// Remove data widgets.
    Delete,
}

// ---- the application, stated once -------------------------------------------

pub struct AppGrants;

impl GrantProfile for AppGrants {
    type Ctx = CapabilityContext;
    type State = DatabaseConnection;
    type Error = DbLoadError;
}

// ---- the assets -------------------------------------------------------------

/// The whole declaration. The key and the loader come off the row's
/// `ScopedRow`; the caller, state and error come off the profile. `list`
/// adds the collection route's `Scoping`, confined to the tenant.
#[asset(row = Model, profile = AppGrants, actions = WidgetAction, list = tenant)]
pub struct WidgetByName;

/// The same row on a second route key: a unit struct, not a newtype.
///
/// `key = pk` rather than `key = Uuid, load_with = …`, and the difference
/// is not brevity. Written out, a primary-key lookup is
/// `Entity::find_by_id(id).one(db)` — which drops the tenant filter, and
/// nothing in the type system asks for it back.
#[asset(row = Model, key = pk, profile = AppGrants, actions = WidgetAction)]
pub struct WidgetById;

// `Row` defaulting to `Self` — the attribute written on the row itself —
// is covered by the macro's own tests. It needs the row and the profile to
// be able to see each other, which is exactly what a separate entity crate
// prevents, so the descriptor form above is the one worth exercising here.

/// The row the two traits were split for: an owner, and no key column.
///
/// Its name route resolves through logic — a bare `orders` tried against
/// every namespace — so there is nothing to mark `#[resource(key)]` with.
/// Marking `name` anyway would generate a lookup that silently picks one
/// of several rows. So it has `ScopedTable` and no `ScopedRow`, and the
/// asset below is what that has to leave reachable.
pub mod keyless {
    use super::*;

    #[derive(
        Clone,
        Debug,
        PartialEq,
        Eq,
        DeriveEntityModel,
        Serialize,
        Deserialize,
        ToSchema,
        PolicyResource,
    )]
    #[sea_orm(table_name = "models")]
    #[resource(entity_type = "DataModel")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        #[resource(id)]
        pub id: Uuid,

        /// Not a key: no column match reaches this row by name.
        pub name: String,

        #[resource(parent = "Tenant", scope)]
        pub tenant_id: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// `key = pk` and `list = tenant` on a row with no key column.
///
/// This declaration is the regression test. `load_by_id` reads the scope
/// column and the primary key and nothing else, so it belongs to
/// `ScopedTable`; were it on `ScopedRow`, this line would not compile and
/// the id route here would go back to a hand-written
/// `find_by_id().filter(tenant_id)` — the one `key = pk` exists to stop.
#[asset(
    row = keyless::Model,
    key = pk,
    profile = AppGrants,
    actions = WidgetAction,
    list = tenant
)]
pub struct DataModelById;

// ---- what the attribute worked out ------------------------------------------

/// The three application types are the profile's, not restated per asset.
#[test]
fn the_profile_supplies_the_caller_state_and_error() {
    fn same<A, B>()
    where
        A: 'static,
        B: 'static,
    {
        assert_eq!(
            std::any::TypeId::of::<A>(),
            std::any::TypeId::of::<B>(),
            "{} is not {}",
            std::any::type_name::<A>(),
            std::any::type_name::<B>(),
        );
    }

    same::<<WidgetByName as Granting>::Ctx, <AppGrants as GrantProfile>::Ctx>();
    same::<<WidgetByName as Granting>::State, <AppGrants as GrantProfile>::State>();
    same::<<WidgetByName as Granting>::Error, <AppGrants as GrantProfile>::Error>();
}

/// The key is the one the row declared through `#[resource(key)]`, so the
/// route and the lookup cannot disagree about what addresses the object.
#[test]
fn the_key_comes_off_the_row() {
    fn key_is_the_scoped_one<A>()
    where
        A: Granting<Key = <Model as ScopedRow>::Key>,
    {
    }

    key_is_the_scoped_one::<WidgetByName>();
}

/// The vocabulary is the enum's table, and the same one either route sees.
#[test]
fn both_descriptors_carry_the_same_vocabulary() {
    assert!(std::ptr::eq(
        <WidgetByName as Granting>::ACTIONS,
        <WidgetAction as ActionTable>::ACTIONS,
    ));
    assert!(std::ptr::eq(
        <WidgetById as Granting>::ACTIONS,
        <WidgetByName as Granting>::ACTIONS,
    ));
}

/// The reason `Row` is a separate associated type rather than `Self`.
///
/// Both routes reach one row, so there is one `PolicyResource` impl and
/// one Cedar identity. Were `WidgetById` a newtype it would carry its own
/// forwarding, and a policy granting on `Widget::"primary"` could silently
/// fail to govern the route that reached the same row by id — a grant that
/// does not apply, with nothing to see in the logs.
#[test]
fn one_row_reached_two_ways_has_one_cedar_identity() {
    fn entity_type<A: Granting>() -> &'static str {
        <A::Row as PolicyResource>::ENTITY_TYPE
    }

    assert_eq!(entity_type::<WidgetByName>(), "Widget");
    assert_eq!(entity_type::<WidgetById>(), entity_type::<WidgetByName>());

    let row = Model {
        id: Uuid::nil(),
        name: "primary".to_owned(),
        tenant_id: "acme".to_owned(),
    };
    assert_eq!(row.resource_id(), "primary");
}

// ---- and it loads -----------------------------------------------------------

fn row() -> Model {
    Model {
        id: Uuid::nil(),
        name: "primary".to_owned(),
        tenant_id: "acme".to_owned(),
    }
}

fn caller(tenant: &str) -> CapabilityContext {
    CapabilityContext {
        tenant_id: Some(tenant.to_owned()),
        roles: vec!["widgets.read".to_owned()],
    }
}

/// The generated loader is the scoped one: the caller's tenant reaches the
/// `WHERE` clause, so a name owned by another tenant is a miss rather than
/// a row the handler is trusted to reject.
#[tokio::test]
async fn the_generated_loader_confines_the_lookup_to_the_caller_s_tenant() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results([vec![row()]])
        .into_connection();

    let found = <WidgetByName as Granting>::load("primary".to_owned(), &db, &caller("acme"))
        .await
        .expect("query runs");

    assert_eq!(found, Some(row()));

    let log = db.into_transaction_log();
    let sql = format!("{:?}", log[0]);
    assert!(
        sql.contains("acme"),
        "the tenant is not in the query: {sql}"
    );
}

/// `key = pk` is scoped too, which is the whole reason it exists as an
/// option rather than as three lines in the application.
///
/// The tenant predicate is asserted rather than the whole statement,
/// because what matters is that it is there at all: without it a caller
/// naming another tenant's id reaches that tenant's row, and the route
/// answers 403 where it would have answered 404 — which confirms the row
/// exists.
#[tokio::test]
async fn the_primary_key_lookup_is_confined_to_the_tenant_too() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results([Vec::<Model>::new()])
        .into_connection();

    <WidgetById as Granting>::load(Uuid::nil(), &db, &caller("acme"))
        .await
        .expect("query runs");

    let log = db.into_transaction_log();
    let sql = format!("{:?}", log[0]);
    assert!(
        sql.contains("tenant_id"),
        "a primary-key lookup that ignores the scope: {sql}",
    );
    assert!(sql.contains("acme"), "{sql}");
}

/// And it is scoped on the row that has no key column either, which is the
/// case that had no id route at all while `load_by_id` sat on `ScopedRow`.
#[tokio::test]
async fn a_row_with_no_key_column_still_has_a_scoped_id_route() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results([Vec::<keyless::Model>::new()])
        .into_connection();

    <DataModelById as Granting>::load(Uuid::nil(), &db, &caller("acme"))
        .await
        .expect("query runs");

    let log = db.into_transaction_log();
    let sql = format!("{:?}", log[0]);
    assert!(
        sql.contains("tenant_id"),
        "a primary-key lookup that ignores the scope: {sql}",
    );
    assert!(sql.contains("acme"), "{sql}");
}

/// `list = tenant` yields the listing `Select`, filtered the same way the
/// instance lookup is — so what a caller may page and what they may fetch
/// one of are the same set.
#[test]
fn the_generated_listing_is_confined_to_the_same_tenant() {
    use doxa::auth::Scoping;
    use sea_orm::QueryTrait;

    let filter = <WidgetByName as Scoping>::scope("read", &caller("acme"))
        .expect("scoping runs")
        .expect("the tenant is always a scope");

    let sql = filter.build(DatabaseBackend::Postgres).to_string();
    assert!(sql.contains(r#""widgets"."tenant_id" = 'acme'"#), "{sql}");
}

/// A caller with no tenant has no scope to be confined to, so the answer
/// is that nothing is there — without a query being issued at all.
///
/// The alternative is defaulting the scope to the empty string, which runs
/// a real `WHERE tenant_id = ''`. That finds nothing on any sane schema,
/// and is a row somebody could create on the wrong one.
#[tokio::test]
async fn a_caller_without_a_tenant_reaches_nothing() {
    // Deliberately empty: an appended result would let a query pass
    // unnoticed, and this asserts that none is issued.
    let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();

    let ctx = CapabilityContext {
        tenant_id: None,
        roles: Vec::new(),
    };

    let found = <WidgetByName as Granting>::load("primary".to_owned(), &db, &ctx)
        .await
        .expect("no tenant is not an error, it is an absence");

    assert_eq!(found, None);
}

/// The same for the listing half: no tenant is no scope, which the
/// collection guard turns into a refusal rather than a page of whatever
/// sits under the empty string.
#[test]
fn a_listing_without_a_tenant_grants_no_scope() {
    use doxa::auth::Scoping;

    let ctx = CapabilityContext {
        tenant_id: None,
        roles: Vec::new(),
    };

    assert!(<WidgetByName as Scoping>::scope("widgets.read", &ctx)
        .expect("not an error")
        .is_none(),);
}

/// A failed query converts through the profile's error, so the asset owes
/// no `map_err`.
#[tokio::test]
async fn a_failed_query_becomes_the_profile_s_error() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors([DbErr::Custom("connection reset".to_owned())])
        .into_connection();

    let error = <WidgetByName as Granting>::load("primary".to_owned(), &db, &caller("acme"))
        .await
        .expect_err("the query failed");

    assert!(matches!(error, DbLoadError::Failed));
}

// ---- and it authorizes ------------------------------------------------------

struct Allow;

#[async_trait::async_trait]
impl CapabilityChecker for Allow {
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
        // The row's own scope column is its Cedar parent, so a policy
        // written `resource in Tenant::"acme"` resolves.
        Ok(resource
            .parents
            .contains(&("Tenant".to_owned(), tenant.to_owned())))
    }
}

struct GetWidget;
impl doxa::auth::GrantSite for GetWidget {
    const PARAMS: &'static [&'static str] = &["name"];
    const ACTION: &'static str = "read";
}

struct DeleteWidget;
impl doxa::auth::GrantSite for DeleteWidget {
    const PARAMS: &'static [&'static str] = &["name"];
    const ACTION: &'static str = "delete";
}

/// A request through a real router, so the key comes off the path exactly
/// as it would in the application.
async fn call<S>(
    db: DatabaseConnection,
    roles: &'static [&'static str],
) -> axum::http::Response<axum::body::Body>
where
    S: doxa::auth::GrantSite,
    Granted<One<WidgetByName, S>>: axum::extract::FromRequestParts<DatabaseConnection>,
{
    use tower::ServiceExt;

    async fn handler(guard: Granted<One<WidgetByName, GetWidget>>) -> String {
        guard.into_inner().name
    }
    async fn deleting(guard: Granted<One<WidgetByName, DeleteWidget>>) -> String {
        guard.into_inner().name
    }

    let app = axum::Router::new()
        .route("/widgets/{name}", axum::routing::get(handler))
        .route("/widgets/{name}", axum::routing::delete(deleting))
        .layer(axum::middleware::from_fn(
            move |mut request: axum::http::Request<axum::body::Body>,
                  next: axum::middleware::Next| async move {
                request.extensions_mut().insert(CapabilityContext {
                    tenant_id: Some("acme".to_owned()),
                    roles: roles.iter().map(|r| (*r).to_owned()).collect(),
                });
                request
                    .extensions_mut()
                    .insert(std::sync::Arc::new(Allow) as std::sync::Arc<dyn CapabilityChecker>);
                next.run(request).await
            },
        ))
        .with_state(db);

    let method = if S::ACTION == "delete" {
        "DELETE"
    } else {
        "GET"
    };
    app.oneshot(
        axum::http::Request::builder()
            .method(method)
            .uri("/widgets/primary")
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await
    .unwrap()
}

/// End to end through the guard: the coarse capability the vocabulary
/// names, then the loader the attribute wrote, then the instance check
/// against the row's own parents. The handler receives the *row*, not the
/// descriptor.
#[tokio::test]
async fn a_route_guards_the_asset_the_attribute_wired() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results([vec![row()]])
        .into_connection();

    let response = call::<GetWidget>(db, &["widgets.read"]).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    assert_eq!(&body[..], b"primary");
}

/// The guard still refuses what the vocabulary does not cover — the
/// capability `WidgetAction::Delete` declared, which this caller lacks.
#[tokio::test]
async fn an_action_the_caller_does_not_hold_is_refused() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results([vec![row()]])
        .into_connection();

    let response = call::<DeleteWidget>(db, &["widgets.read"]).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
