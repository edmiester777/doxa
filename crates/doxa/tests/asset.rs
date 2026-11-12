//! `#[asset]`: the profile is stated once, each asset names its vocabulary, and the key and
//! loader come off the row's own lookup.

#![cfg(all(feature = "full", feature = "policy-sea-orm"))]

use axum::http::StatusCode;
use doxa::auth::{ActionTable, CapabilityContext, FromState, GrantProfile, Granted, Granting, One};
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
    #[action(verb = get)]
    Read,
    /// Remove data widgets.
    #[action(verb = delete)]
    Delete,
}

// ---- the application, stated once -------------------------------------------

pub struct AppGrants;

impl GrantProfile for AppGrants {
    type Ctx = CapabilityContext;
    type State = DatabaseConnection;
    type Source = FromState<DatabaseConnection>;
    type Error = DbLoadError;
}

// ---- the assets -------------------------------------------------------------

#[asset(row = Model, profile = AppGrants, actions = WidgetAction, list = tenant)]
pub struct WidgetByName;

/// The same row by primary key; `key = pk` keeps the tenant filter `find_by_id` would drop.
#[asset(row = Model, key = pk, profile = AppGrants, actions = WidgetAction)]
pub struct WidgetById;

/// A row with an owner and no key column: `ScopedTable` without `ScopedRow`.
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

/// `key = pk` and `list = tenant` compile on a row with no key column.
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

/// The key is the struct the derive wrote around the `#[resource(key)]` column.
#[test]
fn the_key_comes_off_the_row() {
    fn key_is_the_generated_one<A>()
    where
        A: Granting<Key = ModelKey>,
    {
    }

    key_is_the_generated_one::<WidgetByName>();

    // …and the field is the key column, carrying the column's type.
    let key = ModelKey {
        name: "primary".to_owned(),
    };
    let _: <Model as ScopedRow>::Key = key.name;

    assert_eq!(<WidgetByName as Granting>::KEY_NAMES, &["name"]);
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

/// Both routes reach one row, so one Cedar identity governs both.
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

#[tokio::test]
async fn the_generated_loader_confines_the_lookup_to_the_caller_s_tenant() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results([vec![row()]])
        .into_connection();

    let found = <WidgetByName as Granting>::load(
        ModelKey {
            name: "primary".to_owned(),
        },
        &db,
        &caller("acme"),
    )
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

#[tokio::test]
async fn the_primary_key_lookup_is_confined_to_the_tenant_too() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results([Vec::<Model>::new()])
        .into_connection();

    <WidgetById as Granting>::load(ModelId { id: Uuid::nil() }, &db, &caller("acme"))
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

    <DataModelById as Granting>::load(keyless::ModelId { id: Uuid::nil() }, &db, &caller("acme"))
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

/// No tenant means no query, rather than `WHERE tenant_id = ''`.
#[tokio::test]
async fn a_caller_without_a_tenant_reaches_nothing() {
    // Deliberately empty: an appended result would let a query pass
    // unnoticed, and this asserts that none is issued.
    let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();

    let ctx = CapabilityContext {
        tenant_id: None,
        roles: Vec::new(),
    };

    let found = <WidgetByName as Granting>::load(
        ModelKey {
            name: "primary".to_owned(),
        },
        &db,
        &ctx,
    )
    .await
    .expect("no tenant is not an error, it is an absence");

    assert_eq!(found, None);
}

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

    let error = <WidgetByName as Granting>::load(
        ModelKey {
            name: "primary".to_owned(),
        },
        &db,
        &caller("acme"),
    )
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

use widget_action::{Delete as DeleteWidget, Read as GetWidget};

/// A request through a real router, so the key comes off the path exactly
/// as it would in the application.
async fn call<S>(
    db: DatabaseConnection,
    roles: &'static [&'static str],
) -> axum::http::Response<axum::body::Body>
where
    S: doxa::auth::DeclaredAction<Table = WidgetAction>,
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

/// End to end through the guard; the handler receives the row, not the descriptor.
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
