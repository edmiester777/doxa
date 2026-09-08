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
#[sea_orm(table_name = "sources")]
#[resource(entity_type = "Source")]
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
#[actions(resource = "Source", prefix = "sources")]
pub enum SourceAction {
    /// List and view data sources.
    Read,
    /// Remove data sources.
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
/// `ScopedRow`; the caller, state and error come off the profile.
#[asset(row = Model, profile = AppGrants, actions = SourceAction)]
pub struct SourceByName;

/// The same row on a second route key. A unit struct, not a newtype —
/// which is the point of the whole arrangement. The primary key is not
/// what `#[resource(key)]` named, so this one supplies its own lookup.
#[asset(
    row = Model,
    key = Uuid,
    profile = AppGrants,
    actions = SourceAction,
    load_with = by_id
)]
pub struct SourceById;

async fn by_id(
    id: Uuid,
    db: &DatabaseConnection,
    _ctx: &CapabilityContext,
) -> Result<Option<Model>, DbLoadError> {
    Ok(Entity::find_by_id(id).one(db).await?)
}

// `Row` defaulting to `Self` — the attribute written on the row itself —
// is covered by the macro's own tests. It needs the row and the profile to
// be able to see each other, which is exactly what a separate entity crate
// prevents, so the descriptor form above is the one worth exercising here.

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

    same::<<SourceByName as Granting>::Ctx, <AppGrants as GrantProfile>::Ctx>();
    same::<<SourceByName as Granting>::State, <AppGrants as GrantProfile>::State>();
    same::<<SourceByName as Granting>::Error, <AppGrants as GrantProfile>::Error>();
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

    key_is_the_scoped_one::<SourceByName>();
}

/// The vocabulary is the enum's table, and the same one either route sees.
#[test]
fn both_descriptors_carry_the_same_vocabulary() {
    assert!(std::ptr::eq(
        <SourceByName as Granting>::ACTIONS,
        <SourceAction as ActionTable>::ACTIONS,
    ));
    assert!(std::ptr::eq(
        <SourceById as Granting>::ACTIONS,
        <SourceByName as Granting>::ACTIONS,
    ));
}

/// The reason `Row` is a separate associated type rather than `Self`.
///
/// Both routes reach one row, so there is one `PolicyResource` impl and
/// one Cedar identity. Were `SourceById` a newtype it would carry its own
/// forwarding, and a policy granting on `Source::"primary"` could silently
/// fail to govern the route that reached the same row by id — a grant that
/// does not apply, with nothing to see in the logs.
#[test]
fn one_row_reached_two_ways_has_one_cedar_identity() {
    fn entity_type<A: Granting>() -> &'static str {
        <A::Row as PolicyResource>::ENTITY_TYPE
    }

    assert_eq!(entity_type::<SourceByName>(), "Source");
    assert_eq!(entity_type::<SourceById>(), entity_type::<SourceByName>());

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
        roles: vec!["sources.read".to_owned()],
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

    let found = <SourceByName as Granting>::load("primary".to_owned(), &db, &caller("acme"))
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

/// A caller with no tenant scopes to the empty string rather than to
/// everything — the lookup still runs, and still matches nothing.
#[tokio::test]
async fn a_caller_without_a_tenant_matches_nothing() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results([Vec::<Model>::new()])
        .into_connection();

    let ctx = CapabilityContext {
        tenant_id: None,
        roles: Vec::new(),
    };

    let found = <SourceByName as Granting>::load("primary".to_owned(), &db, &ctx)
        .await
        .expect("query runs");

    assert_eq!(found, None);
}

/// A failed query converts through the profile's error, so the asset owes
/// no `map_err`.
#[tokio::test]
async fn a_failed_query_becomes_the_profile_s_error() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors([DbErr::Custom("connection reset".to_owned())])
        .into_connection();

    let error = <SourceByName as Granting>::load("primary".to_owned(), &db, &caller("acme"))
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

struct GetSource;
impl doxa::auth::GrantSite for GetSource {
    const PARAMS: &'static [&'static str] = &["name"];
    const ACTION: &'static str = "read";
}

struct DeleteSource;
impl doxa::auth::GrantSite for DeleteSource {
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
    Granted<One<SourceByName, S>>: axum::extract::FromRequestParts<DatabaseConnection>,
{
    use tower::ServiceExt;

    async fn handler(guard: Granted<One<SourceByName, GetSource>>) -> String {
        guard.into_inner().name
    }
    async fn deleting(guard: Granted<One<SourceByName, DeleteSource>>) -> String {
        guard.into_inner().name
    }

    let app = axum::Router::new()
        .route("/sources/{name}", axum::routing::get(handler))
        .route("/sources/{name}", axum::routing::delete(deleting))
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
            .uri("/sources/primary")
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

    let response = call::<GetSource>(db, &["sources.read"]).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    assert_eq!(&body[..], b"primary");
}

/// The guard still refuses what the vocabulary does not cover — the
/// capability `SourceAction::Delete` declared, which this caller lacks.
#[tokio::test]
async fn an_action_the_caller_does_not_hold_is_refused() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results([vec![row()]])
        .into_connection();

    let response = call::<DeleteSource>(db, &["sources.read"]).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
