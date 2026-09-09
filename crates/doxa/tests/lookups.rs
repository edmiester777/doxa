//! Named lookups, and the table condition every query carries.
//!
//! `FetchByKey` and `FetchById` are facets of a row, so a row gets one of
//! each — the key its routes address it by, and its own identifier. A
//! dataset version has three ways in: a uuid, a dataset name, and a
//! `(dataset, version)` pair. The third used to become a descriptor with
//! `load_with`, which is the one door that gives up the scope guarantee, so
//! the row with the most ways in was the row most likely to lose it.
//!
//! What this file pins is that naming a lookup buys a second way in and not
//! a way out. Every generated lookup builds on `ScopedTable::scoped`, so the
//! tenant filter and the table condition come along whichever way the row is
//! reached — and the composite lookup, the single-column one and the id
//! lookup all have to prove it separately, because each is built by a
//! different arm.

#![cfg(all(feature = "full", feature = "policy-sea-orm"))]

use doxa::auth::{CapabilityContext, FromState, GrantProfile, Granting, RouteKey};
use doxa::policy::{DbLoadError, Lookup, PolicyResource, ScopedTable};
use doxa::{asset, Actions, PolicyResource};
use sea_orm::entity::prelude::*;
use sea_orm::{DatabaseBackend, DatabaseConnection, MockDatabase, QueryTrait, Transaction};
use serde::{Deserialize, Serialize};

// ---- the row ----------------------------------------------------------------

#[derive(
    Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize, PolicyResource,
)]
#[sea_orm(table_name = "versions")]
#[resource(entity_type = "Version", filter = Column::DeletedAt.is_null())]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    #[resource(id)]
    pub id: Uuid,

    /// In two lookups at once — by itself, and as the first half of the
    /// pair. This is the column that would otherwise have forced a choice
    /// between the two routes that read it.
    #[resource(key(FindByDataset, FindByPair), attr)]
    pub dataset: String,

    #[resource(key(FindByPair))]
    pub version: i64,

    /// Every lookup is confined to this, named or not.
    #[resource(parent = "Tenant", scope)]
    pub tenant_id: String,

    /// The tombstone. Not a key and not an attribute — a fact about
    /// whether the row is real, which is what `filter` is for.
    pub deleted_at: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Debug, Clone, Copy, Actions)]
#[actions(resource = "Version", prefix = "versions")]
pub enum VersionAction {
    /// Read one version.
    Read,
}

// ---- the application --------------------------------------------------------

pub struct AppGrants;

impl GrantProfile for AppGrants {
    type Ctx = CapabilityContext;
    type State = DatabaseConnection;
    type Source = FromState<DatabaseConnection>;
    type Error = DbLoadError;
}

/// No `row =`: a marker means "this row, by these columns", so naming the
/// lookup names the row too.
#[asset(with = FindByPair, profile = AppGrants, actions = VersionAction)]
pub struct VersionByPair;

/// The same row, the other way in, and the same `PolicyResource` impl
/// behind both.
#[asset(with = FindByDataset, profile = AppGrants, actions = VersionAction)]
pub struct VersionByDataset;

// ---- helpers ----------------------------------------------------------------

fn row() -> Model {
    Model {
        id: Uuid::nil(),
        dataset: "sales".to_owned(),
        version: 3,
        tenant_id: "acme".to_owned(),
        deleted_at: None,
    }
}

fn caller(tenant: Option<&str>) -> CapabilityContext {
    CapabilityContext {
        tenant_id: tenant.map(str::to_owned),
        roles: vec!["versions.read".to_owned()],
    }
}

fn db_returning(rows: Vec<Model>) -> DatabaseConnection {
    MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results([rows])
        .into_connection()
}

fn same<A: 'static, B: 'static>() {
    assert_eq!(
        std::any::TypeId::of::<A>(),
        std::any::TypeId::of::<B>(),
        "{} is not {}",
        std::any::type_name::<A>(),
        std::any::type_name::<B>(),
    );
}

// ---- what the declaration produced ------------------------------------------

/// The point of the whole feature: `dataset` takes part in two lookups, and
/// the two disagree about the key without disagreeing about the row.
///
/// Before this, a column could belong to one lookup. A row reached both by
/// `dataset` and by `(dataset, version)` had to give one of them up to
/// `load_with` — and it is the composite one that would have gone, because
/// it is the one `#[resource(key)]` could not spell.
#[test]
fn one_column_takes_part_in_more_than_one_lookup() {
    // Every lookup gets its own key struct, one column or several: the
    // field name is what binds the route's segment.
    same::<<FindByDataset as Lookup<DatabaseConnection>>::Key, FindByDatasetKey>();
    same::<<FindByPair as Lookup<DatabaseConnection>>::Key, FindByPairKey>();

    // Different keys, one row.
    same::<<FindByDataset as Lookup<DatabaseConnection>>::Row, Model>();
    same::<<FindByPair as Lookup<DatabaseConnection>>::Row, Model>();
}

/// A lookup carries its row, so the asset needs no `row =` beside `with =`
/// — and two assets over one row cannot come to name different rows.
#[test]
fn the_asset_takes_its_row_and_its_key_from_the_lookup() {
    same::<<VersionByPair as Granting>::Row, Model>();
    same::<<VersionByPair as Granting>::Key, FindByPairKey>();

    same::<<VersionByDataset as Granting>::Row, Model>();
    same::<<VersionByDataset as Granting>::Key, FindByDatasetKey>();

    assert_eq!(
        <<VersionByPair as Granting>::Row as PolicyResource>::ENTITY_TYPE,
        <<VersionByDataset as Granting>::Row as PolicyResource>::ENTITY_TYPE,
    );
}

/// The composite key names its segments, which is what stops a route
/// transposing it. Two `String` columns bound by position parse cleanly
/// and load the wrong row; axum's `Path` binds these by field name, so
/// swapping them means spelling one wrong.
#[test]
fn the_composite_key_names_its_segments() {
    assert_eq!(
        <FindByPairKey as RouteKey>::SEGMENTS.len(),
        2,
        "one segment per column",
    );
    assert_eq!(
        <FindByPairKey as RouteKey>::NAMES,
        ["dataset", "version"],
        "and the route parameters are those names",
    );
}

/// One lookup is generic over the connection, as the unnamed ones are, so
/// the same lookup serves a handler holding an open transaction. A pool
/// cannot see rows the request has written and not committed.
#[test]
fn a_lookup_serves_any_connection() {
    fn reachable<C: sea_orm::ConnectionTrait>()
    where
        FindByPair: Lookup<C, Row = Model>,
    {
    }

    reachable::<DatabaseConnection>();
    reachable::<sea_orm::DatabaseTransaction>();
}

// ---- the queries ------------------------------------------------------------

/// The statement `FindByPair` builds. Shared by the two tests below so the
/// second can pin the *values* without restating the SQL.
const PAIR_SQL: &str = r#"SELECT "versions"."id", "versions"."dataset", "versions"."version", "versions"."tenant_id", "versions"."deleted_at" FROM "versions" WHERE "versions"."tenant_id" = $1 AND "versions"."deleted_at" IS NULL AND "versions"."dataset" = $2 AND "versions"."version" = $3 LIMIT $4"#;

/// The composite lookup matches every column it declared, and the scope
/// besides.
///
/// Pinned whole rather than probed: the scope predicate being present is the
/// security property, and a `contains` assertion would still pass if it
/// moved into an `OR`.
#[tokio::test]
async fn a_composite_lookup_matches_each_column_and_the_scope() {
    let db = db_returning(vec![row()]);

    let found = <FindByPair as Lookup<DatabaseConnection>>::fetch(
        FindByPairKey {
            dataset: "sales".to_owned(),
            version: 3,
        },
        &db,
        "acme",
    )
    .await
    .expect("query runs");

    assert_eq!(found, Some(row()));

    assert_eq!(
        db.into_transaction_log(),
        [Transaction::from_sql_and_values(
            DatabaseBackend::Postgres,
            PAIR_SQL,
            ["acme".into(), "sales".into(), 3i64.into(), 1u64.into()],
        )],
    );
}

/// The key binds by position, and the position is the order the columns
/// were declared in on the struct.
///
/// Worth its own test because the failure is silent when the segments share
/// a type: a `(String, String)` key bound the wrong way round parses cleanly
/// and loads the wrong row. The values are what carry the order — the SQL is
/// identical either way — so this asserts them rather than the statement.
#[tokio::test]
async fn the_composite_key_binds_in_declaration_order() {
    let db = db_returning(vec![]);

    let key = FindByPairKey {
        dataset: "sales".to_owned(),
        version: 7,
    };
    let _ = <FindByPair as Lookup<DatabaseConnection>>::fetch(key, &db, "acme")
        .await
        .expect("query runs");

    assert_eq!(
        db.into_transaction_log(),
        [Transaction::from_sql_and_values(
            DatabaseBackend::Postgres,
            PAIR_SQL,
            // `dataset` then `version`, which is the order they are
            // declared in and therefore the order the tuple takes.
            ["acme".into(), "sales".into(), 7i64.into(), 1u64.into()],
        )],
    );
}

/// A named lookup answers `None` for another tenant's row for the same
/// reason the unnamed one does — it is handed a scope and nothing else, so
/// there is no way for it to decline to apply one.
#[tokio::test]
async fn a_named_lookup_cannot_reach_another_tenants_row() {
    let db = db_returning(vec![]);

    let found = <FindByPair as Lookup<DatabaseConnection>>::fetch(
        FindByPairKey {
            dataset: "sales".to_owned(),
            version: 3,
        },
        &db,
        "globex",
    )
    .await
    .expect("query runs");

    assert_eq!(found, None);

    let sql = format!("{:?}", db.into_transaction_log()[0]);
    assert!(
        sql.contains("globex"),
        "the scope is not in the query: {sql}"
    );
    assert!(!sql.contains("acme"), "{sql}");
}

// ---- the table condition ----------------------------------------------------

/// `filter` reaches the listing.
#[test]
fn the_table_condition_reaches_the_listing() {
    let sql = Model::scoped("acme")
        .build(DatabaseBackend::Postgres)
        .to_string();

    assert!(sql.contains(r#""deleted_at" IS NULL"#), "{sql}");
    assert!(sql.contains(r#""tenant_id" = 'acme'"#), "{sql}");
}

/// …and the id lookup, which is the one that could have been missed.
///
/// `load_by_id` starts from `find_by_id` rather than from `scoped`, so it is
/// the one path that does not inherit the condition and has to fold it in
/// itself. A soft-delete filter applied to three of the four paths is not a
/// compile error; it is a deleted row coming back on the fourth.
#[tokio::test]
async fn the_table_condition_reaches_the_id_lookup() {
    let db = db_returning(vec![]);

    let _ = Model::load_by_id(Uuid::nil(), &db, "acme")
        .await
        .expect("query runs");

    let sql = format!("{:?}", db.into_transaction_log()[0]);
    assert!(sql.contains("deleted_at"), "{sql}");
    assert!(sql.contains("acme"), "{sql}");
}

/// …and every named lookup, since they all build on `scoped`.
#[tokio::test]
async fn the_table_condition_reaches_a_named_lookup() {
    let db = db_returning(vec![]);

    let key = FindByDatasetKey {
        dataset: "sales".to_owned(),
    };
    let _ = <FindByDataset as Lookup<DatabaseConnection>>::fetch(key, &db, "acme")
        .await
        .expect("query runs");

    let sql = format!("{:?}", db.into_transaction_log()[0]);
    assert!(sql.contains("deleted_at"), "{sql}");
}

// ---- through the asset ------------------------------------------------------

/// The generated loader puts the caller's tenant into the query, exactly as
/// it does for an unnamed lookup: `with` changes which columns are matched,
/// not whether the scope is.
#[tokio::test]
async fn the_generated_loader_confines_a_named_lookup() {
    let db = db_returning(vec![row()]);

    let found = <VersionByPair as Granting>::load(
        FindByPairKey {
            dataset: "sales".to_owned(),
            version: 3,
        },
        &db,
        &caller(Some("acme")),
    )
    .await
    .expect("query runs");

    assert_eq!(found, Some(row()));

    let sql = format!("{:?}", db.into_transaction_log()[0]);
    assert!(sql.contains("acme"), "{sql}");
}

/// A caller with no tenant has no scope to confine to, so the answer is
/// that nothing is there — and no query is issued at all.
///
/// The second half is the assertion worth having: a loader that defaulted
/// the scope to `""` would also return `None` here, on any sane schema, and
/// would be a real query for a row somebody could create on a less sane one.
#[tokio::test]
async fn a_caller_with_no_tenant_reaches_no_row_and_no_query() {
    let db = db_returning(vec![row()]);

    let found = <VersionByPair as Granting>::load(
        FindByPairKey {
            dataset: "sales".to_owned(),
            version: 3,
        },
        &db,
        &caller(None),
    )
    .await
    .expect("loader runs");

    assert_eq!(found, None);
    assert!(
        db.into_transaction_log().is_empty(),
        "no tenant should mean no query",
    );
}
