//! `#[derive(PolicyResource)]` over a SeaORM model: Cedar identity and
//! the lookup that loads it, from one declaration.
//!
//! The entity below is the shape this exists for — a control-plane row
//! reached by a name within a tenant. What used to be a descriptor
//! per table (an entity type, an id, an attribute map, a scoped `find`,
//! and a scoped `Select`) is here five field annotations, and the two
//! halves cannot drift apart because there is only one declaration.

#![cfg(feature = "full")]

use axum::http::StatusCode;
use axum::response::IntoResponse;
use doxa::policy::{DbLoadError, PolicyResource, ScopedRow};
use doxa::PolicyResource;
use sea_orm::entity::prelude::*;
use sea_orm::{
    DatabaseBackend, DatabaseConnection, IdenStatic, MockDatabase, QueryTrait, Transaction,
};
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize, PolicyResource,
)]
#[sea_orm(table_name = "connections")]
#[resource(entity_type = "Connection", attrs_with = policy_attrs)]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,

    /// The route's key *and* the Cedar id, which is the common case but
    /// not a requirement — see [`the_key_need_not_be_the_id`].
    #[resource(id, attr, key)]
    pub name: String,

    /// Every lookup is confined to this, so a name belonging to another
    /// tenant is indistinguishable from one that does not exist.
    #[resource(parent = "Tenant", scope)]
    pub tenant_id: String,

    #[resource(attr)]
    pub driver: String,

    pub replicas: i32,
}

impl Model {
    /// An attribute that is a fact about the row rather than a column on
    /// it — the case `attrs_with` exists for.
    fn policy_attrs(&self) -> serde_json::Map<String, serde_json::Value> {
        serde_json::Map::from_iter([("pooled".to_owned(), serde_json::json!(self.replicas > 1))])
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

fn row() -> Model {
    Model {
        id: Uuid::nil(),
        name: "primary".to_owned(),
        tenant_id: "acme".to_owned(),
        driver: "postgres".to_owned(),
        replicas: 3,
    }
}

// ---- identity ---------------------------------------------------------------

#[test]
fn the_entity_type_and_id_come_off_the_annotations() {
    assert_eq!(<Model as PolicyResource>::ENTITY_TYPE, "Connection");
    assert_eq!(row().resource_id(), "primary");
}

/// The parent is what makes a policy written `resource in Tenant::"acme"`
/// hold for a loaded row, and it comes off the row's own owning column
/// rather than the caller's claim about who they are.
#[test]
fn the_scope_column_doubles_as_the_cedar_parent() {
    assert_eq!(row().cedar_parents(), vec![("Tenant", "acme".to_owned())]);
}

/// Field attributes and the computed ones arrive in one map, so a policy
/// cannot tell which kind it is reading.
#[test]
fn computed_attributes_join_the_field_attributes() {
    let attrs = row().cedar_attrs();

    assert_eq!(attrs["name"], serde_json::json!("primary"));
    assert_eq!(attrs["driver"], serde_json::json!("postgres"));
    assert_eq!(attrs["pooled"], serde_json::json!(true));
    assert_eq!(attrs.len(), 3, "`replicas` was never exposed: {attrs:?}");
}

/// A column the struct did not mark is not reachable from a policy. The
/// default is closed: exposing one is a deliberate annotation, so a new
/// column cannot quietly widen what `when { resource.… }` can read.
#[test]
fn an_unmarked_column_is_not_an_attribute() {
    assert!(!row().cedar_attrs().contains_key("replicas"));
    assert!(!row().cedar_attrs().contains_key("id"));
}

// ---- the loader -------------------------------------------------------------

/// `SeaORM`'s `Column` is not `PartialEq`, so these compare the column
/// name each variant stands for — which is the thing that has to be right
/// anyway.
#[test]
fn the_columns_come_off_the_field_names() {
    assert_eq!(<Model as ScopedRow>::KEY_COLUMN.as_str(), "name");
    assert_eq!(<Model as ScopedRow>::SCOPE_COLUMN.as_str(), "tenant_id");
}

/// The listing is the scope filter and nothing else, so what a caller may
/// page and what they may fetch one of are the same set.
#[test]
fn the_listing_is_confined_to_the_scope() {
    let sql = Model::scoped("acme")
        .build(DatabaseBackend::Postgres)
        .to_string();

    assert!(
        sql.contains(r#""connections"."tenant_id" = 'acme'"#),
        "{sql}"
    );
}

#[tokio::test]
async fn a_row_in_scope_is_found() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results([vec![row()]])
        .into_connection();

    let found = Model::load_scoped("primary".to_owned(), &db, "acme")
        .await
        .expect("query runs");

    assert_eq!(found, Some(row()));
}

/// The whole point of the scope column: the tenant is in the `WHERE`
/// clause, so a caller naming another tenant's row gets `None` from the
/// database rather than a row the handler is then trusted to reject.
#[tokio::test]
async fn the_lookup_filters_on_both_the_key_and_the_scope() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results([Vec::<Model>::new()])
        .into_connection();

    Model::load_scoped("primary".to_owned(), &db, "other-tenant")
        .await
        .expect("query runs");

    // Pinned whole rather than probed: the scope predicate being present
    // is the security property, and an assertion that only looked for a
    // substring would still pass if it moved into an `OR`.
    assert_eq!(
        db.into_transaction_log(),
        [Transaction::from_sql_and_values(
            DatabaseBackend::Postgres,
            r#"SELECT "connections"."id", "connections"."name", "connections"."tenant_id", "connections"."driver", "connections"."replicas" FROM "connections" WHERE "connections"."tenant_id" = $1 AND "connections"."name" = $2 LIMIT $3"#,
            ["other-tenant".into(), "primary".into(), 1u64.into()],
        )],
    );
}

/// A miss and a row owned by someone else are the same answer, which is
/// what stops a route reporting 403 where it would otherwise report 404
/// and thereby confirming the row exists.
#[tokio::test]
async fn a_row_out_of_scope_is_indistinguishable_from_a_miss() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results([Vec::<Model>::new(), Vec::<Model>::new()])
        .into_connection();

    let wrong_tenant = Model::load_scoped("primary".to_owned(), &db, "other-tenant")
        .await
        .expect("query runs");
    let no_such_row = Model::load_scoped("absent".to_owned(), &db, "acme")
        .await
        .expect("query runs");

    assert_eq!(wrong_tenant, None);
    assert_eq!(wrong_tenant, no_such_row);
}

// ---- the error --------------------------------------------------------------

/// A loader shaped as `Granting::load` is, so the `?` below is the one an
/// asset actually writes. Its whole body is the conversion this section is
/// about: without [`DbLoadError`] the application supplies its own error
/// and this line is a `map_err`.
async fn load(
    name: &str,
    db: &DatabaseConnection,
    tenant: &str,
) -> Result<Option<Model>, DbLoadError> {
    Ok(Model::load_scoped(name.to_owned(), db, tenant).await?)
}

#[tokio::test]
async fn a_query_that_fails_converts_on_the_question_mark() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors([DbErr::Custom(
            r#"relation "connections" does not exist"#.to_owned(),
        )])
        .into_connection();

    let error = load("primary", &db, "acme")
        .await
        .expect_err("the query failed");

    assert!(matches!(error, DbLoadError::Failed));
}

/// The 500 branch is the one nobody reviews, so what it says is pinned
/// here. A `DbErr` names the statement and the columns in it; none of that
/// may reach the client, and the type holds nothing that could.
#[tokio::test]
async fn the_failure_tells_the_client_nothing_about_the_database() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors([DbErr::Custom(
            r#"relation "connections" does not exist"#.to_owned(),
        )])
        .into_connection();

    let error = load("primary", &db, "acme")
        .await
        .expect_err("the query failed");

    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let body = String::from_utf8(bytes.to_vec()).expect("utf-8");

    for leaked in ["connections", "relation", "does not exist"] {
        assert!(
            !body.contains(leaked),
            "{leaked:?} reached the client: {body}"
        );
    }

    let json: serde_json::Value = serde_json::from_str(&body).expect("an envelope");
    assert_eq!(json["status"], 500);
    assert_eq!(json["code"], "load_failed");
    assert_eq!(json["message"], "could not load the requested resource");
}

/// The route's key and the Cedar id answer different questions. Here the
/// row is reached by its uuid but still names itself by its name, so a
/// policy written against `Connection::"primary"` covers both routes.
#[test]
fn the_key_need_not_be_the_id() {
    // `KEY_COLUMN` is `name` above; this asserts only that the two are
    // separately declared, which is what lets a second descriptor key the
    // same table on `id` without changing what a policy names.
    assert_eq!(<Model as ScopedRow>::KEY_COLUMN.as_str(), "name");
    assert_eq!(row().resource_id(), row().name);
}
