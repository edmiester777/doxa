//! A `#[derive(Patch)]` DTO writes only the columns it sent, through `#[derive(PatchTarget)]`.

#![cfg(feature = "full")]

use doxa::{changed_columns, Nullable, Patch, PatchTarget, PolicyResource};
use sea_orm::entity::prelude::*;
use sea_orm::{ActiveValue, DatabaseBackend, QueryTrait};
use serde::{Deserialize, Serialize};

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    DeriveEntityModel,
    Serialize,
    Deserialize,
    PolicyResource,
    PatchTarget,
)]
#[sea_orm(table_name = "orders")]
#[resource(entity_type = "Order")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    #[resource(id)]
    pub id: Uuid,
    #[resource(scope)]
    #[patch(skip)]
    pub tenant_id: String,
    pub quantity: i32,
    pub note: Option<String>,
    pub level: String,
    #[sea_orm(ignore)]
    pub cached: u8,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// The wire's own type for a column the database stores as text.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Level {
    Low,
    High,
}

impl From<Level> for String {
    fn from(level: Level) -> String {
        format!("{level:?}").to_lowercase()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, Patch)]
#[serde(default)]
pub struct UpdateOrder {
    #[patch(column = "quantity")]
    pub count: Option<i32>,
    pub note: Nullable<String>,
    pub level: Option<Level>,
    #[patch(skip)]
    pub reason: Option<String>,
}

fn row() -> Model {
    Model {
        id: Uuid::nil(),
        tenant_id: "acme".to_owned(),
        quantity: 2,
        note: Some("gift".to_owned()),
        level: "low".to_owned(),
        cached: 0,
    }
}

fn applied(edit: UpdateOrder) -> ActiveModel {
    let mut active: ActiveModel = row().into();
    edit.apply(&mut active);
    active
}

fn changed(active: &ActiveModel) -> Vec<&'static str> {
    changed_columns(active)
        .into_iter()
        .map(|c| sea_orm::IdenStatic::as_str(&c))
        .collect()
}

fn sql(active: ActiveModel) -> String {
    Entity::update(active)
        .validate()
        .unwrap()
        .build(DatabaseBackend::Postgres)
        .to_string()
}

#[test]
fn an_empty_patch_changes_nothing() {
    let active = applied(UpdateOrder::default());
    assert!(changed_columns(&active).is_empty());
}

#[test]
fn a_sent_field_writes_only_its_column() {
    let active = applied(UpdateOrder {
        count: Some(5),
        reason: Some("ignored".to_owned()),
        ..UpdateOrder::default()
    });
    assert_eq!(changed(&active), ["quantity"]);
    let sql = sql(active);
    assert!(sql.contains(r#"SET "quantity" = 5"#), "{sql}");
    assert!(!sql.contains("note"), "{sql}");
}

#[test]
fn a_value_equal_to_the_stored_one_is_not_written() {
    let active = applied(UpdateOrder {
        count: Some(2),
        level: Some(Level::Low),
        ..UpdateOrder::default()
    });
    assert!(changed_columns(&active).is_empty());
}

#[test]
fn null_clears_and_a_value_converts() {
    let active = applied(UpdateOrder {
        note: Nullable::Null,
        level: Some(Level::High),
        ..UpdateOrder::default()
    });
    assert_eq!(active.note, ActiveValue::Set(None));
    assert_eq!(active.level, ActiveValue::Set("high".to_owned()));
    let active = applied(UpdateOrder {
        note: Nullable::Value("rush".to_owned()),
        ..UpdateOrder::default()
    });
    assert_eq!(active.note, ActiveValue::Set(Some("rush".to_owned())));
}

#[test]
fn a_wire_body_patches_what_it_names() {
    let edit: UpdateOrder = serde_json::from_str(r#"{"note":null}"#).unwrap();
    assert_eq!(changed(&applied(edit)), ["note"]);
    let edit: UpdateOrder = serde_json::from_str("{}").unwrap();
    assert!(changed_columns(&applied(edit)).is_empty());
}
