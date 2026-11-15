//! A paged listing: `Query<PageInput>` in, `Json<Page<T>>` out, cut by the database.

use std::collections::BTreeMap;

use doxa::{Page, PageInput, Paged};
use sea_orm::entity::prelude::*;
use sea_orm::{DatabaseBackend, MockDatabase, Transaction};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

mod widget {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize, ToSchema)]
    #[sea_orm(table_name = "widgets")]
    #[schema(as = Widget)]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub name: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[derive(Clone, doxa::State)]
struct AppState;

#[doxa::service]
pub struct Widgets;

/// Widgets, a page at a time.
#[doxa::get("/widgets")]
async fn list_widgets(
    doxa::extract::Query(page): doxa::extract::Query<PageInput>,
) -> doxa::extract::Json<Page<widget::Model>> {
    doxa::extract::Json(Page::of(Vec::new(), &page))
}

#[tokio::test]
async fn a_query_is_counted_and_cut_to_the_page() {
    let count = BTreeMap::from([("num_items".to_owned(), Value::BigInt(Some(25)))]);
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results([[count]])
        .append_query_results([[widget::Model {
            id: 21,
            name: "cog".into(),
        }]])
        .into_connection();

    let page = widget::Entity::find()
        .page(&db, &PageInput::new(3, 10))
        .await
        .unwrap();

    assert_eq!(
        (page.page, page.page_size, page.total, page.total_pages),
        (3, 10, 25, 3)
    );
    assert_eq!(page.items[0].name, "cog");
    let log = db.into_transaction_log();
    let fetch = log.last().unwrap();
    assert_eq!(
        *fetch,
        Transaction::from_sql_and_values(
            DatabaseBackend::Postgres,
            r#"SELECT "widgets"."id", "widgets"."name" FROM "widgets" LIMIT $1 OFFSET $2"#,
            [10u64.into(), 20u64.into()],
        )
    );
}

#[test]
fn the_document_names_the_page_and_its_size() {
    let (_, api) = doxa::app(&AppState).split_for_parts();
    let doc = serde_json::to_value(&api).unwrap();
    let op = &doc["paths"]["/widgets"]["get"];
    let names: Vec<&str> = op["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["page", "page_size"]);
    let body = op["responses"]["200"]["content"]["application/json"]["schema"].to_string();
    for field in ["total_pages", "items"] {
        assert!(doc.to_string().contains(field), "{field} missing: {body}");
    }
}
