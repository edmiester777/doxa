//! A paged listing: `Valid<Query<PageInput<50>>>` in, `Json<Page<T>>` out, cut by the database.

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
    doxa::Valid(doxa::extract::Query(page)): doxa::Valid<doxa::extract::Query<PageInput<50>>>,
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
        .page(&db, &PageInput::<200>::new(3, 10))
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

#[tokio::test]
async fn a_size_past_the_cap_is_refused_per_field() {
    use tower::ServiceExt;
    let ask = |query: &str| {
        let (router, _) = doxa::app(&AppState).split_for_parts();
        let req = axum::http::Request::get(format!("/widgets?{query}"))
            .body(axum::body::Body::empty())
            .unwrap();
        async move { router.oneshot(req).await.unwrap().status().as_u16() }
    };
    assert_eq!(ask("page_size=50").await, 200);
    assert_eq!(ask("page_size=51").await, 422);
    assert_eq!(ask("page=0").await, 422);
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
    assert_eq!(op["parameters"][1]["schema"]["maximum"], 50);
    let body = op["responses"]["200"]["content"]["application/json"]["schema"].to_string();
    for field in ["total_pages", "items"] {
        assert!(doc.to_string().contains(field), "{field} missing: {body}");
    }
}
