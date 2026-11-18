//! `Nullable<T>` and `#[omit_none]` keep the wire and the OpenAPI schema saying the same thing.

use serde_json::{json, Value};

doxa::prelude!();

#[dto]
pub struct Edit {
    pub note: Nullable<String>,
    #[schema(min_length = 1)]
    pub label: Nullable<String>,
    #[omit_none]
    pub name: Option<String>,
    pub tag: Option<String>,
}

/// `#[patch(skip)]` resolves to the derive's helper, not the `patch` route macro in the prelude,
/// and `#[dto]`'s `default` is what `Patch` asks of a `Nullable`.
#[dto]
#[derive(Patch)]
pub struct EditOrder {
    pub note: Nullable<String>,
    #[patch(skip)]
    pub reason: Option<String>,
}

fn schema() -> Value {
    serde_json::to_value(<Edit as utoipa::PartialSchema>::schema()).unwrap()
}

fn blank() -> Edit {
    Edit {
        note: Nullable::Absent,
        label: Nullable::Absent,
        name: None,
        tag: None,
    }
}

#[test]
fn absent_null_and_a_value_are_three_states() {
    let parse = |s: &str| serde_json::from_str::<Edit>(s).unwrap().note;
    assert_eq!(parse("{}"), Nullable::Absent);
    assert_eq!(parse(r#"{"note":null}"#), Nullable::Null);
    assert_eq!(parse(r#"{"note":"n"}"#), Nullable::Value("n".into()));
}

#[test]
fn absent_is_left_out_and_null_is_sent() {
    let out = |e: Edit| serde_json::to_value(e).unwrap();
    assert_eq!(out(blank()), json!({ "tag": null }));
    assert_eq!(
        out(Edit {
            note: Nullable::Null,
            ..blank()
        }),
        json!({ "note": null, "tag": null })
    );
}

#[test]
fn the_schema_marks_null_only_where_it_is_sent() {
    let s = schema();
    assert_eq!(s["required"], Value::Null, "{s:#}");
    assert_eq!(
        s["properties"]["note"]["type"],
        json!(["string", "null"]),
        "{s:#}"
    );
    assert_eq!(s["properties"]["name"]["type"], json!("string"), "{s:#}");
    assert_eq!(
        s["properties"]["tag"]["type"],
        json!(["string", "null"]),
        "{s:#}"
    );
}

#[test]
fn a_nullable_keeps_its_own_schema_rules() {
    let s = schema();
    assert_eq!(
        s["properties"]["label"]["type"],
        json!(["string", "null"]),
        "{s:#}"
    );
    assert_eq!(s["properties"]["label"]["minLength"], json!(1), "{s:#}");
}
