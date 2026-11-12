//! `#[nullable]` and `#[omit_none]` keep the wire and the OpenAPI schema saying the same thing.

use serde_json::{json, Value};

doxa::prelude!();

#[dto]
pub struct Patch {
    #[nullable]
    pub note: Option<Option<String>>,
    #[omit_none]
    pub name: Option<String>,
    pub tag: Option<String>,
}

fn schema() -> Value {
    serde_json::to_value(<Patch as utoipa::PartialSchema>::schema()).unwrap()
}

#[test]
fn absent_null_and_a_value_are_three_states() {
    let parse = |s: &str| serde_json::from_str::<Patch>(s).unwrap().note;
    assert_eq!(parse("{}"), None);
    assert_eq!(parse(r#"{"note":null}"#), Some(None));
    assert_eq!(parse(r#"{"note":"n"}"#), Some(Some("n".into())));
}

#[test]
fn none_is_left_out_and_null_is_sent() {
    let out = |p: Patch| serde_json::to_value(p).unwrap();
    let blank = Patch {
        note: None,
        name: None,
        tag: None,
    };
    assert_eq!(out(blank.clone()), json!({ "tag": null }));
    assert_eq!(
        out(Patch {
            note: Some(None),
            ..blank
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
