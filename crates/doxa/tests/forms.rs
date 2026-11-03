//! `form()` against a `MemDom`, and `Valid<Json<T>>` answering `422`.

use std::cell::RefCell;
use std::rc::Rc;

use doxa::client::{Fetch, FieldError, FieldErrors, NoError};
use doxa::ui::dom::{MemDom, MemEvent};
use doxa::ui::prelude::*;
use doxa::ui::{form, Form};

#[derive(
    Clone, Default, PartialEq, Debug, serde::Serialize, serde::Deserialize, garde::Validate, Form,
)]
pub struct NewOrder {
    #[garde(length(min = 1, max = 64))]
    pub name: String,
    #[garde(range(min = 1, max = 999))]
    pub quantity: u32,
}

thread_local! {
    static SENT: RefCell<Vec<NewOrder>> = const { RefCell::new(Vec::new()) };
}

#[component]
fn NewOrderForm() -> View {
    let form = form(NewOrder::default())
        .rules(<doxa::Valid<doxa::client::Json<NewOrder>> as doxa::wire::Validates>::check);
    let f = form.fields();
    let save = form.submit(async |v: NewOrder| {
        SENT.with(|s| s.borrow_mut().push(v.clone()));
        if v.name == "taken" {
            let fields = FieldErrors(vec![FieldError {
                path: "name".into(),
                message: "is already taken".into(),
            }]);
            return Err(Fetch::<NoError>::Invalid(fields).into());
        }
        Ok(())
    });
    view! {
        <form on:submit={save.handler()}>
            <input id="name" bind:value={f.name}/>
            <p id="name-err">{f.name.error().unwrap_or_default()}</p>
            <input id="qty" type="number" bind:value={f.quantity}/>
            <p id="qty-err">{f.quantity.error().unwrap_or_default()}</p>
            <button disabled={!form.dirty() || save.pending()}>"Create"</button>
        </form>
    }
}

fn settle() {
    doxa::client::task::run_until_stalled();
}

#[test]
fn a_form_checks_its_rules_first_and_shows_the_servers_422_on_the_field() {
    let dom = MemDom::new();
    App::new(|| view! { <NewOrderForm/> })
        .mount_on(Rc::new(dom.clone()), dom.body())
        .keep();
    settle();
    let id = |s: &str| dom.find("id", s).unwrap();
    let text = |s: &str| dom.text(id(s));
    let button = dom.find_tag("button").unwrap();
    assert!(
        dom.attr(button, "disabled").is_some(),
        "nothing to save yet"
    );
    assert_eq!(text("name-err"), "", "untouched fields show no error");

    // Text that doesn't parse stays in the input and is reported once the field is left.
    dom.input(id("qty"), "abc");
    dom.dispatch(id("qty"), "blur", MemEvent::default());
    settle();
    assert_eq!(text("qty-err"), "isn't a valid value");
    assert_eq!(
        dom.prop(id("qty"), "value"),
        Some(doxa::ui::dom::Prop::Str("abc".into()))
    );

    // Submitting shows every rule and sends nothing.
    let form_node = dom.find_tag("form").unwrap();
    assert!(
        !dom.dispatch(form_node, "submit", MemEvent::default()),
        "the browser's submit is stopped"
    );
    settle();
    assert_ne!(text("name-err"), "");
    assert!(SENT.with(|s| s.borrow().is_empty()));

    // A server 422 lands on the field it names, and goes once that field changes.
    dom.input(id("name"), "taken");
    dom.input(id("qty"), "5");
    settle();
    assert_eq!(text("qty-err"), "");
    dom.dispatch(form_node, "submit", MemEvent::default());
    settle();
    assert_eq!(
        SENT.with(|s| s.take()),
        [NewOrder {
            name: "taken".into(),
            quantity: 5
        }]
    );
    assert_eq!(text("name-err"), "is already taken");
    dom.input(id("name"), "fresh");
    settle();
    assert_eq!(text("name-err"), "");
}

#[component]
fn Choices() -> View {
    let size = state(String::from("s"));
    let tags = state(Vec::<String>::new());
    view! {
        <input id="s" type="radio" value="s" bind:group={size}/>
        <input id="m" type="radio" value="m" bind:group={size}/>
        <select id="tags" multiple="" bind:selected={tags}>
            <option value="a">"a"</option>
            <option value="b">"b"</option>
        </select>
        <p>{format!("{} {}", size.get(), tags.get().join(","))}</p>
    }
}

#[test]
fn radios_and_multi_selects_bind_too() {
    let dom = MemDom::new();
    App::new(|| view! { <Choices/> })
        .mount_on(Rc::new(dom.clone()), dom.body())
        .keep();
    settle();
    let id = |s: &str| dom.find("id", s).unwrap();
    use doxa::ui::dom::Prop;
    assert_eq!(dom.prop(id("s"), "checked"), Some(Prop::Bool(true)));
    dom.dispatch(
        id("m"),
        "change",
        MemEvent {
            checked: true,
            ..MemEvent::default()
        },
    );
    dom.dispatch(
        id("tags"),
        "change",
        MemEvent {
            selected: vec!["a".into(), "b".into()],
            ..MemEvent::default()
        },
    );
    settle();
    assert_eq!(dom.text(dom.find_tag("p").unwrap()), "m a,b");
    assert_eq!(dom.prop(id("m"), "checked"), Some(Prop::Bool(true)));
    assert_eq!(dom.prop(id("s"), "checked"), Some(Prop::Bool(false)));
}

#[tokio::test]
async fn valid_answers_422_with_each_failing_field() {
    use axum::routing::post;
    use axum::Json;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn create(doxa::Valid(Json(o)): doxa::Valid<Json<NewOrder>>) -> Json<NewOrder> {
        Json(o)
    }
    let app = axum::Router::new().route("/orders", post(create));
    let send = |body: &'static str| {
        let app = app.clone();
        async move {
            let req = axum::http::Request::post("/orders")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body))
                .unwrap();
            let res = app.oneshot(req).await.unwrap();
            let status = res.status().as_u16();
            let bytes = res.into_body().collect().await.unwrap().to_bytes();
            (
                status,
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            )
        }
    };
    let (status, body) = send(r#"{"name":"","quantity":0}"#).await;
    assert_eq!(status, 422);
    assert_eq!(body["code"], "invalid");
    let paths: Vec<&str> = body["error"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["name", "quantity"]);
    let (status, _) = send(r#"{"name":"bolts","quantity":3}"#).await;
    assert_eq!(status, 200);
}
