//! `form()` against a `MemDom`, and `Valid<Json<T>>` answering `422`.

use std::cell::RefCell;
use std::rc::Rc;

use doxa::client::{Fetch, FieldError, FieldErrors, NoError};
use doxa::ui::dom::{MemDom, MemEvent};
use doxa::ui::prelude::*;
use doxa::ui::{form, Form, RowKey};

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

#[derive(Clone, Default, PartialEq, Debug, garde::Validate, Form)]
pub struct Condition {
    #[garde(length(min = 1))]
    pub column: String,
}

#[derive(Clone, Default, PartialEq, Debug, garde::Validate, Form)]
pub struct Step {
    #[garde(length(min = 1))]
    pub op: String,
}

#[derive(Clone, Default, PartialEq, Debug, garde::Validate, Form)]
pub struct Rule {
    #[garde(skip)]
    pub name: String,
    #[garde(dive)]
    #[form(nested)]
    pub when: Condition,
    #[garde(dive)]
    #[form(list)]
    pub steps: Vec<Step>,
}

fn rule_rules(r: &Rule) -> Result<(), FieldErrors> {
    garde::Validate::validate(r).map_err(FieldErrors::from)
}

thread_local! {
    static RULE: RefCell<Option<Form<Rule>>> = const { RefCell::new(None) };
}

#[component]
fn RuleForm() -> View {
    let form = form(Rule {
        name: "r".into(),
        when: Condition::default(),
        steps: vec![Step { op: "a".into() }, Step { op: String::new() }],
    })
    .rules(rule_rules);
    RULE.with(|r| *r.borrow_mut() = Some(form));
    let f = form.fields();
    let steps = f.steps;
    view! {
        <input id="column" bind:value={f.when.column}/>
        <p id="column-path">{f.when.column.path()}</p>
        <ul>
            {f.steps.rows().into_iter().map(|(key, step)| view! {
                <li key={key}>
                    <input class="op" bind:value={step.op}/>
                    <span class="err">{step.op.error().unwrap_or_default()}</span>
                    <button class="drop" on:click={move |_| steps.remove(key)}>"×"</button>
                </li>
            }).collect::<View>()}
        </ul>
        <button id="add" on:click={move |_| steps.push(Step::default())}>"Add"</button>
    }
}

fn rule_form() -> Form<Rule> {
    RULE.with(|r| r.borrow().expect("mounted"))
}

#[test]
fn nested_and_list_fields_carry_their_paths() {
    let dom = MemDom::new();
    App::new(|| view! { <RuleForm/> })
        .mount_on(Rc::new(dom.clone()), dom.body())
        .keep();
    settle();
    let id = |s: &str| dom.find("id", s).unwrap();
    assert_eq!(dom.text(id("column-path")), "when.column");

    dom.input(id("column"), "region");
    settle();
    assert_eq!(rule_form().value().when.column, "region");

    let form = rule_form();
    let rows = form.fields().steps.rows();
    assert_eq!(rows[1].1.op.path(), "steps[1].op");
    assert_eq!(
        form.errors().get("steps[1].op"),
        Some("length is lower than 1")
    );

    dom.click(id("add"));
    settle();
    assert_eq!(rule_form().value().steps.len(), 3);
    let rows = rule_form().fields().steps.rows();
    assert_eq!(rows[2].1.op.path(), "steps[2].op");
}

#[test]
fn a_reorder_keeps_each_rows_key_and_moves_the_servers_errors_with_it() {
    let dom = MemDom::new();
    App::new(|| view! { <RuleForm/> })
        .mount_on(Rc::new(dom.clone()), dom.body())
        .keep();
    settle();
    let form = rule_form();
    let steps = form.fields().steps;
    let keys: Vec<RowKey> = steps.rows().iter().map(|(k, _)| *k).collect();

    form.set_server_errors(FieldErrors(vec![FieldError {
        path: "steps[0].op".into(),
        message: "unknown op".into(),
    }]));
    steps.move_to(keys[0], 1);
    settle();

    let after: Vec<RowKey> = steps.rows().iter().map(|(k, _)| *k).collect();
    assert_eq!(after, [keys[1], keys[0]], "keys travel with their rows");
    assert_eq!(form.value().steps[1].op, "a");
    assert_eq!(form.errors().get("steps[1].op"), Some("unknown op"));
    assert_eq!(
        form.errors().get("steps[0].op"),
        Some("length is lower than 1")
    );

    // Removing the row drops its error, and the other row's path follows.
    steps.remove(keys[1]);
    settle();
    let rows = steps.rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, keys[0]);
    assert_eq!(rows[0].1.op.path(), "steps[0].op");
    assert_eq!(form.errors().get("steps[0].op"), Some("unknown op"));
}

#[derive(Clone, Default, PartialEq, Debug, garde::Validate, Form)]
pub struct Basic {
    #[garde(length(min = 1))]
    pub user: String,
}

#[derive(Clone, PartialEq, Debug, garde::Validate, Form)]
pub enum Auth {
    Open,
    Basic(
        #[garde(dive)]
        #[form(nested)]
        Basic,
    ),
    Token {
        #[garde(length(min = 8))]
        token: String,
        #[garde(skip)]
        header: bool,
    },
    Note(#[garde(skip)] String),
}

#[derive(Clone, PartialEq, Debug, garde::Validate, Form)]
pub struct Source {
    #[garde(skip)]
    pub name: String,
    #[garde(dive)]
    #[form(nested)]
    pub auth: Auth,
}

thread_local! {
    static SOURCE: RefCell<Option<Form<Source>>> = const { RefCell::new(None) };
}

#[component]
fn SourceForm() -> View {
    let form = form(Source {
        name: "s".into(),
        auth: Auth::Basic(Basic { user: "ann".into() }),
    })
    .rules(|s: &Source| garde::Validate::validate(s).map_err(FieldErrors::from));
    SOURCE.with(|r| *r.borrow_mut() = Some(form));
    let auth = form.fields().auth;
    view! {
        <select id="kind" bind:value={auth.variant}>
            {AuthFields::<Source>::VARIANTS.iter().map(|v| view! {
                <option value={*v}>{*v}</option>
            }).collect::<View>()}
        </select>
        {auth.basic().map(|b| view! { <input id="user" bind:value={b.user}/> })}
        {auth.token().map(|t| view! { <input id="token" bind:value={t.token}/> })}
    }
}

#[test]
fn an_enum_field_switches_variant_and_binds_the_chosen_ones_fields() {
    let dom = MemDom::new();
    App::new(|| view! { <SourceForm/> })
        .mount_on(Rc::new(dom.clone()), dom.body())
        .keep();
    settle();
    let form = SOURCE.with(|r| r.borrow().expect("mounted"));
    let auth = form.fields().auth;
    assert_eq!(auth.variant.get(), "Basic");
    assert!(dom.find("id", "token").is_none());
    let user = auth.basic().unwrap().user;
    assert_eq!(user.path(), "auth[0].user");

    dom.input(dom.find("id", "user").unwrap(), "");
    settle();
    assert_eq!(
        form.errors().get("auth[0].user"),
        Some("length is lower than 1")
    );

    dom.input(dom.find("id", "kind").unwrap(), "Token");
    settle();
    assert!(dom.find("id", "user").is_none());
    assert!(auth.basic().is_none());
    assert_eq!(
        form.value().auth,
        Auth::Token {
            token: String::new(),
            header: false
        },
        "a new variant starts at its default"
    );
    let token = auth.token().unwrap().token;
    assert_eq!(token.path(), "auth.token");
    assert_eq!(
        form.errors().get("auth.token"),
        Some("length is lower than 8")
    );
    dom.input(dom.find("id", "token").unwrap(), "secret-token");
    settle();
    assert!(form.valid());

    auth.variant.set("Nope".into());
    assert_eq!(
        auth.variant.get(),
        "Token",
        "an unknown name changes nothing"
    );
    auth.variant.set("Note".into());
    assert_eq!(auth.note().unwrap().get(), "");
    assert!(auth.variant.dirty());
}
