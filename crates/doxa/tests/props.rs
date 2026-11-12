//! What a tag can pass a prop: bare text and values, and closures typed by the prop.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use doxa::ui::dom::{MemDom, MemEvent};
use doxa::ui::prelude::*;

fn mount<V: IntoView>(root: impl Fn() -> V + 'static) -> MemDom {
    let dom = MemDom::new();
    App::new(root)
        .mount_on(Rc::new(dom.clone()), dom.body())
        .keep();
    settle();
    dom
}

fn settle() {
    doxa::client::task::run_until_stalled();
}

#[component]
fn Labelled(
    label: View,
    #[prop(default)] hint: Option<View>,
    #[prop(default)] unit: Option<String>,
    #[prop(default)] count: Option<usize>,
) -> View {
    let hinted = hint.is_some();
    view! {
        <p>
            {label}
            {hint}
            {unit}
            {count}
            {hinted.then_some("!")}
        </p>
    }
}

#[test]
fn a_view_prop_takes_any_view_value() {
    let dom = mount(|| {
        view! {
            <Labelled label="text"/>
            <Labelled label={String::from("owned")}/>
            <Labelled label={7u32}/>
            <Labelled label={view! { <b>"tag"</b> }}/>
        }
    });
    let text = dom.text(dom.body());
    for shown in ["text", "owned", "7", "tag"] {
        assert!(text.contains(shown), "{text}");
    }
}

#[test]
fn an_optional_view_prop_is_absent_only_for_none() {
    let dom = mount(|| {
        let nothing: Option<&str> = None;
        view! {
            <Labelled label="a" hint="b"/>
            <Labelled label="c" hint={Some("d")}/>
            <Labelled label="e" hint={nothing}/>
            <Labelled label="f" hint={None}/>
        }
    });
    assert_eq!(dom.text(dom.body()), "ab!cd!ef");
}

#[test]
fn an_optional_prop_takes_the_value_or_an_option_of_it() {
    let dom = mount(|| {
        let maybe = Some(String::from("c"));
        view! {
            <Labelled label="" unit="a"/>
            <Labelled label="" unit={String::from("b")}/>
            <Labelled label="" unit={maybe}/>
            <Labelled label="" unit={Some("d")}/>
            <Labelled label="" unit={None}/>
            <Labelled label="" count={1}/>
            <Labelled label="" count={Some(2)}/>
            <Labelled label="" count={None}/>
        }
    });
    assert_eq!(dom.text(dom.body()), "abcd12");
}

thread_local! {
    static SEEN: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

fn seen(what: impl Into<String>) {
    SEEN.with(|s| s.borrow_mut().push(what.into()));
}

fn take_seen() -> Vec<String> {
    SEEN.with(|s| s.take())
}

#[component]
fn Fires(
    #[prop(default)] on_two: Callback<dyn Fn(u32, String)>,
    #[prop(default)] on_none: Callback,
    #[prop(default)] on_maybe: Option<impl Fn(String)>,
    #[prop(default)] on_fail: Callback<dyn Fn(u32)>,
) -> View {
    let (two, none) = (on_two.clone(), on_none.clone());
    view! {
        <button
            id="fire"
            on:click={move || {
                two(1, "x".to_owned());
                none();
                if let Some(f) = &on_maybe {
                    f("m".to_owned());
                }
                on_fail(9);
            }}
        />
    }
}

fn click(dom: &MemDom) {
    let button = dom.find("id", "fire").expect("button");
    dom.dispatch(button, "click", MemEvent::default());
    settle();
}

#[test]
fn a_closure_is_typed_by_the_prop() {
    let dom = mount(|| {
        view! {
            <Fires
                on_two={|n, s| seen(format!("{}{}", n.count_ones(), s.len()))}
                on_none={|| seen("none")}
                on_maybe={|s| seen(s.to_uppercase())}
            />
        }
    });
    click(&dom);
    assert_eq!(take_seen(), ["11", "none", "M"]);
}

#[test]
fn a_closure_may_ignore_what_the_prop_passes() {
    let dom = mount(|| view! { <Fires on_two={|| seen("ignored")}/> });
    click(&dom);
    assert_eq!(take_seen(), ["ignored"]);
}

#[test]
fn a_block_ending_in_a_closure_is_typed_too() {
    let dom = mount(|| {
        view! {
            <Fires
                on_two={{
                    let prefix = String::from("p");
                    move |n, s| seen(format!("{prefix}{n}{}", s.len()))
                }}
            />
        }
    });
    click(&dom);
    assert_eq!(take_seen(), ["p11"]);
}

fn named(n: u32, s: String) {
    seen(format!("named{n}{s}"));
}

#[component]
fn Forwards(on_two: impl Fn(u32, String)) -> View {
    view! { <Fires on_two={on_two}/> }
}

#[test]
fn a_named_function_and_a_held_callback_pass_as_they_are() {
    let dom = mount(|| view! { <Forwards on_two={named}/> });
    click(&dom);
    assert_eq!(take_seen(), ["named1x"]);
}

#[component]
fn Failing() -> View {
    view! {
        <Fires
            on_fail={async |n| {
                seen(format!("async{}", n.count_ones()));
                Err(Thrown::msg("nope"))
            }}
        />
    }
}

#[test]
fn an_async_closure_runs_and_its_error_reaches_the_catch_around_its_writer() {
    let dom = mount(|| {
        view! {
            <Catch fallback={|e| view! { <p>{e.to_string()}</p> }}>
                <Failing/>
            </Catch>
        }
    });
    click(&dom);
    assert_eq!(take_seen(), ["async2"]);
    assert!(dom.text(dom.body()).contains("nope"));
}

#[test]
fn an_async_closure_may_return_nothing_and_ignore_its_arguments() {
    let dom =
        mount(|| view! { <Fires on_none={async || seen("a")} on_fail={async || seen("b")}/> });
    click(&dom);
    assert_eq!(take_seen(), ["a", "b"]);
}

#[component]
async fn Returns(
    cell: impl Fn(&String) -> View,
    pick: Option<impl Fn(u32, &str) -> bool>,
    load: impl AsyncFn(u32) -> String,
) -> View {
    let picked = pick.is_some_and(|f| f(1, "x"));
    let loaded = load(2).await;
    view! {
        <p>
            {cell(&"cell".to_owned())}
            {picked.then_some("|picked|")}
            {loaded}
        </p>
    }
}

#[test]
fn a_callback_can_borrow_return_and_await() {
    let dom = mount(|| {
        view! {
            <Returns
                cell={|s| s.to_uppercase().into_view()}
                pick={|n, s| n == 1 && s == "x"}
                load={async |n| format!("loaded{n}")}
            />
        }
    });
    assert_eq!(dom.text(dom.body()), "CELL|picked|loaded2");
}

#[component]
fn Generic<T: Clone + 'static>(row: T, render: impl Fn(&T) -> String) -> View {
    view! { <p>{render(&row)}</p> }
}

#[test]
fn a_callback_over_a_components_parameter_infers_it() {
    let dom = mount(|| view! { <Generic row={5u8} render={|n| n.to_string()}/> });
    assert_eq!(dom.text(dom.body()), "5");
}

#[component]
fn Stable(hits: Rc<Cell<u32>>) -> View {
    let count = state(0u32);
    let n = count.get();
    let hits_now = hits.clone();
    let save = callback(move |by: u32| hits_now.set(n + by));
    let held = reference(save);
    view! {
        <button
            id="fire"
            on:click={move || {
                save.call(10);
                count.update(|c| *c += 1);
            }}
        />
        <button
            id="held"
            on:click={move || {
                if let Some(save) = held.get() {
                    save.call(1000);
                }
            }}
        />
    }
}

#[test]
fn a_stable_callback_is_copy_and_runs_the_latest_closure() {
    let hits = Rc::new(Cell::new(0));
    let shared = hits.clone();
    let dom = mount(move || view! { <Stable hits={shared.clone()}/> });
    click(&dom);
    assert_eq!(hits.get(), 10);
    click(&dom);
    assert_eq!(hits.get(), 11);
    let held = dom.find("id", "held").expect("button");
    dom.dispatch(held, "click", MemEvent::default());
    settle();
    assert_eq!(
        hits.get(),
        1002,
        "a handle from the first render sees the latest"
    );
}

#[component]
fn Identity(renders: Rc<RefCell<Vec<bool>>>) -> View {
    let bump = state(0u32);
    let stable = callback(move || {});
    let as_prop: Callback = stable.into();
    let last = reference(as_prop.clone());
    renders
        .borrow_mut()
        .push(last.get().is_some_and(|l| l == as_prop));
    last.set(as_prop);
    view! { <button id="fire" on:click={move || bump.update(|b| *b += 1)}/> }
}

#[test]
fn a_stable_callback_keeps_its_identity_as_a_prop() {
    let renders = Rc::new(RefCell::new(Vec::new()));
    let shared = renders.clone();
    let dom = mount(move || view! { <Identity renders={shared.clone()}/> });
    click(&dom);
    assert_eq!(&*renders.borrow(), &[true, true]);
}

#[component]
fn Latest(seen_by_effect: Rc<RefCell<Vec<u32>>>) -> View {
    let count = state(0u32);
    let now = latest(count.get());
    effect((), async move |_| {
        seen_by_effect.borrow_mut().push(now.get().unwrap_or(99));
    });
    let renders = reference(0u32);
    renders.update(|r| *r += 1);
    view! {
        <button id="fire" on:click={move || count.update(|c| *c += 1)}/>
        <p>{renders.get()}</p>
    }
}

#[test]
fn a_reference_keeps_its_value_without_rerendering() {
    let seen = Rc::new(RefCell::new(Vec::new()));
    let shared = seen.clone();
    let dom = mount(move || view! { <Latest seen_by_effect={shared.clone()}/> });
    assert_eq!(dom.text(dom.body()), "1");
    click(&dom);
    assert_eq!(dom.text(dom.body()), "2");
    assert_eq!(&*seen.borrow(), &[0]);
}

#[component]
fn Effects(log: Rc<RefCell<Vec<&'static str>>>) -> View {
    let (one, two) = (log.clone(), log);
    effect((), async move |_| one.borrow_mut().push("unit"));
    effect((), async move |_| {
        two.borrow_mut().push("result");
        Ok(())
    });
    View::empty()
}

#[test]
fn an_effect_returns_nothing_or_a_result() {
    let log = Rc::new(RefCell::new(Vec::new()));
    let shared = log.clone();
    mount(move || view! { <Effects log={shared.clone()}/> });
    assert_eq!(&*log.borrow(), &["unit", "result"]);
}

#[component]
fn Loaded(id: u32, fetched: Rc<Cell<u32>>, fails: Rc<Cell<Option<Thrown>>>) -> View {
    let row = resource(&id, async move |id: &u32| {
        fetched.set(fetched.get() + 1);
        match fails.take() {
            Some(e) => Err(e),
            None => Ok(format!("row{id}")),
        }
    });
    let shown = match row.get() {
        Load::Loading => "loading".to_owned(),
        Load::Ready(r) => r,
        Load::Forbidden => "forbidden".to_owned(),
        Load::Failed(why) => format!("failed {why}"),
    };
    view! { <button id="fire" on:click={move || row.refetch()}>{shown}</button> }
}

#[test]
fn a_resource_loads_refetches_and_keeps_its_data_when_a_refresh_fails() {
    let (fetched, fails) = (Rc::new(Cell::new(0)), Rc::new(Cell::new(None)));
    let (f, e) = (fetched.clone(), fails.clone());
    let dom = mount(move || view! { <Loaded id={1} fetched={f.clone()} fails={e.clone()}/> });
    assert_eq!(dom.text(dom.body()), "row1");
    fails.set(Some(Thrown::msg("offline")));
    click(&dom);
    assert_eq!(
        dom.text(dom.body()),
        "row1",
        "a failed refresh keeps the data"
    );
    assert_eq!(fetched.get(), 2);
    click(&dom);
    assert_eq!(fetched.get(), 3);
}

#[test]
fn a_first_failure_says_why() {
    let (fetched, fails) = (
        Rc::new(Cell::new(0)),
        Rc::new(Cell::new(Some(Thrown::msg("offline")))),
    );
    let (f, e) = (fetched, fails);
    let dom = mount(move || view! { <Loaded id={1} fetched={f.clone()} fails={e.clone()}/> });
    assert_eq!(dom.text(dom.body()), "failed offline");
}

#[test]
fn a_403_replaces_data_a_refresh_would_otherwise_keep() {
    use doxa::client::{Fetch, NoError};
    use doxa::ui::Load;
    let forbidden = Fetch::<NoError>::Forbidden(None);
    assert_eq!(Load::Ready(1).after_error(&forbidden), Load::Forbidden);
}

#[component]
fn Scrolled(seen_at: Rc<Cell<f64>>) -> View {
    let list = node_ref();
    view! {
        <ul ref={list} id="list">
            <li class="row" data-id="a">
                <input id="field"/>
            </li>
            <li class="row active" data-id="b"/>
        </ul>
        <button
            id="fire"
            on:click={move |e: Event| {
                let list = list.get().expect("mounted");
                assert!(!e.target().expect("target").is_editable());
                assert_eq!(list.query_all(".row").len(), 2);
                let active = list.query("li.active[data-id=\"b\"]").expect("active");
                assert_eq!(active.attr("data-id").as_deref(), Some("b"));
                active.reveal();
                let field = list.query("[data-id=a] input").expect("field");
                assert!(field.is_editable());
                assert_eq!(field.closest("ul").map(|u| u.attr("id")), Some(Some("list".to_owned())));
                assert!(field.closest("button").is_none());
                list.scroll_to_end(false);
                seen_at.set(list.scroll().top);
            }}
        />
    }
}

#[test]
fn elements_query_scroll_and_reveal_without_touching_the_browser() {
    use doxa::ui::Scroll;
    let at = Rc::new(Cell::new(0.0));
    let shared = at.clone();
    let dom = mount(move || view! { <Scrolled seen_at={shared.clone()}/> });
    let list = dom.find("id", "list").expect("list");
    dom.set_scroll(
        list,
        Scroll {
            top: 0.0,
            height: 900.0,
            client_height: 100.0,
        },
    );
    click(&dom);
    assert_eq!(at.get(), 900.0);
    assert_eq!(dom.revealed().len(), 1);
}

#[component]
fn Facts(rows: Vec<(View, View)>, #[prop(default)] notes: Vec<(String, View, u32)>) -> View {
    view! {
        <dl>
            {rows.into_iter().map(|(k, v)| view! {
                <dt>{k}</dt>
                <dd>{v}</dd>
            }).collect::<View>()}
        </dl>
        <ul>
            {notes.into_iter().map(|(a, b, n)| view! { <li>{(a, b, n)}</li> }).collect::<View>()}
        </ul>
    }
}

#[test]
fn a_list_prop_takes_anything_into_view_in_its_view_places() {
    let dom = mount(|| {
        view! {
            <Facts
                rows={[("Id", view! { <b>"m-1"</b> }), ("Rows", "1,247".into_view())]}
                notes={vec![("a", 1, 2)]}
            />
        }
    });
    assert_eq!(
        dom.html(dom.find_tag("dl").unwrap()),
        "<dl><dt>Id</dt><dd><b>m-1</b></dd><dt>Rows</dt><dd>1,247</dd></dl>"
    );
    assert_eq!(dom.text(dom.find_tag("ul").unwrap()), "a12");
}

#[component]
fn Shelf(children: View) -> View {
    view! { <p>{children}</p> }
}

#[test]
fn children_set_directly_take_anything_into_view() {
    let dom = mount(|| {
        doxa::ui::__private::comp_for(Shelf::props().children(("x", 1, ["y", "z"])).build())
    });
    assert_eq!(dom.text(dom.find_tag("p").unwrap()), "x1yz");
}
