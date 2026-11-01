//! The renderer against an in-memory document.

use std::rc::Rc;

use doxa::ui::dom::MemDom;
use doxa::ui::prelude::*;

fn mount<V: IntoView>(root: impl Fn() -> V + 'static) -> MemDom {
    let dom = MemDom::new();
    App::new(root).mount_on(Rc::new(dom.clone()), dom.body());
    dom
}

fn settle() {
    doxa::client::task::run_until_stalled();
}

#[component]
fn Counter(start: i32) -> View {
    let n = state(start);
    view! { <button on:click={move |_| n.update(|n| *n += 1)}>{n.get()}</button> }
}

#[test]
fn state_rerenders_in_place() {
    let dom = mount(|| view! { <Counter start={1}/> });
    let b = dom.find_tag("button").unwrap();
    dom.click(b);
    settle();
    assert_eq!(dom.text(b), "2");
    assert_eq!(
        dom.find_tag("button"),
        Some(b),
        "the same element is patched"
    );
}

thread_local! {
    static ORDER: std::cell::RefCell<Vec<u32>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[component]
fn Item(id: u32) -> View {
    view! { <li id={id.to_string()}>{id}</li> }
}

#[component]
fn List() -> View {
    let ids = ORDER.with(|o| o.borrow().clone());
    let tick = state(0);
    let _ = tick.get();
    view! {
        <button on:click={move |_| tick.update(|t| *t += 1)}>"x"</button>
        <ul>{ids.iter().map(|&id| view! { <Item key={id} id={id}/> }).collect::<View>()}</ul>
    }
}

#[test]
fn keyed_children_move_instead_of_being_recreated() {
    ORDER.with(|o| *o.borrow_mut() = vec![1, 2, 3]);
    let dom = mount(|| view! { <List/> });
    let three = dom.find("id", "3").unwrap();
    ORDER.with(|o| *o.borrow_mut() = vec![3, 1, 2]);
    dom.click(dom.find_tag("button").unwrap());
    settle();
    assert_eq!(dom.text(dom.find_tag("ul").unwrap()), "312");
    assert_eq!(dom.find("id", "3"), Some(three));
}

#[component]
fn Flaky(fail: bool) -> Result<View> {
    if fail {
        return Err(Thrown::msg("boom"));
    }
    Ok(view! { <p>"fine"</p> })
}

#[test]
fn catch_shows_its_fallback_for_a_child_error() {
    let dom = mount(|| {
        view! {
            <Catch fallback={|e: &Thrown| view! { <p class="err">{e.to_string()}</p> }}>
                <Flaky fail={true}/>
            </Catch>
        }
    });
    settle();
    assert_eq!(dom.text(dom.find("class", "err").unwrap()), "boom");
}

#[component]
fn Saver() -> View {
    let save = action(async |n: u32| {
        if n == 0 {
            return Err(Thrown::msg("zero"));
        }
        Ok(n)
    });
    view! {
        <button on:click={move |_| save.run(0)}>"save"</button>
        <span>{if save.pending() { "pending" } else { "idle" }}</span>
        {save.error().map(|e| view! { <em>{e.to_string()}</em> })}
    }
}

#[test]
fn an_action_reports_its_error_inline() {
    let dom = mount(|| view! { <Saver/> });
    dom.click(dom.find_tag("button").unwrap());
    settle();
    assert_eq!(dom.text(dom.find_tag("span").unwrap()), "idle");
    assert_eq!(dom.text(dom.find_tag("em").unwrap()), "zero");
}

#[component]
fn Conditional() -> View {
    let flip = state(false);
    if flip.get() {
        let _extra = state(0u8);
    }
    let _after = state(String::new());
    view! { <button on:click={move |_| flip.set(true)}>"flip"</button> }
}

#[test]
#[should_panic(expected = "hook order changed in <Conditional>")]
fn a_conditional_hook_panics_with_both_locations() {
    let dom = mount(|| view! { <Conditional/> });
    dom.click(dom.find_tag("button").unwrap());
    settle();
}

#[page("/things/{id}")]
fn Thing(id: u32, tab: Option<String>) -> View {
    view! {
        <p>
            {id}
            {tab.unwrap_or_default()}
        </p>
    }
}

#[test]
fn a_page_parses_its_path_and_query() {
    assert_eq!(Thing::route(7).as_str(), "/things/7");
    let s = doxa::ui::match_path(Thing::PATH, "/things/7?tab=info").unwrap();
    assert!(
        <Thing as Page>::parse(&s).is_some_and(|p| p.id == 7 && p.tab.as_deref() == Some("info"))
    );
    let bad = doxa::ui::match_path(Thing::PATH, "/things/seven").unwrap();
    assert!(<Thing as Page>::parse(&bad).is_none());
}

thread_local! {
    static LIFE: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    static DOC: std::cell::RefCell<Option<MemDom>> = const { std::cell::RefCell::new(None) };
}

#[component]
fn Tracked() -> View {
    let on = state(true);
    let n = state(0);
    let probe = doxa::ui::el("p").lifecycle(|phase, node| {
        let attached = DOC.with(|d| d.borrow().as_ref().unwrap().find_tag("p")) == Some(node.id());
        LIFE.with(|l| l.borrow_mut().push(format!("{phase:?} {attached}")));
    });
    view! {
        <button id="n" on:click={move |_| n.update(|n| *n += 1)}>{n.get()}</button>
        <button id="off" on:click={move |_| on.set(false)}>"off"</button>
        <div>{on.get().then_some(probe)}</div>
    }
}

#[test]
fn lifecycle_sees_the_node_attached_until_it_is_removed() {
    let dom = MemDom::new();
    DOC.with(|d| *d.borrow_mut() = Some(dom.clone()));
    App::new(|| view! { <Tracked/> }).mount_on(Rc::new(dom.clone()), dom.body());
    dom.click(dom.find("id", "n").unwrap());
    settle();
    dom.click(dom.find("id", "off").unwrap());
    settle();
    assert_eq!(
        LIFE.with(|l| l.take()),
        ["Mounted true", "Patched true", "Unmounting true"]
    );
}
