//! The renderer against an in-memory document.

use std::rc::Rc;

use doxa::client::transport::MockTransport;
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

#[page("/gizmos/{name}")]
fn Gizmo(name: String) -> View {
    let editing = state(false);
    let draft = state(name.clone());
    view! {
        <h1>{name}</h1>
        <button on:click={move |_| editing.set(true)}>"rename"</button>
        {editing.get().then(|| view! { <input bind:value={draft}/> })}
    }
}

#[test]
fn a_page_remounts_when_its_params_change() {
    let dom = MemDom::new();
    App::new(Router::new().page::<Gizmo>()).mount_on(Rc::new(dom.clone()), dom.body());
    navigate("/gizmos/cog");
    settle();
    dom.click(dom.find_tag("button").unwrap());
    settle();
    assert!(dom.find_tag("input").is_some());

    navigate("/gizmos/gear");
    settle();
    assert_eq!(dom.text(dom.find_tag("h1").unwrap()), "gear");
    assert!(dom.find_tag("input").is_none(), "cog's open form is gone");
}

#[page("/shop/{store}")]
fn Shop(store: String) -> View {
    let visits = state(0);
    view! {
        <h2>{store}</h2>
        <button id="visit" on:click={move |_| visits.update(|v| *v += 1)}>{visits.get()}</button>
        <main>
            <Outlet/>
        </main>
    }
}

#[page("/shop/{store}")]
fn ShopHome(store: String) -> View {
    view! { <p>{format!("home of {store}")}</p> }
}

#[page("/shop/{store}/items")]
fn Items(store: String) -> View {
    view! { <p>{format!("items of {store}")}</p> }
}

#[page("/shop/{store}/admin")]
fn Admin(store: String) -> View {
    view! {
        <h3>{format!("admin of {store}")}</h3>
        <section>
            <Outlet/>
        </section>
    }
}

#[page("/shop/{store}/admin/users")]
fn Users(store: String) -> View {
    view! { <p>{format!("users of {store}")}</p> }
}

fn shop() -> MemDom {
    let dom = MemDom::new();
    let router = Router::new()
        .layout::<Shop>(|r| {
            r.page::<ShopHome>()
                .page::<Items>()
                .layout::<Admin>(|r| r.page::<Users>())
        })
        .not_found(|| view! { <p>"no such page"</p> });
    App::new(router).mount_on(Rc::new(dom.clone()), dom.body());
    dom
}

#[test]
fn a_layout_stays_mounted_while_its_pages_change() {
    let dom = shop();
    navigate("/shop/acme");
    settle();
    assert_eq!(dom.text(dom.find_tag("main").unwrap()), "home of acme");
    let visit = dom.find("id", "visit").unwrap();
    dom.click(visit);
    settle();

    navigate("/shop/acme/items");
    settle();
    assert_eq!(dom.text(dom.find_tag("main").unwrap()), "items of acme");
    assert_eq!(dom.find("id", "visit"), Some(visit), "the same node");
    assert_eq!(dom.text(visit), "1", "and the same state");
}

#[test]
fn a_layout_remounts_when_its_own_params_change() {
    let dom = shop();
    navigate("/shop/acme/items");
    settle();
    dom.click(dom.find("id", "visit").unwrap());
    settle();

    navigate("/shop/zenith/items");
    settle();
    assert_eq!(dom.text(dom.find_tag("h2").unwrap()), "zenith");
    assert_eq!(dom.text(dom.find("id", "visit").unwrap()), "0");
}

#[test]
fn layouts_nest() {
    let dom = shop();
    navigate("/shop/acme/admin/users");
    settle();
    assert_eq!(dom.text(dom.find_tag("h2").unwrap()), "acme");
    assert_eq!(dom.text(dom.find_tag("h3").unwrap()), "admin of acme");
    assert_eq!(dom.text(dom.find_tag("section").unwrap()), "users of acme");
}

#[test]
fn an_unmatched_path_under_a_layout_is_not_found() {
    let dom = shop();
    navigate("/shop/acme/nope");
    settle();
    assert!(dom.find_tag("h2").is_none());
    assert_eq!(dom.text(dom.find_tag("p").unwrap()), "no such page");
}

#[test]
fn an_outlet_outside_a_layout_is_empty() {
    let dom = mount(|| view! {
        <div>
            <Outlet/>
        </div>
    });
    assert_eq!(dom.text(dom.find_tag("div").unwrap()), "");
}

#[test]
#[should_panic(expected = "`/gizmos/{name}` isn't under the layout `Shop` at `/shop/{store}`")]
fn a_page_outside_its_layout_is_refused() {
    let _ = Router::new().layout::<Shop>(|r| r.page::<Gizmo>());
}

struct Sidebar;

impl Plugin for Sidebar {
    fn slots(&self, slots: &mut Slots) {
        slots.fill("side", || view! { <i>"x"</i> });
    }
}

#[test]
fn a_slot_shows_each_fill_once_however_often_apps_mount() {
    for _ in 0..2 {
        let dom = MemDom::new();
        App::new(|| {
            view! {
                <aside>
                    <Slot name="side"/>
                </aside>
            }
        })
        .plugin(Sidebar)
        .mount_on(Rc::new(dom.clone()), dom.body());
        assert_eq!(dom.text(dom.find_tag("aside").unwrap()), "x");
    }
}

static VISITS: Singleton<u32> = Singleton::new(|| 0);

mod probes {
    use doxa::client::Probe;
    use doxa::wire::{Method, RouteSpec};

    pub static GUARDED: RouteSpec = RouteSpec {
        method: Method::Get,
        path: "/guarded",
        operation_id: "guarded",
        entities: &[],
        dry_run: true,
    };
    pub static OTHER: RouteSpec = RouteSpec {
        method: Method::Get,
        path: "/other",
        operation_id: "other",
        entities: &[],
        dry_run: true,
    };
    pub static OPAQUE: RouteSpec = RouteSpec {
        method: Method::Get,
        path: "/opaque",
        operation_id: "opaque",
        entities: &[],
        dry_run: false,
    };

    pub mod guarded {
        pub fn can() -> super::Probe {
            super::Probe::new(&super::GUARDED)
        }
    }

    pub mod other {
        pub fn can() -> super::Probe {
            super::Probe::new(&super::OTHER)
        }
    }

    pub mod opaque {
        pub fn can() -> super::Probe {
            super::Probe::new(&super::OPAQUE)
        }
    }
}

fn answer(mock: &MockTransport, status: u16, session: &str) {
    mock.respond(
        status,
        vec![
            (doxa::wire::SESSION_HEADER.into(), session.into()),
            (
                doxa::wire::DRY_RUN_HEADER.into(),
                doxa::wire::DRY_RUN_OK.into(),
            ),
        ],
        Vec::new(),
    );
}

fn mount_with(mock: &MockTransport, root: impl Fn() -> View + 'static) -> MemDom {
    let dom = MemDom::new();
    App::new(root)
        .config(ClientConfig::default().transport(mock.clone()))
        .mount_on(Rc::new(dom.clone()), dom.body());
    dom
}

#[test]
fn singletons_reset_with_the_session_of_the_client_mounted_last() {
    let _ = mount_with(&MockTransport::new(), View::empty);
    VISITS.set(1);

    let mock = MockTransport::new();
    let _ = mount_with(&mock, View::empty);
    VISITS.set(2);
    answer(&mock, 204, "a");
    answer(&mock, 204, "b");
    doxa::client::task::block_on(async {
        let _ = probes::guarded::can().await;
        let _ = probes::other::can().await;
    });
    assert_eq!(VISITS.get(), 0, "a new session starts the singleton over");
}

#[test]
fn can_shows_children_fallback_or_unknown() {
    let mock = MockTransport::new();
    answer(&mock, 403, "s");
    let dom = mount_with(&mock, || {
        view! {
            <p id="denied">
                <Can route={probes::guarded} fallback={"no"} unknown={"?"}>"yes"</Can>
            </p>
            <p id="unknown">
                <Can route={probes::opaque} fallback={"no"} unknown={"?"}>"yes"</Can>
            </p>
        }
    });
    settle();
    assert_eq!(dom.text(dom.find("id", "denied").unwrap()), "no");
    assert_eq!(dom.text(dom.find("id", "unknown").unwrap()), "?");
}

#[test]
fn can_is_recognised_by_its_path() {
    let mock = MockTransport::new();
    answer(&mock, 204, "s");
    let dom = mount_with(&mock, || {
        view! {
            <p>
                <doxa::ui::Can route={probes::guarded}>"yes"</doxa::ui::Can>
            </p>
        }
    });
    settle();
    assert_eq!(dom.text(dom.find_tag("p").unwrap()), "yes");
}

thread_local! {
    /// 0 renders normally, 1 waits forever, 2 fails.
    static MODE: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    static RAN: std::cell::RefCell<Vec<u32>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[component]
async fn Effected() -> Result<View> {
    let n = state(0u32);
    let tick = state(0u32);
    let _ = tick.get();
    effect(n, async |n: &u32| {
        RAN.with(|r| r.borrow_mut().push(*n));
        Ok(())
    });
    match MODE.with(|m| m.get()) {
        1 => std::future::pending::<()>().await,
        2 => return Err(Thrown::msg("render failed")),
        _ => {}
    }
    Ok(view! {
        <button id="n" on:click={move |_| n.set(1)}>"n"</button>
        <button id="tick" on:click={move |_| tick.update(|t| *t += 1)}>"tick"</button>
    })
}

fn effect_survives_an_uncommitted_render(mode: u8) {
    MODE.with(|m| m.set(0));
    RAN.with(|r| r.take());
    let dom = mount(|| view! { <Effected/> });
    settle();
    MODE.with(|m| m.set(mode));
    dom.click(dom.find("id", "n").unwrap());
    settle();
    MODE.with(|m| m.set(0));
    dom.click(dom.find("id", "tick").unwrap());
    settle();
    assert_eq!(RAN.with(|r| r.take()), [0, 1]);
}

#[test]
fn an_effect_runs_after_a_cancelled_render() {
    effect_survives_an_uncommitted_render(1);
}

#[test]
fn an_effect_runs_after_a_failed_render() {
    effect_survives_an_uncommitted_render(2);
}

#[derive(Clone)]
struct Label(&'static str);

#[component]
async fn Provider() -> Result<View> {
    let tick = state(0u32);
    let _ = tick.get();
    match MODE.with(|m| m.get()) {
        1 => std::future::pending::<()>().await,
        2 => return Err(Thrown::msg("render failed")),
        _ => {}
    }
    provide(Label("ctx"));
    Ok(view! {
        <button id="tick" on:click={move |_| tick.update(|t| *t += 1)}>"tick"</button>
        <Reader/>
    })
}

#[component]
fn Reader() -> View {
    let n = state(0u32);
    let label = context::<Label>().0;
    view! {
        <b on:click={move |_| n.update(|n| *n += 1)}>
            {label}
            {n.get()}
        </b>
    }
}

fn context_survives_an_uncommitted_render(mode: u8) {
    MODE.with(|m| m.set(0));
    let dom = mount(|| view! { <Provider/> });
    MODE.with(|m| m.set(mode));
    dom.click(dom.find("id", "tick").unwrap());
    settle();
    dom.click(dom.find_tag("b").unwrap());
    settle();
    assert_eq!(dom.text(dom.find_tag("b").unwrap()), "ctx1");
}

#[test]
fn context_survives_a_cancelled_render() {
    context_survives_an_uncommitted_render(1);
}

#[test]
fn context_survives_a_failed_render() {
    context_survives_an_uncommitted_render(2);
}

#[component]
fn Tally() -> View {
    let n = state(0u32);
    view! { <b on:click={move |_| n.update(|n| *n += 1)}>{n.get()}</b> }
}

#[component]
fn MixedList() -> View {
    let ids = ORDER.with(|o| o.borrow().clone());
    let tick = state(0);
    let _ = tick.get();
    view! {
        <div>
            <input/>
            {ids.iter().map(|&id| view! { <Item key={id} id={id}/> }).collect::<View>()}
            <Tally/>
            <button on:click={move |_| tick.update(|t| *t += 1)}>"x"</button>
        </div>
    }
}

#[test]
fn unkeyed_siblings_of_a_keyed_list_are_kept() {
    ORDER.with(|o| *o.borrow_mut() = vec![1, 2]);
    let dom = mount(|| view! { <MixedList/> });
    let input = dom.find_tag("input").unwrap();
    dom.click(dom.find_tag("b").unwrap());
    settle();
    ORDER.with(|o| *o.borrow_mut() = vec![2, 1, 3]);
    dom.click(dom.find_tag("button").unwrap());
    settle();
    assert_eq!(dom.find_tag("input"), Some(input));
    assert_eq!(
        dom.text(dom.find_tag("b").unwrap()),
        "1",
        "Tally kept its state"
    );
    assert_eq!(dom.text(dom.find_tag("div").unwrap()), "2131x");
}

#[page("/plain")]
fn Plain() -> View {
    view! { <Link to={Target::route()}>"go"</Link> }
}

#[page("/target")]
fn Target() -> View {
    view! { <p>"target"</p> }
}

#[test]
fn a_modified_link_click_is_left_to_the_browser() {
    use doxa::ui::dom::MemEvent;
    let dom = MemDom::new();
    App::new(Router::new().page::<Plain>().page::<Target>())
        .mount_on(Rc::new(dom.clone()), dom.body());
    navigate("/plain");
    settle();
    let a = dom.find_tag("a").unwrap();
    let modified = [
        MemEvent {
            ctrl_key: true,
            ..MemEvent::default()
        },
        MemEvent {
            meta_key: true,
            ..MemEvent::default()
        },
        MemEvent {
            shift_key: true,
            ..MemEvent::default()
        },
        MemEvent {
            alt_key: true,
            ..MemEvent::default()
        },
        MemEvent {
            button: 1,
            ..MemEvent::default()
        },
    ];
    for ev in modified {
        assert!(dom.dispatch(a, "click", ev), "default not prevented");
        settle();
        assert!(dom.find_tag("p").is_none(), "did not navigate");
    }
    assert!(!dom.click(a), "a plain click is handled");
    settle();
    assert_eq!(dom.text(dom.find_tag("p").unwrap()), "target");
}

const LIGHT: Theme = Theme::new("light", &[("--bg", "white"), ("--fg", "black")]);
const DIM: Theme = Theme::new("dim", &[("--bg", "grey")]);

#[test]
fn a_theme_sets_only_its_own_variables() {
    let dom = MemDom::new();
    doxa::ui::dom::Dom::set_attr(&dom, dom.body(), "style", "color: red;");
    App::new(View::empty)
        .theme(LIGHT)
        .mount_on(Rc::new(dom.clone()), dom.body());
    assert_eq!(
        dom.attr(dom.body(), "style").as_deref(),
        Some("color: red; --bg: white; --fg: black;")
    );
    set_theme(DIM);
    assert_eq!(
        dom.attr(dom.body(), "style").as_deref(),
        Some("color: red; --bg: grey;")
    );
}
