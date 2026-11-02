//! Redirects, guards, transitions, query edits, blocking and titles, against a `MemDom`.

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use doxa::ui::block_navigation;
use doxa::ui::dom::MemDom;
use doxa::ui::prelude::*;

fn mount(router: Router) -> MemDom {
    let dom = MemDom::new();
    App::new(router)
        .mount_on(Rc::new(dom.clone()), dom.body())
        .keep();
    settle();
    dom
}

fn settle() {
    doxa::client::task::run_until_stalled();
}

fn here() -> String {
    doxa::ui::location()
}

#[page("/home")]
fn HomePage() -> View {
    title("Home");
    view! { <p>"home"</p> }
}

#[page("/sign-in")]
fn SignInPage() -> View {
    view! { <p>"sign in"</p> }
}

#[page("/orders")]
fn OrdersPage() -> View {
    view! { <p>"orders"</p> }
}

#[test]
fn a_redirect_replaces_the_url_it_matches() {
    let dom = mount(
        Router::new()
            .redirect("/", HomePage::route())
            .page::<HomePage>(),
    );
    assert_eq!(here(), "/home");
    assert_eq!(dom.text(dom.body()), "home");
}

thread_local! {
    static SIGNED_IN: Cell<bool> = const { Cell::new(false) };
}

#[test]
fn a_guard_sends_a_navigation_elsewhere_and_shows_it_pending() {
    let router = Router::new().layout::<Shell>(|r| {
        r.page::<SignInPage>().layout::<OrdersArea>(|r| {
            r.guard(async |_| {
                sleep(Duration::from_secs(1)).await;
                (!SIGNED_IN.get()).then(SignInPage::route)
            })
            .page::<OrdersPage>()
        })
    });
    let dom = mount(router);
    navigate(SignInPage::route());
    settle();
    navigate(OrdersPage::route());
    settle();
    assert_eq!(
        dom.text(dom.body()),
        "nav pendingsign in",
        "the guard is still thinking"
    );
    dom.advance(Duration::from_secs(1));
    assert_eq!(here(), "/sign-in");
    assert_eq!(dom.text(dom.body()), "sign in");
    SIGNED_IN.set(true);
    navigate(OrdersPage::route());
    settle();
    dom.advance(Duration::from_secs(1));
    assert_eq!(dom.text(dom.body()), "orders");
}

/// Shows navigation state above every page.
#[page("/")]
fn Shell() -> View {
    let nav = navigation();
    view! {
        {nav.pending().then(|| view! { <i>"nav pending"</i> })}
        <Outlet/>
    }
}

#[page("/orders")]
fn OrdersArea() -> View {
    view! { <Outlet/> }
}

#[page("/old")]
async fn OldPage() -> Result<View> {
    Err(redirect(HomePage::route()))
}

/// Catches whatever its pages throw.
#[page("/")]
fn Guarded() -> View {
    view! {
        <Catch fallback={|e: &Thrown| view! { <p class="err">{e.to_string()}</p> }}>
            <Outlet/>
        </Catch>
    }
}

#[test]
fn a_page_redirect_beats_the_nearest_catch() {
    let dom = mount(Router::new().layout::<Guarded>(|r| r.page::<OldPage>().page::<HomePage>()));
    navigate(OldPage::route());
    settle();
    assert_eq!(here(), "/home");
    assert_eq!(dom.text(dom.body()), "home");
    assert!(dom.find("class", "err").is_none());
}

#[page("/slow", load = |_| sleep(Duration::from_secs(2)))]
fn SlowPage() -> View {
    view! { <p>"slow"</p> }
}

#[test]
fn keep_previous_holds_the_old_page_until_the_next_loads() {
    let dom = mount(
        Router::new()
            .page::<HomePage>()
            .page::<SlowPage>()
            .transitions(Keep::Previous),
    );
    navigate(HomePage::route());
    settle();
    assert_eq!(dom.text(dom.body()), "home");
    navigate(SlowPage::route());
    settle();
    dom.advance(Duration::from_secs(1));
    assert_eq!(dom.text(dom.body()), "home");
    assert_eq!(here(), "/home");
    dom.advance(Duration::from_secs(1));
    assert_eq!(dom.text(dom.body()), "slow");
}

#[test]
fn set_query_edits_the_current_url() {
    let _dom = mount(Router::new().page::<OrdersPage>());
    navigate("/orders?page=2&q=x");
    settle();
    set_query(|q| q.set("tab", "lines").remove("page"));
    settle();
    assert_eq!(here(), "/orders?q=x&tab=lines");
}

#[page("/editor")]
fn EditorPage() -> View {
    let dirty = state(true);
    block_navigation(dirty.get(), "Discard unsaved changes?");
    view! { <button on:click={move |_| dirty.set(false)}>"save"</button> }
}

#[test]
fn block_navigation_asks_before_leaving() {
    let dom = mount(Router::new().page::<EditorPage>().page::<HomePage>());
    navigate(EditorPage::route());
    settle();
    dom.answer_confirm(false);
    navigate(HomePage::route());
    settle();
    assert_eq!(here(), "/editor");
    assert_eq!(dom.confirms(), ["Discard unsaved changes?"]);
    dom.click(dom.find_tag("button").unwrap());
    settle();
    navigate(HomePage::route());
    settle();
    assert_eq!(here(), "/home");
    assert!(dom.confirms().is_empty(), "nothing to ask once saved");
}

#[component]
fn Detail() -> View {
    title("Order 7 · Home");
    view! { <b>"7"</b> }
}

#[page("/titled")]
fn TitledPage() -> View {
    title("Orders");
    let open = state(true);
    view! {
        <button on:click={move |_| open.set(false)}>"close"</button>
        {open.get().then(|| view! { <Detail/> })}
    }
}

#[test]
fn the_deepest_title_wins_and_unmounting_restores_the_one_below() {
    let dom = mount(Router::new().page::<TitledPage>());
    navigate(TitledPage::route());
    settle();
    assert_eq!(dom.document_title(), "Order 7 · Home");
    dom.click(dom.find_tag("button").unwrap());
    settle();
    assert_eq!(dom.document_title(), "Orders");
}
