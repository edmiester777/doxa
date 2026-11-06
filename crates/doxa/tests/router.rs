//! Redirects, guards, transitions, query edits, blocking and titles, against a `MemDom`.

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use doxa::ui::dom::MemDom;
use doxa::ui::prelude::*;
use doxa::ui::NavigationGuard;

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
    view! {
        <NavigationGuard when={dirty.get()} message="Discard unsaved changes?">
            <button on:click={move |_| dirty.set(false)}>"save"</button>
        </NavigationGuard>
    }
}

#[test]
fn a_guard_asks_before_leaving_and_shows_what_it_wraps() {
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

#[test]
fn staying_on_the_path_never_asks() {
    let dom = mount(Router::new().page::<EditorPage>());
    navigate(EditorPage::route());
    settle();
    dom.answer_confirm(false);
    set_query(|q| q.set("tab", "steps"));
    settle();
    assert_eq!(here(), "/editor?tab=steps");
    navigate("/editor/?tab=history");
    settle();
    assert_eq!(here(), "/editor/?tab=history");
    assert!(dom.confirms().is_empty());
}

#[test]
fn a_page_with_no_guard_never_asks() {
    let dom = mount(Router::new().page::<OrdersPage>().page::<HomePage>());
    navigate("/orders");
    settle();
    dom.answer_confirm(false);
    navigate(HomePage::route());
    settle();
    assert_eq!(here(), "/home");
    assert!(dom.confirms().is_empty());
}

#[page("/scoped/{*rest}")]
fn ScopedPage(rest: String) -> View {
    let _ = rest;
    view! {
        <NavigationGuard when={true} message="Leave the editor?" scope="/scoped">
            <p>"editing"</p>
        </NavigationGuard>
    }
}

#[test]
fn a_scope_counts_everything_under_it_as_staying() {
    let dom = mount(Router::new().page::<ScopedPage>().page::<HomePage>());
    navigate("/scoped/a");
    settle();
    dom.answer_confirm(false);
    navigate("/scoped/b/c");
    settle();
    assert_eq!(here(), "/scoped/b/c");
    assert!(dom.confirms().is_empty());

    navigate("/scoped-not");
    settle();
    assert_eq!(
        here(),
        "/scoped/b/c",
        "a shared prefix is not under the scope"
    );
    assert_eq!(dom.confirms(), ["Leave the editor?"]);

    navigate(HomePage::route());
    settle();
    assert_eq!(here(), "/scoped/b/c");
    assert_eq!(dom.confirms(), ["Leave the editor?"]);
}

#[component]
fn GuardedCard() -> View {
    view! {
        <NavigationGuard when={true} message="Discard the card?">
            <p>"card"</p>
        </NavigationGuard>
    }
}

#[page("/cards")]
fn CardsPage() -> View {
    let open = state(true);
    view! {
        <button on:click={move |_| open.set(false)}>"close"</button>
        {open.get().then(|| view! { <GuardedCard/> })}
    }
}

#[test]
fn a_guard_lasts_only_while_mounted() {
    let dom = mount(Router::new().page::<CardsPage>().page::<HomePage>());
    navigate(CardsPage::route());
    settle();
    dom.click(dom.find_tag("button").unwrap());
    settle();
    dom.answer_confirm(false);
    navigate(HomePage::route());
    settle();
    assert_eq!(here(), "/home");
    assert!(dom.confirms().is_empty());
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

#[page("/orders/{id}")]
fn OrderPage(id: String) -> View {
    view! {
        <Link to={HomePage::route()} active_class="on" data-nav="home">"home"</Link>
        <Link to={OrdersPage::route()} class="tab" active_class="on" data-nav="orders">
            "orders"
        </Link>
        <Link to={OrdersPage::route()} exact=true active_class="on" data-nav="exact">"exact"</Link>
        <Link to={OrderPage::route(id)} aria-label="this" data-nav="self">"self"</Link>
    }
}

#[test]
fn a_link_marks_itself_current_under_its_page() {
    let dom = mount(
        Router::new()
            .page::<HomePage>()
            .page::<OrdersPage>()
            .page::<OrderPage>(),
    );
    navigate("/orders/7?tab=x");
    settle();
    let link = |name| dom.find("data-nav", name).unwrap();
    let current = |name| dom.attr(link(name), "aria-current");
    assert_eq!(current("home"), None);
    assert_eq!(dom.attr(link("home"), "class"), None);
    assert_eq!(current("orders").as_deref(), Some("page"));
    assert_eq!(dom.attr(link("orders"), "class").as_deref(), Some("tab on"));
    assert_eq!(current("exact"), None, "exact needs the whole path");
    assert_eq!(current("self").as_deref(), Some("page"));
    assert_eq!(
        dom.attr(link("self"), "aria-label").as_deref(),
        Some("this")
    );
    assert!(doxa::ui::link_active(&OrdersPage::route(), false));
    assert!(
        !doxa::ui::link_active(&"/ord".into(), false),
        "only on a segment boundary"
    );
}
