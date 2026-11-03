//! The pages, rendered into an in-memory document against the real server router.

use std::rc::Rc;

use std::cell::RefCell;

use doxa::client::layer::{transport, Scoped};
use doxa::client::transport::RouterTransport;
use doxa::ui::dom::MemDom;
use doxa::ui::navigate;
use doxa::ui::react::{Bridge, Content, EventFn, Mount};

thread_local! {
    static SERVED: RefCell<Option<Scoped>> = const { RefCell::new(None) };
}

/// Answer this thread's calls with a fresh server, as `role`, from an empty cache.
fn serve(role: &str) {
    let s = widgets_client::service();
    SERVED.with(|g| g.borrow_mut().take());
    s.end_session();
    let router = widgets_server::app(widgets_server::seeded());
    let guard = s.layers().push_scoped(transport(
        RouterTransport::new(router).with_header("x-role", role),
    ));
    SERVED.with(|g| *g.borrow_mut() = Some(guard));
}

fn mount(role: &str) -> MemDom {
    serve(role);
    let dom = MemDom::new();
    widgets_web::app()
        .mount_on(Rc::new(dom.clone()), dom.body())
        .keep();
    dom
}

/// Let renders, requests and effects run until nothing is left to do.
async fn settle() {
    for _ in 0..20 {
        doxa::client::task::run_until_stalled();
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn the_list_page_renders_every_widget_with_one_request() {
    let dom = mount("viewer");
    settle().await;
    assert_eq!(dom.text(dom.find_tag("ul").unwrap()), "sprocketgearcog");
    assert_eq!(widgets_client::service().requests_sent(), 1);
}

#[tokio::test]
async fn a_link_navigates_and_the_rename_button_follows_the_guard() {
    let dom = mount("viewer");
    settle().await;
    let link = dom.find("href", "/widgets/gear").expect("a link to gear");
    dom.click(link);
    settle().await;
    let h1 = dom.find_tag("h1").unwrap();
    assert_eq!(dom.text(h1), "gear");
    assert!(dom.find("class", "edit").is_none(), "a viewer can't rename");

    let dom = mount("editor");
    navigate("/widgets/gear");
    settle().await;
    assert!(dom.find("class", "edit").is_some(), "an editor can rename");
}

#[tokio::test]
async fn a_renamed_can_takes_its_probe_directly() {
    use doxa::ui::prelude::{view, App};
    use doxa::ui::Can as Allowed;
    use widgets_client::widgets::{rename_widget, WidgetKey};

    for (role, shown) in [("editor", true), ("viewer", false)] {
        serve(role);
        let dom = MemDom::new();
        App::new(|| {
            let key = WidgetKey {
                name: "gear".into(),
            };
            view! {
                <Allowed probe={rename_widget::can(&key)}>
                    <button class="edit">"Rename"</button>
                </Allowed>
            }
        })
        .mount_on(Rc::new(dom.clone()), dom.body())
        .keep();
        settle().await;
        assert_eq!(dom.find("class", "edit").is_some(), shown, "{role}");
    }
}

#[tokio::test]
async fn a_generic_table_infers_its_row_type_from_the_tag() {
    use doxa::ui::prelude::{view, App};
    use widgets_client::widgets::Widget;
    use widgets_web::table::{Column, Table};

    serve("viewer");
    let dom = MemDom::new();
    App::new(|| {
        let rows = vec![(1u32, "gear"), (2, "cog")];
        let widgets = vec![Widget {
            id: 7,
            name: "sprocket".into(),
        }];
        view! {
            <Table
                rows={rows}
                columns={vec![Column { header: "id", cell: |r: &(u32, &str)| r.0.to_string() }]}
                row_key={|r: &(u32, &str)| r.1.to_owned()}
            />
            <Table
                rows={widgets}
                columns={vec![Column { header: "name", cell: |w: &Widget| w.name.clone() }]}
                row_key={|w: &Widget| w.id.to_string()}
            />
        }
    })
    .mount_on(Rc::new(dom.clone()), dom.body())
    .keep();
    settle().await;
    assert_eq!(dom.text(dom.body()), "id12namesprocket");
}

#[tokio::test]
async fn a_tags_extra_attributes_handlers_and_directives_reach_the_element() {
    use doxa::ui::prelude::{state, view, App, Directive, NodeRef};
    use widgets_web::button::Button;

    #[derive(Clone)]
    struct Mark(std::rc::Rc<std::cell::Cell<bool>>);
    impl Directive for Mark {
        fn mounted(&mut self, _: NodeRef) {
            self.0.set(true);
        }
    }
    fn mark(m: Mark) -> Mark {
        m
    }

    serve("viewer");
    let dom = MemDom::new();
    let marked = std::rc::Rc::new(std::cell::Cell::new(false));
    let seen = Mark(marked.clone());
    App::new(move || {
        let clicks = state(0u32);
        view! {
            <Button
                class="ghost px-1"
                class:wide={true}
                type="submit"
                aria-label="Close"
                data-row="7"
                title="close it"
                on:click={move |_| clicks.update(|n| *n += 1)}
                use:mark={seen.clone()}
            >
                "×"
            </Button>
            <p class="clicks">{clicks.get()}</p>
        }
    })
    .mount_on(Rc::new(dom.clone()), dom.body())
    .keep();
    settle().await;

    let button = dom.find_tag("button").unwrap();
    assert_eq!(
        dom.attr(button, "class").as_deref(),
        Some("btn ghost px-1 wide")
    );
    assert_eq!(
        dom.attr(button, "type").as_deref(),
        Some("button"),
        "the element's own wins"
    );
    assert_eq!(dom.attr(button, "aria-label").as_deref(), Some("Close"));
    assert_eq!(dom.attr(button, "data-row").as_deref(), Some("7"));
    assert_eq!(dom.attr(button, "title").as_deref(), Some("close it"));
    assert!(marked.get(), "the directive mounted on the button");
    dom.click(button);
    settle().await;
    assert_eq!(dom.text(dom.find("class", "clicks").unwrap()), "1");
}

#[tokio::test]
async fn a_class_toggle_patches_only_its_own_class() {
    use doxa::ui::dom::Dom;
    use doxa::ui::prelude::{state, view, App};

    serve("viewer");
    let dom = MemDom::new();
    App::new(|| {
        let on = state(false);
        view! {
            <a
                class="tab"
                class:active={on.get()}
                class:idle={!on.get()}
                on:click={move |_| on.toggle()}
            >
                "Tab"
            </a>
        }
    })
    .mount_on(Rc::new(dom.clone()), dom.body())
    .keep();
    settle().await;

    let tab = dom.find_tag("a").unwrap();
    assert_eq!(dom.attr(tab, "class").as_deref(), Some("tab idle"));
    dom.toggle_class(tab, "focused", true);
    dom.click(tab);
    settle().await;
    assert_eq!(
        dom.attr(tab, "class").as_deref(),
        Some("tab focused active"),
        "the class set outside the render stays"
    );
}

#[tokio::test]
async fn a_user_clicks_through_the_list_by_role_and_text_with_a_fake_island() {
    use doxa::ui::prelude::view;
    use doxa::ui::testing::{fake, Role, Screen};
    use widgets_web::Count;

    serve("viewer");
    fake::<Count>(|p| {
        let total = p.prop::<usize>("total").unwrap_or_default();
        let p = p.clone();
        view! {
            <button on:click={move |_| p.fire("onPick", false)}>
                {format!("{total} widgets")}
            </button>
        }
    });
    let screen = Screen::app(widgets_web::app());

    screen.role(Role::Button).name("3 widgets").click().await;
    screen.find_text("1").await.expect("the pick reached Rust");
    screen.role(Role::Link).name("gear").click().await;
    screen
        .role(Role::Heading)
        .name("gear")
        .find()
        .await
        .expect("the widget's page");
}

#[tokio::test]
async fn a_labelled_field_takes_typing_and_a_missing_one_says_what_it_looked_for() {
    use doxa::ui::prelude::{state, view};
    use doxa::ui::testing::{Role, Screen, ScreenError};

    let screen = Screen::mount(|| {
        let title = state(String::new());
        view! {
            <label for="title">"Title"</label>
            <input id="title" prop:value={title.get()} on:input={move |e| title.set(e.value())}/>
            <p>{format!("Saved {}", title.get())}</p>
        }
    });
    screen.label("Title").type_text("Q3").await;
    screen.label("Title").type_text(" report").await;
    screen
        .find_text("Saved Q3 report")
        .await
        .expect("both typed");

    let missing = screen.role(Role::Button).name("Save").get().unwrap_err();
    assert!(matches!(missing, ScreenError::NotFound { .. }));
    let message = missing.to_string();
    assert!(message.contains(r#"a button named "Save""#), "{message}");
    assert!(
        message.contains("<label for=\"title\">Title</label>"),
        "{message}"
    );
}

#[tokio::test]
async fn find_moves_the_clock_to_a_pending_timer_but_not_past_its_timeout() {
    use doxa::ui::prelude::{effect, sleep, state, view};
    use doxa::ui::testing::Screen;
    use std::time::Duration;

    let screen = Screen::mount(|| {
        let shown = state(false);
        effect((), async move |_| {
            sleep(Duration::from_millis(300)).await;
            shown.set(true);
            Ok(())
        });
        view! { <p>{if shown.get() { "Saved" } else { "Saving" }}</p> }
    });
    screen
        .find_text("Saved")
        .await
        .expect("after the 300ms timer");

    let slow = Screen::mount(|| {
        let shown = state(false);
        effect((), async move |_| {
            sleep(Duration::from_secs(5)).await;
            shown.set(true);
            Ok(())
        });
        view! { <p>{if shown.get() { "Saved" } else { "Saving" }}</p> }
    });
    assert!(
        slow.find_text("Saved").await.is_err(),
        "five seconds is past the timeout"
    );
}

/// An island's name and props, and its event handlers.
type Mounted = (String, Vec<(&'static str, EventFn)>);

/// Stands in for React: records each island's props and keeps its event handlers.
#[derive(Clone, Default)]
struct FakeReact(Rc<std::cell::RefCell<Vec<Mounted>>>);

impl Bridge for FakeReact {
    fn mount(&self, m: Mount<'_>) {
        self.0.borrow_mut().push((
            format!(
                "{} {}",
                m.island.name,
                serde_json::to_string(&m.content.props).unwrap()
            ),
            m.events,
        ));
    }
    fn update(&self, _: u32, _: &Content) {}
    fn unmount(&self, _: u32) {}
}

#[tokio::test]
async fn the_react_count_gets_the_total_and_calls_back_into_rust() {
    let react = FakeReact::default();
    doxa::ui::react::set_bridge(react.clone());
    let dom = mount("viewer");
    settle().await;
    let (props, events) = react.0.borrow_mut().remove(0);
    assert_eq!(props, r#"Count {"total":3}"#);
    assert_eq!(dom.text(dom.find("class", "picks").unwrap()), "0");

    let (_, on_pick) = events.iter().find(|(n, _)| *n == "onPick").unwrap();
    on_pick("false");
    settle().await;
    assert_eq!(dom.text(dom.find("class", "picks").unwrap()), "1");
}

#[tokio::test]
async fn svg_icons_render_without_react_and_react_icons_as_islands() {
    let react = FakeReact::default();
    doxa::ui::react::set_bridge(react.clone());
    let dom = mount("viewer");
    navigate("/icons");
    settle().await;

    let svg = dom.find("id", "svg").unwrap();
    let html = dom.inner_html(svg);
    assert!(html.contains(r#"<path d="M5 12h14">"#), "{html}");
    let trash = dom
        .find("class", "icon icon-trash-2 danger")
        .expect("the class joined");
    assert_eq!(dom.attr(trash, "width").as_deref(), Some("16"));
    assert_eq!(dom.attr(trash, "stroke-width").as_deref(), Some("2"));
    let plus = dom.find("class", "icon icon-plus").unwrap();
    assert_eq!(dom.attr(plus, "width").as_deref(), Some("24"));

    let mounted: Vec<String> = react.0.borrow().iter().map(|(p, _)| p.clone()).collect();
    assert!(
        mounted.contains(&r#"Drawn::Plus {"size":20}"#.to_owned()),
        "{mounted:?}"
    );
    assert!(
        mounted.contains(&"Drawn::Less {}".to_owned()),
        "{mounted:?}"
    );
    assert!(
        !html.contains("data-island"),
        "the SVG icons aren't islands"
    );
}

#[tokio::test]
async fn the_shell_stays_mounted_across_pages() {
    let dom = mount("viewer");
    settle().await;
    let header = dom.find_tag("header").unwrap();
    dom.click(dom.find("href", "/widgets/gear").unwrap());
    settle().await;
    assert_eq!(dom.text(dom.find_tag("h1").unwrap()), "gear");
    assert_eq!(dom.find_tag("header"), Some(header));
    assert_eq!(dom.document_title(), "gear · Widgets");
}

#[tokio::test]
async fn renaming_updates_the_page_and_the_url() {
    let dom = mount("editor");
    navigate("/widgets/cog");
    settle().await;
    dom.click(dom.find("class", "edit").unwrap());
    settle().await;
    dom.input(dom.find("class", "name").unwrap(), "flange");
    settle().await;
    dom.click(dom.find("class", "save").unwrap());
    settle().await;
    assert_eq!(doxa::ui::location(), "/widgets/flange");
    assert_eq!(dom.text(dom.find_tag("h1").unwrap()), "flange");
}

#[tokio::test]
async fn an_empty_name_is_refused_before_it_is_sent() {
    let dom = mount("editor");
    navigate("/widgets/cog");
    settle().await;
    dom.click(dom.find("class", "edit").unwrap());
    settle().await;
    dom.input(dom.find("class", "name").unwrap(), "");
    dom.click(dom.find("class", "save").unwrap());
    settle().await;
    assert!(
        dom.find("class", "invalid").is_some(),
        "the rule the server also checks"
    );
    assert!(dom.find("class", "error").is_none(), "nothing was sent");
    assert_eq!(doxa::ui::location(), "/widgets/cog");
}

#[tokio::test]
async fn a_failed_rename_shows_the_routes_own_error() {
    let dom = mount("editor");
    navigate("/widgets/cog");
    settle().await;
    dom.click(dom.find("class", "edit").unwrap());
    settle().await;
    dom.input(dom.find("class", "name").unwrap(), "gear");
    settle().await;
    dom.click(dom.find("class", "save").unwrap());
    settle().await;
    let error = dom.find("class", "error").expect("an inline error");
    assert!(dom.text(error).contains("taken"), "{}", dom.text(error));
}

#[tokio::test]
async fn the_theme_toggle_switches_the_root() {
    let dom = mount("viewer");
    settle().await;
    assert_eq!(dom.find("data-theme", "light"), Some(dom.body()));
    dom.click(dom.find("class", "theme").unwrap());
    settle().await;
    assert_eq!(dom.find("data-theme", "dark"), Some(dom.body()));
    assert_eq!(dom.text(dom.find("class", "theme").unwrap()), "Light");
    assert_eq!(dom.storage("dark").as_deref(), Some("true"));
}

#[tokio::test]
async fn an_unknown_path_shows_not_found() {
    let dom = mount("viewer");
    navigate("/nowhere");
    settle().await;
    assert!(dom.find("class", "missing").is_some());
}

#[tokio::test]
async fn a_typed_query_round_trips_through_a_link_and_set_query_as() {
    let dom = mount("viewer");
    navigate("/widgets/cog/runs?status=queued");
    settle().await;
    let filter = || dom.text(dom.find("class", "filter").unwrap());
    assert_eq!(filter(), "Some(Queued) page 0");

    let next = dom.find("href", "/widgets/cog/runs?status=queued&page=1");
    dom.click(next.expect("a typed link"));
    settle().await;
    assert_eq!(
        doxa::ui::location(),
        "/widgets/cog/runs?status=queued&page=1"
    );
    assert_eq!(filter(), "Some(Queued) page 1");

    dom.click(dom.find("class", "done").unwrap());
    settle().await;
    assert_eq!(doxa::ui::location(), "/widgets/cog/runs?status=done&page=1");
    assert_eq!(filter(), "Some(Done) page 1");
}

#[tokio::test]
async fn a_query_that_does_not_parse_shows_not_found() {
    let dom = mount("viewer");
    navigate("/widgets/cog/runs?status=lost");
    settle().await;
    assert!(dom.find("class", "missing").is_some());
}

#[tokio::test]
async fn an_exported_component_renders_again_with_the_hosts_new_props() {
    use doxa::ui::Exported;
    use widgets_web::kit::{WidgetTitle, WidgetTitleProps};

    serve("viewer");
    let dom = MemDom::new();
    let at = dom.body();
    let props = |name: &str| WidgetTitleProps {
        name: name.into(),
        level: 2,
    };
    let title = Exported::<WidgetTitle>::mount_on(Rc::new(dom.clone()), at, props("gear"));
    settle().await;
    assert_eq!(dom.text(dom.find("class", "title").unwrap()), "gear");
    assert_eq!(dom.find("data-level", "2"), dom.find("class", "title"));

    title.update(props("cog"));
    settle().await;
    assert_eq!(dom.text(dom.find("class", "title").unwrap()), "cog");

    drop(title);
    settle().await;
    assert!(
        dom.find("class", "title").is_none(),
        "unmounted with its handle"
    );
}
