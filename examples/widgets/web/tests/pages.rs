//! The pages, rendered into an in-memory document against the real server router.

use std::rc::Rc;

use doxa::client::transport::RouterTransport;
use doxa::client::{Client, ClientConfig};
use doxa::ui::dom::MemDom;
use doxa::ui::navigate;

fn mount(role: &str) -> MemDom {
    let router = widgets_server::app(widgets_server::seeded());
    let dom = MemDom::new();
    widgets_web::app()
        .config(
            ClientConfig::default()
                .transport(RouterTransport::new(router).with_header("x-role", role)),
        )
        .mount_on(Rc::new(dom.clone()), dom.body());
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
    assert_eq!(Client::current().requests_sent(), 1);
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
}

#[tokio::test]
async fn an_unknown_path_shows_not_found() {
    let dom = mount("viewer");
    navigate("/nowhere");
    settle().await;
    assert!(dom.find("class", "missing").is_some());
}
