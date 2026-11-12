//! The `doxa gallery` page against an in-memory document.

use std::rc::Rc;

use doxa::ui::dom::{MemDom, NodeId};
use doxa::ui::gallery::{Gallery, Initial, StoryMeta, Viewport};
use doxa::ui::prelude::*;

fn story(name: &str, module: &str) -> StoryMeta {
    StoryMeta {
        name: name.into(),
        title: name.into(),
        module: module.into(),
        file: "web/src/stories.rs".into(),
        line: 7,
        source: format!("#[story]\nfn {name}() -> View {{ view! {{}} }}"),
    }
}

fn start() -> Initial {
    Initial {
        story: None,
        dark: false,
        viewport: Viewport::Fill,
    }
}

fn mount(initial: Initial) -> MemDom {
    let entries = vec![
        story("empty_list", "app::lists"),
        story("full_list", "app::lists"),
        story("button", "app::forms"),
    ];
    let dom = MemDom::new();
    App::embedded(move || view! { <Gallery entries={entries.clone()} initial={initial.clone()}/> })
        .mount_on(Rc::new(dom.clone()), dom.body())
        .keep();
    doxa::client::task::run_until_stalled();
    dom
}

fn leaf(dom: &MemDom, name: &str) -> Option<NodeId> {
    dom.find("data-story", name)
}

fn frame_src(dom: &MemDom) -> String {
    let frame = dom.find_tag("iframe").expect("the canvas frame");
    dom.attr(frame, "src").unwrap_or_default()
}

#[test]
fn the_tree_nests_stories_by_module_and_a_click_shows_one() {
    let dom = mount(start());
    let tree = dom.find("role", "tree").expect("the tree");
    assert_eq!(dom.text(tree), "FormsButtonListsEmpty listFull list");
    assert!(
        frame_src(&dom).contains("story=button"),
        "{}",
        frame_src(&dom)
    );
    assert_eq!(dom.document_title(), "Button · Stories");

    dom.click(leaf(&dom, "full_list").expect("the full list story"));
    doxa::client::task::run_until_stalled();
    assert!(
        frame_src(&dom).contains("story=full_list"),
        "{}",
        frame_src(&dom)
    );
    assert_eq!(
        dom.attr(leaf(&dom, "full_list").unwrap(), "aria-selected")
            .as_deref(),
        Some("true")
    );
}

#[test]
fn a_folded_module_hides_its_stories() {
    let dom = mount(start());
    let lists = dom.find("aria-expanded", "true").expect("an open module");
    dom.click(lists);
    doxa::client::task::run_until_stalled();
    assert!(leaf(&dom, "button").is_none());
    assert!(leaf(&dom, "empty_list").is_some());
}

#[test]
fn a_search_keeps_only_matching_stories() {
    let dom = mount(start());
    let input = dom
        .find("aria-label", "Find stories")
        .expect("the search box");
    dom.input(input, "list");
    doxa::client::task::run_until_stalled();
    assert!(leaf(&dom, "button").is_none());
    assert!(leaf(&dom, "empty_list").is_some() && leaf(&dom, "full_list").is_some());
    let mark = dom.find_tag("mark").expect("the match marked");
    assert_eq!(dom.text(mark), "list");
}

#[test]
fn the_url_picks_the_story_viewport_and_theme() {
    let dom = mount(Initial {
        story: Some("empty_list".into()),
        dark: true,
        viewport: Viewport::Phone,
    });
    let src = frame_src(&dom);
    assert!(
        src.contains("story=empty_list") && src.contains("theme=dark"),
        "{src}"
    );
    let frame = dom.find_tag("iframe").unwrap();
    assert_eq!(
        dom.attr(frame, "style").as_deref(),
        Some("width:390px;height:844px")
    );
    let keyword = dom.find("class", "t-kw").expect("highlighted source");
    assert_eq!(dom.text(keyword), "fn");
    assert!(dom.text(dom.body()).contains("web/src/stories.rs:7"));
}

#[test]
fn the_phone_bar_opens_the_tree_and_a_pick_closes_it() {
    let dom = mount(start());
    let open = dom
        .find("aria-label", "Open the story list")
        .expect("the phone bar's menu button");
    assert_eq!(dom.text(open), "Forms / Button");
    let app = dom.find("class", "app panel-open").expect("the app");

    dom.click(open);
    doxa::client::task::run_until_stalled();
    assert!(dom.attr(app, "class").unwrap().contains("menu"));

    dom.click(leaf(&dom, "full_list").unwrap());
    doxa::client::task::run_until_stalled();
    assert!(!dom.attr(app, "class").unwrap().contains("menu"));
    assert_eq!(dom.text(open), "Lists / Full list");
}

#[test]
fn stories_sharing_a_name_stay_apart_and_a_bare_name_finds_one() {
    let entries = vec![
        StoryMeta {
            name: "empty_1a2b3c4d".into(),
            ..story("empty", "app::lists")
        },
        StoryMeta {
            name: "empty_5e6f7a8b".into(),
            ..story("empty", "app::forms")
        },
    ];
    let dom = MemDom::new();
    let initial = Initial {
        story: Some("empty".into()),
        ..start()
    };
    App::embedded(move || view! { <Gallery entries={entries.clone()} initial={initial.clone()}/> })
        .mount_on(Rc::new(dom.clone()), dom.body())
        .keep();
    doxa::client::task::run_until_stalled();
    assert!(leaf(&dom, "empty_1a2b3c4d").is_some() && leaf(&dom, "empty_5e6f7a8b").is_some());
    assert!(
        frame_src(&dom).contains("story=empty_1a2b3c4d"),
        "{}",
        frame_src(&dom)
    );
    assert_eq!(dom.document_title(), "Empty · Stories");
}

#[test]
fn an_unknown_story_in_the_url_falls_back_to_the_first() {
    let dom = mount(Initial {
        story: Some("gone".into()),
        ..start()
    });
    assert!(
        frame_src(&dom).contains("story=button"),
        "{}",
        frame_src(&dom)
    );
}
