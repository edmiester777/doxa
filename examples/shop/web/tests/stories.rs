//! The gallery's stories, mounted alone against their scripted servers.

use std::rc::Rc;
use std::time::Duration;

use doxa::ui::dom::MemDom;
use doxa::ui::StoryRoot;
use shop_web::stories::{data, forms, motion};

async fn settle() {
    for _ in 0..20 {
        doxa::client::task::run_until_stalled();
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn the_feed_story_shows_each_event_as_the_script_reaches_it() {
    let dom = MemDom::new();
    let story = StoryRoot::mount_on(Rc::new(dom.clone()), dom.body(), data::feed_streaming);
    settle().await;
    let feed = dom.find("class", "feed").expect("the feed");
    assert_eq!(dom.text(feed), "");
    assert!(dom.find("class", "muted").is_some());
    dom.advance(Duration::from_millis(400));
    settle().await;
    assert_eq!(dom.text(feed), "renamed to gear-2");
    dom.advance(Duration::from_millis(800));
    settle().await;
    assert_eq!(dom.text(feed), "renamed to gear-2renamed to gear-3deleted");
    drop(story);
    settle().await;
    assert!(dom.find("class", "feed").is_none());
}

#[tokio::test]
async fn the_picker_story_lists_the_mocked_widgets() {
    let dom = MemDom::new();
    let _story = StoryRoot::mount_on(Rc::new(dom.clone()), dom.body(), data::picker);
    settle().await;
    let picker = dom.find("class", "picker").expect("the picker");
    assert!(
        dom.text(picker).ends_with("sprocketgearcogflange"),
        "{}",
        dom.text(picker)
    );
}

#[tokio::test]
async fn the_loading_story_holds_its_fallback_until_the_slow_answer() {
    let dom = MemDom::new();
    let _story = StoryRoot::mount_on(Rc::new(dom.clone()), dom.body(), data::picker_loading);
    settle().await;
    assert!(dom.find("class", "skeleton").is_some());
    assert!(dom.find("class", "picker").is_none());
    dom.advance(Duration::from_millis(1500));
    settle().await;
    assert!(dom.find("class", "skeleton").is_none());
    assert!(dom.find("class", "picker").is_some());
}

#[tokio::test]
async fn the_table_story_has_a_row_per_widget() {
    let dom = MemDom::new();
    let _story = StoryRoot::mount_on(Rc::new(dom.clone()), dom.body(), data::widget_table);
    settle().await;
    let text = |tag| dom.text(dom.find_tag(tag).expect(tag));
    assert_eq!(text("thead"), "IdNameLetters");
    assert_eq!(text("tbody"), "#1sprocket8#2gear4#3cog3#4flange6");
}

#[tokio::test]
async fn the_motion_story_reorders_and_drops_rows() {
    let dom = MemDom::new();
    let _story = StoryRoot::mount_on(Rc::new(dom.clone()), dom.body(), motion::reorder_and_remove);
    settle().await;
    let stack = dom.find("class", "stack").expect("the list");
    let reverse = dom.find("class", "btn").expect("the first button");
    let drop_last = dom
        .find("class", "btn ghost")
        .expect("the first ghost button");
    assert_eq!(dom.text(reverse), "Reverse");
    assert_eq!(dom.text(drop_last), "Drop last");

    dom.click(reverse);
    settle().await;
    assert_eq!(dom.text(stack), "spindleflangecoggearsprocket");
    dom.click(drop_last);
    settle().await;
    assert_eq!(dom.text(stack), "spindleflangecoggear");
}

#[tokio::test]
async fn the_form_story_refuses_an_empty_name_and_saves_a_good_one() {
    let dom = MemDom::new();
    let _story = StoryRoot::mount_on(Rc::new(dom.clone()), dom.body(), forms::rename_form);
    settle().await;
    let input = || dom.find("class", "name").expect("the name field");
    let save = || dom.find("class", "btn save").expect("the save button");

    dom.input(input(), "");
    dom.click(save());
    settle().await;
    assert!(dom.find("class", "invalid").is_some());
    assert!(dom.find("class", "saved").is_none());

    dom.input(input(), "gear-2");
    dom.click(save());
    settle().await;
    assert_eq!(dom.text(save()), "Saving…");
    dom.advance(Duration::from_millis(800));
    settle().await;
    let saved = dom.find("class", "saved").expect("the saved note");
    assert_eq!(dom.text(saved), "Saved as gear-2");
}
