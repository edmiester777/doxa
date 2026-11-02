//! The gallery's stories, mounted alone against their scripted servers.

use std::rc::Rc;
use std::time::Duration;

use doxa::ui::dom::MemDom;
use doxa::ui::StoryRoot;

async fn settle() {
    for _ in 0..20 {
        doxa::client::task::run_until_stalled();
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn the_feed_story_shows_each_event_as_the_script_reaches_it() {
    let dom = MemDom::new();
    let story = StoryRoot::mount_on(
        Rc::new(dom.clone()),
        dom.body(),
        widgets_web::stories::feed_streaming,
    );
    settle().await;
    let feed = dom.find("class", "feed").expect("the feed");
    assert_eq!(dom.text(feed), "");
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
    let _story = StoryRoot::mount_on(
        Rc::new(dom.clone()),
        dom.body(),
        widgets_web::stories::picker_three,
    );
    settle().await;
    let picker = dom.find("class", "picker").expect("the picker");
    assert!(
        dom.text(picker).ends_with("sprocketgearcog"),
        "{}",
        dom.text(picker)
    );
}
