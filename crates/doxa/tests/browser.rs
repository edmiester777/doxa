//! Window events, timers, observers, storage and the browser helpers, against a `MemDom`.

use std::rc::Rc;
use std::time::Duration;

use doxa::client::Download;
use doxa::ui::clipboard::Clip;
use doxa::ui::dom::{MemDom, MemEvent};
use doxa::ui::prelude::*;
use doxa::ui::{broadcast, intersection, resize_observer, Rect, RootHandle};

fn mount_on<V: IntoView>(dom: &MemDom, root: impl Fn() -> V + 'static) -> RootHandle {
    App::new(root).mount_on(Rc::new(dom.clone()), dom.body())
}

fn settle() {
    doxa::client::task::run_until_stalled();
}

fn text(dom: &MemDom) -> String {
    dom.text(dom.body())
}

#[component]
fn Palette() -> View {
    let open = state(false);
    window_event("keydown", move |e: Event| {
        if e.key() == "k" && e.meta_key() {
            e.prevent_default();
            open.toggle();
        }
    });
    let hidden = state(0);
    document_event("visibilitychange", move |_| hidden.update(|n| *n += 1));
    view! { <p>{format!("{} {}", open.get(), hidden.get())}</p> }
}

#[test]
fn window_and_document_events_reach_the_component_until_it_unmounts() {
    let dom = MemDom::new();
    let root = mount_on(&dom, || view! { <Palette/> });
    settle();
    let cmd_k = || MemEvent {
        key: "k".into(),
        meta_key: true,
        ..MemEvent::default()
    };
    assert!(
        !dom.dispatch_window("keydown", cmd_k()),
        "default prevented"
    );
    dom.dispatch_document("visibilitychange", MemEvent::default());
    settle();
    assert_eq!(text(&dom), "true 1");
    drop(root);
    settle();
    assert!(dom.dispatch_window("keydown", cmd_k()), "no listener left");
}

#[component]
fn Ticker() -> View {
    let n = state(0);
    interval(Duration::from_secs(1), move || n.update(|n| *n += 1));
    let done = state(false);
    effect((), async move |_| {
        sleep(Duration::from_secs(5)).await;
        done.set(true);
        Ok(())
    });
    view! { <p>{format!("{} {}", n.get(), done.get())}</p> }
}

#[test]
fn interval_and_sleep_follow_the_manual_clock() {
    let dom = MemDom::new();
    let root = mount_on(&dom, || view! { <Ticker/> });
    settle();
    dom.advance(Duration::from_millis(3500));
    assert_eq!(text(&dom), "3 false");
    dom.advance(Duration::from_millis(1500));
    assert_eq!(text(&dom), "5 true");
    drop(root);
    dom.advance(Duration::from_secs(10));
    assert_eq!(doxa::ui::now(), Duration::from_secs(15));
}

#[component]
fn Search() -> View {
    let q = state(String::new());
    let shown = debounced(q.get(), Duration::from_millis(250));
    view! {
        <input on:input={move |e: Event| q.set(e.value())}/>
        <p>{format!("[{shown}]")}</p>
    }
}

#[test]
fn debounced_waits_for_the_value_to_settle() {
    let dom = MemDom::new();
    let _root = mount_on(&dom, || view! { <Search/> });
    settle();
    let input = dom.find_tag("input").unwrap();
    dom.input(input, "a");
    settle();
    dom.advance(Duration::from_millis(200));
    dom.input(input, "ab");
    settle();
    dom.advance(Duration::from_millis(200));
    assert_eq!(text(&dom), "[]");
    dom.advance(Duration::from_millis(50));
    assert_eq!(text(&dom), "[ab]");
}

#[component]
fn Panel() -> View {
    let r = node_ref();
    let size = resize_observer(r);
    let seen = intersection(r);
    let width = size.get().map_or(0.0, |s| s.width);
    view! { <div id="panel" ref={r}>{format!("{width} {}", seen.get())}</div> }
}

#[test]
fn observers_report_the_referenced_element() {
    let dom = MemDom::new();
    let _root = mount_on(&dom, || view! { <Panel/> });
    settle();
    let panel = dom.find("id", "panel").unwrap();
    dom.resize(
        panel,
        Rect {
            width: 120.0,
            ..Rect::default()
        },
    );
    settle();
    assert_eq!(text(&dom), "120 false");
    dom.intersect(panel, true);
    settle();
    assert_eq!(text(&dom), "120 true");
}

#[component]
fn Prefs() -> View {
    let theme = stored::<String>("theme", || "light".into());
    view! { <button on:click={move |_| theme.set("dark".into())}>{theme.get()}</button> }
}

#[test]
fn stored_state_persists_and_follows_other_tabs() {
    let dom = MemDom::new();
    let _root = mount_on(&dom, || view! { <Prefs/> });
    settle();
    assert_eq!(text(&dom), "light");
    dom.click(dom.find_tag("button").unwrap());
    settle();
    assert_eq!(text(&dom), "dark");
    assert_eq!(dom.storage("theme").as_deref(), Some("\"dark\""));
    dom.store_elsewhere("theme", Some("\"blue\""));
    settle();
    assert_eq!(text(&dom), "blue");
}

#[component]
fn Scheme() -> View {
    let dark = media_query("(prefers-color-scheme: dark)");
    view! { <p>{if dark { "dark" } else { "light" }}</p> }
}

#[test]
fn media_query_tracks_its_query() {
    let dom = MemDom::new();
    dom.set_media("(prefers-color-scheme: dark)", true);
    let _root = mount_on(&dom, || view! { <Scheme/> });
    settle();
    assert_eq!(text(&dom), "dark");
    dom.set_media("(prefers-color-scheme: dark)", false);
    settle();
    assert_eq!(text(&dom), "light");
}

#[component]
fn Station(name: String) -> View {
    let ch = broadcast::<String>("present");
    let send = {
        let (ch, name) = (ch.clone(), name.clone());
        move |_| ch.send(&name)
    };
    view! {
        <button id={name}>{ch.last().unwrap_or_default()}</button>
        <i on:click={send}/>
    }
}

#[test]
fn a_broadcast_reaches_the_other_channels_of_its_name() {
    let dom = MemDom::new();
    let _root = mount_on(&dom, || {
        view! {
            <Station name={"a".to_string()}/>
            <Station name={"b".to_string()}/>
        }
    });
    settle();
    dom.click(dom.find_tag("i").unwrap());
    settle();
    let a = dom.find("id", "a").unwrap();
    let b = dom.find("id", "b").unwrap();
    assert_eq!(dom.text(a), "");
    assert_eq!(dom.text(b), "a");
}

#[component]
fn Once() -> View {
    let n = state(0);
    let target = state(None);
    view! {
        <button
            on:click.once={move |e: Event| {
                n.update(|n| *n += 1);
                target.set(e.target_ref());
            }}
        >
            {format!("{} {}", n.get(), target.get().is_some())}
        </button>
    }
}

#[test]
fn a_once_listener_fires_once_and_sees_its_target() {
    let dom = MemDom::new();
    let _root = mount_on(&dom, || view! { <Once/> });
    settle();
    let button = dom.find_tag("button").unwrap();
    dom.click(button);
    settle();
    dom.click(button);
    settle();
    assert_eq!(text(&dom), "1 true");
}

#[test]
fn the_clipboard_and_downloads_land_in_the_mem_dom() {
    let dom = MemDom::new();
    let clip = Clip::text("hi").html("<b>hi</b>");
    doxa::client::task::block_on(doxa::ui::clipboard::write(clip.clone())).unwrap();
    assert_eq!(dom.clipboard(), Some(clip));
    let file = Download {
        bytes: b"x".to_vec(),
        content_type: Some("text/plain".into()),
        filename: Some("x.txt".into()),
    };
    doxa::ui::save(file.clone()).unwrap();
    assert_eq!(dom.downloads(), [file]);
}
