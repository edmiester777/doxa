//! The gallery page's entry, called by the bundle `doxa gallery` builds: the gallery itself, or
//! with `?story=` set, the one story its canvas frame shows.

use std::cell::RefCell;

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use super::app::Gallery;
use super::model::{entries, Initial, Message, StoryMeta, FORWARDED};
use crate::prelude::*;

const PREFIX: &str = "__doxa_story_";

thread_local! {
    /// The story this frame shows; its components' calls are reported under it.
    static STORY: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Show the gallery over `glue`'s `#[story]` exports, described by `stories` (JSON).
#[wasm_bindgen(js_name = "__doxa_gallery")]
pub fn start(glue: JsValue, stories: &str) -> Result<(), JsError> {
    let window = web_sys::window().ok_or_else(|| JsError::new("no window"))?;
    let document = window
        .document()
        .ok_or_else(|| JsError::new("no document"))?;
    let search = window.location().search().unwrap_or_default();
    let pairs: Vec<(String, String)> =
        serde_urlencoded::from_str(search.trim_start_matches('?')).unwrap_or_default();
    let get = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    if let Some(name) = get("story") {
        return show_story(
            &glue,
            &document,
            name,
            get("theme").as_deref() == Some("dark"),
        );
    }

    let names = js_sys::Reflect::own_keys(&glue)
        .map_err(|_| JsError::new("the bindings aren't an object"))?
        .iter()
        .filter_map(|k| k.as_string()?.strip_prefix(PREFIX).map(str::to_owned))
        .collect();
    let meta: Vec<StoryMeta> = serde_json::from_str(stories)
        .map_err(|e| JsError::new(&format!("the story list doesn't parse: {e}")))?;
    let entries = entries(names, meta);
    let initial = Initial::from_query(&pairs);

    let style = document.create_element("style").map_err(js_error)?;
    style.set_text_content(Some(include_str!("style.css")));
    document
        .head()
        .ok_or_else(|| JsError::new("no <head>"))?
        .append_child(&style)
        .map_err(js_error)?;
    App::embedded(move || view! { <Gallery entries={entries.clone()} initial={initial.clone()}/> })
        .mount("body");
    Ok(())
}

fn show_story(
    glue: &JsValue,
    document: &web_sys::Document,
    name: String,
    dark: bool,
) -> Result<(), JsError> {
    let theme = if dark { "dark" } else { "light" };
    let root = document
        .document_element()
        .ok_or_else(|| JsError::new("no <html>"))?;
    root.set_attribute("data-theme", theme).map_err(js_error)?;
    root.set_attribute("style", &format!("color-scheme: {theme}"))
        .map_err(js_error)?;
    let body = document.body().ok_or_else(|| JsError::new("no <body>"))?;
    body.set_attribute("style", "margin: 0; padding: 1rem")
        .map_err(js_error)?;
    STORY.with(|s| s.replace(Some(name.clone())));
    forward_keys();

    let host = document.create_element("div").map_err(js_error)?;
    host.set_id("story");
    host.set_attribute("data-story", &name).map_err(js_error)?;
    body.replace_children_with_node_1(&host);
    let mount = js_sys::Reflect::get(glue, &format!("{PREFIX}{name}").into()).map_err(js_error)?;
    let Some(mount) = mount.dyn_ref::<js_sys::Function>() else {
        host.set_text_content(Some(&format!("no story named {name}")));
        return Ok(());
    };
    let handle = mount.call1(&JsValue::NULL, &host).map_err(js_error)?;
    // The story stays mounted for the frame's life.
    std::mem::forget(handle);
    Ok(())
}

/// Send the gallery its shortcuts while the story has focus, unless the story took the key.
fn forward_keys() {
    let Some(window) = web_sys::window() else {
        return;
    };
    let on_key = Closure::<dyn Fn(web_sys::KeyboardEvent)>::new(|e: web_sys::KeyboardEvent| {
        let typing = e
            .target()
            .and_then(|t| t.dyn_into::<web_sys::Element>().ok())
            .is_some_and(|t| {
                t.closest("input, textarea, select, [contenteditable]")
                    .ok()
                    .flatten()
                    .is_some()
            });
        let key = e.key();
        if e.default_prevented()
            || e.meta_key()
            || e.ctrl_key()
            || e.alt_key()
            || typing
            || !FORWARDED.contains(&key.as_str())
        {
            return;
        }
        e.prevent_default();
        post(&Message::Key { key });
    });
    let _ = window.add_event_listener_with_callback("keydown", on_key.as_ref().unchecked_ref());
    on_key.forget();
}

/// Tell the gallery a component in this frame's story called its `prop` with `args`.
pub(crate) fn report(component: &str, prop: &str, args: Vec<String>) {
    let Some(story) = STORY.with(|s| s.borrow().clone()) else {
        return;
    };
    post(&Message::Action {
        story,
        component: component.to_owned(),
        prop: prop.to_owned(),
        args,
    });
}

fn post(message: &Message) {
    let parent = web_sys::window().and_then(|w| w.parent().ok().flatten());
    if let (Some(parent), Ok(text)) = (parent, serde_json::to_string(message)) {
        let _ = parent.post_message(&JsValue::from_str(&text), "*");
    }
}

fn js_error(e: JsValue) -> JsError {
    JsError::new(&e.as_string().unwrap_or_else(|| format!("{e:?}")))
}
