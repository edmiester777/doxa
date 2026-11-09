//! The gallery's page: the story tree, the canvas and its toolbar, and the source panel.

use std::rc::Rc;
use std::time::Duration;

use super::highlight::highlight;
use super::model::{
    folders, human, story_url, tree_rows, visible, Initial, Message, Row, StoryMeta, Viewport,
};
use crate::clipboard::{self, Clip};
use crate::prelude::*;
use crate::ElementRef;

/// A pane edge being dragged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Axis {
    Side,
    Panel,
}

/// The gallery around `entries`, starting where `initial` says.
#[component]
pub fn Gallery(entries: Vec<StoryMeta>, initial: Initial) -> View {
    let first = visible(&tree_rows(&entries, "", &[])).into_iter().next();
    let known = initial
        .story
        .clone()
        .filter(|s| entries.iter().any(|e| &e.name == s));
    let story = state(known.or(first));
    let dark = state(initial.dark);
    let viewport = state(initial.viewport);
    let remount = state(0u64);
    let query = state(String::new());
    let copied = state(false);
    let dragging = state(None::<Axis>);
    // The phone layout's drawers: the story tree, and the panel.
    let menu = state(false);
    let sheet = state(false);
    let panel_open = stored("doxa-gallery:panel-open", || true);
    let side = stored("doxa-gallery:side", || 248.0f64);
    let panel = stored("doxa-gallery:panel", || 260.0f64);
    let closed = stored("doxa-gallery:closed", Vec::<String>::new);
    let search = node_ref();
    let frame = node_ref();
    let main = node_ref();

    let current = story.get();
    let meta = current
        .as_ref()
        .and_then(|n| entries.iter().find(|e| &e.name == n))
        .cloned();
    // The phone bar's label: the folders too, while that stays short.
    let full_name = match &meta {
        Some(m) => {
            let name = human(&m.name);
            let mut parts: Vec<String> = folders(m, &entries).iter().map(|p| human(p)).collect();
            parts.push(name.clone());
            let full = parts.join(" / ");
            if full.chars().count() < 24 {
                full
            } else {
                name
            }
        }
        None => "No story".to_owned(),
    };
    title(match &current {
        Some(n) => format!("{} · Stories", human(n)),
        None => "Stories".to_owned(),
    });
    let url = Initial {
        story: current.clone(),
        dark: dark.get(),
        viewport: viewport.get(),
    }
    .query();
    effect(&url, async move |url: &String| replace_url(url));

    let select = move |name: String| {
        menu.set(false);
        if story.get().as_ref() != Some(&name) {
            story.set(Some(name));
        }
    };
    let flip_theme = move || dark.toggle();
    let reload = move || remount.update(|n| *n += 1);
    let flip_panel = move || panel_open.set(!panel_open.get());
    let shut = move || {
        menu.set(false);
        sheet.set(false);
    };

    let shortcut = {
        let entries = entries.clone();
        Rc::new(move |key: &str| -> bool {
            let step = |d: isize| {
                let shown = visible(&tree_rows(&entries, &query.get(), &closed.get()));
                let at = story
                    .get()
                    .and_then(|s| shown.iter().position(|n| *n == s))
                    .map_or(0, |i| i as isize + d);
                let at = at.clamp(0, shown.len() as isize - 1);
                if let Some(next) = shown.get(at as usize) {
                    select(next.clone());
                }
            };
            match key {
                "/" => search.get().into_iter().for_each(|s| s.focus()),
                "Escape" if menu.get() || sheet.get() => shut(),
                "Escape" if !query.with(String::is_empty) => query.set(String::new()),
                "ArrowDown" | "j" => step(1),
                "ArrowUp" | "k" => step(-1),
                "t" => flip_theme(),
                "r" => reload(),
                "p" => flip_panel(),
                _ => return false,
            }
            true
        })
    };
    {
        let shortcut = shortcut.clone();
        window_event("keydown", move |e: Event| {
            let typing = e.target_ref().is_some_and(|t| t.is_editable());
            if e.meta_key() || e.ctrl_key() || e.alt_key() || typing {
                return;
            }
            if shortcut(&e.key()) {
                e.prevent_default();
            }
        });
    }
    window_event("message", move |e: Event| {
        if !from_frame(frame, &e) {
            return;
        }
        if let Some(Message::Key { key }) = message(&e) {
            shortcut(&key);
        }
    });

    let drag = move |axis: Axis| {
        move |e: Event| {
            e.prevent_default();
            capture(&e);
            dragging.set(Some(axis));
        }
    };
    let moved = move |e: Event| match dragging.get() {
        Some(Axis::Side) => side.set(e.client_x().clamp(180.0, 480.0)),
        Some(Axis::Panel) => {
            if let Some(r) = main.get().and_then(|m| m.rect()) {
                let h = r.y + r.height - e.client_y();
                panel.set(h.clamp(120.0, (r.height - 120.0).max(120.0)));
            }
        }
        None => {}
    };
    let dropped = move || dragging.set(None);

    let q = query.get();
    let rows = tree_rows(&entries, &q, &closed.get());
    let tree = if rows.is_empty() {
        let note = if entries.is_empty() {
            "No stories yet."
        } else {
            "No stories match."
        };
        view! { <div class="empty-tree">{note}</div> }
    } else {
        rows.into_iter()
            .map(|row| match row {
                Row::Dir { id, label, depth, open } => view! {
                    <button
                        class={if open { "row dir open" } else { "row dir" }}
                        style={format!("padding-left:{}px", 8 + depth * 14)}
                        aria-expanded={open.to_string()}
                        on:click={move || {
                            closed
                                .update(|c| {
                                    if let Some(i) = c.iter().position(|x| *x == id) {
                                        c.remove(i);
                                    } else {
                                        c.push(id.clone());
                                    }
                                })
                        }}
                    >
                        <span class="chev">{icon("chevron")}</span>
                        {label}
                    </button>
                },
                Row::Leaf { name, label, depth } => {
                    let active = current.as_ref() == Some(&name);
                    view! {
                        <button
                            class="row leaf"
                            class:active={active}
                            role="treeitem"
                            aria-selected={active.to_string()}
                            data-story={name.clone()}
                            style={format!("padding-left:{}px", 8 + depth * 14 + if depth > 0 { 6 } else { 0 })}
                            on:click={move || select(name.clone())}
                        >
                            {icon("story")}
                            <span>{marked(&label, &q)}</span>
                        </button>
                    }
                }
            })
            .collect::<View>()
    };

    let count = entries.len();
    let sidebar = view! {
        <aside class="side">
            <div class="brand">
                <span class="logo">"d"</span>
                "doxa"
                <small>"stories"</small>
                <button
                    class="tool close"
                    title="Close"
                    aria-label="Close the story list"
                    on:click={move || menu.set(false)}
                >
                    {icon("close")}
                </button>
            </div>
            <label class="search">
                {icon("search")}
                <input
                    ref={search}
                    type="search"
                    placeholder="Find stories"
                    aria-label="Find stories"
                    spellcheck="false"
                    bind:value={query}
                    on:keydown={{
                        let entries = entries.clone();
                        move |e: Event| match e.key().as_str() {
                            "Escape" => {
                                query.set(String::new());
                                search.get().into_iter().for_each(|s| s.blur());
                            }
                            "Enter" => {
                                let shown = visible(&tree_rows(&entries, &query.get(), &closed.get()));
                                if let Some(first) = shown.into_iter().next() {
                                    select(first);
                                    search.get().into_iter().for_each(|s| s.blur());
                                }
                            }
                            _ => {}
                        }
                    }}
                />
                <kbd>"/"</kbd>
            </label>
            <div class="tree" role="tree">{tree}</div>
            <div class="foot">
                {format!("{count} {}", if count == 1 { "story" } else { "stories" })}
                <span class="grow"/>
                <span>
                    <kbd>"↑"</kbd>
                    " "
                    <kbd>"↓"</kbd>
                    " to move"
                </span>
            </div>
            <div
                class="resize-x"
                class:on={dragging.get() == Some(Axis::Side)}
                title="Drag to resize"
                on:pointerdown={drag(Axis::Side)}
                on:pointermove={moved}
                on:pointerup={move || dropped()}
                on:pointercancel={move || dropped()}
            />
        </aside>
    };

    let crumb = view! {
        <div class="crumb">
            {meta.iter().flat_map(|m| folders(m, &entries)).map(|p| view! {
                {human(&p)}
                <span>"/"</span>
            }).collect::<View>()}
            <b>{current.as_deref().map_or_else(|| "No story".to_owned(), human)}</b>
        </div>
    };
    let size = viewport.get().size();
    let open_url = current
        .as_deref()
        .map(|n| story_url(n, dark.get(), 0))
        .unwrap_or_default();
    let toolbar = view! {
        <div class="bar">
            {crumb}
            <span class="grow"/>
            {size.map(|(w, h)| view! { <span class="dims">{format!("{w} × {h}")}</span> })}
            {Viewport::ALL.into_iter().map(|v| {
                let tip = match v.size() {
                    Some((w, h)) => format!("{} · {w}×{h}", v.label()),
                    None => "Fill the canvas".to_owned(),
                };
                view! {
                    <button
                        class="tool"
                        class:on={viewport.get() == v}
                        title={tip.clone()}
                        aria-label={tip}
                        on:click={move || viewport.set(v)}
                    >
                        {icon(v.key())}
                    </button>
                }
            }).collect::<View>()}
            <span class="sep"/>
            <button
                class="tool"
                title={format!("Story theme: {} (T)", if dark.get() { "dark" } else { "light" })}
                aria-label="Story theme"
                on:click={move || flip_theme()}
            >
                {icon(if dark.get() { "moon" } else { "sun" })}
            </button>
            <button
                class="tool"
                title="Remount the story (R)"
                aria-label="Remount the story"
                on:click={move || reload()}
            >
                {icon("reload")}
            </button>
            <a
                class="tool"
                href={SafeUrl::parse(&open_url).unwrap_or_else(|| SafeUrl::literal("?"))}
                target="_blank"
                title="Open the story alone"
                aria-label="Open the story alone"
            >
                {icon("external")}
            </a>
            <span class="sep wide"/>
            <button
                class="tool wide"
                class:on={panel_open.get()}
                title="Toggle the panel (P)"
                aria-label="Toggle the panel"
                on:click={move || flip_panel()}
            >
                {icon("panel")}
            </button>
        </div>
    };

    let canvas = match &current {
        Some(name) => {
            let src = story_url(name, dark.get(), remount.get());
            let style = size
                .map(|(w, h)| format!("width:{w}px;height:{h}px"))
                .unwrap_or_default();
            view! {
                <div class="canvas" class:framed={size.is_some()}>
                    <iframe
                        ref={frame}
                        title="Story canvas"
                        class:dark={dark.get()}
                        style={style}
                        src={SafeUrl::parse(&src).unwrap_or_else(|| SafeUrl::literal("?"))}
                    />
                </div>
            }
        }
        None => view! {
            <div class="canvas">
                <div class="empty">
                    {icon("story")}
                    <b>"No stories yet"</b>
                    <span>
                        "Mark a function "
                        <code>"#[story]"</code>
                        " and it shows up here."
                    </span>
                </div>
            </div>
        },
    };

    let body = match meta.filter(|m| !m.source.is_empty()) {
        None => view! {
            <div class="empty">
                {icon("code")}
                <b>"No source"</b>
                <span>"The story's file couldn't be read at build time."</span>
            </div>
        },
        Some(m) => {
            let text = m.source.clone();
            view! {
                <div class="src-head">
                    {icon("story")}
                    {format!("{}:{}", m.file, m.line)}
                    <span class="grow"/>
                    <button
                        class="tool"
                        title="Copy the source"
                        on:click={async move |_| {
                            if clipboard::write(Clip::text(text.clone())).await.is_ok() {
                                copied.set(true);
                                sleep(Duration::from_millis(1400)).await;
                                copied.set(false);
                            }
                        }}
                    >
                        {icon(if copied.get() { "check" } else { "copy" })}
                        {if copied.get() { "Copied" } else { "Copy" }}
                    </button>
                </div>
                <pre class="src">
                    <code>{source_lines(&m.source)}</code>
                </pre>
            }
        }
    };
    let tabs = view! {
        <div class="tabs">
            <span class="tab">
                {icon("code")}
                "Source"
            </span>
            <span class="grow"/>
            <button
                class="tool close"
                title="Close"
                aria-label="Close the panel"
                on:click={move || sheet.set(false)}
            >
                {icon("close")}
            </button>
        </div>
    };
    let mobile_bar = view! {
        <nav class="mnav" aria-label="Navigation controls">
            <button
                class="tool who"
                aria-label="Open the story list"
                aria-expanded={menu.get().to_string()}
                on:click={move || menu.set(true)}
            >
                {icon("menu")}
                <span>{full_name}</span>
            </button>
            <button
                class="tool"
                aria-label="Open the panel"
                aria-expanded={sheet.get().to_string()}
                on:click={move || sheet.set(true)}
            >
                {icon("panel")}
            </button>
        </nav>
        <div class="scrim" on:click={move || shut()}/>
    };
    let lower = view! {
        <div
            class="resize-y"
            class:on={dragging.get() == Some(Axis::Panel)}
            title="Drag to resize"
            on:pointerdown={drag(Axis::Panel)}
            on:pointermove={moved}
            on:pointerup={move || dropped()}
            on:pointercancel={move || dropped()}
        />
        <section class="panel">
            {tabs}
            <div class="body">{body}</div>
        </section>
    };

    let axis = dragging.get();
    view! {
        <div
            class="app"
            class:panel-open={panel_open.get()}
            class:menu={menu.get()}
            class:sheet={sheet.get()}
            class:dragging={axis.is_some()}
            class:x={axis == Some(Axis::Side)}
            class:y={axis == Some(Axis::Panel)}
            style={format!("--side:{}px;--panel:{}px", side.get(), panel.get())}
        >
            {sidebar}
            <main class="main" ref={main}>
                {toolbar}
                {canvas}
                {lower}
            </main>
            {mobile_bar}
        </div>
    }
}

fn source_lines(src: &str) -> View {
    highlight(src)
        .into_iter()
        .map(|line| {
            let tokens = line
                .into_iter()
                .map(|(class, text)| match class {
                    Some(c) => view! { <span class={c}>{text}</span> },
                    None => text.into_view(),
                })
                .collect::<View>();
            view! { <span class="l">{tokens}</span> }
        })
        .collect()
}

/// `label` with the first match of `query` marked.
fn marked(label: &str, query: &str) -> View {
    let q = query.trim().to_lowercase();
    match (!q.is_empty())
        .then(|| label.to_lowercase().find(&q))
        .flatten()
    {
        Some(i) if label.is_char_boundary(i) && label.is_char_boundary(i + q.len()) => view! {
            {&label[..i]}
            <mark>{&label[i..i + q.len()]}</mark>
            {&label[i + q.len()..]}
        },
        _ => label.into_view(),
    }
}

fn icon(name: &str) -> View {
    match name {
        "search" => {
            view! {
                <svg class="i" viewBox="0 0 24 24">
                    <circle cx="11" cy="11" r="7"/>
                    <path d="m20 20-3.5-3.5"/>
                </svg>
            }
        }
        "chevron" => view! {
            <svg class="i" viewBox="0 0 24 24">
                <path d="m9 6 6 6-6 6"/>
            </svg>
        },
        "story" => {
            view! {
                <svg class="i" viewBox="0 0 24 24">
                    <path d="M7 3h10a1 1 0 0 1 1 1v17l-6-4-6 4V4a1 1 0 0 1 1-1z"/>
                </svg>
            }
        }
        "sun" => {
            view! {
                <svg class="i" viewBox="0 0 24 24">
                    <circle cx="12" cy="12" r="4"/>
                    <path
                        d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"
                    />
                </svg>
            }
        }
        "moon" => {
            view! {
                <svg class="i" viewBox="0 0 24 24">
                    <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>
                </svg>
            }
        }
        "reload" => {
            view! {
                <svg class="i" viewBox="0 0 24 24">
                    <path d="M21 12a9 9 0 1 1-3-6.7L21 8"/>
                    <path d="M21 3v5h-5"/>
                </svg>
            }
        }
        "external" => {
            view! {
                <svg class="i" viewBox="0 0 24 24">
                    <path d="M14 4h6v6M20 4 10 14"/>
                    <path d="M19 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h5"/>
                </svg>
            }
        }
        "phone" => {
            view! {
                <svg class="i" viewBox="0 0 24 24">
                    <rect x="7" y="2" width="10" height="20" rx="2"/>
                    <path d="M11 18h2"/>
                </svg>
            }
        }
        "tablet" => {
            view! {
                <svg class="i" viewBox="0 0 24 24">
                    <rect x="4" y="2" width="16" height="20" rx="2"/>
                    <path d="M11 18h2"/>
                </svg>
            }
        }
        "desktop" => {
            view! {
                <svg class="i" viewBox="0 0 24 24">
                    <rect x="2" y="4" width="20" height="13" rx="2"/>
                    <path d="M8 21h8M12 17v4"/>
                </svg>
            }
        }
        "full" => {
            view! {
                <svg class="i" viewBox="0 0 24 24">
                    <path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/>
                </svg>
            }
        }
        "panel" => {
            view! {
                <svg class="i" viewBox="0 0 24 24">
                    <rect x="3" y="3" width="18" height="18" rx="2"/>
                    <path d="M3 15h18"/>
                </svg>
            }
        }
        "copy" => {
            view! {
                <svg class="i" viewBox="0 0 24 24">
                    <rect x="9" y="9" width="12" height="12" rx="2"/>
                    <path d="M5 15V5a2 2 0 0 1 2-2h8"/>
                </svg>
            }
        }
        "check" => view! {
            <svg class="i" viewBox="0 0 24 24">
                <path d="m5 12 5 5 9-10"/>
            </svg>
        },
        "menu" => view! {
            <svg class="i" viewBox="0 0 24 24">
                <path d="M4 7h16M4 12h16M4 17h16"/>
            </svg>
        },
        "close" => view! {
            <svg class="i" viewBox="0 0 24 24">
                <path d="M6 6l12 12M18 6 6 18"/>
            </svg>
        },
        _ => {
            view! {
                <svg class="i" viewBox="0 0 24 24">
                    <path d="m8 8-4 4 4 4M16 8l4 4-4 4"/>
                </svg>
            }
        }
    }
}

fn replace_url(query: &str) {
    #[cfg(target_arch = "wasm32")]
    if let Some(history) = web_sys::window().and_then(|w| w.history().ok()) {
        let _ = history.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(query));
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = query;
}

/// Whether `e` is a message from the story frame.
fn from_frame(frame: ElementRef, e: &Event) -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        let window = frame
            .get()
            .and_then(|f| f.as_element::<web_sys::HtmlIFrameElement>())
            .and_then(|f| f.content_window());
        match (
            e.as_::<web_sys::MessageEvent>().and_then(|m| m.source()),
            window,
        ) {
            (Some(source), Some(window)) => js_sys::Object::is(&source, &window),
            _ => false,
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (frame, e);
        false
    }
}

fn message(e: &Event) -> Option<Message> {
    #[cfg(target_arch = "wasm32")]
    {
        let text = e.as_::<web_sys::MessageEvent>()?.data().as_string()?;
        serde_json::from_str(&text).ok()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = e;
        None
    }
}

/// Keep the pointer's events on the drag handle until it is released.
fn capture(e: &Event) {
    #[cfg(target_arch = "wasm32")]
    if let (Some(p), Some(t)) = (
        e.as_::<web_sys::PointerEvent>(),
        e.target_ref()
            .and_then(|t| t.as_element::<web_sys::Element>()),
    ) {
        let _ = t.set_pointer_capture(p.pointer_id());
    }
    #[cfg(not(target_arch = "wasm32"))]
    let _ = e;
}
