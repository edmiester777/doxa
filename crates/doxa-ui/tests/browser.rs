//! The renderer in a real document. Run with `wasm-bindgen-test-runner` as the
//! wasm32 test runner; every step shares one page, so it is one test.
#![cfg(target_arch = "wasm32")]

use doxa::ui::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

thread_local! {
    static ORDER: std::cell::RefCell<Vec<u32>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[component]
fn Item(id: u32) -> View {
    view! { <li id={format!("item-{id}")}>{id}</li> }
}

#[component]
fn Page() -> View {
    let n = state(1);
    let draft = state(String::new());
    let ids = ORDER.with(|o| o.borrow().clone());
    view! {
        <button id="count" on:click={move |_| n.update(|n| *n += 1)}>{n.get()}</button>
        <input id="draft" bind:value={draft}/>
        <p id="echo">{draft.get()}</p>
        <ul>{ids.iter().map(|&id| view! { <Item key={id} id={id}/> }).collect::<View>()}</ul>
    }
}

fn document() -> web_sys::Document {
    web_sys::window().unwrap().document().unwrap()
}

fn by_id(id: &str) -> web_sys::HtmlElement {
    document()
        .get_element_by_id(id)
        .unwrap()
        .dyn_into()
        .unwrap()
}

/// Let the executor and the browser run everything queued.
async fn settle() {
    let tick = js_sys::Promise::new(&mut |resolve, _| {
        web_sys::window()
            .unwrap()
            .set_timeout_with_callback(&resolve)
            .unwrap();
    });
    wasm_bindgen_futures::JsFuture::from(tick).await.unwrap();
}

#[wasm_bindgen_test]
async fn a_page_renders_patches_and_reorders_in_the_document() {
    let root = document().create_element("div").unwrap();
    root.set_id("root");
    document().body().unwrap().append_child(&root).unwrap();
    ORDER.with(|o| *o.borrow_mut() = vec![1, 2, 3]);
    App::new(|| view! { <Page/> }).mount("#root");
    settle().await;

    let count = by_id("count");
    count.click();
    settle().await;
    assert_eq!(by_id("count").text_content().unwrap(), "2");
    assert!(
        by_id("count").is_same_node(Some(&count)),
        "patched in place"
    );

    let input: web_sys::HtmlInputElement = by_id("draft").dyn_into().unwrap();
    input.set_value("bolt");
    input
        .dispatch_event(&web_sys::Event::new("input").unwrap())
        .unwrap();
    settle().await;
    assert_eq!(by_id("echo").text_content().unwrap(), "bolt");
    assert!(
        by_id("draft").is_same_node(Some(&input)),
        "the input survives a re-render"
    );

    js_sys::eval(
        "const el = document.getElementById('draft');
         const value = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
         window.valueWrites = 0;
         Object.defineProperty(el, 'value', {
             configurable: true,
             get() { return value.get.call(el); },
             set(next) { window.valueWrites++; value.set.call(el, next); },
         });",
    )
    .unwrap();
    input
        .dispatch_event(&web_sys::Event::new("input").unwrap())
        .unwrap();
    settle().await;
    by_id("count").click();
    settle().await;
    assert_eq!(
        js_sys::eval("window.valueWrites").unwrap().as_f64(),
        Some(0.0),
        "a value the input already holds isn't written back"
    );
    js_sys::eval("delete document.getElementById('draft').value").unwrap();

    let three = by_id("item-3");
    ORDER.with(|o| *o.borrow_mut() = vec![3, 1, 2]);
    by_id("count").click();
    settle().await;
    let ul = document().query_selector("ul").unwrap().unwrap();
    assert_eq!(ul.text_content().unwrap(), "312");
    assert!(
        by_id("item-3").is_same_node(Some(&three)),
        "a keyed child moves"
    );

    let second = document().create_element("div").unwrap();
    second.set_id("elements");
    document().body().unwrap().append_child(&second).unwrap();
    App::new(|| view! { <Elements/> }).mount("#elements");
    settle().await;

    by_id("probe").click();
    settle().await;
    assert_eq!(
        probed(),
        [
            "top 120 of 500 in 50",
            "end 450",
            "found 7",
            "ancestor scroller",
            "editable true false",
        ]
    );

    let foreign = document().create_element("em").unwrap();
    by_id("hit").append_child(&foreign).unwrap();
    foreign
        .dyn_ref::<web_sys::EventTarget>()
        .unwrap()
        .dispatch_event(
            &js_sys::eval("new MouseEvent('click', {bubbles: true})")
                .unwrap()
                .unchecked_into(),
        )
        .unwrap();
    settle().await;
    assert_eq!(
        probed(),
        ["target inside hit"],
        "a node doxa didn't place still answers `closest`"
    );

    js_sys::eval(
        "document.getElementById('inner').dispatchEvent(
             new FocusEvent('blur', {relatedTarget: document.getElementById('probe')}))",
    )
    .unwrap();
    settle().await;
    assert_eq!(probed(), ["moving to probe"]);
}

thread_local! {
    static PROBED: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn note(line: impl Into<String>) {
    PROBED.with(|p| p.borrow_mut().push(line.into()));
}

fn probed() -> Vec<String> {
    PROBED.with(|p| p.take())
}

#[component]
fn Elements() -> View {
    let scroller = node_ref();
    view! {
        <div ref={scroller} id="scroller" style="height:50px;overflow:auto">
            <div style="height:500px">
                <input
                    id="inner"
                    on:blur={|e: Event| {
                        let to = e.related_target().and_then(|n| n.attr("id"));
                        note(format!("moving to {}", to.unwrap_or_default()));
                    }}
                />
                <span
                    id="hit"
                    class="hit"
                    data-n="7"
                    on:click={|e: Event| {
                        let within = e.target().and_then(|n| n.closest("[data-n]"));
                        let id = within.and_then(|n| n.attr("id"));
                        note(format!("target inside {}", id.unwrap_or_default()));
                    }}
                />
            </div>
        </div>
        <button
            id="probe"
            on:click={move || {
                let el = scroller.get().expect("mounted");
                el.scroll_to(120.0, false);
                let at = el.scroll();
                note(format!("top {} of {} in {}", at.top, at.height, at.client_height));
                el.scroll_to_end(false);
                note(format!("end {}", el.scroll().top));
                let hit = el.query("span.hit[data-n=\"7\"]").expect("hit");
                note(format!("found {}", hit.attr("data-n").unwrap_or_default()));
                let inner = el.query_all("input").pop().expect("input");
                let up = inner.closest("[style]").and_then(|n| n.closest("#scroller"));
                note(format!("ancestor {}", up.and_then(|n| n.attr("id")).unwrap_or_default()));
                note(format!("editable {} {}", inner.is_editable(), hit.is_editable()));
            }}
        />
    }
}
