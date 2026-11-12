//! Streaming tokens into the last of many keyed messages: DOM changes and time per delta.

use std::rc::Rc;
use std::time::Instant;

use doxa::ui::dom::MemDom;
use doxa::ui::prelude::*;

type Messages = State<Vec<(u32, String)>>;

thread_local! {
    static CHAT: std::cell::RefCell<Option<Messages>> = const { std::cell::RefCell::new(None) };
}

#[component]
fn Chat() -> View {
    let messages = state(
        (0..500)
            .map(|i| (i, format!("message {i}")))
            .collect::<Vec<_>>(),
    );
    CHAT.with(|c| *c.borrow_mut() = Some(messages));
    view! {
        <ul>
            {messages.get().into_iter().map(|(id, text)| view! {
                <li key={id} class="msg">
                    <p>{text}</p>
                </li>
            }).collect::<View>()}
        </ul>
    }
}

fn run(deltas: usize) -> (f64, f64) {
    let dom = MemDom::new();
    App::new(|| view! { <Chat/> })
        .mount_on(Rc::new(dom.clone()), dom.body())
        .keep();
    doxa::client::task::run_until_stalled();
    let chat = CHAT.with(|c| c.borrow().unwrap());
    let before = dom.ops();
    let start = Instant::now();
    for i in 0..deltas {
        chat.update(|m| m.last_mut().unwrap().1.push_str(&format!(" tok{i}")));
        doxa::client::task::run_until_stalled();
    }
    let per = start.elapsed().as_secs_f64() * 1e6 / deltas as f64;
    let ops = (dom.ops() - before) as f64 / deltas as f64;
    (ops, per)
}

#[test]
fn a_delta_to_one_keyed_message_changes_one_text_node() {
    let (ops, _) = run(20);
    assert_eq!(ops, 1.0, "the other 499 messages cost no DOM changes");
}

/// `cargo test -p doxa --features ui --release --test stream_bench -- --ignored --nocapture`
#[test]
#[ignore = "a benchmark; run with --ignored --nocapture"]
fn two_thousand_deltas_into_five_hundred_messages() {
    let (ops, micros) = run(2000);
    println!("2000 deltas, 500 keyed messages: {ops:.2} DOM ops and {micros:.1} µs per delta");
}
