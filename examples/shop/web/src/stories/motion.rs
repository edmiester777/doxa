//! `use:` directives: a FLIP slide on reorder and an exit animation on removal.

use doxa::ui::prelude::*;
use doxa::ui::story;

use crate::motion::{exit, flip};

const START: [&str; 5] = ["sprocket", "gear", "cog", "flange", "spindle"];

/// Reverse, rotate or drop rows: each one slides to its new place and fades as it leaves.
#[story]
pub fn reorder_and_remove() -> View {
    let items = state(START.to_vec());
    view! {
        <figure class="card">
            <p class="eyebrow">"use:flip · use:exit"</p>
            <div class="actions">
                <button class="btn" on:click={move |_| items.update(|v| v.reverse())}>
                    "Reverse"
                </button>
                <button class="btn" on:click={move |_| items.update(|v| v.rotate_left(1))}>
                    "Rotate"
                </button>
                <button
                    class="btn ghost"
                    on:click={move |_| {
                        items
                            .update(|v| {
                                v.pop();
                            })
                    }}
                >
                    "Drop last"
                </button>
                <button class="btn ghost" on:click={move |_| items.set(START.to_vec())}>
                    "Reset"
                </button>
            </div>
            <ul class="stack">
                {items.get().iter().map(|&w| view! {
                    <li key={w} use:flip use:exit={"leaving"}>{w}</li>
                }).collect::<View>()}
            </ul>
        </figure>
    }
}
