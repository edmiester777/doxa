//! React and npm modules used from Rust, and Rust handed to React.

use doxa::ui::prelude::*;
use doxa::ui::{story, Js};

use crate::icons::{Drawn, Glyph};
use crate::interop::{bump, bump_lazy, Exclaim, LazyTally, LetterProps, Pipeline, Shout, Tally};

/// A star rating drawn by React.
#[react(module = "./ts/stars.tsx", export = "Stars")]
pub struct Stars {
    pub value: u8,
    pub max: u8,
    #[react(event)]
    pub on_rate: impl Fn(u8),
}

/// A React component over a Rust signal: each pick comes back through `on_rate`.
#[story]
pub fn react_star_rating() -> View {
    let value = state(3u8);
    view! {
        <figure class="card">
            <p class="eyebrow">"React component · Rust state"</p>
            <h3>"How's the gear?"</h3>
            <Stars value={value.get()} max={5} on_rate={move |n: u8| value.set(n)}/>
            <figcaption class="muted">
                {format!("{} of 5, kept in a Rust signal", value.get())}
            </figcaption>
        </figure>
    }
}

/// Rust inside React: `Pipeline` runs the JS plugins Rust chose, then draws each letter with
/// the Rust closure in `letter` and ends with the Rust view in `done`.
#[story]
pub fn react_plugin_pipeline() -> View {
    let loud = state(false);
    let mut plugins: Vec<Js> = vec![Exclaim::get().into()];
    if loud.get() {
        plugins.insert(0, Shout::get().into());
    }
    view! {
        <figure class="card">
            <p class="eyebrow">"Rust components inside React props"</p>
            <button
                class="toggle"
                aria-pressed={loud.get().to_string()}
                on:click={move |_| loud.toggle()}
            >
                "Shout plugin"
            </button>
            <Pipeline
                text="doxa"
                plugins={plugins}
                letter={|p: LetterProps, children: View| view! {
                    <span class="tile" data-index={p.index.to_string()}>{children}</span>
                }}
                done={view! { <span class="pill">"✓ drawn by Rust"</span> }}
            />
        </figure>
    }
}

/// A JS class Rust builds with `new`, and the same class from a chunk fetched on first use.
#[story]
pub fn classes_from_npm() -> View {
    let count = state(0u32);
    let lazy = state(None::<u32>);
    effect((), async move |_| {
        lazy.set(Some(bump_lazy(&LazyTally::new(9).await?)));
        Ok(())
    });
    view! {
        <figure class="card">
            <p class="eyebrow">"npm classes, eager and lazy"</p>
            <div class="stat">
                <span class="big">{count.get()}</span>
                <button class="btn" on:click={move |_| count.set(bump(&Tally::new(count.get())))}>
                    <code>"new Tally(n).bump()"</code>
                </button>
            </div>
            <p class="muted">
                {match lazy.get() {
                    Some(n) => format!("Lazy chunk loaded · new Tally(9).bump() = {n}"),
                    None => "Fetching the lazy chunk…".to_owned(),
                }}
            </p>
        </figure>
    }
}

/// Icons two ways: SVG files compiled into the wasm, and a React module's exports.
#[story]
pub fn icons_two_ways() -> View {
    view! {
        <figure class="card">
            <p class="eyebrow">"#[icons] · #[react] enum"</p>
            <div class="icons">
                <span>
                    {Glyph::Plus.size(28)}
                    <small>"SVG · Plus"</small>
                </span>
                <span>
                    {Glyph::Trash2.size(28)}
                    <small>"SVG · Trash2"</small>
                </span>
                <span>
                    {Drawn::Plus.size(28)}
                    <small>"React · Plus"</small>
                </span>
                <span>
                    {Drawn::Less.size(28)}
                    <small>"React · Minus"</small>
                </span>
            </div>
        </figure>
    }
}
