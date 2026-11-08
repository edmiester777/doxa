//! JS values Rust only passes along: a class made with `new`, plugin functions, and a
//! component and element nested inside a React prop.

use doxa::ui::prelude::*;
use doxa::ui::{npm, react::Render, Js};

#[npm(module = "./ts/interop.tsx")]
extern "js" {
    /// A counter.
    pub type Tally;
    #[npm(constructor)]
    pub fn new(start: u32) -> Tally;
    pub fn bump(this: &Tally) -> u32;
}

#[npm(module = "./ts/interop.tsx", export = "default")]
extern "js" {
    /// Upper-cases its input.
    pub type Shout;
}

#[npm(module = "./ts/interop.tsx", export = "exclaim")]
extern "js" {
    /// Appends a `!`.
    pub type Exclaim;
}

/// What `components.letter` is given.
#[derive(Clone, serde::Deserialize)]
pub struct LetterProps {
    pub letter: String,
    pub index: u32,
}

/// Runs `text` through `plugins`.
#[react(module = "./ts/interop.tsx", export = "Pipeline")]
pub struct Pipeline {
    pub text: String,
    #[react(js)]
    pub plugins: Vec<Js>,
    #[react(component, rename = "components.letter")]
    pub letter: Render<LetterProps>,
    #[react(element, rename = "icons.done")]
    pub done: View,
}

/// Each interop path, for the browser check.
#[page("/interop")]
pub fn InteropPage() -> View {
    let bumped = state(0u32);
    let loud = state(false);
    let mut plugins: Vec<Js> = vec![Exclaim::get().into()];
    if loud.get() {
        plugins.insert(0, Shout::get().into());
    }
    view! {
        <button id="bump" on:click={move |_| bumped.set(bump(&Tally::new(41)))}>"bump"</button>
        <p id="bumped">{bumped.get()}</p>
        <button id="loud" on:click={move |_| loud.toggle()}>"loud"</button>
        <Pipeline
            text="ok"
            plugins={plugins}
            letter={|p: LetterProps| view! {
                <b class="letter">{format!("{}:{}", p.index, p.letter)}</b>
            }}
            done={view! { <i class="tick">"done"</i> }}
        />
    }
}
