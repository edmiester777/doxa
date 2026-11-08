//! Icons both ways: SVG files compiled into the wasm, and a React module's exports as islands.

use doxa::ui::icons;
use doxa::ui::prelude::*;

/// Drawn by doxa from `assets/icons/*.svg`.
#[icons(dir = "./assets/icons")]
pub enum Glyph {
    Plus,
    Trash2,
}

/// Rendered by React from `ts/glyphs.tsx`.
#[react(module = "./ts/glyphs.tsx")]
pub enum Drawn {
    Plus,
    #[react(export = "Minus")]
    Less,
}

/// Every icon, for the browser check.
#[page("/icons")]
pub fn IconsPage() -> View {
    view! {
        <p id="svg">
            {Glyph::Plus}
            {Glyph::Trash2.size(16).class("danger")}
        </p>
        <p id="react">
            {Drawn::Plus.size(20)}
            {Drawn::Less}
        </p>
    }
}
