//! A plain JS module, bound once and called like Rust.

use doxa::ui::prelude::*;
use doxa::ui::{npm, JsError};

/// How loud to shout.
#[derive(serde::Serialize)]
pub struct Shout {
    pub times: u32,
}

/// What `later` answers.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct Measured {
    pub word: String,
    pub length: u32,
}

#[npm(module = "./ts/words.js")]
extern "js" {
    /// `word`, upper-cased and repeated.
    pub fn shout(word: &str, opts: &Shout) -> String;
    /// A word and its length, a tick later.
    pub async fn later(word: &str) -> Result<Measured, JsError>;
    /// Always throws.
    pub fn refuse() -> Result<(), JsError>;
}

#[npm(module = "./ts/words.js", lazy)]
extern "js" {
    /// `later`, from a chunk fetched on first call.
    #[npm(export = "later")]
    pub async fn later_lazily(word: &str) -> Result<Measured, JsError>;
}

/// Each binding's answer, for the browser check.
#[page("/words")]
pub async fn WordsPage() -> Result<View> {
    let loud = shout("hi", &Shout { times: 2 });
    let measured = later("gear").await?;
    let lazily = later_lazily("cog").await?;
    let refused = refuse().unwrap_err().to_string();
    Ok(view! {
        <p id="loud">{loud}</p>
        <p id="later">{format!("{} {}", measured.word, measured.length)}</p>
        <p id="lazily">{format!("{} {}", lazily.word, lazily.length)}</p>
        <p id="refused">{refused}</p>
    })
}
