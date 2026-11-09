//! The shop: every route, served off wasm and called from the browser.

pub mod orders;
pub mod widgets;

doxa::prelude!();

/// The version route, and what the caller may do at `GET /doxa/capabilities`.
#[doxa::service(layers = caller)]
pub struct Shop;

/// The server's version.
#[get("/api/version")]
pub async fn version() -> Json<String> {
    Json(env!("CARGO_PKG_VERSION").to_owned())
}
