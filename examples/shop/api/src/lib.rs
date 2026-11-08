//! The shop's API: every route `shop-server` serves and `shop-web` calls, declared once.

pub mod orders;
pub mod widgets;

doxa::prelude!();

/// The server's version.
#[get("/api/version")]
pub async fn version() -> Json<String>;
