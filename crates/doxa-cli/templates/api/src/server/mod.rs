//! What only the server compiles: `server_only` in Cargo.toml keeps it out of the browser.
//! Its `pub` items, re-exports too (`pub use sqlx::PgPool;`), are in scope in every route file.

use crate::Greeting;

/// The routes' state; this app has none yet.
#[derive(Clone, doxa::State)]
pub struct NoState;

/// Every route, served.
pub fn app() -> axum::Router {
    let (router, _api) = doxa::app(&NoState).split_for_parts();
    router
}

/// The greeting for `name`.
pub fn greet(name: Option<String>) -> Greeting {
    let name = name.unwrap_or_else(|| "world".into());
    Greeting {
        message: format!("Hello, {name}!"),
    }
}
