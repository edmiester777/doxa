//! Routes private to the server crate; `client_pub!` makes them the client's API.

doxa::prelude!();

/// The server's version.
#[get("/api/version")]
pub(crate) async fn version() -> Json<String> {
    Json(env!("CARGO_PKG_VERSION").to_owned())
}
