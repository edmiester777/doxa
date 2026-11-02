//! Widgets: routes, DTOs and errors, shared by the server and the browser.

pub mod widgets;

doxa::service!();

doxa::server_only! {
    pub mod store;
}
