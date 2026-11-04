//! Widgets: routes, DTOs and errors, shared by the server and the browser.

pub mod widgets;

doxa::client_pub! {
    mod meta;
}

doxa::prelude!();

doxa::server_only! {
    pub mod store;

    /// Every widget route.
    #[doxa::service]
    pub struct Widgets;
}
