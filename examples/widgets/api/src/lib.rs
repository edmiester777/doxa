//! Widgets: routes, DTOs and errors, shared by the server and the browser.

pub mod widgets;

doxa::client_pub! {
    mod meta;
}

doxa::service!();

doxa::server_only! {
    pub mod store;

    /// The routes in modules only this crate can name.
    pub fn meta_routes<S: Clone + Send + Sync + 'static>() -> doxa::OpenApiRouter<S> {
        doxa::OpenApiRouter::new().routes(doxa::routes!(meta::version))
    }
}
