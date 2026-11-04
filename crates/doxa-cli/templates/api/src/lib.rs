//! Routes and DTOs, shared by the server and the browser.

pub mod greeting;

doxa::server_only! {
    /// The routes' state; this app has none yet.
    #[derive(Clone, doxa::State)]
    pub struct NoState;

    /// Every route.
    #[doxa::service]
    pub struct App;
}
