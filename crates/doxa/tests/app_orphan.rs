//! A handler under no service stops the app, naming it.

#[derive(Clone, doxa::State)]
struct NoState;

mod widgets {
    #[doxa::service]
    pub struct Widgets;

    #[doxa::get("/widgets")]
    async fn list() -> &'static str {
        "[]"
    }
}

#[doxa::get("/health")]
async fn health() -> &'static str {
    "ok"
}

#[test]
#[should_panic(expected = "`app_orphan::health` is under no service")]
fn a_handler_outside_every_service_is_named() {
    doxa::spec();
}
