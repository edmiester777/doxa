//! Two services in one module stop the app, naming both.

#[derive(Clone, doxa::State)]
struct NoState;

#[doxa::service]
pub struct Public;

#[doxa::service]
pub struct Private;

#[doxa::get("/health")]
async fn health() -> &'static str {
    "ok"
}

#[test]
#[should_panic(expected = "`Private` and `Public` are both services of `app_services`")]
fn two_services_in_a_module_are_named() {
    doxa::spec();
}
