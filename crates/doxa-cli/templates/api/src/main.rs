use axum::Router;
use doxa::{dist, MountSpaExt, Spa};

#[doxa::main]
async fn start() -> Router {
    __crate___api::server::app().mount_spa(Spa::auto(dist!()))
}
