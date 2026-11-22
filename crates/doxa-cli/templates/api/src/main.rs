use axum::Router;
use doxa::boot::Stopping;

#[doxa::main]
async fn start(stop: Stopping) -> Router {
    __crate___api::server::start(stop).await
}
