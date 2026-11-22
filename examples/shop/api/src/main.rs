use axum::Router;
use doxa::boot::Stopping;

#[doxa::main]
async fn start(stop: Stopping) -> Router {
    shop_api::server::start(stop).await
}
