use doxa::{dist, routes, MountSpaExt, OpenApiRouter, Spa};
use {{crate}}_api::greeting::*;

#[tokio::main]
async fn main() {
    let (router, _api) = OpenApiRouter::<()>::new()
        .routes(routes!(greeting))
        .split_for_parts();
    let app = router.mount_spa(Spa::auto(dist!()));

    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".into());
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
