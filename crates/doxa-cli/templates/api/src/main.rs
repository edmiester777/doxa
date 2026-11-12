use doxa::{dist, MountSpaExt, Spa};

#[tokio::main]
async fn main() {
    let app = {{crate}}_api::server::app().mount_spa(Spa::auto(dist!()));

    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".into());
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
