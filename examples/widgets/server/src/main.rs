#[tokio::main]
async fn main() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    axum::serve(listener, widgets_server::app(widgets_server::seeded()))
        .await
        .unwrap();
}
