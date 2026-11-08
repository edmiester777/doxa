use doxa::{dist, MountSpaExt, Spa};

#[tokio::main]
async fn main() {
    let app = widgets_server::app(widgets_server::seeded())
        // The example has no sign-in: a browser that sends no `x-role` acts as an editor.
        .layer(axum::middleware::from_fn(
            |mut req: axum::extract::Request, next: axum::middleware::Next| async move {
                if !req.headers().contains_key("x-role") {
                    req.headers_mut()
                        .insert("x-role", axum::http::HeaderValue::from_static("editor"));
                }
                next.run(req).await
            },
        ))
        .mount_spa(Spa::auto(dist!()));
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".into());
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
