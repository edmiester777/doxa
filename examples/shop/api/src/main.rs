use axum::Router;
use doxa::{dist, MountSpaExt, Spa};

#[doxa::main]
async fn start() -> Router {
    shop_api::server::app(shop_api::server::seeded())
        // The example has no sign-in: a browser that sends no `x-role` acts as a viewer.
        .layer(axum::middleware::from_fn(
            |mut req: axum::extract::Request, next: axum::middleware::Next| async move {
                if !req.headers().contains_key("x-role") {
                    req.headers_mut()
                        .insert("x-role", axum::http::HeaderValue::from_static("viewer"));
                }
                next.run(req).await
            },
        ))
        .mount_spa(Spa::auto(dist!()))
}
