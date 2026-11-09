use axum::extract::Query;
use axum::Json;
use doxa::{dist, implements, MountSpaExt, Spa};

use {{crate}}_api::{Greeting, Who};

/// The routes' state; this app has none yet.
#[derive(Clone, doxa::State)]
struct NoState;

/// Every route.
#[doxa::service]
struct App;

#[implements({{crate}}_api::greeting)]
async fn greeting(Query(who): Query<Who>) -> Json<Greeting> {
    let name = who.name.unwrap_or_else(|| "world".into());
    Json(Greeting {
        message: format!("Hello, {name}!"),
    })
}

#[tokio::main]
async fn main() {
    let (router, _api) = doxa::app(&NoState).split_for_parts();
    let app = router.mount_spa(Spa::auto(dist!()));

    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".into());
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
