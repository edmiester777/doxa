//! The browser app: pages that call the server's routes as functions.

use doxa::ui::prelude::*;
use {{crate}}_client::greeting::*;

#[doxa::start]
fn start() {
    App::new(Router::new().page::<Home>()).mount("#app");
}

#[page("/", load = |p| greeting(Who { name: p.name.clone() }))]
async fn Home(name: Option<String>) -> Result<View> {
    let hello = greeting(Who { name }).await?;
    Ok(view! { <h1>{&hello.message}</h1> })
}
