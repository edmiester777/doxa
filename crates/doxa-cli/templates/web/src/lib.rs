//! The browser app: pages that call the server's routes as functions.

use doxa::ui::prelude::*;
use {{crate}}_api::*;

#[doxa::start]
fn start() {
    App::new(Router::new().page::<Home>()).mount("#app");
}

#[page("/")]
async fn Home(name: Option<String>) -> Result<View> {
    let hello = greeting(Who { name }).await?;
    Ok(view! { <h1>{&hello.message}</h1> })
}
