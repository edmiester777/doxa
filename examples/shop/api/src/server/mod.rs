//! What only the server compiles: the stores, the guards' assets, the layers and the app.

mod orders;
mod widgets;

pub use orders::{OrderById, OrderRow, Store};
pub use widgets::{field_sizes, Caller, Catalog, WidgetByName, WidgetRow};

pub use axum::extract::Multipart;

use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{FromRef, Request};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::Router;

use doxa::auth::CapabilityContext;
use doxa::policy::{AuthError, Capability, CapabilityChecker, ResourceEntity};
use doxa::Routes;

/// Everything the routes read.
#[derive(Clone, doxa::State)]
pub struct ShopState {
    pub orders: Store,
    pub widgets: Catalog,
}

impl FromRef<ShopState> for Store {
    fn from_ref(state: &ShopState) -> Self {
        state.orders.clone()
    }
}

impl FromRef<ShopState> for Catalog {
    fn from_ref(state: &ShopState) -> Self {
        state.widgets.clone()
    }
}

/// `viewer` reads; `editor` renames widgets; `clerk` places and cancels orders; `admin` does
/// anything.
struct RoleChecker;

#[async_trait]
impl CapabilityChecker for RoleChecker {
    async fn check(&self, _: &str, roles: &[String], cap: &Capability) -> Result<bool, AuthError> {
        let has = |r: &str| roles.iter().any(|x| x == r);
        if has("admin") {
            return Ok(true);
        }
        Ok(match cap.name {
            "orders.cancel" | "orders.place" => has("clerk"),
            "widgets.update" => has("editor"),
            _ => has("viewer") || has("editor") || has("clerk"),
        })
    }

    async fn check_instance(
        &self,
        _: &str,
        roles: &[String],
        action: &str,
        _: &ResourceEntity,
    ) -> Result<bool, AuthError> {
        let has = |r: &str| roles.iter().any(|x| x == r);
        Ok(has("admin")
            || match action {
                "cancel" => has("clerk"),
                "update" => has("editor"),
                _ => true,
            })
    }
}

/// Who the caller is, read from `x-role` in place of a real token.
#[doxa::layers]
pub fn caller(routes: Routes, _: &ShopState) -> Routes {
    routes.layer(axum::middleware::from_fn(
        |mut req: Request, next: Next| async move {
            let role = req
                .headers()
                .get("x-role")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            if let Some(role) = role {
                req.extensions_mut().insert(CapabilityContext {
                    tenant_id: Some("acme".into()),
                    roles: vec![role],
                });
            }
            let checker: Arc<dyn CapabilityChecker> = Arc::new(RoleChecker);
            req.extensions_mut().insert(checker);
            next.run(req).await
        },
    ))
}

/// [`caller`], and `401` without a role.
#[doxa::layers(docs = [caller, doxa::auth::AuthDocs])]
pub fn signed_in(routes: Routes, state: &ShopState) -> Routes {
    let routes = routes.layer(axum::middleware::from_fn(
        |req: Request, next: Next| async move {
            if req.extensions().get::<CapabilityContext>().is_none() {
                return StatusCode::UNAUTHORIZED.into_response();
            }
            next.run(req).await
        },
    ));
    caller(routes, state)
}

/// The shop's OpenAPI document.
#[doxa::spec]
pub fn api_doc() -> doxa::ApiDoc {
    doxa::ApiDocBuilder::new()
        .title("Shop")
        .version("0.0.0")
        .bearer_security("bearer")
        .merge(doxa::spec())
        .build()
}

/// The app over `state`.
pub fn app(state: ShopState) -> Router {
    let (router, _api) = doxa::app(&state).split_for_parts();
    router.layer(doxa::ETagLayer)
}

/// Three widgets and two orders to start with.
pub fn seeded() -> ShopState {
    let widget = |id, name: &str| WidgetRow {
        id,
        name: name.into(),
    };
    let order = |id, item: &str, quantity| OrderRow {
        id,
        item: item.into(),
        quantity,
    };
    ShopState {
        widgets: Catalog::new(vec![
            widget(1, "sprocket"),
            widget(2, "gear"),
            widget(3, "cog"),
        ]),
        orders: Store::new(vec![order(1, "sprocket", 2), order(2, "gear", 5)]),
    }
}
