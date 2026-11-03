//! The widgets server: the shared routes behind a stand-in for `AuthLayer`.

use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{FromRef, Request};
use axum::middleware::Next;
use axum::Router;

use doxa::auth::CapabilityContext;
use doxa::policy::{AuthError, Capability, CapabilityChecker, ResourceEntity};
use doxa::{routes, OpenApiRouter};

use widgets_api::store::Catalog;
use widgets_api::widgets::*;

#[derive(Clone)]
struct AppState {
    catalog: Catalog,
}

impl FromRef<AppState> for Catalog {
    fn from_ref(state: &AppState) -> Self {
        state.catalog.clone()
    }
}

/// `viewer` may read; `editor` may also rename.
struct RoleChecker;

#[async_trait]
impl CapabilityChecker for RoleChecker {
    async fn check(&self, _: &str, roles: &[String], cap: &Capability) -> Result<bool, AuthError> {
        let editor = roles.iter().any(|r| r == "editor");
        let viewer = editor || roles.iter().any(|r| r == "viewer");
        Ok(match cap.name {
            "widgets.update" => editor,
            _ => viewer,
        })
    }

    async fn check_instance(
        &self,
        _: &str,
        roles: &[String],
        action: &str,
        _: &ResourceEntity,
    ) -> Result<bool, AuthError> {
        Ok(action != "update" || roles.iter().any(|r| r == "editor"))
    }
}

fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::<AppState>::new()
        .routes(routes!(get_widget))
        .routes(routes!(list_widgets))
        .routes(routes!(rename_widget))
        .routes(routes!(widget_events))
        .routes(routes!(suggest_name))
        .routes(routes!(widget_label))
        .routes(routes!(upload_photo))
        .routes(routes!(upload_files))
        .merge(widgets_api::meta_routes())
}

/// The widgets API's OpenAPI document.
#[doxa::spec]
pub fn api_doc() -> doxa::ApiDoc {
    let (_, api) = routes().split_for_parts();
    doxa::ApiDocBuilder::new()
        .title("Widgets")
        .version("0.0.0")
        .bearer_security("bearer")
        .merge(api)
        .build()
}

/// The app, with the caller's role read from `x-role` in place of a real token.
pub fn app(catalog: Catalog) -> Router {
    let (router, _api) = routes().split_for_parts();
    router
        .layer(axum::middleware::from_fn(
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
        .layer(doxa::ETagLayer)
        .with_state(AppState { catalog })
}

/// Three widgets to start with.
pub fn seeded() -> Catalog {
    Catalog::new(vec![
        Widget {
            id: 1,
            name: "sprocket".into(),
        },
        Widget {
            id: 2,
            name: "gear".into(),
        },
        Widget {
            id: 3,
            name: "cog".into(),
        },
    ])
}
