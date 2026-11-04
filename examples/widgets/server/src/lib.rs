//! The widgets server: the shared routes behind a stand-in for `AuthLayer`.

use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::Request;
use axum::middleware::Next;
use axum::Router;

use doxa::auth::CapabilityContext;
use doxa::policy::{AuthError, Capability, CapabilityChecker, ResourceEntity};

use widgets_api::store::Catalog;
use widgets_api::widgets::Widget;

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

/// The widgets API's OpenAPI document.
#[doxa::spec]
pub fn api_doc() -> doxa::ApiDoc {
    doxa::ApiDocBuilder::new()
        .title("Widgets")
        .version("0.0.0")
        .bearer_security("bearer")
        .merge(doxa::spec())
        .build()
}

/// The app, with the caller's role read from `x-role` in place of a real token.
pub fn app(catalog: Catalog) -> Router {
    let (router, _api) = doxa::app(&catalog).split_for_parts();
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
