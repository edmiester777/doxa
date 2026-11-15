//! `GET /doxa/capabilities`: the capabilities the caller holds, by the checker
//! `Granted<Cap<…>>` asks, so the two can't disagree.

use std::any::Any;

use axum::http::request::Parts;
use axum::Json;
use doxa::__private::{Builtin, Mount};
use doxa::{OpenApi, OpenApiRouter};
use utoipa::openapi::{OpenApiBuilder, PathsBuilder};

use crate::context::CapabilityContext;
use crate::granted::{caller_and_checker, Denial, FromAuthExtensions};

/// The names of the capabilities the caller holds.
#[utoipa::path(
    get,
    path = "/doxa/capabilities",
    operation_id = "doxa_capabilities",
    tag = "doxa",
    responses((status = 200, description = "The names of the capabilities the caller holds", body = Vec<String>))
)]
async fn capabilities(parts: Parts) -> Result<Json<Vec<&'static str>>, Denial> {
    // Every check would be refused; the shell still renders.
    if CapabilityContext::from_extensions(&parts.extensions)
        .is_some_and(|c| crate::context::unscoped(c.tenant(), &parts.extensions))
    {
        return Ok(Json(Vec::new()));
    }
    let (ctx, checker, _) = caller_and_checker::<CapabilityContext>(&parts.extensions)?;
    let tenant = ctx.tenant().unwrap_or("");
    let caps = doxa_policy::capabilities();
    let allowed = checker
        .check_capabilities(tenant, ctx.roles(), &caps)
        .await?;
    let held = caps
        .iter()
        .zip(allowed)
        .filter(|(_, ok)| *ok)
        .map(|(cap, _)| cap.name);
    Ok(Json(held.collect()))
}

fn doc() -> OpenApi {
    OpenApiBuilder::new()
        .paths(PathsBuilder::new().path_from::<__path_capabilities>())
        .build()
}

fn build(_: &dyn Any) -> Option<doxa::Routes> {
    Some(OpenApiRouter::with_openapi(doc()).route(
        doxa_wire::CAPABILITIES_PATH,
        axum::routing::get(capabilities),
    ))
}

fn declared() -> bool {
    !doxa_policy::capabilities().is_empty()
}

inventory::submit! {
    Builtin {
        route: "GET /doxa/capabilities",
        mount: Mount {
            module: module_path!(),
            handler: "capabilities",
            build,
            doc,
        },
        needed: declared,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::TenantAdmin;

    fn tenant_admin(tenant: Option<&str>) -> Parts {
        let (mut parts, ()) = axum::http::Request::new(()).into_parts();
        parts.extensions.insert(CapabilityContext {
            tenant_id: tenant.map(str::to_owned),
            roles: vec![],
        });
        parts.extensions.insert(TenantAdmin);
        parts
    }

    #[tokio::test]
    async fn a_tenant_admin_holds_every_capability_but_only_with_a_tenant() {
        let Ok(Json(held)) = capabilities(tenant_admin(Some("acme"))).await else {
            panic!("a tenant admin with a tenant is answered");
        };
        assert_eq!(held.len(), doxa_policy::capabilities().len());

        let Ok(Json(held)) = capabilities(tenant_admin(None)).await else {
            panic!("a tenantless caller still gets a list");
        };
        assert!(held.is_empty());
    }
}
