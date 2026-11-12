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
    let (ctx, checker) = caller_and_checker::<CapabilityContext>(&parts.extensions)?;
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
