//! A server serving the routes an API crate declares.

use doxa_wire::{Method, RouteSpec};
use utoipa::openapi::path::{HttpMethod, Operation};

/// One declared route, registered where its API crate is linked.
pub struct Declared(pub &'static RouteSpec);

inventory::collect!(Declared);

/// A declared route's method, as utoipa names it.
pub fn method(m: Method) -> HttpMethod {
    match m {
        Method::Get => HttpMethod::Get,
        Method::Post => HttpMethod::Post,
        Method::Put => HttpMethod::Put,
        Method::Patch => HttpMethod::Patch,
        Method::Delete => HttpMethod::Delete,
    }
}

/// The declared operation id, and the declaration's docs where the handler has none.
pub fn document(op: &mut Operation, spec: &RouteSpec, docs: &str) {
    op.operation_id = Some(spec.operation_id.to_owned());
    if op.summary.is_some() || op.description.is_some() || docs.is_empty() {
        return;
    }
    let (summary, rest) = docs.split_once('\n').unwrap_or((docs, ""));
    op.summary = Some(summary.to_owned());
    let rest = rest.trim();
    if !rest.is_empty() {
        op.description = Some(rest.to_owned());
    }
}
