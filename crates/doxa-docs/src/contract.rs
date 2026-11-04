//! A server serving the routes an API crate declares.

use doxa_wire::{Method, RouteSpec};
use utoipa::openapi::path::{HttpMethod, Operation, PathItem};
use utoipa::openapi::OpenApi;

/// One declared route, registered where its API crate is linked.
pub struct Declared(pub &'static RouteSpec);

inventory::collect!(Declared);

/// The routes declared by the API crates named `crates` that `api` doesn't serve.
///
/// A crate is named as Rust spells it, `orders_api` for the package `orders-api`.
pub fn unserved(api: &OpenApi, crates: &[&str]) -> Vec<&'static RouteSpec> {
    let mut out: Vec<&'static RouteSpec> = inventory::iter::<Declared>
        .into_iter()
        .map(|d| d.0)
        .filter(|s| crates.contains(&s.package.replace('-', "_").as_str()))
        .filter(|s| !served(api, s))
        .collect();
    out.sort_by_key(|s| (s.path, s.method.as_str()));
    out.dedup();
    out
}

/// Panics naming every route the API crates `crates` declare that `api` doesn't serve.
pub fn assert_serves(api: &OpenApi, crates: &[&str]) {
    let missing = unserved(api, crates);
    if missing.is_empty() {
        return;
    }
    let list: Vec<String> = missing
        .iter()
        .map(|s| format!("  {} {} ({})", s.method.as_str(), s.path, s.operation_id))
        .collect();
    panic!(
        "this server doesn't serve {} declared route(s):\n{}\n\
         implement each with `#[doxa::implements(…)]` and mount it with `routes!`",
        missing.len(),
        list.join("\n")
    );
}

fn served(api: &OpenApi, spec: &RouteSpec) -> bool {
    api.paths
        .paths
        .get(spec.path)
        .is_some_and(|item| operation(item, method(spec.method)).is_some())
}

fn operation(item: &PathItem, method: HttpMethod) -> Option<&Operation> {
    match method {
        HttpMethod::Get => item.get.as_ref(),
        HttpMethod::Put => item.put.as_ref(),
        HttpMethod::Post => item.post.as_ref(),
        HttpMethod::Delete => item.delete.as_ref(),
        HttpMethod::Patch => item.patch.as_ref(),
        _ => None,
    }
}

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
