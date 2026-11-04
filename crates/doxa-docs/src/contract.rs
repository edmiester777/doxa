//! A server serving the routes an API crate declares.

use doxa_wire::{Method, RouteSpec};
use utoipa::openapi::path::{HttpMethod, Operation};
use utoipa::openapi::{RefOr, Response};

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

/// The declaration's success statuses in place of the inferred ones, each with the inferred
/// body; a `204` has none.
pub fn respond(op: &mut Operation, responses: &[(u16, &str)]) {
    if responses.is_empty() {
        return;
    }
    let all = &mut op.responses.responses;
    let body = all
        .iter()
        .find(|(status, _)| status.starts_with('2'))
        .and_then(|(_, r)| match r {
            RefOr::T(r) => Some(r.clone()),
            RefOr::Ref(_) => None,
        });
    all.retain(|status, _| !status.starts_with('2'));
    for (status, description) in responses {
        let mut response = body.clone().unwrap_or_else(|| Response::new(*description));
        response.description = (*description).to_owned();
        if *status == 204 {
            response.content.clear();
        }
        all.insert(status.to_string(), RefOr::T(response));
    }
}

/// The declared operation id, and the declaration's docs where the handler has none.
pub fn document(op: &mut Operation, spec: &RouteSpec, docs: &str) {
    op.operation_id = Some(spec.operation_id.to_owned());
    if op.summary.is_some() || op.description.is_some() || docs.is_empty() {
        return;
    }
    let (summary, rest) = docs.split_once("\n\n").unwrap_or((docs, ""));
    op.summary = Some(summary.to_owned());
    let rest = rest.trim();
    if !rest.is_empty() {
        op.description = Some(rest.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn documented(docs: &str) -> Operation {
        const SPEC: RouteSpec = RouteSpec {
            method: Method::Get,
            path: "/",
            operation_id: "route",
            entities: &[],
            dry_run: false,
            invalidates: true,
            package: "api",
        };
        let mut op = Operation::new();
        document(&mut op, &SPEC, docs);
        op
    }

    #[test]
    fn the_summary_is_the_first_paragraph_however_it_wraps() {
        let op = documented("Partially update.\nOnly what is sent changes.\n\nA detail.");
        assert_eq!(
            op.summary.as_deref(),
            Some("Partially update.\nOnly what is sent changes.")
        );
        assert_eq!(op.description.as_deref(), Some("A detail."));
    }

    #[test]
    fn one_paragraph_has_no_description() {
        let op = documented("Fetch one.");
        assert_eq!(op.summary.as_deref(), Some("Fetch one."));
        assert_eq!(op.description, None);
    }
}
