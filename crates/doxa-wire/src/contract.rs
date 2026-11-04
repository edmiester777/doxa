//! A route an API crate declares and a server implements, as both sides see it.

use std::marker::PhantomData;

use crate::{names_covered, Keyed, RouteSpec};

/// One declared route, as `#[get]` / `#[post]` / … on a function without a body states it.
///
/// The macro writes one beside every declaration, as `route_name::Route`.
pub trait Declared {
    /// Method, path and the rest of what the client sends to.
    const SPEC: &'static RouteSpec;
    /// The declaration's doc comment.
    const DOCS: &'static str;
    /// The arguments a client passes, as the client's extractor types, in order.
    type Args;
    /// What a call answers on success, as the client decodes it.
    type Ok;
    /// The route's error, or [`NoError`].
    type Error;
}

/// The error of a declaration that returns no `Result`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoError {}

/// In a declaration, the guard that authorizes a call to this one `E`: the client passes
/// `E`'s key, and the server's guard is an asset whose `entity` is `E`.
pub struct Grant<E: ?Sized>(PhantomData<fn() -> E>);

/// The declared entity a server asset guards, from `#[doxa::asset(entity = …)]`.
#[diagnostic::on_unimplemented(
    message = "`{Self}` doesn't say which declared entity it guards",
    note = "add `entity = …` to its `#[doxa::asset(…)]`, naming the API crate's `#[doxa::entity]`"
)]
pub trait OfEntity {
    /// The entity, as the API crate declares it.
    type Entity: Keyed;
}

/// Whether two keys name the same route parameters, in any order.
pub const fn same_names(a: &[&str], b: &[&str]) -> bool {
    names_covered(a, &[b]) && names_covered(b, &[a])
}
