//! A route an API crate declares and a server implements, as both sides see it.

use crate::RouteSpec;

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
