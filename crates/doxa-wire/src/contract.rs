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
    /// The OpenAPI tags it gave itself.
    const TAGS: &'static [&'static str];
    /// The arguments a client passes, as the client's extractor types, in order.
    type Args;
    /// What a call answers on success, as the client decodes it.
    type Ok;
    /// The route's error, or [`NoError`].
    type Error;
    /// The method, as one of [`verb`]'s markers.
    type Verb;
    /// The entities it guards with `Grant<Many<E>>`.
    const MANY: &'static [&'static str] = &[];
}

/// Whether `entity` is among `declared`.
pub const fn declares(declared: &[&str], entity: &str) -> bool {
    names_covered(&[entity], &[declared])
}

/// The HTTP methods as types, so a server can resolve a guard's action from a declaration.
pub mod verb {
    /// `GET`.
    pub struct Get;
    /// `POST`.
    pub struct Post;
    /// `PUT`.
    pub struct Put;
    /// `PATCH`.
    pub struct Patch;
    /// `DELETE`.
    pub struct Delete;
}

/// The error of a declaration that returns no `Result`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoError {}

/// In a declaration, the guard that authorizes a call to this one `E`: the client passes
/// `E`'s key, and the server's guard is an asset whose `entity` is `E`.
pub struct Grant<E: ?Sized>(PhantomData<fn() -> E>);

/// In a declaration, `Grant<Many<E>>`: the call lists `E`s the server's guard scopes.
pub struct Many<E: ?Sized>(PhantomData<fn() -> E>);

/// In a declaration, `Grant<Cap<M>>`: the call needs the capability `M` names.
pub struct Cap<M: ?Sized>(PhantomData<fn() -> M>);

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

/// Whether a path template has any `{name}` parameter.
pub const fn has_params(template: &str) -> bool {
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            return true;
        }
        i += 1;
    }
    false
}

/// Whether every one of `names` is a `{name}` parameter of `template`.
pub const fn params_include(template: &str, names: &[&str]) -> bool {
    let mut n = 0;
    while n < names.len() {
        if !has_param(template.as_bytes(), names[n].as_bytes()) {
            return false;
        }
        n += 1;
    }
    true
}

const fn has_param(t: &[u8], name: &[u8]) -> bool {
    let mut i = 0;
    while i < t.len() {
        if t[i] == b'{' {
            let mut j = i + 1;
            if j < t.len() && t[j] == b'*' {
                j += 1;
            }
            let mut k = 0;
            while k < name.len() && j + k < t.len() && t[j + k] == name[k] {
                k += 1;
            }
            if k == name.len() && j + k < t.len() && t[j + k] == b'}' {
                return true;
            }
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_template_includes_the_params_it_names() {
        assert!(has_params("/orders/{id}"));
        assert!(!has_params("/orders"));
        assert!(params_include("/f/{fid}/o/{id}", &["id", "fid"]));
        assert!(params_include("/files/{*rest}", &["rest"]));
        assert!(!params_include("/f/{fid}/o/{id}", &["i"]));
        assert!(!params_include("/f/{fid}", &["fids"]));
    }
}
