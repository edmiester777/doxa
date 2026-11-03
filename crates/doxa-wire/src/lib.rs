//! Types a doxa server and its browser client agree on.
//!
//! Everything here builds on every target. The server re-exports it from its
//! usual paths; the client decodes the same types it was sent.

#![deny(missing_docs)]

use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use serde_json::Value as __Value;

mod valid;
pub use valid::Validates;

/// `#[serde(with)]` for `Option<Option<T>>`: absent is `None`, `null` is `Some(None)`.
pub mod double_option {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Writes the inner option; pair with `skip_serializing_if = "Option::is_none"`.
    pub fn serialize<T: Serialize, S: Serializer>(
        value: &Option<Option<T>>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(inner) => inner.serialize(s),
            None => s.serialize_none(),
        }
    }

    /// A present field, `null` or not; pair with `default` so an absent one is `None`.
    pub fn deserialize<'de, T: Deserialize<'de>, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Option<T>>, D::Error> {
        Option::<T>::deserialize(d).map(Some)
    }
}

/// Header a `<Can>` probe sends; the guard answers `204` instead of running the handler.
pub const DRY_RUN_HEADER: &str = "x-doxa-dry-run";
/// Value the server echoes on [`DRY_RUN_HEADER`] when the probe was allowed.
pub const DRY_RUN_OK: &str = "ok";
/// Header carrying the caller's session epoch; a new value clears client caches.
pub const SESSION_HEADER: &str = "x-doxa-session";
/// Header naming further entity types a mutation touched, comma separated.
pub const INVALIDATE_HEADER: &str = "x-doxa-invalidate";
/// Header every cookie-authenticated mutation must carry.
pub const CSRF_HEADER: &str = "x-doxa-csrf";
/// Request headers a doxa client sends, which a cross-origin server must allow.
pub const REQUEST_HEADERS: &[&str] = &[
    "accept",
    "authorization",
    "content-type",
    "if-none-match",
    "last-event-id",
    DRY_RUN_HEADER,
    CSRF_HEADER,
];
/// Response headers a doxa client reads, which a cross-origin server must expose.
pub const RESPONSE_HEADERS: &[&str] = &["etag", DRY_RUN_HEADER, SESSION_HEADER, INVALIDATE_HEADER];

/// Envelope for HTTP error responses produced by `#[derive(ApiError)]`.
///
/// `E` is the route's error enum, or `serde_json::Value` where it is not known.
///
/// ```
/// use doxa_wire::ApiErrorBody;
///
/// let body: ApiErrorBody<()> = ApiErrorBody::new(404, "not_found", "widget 7 does not exist", ());
/// let json = serde_json::to_value(&body).unwrap();
/// assert_eq!(json["status"], 404);
/// assert_eq!(json["code"], "not_found");
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(bound(
    serialize = "E: serde::Serialize",
    deserialize = "E: serde::de::DeserializeOwned"
))]
pub struct ApiErrorBody<E = serde_json::Value> {
    /// Human-readable message from the source error's `Display` impl.
    pub message: String,
    /// HTTP status code, mirrored from the response status line.
    pub status: u16,
    /// Application-level error code, e.g. `"not_found"`.
    pub code: String,
    /// The typed error, as the route's error enum serializes it.
    pub error: E,
}

impl<E> ApiErrorBody<E> {
    /// Construct an [`ApiErrorBody`] from its raw fields.
    pub fn new(status: u16, code: impl Into<String>, message: impl Into<String>, error: E) -> Self {
        Self {
            message: message.into(),
            status,
            code: code.into(),
            error,
        }
    }
}

/// The `code` of a `422` whose `error` is [`FieldErrors`].
pub const INVALID: &str = "invalid";

/// One input field that failed validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct FieldError {
    /// Where, as garde writes it: `name`, `lines[0].sku`.
    pub path: String,
    /// What's wrong.
    pub message: String,
}

/// Every field that failed validation, as a `422`'s `error`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(transparent)]
pub struct FieldErrors(pub Vec<FieldError>);

impl FieldErrors {
    /// The first message for `path`.
    pub fn get(&self, path: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|e| e.path == path)
            .map(|e| e.message.as_str())
    }
}

impl std::fmt::Display for FieldErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let all: Vec<String> = self
            .0
            .iter()
            .map(|e| match e.path.as_str() {
                "" => e.message.clone(),
                p => format!("{p}: {}", e.message),
            })
            .collect();
        f.write_str(&all.join("; "))
    }
}

impl std::error::Error for FieldErrors {}

/// HTTP method of a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// `GET`
    Get,
    /// `POST`
    Post,
    /// `PUT`
    Put,
    /// `PATCH`
    Patch,
    /// `DELETE`
    Delete,
}

impl Method {
    /// The method as it appears on the request line.
    pub const fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
        }
    }

    /// Whether a request with this method changes nothing on the server.
    pub const fn is_safe(self) -> bool {
        matches!(self, Method::Get)
    }
}

/// One route, as its `#[get]` / `#[post]` / … attribute declared it.
///
/// The macro writes one beside every handler, as `route_name::ROUTE`.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct RouteSpec {
    /// HTTP method.
    pub method: Method,
    /// Path template, e.g. `/api/widgets/{name}`.
    pub path: &'static str,
    /// OpenAPI operation id, which is the handler's name unless overridden.
    pub operation_id: &'static str,
    /// Entity types the route's guards are about, for cache invalidation.
    pub entities: &'static [&'static str],
    /// Whether the route answers a `<Can>` dry run.
    pub dry_run: bool,
    /// The client crate the route was compiled into, which names its service.
    pub package: &'static str,
}

impl RouteSpec {
    /// The `{name}` placeholders in [`path`](Self::path), in order.
    pub fn path_names(&self) -> impl Iterator<Item = &'static str> {
        path_names(self.path)
    }
}

/// The `{name}` placeholders in a path template, in order.
pub fn path_names(template: &str) -> impl Iterator<Item = &str> {
    template.split('{').skip(1).filter_map(|rest| {
        let name = rest.split('}').next()?;
        Some(name.trim_start_matches('*'))
    })
}

/// The field names a key serializes to, which are the route parameters it fills.
pub trait KeyNames {
    /// Field names, in declaration order.
    const NAMES: &'static [&'static str];
}

impl KeyNames for () {
    const NAMES: &'static [&'static str] = &[];
}

/// An action vocabulary, as `#[derive(Actions)]` declares it.
pub trait Vocabulary {
    /// The entity type the vocabulary's actions are about.
    const ENTITY_TYPE: &'static str;
}

/// A guarded asset as the client sees it: the key that names one, and what it is.
pub trait Keyed {
    /// The key a route takes to name one.
    type Key;
    /// The entity type the asset is about.
    const ENTITY_TYPE: &'static str;
    /// The client crate whose service caches it.
    const PACKAGE: &'static str = "";
}

/// A value the client cache can store by identity, from `#[derive(Identity)]`.
pub trait Identity {
    /// The value's identity; must never change for the life of the entity.
    type Id: Clone + Eq + std::hash::Hash + 'static;
    /// The entity type, shared with the asset that guards it.
    const ENTITY_TYPE: &'static str;
    /// The client crate whose service caches it.
    const PACKAGE: &'static str = "";
    /// The field holding the identity.
    const ID_FIELD: &'static str = "";
    /// The name of the route key it declares, if any.
    const KEY_TYPE: Option<&'static str> = None;
    /// The key's fields, which are this value's fields of the same names.
    const KEY_FIELDS: &'static [&'static str] = &[];
    /// This value's identity.
    fn identity(&self) -> Self::Id;
    /// The route key naming this value, as it serializes, if it declares one.
    fn route_key(&self) -> Option<serde_json::Value> {
        None
    }
}

/// A route key as JSON, for comparing against what a call sent.
#[doc(hidden)]
pub fn key_value(key: &impl Serialize) -> Option<serde_json::Value> {
    serde_json::to_value(key).ok()
}

/// A value whose instance route takes `K`, so the cache can answer that route from the value.
pub trait KeyedBy<K>: Identity
where
    for<'a> K: From<&'a Self>,
{
}

/// Whether every name in `needles` appears in one of `haystacks`.
pub const fn names_covered(needles: &[&str], haystacks: &[&[&str]]) -> bool {
    let mut i = 0;
    while i < needles.len() {
        let mut found = false;
        let mut h = 0;
        while h < haystacks.len() && !found {
            let mut j = 0;
            while j < haystacks[h].len() {
                if str_eq(needles[i], haystacks[h][j]) {
                    found = true;
                    break;
                }
                j += 1;
            }
            h += 1;
        }
        if !found {
            return false;
        }
        i += 1;
    }
    true
}

const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_names_reads_every_placeholder() {
        let names: Vec<_> = path_names("/folders/{fid}/widgets/{id}/{*rest}").collect();
        assert_eq!(names, ["fid", "id", "rest"]);
    }

    #[test]
    fn coverage_needs_every_name_somewhere() {
        assert!(names_covered(&["fid", "id"], &[&["id"], &["fid"]]));
        assert!(!names_covered(&["fid", "id"], &[&["id"]]));
    }
}
