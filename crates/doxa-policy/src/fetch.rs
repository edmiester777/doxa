//! Backend-neutral row lookups for `#[asset]`: by route key, by id, a listing subset, and named
//! [`Lookup`]s. Each sees only a `&str` scope, never the caller, and must answer `None` for
//! another owner's row exactly as for a missing one.
//!
//! ```
//! # use std::collections::HashMap;
//! # use doxa_policy::fetch::{Fetch, FetchByKey};
//! # #[derive(Clone)]
//! # struct Widget { name: String, tenant: String }
//! # struct Store(HashMap<String, Widget>);
//! /// A struct with one field per segment, so the route's `{name}` binds
//! /// by name. `doxa_auth::route_key!` writes this and its `RouteKey` impl.
//! #[derive(serde::Deserialize)]
//! struct WidgetKey { name: String }
//!
//! impl Fetch<Store> for Widget {
//!     type Error = std::convert::Infallible;
//! }
//!
//! impl FetchByKey<Store> for Widget {
//!     type Key = WidgetKey;
//!
//!     async fn fetch(
//!         key: WidgetKey,
//!         src: &Store,
//!         scope: &str,
//!     ) -> Result<Option<Self>, Self::Error> {
//!         // The scope is not advisory: a widget owned by someone else is
//!         // absent, not refused.
//!         Ok(src.0.get(&key.name).filter(|w| w.tenant == scope).cloned())
//!     }
//! }
//! ```

use std::future::Future;

/// A kind of row one scope confines, reachable through `Src` (generic, so a transaction can be
/// one). [`Error`](Self::Error) is the backend's; `Granting::Error` needs only `From` it.
pub trait Fetch<Src: ?Sized>: Sized + Send + 'static {
    /// How a fetch fails, before the application has had a say.
    type Error: Send;
}

/// One row a route's key names, inside a scope; `#[asset]`'s default loader.
pub trait FetchByKey<Src: ?Sized>: Fetch<Src> {
    /// What the route's key segment parses into.
    type Key: Send;

    /// The columns behind [`Key`](Self::Key), when they differ from its field names; `&[]` if not.
    const KEY_NAMES: &'static [&'static str] = &[];

    /// The row `key` names within `scope`, or `None` alike for missing and not-this-caller's.
    fn fetch(
        key: Self::Key,
        src: &Src,
        scope: &str,
    ) -> impl Future<Output = Result<Option<Self>, Self::Error>> + Send;
}

/// One row its own identifier names, inside a scope; what `#[asset(key = pk)]` reaches.
pub trait FetchById<Src: ?Sized>: Fetch<Src> {
    /// The row's own identifier.
    type Id: Send;

    /// The identifier columns, in key order — the
    /// [`FetchByKey::KEY_NAMES`] of the id route, read the same way.
    const ID_NAMES: &'static [&'static str] = &[];

    /// The row `id` names within `scope`, or `None`.
    fn fetch_by_id(
        id: Self::Id,
        src: &Src,
        scope: &str,
    ) -> impl Future<Output = Result<Option<Self>, Self::Error>> + Send;
}

/// A named way into a row, for a row reached more ways than [`FetchByKey`] and [`FetchById`].
/// `Self` is a marker carrying the row, the key and the query, and still sees only the scope.
///
/// ```ignore
/// #[derive(PolicyResource)]
/// #[resource(entity_type = "Revision")]
/// struct Model {
///     #[resource(key(FindByPair))] widget: String,
///     #[resource(key(FindByPair))] revision: i64,
///     #[resource(scope)]           tenant_id: String,
/// }
///
/// // …and the asset names the way in rather than the row:
/// #[asset(with = FindByPair, profile = AppGrants, actions = RevisionAction)]
/// pub struct RevisionByPair;
/// ```
pub trait Lookup<Src: ?Sized>: Send + Sync + 'static {
    /// The row this way in produces, and what the policy decides about.
    type Row: Send + 'static;

    /// What the route's segments parse into: a struct with one named
    /// field per segment, which `scoped_lookup!` writes.
    type Key: Send;

    /// The columns matched, when they differ from the key's field names; `&[]` if not.
    const KEY_NAMES: &'static [&'static str] = &[];

    /// How the lookup fails, before the application has had a say.
    type Error: Send;

    /// The row this key names within `scope`, or `None` alike for missing and not-this-caller's.
    fn fetch(
        key: Self::Key,
        src: &Src,
        scope: &str,
    ) -> impl Future<Output = Result<Option<Self::Row>, Self::Error>> + Send;
}

/// The subset of a collection one scope owns, behind `#[asset(list = tenant)]`. A description,
/// not rows, so the handler can run it in its own transaction.
pub trait FetchSubset: Sized + Send + 'static {
    /// The authorized subset, as this collection's queries take it.
    type Filter: Send;

    /// Every row `scope` owns.
    fn subset(scope: &str) -> Self::Filter;

    /// The subset for an unrestricted caller; `None` (the default) gives them [`subset`](Self::subset).
    fn everything() -> Option<Self::Filter> {
        None
    }
}
