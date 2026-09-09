//! Fetching the row a policy decision is then made about, from wherever
//! it lives.
//!
//! `scoped` says how a SeaORM table answers the lookups a route needs —
//! and is behind the `sea-orm` feature, which is why it is named here
//! rather than linked. This says what those lookups *are*, in terms no
//! backend owns: a key, a source to ask, and the scope the answer must be
//! confined to. A row in Postgres, one behind an HTTP control plane and
//! one in a process-local map all answer the same question, so `#[asset]`
//! can write the same `Granting` impl over any of them.
//!
//! The scope is why this is a trait rather than a function type. Every
//! fetch here takes it and every implementation owes it: a key belonging
//! to another owner must answer `None` exactly as a key that does not
//! exist would, so a route cannot confirm another tenant's object by
//! answering 403 where it would otherwise answer 404.
//!
//! Note what a fetch is *not* given. It sees a `&str` and no caller —
//! no roles, no claims, no session — which is deliberate and is the whole
//! guarantee: an implementation that cannot see the caller cannot ignore
//! the caller's tenant. `#[asset]`'s `load_with` is the door for a lookup
//! that needs more than that, and it is handed the whole context. Those
//! are the same fact, and the cost of the door: the loader that quietly
//! ignores its caller is the one bug none of the rest of this catches.
//!
//! The split into three traits is `scoped`'s, for its
//! reasons. A key is a fact about a *route*, an id and a subset are facts
//! about the *collection*: a table addressed by no key column still has an
//! owner, so it can still be listed and still be reached by its own
//! identifier. Keeping them apart is what lets such a row implement two of
//! the three and be refused, at compile time, only for the route it cannot
//! serve.
//!
//! Those three are facets of the row, so a row gets one of each. [`Lookup`]
//! is for the row that has more ways in than that — a version addressed by
//! uuid, by name, and by `(dataset, version)` — and makes each one a named
//! type rather than a fourth trait. Reach for it when you run out of the
//! three, not before.
//!
//! # Implementing one
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

/// A kind of row one scope confines, reachable through `Src`.
///
/// The supertrait of the fetches rather than a fetch itself, because
/// [`Error`](Self::Error) is one answer per backend while the lookups are
/// one per route. A row reached by key and by id fails the same way.
///
/// `Src` is a type parameter rather than an associated type so that one
/// row can be fetched from more than one place — and, for SeaORM, so a
/// single impl covers every `ConnectionTrait`. That is not a generality
/// for its own sake: a pool cannot see rows the request has written and
/// not committed, so a loader pinned to one would answer `None` for an
/// object the caller is holding.
///
/// # Errors
///
/// [`Error`](Self::Error) is the *backend's*, not the application's.
/// `#[asset]` writes a loader that ends in `?`, so the only thing an
/// application's `Granting::Error` owes it is `From`. That is what keeps
/// `DbErr` from having to be rendered — `DbLoadError` converts it and logs
/// on the way past — while a consumer who wants their own envelope
/// substitutes it without touching the fetch.
pub trait Fetch<Src: ?Sized>: Sized + Send + 'static {
    /// How a fetch fails, before the application has had a say.
    type Error: Send;
}

/// One row a route's key names, inside a scope.
///
/// The lookup behind `#[asset]`'s default loader. [`Key`](Self::Key) is
/// what the route's segment parsed into, and is a fact about the route:
/// the same row reached by name on one route and by id on another has this
/// impl for the first and [`FetchById`] for the second.
pub trait FetchByKey<Src: ?Sized>: Fetch<Src> {
    /// What the route's key segment parses into.
    type Key: Send;

    /// The *columns* behind [`Key`](Self::Key), in key order.
    ///
    /// Usually the same list as the key's own field names, and `#[asset]`
    /// prefers those. This is for the lookup that matches more columns
    /// than its key parses segments — a qualified name split on the way in
    /// — where the two lists are not the same. `&[]` declines to say.
    const KEY_NAMES: &'static [&'static str] = &[];

    /// The row `key` names within `scope`, or `None`.
    ///
    /// `None` covers both "no such key" and "not this caller's" — and must
    /// cover them identically. See the module docs for why.
    fn fetch(
        key: Self::Key,
        src: &Src,
        scope: &str,
    ) -> impl Future<Output = Result<Option<Self>, Self::Error>> + Send;
}

/// One row its own identifier names, inside a scope.
///
/// What `#[asset(key = pk)]` reaches. Separate from [`FetchByKey`] because
/// an identifier belongs to the collection rather than to a route, so a row
/// that no route addresses by a key column has this one and not the other —
/// and gets an id route without inventing a key for it to hold.
pub trait FetchById<Src: ?Sized>: Fetch<Src> {
    /// The row's own identifier.
    type Id: Send;

    /// The identifier columns, in key order — the
    /// [`FetchByKey::KEY_NAMES`] of the id route, read the same way.
    const ID_NAMES: &'static [&'static str] = &[];

    /// The row `id` names within `scope`, or `None`.
    ///
    /// Confined for the reason [`FetchByKey::fetch`] is, and more sharply:
    /// the obvious hand-written version of this — find by primary key,
    /// then authorize — reads another tenant's row before deciding
    /// anything, and answers 403 where it should have answered 404.
    fn fetch_by_id(
        id: Self::Id,
        src: &Src,
        scope: &str,
    ) -> impl Future<Output = Result<Option<Self>, Self::Error>> + Send;
}

/// One *named* way into a row, when a row has more than one.
///
/// [`FetchByKey`] and [`FetchById`] are facets of the row itself, so a row
/// gets one of each: the key its routes address it by, and its own
/// identifier. That is the whole vocabulary for most rows, and they should
/// keep using it — `#[asset]` finds those two without being told.
///
/// It runs out when a row is reached three ways. A dataset version has a
/// uuid, a name, and a `(dataset, version)` pair, and only two of those fit.
/// The third used to become a descriptor with `load_with`, which is the one
/// door that gives up the scope guarantee — so the row with the most ways in
/// was the row most likely to lose it.
///
/// So a lookup becomes a type. `Self` is a marker naming one way in, and
/// carries the row, the key and the query together:
///
/// ```ignore
/// #[derive(PolicyResource)]
/// #[resource(entity_type = "Version")]
/// struct Model {
///     #[resource(key(FindByPair))] dataset: String,
///     #[resource(key(FindByPair))] version: i64,
///     #[resource(scope)]           tenant_id: String,
/// }
///
/// // …and the asset names the way in rather than the row:
/// #[asset(with = FindByPair, profile = AppGrants, actions = VersionAction)]
/// pub struct VersionByPair;
/// ```
///
/// [`Row`](Self::Row) is here rather than on the asset because a marker is
/// nothing on its own — `FindByPair` has no meaning except "this row, by
/// these columns" — so `#[asset(with = …)]` needs no `row =` beside it and
/// two lookups over one row cannot come to disagree about which row that is.
///
/// # The scope is still not optional
///
/// `fetch` takes the same `&str` and the same nothing-else that
/// [`FetchByKey::fetch`] does, for the same reason: a lookup that cannot see
/// the caller cannot ignore the caller's tenant. Naming a lookup buys a
/// second way in, not a way out — which is the point, since the alternative
/// on offer was `load_with`.
pub trait Lookup<Src: ?Sized>: Send + Sync + 'static {
    /// The row this way in produces, and what the policy decides about.
    type Row: Send + 'static;

    /// What the route's segments parse into: a struct with one named
    /// field per segment, which `scoped_lookup!` writes.
    type Key: Send;

    /// The columns this way in matches, in key order.
    ///
    /// Usually the key's own field names, and `#[asset]` prefers those.
    /// This is for a key that collapses several columns into fewer
    /// segments — a qualified name parsed out of one — where the two lists
    /// differ. `&[]` declines to say.
    const KEY_NAMES: &'static [&'static str] = &[];

    /// How the lookup fails, before the application has had a say.
    type Error: Send;

    /// The row this key names within `scope`, or `None`.
    ///
    /// `None` covers both "no such key" and "not this caller's", and must
    /// cover them identically. See the module docs for why.
    fn fetch(
        key: Self::Key,
        src: &Src,
        scope: &str,
    ) -> impl Future<Output = Result<Option<Self::Row>, Self::Error>> + Send;
}

/// The subset of a collection one scope owns.
///
/// Behind `#[asset(list = tenant)]`, which turns it into a `Scoping` impl.
///
/// Takes no source: a subset is a *description* of rows, not the rows, and
/// every backend worth having lets one be built before it is run. That is
/// what lets the guard hand a filter to a handler that then applies it
/// inside a transaction the extractor never saw.
pub trait FetchSubset: Sized + Send + 'static {
    /// The authorized subset, as this collection's queries take it.
    type Filter: Send;

    /// Every row `scope` owns.
    fn subset(scope: &str) -> Self::Filter;

    /// The subset for a caller the policy resolved as unrestricted, when
    /// this collection draws the distinction.
    ///
    /// `None` — the default — means it does not, and an administrator gets
    /// whatever [`subset`](Self::subset) returns. Right for a scope that is
    /// only tenancy, since an administrator of a tenant is still inside it;
    /// wrong where "everything" is a thing the backend can say, and only
    /// the backend can say it.
    fn everything() -> Option<Self::Filter> {
        None
    }
}
