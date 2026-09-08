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
//! # Implementing one
//!
//! ```
//! # use std::collections::HashMap;
//! # use doxa_policy::fetch::{Fetch, FetchByKey};
//! # #[derive(Clone)]
//! # struct Widget { name: String, tenant: String }
//! # struct Store(HashMap<String, Widget>);
//! impl Fetch<Store> for Widget {
//!     type Error = std::convert::Infallible;
//! }
//!
//! impl FetchByKey<Store> for Widget {
//!     type Key = String;
//!
//!     async fn fetch(
//!         key: String,
//!         src: &Store,
//!         scope: &str,
//!     ) -> Result<Option<Self>, Self::Error> {
//!         // The scope is not advisory: a widget owned by someone else is
//!         // absent, not refused.
//!         Ok(src.0.get(&key).filter(|w| w.tenant == scope).cloned())
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
