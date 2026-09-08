//! Loading the row a policy decision is then made about.
//!
//! [`PolicyResource`](crate::PolicyResource) says what a row *is* to
//! Cedar. This says how a route *reaches* it. The two are separate
//! because identity is one fact about a table while a lookup is one per
//! route: a row addressed by name and the same row addressed by id are
//! one Cedar entity with two loaders, and only the loaders differ.
//!
//! The same reasoning splits this module's own two traits.
//! [`ScopedTable`] is what the table owes — the column that says whose
//! rows these are, what its Cedar attributes mean in SQL, and the lookups
//! that need nothing beyond those: the listing, and the row addressed by
//! the primary key the table already has. [`ScopedRow`] adds the key one
//! route matches on, and the two lookups that read it. A table reached by
//! a name that no column holds still has an owner, so it can still be
//! listed, still have a policy's residual read against it, and still be
//! reached by id; requiring a key would have meant inventing one.
//!
//! Nothing here names an application type. [`Granting`] needs a caller
//! shape, a state type and an error of the application's choosing — none
//! of which a derive expanding inside an entity crate could write. What a
//! derive *can* write is the query: two columns and the table they sit
//! in. The application keeps the thin [`Granting`] impl that supplies its
//! own caller, which is the part that was never mechanical.
//!
//! The error was never that part, though it was written as if it were.
//! Turning a [`DbErr`] into a response admits one answer — a 500, and the
//! detail in the log rather than the body — so [`DbLoadError`] ships it
//! and an `impl Granting` names it instead of declaring it.
//!
//! [`Granting`]: https://docs.rs/doxa-auth/latest/doxa_auth/granted/trait.Granting.html

use std::future::Future;

use sea_orm::{
    ColumnTrait, ConnectionTrait, DbErr, EntityTrait, FromQueryResult, PrimaryKeyTrait,
    QueryFilter, Select, Value,
};

/// The value a row's primary key takes, for [`ScopedTable::load_by_id`].
pub type PrimaryKeyOf<R> =
    <<<R as ScopedTable>::Entity as EntityTrait>::PrimaryKey as PrimaryKeyTrait>::ValueType;

/// A table one scope column confines, and what its Cedar attributes mean
/// in SQL.
///
/// The scope column is the whole security property: every query built here
/// carries it, so a row belonging to someone else is not merely refused,
/// it is absent — and a route built on this cannot leak the existence of
/// another owner's object by answering 403 where it would otherwise answer
/// 404.
///
/// Separate from [`ScopedRow`] because a key is a fact about a *route* and
/// a scope is a fact about the *table*. Two routes reach one table by
/// different keys; a table addressed by no key at all — a name resolved
/// through logic rather than matched against a column — still has an owner
/// and still has attributes a policy names. Splitting them is what lets
/// that table be listed, have its residual read and be reached by its
/// primary key, without inventing a key column for it to hold.
///
/// # Example
///
/// ```ignore
/// impl ScopedTable for Model {
///     type Entity = Entity;
///     const SCOPE_COLUMN: Column = Column::CompanyId;
/// }
///
/// let page = Model::scoped("acme").paginate(&db, 50);
/// ```
///
/// `FromQueryResult` is a supertrait rather than left to
/// `EntityTrait::Model`'s own bound: the compiler will not read that bound
/// backwards through `Entity = Self`, and every SeaORM `Model` satisfies
/// it anyway.
pub trait ScopedTable: Sized + Send + FromQueryResult {
    /// Table the scope column sits in.
    type Entity: EntityTrait<Model = Self>;

    /// Column carrying the owner every query is confined to.
    const SCOPE_COLUMN: <Self::Entity as EntityTrait>::Column;

    /// The column a policy means by `resource.<attr>`.
    ///
    /// A residual is written against the Cedar attributes the row exposes
    /// — `resource.region == "us"` — and turning one into a `WHERE` clause
    /// needs the column behind that name. `#[derive(PolicyResource)]`
    /// writes this from the same `#[resource(attr)]` fields it builds
    /// [`cedar_attrs`](crate::PolicyResource::cedar_attrs) from, so the
    /// attributes a policy can mention and the columns they resolve to are
    /// one list rather than two that drift.
    ///
    /// The default answers `None` for everything, which
    /// [`condition_from_residual`](crate::condition_from_residual) treats
    /// as untranslatable and therefore refuses. That is the safe default:
    /// a row whose attributes have no columns cannot have a policy
    /// condition pushed into its query, and the alternative to refusing is
    /// a filter *wider* than the policy authorized.
    ///
    /// It answers about *this* table. A policy attribute that names
    /// something the row does not store — a column of the data a row
    /// merely describes, say — has no answer here and must not be given
    /// one: a filter built against the wrong table is the one failure this
    /// module's refusals cannot catch.
    fn column_for_attr(_attr: &str) -> Option<<Self::Entity as EntityTrait>::Column> {
        None
    }

    /// Every row `scope` owns, as a `Select` the caller pages.
    fn scoped(scope: impl Into<Value>) -> Select<Self::Entity> {
        Self::Entity::find().filter(Self::SCOPE_COLUMN.eq(scope))
    }

    /// One row by primary key, still confined to `scope`.
    ///
    /// The lookup for a route that addresses the table by its id. It sits
    /// here rather than on [`ScopedRow`] because it reads nothing a key
    /// would supply — a primary key belongs to the table, not to a route —
    /// so a table addressed by no key column has an id route all the same.
    ///
    /// It exists because the obvious hand-written version is wrong in a
    /// way that passes every test. `Entity::find_by_id(id).one(db)` is
    /// what a primary-key lookup looks like, and it ignores the scope
    /// entirely: a caller naming another tenant's id gets that tenant's
    /// row. An instance check will usually still refuse it — but by then
    /// the route has answered `403` where it would have answered `404`,
    /// and that difference confirms the row exists. Every lookup in this
    /// module takes the scope for that reason, and this one is here so the
    /// id route does not have to be written out to get it.
    ///
    /// Generic over the connection rather than taking a
    /// [`DatabaseConnection`](sea_orm::DatabaseConnection), so the same
    /// derived lookup serves a handler that has a transaction open. That is
    /// not a convenience: a pool cannot see rows the request has written
    /// and not committed, so a loader pinned to one would answer `None` for
    /// an object the caller is holding — and the route would 404 on
    /// something it just created. Every lookup here takes `&C` for that
    /// reason.
    fn load_by_id<C: ConnectionTrait>(
        id: PrimaryKeyOf<Self>,
        db: &C,
        scope: impl Into<Value> + Send,
    ) -> impl Future<Output = Result<Option<Self>, DbErr>> + Send {
        let query = Self::Entity::find_by_id(id).filter(Self::SCOPE_COLUMN.eq(scope));
        async move { query.one(db).await }
    }
}

/// A row one key resolves to, within its table's scope.
///
/// [`ScopedTable`] says which rows are the caller's; this says how a route
/// reaches one of them. Every method has a default body, so an
/// implementation is three lines — which is why
/// `#[derive(PolicyResource)]` can write it from `#[resource(key)]` and
/// leave nothing behind.
///
/// # Example
///
/// ```ignore
/// impl ScopedRow for Model {
///     type Key = String;
///     const KEY_COLUMN: Column = Column::Name;
/// }
///
/// let row = Model::load_scoped("orders".to_owned(), &db, "acme").await?;
/// ```
pub trait ScopedRow: ScopedTable {
    /// What the route's key segment parses into.
    type Key: Into<Value> + Send;

    /// Column the key matches.
    const KEY_COLUMN: <Self::Entity as EntityTrait>::Column;

    /// One row, or `None` if `scope` holds no such key.
    ///
    /// Built on [`scoped`](Self::scoped) rather than filtering from
    /// scratch, so the instance lookup cannot drift from the listing.
    ///
    /// Generic over the connection for the reason
    /// [`load_by_id`](ScopedTable::load_by_id) gives.
    fn load_scoped<C: ConnectionTrait>(
        key: Self::Key,
        db: &C,
        scope: impl Into<Value> + Send,
    ) -> impl Future<Output = Result<Option<Self>, DbErr>> + Send {
        // Built outside the async block so the future captures a plain
        // `Select` rather than the `impl Into<Value>` type parameter.
        let query = Self::scoped(scope).filter(Self::KEY_COLUMN.eq(key));
        async move { query.one(db).await }
    }

    /// Every row in `scope` whose key is one of `keys`, in one query.
    ///
    /// The lookup a request naming several objects at once wants — a body
    /// referring to three sources by name. Done a key at a time it is three
    /// round trips and, if each one is then authorized on its own, three
    /// policy evaluations; done here it is one `IN` and one filter.
    ///
    /// Absent keys are simply absent from the result: this answers *which
    /// of these exist in scope*, and the caller compares what came back
    /// against what it asked for. Confinement is [`scoped`](Self::scoped)'s,
    /// so a key belonging to another owner is missing for the same reason a
    /// key that does not exist is — the caller cannot tell which, and that
    /// is the property this trait exists to hold.
    fn load_all_scoped<C: ConnectionTrait>(
        keys: impl IntoIterator<Item = Self::Key> + Send,
        db: &C,
        scope: impl Into<Value> + Send,
    ) -> impl Future<Output = Result<Vec<Self>, DbErr>> + Send {
        let query = Self::scoped(scope).filter(Self::KEY_COLUMN.is_in(keys));
        async move { query.all(db).await }
    }
}

/// A load that failed for a reason the caller had nothing to do with.
///
/// The error type a SeaORM loader wants, so that `Granting::Error` is
/// something to name rather than something to write. There is one shape
/// worth having — a 500 the client is told nothing about, and the real
/// [`DbErr`] in the log — and no application-specific decision inside it,
/// which is why every consumer had been writing the same twenty lines.
///
/// Named once, on the application's profile, and every asset inherits it:
///
/// ```ignore
/// impl GrantProfile for AppGrants {
///     type Ctx = Caller;
///     type State = DatabaseConnection;
///     type Error = DbLoadError;
/// }
///
/// #[doxa::asset(row = Model, profile = AppGrants, actions = WidgetAction)]
/// pub struct WidgetByName;
/// ```
///
/// The loader `#[asset]` writes ends in `?`, so the only requirement this
/// type places on an application that substitutes its own error is
/// `From<DbErr>`.
///
/// A row the caller may not see is not this: [`ScopedRow::load_scoped`]
/// answers `Ok(None)` for a key in another scope exactly as it does for a
/// key that does not exist, and the guard turns that into a 404. This type
/// is only for the query itself failing.
///
/// ## Why it carries nothing
///
/// A [`DbErr`]'s `Display` can hold the statement, the column names and
/// sometimes a bound value. The response envelope is built from the error's
/// own `Display` and its serialized form, so anything this type held would
/// be a schema leak on a path nobody reviews — the 500 branch. It therefore
/// holds nothing, and the `From<`[`DbErr`]`>` impl logs before discarding.
///
/// Logging in a `From` is deliberate rather than incidental: the conversion
/// is the last point at which the diagnosis exists. A consumer that catches
/// the error and answers some other way still gets the record, which is not
/// true of a type that logs when it renders.
///
/// Requires the `sea-orm` feature; the response half requires `axum` too.
#[derive(Debug, thiserror::Error)]
#[cfg_attr(
    feature = "axum",
    derive(serde::Serialize, doxa::ToSchema, doxa_macros::ApiError)
)]
pub enum DbLoadError {
    /// The query did not complete. Deliberately incurious in what it says:
    /// the detail is in the log, under the request's own span.
    #[error("could not load the requested resource")]
    #[cfg_attr(feature = "axum", api(status = 500, code = "load_failed"))]
    Failed,
}

impl From<DbErr> for DbLoadError {
    fn from(error: DbErr) -> Self {
        tracing::error!(%error, "resource load failed");
        DbLoadError::Failed
    }
}

/// Answer the backend-neutral [`fetch`](crate::fetch) traits from a row's
/// [`ScopedTable`] — and, with `key`, its [`ScopedRow`].
///
/// `#[derive(PolicyResource)]` emits this, so a derived row needs nothing.
/// It is exported for the row that implements [`ScopedTable`] by hand,
/// which would otherwise transcribe three impls that have one possible
/// body each.
///
/// Why a macro rather than a blanket `impl<T: ScopedTable, C:
/// ConnectionTrait> Fetch<C> for T`: a blanket would be the last word.
/// Coherence cannot rule out a downstream row implementing both
/// [`ScopedTable`] and its own [`Fetch`](crate::fetch::Fetch) against some
/// non-SeaORM source, so the blanket would be rejected the moment any
/// consumer wrote the impl this whole module exists to make possible.
/// Emitting concrete impls per row leaves that door open.
///
/// ```ignore
/// impl ScopedTable for Model {
///     type Entity = Entity;
///     const SCOPE_COLUMN: Column = Column::TenantId;
/// }
///
/// impl ScopedRow for Model {
///     type Key = String;
///     const KEY_COLUMN: Column = Column::Name;
/// }
///
/// doxa_policy::fetch_from_scoped!(Model, key);
/// ```
///
/// Without the `key` argument only [`FetchById`](crate::fetch::FetchById)
/// and [`FetchSubset`](crate::fetch::FetchSubset) are written, which is
/// right for a table no route addresses by a column: it can still be
/// listed and still be reached by its own id.
#[cfg(feature = "sea-orm")]
#[macro_export]
macro_rules! fetch_from_scoped {
    ($row:ty) => {
        impl<C: $crate::__private::sea_orm::ConnectionTrait> $crate::fetch::Fetch<C> for $row {
            type Error = $crate::__private::sea_orm::DbErr;
        }

        impl<C: $crate::__private::sea_orm::ConnectionTrait> $crate::fetch::FetchById<C> for $row {
            type Id = $crate::PrimaryKeyOf<$row>;

            fn fetch_by_id(
                id: Self::Id,
                src: &C,
                scope: &str,
            ) -> impl ::core::future::Future<
                Output = ::core::result::Result<
                    ::core::option::Option<Self>,
                    $crate::__private::sea_orm::DbErr,
                >,
            > + Send {
                <$row as $crate::ScopedTable>::load_by_id(id, src, scope.to_owned())
            }
        }

        impl $crate::fetch::FetchSubset for $row {
            type Filter = $crate::__private::sea_orm::Select<<$row as $crate::ScopedTable>::Entity>;

            fn subset(scope: &str) -> Self::Filter {
                <$row as $crate::ScopedTable>::scoped(scope.to_owned())
            }
        }
    };
    ($row:ty, key) => {
        $crate::fetch_from_scoped!($row);

        impl<C: $crate::__private::sea_orm::ConnectionTrait> $crate::fetch::FetchByKey<C> for $row {
            type Key = <$row as $crate::ScopedRow>::Key;

            fn fetch(
                key: Self::Key,
                src: &C,
                scope: &str,
            ) -> impl ::core::future::Future<
                Output = ::core::result::Result<
                    ::core::option::Option<Self>,
                    $crate::__private::sea_orm::DbErr,
                >,
            > + Send {
                <$row as $crate::ScopedRow>::load_scoped(key, src, scope.to_owned())
            }
        }
    };
}
