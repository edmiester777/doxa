//! Loading the row a policy decision is then made about.
//!
//! [`PolicyResource`](crate::PolicyResource) says what a row *is* to
//! Cedar. This says how a route *reaches* it. The two are separate
//! because identity is one fact about a table while a lookup is one per
//! route: a row addressed by name and the same row addressed by id are
//! one Cedar entity with two loaders, and only the loaders differ.
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

/// The value a row's primary key takes, for [`ScopedRow::load_by_id`].
pub type PrimaryKeyOf<R> =
    <<<R as ScopedRow>::Entity as EntityTrait>::PrimaryKey as PrimaryKeyTrait>::ValueType;

/// A row one key resolves to, within one scope column.
///
/// The scope column is the whole security property: every lookup is
/// confined to it, so a key belonging to someone else is indistinguishable
/// from a key that does not exist. Both answer `None`, and a route built
/// on this cannot leak the existence of another owner's object by
/// answering 403 where it would otherwise answer 404.
///
/// Both methods have default bodies, so an implementation is four lines —
/// which is why `#[derive(PolicyResource)]` can write it from
/// `#[resource(key)]` and `#[resource(scope)]` and leave nothing behind.
///
/// # Example
///
/// ```ignore
/// impl ScopedRow for Model {
///     type Entity = Entity;
///     type Key = String;
///     const KEY_COLUMN: Column = Column::Name;
///     const SCOPE_COLUMN: Column = Column::CompanyId;
/// }
///
/// let row = Model::load_scoped("orders".to_owned(), &db, "acme").await?;
/// ```
/// `FromQueryResult` is a supertrait rather than left to
/// `EntityTrait::Model`'s own bound: the compiler will not read that bound
/// backwards through `Entity = Self`, and every SeaORM `Model` satisfies
/// it anyway.
pub trait ScopedRow: Sized + Send + FromQueryResult {
    /// Table the key resolves in.
    type Entity: EntityTrait<Model = Self>;

    /// What the route's key segment parses into.
    type Key: Into<Value> + Send;

    /// Column the key matches.
    const KEY_COLUMN: <Self::Entity as EntityTrait>::Column;

    /// Column carrying the owner every lookup is confined to.
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
    fn column_for_attr(_attr: &str) -> Option<<Self::Entity as EntityTrait>::Column> {
        None
    }

    /// One row, or `None` if `scope` holds no such key.
    ///
    /// Built on [`scoped`](Self::scoped) rather than filtering from
    /// scratch, so the instance lookup cannot drift from the listing.
    ///
    /// Generic over the connection rather than taking a
    /// [`DatabaseConnection`](sea_orm::DatabaseConnection), so the same
    /// derived lookup serves a handler that has a transaction open. That is
    /// not a convenience: a pool cannot see rows the request has written
    /// and not committed, so a loader pinned to one would answer `None` for
    /// an object the caller is holding — and the route would 404 on
    /// something it just created. Every lookup here takes `&C` for that
    /// reason.
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

    /// One row by primary key, still confined to `scope`.
    ///
    /// The sibling of [`load_scoped`](Self::load_scoped), for the route
    /// that addresses the same table by its id rather than by
    /// [`KEY_COLUMN`](Self::KEY_COLUMN).
    ///
    /// It exists because the obvious hand-written version is wrong in a
    /// way that passes every test. `Entity::find_by_id(id).one(db)` is
    /// what a primary-key lookup looks like, and it ignores the scope
    /// entirely: a caller naming another tenant's id gets that tenant's
    /// row. An instance check will usually still refuse it — but by then
    /// the route has answered `403` where it would have answered `404`,
    /// and that difference confirms the row exists. Every lookup on this
    /// trait takes the scope for that reason, and this one is here so the
    /// id route does not have to be written out to get it.
    fn load_by_id<C: ConnectionTrait>(
        id: PrimaryKeyOf<Self>,
        db: &C,
        scope: impl Into<Value> + Send,
    ) -> impl Future<Output = Result<Option<Self>, DbErr>> + Send {
        let query = Self::Entity::find_by_id(id).filter(Self::SCOPE_COLUMN.eq(scope));
        async move { query.one(db).await }
    }

    /// Every row `scope` owns, as a `Select` the caller pages.
    fn scoped(scope: impl Into<Value>) -> Select<Self::Entity> {
        Self::Entity::find().filter(Self::SCOPE_COLUMN.eq(scope))
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
