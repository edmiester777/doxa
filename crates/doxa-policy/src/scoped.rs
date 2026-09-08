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
    ColumnTrait, DatabaseConnection, DbErr, EntityTrait, FromQueryResult, QueryFilter, Select,
    Value,
};

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

    /// One row, or `None` if `scope` holds no such key.
    ///
    /// Built on [`scoped`](Self::scoped) rather than filtering from
    /// scratch, so the instance lookup cannot drift from the listing.
    fn load_scoped(
        key: Self::Key,
        db: &DatabaseConnection,
        scope: impl Into<Value> + Send,
    ) -> impl Future<Output = Result<Option<Self>, DbErr>> + Send {
        // Built outside the async block so the future captures a plain
        // `Select` rather than the `impl Into<Value>` type parameter.
        let query = Self::scoped(scope).filter(Self::KEY_COLUMN.eq(key));
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
/// #[doxa::asset(row = Model, profile = AppGrants, actions = SourceAction)]
/// pub struct SourceByName;
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
