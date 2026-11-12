//! SeaORM loaders confined to a scope column. [`ScopedTable`] is the table's half (scope,
//! attribute columns, listing, id lookup); [`ScopedRow`] adds the key a route matches on.
//! [`DbLoadError`] is the 500 a failed query answers with.

use std::future::Future;

use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, DbErr, EntityTrait, FromQueryResult, PrimaryKeyTrait,
    QueryFilter, Select, Value,
};

/// The value a row's primary key takes, for [`ScopedTable::load_by_id`].
pub type PrimaryKeyOf<R> =
    <<<R as ScopedTable>::Entity as EntityTrait>::PrimaryKey as PrimaryKeyTrait>::ValueType;

/// A table one scope column confines, so another owner's row is absent (404), never refused.
/// `FromQueryResult` is a supertrait because rustc won't infer it back through `Entity = Self`.
///
/// ```ignore
/// impl ScopedTable for Model {
///     type Entity = Entity;
///     const SCOPE_COLUMN: Column = Column::TenantId;
/// }
///
/// let page = Model::scoped("acme").paginate(&db, 50);
/// ```
pub trait ScopedTable: Sized + Send + FromQueryResult {
    /// Table the scope column sits in.
    type Entity: EntityTrait<Model = Self>;

    /// Column carrying the owner every query is confined to.
    const SCOPE_COLUMN: <Self::Entity as EntityTrait>::Column;

    /// This table's column for `resource.<attr>`. `None` (the default) makes a residual refuse;
    /// never map an attribute to another table's column.
    fn column_for_attr(_attr: &str) -> Option<<Self::Entity as EntityTrait>::Column> {
        None
    }

    /// A condition every query carries besides the scope, such as a soft-delete tombstone;
    /// `#[resource(filter = …)]` writes it.
    fn table_condition() -> Option<Condition> {
        None
    }

    /// Every row `scope` owns, as a `Select` the caller pages.
    fn scoped(scope: impl Into<Value>) -> Select<Self::Entity> {
        let query = Self::Entity::find().filter(Self::SCOPE_COLUMN.eq(scope));
        match Self::table_condition() {
            Some(condition) => query.filter(condition),
            None => query,
        }
    }

    /// One row by primary key, still confined to `scope`, unlike `find_by_id`. Generic over the
    /// connection so a transaction sees its own uncommitted rows.
    fn load_by_id<C: ConnectionTrait>(
        id: PrimaryKeyOf<Self>,
        db: &C,
        scope: impl Into<Value> + Send,
    ) -> impl Future<Output = Result<Option<Self>, DbErr>> + Send {
        // `find_by_id` isn't built on `scoped`, so fold the table condition in by hand.
        let query = Self::Entity::find_by_id(id).filter(Self::SCOPE_COLUMN.eq(scope));
        let query = match Self::table_condition() {
            Some(condition) => query.filter(condition),
            None => query,
        };
        async move { query.one(db).await }
    }
}

/// A row one key resolves to, within its table's scope.
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

    /// Every row in `scope` whose key is one of `keys`, in one query; absent keys are omitted.
    fn load_all_scoped<C: ConnectionTrait>(
        keys: impl IntoIterator<Item = Self::Key> + Send,
        db: &C,
        scope: impl Into<Value> + Send,
    ) -> impl Future<Output = Result<Vec<Self>, DbErr>> + Send {
        let query = Self::scoped(scope).filter(Self::KEY_COLUMN.is_in(keys));
        async move { query.all(db).await }
    }
}

/// A failed query: a 500 with nothing in the body, the [`DbErr`] logged by `From` (it can hold
/// SQL and bound values).
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

/// The [`fetch`](crate::fetch) traits from a hand-written [`ScopedTable`] (and, with `key`,
/// [`ScopedRow`]). A macro, since a blanket impl would forbid a row's own non-SeaORM `Fetch`.
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
/// #[derive(serde::Deserialize)]
/// struct ModelKey { name: String }
///
/// doxa_policy::fetch_from_scoped!(Model, key = ModelKey { name });
/// ```
///
/// Without `key`, only `FetchById` and `FetchSubset`. The key struct's field names are the
/// route parameters it binds by.
#[cfg(feature = "sea-orm")]
#[macro_export]
macro_rules! fetch_from_scoped {
    // No id struct: nothing routes to this row by its own id, so the id
    // stays SeaORM's own primary-key value and names no segment.
    ($row:ty) => {
        $crate::__fetch_row!($row);

        impl<C: $crate::__private::sea_orm::ConnectionTrait> $crate::fetch::FetchById<C> for $row {
            type Id = $crate::PrimaryKeyOf<$row>;

            const ID_NAMES: &'static [&'static str] = &[];

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
    };
    ($row:ty, id = $idty:ident { $($idf:ident),+ $(,)? }) => {
        $crate::__fetch_row!($row);

        impl<C: $crate::__private::sea_orm::ConnectionTrait> $crate::fetch::FetchById<C> for $row {
            type Id = $idty;

            const ID_NAMES: &'static [&'static str] = &[$(::core::stringify!($idf)),+];

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
                let $idty { $($idf,)+ } = id;
                <$row as $crate::ScopedTable>::load_by_id(
                    $crate::__pk_value!($($idf),+),
                    src,
                    scope.to_owned(),
                )
            }
        }
    };
    ($row:ty, key = $key:ident { $field:ident }) => {
        $crate::fetch_from_scoped!($row);
        $crate::__fetch_by_key!($row, key = $key { $field });
    };
    (
        $row:ty,
        id = $idty:ident { $($idf:ident),+ $(,)? },
        key = $key:ident { $field:ident }
    ) => {
        $crate::fetch_from_scoped!($row, id = $idty { $($idf),+ });
        $crate::__fetch_by_key!($row, key = $key { $field });
    };
}

/// `Fetch` and `FetchSubset`, which every arm of
/// [`fetch_from_scoped!`](crate::fetch_from_scoped) writes identically.
#[cfg(feature = "sea-orm")]
#[macro_export]
#[doc(hidden)]
macro_rules! __fetch_row {
    ($row:ty) => {
        impl<C: $crate::__private::sea_orm::ConnectionTrait> $crate::fetch::Fetch<C> for $row {
            type Error = $crate::__private::sea_orm::DbErr;
        }

        impl $crate::fetch::FetchSubset for $row {
            type Filter = $crate::__private::sea_orm::Select<<$row as $crate::ScopedTable>::Entity>;

            fn subset(scope: &str) -> Self::Filter {
                <$row as $crate::ScopedTable>::scoped(scope.to_owned())
            }
        }
    };
}

/// A primary key as [`ScopedTable::load_by_id`] takes it: one column bare, several a tuple.
#[cfg(feature = "sea-orm")]
#[macro_export]
#[doc(hidden)]
macro_rules! __pk_value {
    ($field:ident) => { $field };
    ($first:ident, $($rest:ident),+) => { ($first, $($rest),+) };
}

#[cfg(feature = "sea-orm")]
#[macro_export]
#[doc(hidden)]
macro_rules! __fetch_by_key {
    ($row:ty, key = $key:ident { $field:ident }) => {
        impl<C: $crate::__private::sea_orm::ConnectionTrait> $crate::fetch::FetchByKey<C> for $row {
            type Key = $key;

            const KEY_NAMES: &'static [&'static str] = &[::core::stringify!($field)];

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
                let $key { $field } = key;
                <$row as $crate::ScopedRow>::load_scoped($field, src, scope.to_owned())
            }
        }
    };
}

/// Declare a named [`Lookup`](crate::fetch::Lookup) marker over a [`ScopedTable`], with its key
/// struct and the columns it matches.
///
/// ```ignore
/// doxa_policy::scoped_lookup!(pub FindByName as FindByNameKey for Model {
///     name: String => Column::Name,
/// });
///
/// doxa_policy::scoped_lookup!(pub FindByPair as FindByPairKey for Model {
///     widget:   String => Column::Widget,
///     revision: i64    => Column::Revision,
/// });
///
/// let key = FindByPairKey { widget: "sprocket".into(), revision: 3 };
/// ```
///
/// The key derives `serde::Deserialize`, so the caller needs `serde`; it gets no `RouteKey`
/// impl, which the derive writes.
#[cfg(feature = "sea-orm")]
#[macro_export]
macro_rules! scoped_lookup {
    // Always named fields: they bind segments by name, so same-typed ones can't swap.
    (
        $(#[$meta:meta])*
        $vis:vis $name:ident as $key:ident for $row:ty {
            $($field:ident : $ty:ty => $column:expr),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis struct $name;

        #[doc = ::core::concat!("The key [`", ::core::stringify!($name), "`] matches on.")]
        #[derive(Debug, Clone, PartialEq, Eq, ::serde::Deserialize)]
        $vis struct $key {
            $(
                #[allow(missing_docs)]
                pub $field: $ty,
            )+
        }

        impl<C: $crate::__private::sea_orm::ConnectionTrait> $crate::fetch::Lookup<C> for $name {
            type Row = $row;
            type Key = $key;
            type Error = $crate::__private::sea_orm::DbErr;

            const KEY_NAMES: &'static [&'static str] =
                &[$(::core::stringify!($field)),+];

            fn fetch(
                key: Self::Key,
                src: &C,
                scope: &str,
            ) -> impl ::core::future::Future<
                Output = ::core::result::Result<
                    ::core::option::Option<$row>,
                    $crate::__private::sea_orm::DbErr,
                >,
            > + Send {
                use $crate::__private::sea_orm::{ColumnTrait as _, QueryFilter as _};

                // Built outside the async block, so the future captures a
                // plain `Select` rather than the borrow of `scope`.
                let query = <$row as $crate::ScopedTable>::scoped(scope.to_owned());
                let $key { $($field,)+ } = key;
                let query = query $(.filter($column.eq($field)))+;
                async move { query.one(src).await }
            }
        }
    };
}
