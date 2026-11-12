//! SeaORM migrator for `doxa_audit_log`, tracked in its own `doxa_audit_seaql_migrations`.
//! Every migration shares this file, so `DeriveMigrationName` (the file stem) can't name them:
//! write [`MigrationName`] by hand, and never rename a shipped one.
//!
//! ```ignore
//! use sea_orm_migration::MigratorTrait;
//! doxa_audit::Migrator::up(&db, None).await?;
//! ```

use sea_orm::{DatabaseConnection, DbErr};
use sea_orm_migration::prelude::*;

/// Run all pending `doxa-audit` migrations against `db`.
///
/// Convenience wrapper around `Migrator::up(db, None)` for callers that
/// don't want to import [`MigratorTrait`]. Idempotent — applied
/// migrations are tracked in `doxa_audit_seaql_migrations`.
pub async fn init(db: &DatabaseConnection) -> Result<(), DbErr> {
    Migrator::up(db, None).await
}

/// SeaORM migrator owning the `doxa_audit_log` schema.
///
/// Tracks applied migrations in `doxa_audit_seaql_migrations` — isolated
/// from any other migrator running against the same database.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260515_000001_create_audit_log::Migration),
            Box::new(m20260723_000001_add_tenant_id::Migration),
            Box::new(m20260723_000002_add_audit_log_indexes::Migration),
        ]
    }

    fn migration_table_name() -> sea_orm::DynIden {
        Alias::new("doxa_audit_seaql_migrations").into_iden()
    }
}

mod m20260515_000001_create_audit_log {
    use sea_orm::Schema;
    use sea_orm_migration::prelude::*;

    use crate::entity::doxa_audit_log;

    pub struct Migration;

    impl MigrationName for Migration {
        /// Frozen: databases from 0.1.4–0.1.6 recorded this name, and renaming it recreates the table.
        fn name(&self) -> &str {
            "migration"
        }
    }

    #[async_trait::async_trait]
    impl MigrationTrait for Migration {
        /// Built from the live entity, so a later migration adding a column must guard on
        /// [`SchemaManager::has_column`].
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            let backend = manager.get_database_backend();
            let schema = Schema::new(backend);
            let stmt = schema.create_table_from_entity(doxa_audit_log::Entity);
            manager.create_table(stmt).await
        }

        async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .drop_table(Table::drop().table(doxa_audit_log::Entity).to_owned())
                .await
        }
    }
}

mod m20260723_000001_add_tenant_id {
    use sea_orm_migration::prelude::*;

    use crate::entity::doxa_audit_log::{Column, Entity};

    pub struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m20260723_000001_add_tenant_id"
        }
    }

    #[async_trait::async_trait]
    impl MigrationTrait for Migration {
        /// Nullable: auth failures are recorded before a tenant is known. A no-op where the
        /// create-table migration already built the column.
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            if manager.has_column("doxa_audit_log", "tenant_id").await? {
                return Ok(());
            }

            manager
                .alter_table(
                    Table::alter()
                        .table(Entity)
                        .add_column(ColumnDef::new(Column::TenantId).string_len(255).null())
                        .to_owned(),
                )
                .await
        }

        async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            manager
                .alter_table(
                    Table::alter()
                        .table(Entity)
                        .drop_column(Column::TenantId)
                        .to_owned(),
                )
                .await
        }
    }
}

mod m20260723_000002_add_audit_log_indexes {
    use sea_orm_migration::prelude::*;

    use crate::entity::doxa_audit_log::{Column, Entity};

    pub struct Migration;

    impl MigrationName for Migration {
        fn name(&self) -> &str {
            "m20260723_000002_add_audit_log_indexes"
        }
    }

    /// Each filter column's index, trailing `created_at DESC` so a newest-first read stops at
    /// its `LIMIT` instead of sorting.
    pub(super) fn index_specs() -> Vec<(&'static str, Vec<Column>)> {
        vec![
            // Unfiltered timeline; also the retention sweep.
            ("idx_doxa_audit_log_created_at", vec![]),
            // "Everything that happened in this tenant."
            (
                "idx_doxa_audit_log_tenant_created_at",
                vec![Column::TenantId],
            ),
            // "Everything this principal did" — subject-access requests.
            (
                "idx_doxa_audit_log_actor_created_at",
                vec![Column::ActorSub],
            ),
            // "Who touched this record" — the per-object history view.
            (
                "idx_doxa_audit_log_resource",
                vec![Column::ResourceType, Column::ResourceId],
            ),
            // "All admin deletes last quarter" — category rollups.
            (
                "idx_doxa_audit_log_event_type_created_at",
                vec![Column::EventType],
            ),
            // "Every denial" — the failed-access review control.
            (
                "idx_doxa_audit_log_outcome_created_at",
                vec![Column::Outcome],
            ),
        ]
    }

    /// Build `CREATE INDEX <name> ON doxa_audit_log (<cols…>, created_at DESC)`.
    pub(super) fn timeline_index(name: &str, prefix: &[Column]) -> IndexCreateStatement {
        let mut stmt = Index::create();
        stmt.if_not_exists().name(name).table(Entity);
        for col in prefix {
            stmt.col(*col);
        }
        stmt.col((Column::CreatedAt, IndexOrder::Desc));
        stmt.to_owned()
    }

    /// Correlates an audit row back to the `x-request-id` in the
    /// application logs. Point lookup, no time ordering to preserve.
    pub(super) fn request_id_index() -> IndexCreateStatement {
        Index::create()
            .if_not_exists()
            .name("idx_doxa_audit_log_request_id")
            .table(Entity)
            .col(Column::RequestId)
            .to_owned()
    }

    #[async_trait::async_trait]
    impl MigrationTrait for Migration {
        async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            for (name, prefix) in index_specs() {
                manager.create_index(timeline_index(name, &prefix)).await?;
            }
            manager.create_index(request_id_index()).await
        }

        async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
            for (name, _) in index_specs() {
                manager
                    .drop_index(
                        Index::drop()
                            .if_exists()
                            .name(name)
                            .table(Entity)
                            .to_owned(),
                    )
                    .await?;
            }
            manager
                .drop_index(
                    Index::drop()
                        .if_exists()
                        .name("idx_doxa_audit_log_request_id")
                        .table(Entity)
                        .to_owned(),
                )
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement};

    use super::*;

    /// Every index `m20260723_000002` is expected to leave behind.
    const EXPECTED_INDEXES: &[&str] = &[
        "idx_doxa_audit_log_created_at",
        "idx_doxa_audit_log_tenant_created_at",
        "idx_doxa_audit_log_actor_created_at",
        "idx_doxa_audit_log_resource",
        "idx_doxa_audit_log_event_type_created_at",
        "idx_doxa_audit_log_outcome_created_at",
        "idx_doxa_audit_log_request_id",
    ];

    async fn migrated_db() -> DatabaseConnection {
        // Each `sqlite::memory:` connection is its own database, so pin the pool to one.
        let mut opts = sea_orm::ConnectOptions::new("sqlite::memory:");
        opts.max_connections(1).sqlx_logging(false);

        let db = Database::connect(opts).await.expect("in-memory sqlite");
        Migrator::up(&db, None).await.expect("migrations apply");
        db
    }

    /// Indexes this migrator owns, excluding the implicit one SQLite
    /// builds for the non-integer primary key.
    async fn index_names(db: &DatabaseConnection) -> Vec<String> {
        db.query_all_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT name FROM sqlite_master \
             WHERE type = 'index' AND tbl_name = 'doxa_audit_log' \
               AND name LIKE 'idx_doxa_audit_log_%'",
        ))
        .await
        .expect("read sqlite_master")
        .iter()
        .map(|row| row.try_get::<String>("", "name").expect("name column"))
        .collect()
    }

    #[tokio::test]
    async fn migrations_create_every_index() {
        let db = migrated_db().await;
        let found = index_names(&db).await;

        for expected in EXPECTED_INDEXES {
            assert!(
                found.iter().any(|n| n == expected),
                "missing index {expected}; found {found:?}",
            );
        }
    }

    #[tokio::test]
    async fn migrations_are_idempotent() {
        let db = migrated_db().await;

        // A second `up` must find nothing pending rather than replaying
        // the index creates against a schema that already has them.
        Migrator::up(&db, None).await.expect("second up is a no-op");
        assert_eq!(index_names(&db).await.len(), EXPECTED_INDEXES.len());
    }

    #[tokio::test]
    async fn tenant_id_is_added_to_a_pre_existing_table() {
        let db = migrated_db().await;
        let manager = SchemaManager::new(&db);

        // A pre-column database. SQLite won't drop a column an index references.
        for sql in [
            "DROP INDEX idx_doxa_audit_log_tenant_created_at",
            "ALTER TABLE doxa_audit_log DROP COLUMN tenant_id",
        ] {
            db.execute_raw(Statement::from_string(DbBackend::Sqlite, sql))
                .await
                .unwrap_or_else(|e| panic!("{sql}: {e}"));
        }
        assert!(!manager
            .has_column("doxa_audit_log", "tenant_id")
            .await
            .unwrap());

        m20260723_000001_add_tenant_id::Migration
            .up(&manager)
            .await
            .expect("add tenant_id");

        assert!(manager
            .has_column("doxa_audit_log", "tenant_id")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn add_tenant_id_is_a_noop_when_the_column_exists() {
        let db = migrated_db().await;
        let manager = SchemaManager::new(&db);

        // The path a fresh database takes: the column is already there,
        // so a second ALTER must be skipped rather than erroring.
        m20260723_000001_add_tenant_id::Migration
            .up(&manager)
            .await
            .expect("no-op on a table that already has the column");
    }

    #[tokio::test]
    async fn down_reverts_the_whole_schema() {
        let db = migrated_db().await;

        Migrator::down(&db, None).await.expect("full rollback");

        assert!(!SchemaManager::new(&db)
            .has_table("doxa_audit_log")
            .await
            .unwrap());
    }

    /// SQLite can't report index column order, so pin the Postgres DDL.
    #[test]
    fn postgres_ddl_orders_created_at_descending() {
        use m20260723_000002_add_audit_log_indexes as indexes;
        use sea_orm::sea_query::PostgresQueryBuilder;

        let rendered: Vec<String> = indexes::index_specs()
            .into_iter()
            .map(|(name, prefix)| {
                indexes::timeline_index(name, &prefix).to_string(PostgresQueryBuilder)
            })
            .collect();

        assert_eq!(
            rendered,
            vec![
                r#"CREATE INDEX IF NOT EXISTS "idx_doxa_audit_log_created_at" ON "doxa_audit_log" ("created_at" DESC)"#,
                r#"CREATE INDEX IF NOT EXISTS "idx_doxa_audit_log_tenant_created_at" ON "doxa_audit_log" ("tenant_id", "created_at" DESC)"#,
                r#"CREATE INDEX IF NOT EXISTS "idx_doxa_audit_log_actor_created_at" ON "doxa_audit_log" ("actor_sub", "created_at" DESC)"#,
                r#"CREATE INDEX IF NOT EXISTS "idx_doxa_audit_log_resource" ON "doxa_audit_log" ("resource_type", "resource_id", "created_at" DESC)"#,
                r#"CREATE INDEX IF NOT EXISTS "idx_doxa_audit_log_event_type_created_at" ON "doxa_audit_log" ("event_type", "created_at" DESC)"#,
                r#"CREATE INDEX IF NOT EXISTS "idx_doxa_audit_log_outcome_created_at" ON "doxa_audit_log" ("outcome", "created_at" DESC)"#,
            ],
        );

        assert_eq!(
            indexes::request_id_index().to_string(PostgresQueryBuilder),
            r#"CREATE INDEX IF NOT EXISTS "idx_doxa_audit_log_request_id" ON "doxa_audit_log" ("request_id")"#,
        );
    }
}
