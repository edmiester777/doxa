//! SeaORM migrator for the `doxa_audit_log` table.
//!
//! The migrator uses its own tracking table (`doxa_audit_seaql_migrations`)
//! so it never touches the consumer application's own `seaql_migrations`.
//! Run it standalone:
//!
//! ```ignore
//! use sea_orm_migration::MigratorTrait;
//! doxa_audit::Migrator::up(&db, None).await?;
//! ```
//!
//! Or use the [`crate::init`] convenience wrapper.

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
        vec![Box::new(m20260515_000001_create_audit_log::Migration)]
    }

    fn migration_table_name() -> sea_orm::DynIden {
        Alias::new("doxa_audit_seaql_migrations").into_iden()
    }
}

mod m20260515_000001_create_audit_log {
    use sea_orm::Schema;
    use sea_orm_migration::prelude::*;

    use crate::entity::doxa_audit_log;

    #[derive(DeriveMigrationName)]
    pub struct Migration;

    #[async_trait::async_trait]
    impl MigrationTrait for Migration {
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
