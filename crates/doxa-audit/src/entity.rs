//! SeaORM entity for the `doxa_audit_log` table.

pub mod doxa_audit_log {
    use crate::event::Outcome;
    use sea_orm::entity::prelude::*;
    use serde::{Deserialize, Serialize};

    /// Append-only SOC 2 audit log entry capturing data access events.
    ///
    /// No foreign keys — the audit log is fully self-contained and must
    /// never cascade-delete. Actor fields are a point-in-time snapshot,
    /// not live references to RBAC tables.
    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
    #[sea_orm(table_name = "doxa_audit_log")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        #[sea_orm(column_type = "String(StringLen::N(50))")]
        pub event_type: String,
        /// Specific action (e.g. `read`, `create_role`, `delete_document`).
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub action: String,
        pub outcome: Outcome,
        /// JWT `sub` claim of the actor.
        #[sea_orm(column_type = "String(StringLen::N(255))", nullable)]
        pub actor_sub: Option<String>,
        /// Snapshot of the actor's roles at event time (not a live FK).
        #[sea_orm(column_type = "JsonBinary", nullable)]
        pub actor_roles: Option<serde_json::Value>,
        /// Consumer-defined identity attributes (tenant id, project id,
        /// department, …). Opaque JSON — the library has no opinion on
        /// the shape. Query with JSON operators (`actor_attrs->>'key'`)
        /// when filtering by tenant.
        #[sea_orm(column_type = "JsonBinary")]
        pub actor_attrs: serde_json::Value,
        /// Resource type name — `document`, `role`, `connection`, etc.
        #[sea_orm(column_type = "String(StringLen::N(100))", nullable)]
        pub resource_type: Option<String>,
        /// Resource identifier — document id, role UUID, etc.
        #[sea_orm(column_type = "String(StringLen::N(255))", nullable)]
        pub resource_id: Option<String>,
        /// Sanitized request payload — never contains raw secrets.
        #[sea_orm(column_type = "JsonBinary", nullable)]
        pub request_body: Option<serde_json::Value>,
        /// Metadata only (record count, duration) — never raw query results.
        #[sea_orm(column_type = "JsonBinary", nullable)]
        pub response_summary: Option<serde_json::Value>,
        /// Client IP from `X-Forwarded-For` or `ConnectInfo`.
        #[sea_orm(column_type = "String(StringLen::N(45))", nullable)]
        pub source_ip: Option<String>,
        /// HTTP User-Agent header.
        #[sea_orm(column_type = "String(StringLen::N(512))", nullable)]
        pub user_agent: Option<String>,
        /// Correlates with `x-request-id` for log correlation.
        #[sea_orm(column_type = "String(StringLen::N(100))", nullable)]
        pub request_id: Option<String>,
        /// HTTP method (GET, POST, etc.).
        #[sea_orm(column_type = "String(StringLen::N(10))", nullable)]
        pub http_method: Option<String>,
        /// Request path (e.g. `/api/v1/widgets/42`).
        #[sea_orm(column_type = "String(StringLen::N(2048))", nullable)]
        pub http_path: Option<String>,
        /// HTTP response status code.
        pub http_status: Option<i16>,
        /// Request duration in milliseconds.
        pub duration_ms: Option<i64>,
        /// Error detail when outcome is `denied` or `error`.
        #[sea_orm(column_type = "Text", nullable)]
        pub error_message: Option<String>,
        pub created_at: DateTimeWithTimeZone,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
