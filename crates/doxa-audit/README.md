# doxa-audit

SOC 2-flavored append-only audit logging primitives with an optional SeaORM persistence backend. Events buffer through an async mpsc channel and persist via a background writer — query execution is never blocked.

## Usage

### Manual event emission

```rust
use doxa_audit::{AuditEventBuilder, AuditLogger, EventType, Outcome};

let audit = AuditEventBuilder::new(logger.clone());
audit.set_actor(Some(&principal), &roles, json!({ "department": dept }));
audit.set_tenant(Some(&tenant));
audit.set_event(EventType::DataAccess, "read");
audit.set_resource("document", "doc-42");
audit.set_outcome(Outcome::Allowed);
audit.emit();  // non-blocking — buffered to the channel
```

### Automatic with `AuditLayer`

Stack the middleware outside the auth layer. It creates an `AuditEventBuilder` per request, captures HTTP metadata, and auto-emits with `Outcome::Allowed` after the response. Auth failures and `ApiError` outcomes propagate automatically.

```rust
use doxa_audit::{AuditLayer, spawn_audit_writer};

let audit_logger = spawn_audit_writer(db.clone(), 4096);

let audited = OpenApiRouter::new()
    .routes(routes!(list_documents, get_document))
    .layer_documented(AuthLayer::new(auth_state))
    .layer(AuditLayer::new(audit_logger));
```

Handlers enrich the builder from extensions — no terminal call needed:

```rust
async fn get_document(
    Path(id): Path<String>,
    Extension(audit): Extension<AuditEventBuilder>,
) -> Result<Json<Document>, DocumentError> {
    audit.set_event(EventType::DataAccess, "read");
    audit.set_resource("document", &id);
    Ok(Json(db::find_document(&id).await?))
    // AuditLayer auto-emits Outcome::Allowed
}
```

### Custom event types

Define domain-specific event vocabularies:

```rust
use doxa_audit::AuditEventType;

#[derive(Debug, Clone, Copy)]
enum BillingEvent {
    InvoiceGenerated,
    PaymentProcessed,
}

impl AuditEventType for BillingEvent {
    fn as_str(&self) -> &str {
        match self {
            Self::InvoiceGenerated  => "billing.invoice_generated",
            Self::PaymentProcessed  => "billing.payment_processed",
        }
    }
}

audit.set_event(BillingEvent::PaymentProcessed, "charge");
```

## Tenancy

`tenant_id` is a first-class indexed column, not a key inside
`actor_attrs`. With `doxa-auth` in the stack it is populated
automatically from `Claims::scope()` — the same partition key the policy
evaluator scopes by, so an audit trail filters to exactly the tenant
whose policies decided the request. Outside a request's auth context,
set it yourself with `set_tenant`.

It is nullable: single-tenant deployments never set it, and auth
failures are recorded before a principal — and therefore a tenant — has
been resolved. Every other identity dimension (project, department, …)
stays in the opaque `actor_attrs` JSON.

## Schema and indexes

`Migrator` owns `doxa_audit_log` and tracks itself in
`doxa_audit_seaql_migrations`, isolated from the consuming
application's own migrations. Indexes ship with the schema:

| Index | Serves |
|-------|--------|
| `created_at DESC` | Unfiltered timeline; retention sweeps |
| `tenant_id, created_at DESC` | Per-tenant activity feed |
| `actor_sub, created_at DESC` | "Everything this principal did" — subject-access requests |
| `resource_type, resource_id, created_at DESC` | Per-object history |
| `event_type, created_at DESC` | Category rollups |
| `outcome, created_at DESC` | Failed-access review |
| `request_id` | Correlation back to application logs |

Each composite trails `created_at DESC` so a filtered scan comes back
already ordered — audit reads are newest-first without exception, so the
planner walks matching rows in output order and stops at the `LIMIT`
instead of sorting the whole match set.

This is a write-amplifying set, and an append-only log pays for every
index on every insert. It is sized for deployments that actually query
their audit trail; drop the ones yours never uses.

## Key types

| Type | Purpose |
|------|---------|
| `AuditLogger` | Channel sender for emitting events |
| `AuditEventBuilder` | Stateful builder for constructing events (Arc-backed, clone-safe) |
| `AuditEvent` | Complete audit event record |
| `AuditEventType` | Trait for custom event-type enums |
| `EventType` | Reference implementation (DataAccess, AdminCreate, AdminUpdate, etc.) |
| `Outcome` | Allowed / Denied / Error |
| `AuditLayer` | Tower middleware for automatic audit emission |
| `spawn_audit_writer` | Background persistence task (SeaORM-backed) |

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `sea-orm` | yes | SeaORM-backed persistence via `spawn_audit_writer` |

Disable `sea-orm` to consume only the channel surface and ship events to your own sink.

## License

Apache 2.0
