# doxa-audit

SOC 2-flavored append-only audit logging primitives with an optional SeaORM persistence backend. Events buffer through an async mpsc channel and persist via a background writer — query execution is never blocked.

## Usage

### Manual event emission

```rust
use doxa_audit::{AuditEventBuilder, AuditLogger, EventType, Outcome};

let audit = AuditEventBuilder::new(logger.clone());
audit.set_actor(Some(&principal), &roles, json!({ "tenant": tenant }));
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
