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

### Decisions deposited by a guard

An authorization guard reaches its verdict before the handler runs, so it must not use the setters above — the last call wins between two of them, and the guard would pre-empt a handler that has not spoken yet. It deposits a `Decision` instead:

```rust
use doxa_audit::Decision;

audit.record_decision(
    Decision::granted("read", "Document", &id).with_event_type(EventType::DataAccess),
);
```

The deposit is folded into the event at emit time, filling only fields nothing else named — so order stops mattering and the handler always wins. `doxa-auth`'s `Granted<T>` does exactly this, which is why a guarded route's handler writes nothing to the builder at all.

Two rules break the tie when there is one:

- **Between two deposits, the first stands.** A route's own subject is authorized before its body is parsed, so a dependency named in that body does not displace it.
- **A refusal displaces a grant, and its `Denied` outcome overrides everything.** A request that ends on a denial is about that denial, and must never reach the trail looking allowed.

`Decision::denied(...)` carries both, plus `EventType::AuthFailure` and the reason as the event's error text. Pair it with `settle(status)`, which emits only when no `AuditLayer` is in the stack to do it later.

### Terminals inside a request record rather than send

Emitting *takes* the builder. Called from a handler or middleware that runs under an `AuditLayer`, that lands before the response exists — `http_status` is never stamped, `duration_ms` stops at the call, and anything fallible afterwards is already recorded as a success.

So under a layer, `emit`, `emit_allowed`, `emit_denied`, `emit_error` and `emit_permission_denied` record their outcome and return; the layer's `auto_emit` sends the same event moments later with the status and duration intact. Whatever you wanted recorded is recorded — only the timing changes, and the call itself becomes redundant rather than harmful.

Two consequences:

- A deferred emit does not freeze the builder, so a later write still lands. One event, sent at the end, carrying everything anyone knew about it.
- The response's outcome is applied afterwards and wins. An error variant annotated `outcome = "allowed"` lands on the event even where a handler had assumed worse — that annotation is the author declaring the failure benign, and it gets the final say.

A deposited `Decision` is the one thing the response cannot override, and only for its outcome. A policy refusal is not an opinion about how the request went; it is the event the trail exists for. Masking it in the response is legitimate and common — answering 404 rather than 403 so a caller cannot probe for what exists — and none of that unmakes the refusal. The client is told nothing; the trail is told everything.

With no `AuditLayer` in the stack, every terminal sends immediately, exactly as before.

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
| `Decision` | An authorization verdict a guard deposits, folded in at emit time |
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
