# Audit

Every request leaves a record: who, what, which object, allowed or not, how long it took. The trick is that you mostly don't write any of it. A layer fills it in, the guard says what it checked, and your error type says what the outcome was.

## The layer does the work

`AuditLayer` makes an event per request, fills in the method, path, source IP, user agent and request id, and **sends it once the response is done**. Put it *outside* the auth layer so it sees auth failures too:

```rust
use doxa::audit::AuditLayer;
use doxa::auth::{AuthDocs, AuthLayer};

// Order matters: AuditLayer wraps AuthLayer.
#[doxa::layers(docs = [AuthDocs])]
fn audited(routes: Routes, state: &AppState) -> Routes {
    routes
        .layer(AuthLayer::new(state.auth.clone()))
        .layer(AuditLayer::new(state.audit.clone()))
}

#[doxa::service(layers = crate::audited)]
pub struct Documents;   // audited and authenticated

#[doxa::service]
pub struct Health;      // no layers, no audit noise
```

Health checks stay quiet; everything in `documents` is recorded.

## A guarded route writes nothing

[`Granted<T>`](04-authorization.md) already knows which action it checked and on which object. Put the audit category beside the action, and the record is complete:

```rust
#[derive(Actions)]
#[actions(resource = "Document")]
pub enum DocumentAction {
    #[action(verb = get, event = EventType::DataAccess.as_static())]
    Read,
    #[action(verb = delete, event = EventType::AdminDelete.as_static())]
    Delete,
}

#[get("/documents/{id}")]
async fn get_document(doc: Granted<Document>) -> Json<Document> {
    Json(doc.into_inner())
    // event: data_access · action: read · resource: Document/<id>
    // outcome, status and duration: filled in by the layer
}
```

A refusal goes the same way, so the grant and the denial name the same action and resource.

## Outcomes come from your errors

Recall the `outcome` on an [`ApiError` variant](02-routes.md#typed-errors-grouped-by-status). When a handler returns that error, the layer records that outcome: `allowed` for an honest 404, `denied` for a refusal, `error` by default.

## Enrich when you know more

For a route with no guard, or a handler that knows something the guard can't, take the builder and add to it. What you set wins:

```rust
#[get("/documents/{id}")]
async fn get_document(
    Path(id): Path<String>,
    Extension(audit): Extension<AuditEventBuilder>,
) -> Result<Json<Document>, DocumentError> {
    audit.set_event(EventType::DataAccess, "read");
    audit.set_resource("document", &id);
    let doc = db::find_document(&id).await?;
    audit.set_response_summary(serde_json::json!({ "size_bytes": doc.body.len() }));
    Ok(Json(doc))
}
```

Clones of a builder share state, so exactly one event goes out however many places touch it.

## Middleware can audit too

Rate limits, IP blocks, request validation: pull the builder from the request and record before you short-circuit:

```rust
async fn ip_denylist(request: Request, next: Next) -> Result<Response, StatusCode> {
    let ip = client_ip(&request);
    if is_blocked(&ip) {
        if let Some(audit) = request.extensions().get::<AuditEventBuilder>().cloned() {
            audit.emit_permission_denied(
                EventType::AuthFailure, "ip_blocked", "api", "global",
                &format!("IP {ip} is on the denylist"),
            );
        }
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(next.run(request).await)
}
```

Stack it between `AuditLayer` (outermost) and the routes. Inside a request, `emit` and friends *record* the outcome, and the layer *sends* it after the response, so the event still gets its `403` and its real duration.

## Your own event types

```rust
#[derive(Debug, Clone, Copy)]
enum BillingEvent { InvoiceGenerated, PaymentProcessed, RefundIssued }

impl AuditEventType for BillingEvent {
    fn as_str(&self) -> &str {
        match self {
            Self::InvoiceGenerated => "billing.invoice_generated",
            Self::PaymentProcessed => "billing.payment_processed",
            Self::RefundIssued => "billing.refund_issued",
        }
    }
}

audit.set_event(BillingEvent::PaymentProcessed, "charge");
```

Query by domain later with `WHERE event_type LIKE 'billing.%'`, with no schema change.

## Outside a request

```rust
let logger = spawn_audit_writer(db, 4096);   // background task, bounded channel
let audit = AuditEventBuilder::new(logger.clone());
audit.set_actor(Some(&principal), &roles, json!({ "tenant": tenant }));
audit.set_event(EventType::DataAccess, "read");
audit.set_resource("document", "doc-42");
audit.set_outcome(Outcome::Allowed);
audit.emit();   // never blocks the caller
```

Events land in the `doxa_audit_log` table through SeaORM. Turn off the `sea-orm` feature to ship them somewhere else.
