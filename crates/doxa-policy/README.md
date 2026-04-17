# doxa-policy

Framework-neutral Cedar-based authorization policy engine with pluggable storage and domain-specific extensibility.

## Usage

### Define a policy store

```rust
use doxa_policy::{PolicyStore, SharedPolicyStore};

struct MyPolicyStore { /* ... */ }

#[async_trait]
impl PolicyStore for MyPolicyStore {
    async fn get_policies(&self, tenant: &str) -> Result<PolicySet, AuthError> {
        // Load Cedar policies from your backend
    }
}

let store: SharedPolicyStore = Arc::new(MyPolicyStore::new(&db));
```

### Build a router and check access

```rust
use doxa_policy::{PolicyRouter, uid::build_uid};

let router = PolicyRouter::new(store, MyExtension);

let resource = build_uid("Document", "doc-42")?;
let decision = router
    .check(company_id, &roles, "read", resource)
    .await?;
// decision.allowed, decision.reason
```

### Capability-based gating

Declare a static capability — a bundle of `(action, entity_type, entity_id)` checks that must all pass:

```rust
use doxa_policy::{Capable, Capability, CapabilityCheck};

pub const WIDGETS_READ: Capability = Capability {
    name: "widgets.read",
    description: "Read widget definitions",
    checks: &[CapabilityCheck {
        action: "read",
        entity_type: "Widget",
        entity_id: "collection",
    }],
};

pub struct WidgetsRead;
impl Capable for WidgetsRead {
    const CAPABILITY: &'static Capability = &WIDGETS_READ;
}
```

Use with `doxa-auth`'s `Require<WidgetsRead>` extractor for runtime enforcement + OpenAPI documentation.

## Key types

| Type | Purpose |
|------|---------|
| `PolicyRouter` | Centralized slow-path PEP for arbitrary `(action, resource)` checks |
| `PolicyStore` | Trait for pluggable Cedar policy storage |
| `Policy` | Trait for role-to-session resolution |
| `PolicyExtension` | Trait for domain-specific post-evaluation behavior |
| `Capability` | Static bundle of checks that must all pass |
| `Capable` | Trait binding zero-sized markers to capabilities |
| `AccessDecision` | Allow/Deny result with reason |
| `CedarPolicy` | Generic Cedar implementation of the `Policy` trait |

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `axum` | no | Derives `ApiError` for `AuthError`, adds axum/utoipa integration |

## License

Apache 2.0
