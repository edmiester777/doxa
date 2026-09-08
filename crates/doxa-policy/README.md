# doxa-policy

Framework-neutral Cedar-based authorization policy engine with pluggable storage and domain-specific extensibility.

Everything is keyed by a **tenant** — the partition your policies, entities and sessions are stored under. A check with no tenant is refused rather than evaluated against a shared set, so a single-tenant deployment supplies a constant rather than `None`.

## Usage

### Define a policy store

Three methods, all per-tenant: what exists, what the rules are, and what the entities look like.

```rust
use std::collections::HashMap;
use doxa_policy::{AuthError, PolicyStore, SharedPolicyStore};
use cedar_policy::PolicySet;
use serde_json::Value;

struct MyPolicyStore { /* ... */ }

#[async_trait]
impl PolicyStore for MyPolicyStore {
    /// Every resource this tenant owns, grouped by Cedar entity type.
    /// Iterated when assembling a session.
    async fn list_resources(&self, tenant: &str)
        -> Result<HashMap<String, Vec<String>>, AuthError> { /* ... */ }

    /// Tenant-scoped and system-wide policies, combined into one set.
    async fn load_policy_set(&self, tenant: &str) -> Result<PolicySet, AuthError> { /* ... */ }

    /// Cedar entities in the standard JSON format —
    /// `{ "uid": …, "attrs": {…}, "parents": […] }`.
    async fn load_entity_jsons(&self, tenant: &str) -> Result<Vec<Value>, AuthError> { /* ... */ }
}

let store: SharedPolicyStore = Arc::new(MyPolicyStore::new(&db));
```

Each tenant's policy set and entity set is parsed once and cached behind `TenantStoreCache`, so a hot tenant does not re-parse its Cedar hierarchy per request.

### Build a router and check access

```rust
use doxa_policy::{PolicyRouter, uid::build_uid};

let router = PolicyRouter::new(store, MyExtension);

let resource = build_uid("Document", "doc-42")?;
let decision = router
    .check(tenant_id, &roles, "read", resource)
    .await?;
// decision.allowed, decision.reason
```

### Checking a specific object

`check` names a resource by UID. To decide against an object's *attributes* — `when { resource.region == "us" }` — describe it with `PolicyResource` and the router injects it as a Cedar entity for the evaluation:

```rust
use doxa_policy::{PolicyResource, ResourceEntity};
use serde_json::{Map, Value};

impl PolicyResource for Document {
    const ENTITY_TYPE: &'static str = "Document";
    const TENANT_PARENT: Option<&'static str> = Some("Tenant");

    fn resource_id(&self) -> String { self.name.clone() }

    // `cedar_attrs` and `cedar_parents` both default to empty
    fn cedar_attrs(&self) -> Map<String, Value> { /* ... */ }
}

let entity = ResourceEntity::of(&doc, tenant_id);
let decision = router
    .check_instance(tenant_id, &roles, "read", &entity)
    .await?;

// Several objects, one evaluation and one entity-set build rather than N
let entities: Vec<ResourceEntity> =
    docs.iter().map(|d| ResourceEntity::of(d, tenant_id)).collect();
let decisions = router
    .check_instance_many(tenant_id, &roles, "read", &entities)
    .await?;
```

`TENANT_PARENT` is the parent a *request* supplies rather than a column: a row belongs to whichever tenant is asking about it, and a nullable column would not answer that. `#[derive(PolicyResource)]` in `doxa-macros` writes this impl from field attributes.

### Answering from a resolved session

A service whose policy resolves into a session up front already holds the answer to many checks — an allow-list, or an administrator's blanket grant. `SessionChecker` binds the shared router to one caller's session so those are answered without a policy call, and everything else falls through:

```rust
use doxa_policy::SessionChecker;

let checker = SessionChecker::new(Arc::clone(&router), session.clone());
request.extensions_mut().insert(checker.into_extension());
```

What it may shortcut is the extension's to declare — `PolicyExtension::session_is_admin` and `decide_from_session`, both defaulting to "the session says nothing". The tenant is not among them: it comes from the auth layer, so the two cannot come to disagree about which partition a request was decided in.

### Capability-based gating

Declare a static capability — a bundle of `(action, entity_type, entity_id)` checks that must all pass:

```rust
use doxa_policy::{Capable, Capability, CapabilityCheck, ResourceId};

pub const WIDGETS_READ: Capability = Capability {
    name: "widgets.read",
    description: "Read widget definitions",
    checks: &[CapabilityCheck {
        action: "read",
        entity_type: "Widget",
        entity_id: ResourceId::Literal("collection"),
    }],
};

pub struct WidgetsRead;
impl Capable for WidgetsRead {
    const CAPABILITY: &'static Capability = &WIDGETS_READ;
}
```

Use with `doxa-auth`'s `Require<WidgetsRead>` extractor for runtime enforcement + OpenAPI documentation.

`entity_id` also takes the bare word `tenant` — `entity_id = tenant` — for a gate whose resource *is* the caller's partition rather than a named object. With the `catalog` feature (on by default) every declaration registers itself, so `capabilities()` returns the full set, sorted by name, without a hand-maintained list.

### Loading the row, and pushing the policy into the query

Behind the `sea-orm` feature, two traits cover the half of authorization that happens in SQL.

`ScopedTable` names the column that says whose rows these are. Every query built from it carries that column, so another owner's row is **absent** rather than refused — which is what lets a route answer `404` instead of confirming the object exists with a `403`. `ScopedRow` adds the key one route matches on; every method has a default body, so an impl is three lines:

```rust
use doxa_policy::{ScopedRow, ScopedTable};

impl ScopedTable for Model {
    type Entity = Entity;
    const SCOPE_COLUMN: Column = Column::TenantId;
}

impl ScopedRow for Model {
    type Key = String;
    const KEY_COLUMN: Column = Column::Name;
}

let page = Model::scoped("acme").paginate(&db, 50);
let row  = Model::load_scoped("orders".into(), &txn, "acme").await?;
let rows = Model::load_all_scoped(names, &txn, "acme").await?;   // one IN, one filter
let byid = Model::load_by_id(id, &txn, "acme").await?;           // still scoped
```

They are separate because a scope is a fact about the *table* and a key is a fact about a *route*: two routes reach one table by different keys, and a table addressed by no column at all still has an owner and can still be listed.

`condition_from_residual` closes the loop. When a policy's `when` clause cannot be fully evaluated — because it names an attribute of a resource that was withheld — Cedar returns a residual, and this turns it into a `Condition` the query carries:

```rust
use doxa_policy::condition_from_residual;

// permit(...) when { resource.region == "us" }  →  WHERE region = 'us'
let filter = match residual_body {
    Some(body) => condition_from_residual::<Model>(&body)?,
    None => Condition::all(),
};
```

The column behind each attribute comes from `ScopedTable::column_for_attr`, which `#[derive(PolicyResource)]` writes from the same fields it builds `cedar_attrs` from — so the attributes a policy may mention and the columns they resolve to are one list rather than two that drift. An attribute with no column is untranslatable and **refused**, because the alternative to refusing is a filter wider than the policy authorized.

`DbLoadError` ships the one shape a failed load admits: a 500, nothing in the body, and the real `DbErr` logged at the conversion.

## Key types

| Type | Purpose |
|------|---------|
| `PolicyRouter` | Centralized slow-path PEP for arbitrary `(action, resource)` checks |
| `PolicyStore` | Trait for pluggable Cedar policy storage |
| `Policy` | Trait for role-to-session resolution |
| `PolicyExtension` | Trait for domain-specific post-evaluation behavior |
| `PolicyResource` | Trait giving a domain type its Cedar identity, attributes and parents |
| `ResourceEntity` | A resource as the evaluator sees it — type, id, attrs, parents |
| `SessionChecker` | The router bound to one caller's session, answering what it already knows |
| `CapabilityChecker` | Object-safe check interface a guard reaches through |
| `Capability` | Static bundle of checks that must all pass |
| `Capable` | Trait binding zero-sized markers to capabilities |
| `AccessDecision` | Allow/Deny result with reason |
| `CedarPolicy` | Generic Cedar implementation of the `Policy` trait |
| `TenantStoreCache` | Per-tenant parsed policy + entity cache, bounded and TTL'd |
| `ScopedTable` / `ScopedRow` | The scope column a query is confined to, and the key a route reaches one row by (`sea-orm`) |
| `condition_from_residual` | A policy's leftover `when` clause as a SeaORM `Condition` (`sea-orm`) |
| `DbLoadError` | A load that failed for a reason the caller had nothing to do with (`sea-orm`) |

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `catalog` | yes | Self-registering capability catalog, so `capabilities()` answers without a hand-maintained list |
| `axum` | no | Derives `ApiError` for `AuthError`, adds axum/utoipa integration |
| `sea-orm` | no | `ScopedTable` / `ScopedRow` loaders, `condition_from_residual`, `DbLoadError` |

`catalog` costs one life-before-main constructor per declared capability; turn it off on a target that objects and enumerate the catalog yourself. `sea-orm` is the only feature that pulls an ORM into the policy layer — the rest of the crate is framework- and storage-neutral.

## License

Apache 2.0
