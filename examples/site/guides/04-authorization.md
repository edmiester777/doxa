# Authorization

"May they call this route?" is the easy question. The useful one is "may they do this to *this* widget?", and answering it means loading the widget first. doxa answers both from the route's signature, with [Cedar](https://www.cedarpolicy.com) policies in your own store.

## Guard on the object

| Form | Asks | Hands the handler |
|---|---|---|
| `Granted<Widget>` | may this caller act on **this object**? | the loaded object |
| `Granted<Many<Widget>>` | which **subset** may they see? | a filter for your query |
| `Granted<Cap<M>>` | may they call this at all? | `()` |

```rust
use doxa::auth::{Cap, Granted, Many};

// Loads the widget, checks `read` against its attributes:
// 404 if it doesn't exist, 403 if the policy says no.
#[get("/widgets/{id}")]
async fn get_widget(widget: Granted<Widget>) -> Json<Widget> {
    Json(widget.into_inner())
}

// The subset, as a filter the handler pushes into its own query.
#[get("/widgets")]
async fn list_widgets(scope: Granted<Many<Widget>>) -> Json<Vec<Widget>> {
    Json(load_where(scope.into_inner()).await)
}

#[post("/flush")]
async fn flush(_: Granted<Cap<WidgetsRead>>) -> StatusCode { StatusCode::OK }
```

Need the caller too? `Granted(caller, widget): Granted<Widget>` gives you both, with no second extractor.

The spec gets the `security` requirement, the badge, and the `401`/`403` the guard can return, plus `400` and `404` on the instance form.

## Where the key comes from

You don't say. A key is a struct, and its field names *are* the route parameters:

```rust
doxa::auth::route_key!(pub WidgetKey { name: String });

#[get("/widgets/{name}")]                // read from the path…
async fn get(w: Granted<WidgetByName>) -> Json<Widget> { /* ... */ }

#[get("/widgets")]                       // …or from ?name=, inferred
async fn find(w: Granted<WidgetByName>) -> Json<Widget> { /* ... */ }
```

A route whose parameters don't include the key's fails to build.

## Describe the asset once

With the `policy-sea-orm` feature, the row derives its Cedar identity and its scoped lookup, and `#[asset]` writes the rest:

```rust
#[derive(DeriveEntityModel, PolicyResource)]
#[resource(entity_type = "Widget")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    #[resource(id, attr, key)]              // Cedar id, policy attribute, route key
    pub name: String,
    #[resource(parent = "Tenant", scope)]   // every lookup is confined to this
    pub tenant_id: String,
}

#[derive(Actions)]
#[actions(resource = "Widget", prefix = "widgets")]
pub enum WidgetAction {
    /// List and view widgets.
    Read,
    /// Remove widgets.
    Delete,
}

impl GrantProfile for AppGrants {
    type Ctx = CapabilityContext;
    type State = DatabaseConnection;
    type Source = FromState<DatabaseConnection>;
    type Error = DbLoadError;
}

#[asset(row = Model, profile = AppGrants, actions = WidgetAction, list = tenant)]
pub struct WidgetByName;
```

`#[resource(scope)]` is the part that matters for security. Every generated lookup filters on the scope column, so another tenant's widget is *absent* (`404`), not *forbidden* (`403`), and its existence doesn't leak. `#[derive(Actions)]` turns each variant and its doc comment into a capability (`widgets.read`, `widgets.delete`) and registers it, so `doxa::policy::capabilities()` lists them all.

A route's action comes from its method: `get` → read, `post` → create, `put`/`patch` → update, `delete` → delete, as the vocabulary maps them with `#[action(verb = get)]`. Name another with `#[grant(action = Archive)]`.

## When the guard can't see it

A guard runs before the body arrives. For objects the handler finds later, inside a transaction for instance, the same check is a method:

```rust
let widget = find_widget(&txn, tenant, &name).await?
    .authorize::<WidgetByName, _>(widget_action::Read, &parts.extensions).await?;

let folders = Folder::load_all_scoped(body.folders, &txn, tenant).await?
    .authorize_all_dependency::<FolderByName, _>(folder_action::Read, &parts.extensions).await?;
```

## The manual form

Under all of that is one call. You rarely write it yourself, but it's good to know it's there:

```rust
let tenant = ctx.tenant_id().ok_or(MyError::Unscoped)?;
let resource = build_uid("Document", &doc_id)?;
let decision = router.check(tenant, ctx.roles(), "read", resource).await?;
// decision.allowed, decision.reason
```

Implement `PolicyStore` for your backend. A `PolicyExtension` adds domain logic after evaluation, such as row filters from Cedar residuals.
