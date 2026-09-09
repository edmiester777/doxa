# doxa-auth

Provider-agnostic OIDC / RFC 7519 / RFC 7662 auth middleware with a pluggable Cedar policy engine. Generic over a consumer-defined claim type and session output type so the same library works across services with different claim shapes and authorization vocabularies.

Works with Keycloak, Auth0, Cognito, Okta, Azure AD, or any RFC-compliant IdP.

## Usage

### Define your claims

```rust
use doxa_auth::Claims;

#[derive(Debug, Clone, Deserialize)]
struct MyClaims {
    sub: String,
    email: String,
    tenant_id: String,
    roles: Vec<String>,
}

impl Claims for MyClaims {
    fn sub(&self) -> &str { &self.sub }
    fn roles(&self) -> &[String] { &self.roles }
    fn scope(&self) -> Option<&str> { Some(&self.tenant_id) }
}
```

### Extract in handlers

```rust
use doxa_auth::Auth;

async fn whoami(Auth(ctx): Auth<MySession, MyClaims>) -> String {
    format!("hello {} from tenant {}", ctx.claims.email, ctx.claims.tenant_id)
}
```

### Auth layer with OpenAPI

`AuthLayer` runs the full pipeline (validate token, resolve claims, evaluate policy) on every request. Apply it with `layer_documented` and the OpenAPI spec is annotated automatically — bearer security requirement and 401 response.

The credential is documented as a security scheme and nothing else. OpenAPI reserves `Authorization` as a header parameter name, and the security requirement says strictly more than a parameter can: the scheme's type, and the scopes the operation needs.

```rust
use doxa_auth::{AuthLayer, AuthState};

let protected = OpenApiRouter::new()
    .routes(routes!(list_widgets, get_widget))
    .layer_documented(AuthLayer::new(auth_state));
```

### Capability-based authorization

`Require<M>` enforces a capability at runtime and stamps OpenAPI security metadata:

```rust
use doxa_auth::Require;

#[get("/widgets")]
async fn list_widgets(_: Require<WidgetsRead>) -> Json<Vec<Widget>> {
    Json(load().await)
}
```

### Per-object authorization

`Require<M>` answers *may they call this at all*. `Granted<T>` answers the narrower question — *may they do this to **this** object* — by loading the object and checking the policy against its Cedar attributes. One extractor covers all three forms:

| Form | Asks | Yields |
|------|------|--------|
| `Granted<Widget>` | may this caller act on **this object** | the loaded object |
| `Granted<Many<Widget>>` | what **subset** may they see | a query filter |
| `Granted<Cap<M>>` | may they call this at all | `()` |

```rust
use doxa_auth::{Granted, Many};

#[get("/widgets/{id}")]
async fn get_widget(widget: Granted<Widget>) -> Json<Widget> {
    Json(widget.into_inner())   // derefs to the object; 404 if absent, 403 if refused
}

#[get("/widgets")]
async fn list_widgets(scope: Granted<Many<Widget>>) -> Json<Vec<Widget>> {
    Json(load_where(scope.into_inner()).await)
}
```

Destructure for the caller alongside the object — `Granted(caller, widget)` — rather than pairing the guard with a second `Auth<S, C>`; the context is shared, not copied. The key comes out of the path, or out of the query string on a route whose template names no parameter, and the OpenAPI parameter moves with it.

One trait per asset says what it is and what may be done to it:

```rust
doxa_auth::route_key!(pub WidgetKey { id: u32 });

impl Granting for Widget {
    type Row = Self;              // Cedar identity, from #[derive(PolicyResource)]
    type Key = WidgetKey;         // one named field per segment: {id}
    type Ctx = CapabilityContext; // tenant + roles, or your own Auth context
    type State = DatabaseConnection;      // what load() is handed
    type Source = FromState<DatabaseConnection>; // how the guard gets hold of it
    type Error = DbLoadError;

    /// The whole vocabulary, as a type. Every form bounds its action on
    /// `Table = Self::Actions`, so an action belonging to another asset
    /// does not compile here — even where the two spell it the same.
    type Actions = WidgetAction;

    async fn load(WidgetKey { id }: WidgetKey, db: &Self::State, ctx: &Self::Ctx)
        -> Result<Option<Self>, Self::Error> { /* ... */ }
}
```

The key's field names are the route's parameters — a guard reads it with axum's own `Path` / `Query` — so nothing at the call site says which segment feeds the lookup, and a route whose parameters do not include the key's fails the build.

The action is a type — one of the markers `#[derive(Actions)]` emits per variant — and carries its own row, so the capability the gate checks and the category the audit records are read off it rather than looked up by name. A route that names none resolves through its method — `get` → `ReadAction`, `post` → `CreateAction`, `put` / `patch` → `UpdateAction`, `delete` → `DeleteAction` — against the mapping the vocabulary declares with `#[action(verb = get)]`, so nothing is derived from a name. `#[grant(action = Archive)]` names one the method does not imply. The guard stamps its own OpenAPI metadata: `security`, the badge, and the `401` / `403` it can return — plus `400` / `404` on the instance form, the only one that parses a key and loads an object. It also deposits the action, resource and audit category onto the request's `AuditEventBuilder`, so a guarded handler writes nothing to the audit trail.

`#[asset]` writes the `Granting` impl from a `GrantProfile` (the application's caller, state, source and error, stated once) and an `#[derive(Actions)]` enum. The key and the loader come off `doxa-policy`'s `fetch` traits, which name no backend, so the same declaration serves a SeaORM model, a document behind an HTTP API, or a row in a map. Whichever it is, the generated loader reads the caller's tenant and confines the lookup to it — another tenant's row is *absent* rather than refused, and the route answers `404` where a bare primary-key lookup would leak its existence with a `403`. With `doxa-policy`'s `sea-orm` feature, `#[derive(PolicyResource)]` supplies those impls from field roles.

`Source` is how the guard gets hold of the loader's state, and it is an extractor rather than a `FromRef` slice of the router state. `FromState<Db>` is the ordinary answer; `Extension<Txn>` is the one a router-state loader cannot give, since a pool does not see rows the request has written and not committed.

### Authorizing what the guard cannot see

A guard runs in `FromRequestParts`, before the body exists. For objects a handler finds in that body — or loads inside an open transaction — the same chain is reachable directly, recording identically:

```rust
// an object the handler already holds
let widget = find_widget(&txn, tenant, &name).await?
    .authorize::<WidgetByName, _>(widget_action::Read, &parts.extensions).await?;

// several at once — one pass through the policy, and the refusal still
// names the one that caused it
let folders = Folder::load_all_scoped(body.folders, &txn, tenant).await?
    .authorize_all_dependency::<FolderByName, _>(folder_action::Read, &parts.extensions).await?;
```

### Where there is no request at all

A background job, a queue consumer and a scheduled task decide the same things a route does, and the chain never needed a request — it reads a caller, a checker and a state, all of which a worker has. `OffRequest` is somewhere to put them:

```rust
let work = OffRequest::new(caller, checker, logger).actor("job:reindex");

let dataset = work
    .authorize::<One<DatasetByName>>(name, "read", &db)
    .await?;
```

The state is passed rather than extracted — `LoaderSource` and the `FromRequestParts` half of the guard are the request's business, and a worker already holds its connection.

The logger is not optional, and that is the point. Assembling the extensions by hand works, but a verdict is deposited only if an audit builder is present and the deposit returns quietly if it is not — so a worker that builds two of the three things a chain reads authorizes successfully and records nothing. There is no constructor here that omits it. Refusals settle themselves and dropping the handle emits the rest, so nothing has to be remembered.

Where the caller comes from is yours: an inherited snapshot of whoever queued the work, a service principal, or a re-resolved session are all just a `FromAuthExtensions`, and which is right depends on whether authority captured at enqueue should still hold at run time.

This is a claim about that door only. An `AuthLayer` with no `AuditLayer` above it and no logger of its own still inserts no builder, and guards under it still record nothing.

## Key types

| Type | Purpose |
|------|---------|
| `Auth<S, C>` | Extractor for the authenticated context (shared, behind an `Arc`) |
| `Require<M>` | Capability-checking extractor |
| `Granted<T>` | Route guard for an object, a collection, or a capability |
| `Granting` | Trait an asset implements: its key, loader, and action vocabulary |
| `GrantProfile` | The application's caller / state / source / error, stated once for every asset |
| `LoaderSource` | Where a loader's state comes from — any extractor, not just router state |
| `FromState<T>` | The ordinary source: `T` reached out of the router state through `FromRef` |
| `Scoping` | Adds the collection form — which subset the caller may query for |
| `Action` | One row of `Granting::ACTIONS`: capability, audit category, existence |
| `AuthorizeLoaded` / `AuthorizeLoadedAll` | Authorize objects the handler already holds |
| `AuthorizeScope` | The query filter, for a handler building its own query |
| `OffRequest<C>` | The same chain outside a request, with the audit event it records to (`audit`) |
| `AuthState` | Middleware state (validator + resolver + policy + optional audit) |
| `AuthLayer` | Tower layer implementing the auth pipeline |
| `TokenValidator` | Trait for IdP token validation |
| `ClaimResolver` | Trait for claims resolution |
| `Claims` | Trait for consumer-defined claim types |

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `axum` | yes | Auth middleware, `Auth` / `Require` / `Granted` extractors, `IntoResponse` on errors |
| `audit` | yes | Stamps actor info onto `AuditEventBuilder`, emits auth-failure events |
| `uuid` | yes | `RouteKey` for `uuid::Uuid`, so a UUID `{id}` segment binds without a newtype |
| `catalog` | no | Self-registering action catalog, so `actions()` answers without a hand-maintained list |

Disable `axum` to use the framework-neutral pipeline from non-axum contexts — `Granted` and everything around it lives behind that feature. Disable `audit` to drop `doxa-audit` from the dependency graph. `catalog` costs a life-before-main constructor per declared action; it is off here and turned on by the `doxa` facade's `auth-catalog` feature, which is on by default.

## License

Apache 2.0
