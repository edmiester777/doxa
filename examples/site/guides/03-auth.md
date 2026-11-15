# Authentication

Bring your identity provider and your claims. doxa verifies tokens, hands your handler a typed context, and documents which routes need a token.

## Your claims, your struct

```rust
use doxa::auth::{Auth, Claims, Tenant};

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

async fn whoami(Auth(ctx): Auth<MySession, MyClaims>) -> String {
    format!("hello {} from tenant {}", ctx.claims.email, ctx.claims.tenant_id)
}
```

## The tenant

`scope()` is the caller's tenant. Most handlers need only that, so they ask for it by itself:

```rust
#[get("/widgets")]
async fn list(tenant: Tenant) -> Json<Vec<Widget>> {
    Json(load_for(&tenant).await)
}

// Parsed into your own type; a scope that doesn't parse is a 401.
async fn typed(Tenant(id): Tenant<TenantId>) { /* ... */ }
```

A route that already has a guard reads it from there: `grant.tenant()`. A caller with no scope is refused by every guard with a `403`, so a handler never sees an empty tenant. The browser never sees `Tenant` at all, because it's read on the server.

## Admins are yours

doxa never decides who is an admin. Your own layer, inside `AuthLayer`, marks the request with one of two tiers:

```rust
async fn admins(mut req: Request, next: Next) -> Response {
    match role_of(&req) {
        Some("sysadmin") => { req.extensions_mut().insert(doxa::auth::SuperAdmin); }
        Some("tadmin") => { req.extensions_mut().insert(doxa::auth::TenantAdmin); }
        _ => {}
    }
    next.run(req).await
}
```

| | Policy | Own tenant's rows | Other tenants' rows | No tenant |
|---|---|---|---|---|
| `SuperAdmin` | skipped | yes | yes | allowed |
| `TenantAdmin` | skipped | yes, minus your `confine` rule | never | `403` |
| everyone else | asked | yes, minus your `confine` rule, as the policy narrows | never | `403` |

A tenant admin holds every capability, so a platform-wide route asks for the stronger tier itself:

```rust
#[post("/tenants")]
async fn create_tenant(_: SuperAdmin, body: Json<NewTenant>) -> StatusCode { /* ... */ }
```

`_: TenantAdmin` also admits a super admin. Both answer `401` without a token and `403` otherwise, and both appear in the spec. Work outside a request picks a tier with `OffRequest::new(…).super_admin()` or `.tenant_admin()`; a granted or refused event records which in its `actor_attrs.via`.

### What confines a tenant admin

The row's `#[resource(scope)]` column is its owner: another tenant's row is a `404` from `Granted<T>` and a `403` from `authorize`, before the policy is asked. A row that records no owner is refused to a tenant admin; mark a nullable owner `#[resource(scope, shared)]` when `NULL` means every tenant's, or write `owned_by` by hand when ownership runs through a parent.

On top of that sits your own rule. `#[resource(filter = …)]` applies to everyone, a super admin included; `#[asset(confine = Rule)]` applies to everyone but a super admin. One rule serves rows and listings across tables:

```rust
/// Flagged posts are visible only to their author.
pub struct HideFlagged;

impl<M: FlaggedRow> RowRule<M, Caller> for HideFlagged {
    fn admits(row: &M, _: &str, ctx: &Caller) -> bool {
        !row.flagged() || row.author() == ctx.claims.sub
    }
}

impl<E: FlaggedTable> ListRule<Select<E>, Caller> for HideFlagged {
    fn confine(rows: Select<E>, _: &str, ctx: &Caller) -> Select<E> {
        rows.filter(Condition::any()
            .add(E::flag_column().eq(false))
            .add(E::author_column().eq(ctx.claims.sub.clone())))
    }
}

#[doxa::asset(row = post::Model, profile = AppGrants, actions = PostAction, list = tenant, confine = HideFlagged)]
pub struct PostByName;
```

Keep a rule and the row and table traits it reads in one crate. A hand-written `Scoping` splits a listing the same way: `owned` is the tenant's rows and the whole of a tenant admin's listing, `confine` is your rule, and `narrow` is the policy's part, never asked for an admin.

Loaders and `narrow` never see the tier. A super admin's `Granted<T>` still loads through the tenant-confined loader; only listings widen, through `unscoped`.

Under the hood: JWKS fetching and caching, JWT signature checks, and RFC 7662 introspection as a fallback. It works with Keycloak, Auth0, Cognito, Okta, Azure AD or any standards-compliant issuer. Turn off the `axum` feature and the pipeline runs on its own, outside a web server.

## Guard a whole service

Put `AuthLayer` in a [layer stack](02-routes.md#services-and-layer-stacks) and every route the service owns requires a token. `AuthDocs` puts the same fact in the spec:

```rust
#[doxa::layers(docs = [AuthDocs])]
fn protected(routes: Routes, state: &AppState) -> Routes {
    routes.layer(AuthLayer::new(state.auth.clone()))
}

#[doxa::service(layers = crate::protected)]
pub struct Widgets;
```

Register the scheme once on the document with `.bearer_security("bearer")`.

## Capabilities: may they call this at all?

A capability is a named permission. Declare it, then require it on a route. doxa enforces it at runtime and stamps it on the operation:

```rust
use doxa::auth::Require;

#[capability(
    name = "widgets.read",
    description = "Read widget definitions",
    checks(action = "read", entity_type = "Widget", entity_id = "collection"),
)]
pub struct WidgetsRead;

#[get("/widgets")]
async fn list_widgets(_: Require<WidgetsRead>) -> Json<Vec<Widget>> {
    Json(load().await)
}
```

The spec gets a standard `security` requirement for code generators, an `x-required-permissions` extension for your own tooling, and an `x-badges` chip that Scalar shows on the operation. For another scheme name, write `Require<WidgetsRead, MyScheme>`.

Most apps don't write capabilities one by one: `#[derive(Actions)]` on a vocabulary enum writes one per variant. See [authorization](04-authorization.md).

## In the browser

The `oidc` feature signs the browser in with authorization code + PKCE, refreshes ahead of expiry, and lets one tab refresh for all of them:

```rust
let auth = Oidc::<Claims>::issuer("https://id.example.com/realms/acme")
    .client_id("web")
    .install();
layers().push(auth.bearer()).push(on_status(401, move |_| auth.sign_in()));
App::new(router().guard(auth.required())).mount("#app");
```

Any component can read the session, and re-renders when it changes:

```rust
if let Some(t) = doxa::ui::oidc::session::<Claims>().tokens() {
    /* t.claims().name */
}
```
