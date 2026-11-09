# Authentication

Bring your identity provider and your claims. doxa verifies tokens, hands your handler a typed context, and documents which routes need a token.

## Your claims, your struct

```rust
use doxa::auth::{Auth, Claims};

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
