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

`AuthLayer` runs the full pipeline (validate token, resolve claims, evaluate policy) on every request. Apply it with `layer_documented` and the OpenAPI spec is annotated automatically — Authorization header, 401 response, bearer security scheme.

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

## Key types

| Type | Purpose |
|------|---------|
| `Auth<S, C>` | Extractor for the authenticated context |
| `Require<M>` | Capability-checking extractor |
| `AuthState` | Middleware state (validator + resolver + policy + optional audit) |
| `AuthLayer` | Tower layer implementing the auth pipeline |
| `TokenValidator` | Trait for IdP token validation |
| `ClaimResolver` | Trait for claims resolution |
| `Claims` | Trait for consumer-defined claim types |

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `axum` | yes | Auth middleware, `Auth` extractor, `IntoResponse` on errors |
| `audit` | yes | Stamps actor info onto `AuditEventBuilder`, emits auth-failure events |

Disable `axum` to use the framework-neutral pipeline from non-axum contexts. Disable `audit` to drop `doxa-audit` from the dependency graph.

## License

Apache 2.0
