//! # doxa
//!
//! Facade crate for the doxa family. Enable only the features you need:
//!
//! | Feature | Crate | What you get |
//! |---------|-------|--------------|
//! | `docs` (default) | `doxa-docs` | [`ApiDocBuilder`], Scalar UI, [`ProblemDetails`], OpenAPI routing |
//! | `macros` (default) | `doxa-macros` | `#[derive(ApiError)]`, `#[derive(SseEvent)]`, `#[get]`/`#[post]`/… |
//! | `docs-scalar` (default) | `doxa-docs` | Scalar API reference UI |
//! | `protected` | `doxa-protected` | `ProtectedString` — zeroize-on-drop secret type |
//! | `audit` | `doxa-audit` | Append-only audit logging primitives |
//! | `auth` | `doxa-auth` | OIDC / JWT auth middleware with Cedar policy integration |
//! | `policy` | `doxa-policy` | Cedar-based authorization policy engine |
//! | `client` | `doxa-client` | Call routes from the browser as async functions |
//! | `ui` | `doxa-ui` | Components, `view!`, hooks and a router, rendered in the browser |
//! | `embed` | `doxa-docs` | `dist!()` compiles the built SPA into the binary |
//! | `full` | all of the above | Everything |
//!
//! A crate whose `build.rs` calls `doxa_role::client()` sees every route as a
//! typed call; `doxa::prelude!()` brings in the names for whichever half it is.
//!
//! ```toml
//! doxa = "0.1"
//! doxa = { version = "0.1", features = ["auth", "policy"] }
//! doxa = { version = "0.1", features = ["full"] }
//! ```

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

#[cfg(all(feature = "docs", not(target_arch = "wasm32")))]
pub use doxa_docs::*;

#[cfg(all(feature = "docs", not(target_arch = "wasm32")))]
pub use doxa_docs::dist;

/// Types the server and its browser client agree on.
pub use doxa_wire as wire;

/// Zeroize-on-drop secret string type with `[REDACTED]` Debug/Display.
#[cfg(feature = "protected")]
pub use doxa_protected as protected;

/// SOC 2-flavored append-only audit logging primitives.
#[cfg(all(feature = "audit", not(target_arch = "wasm32")))]
pub use doxa_audit as audit;

/// Provider-agnostic OIDC / JWT auth middleware with Cedar policy integration.
#[cfg(all(feature = "auth", not(target_arch = "wasm32")))]
pub use doxa_auth as auth;

/// Cedar-based authorization policy engine.
#[cfg(all(feature = "policy", not(target_arch = "wasm32")))]
pub use doxa_policy as policy;

#[cfg(any(feature = "macros", feature = "client"))]
pub use doxa_macros::{client, client_only, prelude, server, server_only, Identity};

/// The server half: what `doxa::prelude!()` brings in where the crate is the server.
#[cfg(all(feature = "docs", feature = "macros", not(target_arch = "wasm32")))]
pub mod server {
    /// Names a shared route file needs when compiled as the server.
    pub mod prelude {
        pub use crate::{
            asset, capability, client, client_only, delete, get, operation, patch, post, put,
            server, server_only, Actions, ApiError, Identity, IntoParams, PolicyResource, SseEvent,
            SseStream, ToSchema,
        };
        pub use axum::extract::{Extension, Form, Path, Query, State};
        pub use axum::http::StatusCode;
        pub use axum::Json;
        pub use serde::{Deserialize, Serialize};

        #[cfg(feature = "auth")]
        pub use doxa_auth::{route_key, Cap, Granted, Many, One, Require};
    }
}

/// Components, hooks and routing for the browser.
#[cfg(feature = "ui")]
pub use doxa_ui as ui;

#[cfg(feature = "ui")]
pub use doxa_ui::start;

/// Every prop given compiles:
///
/// ```
/// use doxa::ui::prelude::*;
/// #[component]
/// fn Row(name: String) -> View { view! { <li>{name}</li> } }
/// let _ = view! { <Row name="a"/> };
/// ```
///
/// A required prop left out names it:
///
/// ```compile_fail
/// use doxa::ui::prelude::*;
/// #[component]
/// fn Row(name: String) -> View { view! { <li>{name}</li> } }
/// let _ = view! { <Row/> };
/// ```
///
/// A prop named anything but `key` compiles:
///
/// ```
/// use doxa::ui::prelude::*;
/// #[component]
/// fn Row(id: u32) -> View { view! { <li>{id}</li> } }
/// ```
///
/// `key` is reserved for list identity:
///
/// ```compile_fail
/// use doxa::ui::prelude::*;
/// #[component]
/// fn Row(key: u32) -> View { view! { <li>{key}</li> } }
/// ```
#[cfg(feature = "ui")]
#[doc(hidden)]
pub mod ui_diagnostics {}

/// The client half: typed calls to the server's routes.
#[cfg(feature = "client")]
pub mod client {
    pub use doxa_client::*;

    /// Names a shared route file needs when compiled as the client.
    pub mod prelude {
        pub use doxa_client::route_key;
        pub use doxa_client::{Form, Granted, Json, Path, Query, SseStream, StatusCode};
        pub use doxa_macros::{
            asset, capability, client, client_only, delete, get, operation, patch, post, put,
            server, server_only, Actions, ApiError, ClientIntoParams as IntoParams,
            ClientToSchema as ToSchema, Identity, PolicyResource, SseEvent,
        };
        pub use serde::{Deserialize, Serialize};
    }
}
