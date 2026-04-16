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
//! | `full` | all of the above | Everything |
//!
//! With default features, `doxa` is a drop-in replacement for the
//! previous standalone `doxa-docs` crate — all public types, macros,
//! and re-exports are available at the same paths.
//!
//! ```toml
//! # Just OpenAPI docs (same as before):
//! doxa = "0.1"
//!
//! # Docs + auth + policy:
//! doxa = { version = "0.1", features = ["auth", "policy"] }
//!
//! # Everything:
//! doxa = { version = "0.1", features = ["full"] }
//! ```

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

#[cfg(feature = "docs")]
pub use doxa_docs::*;

/// Zeroize-on-drop secret string type with `[REDACTED]` Debug/Display.
#[cfg(feature = "protected")]
pub use doxa_protected as protected;

/// SOC 2-flavored append-only audit logging primitives.
#[cfg(feature = "audit")]
pub use doxa_audit as audit;

/// Provider-agnostic OIDC / JWT auth middleware with Cedar policy integration.
#[cfg(feature = "auth")]
pub use doxa_auth as auth;

/// Cedar-based authorization policy engine.
#[cfg(feature = "policy")]
pub use doxa_policy as policy;
