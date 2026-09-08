//! HTTP authentication middleware with a pluggable policy engine.
//!
//! `doxa-auth` is a framework-neutral OIDC / RFC 7519 / RFC 7662
//! authentication library. The auth pipeline is provider-agnostic — every
//! IdP-specific assumption lives behind the [`TokenValidator`] /
//! [`ClaimResolver`] traits in [`provider`], so the same code drives
//! Keycloak, Auth0, Cognito, Okta, Azure AD, or any other RFC-compliant
//! deployment. LDAP / Active Directory deployments are expected to put
//! Keycloak (or similar) in front and consume the resulting OIDC tokens.
//!
//! The crate is **generic over both the session output type and the
//! consumer-defined claim type**, so it can be reused across services with
//! different authorization vocabularies and different claim shapes. Plug in
//! a [`doxa_policy::Policy<S>`] for whatever `S` your service needs,
//! define a claim struct implementing [`Claims`] for whatever fields your
//! IdP produces, and the middleware threads both through to handlers via
//! [`AuthContext<S, C>`].
//!
//! ## Cargo features
//!
//! - **`axum`** *(default)* — enables the [`middleware`] and [`extractors`]
//!   modules. Disable with `default-features = false` to use the
//!   framework-neutral pieces (provider pipeline, [`AuthContext`],
//!   [`AuthState`]) from a non-axum web framework.
//!
//! ## Module overview
//!
//! | Module | Purpose | Feature |
//! |--------|---------|---------|
//! | [`claims`] | [`Claims`] trait + stock [`OidcClaims`] quick-start type | always |
//! | [`context`] | [`AuthContext<S, C>`] type carried in request extensions | always |
//! | [`provider`] | [`TokenValidator`] / [`ClaimResolver`] traits + concrete OIDC implementations | always |
//! | [`middleware`] | Axum auth middleware (validate → resolve → policy) | `axum` |
//! | [`extractors`] | [`Auth`] axum extractor | `axum` |

pub mod claims;
pub mod config;
pub mod context;
pub mod provider;

#[cfg(feature = "axum")]
pub mod extractors;
#[cfg(feature = "axum")]
pub mod granted;
#[cfg(feature = "axum")]
pub mod layer;
#[cfg(feature = "axum")]
pub mod middleware;
#[cfg(feature = "axum")]
pub mod openapi;
#[cfg(feature = "axum")]
pub(crate) mod record;

/// Re-exported so `#[derive(Actions)]`'s output can register itself
/// without the declaring crate taking a direct dependency on `inventory`.
#[cfg(feature = "catalog")]
#[doc(hidden)]
pub use inventory;

/// Stand-in for the above when the `catalog` feature is off, so the
/// derive expands to the same tokens either way and the registration
/// simply evaporates.
#[cfg(not(feature = "catalog"))]
#[doc(hidden)]
pub mod inventory {
    #[doc(hidden)]
    pub use crate::__doxa_action_submit as submit;
}

#[cfg(not(feature = "catalog"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __doxa_action_submit {
    ($($tt:tt)*) => {};
}

pub use claims::{Claims, OidcClaims};
pub use config::{AuthProviderConfig, ClaimMapping, ResolverConfig, ValidatorConfig};
pub use context::{AuthContext, CapabilityContext};
pub use provider::{ClaimResolver, MinimalClaims, OidcClaimConfig, TokenValidator};

#[cfg(feature = "axum")]
pub use extractors::{Auth, BearerScheme, Require, SchemeName};
#[cfg(all(feature = "axum", feature = "catalog"))]
pub use granted::actions;
#[cfg(feature = "axum")]
pub use granted::{
    authorize, declares, distinct, Action, ActionTable, AuthorizeLoaded, Cap, DeclaredAction,
    DefaultSite, Denial, FromAuthExtensions, GrantProfile, GrantSite, Granted, Granting, KeyError,
    KeySegment, Many, NoState, One, Refusal, RouteKey, Scoping, Subject, SubjectForm,
};
#[cfg(feature = "axum")]
pub use layer::{AuthLayer, AuthService};
#[cfg(feature = "axum")]
pub use middleware::AuthState;
#[cfg(feature = "axum")]
pub use openapi::{auth_contribution, BearerAuthorization};
