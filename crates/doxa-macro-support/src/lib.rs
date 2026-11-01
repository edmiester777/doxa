//! Emit the server half, the client half, or both, from a proc macro.
//!
//! A crate's role is set by its `build.rs` through `doxa-role`. A macro wraps
//! each generated item in [`tag`], and only the halves for that role survive.

#![deny(missing_docs)]

use proc_macro2::TokenStream;

/// Which half of an app an item belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Emitted in both halves.
    Shared,
    /// Emitted only where the crate is the server half.
    Server,
    /// Emitted only where the crate is the client half.
    Client,
}

/// The role of the crate whose code is being expanded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The default, and today's behavior.
    Server,
    /// Set by `doxa_role::client()`.
    Client,
}

impl Role {
    /// The role of the crate currently being compiled.
    pub fn current() -> Role {
        match std::env::var("DOXA_ROLE").as_deref() {
            Ok("client") => Role::Client,
            _ => Role::Server,
        }
    }

    /// Whether an item tagged `side` belongs in this role.
    pub fn includes(self, side: Side) -> bool {
        matches!(
            (self, side),
            (_, Side::Shared) | (Role::Server, Side::Server) | (Role::Client, Side::Client)
        )
    }
}

/// `item` if it belongs in the current crate's role, nothing otherwise.
pub fn tag(side: Side, item: TokenStream) -> TokenStream {
    if Role::current().includes(side) {
        item
    } else {
        TokenStream::new()
    }
}

/// Whether the current crate is the client half.
pub fn is_client() -> bool {
    Role::current() == Role::Client
}
