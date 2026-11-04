//! Emit the server half, the client half, or both, from a proc macro.
//!
//! A crate's role is set by its `build.rs` through `doxa-role`. A macro wraps
//! each generated item in [`tag`], or picks an expansion with [`split`].

#![deny(missing_docs)]

use proc_macro2::TokenStream;
use quote::quote;

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
    /// Set by `doxa_role::api()`: one crate built for both, server items off wasm only.
    Api,
}

impl Role {
    /// The role of the crate currently being compiled.
    pub fn current() -> Role {
        match std::env::var("DOXA_ROLE").as_deref() {
            Ok("client") => Role::Client,
            Ok("api") => Role::Api,
            _ => Role::Server,
        }
    }

    /// Whether an item tagged `side` belongs in this role.
    pub fn includes(self, side: Side) -> bool {
        matches!(
            (self, side),
            (_, Side::Shared)
                | (Role::Api, _)
                | (Role::Server, Side::Server)
                | (Role::Client, Side::Client)
        )
    }
}

/// `item` if it belongs in the current crate's role, nothing otherwise. In an API crate a
/// server item compiles only off wasm, and a client item everywhere.
pub fn tag(side: Side, item: TokenStream) -> TokenStream {
    tag_in(Role::current(), side, item)
}

fn tag_in(role: Role, side: Side, item: TokenStream) -> TokenStream {
    match (role, side) {
        (Role::Api, Side::Server) => gate(quote!(not(target_arch = "wasm32")), item),
        (role, side) if role.includes(side) => item,
        _ => TokenStream::new(),
    }
}

/// `server` in the server half, `client` in the client half; in an API crate, `server` off
/// wasm and `client` on it, for an item the two halves define differently.
pub fn split(server: TokenStream, client: TokenStream) -> TokenStream {
    split_in(Role::current(), server, client)
}

fn split_in(role: Role, server: TokenStream, client: TokenStream) -> TokenStream {
    match role {
        Role::Server => server,
        Role::Client => client,
        Role::Api => {
            let mut out = gate(quote!(not(target_arch = "wasm32")), server);
            out.extend(gate(quote!(target_arch = "wasm32"), client));
            out
        }
    }
}

/// Each item in `items` under `#[cfg(predicate)]`.
fn gate(predicate: TokenStream, items: TokenStream) -> TokenStream {
    match syn::parse2::<syn::File>(items.clone()) {
        Ok(file) => file
            .items
            .into_iter()
            .map(|item| quote!(#[cfg(#predicate)] #item))
            .collect(),
        Err(_) => quote!(
            #[cfg(#predicate)]
            ::doxa::__doxa_items! { #items }
        ),
    }
}

/// Whether the current crate is the client half.
pub fn is_client() -> bool {
    Role::current() == Role::Client
}

/// Whether the current crate is an API crate, built for both halves.
pub fn is_api() -> bool {
    Role::current() == Role::Api
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(t: TokenStream) -> String {
        t.to_string()
    }

    #[test]
    fn an_api_crate_keeps_server_items_off_wasm_and_client_items_everywhere() {
        let server = tag_in(Role::Api, Side::Server, quote!(struct A; impl A {}));
        assert_eq!(
            text(server),
            text(quote!(
                #[cfg(not(target_arch = "wasm32"))]
                struct A;
                #[cfg(not(target_arch = "wasm32"))]
                impl A {}
            ))
        );
        let client = tag_in(
            Role::Api,
            Side::Client,
            quote!(
                struct B;
            ),
        );
        assert_eq!(
            text(client),
            text(quote!(
                struct B;
            ))
        );
    }

    #[test]
    fn an_api_crate_builds_each_halfs_expansion_for_its_target() {
        let out = split_in(
            Role::Api,
            quote!(
                struct S;
            ),
            quote!(
                struct S {
                    c: u8,
                }
            ),
        );
        assert_eq!(
            text(out),
            text(quote!(
                #[cfg(not(target_arch = "wasm32"))]
                struct S;
                #[cfg(target_arch = "wasm32")]
                struct S {
                    c: u8,
                }
            ))
        );
        assert_eq!(text(split_in(Role::Client, quote!(a), quote!(b))), "b");
        assert!(tag_in(
            Role::Client,
            Side::Server,
            quote!(
                struct A;
            )
        )
        .is_empty());
    }
}
