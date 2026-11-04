//! Marks a crate as the client or server half of a doxa app, or an API both depend on, from
//! `build.rs`.
//!
//! ```ignore
//! // web/build.rs
//! fn main() { doxa_role::client() }
//! ```

#![deny(missing_docs)]

/// Environment variable doxa's macros read to pick which half to emit.
pub const ROLE_ENV: &str = "DOXA_ROLE";

/// Build this crate as the client half: routes become typed HTTP calls.
pub fn client() {
    emit("client");
    println!("cargo::rustc-cfg=doxa_client");
}

/// Build this crate as an API contract both halves depend on: route declarations become
/// calls everywhere, and what only a server needs compiles off wasm.
pub fn api() {
    emit("api");
}

/// Build this crate as the server half. The default; only needed to say so.
pub fn server() {
    emit("server");
}

fn emit(role: &str) {
    println!("cargo::rustc-env={ROLE_ENV}={role}");
    println!("cargo::rustc-check-cfg=cfg(doxa_client)");
    println!("cargo::rerun-if-changed=build.rs");
}
