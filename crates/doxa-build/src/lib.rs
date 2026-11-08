//! The asset pipeline behind `doxa build`: the web crate to wasm, its bindings and
//! islands bundled by esbuild, stylesheets through Tailwind and lightningcss, and a
//! content-hashed `target/doxa/dist` with a manifest and precompressed copies.
//!
//! With only the `client` feature, it is the generator a client crate's `build.rs` runs.

#![deny(missing_docs)]

#[cfg(feature = "pipeline")]
pub mod bindgen;
#[cfg(feature = "pipeline")]
pub mod bundle;
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "pipeline")]
pub mod config;
#[cfg(feature = "pipeline")]
pub mod css;
#[cfg(feature = "pipeline")]
pub mod dist;
#[cfg(feature = "pipeline")]
mod error;
/// The web crate's resolved dependency graph.
#[cfg(feature = "pipeline")]
pub mod graph;
#[cfg(feature = "pipeline")]
pub mod hot;
#[cfg(feature = "pipeline")]
pub mod library;
#[cfg(feature = "pipeline")]
pub mod npm;
#[cfg(feature = "pipeline")]
pub mod pipeline;
#[cfg(feature = "pipeline")]
pub mod split;
#[cfg(feature = "pipeline")]
pub mod stories;
#[cfg(feature = "pipeline")]
pub mod tool;

#[cfg(feature = "client")]
pub use client::{openapi_from_json, ClientSpec, GenerateError};
#[cfg(feature = "pipeline")]
pub use error::{Error, Result};
#[cfg(feature = "pipeline")]
pub use pipeline::{BuildOptions, Pipeline};
