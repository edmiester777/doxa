//! The asset pipeline behind `doxa build`: the web crate to wasm, its bindings and
//! islands bundled by esbuild, stylesheets through Tailwind and lightningcss, and a
//! content-hashed `target/doxa/dist` with a manifest and precompressed copies.

#![deny(missing_docs)]

pub mod bindgen;
pub mod bundle;
pub mod config;
pub mod css;
pub mod dist;
mod error;
pub mod npm;
pub mod pipeline;
pub mod tool;

pub use error::{Error, Result};
pub use pipeline::{BuildOptions, Pipeline};
