//! `doxa gallery`'s page: the app's `#[story]` exports in a tree by module, a canvas showing
//! one, and a panel with its source.

#[cfg(not(test))]
mod app;
mod highlight;
#[cfg_attr(test, allow(dead_code))]
mod model;
#[cfg(all(target_arch = "wasm32", not(test)))]
mod web;

#[cfg(not(test))]
pub use app::{Gallery, GalleryBuilder, GalleryProps};
pub use model::{entries, Initial, StoryMeta, Viewport};
