//! A client-rendered UI for doxa apps. Components are async functions that call
//! routes directly; hooks follow React's rules, checked at runtime.
//!
//! Most apps only need `use doxa::ui::prelude::*;`.

mod app;
mod boundary;
mod can;
mod component;
mod directive;
pub mod dom;
mod error;
mod hooks;
mod plugin;
#[cfg(feature = "react")]
pub mod react;
mod reconcile;
mod router;
mod runtime;
mod theme;
mod view;

pub use app::{App, IntoRoot, RootHandle};
pub use boundary::{Catch, CatchBuilder, CatchProps, Suspense, SuspenseBuilder, SuspenseProps};
pub use can::{Can, CanBuilder, CanProps};
pub use component::{Component, IntoRender, RenderFuture, Set, Unset};
pub use directive::Directive;
pub use dom::{Event, NodeRef, Phase};
pub use error::{Result, Thrown};
pub use hooks::{
    action, context, effect, memo, provide, state, try_context, Action, Deps, Singleton, State,
};
pub use plugin::{Plugin, Slot, SlotBuilder, SlotProps, Slots};
pub use router::{
    location, match_path, navigate, Link, LinkBuilder, LinkProps, Outlet, OutletBuilder,
    OutletProps, Page, Prefetch, Route, Router, Segments,
};
pub use theme::{set_theme, theme, Theme};
pub use view::{
    comp, el, Callback, ComponentView, DangerousHtml, Element, IntoAttr, IntoProp, IntoView, Key,
    SafeUrl, View,
};

/// A React component as a doxa one: `#[react(module = "…", export = "…")]` on its props struct.
///
/// A `children: View` field reaches React as an element wrapping doxa's DOM, so Radix `asChild` can't take it.
#[cfg(feature = "react")]
pub use doxa_ui_macros::react;
pub use doxa_ui_macros::{component, page, start, view};

#[doc(hidden)]
pub mod __private {
    pub use crate::view::FromChildren;
    #[cfg(target_arch = "wasm32")]
    pub use wasm_bindgen;
}

/// Everything a component file uses.
pub mod prelude {
    #[cfg(feature = "react")]
    pub use crate::react;
    pub use crate::{
        action, component, context, effect, memo, navigate, page, provide, set_theme, state, theme,
        try_context, view, Action, App, Callback, Can, Catch, DangerousHtml, Directive, Event,
        IntoView, Link, NodeRef, Outlet, Page, Plugin, Result, Route, Router, SafeUrl, Singleton,
        Slot, Slots, State, Suspense, Theme, Thrown, View,
    };
    pub use doxa_client::{layers, service, CacheConfig};
}
