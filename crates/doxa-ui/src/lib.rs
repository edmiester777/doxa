//! A client-rendered UI for doxa apps. Components are async functions that call
//! routes directly; hooks follow React's rules, checked at runtime.
//!
//! Most apps only need `use doxa::ui::prelude::*;`.

mod app;
mod boundary;
mod browser;
mod can;
mod component;
mod directive;
pub mod dom;
mod error;
mod head;
mod hooks;
mod plugin;
mod portal;
#[cfg(feature = "react")]
pub mod react;
mod reconcile;
mod router;
mod runtime;
mod theme;
mod view;

pub use app::{App, IntoRoot, RootHandle};
pub use boundary::{Catch, CatchBuilder, CatchProps, Suspense, SuspenseBuilder, SuspenseProps};
pub use browser::{
    broadcast, clipboard, debounced, document_event, exit_fullscreen, fullscreen, intersection,
    interval, media_query, now, resize_observer, save, sleep, stored, window_event, Broadcast,
    BrowserError, Stored,
};
pub use can::{Can, CanBuilder, CanProps};
pub use component::{Component, IntoRender, RenderFuture, Set, Unset};
pub use directive::Directive;
pub use dom::{Event, Listen, NodeRef, Phase, Rect};
pub use error::{Result, Thrown};
pub use head::title;
pub use hooks::{
    action, context, effect, memo, node_ref, provide, state, try_context, Action, Deps, ElementRef,
    Singleton, State,
};
pub use plugin::{Plugin, Slot, SlotBuilder, SlotProps, Slots};
pub use portal::{Portal, PortalBuilder, PortalProps, PortalTarget};
pub use router::{
    block_navigation, location, match_path, navigate, navigate_with, navigation, redirect,
    set_query, Keep, Link, LinkBuilder, LinkProps, Nav, Navigation, Outlet, OutletBuilder,
    OutletProps, Page, Prefetch, Query, Route, Router, Segments,
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
        action, component, context, debounced, document_event, effect, interval, media_query, memo,
        navigate, navigate_with, navigation, node_ref, page, provide, redirect, set_query,
        set_theme, sleep, state, stored, theme, title, try_context, view, window_event, Action,
        App, Callback, Can, Catch, DangerousHtml, Directive, ElementRef, Event, IntoView, Keep,
        Link, Nav, NodeRef, Outlet, Page, Plugin, Portal, Result, Route, Router, SafeUrl,
        Singleton, Slot, Slots, State, Suspense, Theme, Thrown, View,
    };
    pub use doxa_client::{layers, service, CacheConfig};
}
