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
#[cfg(feature = "export")]
mod export;
#[cfg(feature = "forms")]
mod form;
mod head;
mod hooks;
mod hot;
#[cfg(feature = "oidc")]
pub mod oidc;
mod plugin;
mod portal;
#[cfg(feature = "react")]
pub mod react;
mod reconcile;
mod router;
mod runtime;
mod story;
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
/// One [`Field`] per struct field, named by its path in the rules' errors.
#[cfg(feature = "forms")]
pub use doxa_ui_macros::Form;
pub use error::{Result, Thrown};
#[cfg(feature = "forms")]
#[doc(hidden)]
pub use form::At;
#[cfg(feature = "forms")]
pub use form::{field_errors, form, Field, FieldList, Form, FormFields, RowKey, Submit};
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
pub use story::{IntoStory, StoryRoot};
pub use theme::{set_theme, theme, Theme};
pub use view::{
    comp, el, BindChecked, BindSelected, BindValue, Callback, ComponentView, DangerousHtml,
    Element, IntoAttr, IntoProp, IntoView, Key, SafeUrl, View,
};

/// A React component as a doxa one: `#[react(module = "…", export = "…")]` on its props struct.
///
/// A `View` field reaches React as an element wrapping doxa's DOM; for a `render`/`asChild`
/// prop, `#[react(element)]` has React render the element and doxa only its children.
#[cfg(feature = "react")]
pub use doxa_ui_macros::react;
pub use doxa_ui_macros::{component, page, start, story, view};

/// A doxa component mounted by a foreign React host, as `#[component(export)]` wrappers do.
#[cfg(feature = "export")]
pub use export::Exported;

#[doc(hidden)]
pub mod __private {
    #[cfg(all(feature = "export", target_arch = "wasm32"))]
    pub use crate::export::{callback, mount as mount_export, prop, Calls, ExportHandle};
    pub use crate::view::FromChildren;
    #[cfg(target_arch = "wasm32")]
    pub use web_sys;

    #[cfg(target_arch = "wasm32")]
    pub use crate::story::{mount_story, StoryHandle};

    /// Whether a library package or the gallery loaded this wasm, so the app doesn't own the page.
    #[cfg(target_arch = "wasm32")]
    pub fn hosted() -> bool {
        js_sys::Reflect::get(&js_sys::global(), &"__DOXA_HOSTED__".into())
            .is_ok_and(|v| v.is_truthy())
    }
    #[cfg(target_arch = "wasm32")]
    pub use wasm_bindgen;
    #[cfg(target_arch = "wasm32")]
    pub use wasm_splitter as wasm_split;
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
