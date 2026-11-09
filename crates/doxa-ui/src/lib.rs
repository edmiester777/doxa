//! A client-rendered UI for doxa apps. Components are async functions that call
//! routes directly; hooks follow React's rules, checked at runtime.
//!
//! Most apps only need `use doxa::ui::prelude::*;`.

// The gallery is written with doxa's own macros, which name `::doxa::ui`.
#[cfg(all(feature = "gallery", not(test)))]
extern crate self as doxa;
#[cfg(all(feature = "gallery", not(test)))]
#[doc(hidden)]
pub mod ui {
    pub use crate::*;
}

mod app;
mod attrs;
mod boundary;
mod browser;
mod can;
mod class;
mod component;
mod directive;
pub mod dom;
mod error;
#[cfg(feature = "export")]
mod export;
#[cfg(feature = "forms")]
mod form;
#[cfg(feature = "gallery")]
pub mod gallery;
mod head;
mod hooks;
mod hot;
mod icon;
#[cfg(any(feature = "npm", feature = "react"))]
mod js;
#[cfg(feature = "npm")]
mod npm;
#[cfg(feature = "oidc")]
pub mod oidc;
#[cfg(any(feature = "npm", feature = "react"))]
pub use js::Js;
#[cfg(feature = "npm")]
pub use npm::{JsCallback, JsError};
mod plugin;
mod portal;
#[cfg(feature = "react")]
pub mod react;
mod reconcile;
mod resource;
mod router;
mod runtime;
mod story;
#[cfg(not(target_arch = "wasm32"))]
pub mod testing;
mod theme;
mod view;

pub use app::{App, IntoRoot, RootHandle};
pub use attrs::Attrs;
pub use boundary::{Catch, CatchBuilder, CatchProps, Suspense, SuspenseBuilder, SuspenseProps};
pub use browser::{
    broadcast, clipboard, debounced, document_event, exit_fullscreen, fullscreen, intersection,
    interval, is_mac, media_query, now, resize_observer, save, sleep, stored, window_event,
    Broadcast, BrowserError, Stored,
};
pub use can::{requires, Can, CanBuilder, CanProps};
pub use class::ClassPart;
pub use component::{Component, ComponentProps, IntoRender, RenderFuture, Set, Unset};
pub use directive::Directive;
pub use dom::{Event, Listen, NodeRef, Phase, Rect, Scroll};
/// One [`Field`] per struct field, named by its path in the rules' errors; on an enum, one
/// per variant's field, plus the variant itself.
#[cfg(feature = "forms")]
pub use doxa_ui_macros::Form;
pub use error::{Outcome, Result, Thrown};
#[cfg(feature = "forms")]
#[doc(hidden)]
pub use form::At;
#[cfg(feature = "forms")]
pub use form::{field_errors, form, Field, FieldList, Form, FormFields, RowKey, Submit};
pub use head::title;
pub use hooks::{
    action, callback, context, effect, latest, memo, node_ref, provide, reference, state,
    try_context, Action, Deps, ElementRef, Reference, Singleton, StableCallback, State,
};
pub use icon::{Icon, IconExt, IconProps, IconSet, IconStyle};
pub use plugin::{Plugin, Slot, SlotBuilder, SlotProps, Slots};
pub use portal::{Portal, PortalBuilder, PortalProps, PortalTarget};
pub use resource::{polled_resource, resource, Load, LoadError, Resource};
pub use router::{
    href, link_active, location, match_path, navigate, navigate_through, navigate_with, navigation,
    redirect, set_query, set_query_as, Keep, Link, LinkBuilder, LinkProps, Nav, Navigation,
    NavigationGuard, NavigationGuardBuilder, NavigationGuardProps, Outlet, OutletBuilder,
    OutletProps, Page, Prefetch, Query, Route, Router, Segments,
};
pub use story::{IntoStory, Story, StoryRoot};
pub use theme::{set_theme, theme, Theme};
pub use view::{
    comp, el, BindChecked, BindSelected, BindValue, Callback, ComponentView, DangerousHtml,
    Element, IntoAttr, IntoProp, IntoView, Key, SafeUrl, View,
};

/// An enum of SVG icons read at compile time: `#[icons(from = "lucide-static/icons/{kebab}.svg")]`.
pub use doxa_ui_macros::icons;
#[cfg(feature = "npm")]
pub use doxa_ui_macros::npm;
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
    pub use crate::attrs::RestAttrs;
    pub use crate::component::comp_for;
    #[cfg(all(feature = "export", target_arch = "wasm32"))]
    pub use crate::export::{callback, mount as mount_export, prop, Calls, ExportHandle};
    pub use crate::icon::{svg_el, svg_root};
    pub use crate::story::story_meta;
    pub use crate::view::{owner, FromChildren, IntoOptional, OptionOf, Owner};
    pub use futures_util::future::LocalBoxFuture;
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
    #[cfg(all(feature = "npm", target_arch = "wasm32"))]
    pub use crate::npm::convert::{
        await_promise, describe, from_js, js_callback, js_error, js_error_from, js_node, js_raw,
        to_js,
    };
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
        action, callback, classes, component, context, debounced, document_event, effect, interval,
        latest, media_query, memo, navigate, navigate_with, navigation, node_ref, page,
        polled_resource, provide, redirect, reference, resource, set_query, set_query_as,
        set_theme, sleep, state, stored, theme, title, try_context, view, window_event, Action,
        App, Attrs, Callback, Can, Catch, DangerousHtml, Directive, ElementRef, Event, IconExt,
        IntoView, Keep, Link, Load, Nav, NodeRef, Outlet, Page, Plugin, Portal, Reference,
        Resource, Result, Route, Router, SafeUrl, Scroll, Singleton, Slot, Slots, StableCallback,
        State, Suspense, Theme, Thrown, View,
    };
    pub use doxa_client::{layers, service};
}
