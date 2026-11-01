//! `<Can>`: show children only when the route's own guard would let this caller in.

use std::marker::PhantomData;

use doxa_client::{Permission, Probe};

use crate::component::{required, Component, RenderFuture, Set, Unset};
use crate::{IntoView, View};

/// Renders its children when a dry run of the route is allowed, `fallback` when
/// it is denied, and `unknown` when the route can't say.
///
/// ```ignore
/// view! {
///     <Can route={rename_widget} args={&key} fallback={"read only"}>
///         <button>"Rename"</button>
///     </Can>
/// }
/// ```
pub struct Can;

/// Props of [`Can`].
#[derive(Clone)]
pub struct CanProps {
    probe: Probe,
    fallback: View,
    unknown: View,
    children: View,
}

required!(
    Can_needs_route,
    "`<Can>` is missing the `route` prop",
    "add `route={{the_route_fn}}` to the tag"
);

/// Builds [`CanProps`]; `view!` sets `probe` from `route` and `args`.
pub struct CanBuilder<P> {
    probe: Option<Probe>,
    fallback: View,
    unknown: View,
    children: View,
    _set: PhantomData<P>,
}

impl Can {
    /// Start building its props.
    pub fn props() -> CanBuilder<Unset> {
        CanBuilder {
            probe: None,
            fallback: View::empty(),
            unknown: View::empty(),
            children: View::empty(),
            _set: PhantomData,
        }
    }
}

impl<P> CanBuilder<P> {
    /// The dry run to ask, `route_name::can(args…)`.
    pub fn probe(self, probe: Probe) -> CanBuilder<Set> {
        CanBuilder {
            probe: Some(probe),
            fallback: self.fallback,
            unknown: self.unknown,
            children: self.children,
            _set: PhantomData,
        }
    }

    /// Shown when the route says no.
    pub fn fallback(mut self, v: impl IntoView) -> Self {
        self.fallback = v.into_view();
        self
    }

    /// Shown when the route can't answer a dry run; nothing by default.
    pub fn unknown(mut self, v: impl IntoView) -> Self {
        self.unknown = v.into_view();
        self
    }

    /// Shown when the route says yes.
    pub fn children(mut self, children: View) -> Self {
        self.children = children;
        self
    }
}

impl<P> CanBuilder<P> {
    /// Finish; every required prop must be given.
    pub fn build(self) -> CanProps
    where
        P: Can_needs_route,
    {
        CanProps {
            probe: self.probe.expect("set"),
            fallback: self.fallback,
            unknown: self.unknown,
            children: self.children,
        }
    }
}

impl Component for Can {
    type Props = CanProps;
    const NAME: &'static str = "Can";

    fn render(props: CanProps) -> RenderFuture {
        RenderFuture::new(async move {
            Ok(match props.probe.await {
                Permission::Allowed => props.children,
                Permission::Denied => props.fallback,
                Permission::Unknown => props.unknown,
            })
        })
    }
}
