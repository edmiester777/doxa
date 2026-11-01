//! `<Can>`: show children only when the route's own guard would let this caller in.

use std::marker::PhantomData;

use doxa_client::Probe;

use crate::component::{Component, PropSet, RenderFuture, Set};
use crate::{IntoView, View};

/// Renders its children when a dry run of the route is allowed, `fallback` otherwise.
///
/// ```ignore
/// view! {
///     <Can route={rename_widget} args={&key}>
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
    children: View,
}

#[doc(hidden)]
#[allow(non_camel_case_types)]
pub struct Can_is_missing_the_route_prop;

/// Builds [`CanProps`]; `view!` sets `probe` from `route` and `args`.
pub struct CanBuilder<P> {
    probe: Option<Probe>,
    fallback: View,
    children: View,
    _set: PhantomData<P>,
}

impl Can {
    /// Start building its props.
    pub fn props() -> CanBuilder<Can_is_missing_the_route_prop> {
        CanBuilder {
            probe: None,
            fallback: View::empty(),
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
            children: self.children,
            _set: PhantomData,
        }
    }

    /// Shown when the route says no, or can't say.
    pub fn fallback(mut self, v: impl IntoView) -> Self {
        self.fallback = v.into_view();
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
        P: PropSet,
    {
        CanProps {
            probe: self.probe.expect("set"),
            fallback: self.fallback,
            children: self.children,
        }
    }
}

impl Component for Can {
    type Props = CanProps;
    const NAME: &'static str = "Can";

    fn render(props: CanProps) -> RenderFuture {
        RenderFuture::new(async move {
            Ok(if props.probe.await.allowed() {
                props.children
            } else {
                props.fallback
            })
        })
    }
}
