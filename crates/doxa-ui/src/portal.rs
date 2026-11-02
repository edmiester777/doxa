//! `<Portal to="body">`: render children into another element, keeping context and
//! `<Catch>` from where the portal is written.

use std::marker::PhantomData;
use std::rc::Rc;

use crate::component::{required, Component, RenderFuture, Set, Unset};
use crate::dom::NodeRef;
use crate::view::Node;
use crate::View;

/// Renders its children at the end of `to` instead of in place.
///
/// ```ignore
/// view! { <Portal to="body"><Dialog/></Portal> }
/// ```
pub struct Portal;

/// Where a [`Portal`] renders: a CSS selector, or an element from a [`node_ref`](crate::node_ref).
#[derive(Clone, PartialEq)]
pub enum PortalTarget {
    /// The first element matching a selector, looked up when the portal mounts.
    Selector(Rc<str>),
    /// This element.
    Node(NodeRef),
}

impl From<&str> for PortalTarget {
    fn from(s: &str) -> Self {
        PortalTarget::Selector(s.into())
    }
}

impl From<String> for PortalTarget {
    fn from(s: String) -> Self {
        PortalTarget::Selector(s.into())
    }
}

impl From<NodeRef> for PortalTarget {
    fn from(n: NodeRef) -> Self {
        PortalTarget::Node(n)
    }
}

/// Props of [`Portal`].
#[derive(Clone)]
pub struct PortalProps {
    to: PortalTarget,
    children: View,
}

pub(crate) struct PortalNode {
    pub to: PortalTarget,
    pub children: View,
}

required!(
    Portal_needs_to,
    "`<Portal>` is missing the `to` prop",
    "add `to=\"body\"`, or `to={{node}}`, to the tag"
);

/// Builds [`PortalProps`].
pub struct PortalBuilder<T> {
    to: Option<PortalTarget>,
    children: View,
    _set: PhantomData<T>,
}

impl Portal {
    /// Start building its props.
    pub fn props() -> PortalBuilder<Unset> {
        PortalBuilder {
            to: None,
            children: View::empty(),
            _set: PhantomData,
        }
    }
}

impl<T> PortalBuilder<T> {
    /// The element to render into.
    pub fn to(self, to: impl Into<PortalTarget>) -> PortalBuilder<Set> {
        PortalBuilder {
            to: Some(to.into()),
            children: self.children,
            _set: PhantomData,
        }
    }

    /// What to render there.
    pub fn children(mut self, children: View) -> Self {
        self.children = children;
        self
    }

    /// Finish; `to` must be given.
    pub fn build(self) -> PortalProps
    where
        T: Portal_needs_to,
    {
        PortalProps {
            to: self.to.expect("set"),
            children: self.children,
        }
    }
}

impl Component for Portal {
    type Props = PortalProps;
    const NAME: &'static str = "Portal";

    fn render(props: PortalProps) -> RenderFuture {
        RenderFuture::ready(Ok(View(Node::Portal(Rc::new(PortalNode {
            to: props.to,
            children: props.children,
        })))))
    }
}
