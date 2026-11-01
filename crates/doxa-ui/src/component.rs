//! Components: what `#[component]` implements.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::future::LocalBoxFuture;

use crate::{IntoView, Result, Thrown, View};

/// Compares two components' props, both `Rc<Props>` erased.
#[doc(hidden)]
pub type SameProps = fn(&std::rc::Rc<dyn std::any::Any>, &std::rc::Rc<dyn std::any::Any>) -> bool;

/// A component. Write it as a function with `#[component]`.
pub trait Component: 'static {
    /// Its props.
    type Props: Clone + 'static;
    /// Its name, for diagnostics.
    const NAME: &'static str;
    /// Set by `#[component(memo)]`: skip re-rendering when props are equal.
    #[doc(hidden)]
    const SAME_PROPS: Option<SameProps> = None;
    /// Render with `props`.
    fn render(props: Self::Props) -> RenderFuture;
}

/// A component's render, possibly still waiting on data.
pub struct RenderFuture(Inner);

enum Inner {
    Ready(Option<Result<View>>),
    Pending(LocalBoxFuture<'static, Result<View>>),
}

impl RenderFuture {
    /// A render that awaits.
    pub fn new(fut: impl Future<Output = Result<View>> + 'static) -> Self {
        RenderFuture(Inner::Pending(Box::pin(fut)))
    }

    /// A render that is already done.
    pub fn ready(view: Result<View>) -> Self {
        RenderFuture(Inner::Ready(Some(view)))
    }
}

impl Future for RenderFuture {
    type Output = Result<View>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<View>> {
        match &mut self.0 {
            Inner::Ready(v) => Poll::Ready(v.take().expect("polled after completion")),
            Inner::Pending(f) => f.as_mut().poll(cx),
        }
    }
}

/// What a component function may return: a view, or a `Result` of one.
#[diagnostic::on_unimplemented(
    message = "a component returns `View` or `Result<View>`, not `{Self}`",
    label = "change the return type"
)]
pub trait IntoRender {
    /// Convert, keeping any error for `<Catch>`.
    fn into_render(self) -> Result<View>;
}

impl<V: IntoView> IntoRender for V {
    fn into_render(self) -> Result<View> {
        Ok(self.into_view())
    }
}

impl<V: IntoView, E: Into<Thrown>> IntoRender for std::result::Result<V, E> {
    fn into_render(self) -> Result<View> {
        self.map(IntoView::into_view).map_err(Into::into)
    }
}

/// A required prop not yet given; `build()` is unavailable until every one is.
#[diagnostic::on_unimplemented(
    message = "a required prop is missing: {Self}",
    label = "add the prop to the component's tag"
)]
pub trait PropSet {}

/// Marker for a prop that has been given.
#[doc(hidden)]
pub struct Set;

impl PropSet for Set {}
