//! `<Catch>` and `<Suspense>`: where errors and loading states stop.

use std::marker::PhantomData;
use std::rc::Rc;

use crate::component::{required, Component, RenderFuture, Set, Unset};
use crate::hooks::{catch_boundary, suspense_boundary};
use crate::view::el;
use crate::{IntoView, Thrown, View};

type Fallback = Rc<dyn Fn(&Thrown) -> View>;

/// Shows `fallback` instead of its children when one of them throws.
///
/// ```ignore
/// view! {
///     <Catch fallback={|e: &Thrown| view! { <p>{e.to_string()}</p> }}>
///         <WidgetPage name="sprocket"/>
///     </Catch>
/// }
/// ```
pub struct Catch;

/// Props of [`Catch`].
#[derive(Clone)]
pub struct CatchProps {
    fallback: Fallback,
    children: View,
}

required!(
    Catch_needs_fallback,
    "`<Catch>` is missing the `fallback` prop",
    "add `fallback={{|e: &Thrown| …}}` to the tag"
);

/// Builds [`CatchProps`].
pub struct CatchBuilder<F> {
    fallback: Option<Fallback>,
    children: View,
    _set: PhantomData<F>,
}

impl Catch {
    /// Start building its props.
    pub fn props() -> CatchBuilder<Unset> {
        CatchBuilder {
            fallback: None,
            children: View::empty(),
            _set: PhantomData,
        }
    }
}

impl<F> CatchBuilder<F> {
    /// What to show instead of the children when one throws.
    pub fn fallback<V: IntoView>(self, f: impl Fn(&Thrown) -> V + 'static) -> CatchBuilder<Set> {
        CatchBuilder {
            fallback: Some(Rc::new(move |e| f(e).into_view())),
            children: self.children,
            _set: PhantomData,
        }
    }

    /// `fallback={|e| …}` in `view!`.
    #[doc(hidden)]
    pub fn __fn_fallback<V: IntoView>(
        self,
        f: impl Fn(&Thrown) -> V + 'static,
    ) -> CatchBuilder<Set> {
        self.fallback(f)
    }

    /// `fallback={|| …}` in `view!`.
    #[doc(hidden)]
    pub fn __fn0_fallback<V: IntoView>(self, f: impl Fn() -> V + 'static) -> CatchBuilder<Set> {
        self.fallback(move |_| f())
    }

    /// The guarded children.
    pub fn children(mut self, children: View) -> Self {
        self.children = children;
        self
    }
}

impl<F> CatchBuilder<F> {
    /// Finish; every required prop must be given.
    pub fn build(self) -> CatchProps
    where
        F: Catch_needs_fallback,
    {
        CatchProps {
            fallback: self.fallback.expect("set"),
            children: self.children,
        }
    }
}

impl Component for Catch {
    type Props = CatchProps;
    const NAME: &'static str = "Catch";

    fn render(props: CatchProps) -> RenderFuture {
        RenderFuture::ready(Ok(match catch_boundary() {
            Some(e) => (props.fallback)(&e),
            None => props.children,
        }))
    }
}

/// Shows `fallback` while any child is still loading for the first time.
pub struct Suspense;

/// Props of [`Suspense`].
#[derive(Clone, Default)]
pub struct SuspenseProps {
    fallback: View,
    children: View,
}

/// Builds [`SuspenseProps`].
#[derive(Default)]
pub struct SuspenseBuilder(SuspenseProps);

impl Suspense {
    /// Start building its props.
    pub fn props() -> SuspenseBuilder {
        SuspenseBuilder::default()
    }
}

impl SuspenseBuilder {
    /// What to show while loading.
    pub fn fallback(mut self, v: impl IntoView) -> Self {
        self.0.fallback = v.into_view();
        self
    }

    /// The children.
    pub fn children(mut self, children: View) -> Self {
        self.0.children = children;
        self
    }

    /// Finish.
    pub fn build(self) -> SuspenseProps {
        self.0
    }
}

impl Component for Suspense {
    type Props = SuspenseProps;
    const NAME: &'static str = "Suspense";

    fn render(props: SuspenseProps) -> RenderFuture {
        let loading = suspense_boundary() > 0;
        let children = el("doxa-suspense")
            .attr(
                "style",
                if loading {
                    "display:none"
                } else {
                    "display:contents"
                },
            )
            .child(props.children);
        // Children first: a fallback ahead of them would shift their place and remount them.
        RenderFuture::ready(Ok(View::fragment([
            children.into_view(),
            if loading {
                props.fallback
            } else {
                View::empty()
            },
        ])))
    }
}
