//! Plugins: views and providers added to an app from outside its own components.

use std::cell::RefCell;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::rc::Rc;

use crate::component::{Component, PropSet, RenderFuture, Set};
use crate::{IntoView, View};

/// Something an app installs with `App::plugin`.
///
/// ```ignore
/// struct Audit;
/// impl Plugin for Audit {
///     fn slots(&self, slots: &mut Slots) {
///         slots.fill("sidebar", || view! { <AuditFeed/> });
///     }
/// }
/// ```
pub trait Plugin: 'static {
    /// Add views to named `<Slot>`s.
    fn slots(&self, slots: &mut Slots) {
        let _ = slots;
    }

    /// Wrap the whole app, for example to `provide` a value to every component.
    fn wrap(&self, app: View) -> View {
        app
    }
}

type Fill = Rc<dyn Fn() -> View>;

/// What plugins put in each `<Slot name="…">`.
#[derive(Default)]
pub struct Slots(HashMap<&'static str, Vec<Fill>>);

impl Slots {
    /// Render `view` inside every `<Slot name={slot}>`, after earlier fills.
    pub fn fill<V: IntoView>(&mut self, slot: &'static str, view: impl Fn() -> V + 'static) {
        self.0
            .entry(slot)
            .or_default()
            .push(Rc::new(move || view().into_view()));
    }
}

thread_local! {
    static SLOTS: RefCell<Slots> = RefCell::new(Slots::default());
}

pub(crate) fn install(fill: impl FnOnce(&mut Slots)) {
    SLOTS.with(|s| fill(&mut s.borrow_mut()));
}

/// Where plugins' views go: `<Slot name="sidebar"/>`.
pub struct Slot;

/// Props of [`Slot`].
#[derive(Clone)]
pub struct SlotProps {
    name: &'static str,
}

#[doc(hidden)]
#[allow(non_camel_case_types)]
pub struct Slot_is_missing_the_name_prop;

/// Builds [`SlotProps`].
pub struct SlotBuilder<N> {
    name: &'static str,
    _set: PhantomData<N>,
}

impl Slot {
    /// Start building its props.
    pub fn props() -> SlotBuilder<Slot_is_missing_the_name_prop> {
        SlotBuilder {
            name: "",
            _set: PhantomData,
        }
    }
}

impl<N> SlotBuilder<N> {
    /// The slot's name.
    pub fn name(self, name: &'static str) -> SlotBuilder<Set> {
        SlotBuilder {
            name,
            _set: PhantomData,
        }
    }
}

impl<N> SlotBuilder<N> {
    /// Finish; every required prop must be given.
    pub fn build(self) -> SlotProps
    where
        N: PropSet,
    {
        SlotProps { name: self.name }
    }
}

impl Component for Slot {
    type Props = SlotProps;
    const NAME: &'static str = "Slot";

    fn render(props: SlotProps) -> RenderFuture {
        let fills: Vec<Fill> =
            SLOTS.with(|s| s.borrow().0.get(props.name).cloned().unwrap_or_default());
        RenderFuture::ready(Ok(fills.iter().map(|f| f()).collect()))
    }
}
