//! `fake::<Island>(|p| view! { … })`: a doxa stand-in that renders where a React island would,
//! so a test can click through it without a browser.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::react::{set_bridge, Bridge, Content, EventFn, IslandProps, Mount, Props, SlotPlacer};
use crate::{App, Component, RootHandle, View};

/// What a stand-in sees: the island's data props, and its event props to call.
#[derive(Clone)]
pub struct FakeProps {
    props: Props,
    events: Vec<(&'static str, EventFn)>,
}

impl FakeProps {
    /// A data prop by its React name, e.g. `p.prop::<usize>("total")`.
    pub fn prop<T: DeserializeOwned>(&self, name: &str) -> Option<T> {
        serde_json::from_value(self.props.get(name)?.clone()).ok()
    }

    /// Call an event prop by its React name, as React would: `p.fire("onPick", true)`.
    pub fn fire(&self, event: &str, arg: impl Serialize) {
        let json = serde_json::to_string(&arg).expect("an event argument serializes");
        match self.events.iter().find(|(n, _)| *n == event) {
            Some((_, f)) => f(&json),
            None => panic!("the island has no `{event}` event prop"),
        }
    }
}

type Stand = Rc<dyn Fn(&FakeProps) -> View>;

struct Live {
    host: crate::NodeRef,
    stand: Stand,
    events: Vec<(&'static str, EventFn)>,
    /// The stand-in's root and the element it renders into.
    root: Option<(RootHandle, crate::dom::NodeId)>,
}

impl Drop for Live {
    fn drop(&mut self) {
        clear(&mut self.root);
    }
}

fn clear(root: &mut Option<(RootHandle, crate::dom::NodeId)>) {
    if let Some((handle, at)) = root.take() {
        drop(handle);
        crate::runtime::dom().remove(at);
    }
}

#[derive(Default)]
struct Fakes {
    stands: HashMap<&'static str, Stand>,
    live: HashMap<u32, Live>,
    slots: Rc<SlotPlacer>,
}

thread_local! {
    static FAKES: Rc<RefCell<Fakes>> = Rc::default();
}

/// Render `C`, a `#[react]` component, as `stand` returns on this thread from now on.
pub fn fake<C>(stand: impl Fn(&FakeProps) -> View + 'static)
where
    C: Component,
    C::Props: IslandProps,
{
    let fakes = FAKES.with(Rc::clone);
    fakes
        .borrow_mut()
        .stands
        .insert(<C::Props as IslandProps>::ISLAND.name, Rc::new(stand));
    set_bridge(FakeBridge(fakes));
}

struct FakeBridge(Rc<RefCell<Fakes>>);

impl Bridge for FakeBridge {
    fn mount(&self, m: Mount<'_>) {
        let slots = self.0.borrow().slots.clone();
        slots.mount(m.id, m.host, &m.content.slots);
        let Some(stand) = self.0.borrow().stands.get(m.island.name).cloned() else {
            return;
        };
        self.0.borrow_mut().live.insert(
            m.id,
            Live {
                host: m.host,
                stand,
                events: m.events,
                root: None,
            },
        );
        render(&self.0, m.id, m.content.props.clone());
    }

    fn update(&self, id: u32, content: &Content) {
        let slots = self.0.borrow().slots.clone();
        slots.update(id, &content.slots);
        render(&self.0, id, content.props.clone());
    }

    fn unmount(&self, id: u32) {
        let slots = self.0.borrow().slots.clone();
        slots.unmount(id);
        let live = self.0.borrow_mut().live.remove(&id);
        drop(live);
    }
}

/// Mount the stand-in, after the render that placed the island has finished.
fn render(fakes: &Rc<RefCell<Fakes>>, id: u32, props: Props) {
    let fakes = fakes.clone();
    doxa_client::task::spawn(async move {
        let found = fakes
            .borrow_mut()
            .live
            .get_mut(&id)
            .map(|l| (l.root.take(), l.host, l.stand.clone(), l.events.clone()));
        let Some((mut old, host, stand, events)) = found else {
            return;
        };
        clear(&mut old);
        let dom = crate::runtime::dom();
        let at = dom.create_element("div", None);
        dom.set_attr(at, "data-fake", "");
        dom.set_attr(at, "style", "display: contents");
        dom.insert(host.id(), at, None);
        let p = Rc::new(FakeProps { props, events });
        let root = App::embedded(move || stand(&p)).mount_on(dom, at);
        if let Some(l) = fakes.borrow_mut().live.get_mut(&id) {
            l.root = Some((root, at));
        }
    });
}
