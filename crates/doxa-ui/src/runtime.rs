//! Mounted components, and when they render.
//!
//! A component's render is a future. Its first poll happens inline so cached
//! data shows in the same frame; if it waits, it finishes as a task, and a
//! re-render meanwhile cancels it while the previous view stays on screen.

use std::any::{Any, TypeId};
use std::cell::{Cell, RefCell};
use std::future::Future;
use std::panic::Location;
use std::pin::Pin;
use std::rc::{Rc, Weak};
use std::task::{Context, Poll, Waker};

use futures_util::future::LocalBoxFuture;

use crate::component::RenderFuture;
use crate::dom::{Dom, NodeId};
use crate::reconcile::{self, Mounted};
use crate::{Result, Thrown, View};

pub(crate) struct Hook {
    pub at: &'static Location<'static>,
    pub type_id: TypeId,
    pub value: Rc<dyn Any>,
}

pub(crate) struct Instance {
    pub id: u64,
    pub name: &'static str,
    pub type_id: TypeId,
    pub depth: usize,
    pub parent: Option<Weak<Instance>>,
    pub render: fn(&Rc<dyn Any>) -> RenderFuture,
    pub props: RefCell<Rc<dyn Any>>,
    pub hooks: RefCell<Vec<Hook>>,
    pub cursor: Cell<usize>,
    pub contexts: RefCell<Vec<(TypeId, Rc<dyn Any>)>>,
    /// What this render `provide`d; replaces `contexts` when it commits.
    pub provided: RefCell<Vec<(TypeId, Rc<dyn Any>)>>,
    pub keeps_contexts: bool,
    pub region: RefCell<Vec<Mounted>>,
    pub parent_node: Cell<NodeId>,
    pub dirty: Cell<bool>,
    pub alive: Cell<bool>,
    pub committed: Cell<bool>,
    generation: Cell<u64>,
    task: RefCell<Option<Cancel>>,
    pub effects: RefCell<Vec<Box<dyn FnOnce()>>>,
    pub catcher: Cell<bool>,
    pub caught: RefCell<Option<Thrown>>,
    pub suspense: Cell<bool>,
    pub waiting: Cell<usize>,
    counted: Cell<Option<Weak<Instance>>>,
    observer: Rc<Observe>,
}

struct Observe(RefCell<Weak<Instance>>);

impl doxa_client::cache::Observer for Observe {
    fn changed(&self) {
        if let Some(inst) = self.0.borrow().upgrade() {
            schedule(&inst);
        }
    }
}

impl Instance {
    pub fn new(
        name: &'static str,
        type_id: TypeId,
        parent: Option<&Rc<Instance>>,
        render: fn(&Rc<dyn Any>) -> RenderFuture,
        props: Rc<dyn Any>,
        parent_node: NodeId,
    ) -> Rc<Instance> {
        let id = NEXT_ID.with(|n| n.replace(n.get() + 1));
        let inst = Rc::new(Instance {
            id,
            name,
            type_id,
            depth: parent.map_or(0, |p| p.depth + 1),
            parent: parent.map(Rc::downgrade),
            render,
            props: RefCell::new(props),
            hooks: RefCell::new(Vec::new()),
            cursor: Cell::new(0),
            contexts: RefCell::new(Vec::new()),
            provided: RefCell::new(Vec::new()),
            keeps_contexts: parent.is_none(),
            region: RefCell::new(Vec::new()),
            parent_node: Cell::new(parent_node),
            dirty: Cell::new(false),
            alive: Cell::new(true),
            committed: Cell::new(false),
            generation: Cell::new(0),
            task: RefCell::new(None),
            effects: RefCell::new(Vec::new()),
            catcher: Cell::new(false),
            caught: RefCell::new(None),
            suspense: Cell::new(false),
            waiting: Cell::new(0),
            counted: Cell::new(None),
            observer: Rc::new(Observe(RefCell::new(Weak::new()))),
        });
        *inst.observer.0.borrow_mut() = Rc::downgrade(&inst);
        LIVE.with(|l| l.borrow_mut().insert(id, Rc::downgrade(&inst)));
        inst
    }

    /// The live instance with `id`.
    pub fn find(id: u64) -> Option<Rc<Instance>> {
        LIVE.with(|l| l.borrow().get(&id).and_then(Weak::upgrade))
    }

    pub fn parent(&self) -> Option<Rc<Instance>> {
        self.parent.as_ref().and_then(Weak::upgrade)
    }

    /// The id of the root this instance is mounted under.
    pub fn root_id(self: &Rc<Self>) -> u64 {
        self.ancestors().last().map_or(self.id, |r| r.id)
    }

    fn ancestors(self: &Rc<Self>) -> impl Iterator<Item = Rc<Instance>> {
        std::iter::successors(Some(self.clone()), |i| i.parent())
    }

    /// Stop rendering and running effects; called when unmounted.
    pub fn kill(&self) {
        self.alive.set(false);
        LIVE.with(|l| l.borrow_mut().remove(&self.id));
        if let Some(t) = self.task.borrow_mut().take() {
            t.cancel();
        }
        self.settle_waiting();
        for hook in self.hooks.borrow().iter() {
            if let Some(e) = hook.value.downcast_ref::<crate::hooks::EffectSlot>() {
                e.stop();
            }
        }
    }

    fn settle_waiting(&self) {
        if let Some(boundary) = self.counted.take().and_then(|w| w.upgrade()) {
            boundary
                .waiting
                .set(boundary.waiting.get().saturating_sub(1));
            if boundary.waiting.get() == 0 {
                schedule(&boundary);
            }
        }
    }
}

thread_local! {
    static NEXT_ID: Cell<u64> = const { Cell::new(1) };
    static LIVE: RefCell<std::collections::HashMap<u64, Weak<Instance>>> = RefCell::new(std::collections::HashMap::new());
    static DOM: RefCell<Option<Rc<dyn Dom>>> = const { RefCell::new(None) };
    static CURRENT: RefCell<Vec<Rc<Instance>>> = const { RefCell::new(Vec::new()) };
    static DIRTY: RefCell<Vec<Rc<Instance>>> = const { RefCell::new(Vec::new()) };
    static SCHEDULED: Cell<bool> = const { Cell::new(false) };
}

pub(crate) fn set_dom(dom: Rc<dyn Dom>) {
    DOM.with(|d| *d.borrow_mut() = Some(dom));
}

/// Whether `dom` is the document roots on this thread render into.
pub(crate) fn is_dom(dom: &Rc<dyn Dom>) -> bool {
    DOM.with(|d| {
        d.borrow()
            .as_ref()
            .is_some_and(|c| std::ptr::addr_eq(Rc::as_ptr(c), Rc::as_ptr(dom)))
    })
}

pub(crate) fn try_dom() -> Option<Rc<dyn Dom>> {
    DOM.with(|d| d.borrow().clone())
}

pub(crate) fn dom() -> Rc<dyn Dom> {
    DOM.with(|d| d.borrow().clone())
        .expect("no document: mount an App first")
}

/// The component whose render is running, if any.
pub(crate) fn current_instance() -> Option<Rc<Instance>> {
    CURRENT.with(|c| c.borrow().last().cloned())
}

pub(crate) fn current_or_panic(hook: &str) -> Rc<Instance> {
    current_instance().unwrap_or_else(|| {
        panic!("`{hook}` was called outside a component's render; hooks only work inside `#[component]` bodies")
    })
}

/// Re-render `inst` soon, batched with everything else that changed.
pub(crate) fn schedule(inst: &Rc<Instance>) {
    if !inst.alive.get() || inst.dirty.replace(true) {
        return;
    }
    DIRTY.with(|d| d.borrow_mut().push(inst.clone()));
    if !SCHEDULED.with(|s| s.replace(true)) {
        doxa_client::task::spawn(async { flush() });
    }
}

/// The components that read a shared value, re-rendered when it changes.
#[derive(Default)]
pub(crate) struct Readers(Vec<Weak<Instance>>);

impl Readers {
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Remember the component rendering now, if any.
    pub fn track(&mut self) {
        if let Some(r) = current_instance() {
            if !self.0.iter().any(|w| w.as_ptr() == Rc::as_ptr(&r)) {
                self.0.push(Rc::downgrade(&r));
            }
        }
    }

    /// The readers still mounted; pass them to [`schedule_all`] once every borrow is released.
    pub fn live(&mut self) -> Vec<Rc<Instance>> {
        self.0.retain(|w| w.strong_count() > 0);
        self.0.iter().filter_map(Weak::upgrade).collect()
    }
}

pub(crate) fn schedule_all(readers: Vec<Rc<Instance>>) {
    readers.iter().for_each(schedule);
}

/// Re-render everything scheduled, parents first.
pub(crate) fn flush() {
    SCHEDULED.with(|s| s.set(false));
    let mut dirty = DIRTY.with(|d| std::mem::take(&mut *d.borrow_mut()));
    dirty.sort_by_key(|i| i.depth);
    for inst in dirty {
        if inst.alive.get() && inst.dirty.get() {
            run(&inst);
        }
    }
}

/// A render future that knows which component it belongs to.
struct Tracked {
    inst: Rc<Instance>,
    fut: RenderFuture,
}

impl Future for Tracked {
    type Output = Result<View>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<View>> {
        let inst = self.inst.clone();
        inside(&inst, || Pin::new(&mut self.fut).poll(cx))
    }
}

/// Run `f` as part of `inst`'s render: hooks find it, and cache reads re-render it.
fn inside<R>(inst: &Rc<Instance>, f: impl FnOnce() -> R) -> R {
    CURRENT.with(|c| c.borrow_mut().push(inst.clone()));
    let previous = doxa_client::cache::set_observer(Some(inst.observer.clone()));
    let out = f();
    doxa_client::cache::set_observer(previous);
    CURRENT.with(|c| c.borrow_mut().pop());
    out
}

/// A task that can be stopped from outside.
#[derive(Clone)]
pub(crate) struct Cancel(Rc<RefCell<Option<LocalBoxFuture<'static, ()>>>>);

impl Cancel {
    pub fn cancel(&self) {
        self.0.borrow_mut().take();
    }
}

pub(crate) fn spawn_cancellable(fut: impl Future<Output = ()> + 'static) -> Cancel {
    let cell: Rc<RefCell<Option<LocalBoxFuture<'static, ()>>>> =
        Rc::new(RefCell::new(Some(Box::pin(fut))));
    let driver = cell.clone();
    doxa_client::task::spawn(std::future::poll_fn(move |cx| {
        let mut slot = driver.borrow_mut();
        let Some(fut) = slot.as_mut() else {
            return Poll::Ready(());
        };
        match fut.as_mut().poll(cx) {
            Poll::Ready(()) => {
                *slot = None;
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }));
    Cancel(cell)
}

/// Render `inst` now, keeping its current view until the new one is ready.
pub(crate) fn run(inst: &Rc<Instance>) {
    inst.dirty.set(false);
    if let Some(t) = inst.task.borrow_mut().take() {
        t.cancel();
    }
    let generation = inst.generation.get() + 1;
    inst.generation.set(generation);
    inst.cursor.set(0);
    inst.provided.borrow_mut().clear();
    inst.effects.borrow_mut().clear();

    let props = inst.props.borrow().clone();
    let mut fut = Box::pin(Tracked {
        inst: inst.clone(),
        fut: inside(inst, || (inst.render)(&props)),
    });
    match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(out) => commit(inst, out),
        Poll::Pending => {
            if !inst.committed.get() {
                count_waiting(inst);
            }
            let weak = Rc::downgrade(inst);
            let task = spawn_cancellable(async move {
                let out = fut.await;
                if let Some(inst) = weak.upgrade() {
                    if inst.alive.get() && inst.generation.get() == generation {
                        inst.task.borrow_mut().take();
                        commit(&inst, out);
                    }
                }
            });
            *inst.task.borrow_mut() = Some(task);
        }
    }
}

fn count_waiting(inst: &Rc<Instance>) {
    let already = inst.counted.take();
    if already.is_some() {
        inst.counted.set(already);
        return;
    }
    let boundary = inst.ancestors().skip(1).find(|a| a.suspense.get());
    if let Some(b) = boundary {
        b.waiting.set(b.waiting.get() + 1);
        if b.waiting.get() == 1 {
            schedule(&b);
        }
        inst.counted.set(Some(Rc::downgrade(&b)));
    }
}

fn commit(inst: &Rc<Instance>, out: Result<View>) {
    match out {
        Ok(view) => {
            commit_contexts(inst);
            reconcile::update_region(inst, view);
            inst.committed.set(true);
            inst.settle_waiting();
            let effects = std::mem::take(&mut *inst.effects.borrow_mut());
            for start in effects {
                start();
            }
        }
        Err(e) => throw(Some(inst), e),
    }
}

fn commit_contexts(inst: &Instance) {
    let provided = std::mem::take(&mut *inst.provided.borrow_mut());
    let mut contexts = inst.contexts.borrow_mut();
    if !inst.keeps_contexts {
        contexts.clear();
    }
    for (t, v) in provided {
        contexts.retain(|(c, _)| *c != t);
        contexts.push((t, v));
    }
}

/// Hand an error to the nearest `<Catch>` above `from`.
pub(crate) fn throw(from: Option<&Rc<Instance>>, e: Thrown) {
    let catcher = from.and_then(|f| f.ancestors().skip(1).find(|a| a.catcher.get()));
    match catcher {
        Some(c) => {
            *c.caught.borrow_mut() = Some(e);
            schedule(&c);
        }
        None => report(from.map(|f| f.name), &e),
    }
}

fn report(component: Option<&str>, e: &Thrown) {
    let msg = match component {
        Some(c) => format!("uncaught error in <{c}>: {e}"),
        None => format!("uncaught error: {e}"),
    };
    #[cfg(target_arch = "wasm32")]
    web_sys_console(&msg);
    #[cfg(not(target_arch = "wasm32"))]
    eprintln!("{msg}");
}

#[cfg(target_arch = "wasm32")]
fn web_sys_console(msg: &str) {
    #[wasm_bindgen::prelude::wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_namespace = console, js_name = error)]
        fn console_error(s: &str);
    }
    console_error(msg);
}
