//! React's hooks: `state`, `memo`, `effect`, `action`, `provide` / `context`, and `Singleton`.
//!
//! Each hook claims the next slot of the component calling it. The call site is
//! recorded, and in debug builds a render reaching a slot from a different call
//! site panics naming both, which catches conditional hooks.

use std::any::{Any, TypeId};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::panic::Location;
use std::rc::Rc;

use crate::runtime::{self, current_or_panic, Cancel, Hook, Instance, Readers};
use crate::{Result, Thrown};

#[track_caller]
pub(crate) fn slot<T: 'static>(
    hook: &str,
    init: impl FnOnce() -> T,
) -> (Rc<Instance>, usize, Rc<T>) {
    let inst = current_or_panic(hook);
    let at = Location::caller();
    let i = inst.cursor.get();
    inst.cursor.set(i + 1);
    let mut hooks = inst.hooks.borrow_mut();
    if let Some(h) = hooks.get(i) {
        if cfg!(debug_assertions) && (h.at != at || h.type_id != TypeId::of::<T>()) {
            panic!(
                "hook order changed in <{}>: `{hook}` at {at} ran where the hook at {} ran last render. \
                 Hooks must run in the same order every render: don't call them conditionally, in loops, \
                 or after an early return",
                inst.name, h.at
            );
        }
        let value = h
            .value
            .clone()
            .downcast::<T>()
            .expect("slot type checked above");
        drop(hooks);
        return (inst, i, value);
    }
    let value = Rc::new(init());
    hooks.push(Hook {
        at,
        type_id: TypeId::of::<T>(),
        value: value.clone(),
    });
    drop(hooks);
    (inst, i, value)
}

/// A piece of component state. `Copy`, so closures take it without cloning.
pub struct State<T: 'static> {
    instance: u64,
    slot: usize,
    _t: PhantomData<fn() -> T>,
}

impl<T> Clone for State<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for State<T> {}

/// Component state, like React's `useState`: `init` is used on the first render only.
#[track_caller]
pub fn state<T: 'static>(init: T) -> State<T> {
    let (inst, slot, _) = slot("state", || RefCell::new(init));
    State {
        instance: inst.id,
        slot,
        _t: PhantomData,
    }
}

/// The value in hook `slot` of a still-mounted instance.
fn hook_value<T: 'static>(instance: u64, slot: usize) -> Option<Rc<T>> {
    let inst = Instance::find(instance)?;
    let value = inst.hooks.borrow().get(slot)?.value.clone();
    value.downcast::<T>().ok()
}

impl<T: 'static> State<T> {
    fn with_cell<R>(&self, f: impl FnOnce(&RefCell<T>) -> R) -> Option<R> {
        hook_value::<RefCell<T>>(self.instance, self.slot).map(|c| f(&c))
    }

    /// Read the value without cloning it.
    pub fn with<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        self.with_cell(|c| f(&c.borrow()))
            .expect("state read after its component unmounted")
    }

    /// Replace the value and re-render.
    pub fn set(&self, value: T) {
        self.update(|v| *v = value);
    }

    /// Change the value in place and re-render.
    pub fn update(&self, f: impl FnOnce(&mut T)) {
        if self.with_cell(|c| f(&mut c.borrow_mut())).is_some() {
            if let Some(inst) = Instance::find(self.instance) {
                runtime::schedule(&inst);
            }
        }
    }
}

impl<T: Clone + 'static> State<T> {
    /// A copy of the value.
    pub fn get(&self) -> T {
        self.with(T::clone)
    }
}

impl State<bool> {
    /// Flip it.
    pub fn toggle(&self) {
        self.update(|b| *b = !*b);
    }
}

/// Dependencies of a `memo` or `effect`: values, references, or tuples of them.
pub trait Deps {
    /// The owned copy compared between renders.
    type Owned: PartialEq + Clone + 'static;
    /// Take the copy.
    fn to_deps(&self) -> Self::Owned;
}

impl<T: Clone + PartialEq + 'static> Deps for &T {
    type Owned = T;
    fn to_deps(&self) -> T {
        (*self).clone()
    }
}

impl<T: Clone + PartialEq + 'static> Deps for State<T> {
    type Owned = T;
    fn to_deps(&self) -> T {
        self.get()
    }
}

impl Deps for () {
    type Owned = ();
    fn to_deps(&self) {}
}

macro_rules! tuple_deps {
    ($($n:ident $i:tt),+) => {
        impl<$($n: Deps),+> Deps for ($($n,)+) {
            type Owned = ($($n::Owned,)+);
            fn to_deps(&self) -> Self::Owned {
                ($(self.$i.to_deps(),)+)
            }
        }
    };
}

tuple_deps!(A 0);
tuple_deps!(A 0, B 1);
tuple_deps!(A 0, B 1, C 2);
tuple_deps!(A 0, B 1, C 2, D 3);

struct MemoCell<D, T> {
    entry: RefCell<Option<(D, T)>>,
}

/// A value recomputed only when `deps` change, like React's `useMemo`.
#[track_caller]
pub fn memo<D: Deps, T: Clone + 'static>(deps: D, compute: impl FnOnce(&D::Owned) -> T) -> T {
    let (_, _, cell) = slot("memo", || MemoCell::<D::Owned, T> {
        entry: RefCell::new(None),
    });
    let now = deps.to_deps();
    let mut entry = cell.entry.borrow_mut();
    match &*entry {
        Some((d, v)) if *d == now => v.clone(),
        _ => {
            let v = compute(&now);
            *entry = Some((now, v.clone()));
            v
        }
    }
}

pub(crate) struct EffectSlot {
    deps: RefCell<Option<Box<dyn Any>>>,
    running: RefCell<Option<Cancel>>,
}

impl EffectSlot {
    pub fn stop(&self) {
        if let Some(c) = self.running.borrow_mut().take() {
            c.cancel();
        }
    }
}

/// Run `f` after the render commits whenever `deps` change, like React's `useEffect`.
///
/// The previous run is dropped first; dropping is its cleanup. An `Err` goes to
/// the nearest `<Catch>`.
#[track_caller]
pub fn effect<D, F>(deps: D, f: F)
where
    D: Deps,
    F: AsyncFnOnce(&D::Owned) -> Result<()> + 'static,
{
    let (inst, _, cell) = slot("effect", || EffectSlot {
        deps: RefCell::new(None),
        running: RefCell::new(None),
    });
    let now = deps.to_deps();
    let same = cell
        .deps
        .borrow()
        .as_ref()
        .and_then(|d| d.downcast_ref::<D::Owned>())
        .is_some_and(|d| *d == now);
    if same {
        return;
    }
    *cell.deps.borrow_mut() = Some(Box::new(now.clone()));
    let owner = Rc::downgrade(&inst);
    inst.effects.borrow_mut().push(Box::new(move || {
        cell.stop();
        let task = runtime::spawn_cancellable(async move {
            if let Err(e) = f(&now).await {
                if let Some(inst) = owner.upgrade() {
                    runtime::throw(Some(&inst), e);
                }
            }
        });
        *cell.running.borrow_mut() = Some(task);
    }));
}

type Runner<A, T> = Rc<dyn Fn(A) -> futures_util::future::LocalBoxFuture<'static, Result<T>>>;

struct ActionCell<A, T> {
    run: RefCell<Runner<A, T>>,
    pending: Cell<bool>,
    error: RefCell<Option<Thrown>>,
    value: RefCell<Option<T>>,
}

/// An async operation started by an event, with its pending and error state.
/// `Copy`, like [`State`].
pub struct Action<A: 'static, T: 'static> {
    instance: u64,
    slot: usize,
    _t: PhantomData<fn(A) -> T>,
}

impl<A, T> Clone for Action<A, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<A, T> Copy for Action<A, T> {}

/// An operation to run from event handlers, like a form submit. While one is
/// running further `run`s are ignored, and the runtime, not the component,
/// owns it, so unmounting doesn't lose its effects.
#[track_caller]
pub fn action<A, T, F>(f: F) -> Action<A, T>
where
    A: 'static,
    T: 'static,
    F: AsyncFn(A) -> Result<T> + 'static,
{
    let f = Rc::new(f);
    let run: Runner<A, T> = Rc::new(move |a| {
        let f = f.clone();
        Box::pin(async move { f(a).await })
    });
    let (inst, slot, cell) = slot("action", || ActionCell::<A, T> {
        run: RefCell::new(run.clone()),
        pending: Cell::new(false),
        error: RefCell::new(None),
        value: RefCell::new(None),
    });
    // Each render's closure sees that render's captures.
    *cell.run.borrow_mut() = run;
    Action {
        instance: inst.id,
        slot,
        _t: PhantomData,
    }
}

impl<A: 'static, T: 'static> Action<A, T> {
    fn cell(&self) -> Option<Rc<ActionCell<A, T>>> {
        hook_value(self.instance, self.slot)
    }

    /// Start it, unless it is already running.
    pub fn run(&self, arg: A) {
        let Some(cell) = self.cell() else { return };
        if cell.pending.replace(true) {
            return;
        }
        cell.error.borrow_mut().take();
        self.rerender();
        let run = cell.run.borrow().clone();
        let fut = run(arg);
        let this = *self;
        doxa_client::task::spawn(async move {
            let out = fut.await;
            if let Some(cell) = this.cell() {
                cell.pending.set(false);
                match out {
                    Ok(v) => *cell.value.borrow_mut() = Some(v),
                    Err(e) => *cell.error.borrow_mut() = Some(e),
                }
                this.rerender();
            }
        });
    }

    fn rerender(&self) {
        if let Some(inst) = Instance::find(self.instance) {
            runtime::schedule(&inst);
        }
    }

    /// Whether it is running.
    pub fn pending(&self) -> bool {
        self.cell().is_some_and(|c| c.pending.get())
    }

    /// The last run's error, until it runs again.
    pub fn error(&self) -> Option<Thrown> {
        self.cell().and_then(|c| c.error.borrow().clone())
    }
}

impl<A: 'static, T: Clone + 'static> Action<A, T> {
    /// The last successful result.
    pub fn value(&self) -> Option<T> {
        self.cell().and_then(|c| c.value.borrow().clone())
    }
}

/// Make `value` available to every component below this one, like a React context provider.
pub fn provide<T: Clone + 'static>(value: T) {
    let inst = current_or_panic("provide");
    let mut contexts = inst.contexts.borrow_mut();
    contexts.retain(|(t, _)| *t != TypeId::of::<T>());
    contexts.push((TypeId::of::<T>(), Rc::new(value)));
}

/// The nearest `T` an ancestor provided.
#[track_caller]
pub fn context<T: Clone + 'static>() -> T {
    try_context().unwrap_or_else(|| {
        panic!(
            "no `{}` was provided above this component; call `provide(…)` in an ancestor or `App::provide`",
            std::any::type_name::<T>()
        )
    })
}

/// The nearest `T` an ancestor provided, if any.
pub fn try_context<T: Clone + 'static>() -> Option<T> {
    let inst = current_or_panic("context");
    std::iter::successors(Some(inst), |i| i.parent()).find_map(|i| {
        i.contexts
            .borrow()
            .iter()
            .find(|(t, _)| *t == TypeId::of::<T>())
            .and_then(|(_, v)| v.downcast_ref::<T>().cloned())
    })
}

/// App-wide state: one value per page, read and written from any component.
///
/// ```ignore
/// pub static CART: Singleton<Cart> = Singleton::new(Cart::default);
/// let items = CART.get().items;
/// CART.update(|c| c.items.push(item));
/// ```
///
/// Readers re-render when it changes. It resets when the session changes.
pub struct Singleton<T: 'static> {
    init: fn() -> T,
}

struct SingletonCell {
    value: Box<dyn Any>,
    readers: Readers,
}

type Cells = HashMap<usize, Rc<RefCell<SingletonCell>>>;

thread_local! {
    static SINGLETONS: RefCell<Cells> = RefCell::new(HashMap::new());
    static WATCHING_SESSION: Cell<bool> = const { Cell::new(false) };
}

fn reset_singletons() {
    let cells: Vec<_> = SINGLETONS.with(|s| s.borrow_mut().drain().map(|(_, c)| c).collect());
    for cell in cells {
        let readers = cell.borrow_mut().readers.live();
        runtime::schedule_all(readers);
    }
}

impl<T: 'static> Singleton<T> {
    /// A singleton built by `init` on first use.
    pub const fn new(init: fn() -> T) -> Self {
        Self { init }
    }

    // Each cell is its own `RefCell`, so `init` and `f` may use other singletons.
    fn cell(&'static self) -> Rc<RefCell<SingletonCell>> {
        if !WATCHING_SESSION.with(|w| w.replace(true)) {
            doxa_client::Client::current().on_session_change(reset_singletons);
        }
        let id = self as *const Self as usize;
        if let Some(c) = SINGLETONS.with(|s| s.borrow().get(&id).cloned()) {
            return c;
        }
        let cell = Rc::new(RefCell::new(SingletonCell {
            value: Box::new((self.init)()),
            readers: Readers::default(),
        }));
        SINGLETONS.with(|s| s.borrow_mut().entry(id).or_insert(cell).clone())
    }

    /// Read it without cloning, re-rendering this component when it changes.
    pub fn with<R>(&'static self, f: impl FnOnce(&T) -> R) -> R {
        let cell = self.cell();
        let mut c = cell.borrow_mut();
        c.readers.track();
        f(c.value.downcast_ref::<T>().expect("singleton type"))
    }

    /// Change it and re-render its readers.
    pub fn update(&'static self, f: impl FnOnce(&mut T)) {
        let cell = self.cell();
        let readers = {
            let mut c = cell.borrow_mut();
            f(c.value.downcast_mut::<T>().expect("singleton type"));
            c.readers.live()
        };
        runtime::schedule_all(readers);
    }

    /// Replace it.
    pub fn set(&'static self, value: T) {
        self.update(|v| *v = value);
    }
}

impl<T: Clone + 'static> Singleton<T> {
    /// A copy of the value.
    pub fn get(&'static self) -> T {
        self.with(T::clone)
    }
}

/// Mark the calling component as a `<Catch>` boundary; returns the error it caught.
pub(crate) fn catch_boundary() -> Option<Thrown> {
    let inst = current_or_panic("Catch");
    inst.catcher.set(true);
    let caught = inst.caught.borrow().clone();
    caught
}

/// Mark the calling component as a `<Suspense>` boundary; returns how many below it are loading.
pub(crate) fn suspense_boundary() -> usize {
    let inst = current_or_panic("Suspense");
    inst.suspense.set(true);
    inst.waiting.get()
}
