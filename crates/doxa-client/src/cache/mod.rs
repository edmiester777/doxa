//! Responses kept by calls that opt in with [`Call::cache`](crate::Call::cache), and by GETs
//! awaited in a render for that component's next render, until they expire, a mutation
//! invalidates them, or the session changes.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::panic::Location;
use std::rc::{Rc, Weak};
use std::task::{Poll, Waker};
use std::time::Duration;

use doxa_wire::{Identity, Keyed, RouteSpec};
use serde::Serialize;
use serde_json::Value;

use crate::arg::Arg;
use crate::service::service;

/// Something that re-renders when a cached value it read changes.
pub trait Observer {
    /// A value this observer read was replaced, patched or invalidated.
    fn changed(&self);

    /// The render's next hook slot for a call made at `at`, as a key unique to it;
    /// `None` when the observer isn't rendering.
    fn slot(&self, _at: &'static Location<'static>) -> Option<String> {
        None
    }
}

/// The slot a GET awaited now, during a render, keeps its answer in.
pub(crate) fn render_slot(at: &'static Location<'static>) -> Option<String> {
    current_observer()?.slot(at)
}

thread_local! {
    static OBSERVER: RefCell<Option<Rc<dyn Observer>>> = const { RefCell::new(None) };
    static ANSWERED: RefCell<HashMap<usize, &'static str>> = RefCell::new(HashMap::new());
    static REPORTED: RefCell<Vec<Reported>> = const { RefCell::new(Vec::new()) };
}

type Reported = Rc<dyn Fn(&[&str])>;

/// Run `f` with the entity types each mutation, or [`invalidate`], marks stale; for a host
/// keeping its own cache.
pub fn on_invalidated(f: impl Fn(&[&str]) + 'static) {
    REPORTED.with(|r| r.borrow_mut().push(Rc::new(f)));
}

pub(crate) fn report(entities: &[&str]) {
    let mut unique: Vec<&str> = Vec::new();
    for e in entities {
        if !unique.contains(e) {
            unique.push(e);
        }
    }
    if unique.is_empty() {
        return;
    }
    let all: Vec<_> = REPORTED.with(|r| r.borrow().clone());
    all.iter().for_each(|f| f(&unique));
}

/// Mark stale every cached query, in every service, about any of `entities`; for a host's own
/// mutations, so it isn't reported back to [`on_invalidated`].
pub fn invalidate_entities(entities: &[&str]) {
    crate::service::each(|s| s.cache.invalidate(entities));
}

/// Record that `route` answers `entity`, which a stub finds only at run time.
pub(crate) fn answers(route: &'static RouteSpec, entity: &'static str) {
    ANSWERED.with(|a| {
        a.borrow_mut()
            .insert(route as *const RouteSpec as usize, entity)
    });
}

/// Every entity `route` is about: its guards, `touches`, and the entity it answers.
pub(crate) fn about(route: &'static RouteSpec) -> Vec<&'static str> {
    let mut out = route.entities.to_vec();
    let answered = ANSWERED.with(|a| {
        a.borrow()
            .get(&(route as *const RouteSpec as usize))
            .copied()
    });
    out.extend(answered.filter(|e| !out.contains(e)));
    out
}

/// Make `observer` the one subsequent reads are recorded against; returns the previous one.
pub fn set_observer(observer: Option<Rc<dyn Observer>>) -> Option<Rc<dyn Observer>> {
    OBSERVER.with(|o| o.replace(observer))
}

fn current_observer() -> Option<Rc<dyn Observer>> {
    OBSERVER.with(|o| o.borrow().clone())
}

/// Mark stale every cached query about the asset `W` with this key, and every list of them.
///
/// ```ignore
/// cache::invalidate::<WidgetByName>("cog");
/// ```
pub fn invalidate<W: Keyed>(key: impl Arg<W::Key>)
where
    W::Key: Serialize,
{
    let key = doxa_wire::key_value(&key.into_arg());
    service(W::PACKAGE).cache.invalidate_where(|e| {
        about(e.route).contains(&W::ENTITY_TYPE) && (e.key.is_none() || e.key == key)
    });
    report(&[W::ENTITY_TYPE]);
}

/// Mark stale every cached query about the asset `W`.
pub fn invalidate_all<W: Keyed>() {
    service(W::PACKAGE).cache.invalidate(&[W::ENTITY_TYPE]);
    report(&[W::ENTITY_TYPE]);
}

/// Patch every cached `T` whose route key is `key`, in instances and lists, and
/// re-render whoever read one. For a live update, e.g. from an SSE event.
///
/// ```ignore
/// cache::apply::<Widget>(&key, |w| w.name = name.clone());
/// ```
pub fn apply<T: Identity + Clone + 'static>(key: &impl Serialize, f: impl Fn(&mut T)) {
    let Some(key) = doxa_wire::key_value(key) else {
        return;
    };
    service(T::PACKAGE)
        .cache
        .patch(|value| map_items::<T>(value, |t| t.route_key().as_ref() == Some(&key), &f));
}

/// Apply `f` to every `T` in a cached `T`, `Vec<T>` or `Option<T>` that `hit` matches.
pub(crate) fn map_items<T: Clone + 'static>(
    value: &Rc<dyn Any>,
    hit: impl Fn(&T) -> bool,
    f: &dyn Fn(&mut T),
) -> Option<Rc<dyn Any>> {
    if let Some(t) = value.downcast_ref::<T>() {
        return hit(t).then(|| {
            let mut t = t.clone();
            f(&mut t);
            Rc::new(t) as Rc<dyn Any>
        });
    }
    if let Some(items) = value.downcast_ref::<Vec<T>>() {
        if !items.iter().any(&hit) {
            return None;
        }
        let mut items = items.clone();
        items.iter_mut().filter(|t| hit(t)).for_each(f);
        return Some(Rc::new(items));
    }
    if let Some(Some(t)) = value.downcast_ref::<Option<T>>() {
        return hit(t).then(|| {
            let mut t = t.clone();
            f(&mut t);
            Rc::new(Some(t)) as Rc<dyn Any>
        });
    }
    None
}

pub(crate) struct Entry {
    value: Rc<dyn Any>,
    route: &'static RouteSpec,
    /// The guard key the call sent; `None` for a list.
    key: Option<Value>,
    /// Milliseconds, from [`now`](crate::service::now).
    at: f64,
    ttl: Duration,
    stale: bool,
    observers: Vec<Weak<dyn Observer>>,
    /// A render slot's entry, which answers only this URL and lives while its component does.
    slot_url: Option<String>,
}

impl Entry {
    fn expired(&self, now: f64) -> bool {
        self.stale || now - self.at >= self.ttl.as_secs_f64() * 1000.0
    }
}

/// A render slot's request in flight, outliving the render that sent it.
#[derive(Default)]
pub(crate) struct Pending {
    outcome: RefCell<Option<Box<dyn Any>>>,
    done: Cell<bool>,
    wakers: RefCell<Vec<Waker>>,
}

impl Pending {
    pub fn finish(&self, outcome: Box<dyn Any>) {
        *self.outcome.borrow_mut() = Some(outcome);
        self.done.set(true);
        self.wakers.borrow_mut().drain(..).for_each(Waker::wake);
    }

    /// Resolves once the request has finished, leaving its outcome.
    pub async fn settled(&self) {
        std::future::poll_fn(|cx| {
            if self.done.get() {
                return Poll::Ready(());
            }
            self.wakers.borrow_mut().push(cx.waker().clone());
            Poll::Pending
        })
        .await
    }

    /// The outcome, for the first render to ask once it lands; `None` if another took it.
    pub async fn take(&self) -> Option<Box<dyn Any>> {
        std::future::poll_fn(|cx| {
            if self.done.get() {
                return Poll::Ready(self.outcome.borrow_mut().take());
            }
            self.wakers.borrow_mut().push(cx.waker().clone());
            Poll::Pending
        })
        .await
    }
}

#[derive(Default)]
pub(crate) struct Cache {
    entries: RefCell<HashMap<String, Entry>>,
    pending: RefCell<HashMap<String, (String, Rc<Pending>)>>,
    requests: Cell<u64>,
}

impl Cache {
    /// The request slot `slot` has in flight for `url`, or a new one for the caller to send.
    pub fn pending(&self, slot: &str, url: &str) -> (Rc<Pending>, bool) {
        let mut pending = self.pending.borrow_mut();
        if let Some((u, p)) = pending.get(slot) {
            if u == url {
                return (p.clone(), false);
            }
        }
        let p = Rc::new(Pending::default());
        pending.insert(slot.to_owned(), (url.to_owned(), p.clone()));
        (p, true)
    }

    /// Retire `p`, unless a newer request for the slot replaced it.
    pub fn end_pending(&self, slot: &str, p: &Rc<Pending>) {
        let mut pending = self.pending.borrow_mut();
        if pending.get(slot).is_some_and(|(_, q)| Rc::ptr_eq(p, q)) {
            pending.remove(slot);
        }
    }

    /// The value at `key` while it is fresh, recording the current observer as its reader.
    pub fn get(&self, key: &str, now: f64) -> Option<Rc<dyn Any>> {
        let observer = current_observer();
        let mut entries = self.entries.borrow_mut();
        let entry = entries.get_mut(key)?;
        observe(entry, observer.as_ref());
        (!entry.expired(now) && entry.slot_url.is_none()).then(|| entry.value.clone())
    }

    /// What render slot `slot` last kept for `url`, unless an invalidation dropped it.
    pub fn get_slot(&self, slot: &str, url: &str) -> Option<Rc<dyn Any>> {
        let observer = current_observer();
        let mut entries = self.entries.borrow_mut();
        let entry = entries.get_mut(slot)?;
        observe(entry, observer.as_ref());
        (!entry.stale && entry.slot_url.as_deref() == Some(url)).then(|| entry.value.clone())
    }

    pub fn store_slot(
        &self,
        slot: String,
        route: &'static RouteSpec,
        route_key: Option<Value>,
        value: Rc<dyn Any>,
        url: String,
    ) {
        let now = crate::service::now();
        self.insert(slot, route, route_key, value, Duration::MAX, now, Some(url));
    }

    pub fn count_request(&self) {
        self.requests.set(self.requests.get() + 1);
    }

    pub fn store(
        &self,
        key: String,
        route: &'static RouteSpec,
        route_key: Option<Value>,
        value: Rc<dyn Any>,
        ttl: Duration,
        now: f64,
    ) {
        self.insert(key, route, route_key, value, ttl, now, None);
    }

    #[allow(clippy::too_many_arguments)]
    fn insert(
        &self,
        key: String,
        route: &'static RouteSpec,
        route_key: Option<Value>,
        value: Rc<dyn Any>,
        ttl: Duration,
        now: f64,
        slot_url: Option<String>,
    ) {
        let observer = current_observer();
        let mut entries = self.entries.borrow_mut();
        let observers = entries
            .remove(&key)
            .map(|e| e.observers)
            .unwrap_or_default();
        let mut entry = Entry {
            value,
            route,
            key: route_key,
            at: now,
            ttl,
            stale: false,
            observers,
            slot_url,
        };
        observe(&mut entry, observer.as_ref());
        entries.insert(key, entry);
        drop(entries);
        self.collect(now);
    }

    /// Mark stale every query about any of `entities`, and tell their readers.
    pub fn invalidate(&self, entities: &[&str]) {
        self.invalidate_where(|e| about(e.route).iter().any(|t| entities.contains(t)));
    }

    fn invalidate_where(&self, hit: impl Fn(&Entry) -> bool) {
        let observers: Vec<_> = {
            let mut entries = self.entries.borrow_mut();
            entries
                .values_mut()
                .filter(|e| hit(e))
                .flat_map(|e| {
                    e.stale = true;
                    e.observers.clone()
                })
                .collect()
        };
        notify(&observers);
    }

    /// Run `f` over every cached value, telling readers of the ones it changed.
    pub fn patch(
        &self,
        mut f: impl FnMut(&Rc<dyn Any>) -> Option<Rc<dyn Any>>,
    ) -> Vec<(String, Rc<dyn Any>)> {
        let mut previous = Vec::new();
        let observers: Vec<_> = {
            let mut entries = self.entries.borrow_mut();
            entries
                .iter_mut()
                .filter_map(|(k, e)| {
                    let next = f(&e.value)?;
                    previous.push((k.clone(), std::mem::replace(&mut e.value, next)));
                    Some(e.observers.clone())
                })
                .flatten()
                .collect()
        };
        notify(&observers);
        previous
    }

    pub fn restore(&self, previous: Vec<(String, Rc<dyn Any>)>) {
        let observers: Vec<_> = {
            let mut entries = self.entries.borrow_mut();
            previous
                .into_iter()
                .filter_map(|(k, v)| {
                    let e = entries.get_mut(&k)?;
                    e.value = v;
                    Some(e.observers.clone())
                })
                .flatten()
                .collect()
        };
        notify(&observers);
    }

    /// Forget everything, e.g. on a new session.
    pub fn clear(&self) {
        self.pending.borrow_mut().clear();
        let observers: Vec<_> = self
            .entries
            .borrow_mut()
            .drain()
            .flat_map(|(_, e)| e.observers)
            .collect();
        notify(&observers);
    }

    /// Drop expired entries nobody mounted still reads, and slots whose component is gone;
    /// a reader keeps its entry so an invalidation still reaches it.
    fn collect(&self, now: f64) {
        self.entries.borrow_mut().retain(|_, e| {
            e.observers.retain(|w| w.strong_count() > 0);
            !e.observers.is_empty() || (e.slot_url.is_none() && !e.expired(now))
        });
    }

    /// Requests sent to the network, for tests and diagnostics.
    pub fn requests(&self) -> u64 {
        self.requests.get()
    }
}

fn observe(entry: &mut Entry, observer: Option<&Rc<dyn Observer>>) {
    if let Some(o) = observer {
        if !entry.observers.iter().any(|w| ptr_eq(w, o)) {
            entry.observers.push(Rc::downgrade(o));
        }
    }
}

fn ptr_eq(w: &Weak<dyn Observer>, o: &Rc<dyn Observer>) -> bool {
    std::ptr::addr_eq(w.as_ptr(), Rc::as_ptr(o))
}

fn notify(observers: &[Weak<dyn Observer>]) {
    let mut seen: Vec<*const dyn Observer> = Vec::new();
    for o in observers.iter().filter_map(Weak::upgrade) {
        let p = Rc::as_ptr(&o);
        if !seen.iter().any(|s| std::ptr::addr_eq(*s, p)) {
            seen.push(p);
            o.changed();
        }
    }
}
