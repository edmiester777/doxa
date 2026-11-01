//! The request cache: one entry per GET, shared by every caller, revalidated
//! in the background at most once per stale period, and cleared when the
//! session changes.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::{Rc, Weak};
use std::task::Waker;
use std::time::Duration;

use doxa_wire::{Identity, Keyed, RouteSpec};
use serde::Serialize;
use serde_json::Value;

use crate::arg::Arg;
use crate::client::Client;

/// Something that re-renders when a query it read changes.
pub trait Observer {
    /// A query this observer read has a new value, or went stale.
    fn changed(&self);
}

thread_local! {
    static OBSERVER: RefCell<Option<Rc<dyn Observer>>> = const { RefCell::new(None) };
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
    Client::current().cache.invalidate_where(|e| {
        e.route.entities.contains(&W::ENTITY_TYPE) && (e.key.is_none() || e.key == key)
    });
}

/// Mark stale every cached query about the asset `W`.
pub fn invalidate_all<W: Keyed>() {
    Client::current().cache.invalidate(&[W::ENTITY_TYPE]);
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
    Client::current()
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

/// How long data stays fresh, globally and per route.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    stale_time: Duration,
    gc_time: Duration,
    routes: Vec<(&'static RouteSpec, Duration)>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            stale_time: Duration::from_secs(30),
            gc_time: Duration::from_secs(300),
            routes: Vec::new(),
        }
    }
}

impl CacheConfig {
    /// How long a response is served without asking the server again. Default: 30 seconds.
    pub fn stale_time(mut self, d: Duration) -> Self {
        self.stale_time = d;
        self
    }

    /// How long an unread response is kept.
    pub fn gc_time(mut self, d: Duration) -> Self {
        self.gc_time = d;
        self
    }

    /// A different stale time for one route: `.route(&get_widget::ROUTE, …)`.
    pub fn route(mut self, route: &'static RouteSpec, stale_time: Duration) -> Self {
        self.routes.push((route, stale_time));
        self
    }

    fn stale_time_for(&self, route: &'static RouteSpec) -> Duration {
        self.routes
            .iter()
            .find(|(r, _)| std::ptr::eq(*r, route))
            .map_or(self.stale_time, |(_, d)| *d)
    }
}

pub(crate) struct Entry {
    value: Rc<dyn Any>,
    route: &'static RouteSpec,
    /// The guard key the call sent; `None` for a list.
    key: Option<Value>,
    at: f64,
    stale: bool,
    /// Renewed by every store and invalidation, unique across clears, so a
    /// revalidation that started before one is discarded.
    generation: u64,
    max_age: Option<Duration>,
    etag: Option<String>,
    digest: Option<u64>,
    observers: Vec<Weak<dyn Observer>>,
}

/// What a waiter on an in-flight request gets.
pub(crate) enum Outcome {
    Value(Rc<dyn Any>),
    Status(u16, Rc<[u8]>),
    Failed(crate::fetch::Fetch),
}

#[derive(Default)]
pub(crate) struct Slot {
    pub outcome: RefCell<Option<Rc<Outcome>>>,
    wakers: RefCell<Vec<Waker>>,
}

impl Slot {
    pub fn finish(&self, outcome: Outcome) {
        *self.outcome.borrow_mut() = Some(Rc::new(outcome));
        for w in self.wakers.borrow_mut().drain(..) {
            w.wake();
        }
    }

    pub async fn wait(self: Rc<Self>) -> Rc<Outcome> {
        std::future::poll_fn(|cx| match self.outcome.borrow().clone() {
            Some(o) => std::task::Poll::Ready(o),
            None => {
                self.wakers.borrow_mut().push(cx.waker().clone());
                std::task::Poll::Pending
            }
        })
        .await
    }
}

/// What a read found.
pub(crate) enum Lookup {
    Fresh(Rc<dyn Any>),
    /// Stale, and this caller now owns its one revalidation.
    Revalidate(Rc<dyn Any>, Revalidation),
    Pending(Rc<Slot>),
    Miss,
}

/// A claimed background revalidation of one entry.
pub(crate) struct Revalidation {
    pub etag: Option<String>,
    generation: u64,
}

/// How a revalidation ended.
pub(crate) enum Revalidated {
    Value(Rc<dyn Any>, Meta),
    NotModified(f64),
    Failed,
}

#[derive(Default)]
pub(crate) struct Cache {
    pub config: RefCell<CacheConfig>,
    entries: RefCell<HashMap<String, Entry>>,
    inflight: RefCell<HashMap<String, Rc<Slot>>>,
    /// Each claimed revalidation, by the generation it claimed.
    revalidating: RefCell<HashMap<String, u64>>,
    generations: Cell<u64>,
    requests: Cell<u64>,
}

impl Cache {
    /// Read `key`. A stale entry is stamped fresh as its revalidation is claimed,
    /// so it is asked for again only once the stale time passes once more.
    pub fn lookup(&self, key: &str, now: f64) -> Lookup {
        let observer = current_observer();
        let mut entries = self.entries.borrow_mut();
        if let Some(entry) = entries.get_mut(key) {
            observe(entry, observer.as_ref());
            if !self.is_stale(entry, now) || self.revalidating.borrow().contains_key(key) {
                return Lookup::Fresh(entry.value.clone());
            }
            self.revalidating
                .borrow_mut()
                .insert(key.to_owned(), entry.generation);
            entry.at = now;
            entry.stale = false;
            return Lookup::Revalidate(
                entry.value.clone(),
                Revalidation {
                    etag: entry.etag.clone(),
                    generation: entry.generation,
                },
            );
        }
        drop(entries);
        match self.inflight.borrow().get(key) {
            Some(slot) => Lookup::Pending(slot.clone()),
            None => Lookup::Miss,
        }
    }

    /// The value at `key` if it is fresh, without claiming a revalidation.
    pub fn fresh(&self, key: &str, now: f64) -> Option<Rc<dyn Any>> {
        let observer = current_observer();
        let mut entries = self.entries.borrow_mut();
        let entry = entries.get_mut(key)?;
        observe(entry, observer.as_ref());
        (!self.is_stale(entry, now)).then(|| entry.value.clone())
    }

    fn is_stale(&self, entry: &Entry, now: f64) -> bool {
        let fresh_for = entry
            .max_age
            .unwrap_or_else(|| self.config.borrow().stale_time_for(entry.route));
        entry.stale || now - entry.at >= fresh_for.as_secs_f64() * 1000.0
    }

    /// Record the current observer as a reader of `key` without reading it.
    pub fn watch(&self, key: &str) {
        let observer = current_observer();
        if let Some(e) = self.entries.borrow_mut().get_mut(key) {
            observe(e, observer.as_ref());
        }
    }

    pub fn count_request(&self) {
        self.requests.set(self.requests.get() + 1);
    }

    pub fn begin(&self, key: &str) -> Rc<Slot> {
        self.count_request();
        let slot = Rc::new(Slot::default());
        self.inflight
            .borrow_mut()
            .insert(key.to_owned(), slot.clone());
        slot
    }

    /// Retire `slot`, unless a clear already replaced it.
    pub fn end(&self, key: &str, slot: &Slot) {
        let mut inflight = self.inflight.borrow_mut();
        if inflight.get(key).is_some_and(|s| std::ptr::eq(&**s, slot)) {
            inflight.remove(key);
        }
    }

    fn next_generation(&self) -> u64 {
        let g = self.generations.get() + 1;
        self.generations.set(g);
        g
    }

    pub fn store(
        &self,
        key: String,
        route: &'static RouteSpec,
        route_key: Option<Value>,
        value: Rc<dyn Any>,
        meta: Meta,
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
            at: meta.now,
            stale: false,
            generation: self.next_generation(),
            max_age: meta.max_age,
            etag: meta.etag,
            digest: meta.digest,
            observers,
        };
        observe(&mut entry, observer.as_ref());
        entries.insert(key, entry);
        drop(entries);
        self.collect(meta.now);
    }

    /// Finish the revalidation `claim` of `key`, telling readers if the value changed.
    pub fn revalidated(&self, key: &str, claim: Revalidation, result: Revalidated) {
        {
            let mut revalidating = self.revalidating.borrow_mut();
            if revalidating.get(key) == Some(&claim.generation) {
                revalidating.remove(key);
            }
        }
        let observers = {
            let mut entries = self.entries.borrow_mut();
            let Some(e) = entries.get_mut(key) else {
                return;
            };
            if e.generation != claim.generation {
                // Invalidated meanwhile: what came back may predate the change.
                e.observers.clone()
            } else {
                match result {
                    Revalidated::Value(value, meta) => {
                        e.at = meta.now;
                        e.max_age = meta.max_age;
                        e.etag = meta.etag;
                        if e.digest.is_some() && e.digest == meta.digest {
                            return;
                        }
                        e.value = value;
                        e.digest = meta.digest;
                        e.observers.clone()
                    }
                    Revalidated::NotModified(now) => {
                        e.at = now;
                        return;
                    }
                    Revalidated::Failed => return,
                }
            }
        };
        notify(&observers);
    }

    /// Mark stale every query about any of `entities`, and tell their readers.
    pub fn invalidate(&self, entities: &[&str]) {
        self.invalidate_where(|e| e.route.entities.iter().any(|t| entities.contains(t)));
    }

    fn invalidate_where(&self, hit: impl Fn(&Entry) -> bool) {
        let observers: Vec<_> = {
            let mut entries = self.entries.borrow_mut();
            entries
                .values_mut()
                .filter(|e| hit(e))
                .flat_map(|e| {
                    e.stale = true;
                    e.generation = self.next_generation();
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
        self.inflight.borrow_mut().clear();
        self.revalidating.borrow_mut().clear();
        let observers: Vec<_> = self
            .entries
            .borrow_mut()
            .drain()
            .flat_map(|(_, e)| e.observers)
            .collect();
        notify(&observers);
    }

    /// Drop entries nobody has read for longer than the gc time.
    fn collect(&self, now: f64) {
        let gc = self.config.borrow().gc_time.as_secs_f64() * 1000.0;
        self.entries.borrow_mut().retain(|_, e| {
            e.observers.retain(|w| w.strong_count() > 0);
            !e.observers.is_empty() || now - e.at < gc
        });
    }

    /// Requests sent to the network, for tests and diagnostics.
    pub fn requests(&self) -> u64 {
        self.requests.get()
    }
}

pub(crate) struct Meta {
    pub now: f64,
    pub max_age: Option<Duration>,
    pub etag: Option<String>,
    /// A hash of the body, so an identical refetch doesn't re-render readers.
    pub digest: Option<u64>,
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

/// `max-age` from a `Cache-Control` header. `no-cache` is left to the stale time:
/// `ETagLayer` sends it for the browser's cache, which this one replaces.
pub(crate) fn max_age(cache_control: Option<&str>) -> Option<Duration> {
    let cc = cache_control?;
    if cc.contains("no-store") {
        return Some(Duration::ZERO);
    }
    cc.split(',')
        .find_map(|d| d.trim().strip_prefix("max-age="))
        .and_then(|s| s.parse().ok())
        .map(Duration::from_secs)
}
