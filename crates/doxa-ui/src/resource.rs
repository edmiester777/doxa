//! `resource`: data a component fetches, with its loading, forbidden and failed states.

use std::time::Duration;

use doxa_client::Fetch;

use crate::hooks::{effect, reference, state, Deps, State};

/// What fetched data can be showing, with a 403 as its own state.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum Load<T> {
    /// Nothing yet.
    #[default]
    Loading,
    /// The data.
    Ready(T),
    /// The policy refused.
    Forbidden,
    /// The fetch failed, saying why.
    Failed(String),
}

impl<T> Load<T> {
    /// The state after a failed fetch. A refresh failing leaves what's on screen; a 403 never does.
    pub fn after_error(self, error: &impl LoadError) -> Load<T> {
        match self {
            _ if error.is_forbidden() => Load::Forbidden,
            Load::Ready(data) => Load::Ready(data),
            _ => Load::Failed(error.message()),
        }
    }

    /// The data, if it is here.
    pub fn ready(self) -> Option<T> {
        match self {
            Load::Ready(data) => Some(data),
            _ => None,
        }
    }

    /// Whether nothing has arrived yet.
    pub fn is_loading(&self) -> bool {
        matches!(self, Load::Loading)
    }
}

/// An error a [`resource`] fetch can fail with.
pub trait LoadError {
    /// Whether the policy refused, which a refresh mustn't hide.
    fn is_forbidden(&self) -> bool {
        false
    }
    /// What to tell the user.
    fn message(&self) -> String;
}

impl<E> LoadError for Fetch<E>
where
    Fetch<E>: std::fmt::Display,
{
    fn is_forbidden(&self) -> bool {
        matches!(self, Fetch::Forbidden(_))
    }

    fn message(&self) -> String {
        self.to_string()
    }
}

impl LoadError for String {
    fn message(&self) -> String {
        self.clone()
    }
}

impl LoadError for crate::Thrown {
    fn message(&self) -> String {
        self.to_string()
    }
}

/// Data a component fetched. `Copy`, like [`State`]: read it, or fetch it again.
pub struct Resource<T: 'static> {
    load: State<Load<T>>,
    again: State<u64>,
}

impl<T> Clone for Resource<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Resource<T> {}

impl<T: 'static> Resource<T> {
    /// Read its state without cloning.
    pub fn with<R>(&self, f: impl FnOnce(&Load<T>) -> R) -> R {
        self.load.with(f)
    }

    /// Fetch again, keeping what's on screen until the answer arrives.
    pub fn refetch(&self) {
        self.again.update(|n| *n += 1);
    }

    /// Fetch again, showing [`Load::Loading`] until the answer arrives.
    pub fn reload(&self) {
        self.load.set(Load::Loading);
        self.refetch();
    }

    /// Replace what it holds, e.g. with what a save answered.
    pub fn set(&self, data: T) {
        self.load.set(Load::Ready(data));
    }

    /// Change the data in place; nothing while there is none.
    pub fn update(&self, f: impl FnOnce(&mut T)) {
        self.load.update(|load| {
            if let Load::Ready(data) = load {
                f(data);
            }
        });
    }

    /// Whether nothing has arrived yet.
    pub fn is_loading(&self) -> bool {
        self.with(Load::is_loading)
    }
}

impl<T: Clone + 'static> Resource<T> {
    /// A copy of its state.
    pub fn get(&self) -> Load<T> {
        self.load.get()
    }

    /// A copy of the data, if it is here.
    pub fn data(&self) -> Option<T> {
        self.get().ready()
    }
}

/// Fetch with `fetch` now and whenever `deps` change. New deps show [`Load::Loading`]; a
/// [`refetch`](Resource::refetch) keeps the old data on screen.
#[track_caller]
pub fn resource<D, T, E, F>(deps: D, fetch: F) -> Resource<T>
where
    D: Deps,
    T: 'static,
    E: LoadError + 'static,
    F: AsyncFn(&D::Owned) -> Result<T, E> + 'static,
{
    run(deps, None, fetch)
}

/// [`resource`], fetching again every `every` while the component is mounted.
#[track_caller]
pub fn polled_resource<D, T, E, F>(deps: D, every: Duration, fetch: F) -> Resource<T>
where
    D: Deps,
    T: 'static,
    E: LoadError + 'static,
    F: AsyncFn(&D::Owned) -> Result<T, E> + 'static,
{
    run(deps, Some(every), fetch)
}

#[track_caller]
fn run<D, T, E, F>(deps: D, every: Option<Duration>, fetch: F) -> Resource<T>
where
    D: Deps,
    T: 'static,
    E: LoadError + 'static,
    F: AsyncFn(&D::Owned) -> Result<T, E> + 'static,
{
    let load = state(Load::Loading);
    let again = state(0u64);
    let fetched_for = reference(None::<D::Owned>);
    effect((deps, again), async move |(deps, _): &(D::Owned, u64)| {
        let same = fetched_for.with(|f| f.as_ref() == Some(deps));
        if same == Some(false) {
            if fetched_for.with(Option::is_some) == Some(true) {
                load.set(Load::Loading);
            }
            fetched_for.set(Some(deps.clone()));
        }
        loop {
            match fetch(deps).await {
                Ok(data) => load.set(Load::Ready(data)),
                Err(error) => load.update(|l| {
                    let was = std::mem::take(l);
                    *l = was.after_error(&error);
                }),
            }
            let Some(every) = every else { return };
            doxa_client::clock::sleep(every).await;
        }
    });
    Resource { load, again }
}
