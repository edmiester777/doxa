//! Answering an instance route from any cached value holding that instance.
//! A route's stub picks [`Entity`] for its response type, when it has an
//! `#[identity(key = …)]`, by autoref: no bound reaches generic code.

use std::any::Any;
use std::marker::PhantomData;
use std::rc::Rc;

use doxa_wire::Identity;
use serde_json::Value;

use crate::cached::Cached;
use crate::response::FromResponse;

/// How the cache finds a route's `T` in other cached values, and files one.
#[derive(Clone, Copy)]
pub struct Entity {
    pub(crate) find: fn(&Rc<dyn Any>, &Value) -> Option<Rc<dyn Any>>,
    pub(crate) key: fn(&Rc<dyn Any>) -> Option<Value>,
}

fn find<T: Identity + Clone + 'static>(value: &Rc<dyn Any>, key: &Value) -> Option<Rc<dyn Any>> {
    let hit = |t: &T| t.route_key().as_ref() == Some(key);
    if let Some(t) = value.downcast_ref::<T>() {
        return hit(t).then(|| value.clone());
    }
    let t = match (
        value.downcast_ref::<Vec<T>>(),
        value.downcast_ref::<Option<T>>(),
    ) {
        (Some(items), _) => items.iter().find(|t| hit(t))?,
        (_, Some(Some(t))) if hit(t) => t,
        _ => return None,
    };
    Some(Rc::new(t.clone()))
}

fn key<T: Identity + 'static>(value: &Rc<dyn Any>) -> Option<Value> {
    value.downcast_ref::<T>()?.route_key()
}

/// A response output the cache can file by identity.
pub trait CachedEntity {
    /// Its lookups.
    const ENTITY: Entity;
}

impl<T: Identity + Clone + 'static> CachedEntity for Cached<T> {
    const ENTITY: Entity = Entity {
        find: find::<T>,
        key: key::<T>,
    };
}

/// `(&EntityOf::<R>::new()).entity()` is `Some` when `R`'s output has an identity.
pub struct EntityOf<R>(PhantomData<fn() -> R>);

impl<R> EntityOf<R> {
    /// The probe.
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<R> Default for EntityOf<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R> Clone for EntityOf<R> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<R> Copy for EntityOf<R> {}

/// Chosen when the output has an identity.
pub trait IsEntity {
    /// Its lookups.
    fn entity(self) -> Option<Entity>;
}

impl<R: FromResponse> IsEntity for &EntityOf<R>
where
    R::Output: CachedEntity,
{
    fn entity(self) -> Option<Entity> {
        Some(<R::Output as CachedEntity>::ENTITY)
    }
}

/// The fallback, reached only through a deref: no identity, so nothing to look up.
pub trait NotEntity: Sized {
    /// Nothing.
    fn entity(self) -> Option<Entity> {
        None
    }
}

impl<R> NotEntity for EntityOf<R> {}
