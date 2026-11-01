//! `Cached<T>`: a response as the cache holds it, shared rather than copied.

use std::fmt;
use std::ops::Deref;
use std::rc::Rc;

/// A value read from the request cache. Clones share it; reads go through `Deref`.
///
/// ```
/// use doxa_client::Cached;
///
/// let a = Cached::new(String::from("cog"));
/// let b = a.clone();
/// assert!(Cached::ptr_eq(&a, &b));
/// assert_eq!(a.len(), 3);
/// ```
pub struct Cached<T>(Rc<T>);

impl<T> Cached<T> {
    /// Wrap a value that isn't in any cache.
    pub fn new(value: T) -> Self {
        Self(Rc::new(value))
    }

    /// Whether both are the same cached value, as for a memo dependency.
    pub fn ptr_eq(this: &Self, other: &Self) -> bool {
        Rc::ptr_eq(&this.0, &other.0)
    }

    /// The value itself, cloned unless this is the last reference.
    pub fn into_inner(this: Self) -> T
    where
        T: Clone,
    {
        Rc::unwrap_or_clone(this.0)
    }

    pub(crate) fn from_rc(rc: Rc<T>) -> Self {
        Self(rc)
    }

    pub(crate) fn rc(this: &Self) -> &Rc<T> {
        &this.0
    }
}

impl<T> Clone for Cached<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Deref for Cached<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> AsRef<T> for Cached<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T> std::borrow::Borrow<T> for Cached<T> {
    fn borrow(&self) -> &T {
        &self.0
    }
}

impl<T> From<T> for Cached<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T: fmt::Debug> fmt::Debug for Cached<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<T: fmt::Display> fmt::Display for Cached<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<T: PartialEq> PartialEq for Cached<T> {
    fn eq(&self, other: &Self) -> bool {
        *self.0 == *other.0
    }
}

impl<T: PartialEq> PartialEq<T> for Cached<T> {
    fn eq(&self, other: &T) -> bool {
        *self.0 == *other
    }
}

impl<T: Eq> Eq for Cached<T> {}

impl<T: std::hash::Hash> std::hash::Hash for Cached<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl<T: serde::Serialize> serde::Serialize for Cached<T> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'a, T> IntoIterator for &'a Cached<T>
where
    &'a T: IntoIterator,
{
    type Item = <&'a T as IntoIterator>::Item;
    type IntoIter = <&'a T as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        (&*self.0).into_iter()
    }
}
