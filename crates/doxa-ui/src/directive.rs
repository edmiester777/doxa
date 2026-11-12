//! `use:name={value}`: code a library attaches to an element's life, for what CSS can't do:
//! hold a leaving node, measure around a keyed move, see each render's value.

use std::any::{Any, TypeId};
use std::cell::RefCell;
use std::rc::Rc;

use futures_util::future::LocalBoxFuture;

use crate::dom::{NodeRef, Phase};

/// An element extension. `use:exit={"fade"}` calls `exit("fade")` and attaches what it returns.
///
/// ```
/// use doxa_ui::{Directive, NodeRef};
///
/// #[derive(Clone)]
/// struct Track(&'static str);
///
/// impl Directive for Track {
///     fn mounted(&mut self, node: NodeRef) {
///         let _ = (self.0, node);
///     }
/// }
/// ```
#[diagnostic::on_unimplemented(
    message = "`{Self}` isn't a `Directive`",
    note = "`use:name` calls the function `name` with its value; it must return a `doxa::ui::Directive`"
)]
pub trait Directive: Clone + 'static {
    /// The element was inserted, once its render committed.
    fn mounted(&mut self, _node: NodeRef) {}
    /// This render's value; the default replaces the old one.
    fn update(&mut self, next: Self) {
        *self = next;
    }
    /// The element was patched, once its render committed, after [`update`](Self::update).
    fn updated(&mut self, _node: NodeRef) {}
    /// A keyed reorder of the element's siblings is about to move nodes: measure now.
    fn before_move(&mut self, _node: NodeRef) {}
    /// The reorder has moved them.
    fn after_move(&mut self, _node: NodeRef) {}
    /// The element is being removed. A future keeps its node in the document until it
    /// resolves; only the outermost removed element is asked.
    fn leaving(&mut self, _node: NodeRef) -> Option<LocalBoxFuture<'static, ()>> {
        None
    }
    /// The element is unmounted; its components have stopped.
    fn unmounted(&mut self, _node: NodeRef) {}
}

/// A directive with its type erased, as a mounted element holds it.
pub(crate) trait AnyDirective {
    fn mounted(&mut self, node: NodeRef);
    fn replace(&mut self, next: Box<dyn Any>);
    fn updated(&mut self, node: NodeRef);
    fn before_move(&mut self, node: NodeRef);
    fn after_move(&mut self, node: NodeRef);
    fn leaving(&mut self, node: NodeRef) -> Option<LocalBoxFuture<'static, ()>>;
    fn unmounted(&mut self, node: NodeRef);
}

impl<D: Directive> AnyDirective for D {
    fn mounted(&mut self, node: NodeRef) {
        Directive::mounted(self, node)
    }
    fn replace(&mut self, next: Box<dyn Any>) {
        if let Ok(next) = next.downcast::<D>() {
            self.update(*next);
        }
    }
    fn updated(&mut self, node: NodeRef) {
        Directive::updated(self, node)
    }
    fn before_move(&mut self, node: NodeRef) {
        Directive::before_move(self, node)
    }
    fn after_move(&mut self, node: NodeRef) {
        Directive::after_move(self, node)
    }
    fn leaving(&mut self, node: NodeRef) -> Option<LocalBoxFuture<'static, ()>> {
        Directive::leaving(self, node)
    }
    fn unmounted(&mut self, node: NodeRef) {
        Directive::unmounted(self, node)
    }
}

/// A directive's value in a view, cloned into each element it mounts or patches.
pub(crate) trait Proto {
    fn kind(&self) -> TypeId;
    fn instance(&self) -> Box<dyn AnyDirective>;
    fn value(&self) -> Box<dyn Any>;
}

impl<D: Directive> Proto for D {
    fn kind(&self) -> TypeId {
        TypeId::of::<D>()
    }
    fn instance(&self) -> Box<dyn AnyDirective> {
        Box::new(self.clone())
    }
    fn value(&self) -> Box<dyn Any> {
        Box::new(self.clone())
    }
}

pub(crate) type Live = Rc<RefCell<Box<dyn AnyDirective>>>;

/// [`Element::lifecycle`](crate::Element::lifecycle), as a directive.
#[derive(Clone)]
pub(crate) struct Lifecycle(pub Rc<dyn Fn(Phase, NodeRef)>);

impl Directive for Lifecycle {
    fn mounted(&mut self, node: NodeRef) {
        (self.0)(Phase::Mounted, node)
    }
    fn updated(&mut self, node: NodeRef) {
        (self.0)(Phase::Patched, node)
    }
    fn unmounted(&mut self, node: NodeRef) {
        (self.0)(Phase::Unmounting, node)
    }
}
