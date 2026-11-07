//! `#[story]`: a view shown alone in `doxa gallery`, mounted as its own root.

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use crate::app::{App, RootHandle};
use crate::dom::{Dom, NodeId};
use crate::{IntoView, View};

/// What a story returns: a view, or a view and what must live as long as it, such as a
/// [`push_scoped`](doxa_client::layer) guard.
pub trait IntoStory {
    #[doc(hidden)]
    fn into_story(self) -> (View, Box<dyn Any>);
}

impl<V: IntoView> IntoStory for V {
    fn into_story(self) -> (View, Box<dyn Any>) {
        (self.into_view(), Box::new(()))
    }
}

impl<V: IntoView, K: 'static> IntoStory for (V, K) {
    fn into_story(self) -> (View, Box<dyn Any>) {
        (self.0.into_view(), Box::new(self.1))
    }
}

/// A mounted story; dropping it unmounts the story, then drops what it kept.
pub struct StoryRoot {
    root: Option<RootHandle>,
    _keep: Rc<RefCell<Option<Box<dyn Any>>>>,
}

impl Drop for StoryRoot {
    fn drop(&mut self) {
        self.root.take();
    }
}

impl StoryRoot {
    /// Mount `story` at `at`; tests pass a [`MemDom`](crate::dom::MemDom). The story runs on the
    /// root's every render, so a hot patch of its body shows.
    pub fn mount_on<S: IntoStory + 'static>(
        dom: Rc<dyn Dom>,
        at: NodeId,
        story: fn() -> S,
    ) -> Self {
        let keep = Rc::new(RefCell::new(None));
        let held = keep.clone();
        let root = App::embedded(move || {
            let (view, guard) = crate::hot::story(story).into_story();
            held.replace(Some(guard));
            view
        })
        .mount_on(dom, at);
        StoryRoot {
            root: Some(root),
            _keep: keep,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::dom::MemDom;

    thread_local! {
        static RUNS: Cell<u32> = const { Cell::new(0) };
        static GUARDS_DROPPED: Cell<u32> = const { Cell::new(0) };
    }

    struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            GUARDS_DROPPED.with(|d| d.set(d.get() + 1));
        }
    }

    fn counted() -> (View, Guard) {
        RUNS.with(|r| r.set(r.get() + 1));
        ("shown".into_view(), Guard)
    }

    #[test]
    fn a_rerender_reruns_the_story_and_replaces_what_it_kept() {
        let dom = Rc::new(MemDom::new());
        let at = dom.body();
        let root = StoryRoot::mount_on(dom.clone(), at, counted);
        crate::runtime::flush();
        assert_eq!(RUNS.with(Cell::get), 1);
        assert_eq!(GUARDS_DROPPED.with(Cell::get), 0);

        crate::runtime::rerender_all();
        crate::runtime::flush();
        assert_eq!(RUNS.with(Cell::get), 2);
        assert_eq!(GUARDS_DROPPED.with(Cell::get), 1);

        drop(root);
        assert_eq!(GUARDS_DROPPED.with(Cell::get), 2);
    }
}

#[cfg(target_arch = "wasm32")]
pub use web::*;

#[cfg(target_arch = "wasm32")]
mod web {
    use std::rc::Rc;

    use wasm_bindgen::prelude::*;

    use super::{IntoStory, StoryRoot};
    use crate::dom::WebDom;
    use crate::runtime;

    /// A story the gallery mounted; `free()` unmounts it.
    #[wasm_bindgen]
    pub struct StoryHandle(#[allow(dead_code)] StoryRoot);

    /// Mount `story` inside `host`.
    pub fn mount_story<S: IntoStory + 'static>(
        host: web_sys::Element,
        story: fn() -> S,
    ) -> Result<StoryHandle, JsError> {
        let dom = runtime::try_dom().unwrap_or_else(|| Rc::new(WebDom::new()));
        let at = dom
            .adopt(host.into())
            .ok_or_else(|| JsError::new("the host element isn't in this document"))?;
        Ok(StoryHandle(StoryRoot::mount_on(dom, at, story)))
    }
}
