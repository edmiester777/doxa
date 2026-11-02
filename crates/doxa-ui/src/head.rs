//! `title(…)`: the document title, owned by the deepest mounted component that sets one.

use std::cell::RefCell;

use crate::browser::hold;
use crate::hooks::{effect, slot};
use crate::runtime;

struct Titles {
    next: u64,
    /// `(depth, id, title)`; the deepest, then the latest, wins.
    set: Vec<(usize, u64, String)>,
    /// The title before any component set one.
    original: Option<String>,
}

thread_local! {
    static TITLES: RefCell<Titles> = const { RefCell::new(Titles { next: 0, set: Vec::new(), original: None }) };
}

/// Set the document title while this component is mounted; unmounting restores the one below.
#[track_caller]
pub fn title(text: impl Into<String>) {
    let (inst, _, _) = slot("title", || ());
    let depth = inst.ancestors().count();
    effect(&text.into(), async move |text: &String| {
        let id = TITLES.with(|t| {
            let mut t = t.borrow_mut();
            if t.original.is_none() {
                t.original = Some(runtime::dom().title());
            }
            t.next += 1;
            let id = t.next;
            t.set.push((depth, id, text.clone()));
            id
        });
        apply();
        hold(Owned(id)).await
    });
}

struct Owned(u64);

impl Drop for Owned {
    fn drop(&mut self) {
        // `try_with`: this also runs as the thread's executor is torn down.
        if TITLES
            .try_with(|t| t.borrow_mut().set.retain(|(_, id, _)| *id != self.0))
            .is_ok()
        {
            apply();
        }
    }
}

fn apply() {
    let Some(dom) = runtime::try_dom() else {
        return;
    };
    let title = TITLES.with(|t| {
        let t = t.borrow();
        t.set
            .iter()
            .max_by_key(|(depth, id, _)| (*depth, *id))
            .map(|(.., s)| s.clone())
            .or_else(|| t.original.clone())
    });
    if let Some(title) = title {
        dom.set_title(&title);
    }
}
