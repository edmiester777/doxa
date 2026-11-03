//! A list field whose rows are forms of their own, each keyed so a reorder keeps its DOM.

use std::marker::PhantomData;

use super::lens::RowKey;
use super::{under, At, Form, FormFields, FormState, Lens};

/// A `Vec` field of a [`Form`], from `#[form(list)]`: rows to bind, add, remove and reorder. `Copy`.
pub struct FieldList<T: 'static, E: 'static> {
    form: Form<T>,
    lens: u32,
    _e: PhantomData<fn() -> E>,
}

impl<T, E> Clone for FieldList<T, E> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T, E> Copy for FieldList<T, E> {}

impl<T: 'static, E: 'static> FieldList<T, E> {
    pub(super) fn at(form: Form<T>, lens: u32) -> Self {
        FieldList {
            form,
            lens,
            _e: PhantomData,
        }
    }
}

impl<T, E> FieldList<T, E>
where
    T: Clone + PartialEq + 'static,
    E: FormFields,
{
    fn lens(&self) -> std::rc::Rc<Lens<T, Vec<E>>> {
        self.form.0.with(|s| s.lens(self.lens))
    }

    fn len_in(&self, s: &FormState<T>) -> usize {
        let lens = self.lens();
        let rows = s.rows.borrow();
        (lens.get)(&s.value, &rows).map_or(0, Vec::len)
    }

    /// Each row's key and fields, in order. Key each row's view by its key.
    pub fn rows(&self) -> Vec<(RowKey, E::Fields<T>)> {
        let list = self.lens;
        let keys = self.form.0.with(|s| {
            let len = self.len_in(s);
            let mut rows = s.rows.borrow_mut();
            rows.sync(list, len);
            rows.keys(list).to_vec()
        });
        let lens = self.lens();
        keys.into_iter()
            .map(|key| {
                let row = self.form.0.with(|s| {
                    let mut lenses = s.lenses.borrow_mut();
                    let at = format!("{}#{key}", lenses.key(list));
                    lenses.intern(at, || lens.row(list, key))
                });
                let fields = E::project(At {
                    form: self.form,
                    lens: row,
                    _s: PhantomData,
                });
                (key, fields)
            })
            .collect()
    }

    /// How many rows there are.
    pub fn len(&self) -> usize {
        self.form.0.with(|s| self.len_in(s))
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Add `row` at the end.
    pub fn push(&self, row: E) {
        self.edit(|items, keys, fresh| {
            items.push(row);
            keys.push(fresh);
        });
    }

    /// Add `row` at `index`, or at the end if `index` is past it.
    pub fn insert(&self, index: usize, row: E) {
        self.edit(|items, keys, fresh| {
            let i = index.min(items.len());
            items.insert(i, row);
            keys.insert(i, fresh);
        });
    }

    /// Remove the row keyed `key`.
    pub fn remove(&self, key: RowKey) {
        self.edit(|items, keys, _| {
            if let Some(i) = keys.iter().position(|k| *k == key) {
                items.remove(i);
                keys.remove(i);
            }
        });
    }

    /// Move the row keyed `key` to `index`.
    pub fn move_to(&self, key: RowKey, index: usize) {
        self.edit(|items, keys, _| {
            if let Some(from) = keys.iter().position(|k| *k == key) {
                let to = index.min(items.len() - 1);
                let item = items.remove(from);
                items.insert(to, item);
                let k = keys.remove(from);
                keys.insert(to, k);
            }
        });
    }

    /// The list's own error, such as too few rows, once the form is submitted.
    pub fn error(&self) -> Option<String> {
        self.form.0.with(|s| {
            if !s.submitted {
                return None;
            }
            let path = s.path(self.lens)?;
            s.verdict()
                .0
                .iter()
                .chain(&s.server.0)
                .find(|e| e.path == path)
                .map(|e| e.message.clone())
        })
    }

    /// Change the rows and their keys together, then move the server's errors with their rows.
    fn edit(&self, f: impl FnOnce(&mut Vec<E>, &mut Vec<RowKey>, RowKey)) {
        let (list, lens) = (self.lens, self.lens());
        let len = self.len();
        let Some(path) = self.form.0.with(|s| s.path(list)) else {
            return;
        };
        self.form.0.update(|s| {
            let mut rows = s.rows.borrow_mut();
            rows.sync(list, len);
            let before = rows.keys(list).to_vec();
            let fresh = rows.fresh();
            let mut keys = before.clone();
            // The rows' own lenses read `rows`, so the list is reached with the keys as they were.
            if let Some(items) = (lens.get_mut)(&mut s.value, &rows) {
                f(items, &mut keys, fresh);
            }
            *rows.keys_mut(list) = keys.clone();
            drop(rows);
            remap(&mut s.server, &path, &before, &keys);
        });
    }
}

/// Rewrite `{list}[i]…` in `errors` from the row's old index to its new one, dropping removed rows'.
fn remap(errors: &mut doxa_client::FieldErrors, list: &str, before: &[RowKey], after: &[RowKey]) {
    errors.0.retain_mut(|e| {
        if !under(&e.path, list) {
            return true;
        }
        let rest = &e.path[list.len()..];
        let Some(close) = rest.strip_prefix('[').and_then(|r| r.find(']')) else {
            return true;
        };
        let Ok(old) = rest[1..=close].parse::<usize>() else {
            return true;
        };
        let Some(new) = before
            .get(old)
            .and_then(|k| after.iter().position(|a| a == k))
        else {
            return false;
        };
        e.path = format!("{list}[{new}]{}", &rest[close + 2..]);
        true
    });
}
