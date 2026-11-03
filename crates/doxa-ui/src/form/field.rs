//! One field of a form, bindable with `bind:value`, `bind:checked` or `bind:selected`.

use std::marker::PhantomData;
use std::str::FromStr;

use super::{under, Form, Lens};
use crate::view::{BindChecked, BindSelected, BindValue};

/// One field of a [`Form`]: its value, whether it was touched, and its error. `Copy`.
pub struct Field<T: 'static, V: 'static> {
    form: Form<T>,
    lens: u32,
    _v: PhantomData<fn() -> V>,
}

impl<T, V> Clone for Field<T, V> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T, V> Copy for Field<T, V> {}

impl<T: 'static, V: 'static> Field<T, V> {
    pub(super) fn at(form: Form<T>, lens: u32) -> Self {
        Field {
            form,
            lens,
            _v: PhantomData,
        }
    }
}

impl<T, V> Field<T, V>
where
    T: Clone + PartialEq + 'static,
    V: Clone + PartialEq + 'static,
{
    /// The field at path `path`, for a type that can't `#[derive(Form)]`, such as one
    /// from a crate shared with the server: `Field::new(form, "name", |r| &r.name, |r| &mut r.name)`.
    pub fn new(
        form: Form<T>,
        path: &'static str,
        get: fn(&T) -> &V,
        get_mut: fn(&mut T) -> &mut V,
    ) -> Self {
        let lens = form.0.with(|s| {
            let root = s.lens::<T>(0);
            s.lenses
                .borrow_mut()
                .intern(format!(".{path}"), || root.field(path, get, get_mut))
        });
        Field::at(form, lens)
    }

    fn lens(&self) -> std::rc::Rc<Lens<T, V>> {
        self.form.0.with(|s| s.lens(self.lens))
    }

    /// Its path, as the rules name it: `name`, `steps[2].op`.
    pub fn path(&self) -> String {
        self.form.0.with(|s| s.path(self.lens)).unwrap_or_default()
    }

    /// Its value.
    ///
    /// Panics if it is a field of a list row that has been removed.
    pub fn get(&self) -> V {
        let lens = self.lens();
        self.form.0.with(|s| {
            (lens.get)(&s.value, &s.rows.borrow())
                .cloned()
                .expect("a field of a removed row")
        })
    }

    /// Change it, re-checking the rules and clearing the server's error for it.
    pub fn set(&self, value: V) {
        let (id, lens) = (self.lens, self.lens());
        let Some(path) = self.form.0.with(|s| s.path(id)) else {
            return;
        };
        self.form.0.update(|s| {
            let rows = s.rows.borrow();
            if let Some(at) = (lens.get_mut)(&mut s.value, &rows) {
                *at = value;
            }
            drop(rows);
            s.raw.retain(|(p, _)| *p != id);
            s.server.0.retain(|e| !under(&e.path, &path));
        });
    }

    /// Whether it differs from where it started.
    pub fn dirty(&self) -> bool {
        let lens = self.lens();
        self.form.0.with(|s| {
            let rows = s.rows.borrow();
            (lens.get)(&s.value, &rows) != (lens.get)(&s.initial, &rows)
        })
    }

    /// Whether the user has left it, or the form was submitted.
    pub fn touched(&self) -> bool {
        self.form
            .0
            .with(|s| s.submitted || s.touched.contains(&self.lens))
    }

    /// Mark it touched, as leaving it does.
    pub fn touch(&self) {
        let id = self.lens;
        if !self.form.0.with(|s| s.touched.contains(&id)) {
            self.form.0.update(|s| s.touched.push(id));
        }
    }

    /// Its first error, once [`touched`](Self::touched): unparseable text, a rule, or the server's.
    pub fn error(&self) -> Option<String> {
        if !self.touched() {
            return None;
        }
        self.form.0.with(|s| {
            if s.raw.iter().any(|(p, _)| *p == self.lens) {
                return Some("isn't a valid value".to_owned());
            }
            let path = s.path(self.lens)?;
            s.verdict()
                .0
                .iter()
                .chain(&s.server.0)
                .find(|e| under(&e.path, &path))
                .map(|e| e.message.clone())
        })
    }
}

impl<T, V> BindValue for Field<T, V>
where
    T: Clone + PartialEq + 'static,
    V: Clone + PartialEq + FromStr + ToString + 'static,
{
    fn current(&self) -> String {
        let raw = self.form.0.with(|s| {
            s.raw
                .iter()
                .find(|(p, _)| *p == self.lens)
                .map(|(_, t)| t.clone())
        });
        raw.unwrap_or_else(|| self.get().to_string())
    }

    fn input(&self, text: String) {
        match text.parse::<V>() {
            Ok(v) => self.set(v),
            // Keep what was typed, so the input doesn't snap back, and report it.
            Err(_) => {
                let id = self.lens;
                self.form.0.update(|s| {
                    s.raw.retain(|(p, _)| *p != id);
                    s.raw.push((id, text));
                })
            }
        }
    }

    fn blur(&self) {
        self.touch();
    }
}

impl<T> BindChecked for Field<T, bool>
where
    T: Clone + PartialEq + 'static,
{
    fn checked(&self) -> bool {
        self.get()
    }

    fn set_checked(&self, on: bool) {
        self.set(on);
        self.touch();
    }
}

impl<T> BindSelected for Field<T, Vec<String>>
where
    T: Clone + PartialEq + 'static,
{
    fn selected(&self) -> Vec<String> {
        self.get()
    }

    fn set_selected(&self, values: Vec<String>) {
        self.set(values);
        self.touch();
    }
}
