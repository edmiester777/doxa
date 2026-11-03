//! `form(value)`: a value edited field by field and checked by the route's own rules, with a
//! server's `422` mapped onto the same fields.

mod field;
mod lens;
mod list;

use std::cell::{OnceCell, RefCell};
use std::marker::PhantomData;
use std::rc::Rc;

use doxa_client::FieldErrors;

use crate::hooks::{action, state, Action, State};
use crate::{Event, Result, Thrown};

pub use field::Field;
pub use lens::RowKey;
pub use list::FieldList;

use lens::{Lens, Lenses, Rows};

struct FormState<T> {
    value: T,
    initial: T,
    /// Text typed into a field that didn't parse, by lens.
    raw: Vec<(u32, String)>,
    touched: Vec<u32>,
    /// Set once, by [`Form::rules`].
    check: OnceCell<Rules<T>>,
    /// The server's last `422`, cleared field by field as they change.
    server: FieldErrors,
    submitted: bool,
    // Handed out while rendering, so kept behind cells that change nothing a render reads.
    lenses: RefCell<Lenses>,
    rows: RefCell<Rows>,
}

type Rules<T> = Rc<dyn Fn(&T) -> Result<(), FieldErrors>>;

impl<T: 'static> FormState<T> {
    /// What the rules say about the value now.
    fn verdict(&self) -> FieldErrors {
        match self.check.get() {
            Some(check) => check(&self.value).err().unwrap_or_default(),
            None => FieldErrors::default(),
        }
    }

    fn lens<V: 'static>(&self, id: u32) -> Rc<Lens<T, V>> {
        self.lenses.borrow().get(id)
    }

    /// The path of lens `id` as the rules name it, or `None` once its row is gone.
    fn path(&self, id: u32) -> Option<String> {
        let path = self.lenses.borrow().path(id);
        path(&self.rows.borrow())
    }
}

/// A form over a `T`; `Copy`, like [`State`].
pub struct Form<T: 'static>(State<FormState<T>>);

impl<T> Clone for Form<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Form<T> {}

/// What `#[derive(Form)]` implements: a struct of fields for any form that holds a `Self`.
pub trait FormFields: Sized + 'static {
    /// One [`Field`], nested fields or [`FieldList`] per struct field, in a form over `R`.
    type Fields<R: 'static>: Copy;
    #[doc(hidden)]
    fn project<R: 'static>(at: At<R, Self>) -> Self::Fields<R>;
}

/// Where a `S` sits in a form over `R`; what `#[derive(Form)]` builds its fields from.
#[doc(hidden)]
pub struct At<R: 'static, S: 'static> {
    form: Form<R>,
    lens: u32,
    _s: PhantomData<fn() -> S>,
}

impl<R, S> Clone for At<R, S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<R, S> Copy for At<R, S> {}

impl<R: 'static, S: 'static> At<R, S> {
    fn child<V: 'static>(
        self,
        name: &'static str,
        get: fn(&S) -> &V,
        get_mut: fn(&mut S) -> &mut V,
    ) -> u32 {
        self.form.0.with(|s| {
            let parent = s.lens::<S>(self.lens);
            let mut lenses = s.lenses.borrow_mut();
            let key = format!("{}.{name}", lenses.key(self.lens));
            lenses.intern(key, || parent.field(name, get, get_mut))
        })
    }

    /// The field `name`.
    pub fn field<V: 'static>(
        self,
        name: &'static str,
        get: fn(&S) -> &V,
        get_mut: fn(&mut S) -> &mut V,
    ) -> Field<R, V> {
        Field::at(self.form, self.child(name, get, get_mut))
    }

    /// The fields of `name`, a struct that derives `Form` too.
    pub fn nested<N: FormFields>(
        self,
        name: &'static str,
        get: fn(&S) -> &N,
        get_mut: fn(&mut S) -> &mut N,
    ) -> N::Fields<R> {
        N::project(At {
            form: self.form,
            lens: self.child(name, get, get_mut),
            _s: PhantomData,
        })
    }

    /// The rows of `name`, a list of structs that derive `Form`.
    pub fn list<E: FormFields>(
        self,
        name: &'static str,
        get: fn(&S) -> &Vec<E>,
        get_mut: fn(&mut S) -> &mut Vec<E>,
    ) -> FieldList<R, E> {
        FieldList::at(self.form, self.child(name, get, get_mut))
    }
}

/// A form starting at `initial`, like React's `useState`: used on the first render only.
#[track_caller]
pub fn form<T>(initial: T) -> Form<T>
where
    T: Clone + PartialEq + 'static,
{
    let mut lenses = Lenses::default();
    lenses.intern(String::new(), Lens::<T, T>::root);
    Form(state(FormState {
        value: initial.clone(),
        initial,
        raw: Vec::new(),
        touched: Vec::new(),
        check: OnceCell::new(),
        server: FieldErrors::default(),
        submitted: false,
        lenses: RefCell::new(lenses),
        rows: RefCell::new(Rows::default()),
    }))
}

/// Whether `path` is `field` or inside it, as `lines[0].sku` is inside `lines`.
fn under(path: &str, field: &str) -> bool {
    path.strip_prefix(field)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('.') || rest.starts_with('['))
}

impl<T> Form<T>
where
    T: Clone + PartialEq + 'static,
{
    /// Check each edit with `check`, such as a route's `create_order::check`. The first call wins.
    pub fn rules(self, check: impl Fn(&T) -> Result<(), FieldErrors> + 'static) -> Self {
        self.0.with(|s| {
            let _ = s.check.set(Rc::new(check));
        });
        self
    }

    /// The value as edited so far.
    pub fn value(&self) -> T {
        self.0.with(|s| s.value.clone())
    }

    /// Replace the whole value, as if every field were typed.
    pub fn set(&self, value: T) {
        self.0.update(|s| {
            s.value = value;
            s.raw.clear();
            s.server = FieldErrors::default();
        });
    }

    /// Whether the value differs from where it started.
    pub fn dirty(&self) -> bool {
        self.0.with(|s| s.value != s.initial)
    }

    /// Whether every rule passes and every field parsed.
    pub fn valid(&self) -> bool {
        self.0
            .with(|s| s.verdict().0.is_empty() && s.raw.is_empty() && s.server.0.is_empty())
    }

    /// Every current error: rules, then the server's.
    pub fn errors(&self) -> FieldErrors {
        self.0.with(|s| {
            let mut all = s.verdict();
            all.0.extend(s.server.0.iter().cloned());
            all
        })
    }

    /// Put a server's verdict on the fields it names.
    pub fn set_server_errors(&self, errors: FieldErrors) {
        self.0.update(|s| s.server = errors);
    }

    /// Show every field's errors, as a submit does; true if there are none.
    pub fn check(&self) -> bool {
        self.0.update(|s| s.submitted = true);
        self.valid()
    }

    /// Back to the initial value, with nothing touched.
    pub fn reset(&self) {
        self.0.update(|s| {
            s.value = s.initial.clone();
            s.raw.clear();
            s.touched.clear();
            s.server = FieldErrors::default();
            s.submitted = false;
        });
    }

    /// The fields `#[derive(Form)]` generates, each bindable with `bind:value`.
    pub fn fields(&self) -> T::Fields<T>
    where
        T: FormFields,
    {
        T::project(At {
            form: *self,
            lens: 0,
            _s: PhantomData,
        })
    }

    /// Submitting it: the rules run first, then `f`; a `422` from `f` lands on the fields.
    #[track_caller]
    pub fn submit<R, F>(&self, f: F) -> Submit<T, R>
    where
        R: 'static,
        F: AsyncFn(T) -> Result<R> + 'static,
    {
        let form = *self;
        let run = action(async move |v: T| match f(v).await {
            Ok(r) => Ok(r),
            Err(e) => {
                if let Some(fields) = field_errors(&e) {
                    form.set_server_errors(fields);
                }
                Err(e)
            }
        });
        Submit { form, run }
    }
}

/// The [`FieldErrors`] anywhere in `e`'s source chain, as a `Fetch::Invalid` carries them.
pub fn field_errors(e: &Thrown) -> Option<FieldErrors> {
    let mut at: Option<&(dyn std::error::Error + 'static)> = Some(e.inner());
    while let Some(err) = at {
        if let Some(f) = err.downcast_ref::<FieldErrors>() {
            return Some(f.clone());
        }
        at = err.source();
    }
    None
}

/// A form's submit, from [`Form::submit`].
pub struct Submit<T: 'static, R: 'static> {
    form: Form<T>,
    run: Action<T, R>,
}

impl<T, R> Clone for Submit<T, R> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T, R> Copy for Submit<T, R> {}

impl<T, R> Submit<T, R>
where
    T: Clone + PartialEq + 'static,
    R: 'static,
{
    /// Check the rules and, if they pass, send the value.
    pub fn run(&self) {
        if self.form.check() {
            self.run.run(self.form.value());
        }
    }

    /// For `on:submit`: stops the browser's own submit, then [`run`](Self::run)s.
    pub fn handler(&self) -> impl Fn(Event) + 'static {
        let this = *self;
        move |e: Event| {
            e.prevent_default();
            this.run();
        }
    }

    /// Whether it is being sent.
    pub fn pending(&self) -> bool {
        self.run.pending()
    }

    /// The last send's error, until it is sent again.
    pub fn error(&self) -> Option<Thrown> {
        self.run.error()
    }
}

impl<T: 'static, R: Clone + 'static> Submit<T, R> {
    /// What the last successful send returned.
    pub fn value(&self) -> Option<R> {
        self.run.value()
    }
}
