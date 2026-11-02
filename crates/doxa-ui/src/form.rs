//! `form(value)`: a value edited field by field and checked by its garde rules, with a
//! server's `422` mapped onto the same fields.

use std::str::FromStr;

use doxa_client::{FieldError, FieldErrors};

use crate::hooks::{action, state, Action, State};
use crate::view::{BindChecked, BindSelected, BindValue};
use crate::{Event, Result, Thrown};

struct FormState<T> {
    value: T,
    initial: T,
    /// Text typed into a field that didn't parse, by path.
    raw: Vec<(&'static str, String)>,
    touched: Vec<&'static str>,
    /// The garde rules' verdict on `value`.
    rules: FieldErrors,
    /// The server's last `422`, cleared field by field as they change.
    server: FieldErrors,
    submitted: bool,
}

/// A form over a `T`; `Copy`, like [`State`].
pub struct Form<T: 'static>(State<FormState<T>>);

impl<T> Clone for Form<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Form<T> {}

/// What `#[derive(Form)]` implements: one [`Field`] per struct field.
pub trait FormFields: Sized + 'static {
    /// The struct of fields.
    type Fields;
    #[doc(hidden)]
    fn fields(form: Form<Self>) -> Self::Fields;
}

fn rules<T: garde::Validate>(v: &T) -> FieldErrors
where
    T::Context: Default,
{
    match v.validate() {
        Ok(()) => FieldErrors::default(),
        Err(report) => FieldErrors(
            report
                .iter()
                .map(|(path, e)| FieldError {
                    path: path.to_string(),
                    message: e.message().to_owned(),
                })
                .collect(),
        ),
    }
}

/// A form starting at `initial`, like React's `useState`: used on the first render only.
#[track_caller]
pub fn form<T>(initial: T) -> Form<T>
where
    T: Clone + PartialEq + garde::Validate + 'static,
    T::Context: Default,
{
    let checked = rules(&initial);
    Form(state(FormState {
        value: initial.clone(),
        initial,
        raw: Vec::new(),
        touched: Vec::new(),
        rules: checked,
        server: FieldErrors::default(),
        submitted: false,
    }))
}

/// Whether `path` is `field` or inside it, as `lines[0].sku` is inside `lines`.
fn under(path: &str, field: &str) -> bool {
    path.strip_prefix(field)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('.') || rest.starts_with('['))
}

impl<T> Form<T>
where
    T: Clone + PartialEq + garde::Validate + 'static,
    T::Context: Default,
{
    /// The value as edited so far.
    pub fn value(&self) -> T {
        self.0.with(|s| s.value.clone())
    }

    /// Replace the whole value, as if every field were typed.
    pub fn set(&self, value: T) {
        self.0.update(|s| {
            s.rules = rules(&value);
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
            .with(|s| s.rules.0.is_empty() && s.raw.is_empty() && s.server.0.is_empty())
    }

    /// Every current error: rules, then the server's.
    pub fn errors(&self) -> FieldErrors {
        self.0.with(|s| {
            let mut all = s.rules.clone();
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
            s.rules = rules(&s.value);
            s.raw.clear();
            s.touched.clear();
            s.server = FieldErrors::default();
            s.submitted = false;
        });
    }

    /// The fields `#[derive(Form)]` generates, each bindable with `bind:value`.
    pub fn fields(&self) -> T::Fields
    where
        T: FormFields,
    {
        T::fields(*self)
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
    T: Clone + PartialEq + garde::Validate + 'static,
    T::Context: Default,
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

/// One field of a [`Form`]: its value, whether it was touched, and its error. `Copy`.
pub struct Field<T: 'static, V: 'static> {
    form: Form<T>,
    path: &'static str,
    get: fn(&T) -> &V,
    get_mut: fn(&mut T) -> &mut V,
}

impl<T, V> Clone for Field<T, V> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T, V> Copy for Field<T, V> {}

impl<T, V> Field<T, V>
where
    T: Clone + PartialEq + garde::Validate + 'static,
    T::Context: Default,
    V: Clone + PartialEq + 'static,
{
    /// The field at garde path `path`, for a type that can't `#[derive(Form)]`, such as one
    /// from a crate shared with the server: `Field::new(form, "name", |r| &r.name, |r| &mut r.name)`.
    pub fn new(
        form: Form<T>,
        path: &'static str,
        get: fn(&T) -> &V,
        get_mut: fn(&mut T) -> &mut V,
    ) -> Self {
        Field {
            form,
            path,
            get,
            get_mut,
        }
    }

    /// Its garde path.
    pub fn path(&self) -> &'static str {
        self.path
    }

    /// Its value.
    pub fn get(&self) -> V {
        self.form.0.with(|s| (self.get)(&s.value).clone())
    }

    /// Change it, re-checking the rules and clearing the server's error for it.
    pub fn set(&self, value: V) {
        let (path, get_mut) = (self.path, self.get_mut);
        self.form.0.update(|s| {
            *get_mut(&mut s.value) = value;
            s.raw.retain(|(p, _)| *p != path);
            s.server.0.retain(|e| !under(&e.path, path));
            s.rules = rules(&s.value);
        });
    }

    /// Whether it differs from where it started.
    pub fn dirty(&self) -> bool {
        self.form
            .0
            .with(|s| (self.get)(&s.value) != (self.get)(&s.initial))
    }

    /// Whether the user has left it, or the form was submitted.
    pub fn touched(&self) -> bool {
        self.form
            .0
            .with(|s| s.submitted || s.touched.contains(&self.path))
    }

    /// Mark it touched, as leaving it does.
    pub fn touch(&self) {
        let path = self.path;
        if !self.form.0.with(|s| s.touched.contains(&path)) {
            self.form.0.update(|s| s.touched.push(path));
        }
    }

    /// Its first error, once [`touched`](Self::touched): unparseable text, a rule, or the server's.
    pub fn error(&self) -> Option<String> {
        if !self.touched() {
            return None;
        }
        self.form.0.with(|s| {
            if s.raw.iter().any(|(p, _)| *p == self.path) {
                return Some("isn't a valid value".to_owned());
            }
            s.rules
                .0
                .iter()
                .chain(&s.server.0)
                .find(|e| under(&e.path, self.path))
                .map(|e| e.message.clone())
        })
    }
}

impl<T, V> BindValue for Field<T, V>
where
    T: Clone + PartialEq + garde::Validate + 'static,
    T::Context: Default,
    V: Clone + PartialEq + FromStr + ToString + 'static,
{
    fn current(&self) -> String {
        let raw = self.form.0.with(|s| {
            s.raw
                .iter()
                .find(|(p, _)| *p == self.path)
                .map(|(_, t)| t.clone())
        });
        raw.unwrap_or_else(|| self.get().to_string())
    }

    fn input(&self, text: String) {
        match text.parse::<V>() {
            Ok(v) => self.set(v),
            // Keep what was typed, so the input doesn't snap back, and report it.
            Err(_) => {
                let path = self.path;
                self.form.0.update(|s| {
                    s.raw.retain(|(p, _)| *p != path);
                    s.raw.push((path, text));
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
    T: Clone + PartialEq + garde::Validate + 'static,
    T::Context: Default,
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
    T: Clone + PartialEq + garde::Validate + 'static,
    T::Context: Default,
{
    fn selected(&self) -> Vec<String> {
        self.get()
    }

    fn set_selected(&self, values: Vec<String>) {
        self.set(values);
        self.touch();
    }
}
