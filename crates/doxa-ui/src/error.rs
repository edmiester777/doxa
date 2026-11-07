//! `Thrown`: any error a component's `?` can raise.

use std::fmt;
use std::rc::Rc;

/// An error raised by a component, effect or action, caught by the nearest `<Catch>`.
///
/// Like `anyhow::Error`, it is not itself an `Error`, which is what lets `?`
/// convert any error into it.
#[derive(Clone)]
pub struct Thrown(Rc<dyn std::error::Error>);

impl Thrown {
    /// A `Thrown` carrying just a message.
    pub fn msg(message: impl fmt::Display) -> Self {
        Thrown(Rc::new(Message(message.to_string())))
    }

    /// The underlying error, to downcast: `thrown.inner().downcast_ref::<Fetch<E>>()`.
    pub fn inner(&self) -> &(dyn std::error::Error + 'static) {
        &*self.0
    }

    /// The error as `E`, if that is what it is.
    pub fn downcast_ref<E: std::error::Error + 'static>(&self) -> Option<&E> {
        self.0.downcast_ref()
    }
}

impl<E: std::error::Error + 'static> From<E> for Thrown {
    fn from(e: E) -> Self {
        Thrown(Rc::new(e))
    }
}

impl fmt::Display for Thrown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Debug for Thrown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

#[derive(Debug)]
struct Message(String);

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Message {}

/// What components, effects and actions return.
pub type Result<T = crate::View, E = Thrown> = std::result::Result<T, E>;

/// What an effect or async handler may return: `()`, or a `Result` for `<Catch>`.
#[diagnostic::on_unimplemented(
    message = "an effect or async handler returns `()` or `Result<()>`, not `{Self}`",
    label = "change what it returns"
)]
pub trait Outcome {
    /// As a `Result`.
    fn into_result(self) -> Result<()>;
}

impl Outcome for () {
    fn into_result(self) -> Result<()> {
        Ok(())
    }
}

impl Outcome for Result<()> {
    fn into_result(self) -> Result<()> {
        self
    }
}
