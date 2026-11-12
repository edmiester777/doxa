//! Authorization for a job, queue consumer or scheduled task, where there is no request.
//!
//! The logger is required, so every verdict reached through an [`OffRequest`] is audited.
//!
//! ```ignore
//! let work = OffRequest::new(caller, checker, logger).actor("job:reindex");
//! let widget = work.authorize::<One<WidgetByName>>(name, &db).await?;
//! ```

use std::marker::PhantomData;
use std::sync::Arc;

use doxa_audit::{AuditEventBuilder, AuditLogger};
use doxa_policy::CapabilityChecker;
use http::Extensions;

use crate::granted::{authorize, Chain, FromAuthExtensions, Refusal};

/// A caller, a checker and an audit event, outside any request.
///
/// Every decision lands on one event, sent once when the handle is dropped or [`finish`](Self::finish)ed.
/// A job that fails after authorizing says so first, through [`event`](Self::event):
///
/// ```ignore
/// if let Err(error) = reindex(&widget).await {
///     work.event().emit_error(&error.to_string());
/// }
/// ```
pub struct OffRequest<C: FromAuthExtensions> {
    extensions: Extensions,
    audit: AuditEventBuilder,
    caller: PhantomData<fn() -> C>,
}

impl<C: FromAuthExtensions> OffRequest<C> {
    /// Assemble what a chain reads: the caller, the checker that answers for them, and the event.
    pub fn new(caller: C, checker: Arc<dyn CapabilityChecker>, logger: AuditLogger) -> Self {
        // Layered, so a refusal doesn't send the event early; the drop does.
        let audit = AuditEventBuilder::layered(logger);
        audit.set_tenant(caller.tenant());
        audit.set_actor(None, caller.roles(), serde_json::Value::Null);

        let mut extensions = Extensions::new();
        extensions.insert(caller);
        extensions.insert(checker);
        extensions.insert(audit.clone());

        OffRequest {
            extensions,
            audit,
            caller: PhantomData,
        }
    }

    /// Name the principal this work is done as; left unset, the event records only the roles.
    #[must_use]
    pub fn actor(self, sub: &str) -> Self {
        self.audit.set_actor(
            Some(sub),
            // `set_actor` replaces all three, so the roles are restated.
            C::from_extensions(&self.extensions)
                .as_ref()
                .map(FromAuthExtensions::roles)
                .unwrap_or_default(),
            serde_json::Value::Null,
        );
        self
    }

    /// Authorize a subject through the chain a route's extractor runs, recording the verdict.
    pub async fn authorize<T: Chain<Ctx = C>>(
        &self,
        key: T::Key,
        state: &T::State,
    ) -> Result<T::Loaded, Refusal<T::Error>> {
        authorize::<T>(key, state, &self.extensions).await
    }

    /// The extensions a chain reads, for doors such as
    /// [`AuthorizeLoaded`](crate::granted::AuthorizeLoaded) that take them directly.
    ///
    /// ```ignore
    /// let widget = load_widget(&db, &name).await?
    ///     .authorize::<WidgetByName, _>(Read, work.extensions())
    ///     .await?;
    /// ```
    pub fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    /// The event every verdict here lands on, for what only the job knows.
    pub fn event(&self) -> &AuditEventBuilder {
        &self.audit
    }

    /// Send the event now rather than when the handle drops.
    pub fn finish(self) {}
}

impl<C: FromAuthExtensions> Drop for OffRequest<C> {
    /// Send the event, its outcome folded from every decision (a denial outranks a grant).
    fn drop(&mut self) {
        self.audit.auto_emit();
    }
}
