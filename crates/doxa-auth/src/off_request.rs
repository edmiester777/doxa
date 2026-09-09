//! The same authorization, where there is no request to hang it on.
//!
//! A background job, a queue consumer and a scheduled task all decide the
//! same things a route does — may this caller read this dataset, which
//! subset may they see — and none of them has an [`http::Extensions`] to
//! read a caller out of. The chain never needed one: [`authorize`] takes a
//! caller, a checker and a state, and a worker has all three. What it did
//! not have was anywhere to put them.
//!
//! ```ignore
//! let work = OffRequest::new(caller, checker, logger).actor("job:reindex");
//!
//! let dataset = work
//!     .authorize::<One<DatasetByName>>(name, "read_dataset", &db)
//!     .await?;
//! ```
//!
//! # Why the logger is not optional
//!
//! Assembling the extensions by hand works, and is what the tests in this
//! workspace do. It has one sharp edge: a verdict is deposited only if an
//! [`AuditEventBuilder`] is present, and the deposit returns quietly if it
//! is not. A worker that builds two of the three things a chain reads
//! therefore authorizes successfully and records nothing — which is exactly
//! the outcome the guards exist to make impossible, reached by assembling
//! the inputs wrong rather than by choosing to.
//!
//! So there is no constructor here that omits the logger, and no
//! `authorize_unaudited` beside the one below. The type is the invariant:
//! if you are holding one, the verdict is going somewhere.
//!
//! That is a claim about *this* door only. `AuthLayer` with no `AuditLayer`
//! above it and no logger of its own still inserts no builder, and every
//! guard under it still records nothing — see [`authorize`], which is
//! unchanged.
//!
//! # What it does not decide
//!
//! Where the caller came from. A job that inherits the tenant and roles of
//! whoever queued it, a service principal with roles of its own, and a
//! re-resolved session are all just a [`FromAuthExtensions`] — and which of
//! those is right depends on whether authority captured at enqueue should
//! still hold at run time, which is an application's question and not this
//! crate's. Build whichever, and hand it over.
//!
//! [`authorize`]: crate::granted::authorize
//! [`AuditEventBuilder`]: doxa_audit::AuditEventBuilder

use std::marker::PhantomData;
use std::sync::Arc;

use doxa_audit::{AuditEventBuilder, AuditLogger};
use doxa_policy::CapabilityChecker;
use http::Extensions;

use crate::granted::{authorize, Chain, FromAuthExtensions, Refusal};

/// A caller, a checker and an audit event, outside any request.
///
/// Generic over the caller shape, and that is the point of the parameter
/// rather than storing it type-erased: a handle built from a
/// [`CapabilityContext`](crate::CapabilityContext) will not authorize a
/// subject whose [`Ctx`](crate::granted::Subject::Ctx) is the assembled
/// session, and says so at compile time. Through the request path the same
/// mistake is a `401` at run time, because extensions cannot be typed that
/// way.
///
/// An application with one caller shape — which is most of them, since the
/// shape comes off the profile — never notices the parameter. One that
/// genuinely mixes builds a handle per shape, or reaches past this with
/// [`extensions`](Self::extensions).
///
/// # Terminating the event
///
/// Nothing needs to be called. A refusal settles itself, and dropping the
/// handle emits whatever is left as
/// [`Outcome::Allowed`](doxa_audit::Outcome::Allowed) — the same terminal
/// [`AuditLayer`](doxa_audit::AuditLayer) applies after a response that
/// raised nothing. A job that fails *after* authorizing should say so
/// before dropping, through [`event`](Self::event):
///
/// ```ignore
/// if let Err(error) = reindex(&dataset).await {
///     work.event().emit_error(&error.to_string());
/// }
/// ```
pub struct OffRequest<C: FromAuthExtensions> {
    extensions: Extensions,
    audit: AuditEventBuilder,
    caller: PhantomData<fn() -> C>,
}

impl<C: FromAuthExtensions> OffRequest<C> {
    /// Assemble what a chain reads: the caller, the checker that answers
    /// for them, and the event their verdicts land on.
    ///
    /// The builder is the un-layered kind, because nothing downstream will
    /// terminate it — there is no response to wait for. The caller's tenant
    /// and roles are stamped onto it immediately, so an event emitted by a
    /// refusal that happens before anything else still names who was
    /// refused.
    pub fn new(caller: C, checker: Arc<dyn CapabilityChecker>, logger: AuditLogger) -> Self {
        let audit = AuditEventBuilder::new(logger);
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

    /// Name the principal this work is being done as.
    ///
    /// `FromAuthExtensions` carries a tenant and roles but no subject —
    /// there is no token here for one to have come from — so a job's actor
    /// is whatever the application calls it. Left unset, the event records
    /// the roles and no subject, which is honest rather than useful.
    #[must_use]
    pub fn actor(self, sub: &str) -> Self {
        self.audit.set_actor(
            Some(sub),
            // `set_actor` replaces all three, so the roles have to be
            // restated rather than left to the constructor's call.
            C::from_extensions(&self.extensions)
                .as_ref()
                .map(FromAuthExtensions::roles)
                .unwrap_or_default(),
            serde_json::Value::Null,
        );
        self
    }

    /// Authorize a subject, recording the verdict either way.
    ///
    /// The same call the extractor makes, against the same chain — so a
    /// decision reached here is indistinguishable in the trail from one a
    /// route reached, which is the property that makes an audit log worth
    /// querying across both.
    ///
    /// The state is passed rather than extracted. [`LoaderSource`] and the
    /// whole `FromRequestParts` half of the guard are the request's
    /// business; a worker holds its connection already.
    ///
    /// [`LoaderSource`]: crate::granted::LoaderSource
    pub async fn authorize<T: Chain<Ctx = C>>(
        &self,
        key: T::Key,
        state: &T::State,
    ) -> Result<T::Loaded, Refusal<T::Error>> {
        authorize::<T>(key, state, &self.extensions).await
    }

    /// The extensions a chain reads, for the doors that take them directly.
    ///
    /// [`AuthorizeLoaded`](crate::granted::AuthorizeLoaded) is the one a
    /// worker most often wants: a job usually loads its own rows, and that
    /// door decides about a row already in hand and returns a
    /// [`Denial`](crate::granted::Denial), which carries no HTTP response
    /// the way [`Refusal`] does.
    ///
    /// ```ignore
    /// let dataset = load_dataset(&db, &name).await?
    ///     .authorize::<DatasetByName, _>(Read, work.extensions())
    ///     .await?;
    /// ```
    pub fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    /// The event every verdict here lands on, for what only the job knows.
    ///
    /// The same enrichment a handler does: a domain event category, a
    /// summary of what the work produced, or a terminal outcome when the
    /// job fails after being authorized.
    pub fn event(&self) -> &AuditEventBuilder {
        &self.audit
    }
}

impl<C: FromAuthExtensions> Drop for OffRequest<C> {
    /// Emit whatever has not been emitted, as allowed.
    ///
    /// The same terminal [`AuditLayer`](doxa_audit::AuditLayer) applies
    /// after a response, and idempotent for the same reason: a refusal
    /// settled the event already, and this finds nothing left to send.
    /// Without it, forgetting to emit would lose exactly the grants — the
    /// refusals self-settle — which is the half an audit trail is least
    /// able to do without.
    fn drop(&mut self) {
        self.audit.auto_emit();
    }
}
