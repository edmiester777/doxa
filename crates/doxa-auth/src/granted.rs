//! One way to authorize a route, whatever it is guarding.
//!
//! [`Granted<T>`] replaces the split between a coarse capability gate and
//! an instance gate. A route names what it is about and gets back the
//! caller alongside it:
//!
//! ```ignore
//! async fn get(widget: Granted<Widget>) -> Json<Widget>
//! async fn list(scope: Granted<Many<Widget>>) -> Json<Vec<Widget>>
//! async fn flush(_: Granted<Cap<FlushCaches>>) -> StatusCode
//! ```
//!
//! The guard [derefs](std::ops::Deref) to what it authorized, so
//! `widget.name` reads through it and a `#[tracing::instrument]` span
//! field can borrow it before the body runs. Take ownership with
//! [`into_inner`](Granted::into_inner), reach the caller with
//! [`caller`](Granted::caller), or destructure for both:
//!
//! ```ignore
//! async fn transfer(Granted(caller, widget): Granted<Widget>) -> StatusCode
//! ```
//!
//! The three forms run the same chain and differ only in what the policy
//! is asked about:
//!
//! | Form | Asks | Yields |
//! |------|------|--------|
//! | `Granted<Widget>` | may this caller act on *this object* | the loaded object |
//! | `Granted<Many<Widget>>` | what *subset* may they see | a query filter |
//! | `Granted<Cap<M>>` | may they call this at all | `()` |
//!
//! Every verdict leaves through one place, so the log line and the audit
//! record cannot drift apart the way they did when each guard owned its
//! own deny branch.
//!
//! ## What the handler owes the audit trail
//!
//! Nothing. The chain already knows which action it checked, which object
//! it checked it against, and — from the asset's
//! [`Granting::event_type`] — which category to file that under, so it
//! deposits all three and the audit layer folds them into the event after
//! the response. A handler writes to the event only where it knows
//! something the guard cannot: a sanitized request body, a response
//! summary, or a domain event of its own. Whatever it writes wins, in
//! whatever order it writes it — the fold fills blanks and never
//! overwrites.
//!
//! ## Why the caller comes back
//!
//! The old `Require<M>` discarded the tenant it had just authorized
//! against, so callers paired it with a second `Auth<S, C>` extractor to
//! read the same values back out of extensions. [`Granted`] hands the
//! context over directly. Which context it is comes from the asset's
//! [`Subject::Ctx`], so a route that only needs tenant + roles never
//! names the consumer's session and claim types at all.

use std::borrow::Cow;
use std::future::Future;
use std::marker::PhantomData;

use axum::extract::FromRequestParts;
use axum::response::{IntoResponse, Response};
use http::Extensions;

use doxa_policy::{
    AuthError, Capability, CapabilityChecker, Capable, PolicyResource, ResourceEntity,
    ResourceIdType,
};

use crate::claims::Claims;
use crate::context::{AuthContext, CapabilityContext};

// ---------------------------------------------------------------------------
// Caller context
// ---------------------------------------------------------------------------

/// A caller shape recoverable from request extensions.
///
/// Implemented for [`CapabilityContext`] (tenant + roles, no consumer
/// generics) and for [`AuthContext<S, C>`] (claims + resolved session).
/// An asset picks one as its [`Subject::Ctx`]; a collection asset needs
/// the typed form, because the authorized scope lives in the session the
/// policy assembled.
pub trait FromAuthExtensions: Clone + Send + Sync + 'static {
    /// Recover the context, or `None` when the auth layer never ran.
    fn from_extensions(extensions: &Extensions) -> Option<Self>;

    /// Tenancy boundary the policy check runs within.
    fn tenant(&self) -> Option<&str>;

    /// Roles asserted for the caller.
    fn roles(&self) -> &[String];
}

impl FromAuthExtensions for CapabilityContext {
    fn from_extensions(extensions: &Extensions) -> Option<Self> {
        extensions.get::<CapabilityContext>().cloned()
    }

    fn tenant(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }

    fn roles(&self) -> &[String] {
        &self.roles
    }
}

impl<S, C> FromAuthExtensions for AuthContext<S, C>
where
    S: Clone + Send + Sync + 'static,
    C: Claims + Clone,
{
    fn from_extensions(extensions: &Extensions) -> Option<Self> {
        extensions.get::<AuthContext<S, C>>().cloned()
    }

    fn tenant(&self) -> Option<&str> {
        self.claims.scope()
    }

    fn roles(&self) -> &[String] {
        self.claims.roles()
    }
}

// ---------------------------------------------------------------------------
// Route keys
// ---------------------------------------------------------------------------

/// The identifying values a loader needs, parsed from route segments.
///
/// Implemented for `()`, for the scalars below, and for tuples of them
/// up to four.
///
/// A composite key binds **by position**: the order of `#[key("a", "b")]`
/// is the order of the tuple, and a two-`String` key bound the wrong way
/// round parses cleanly and loads the wrong object. Prefer distinct
/// types per segment where you can, so a swap fails to parse instead of
/// succeeding quietly. [`SEGMENTS`](Self::SEGMENTS) is checked against
/// the site's parameter count before any of them are read, so a key and
/// a route that disagree are refused rather than silently truncated.
pub trait RouteKey: Sized + Send {
    /// Schema kind per segment, in key order. Drives the OpenAPI
    /// parameter types without a runtime call.
    const SEGMENTS: &'static [ResourceIdType];

    /// Parse the raw segments the route supplied.
    fn parse(raw: &[&str]) -> Result<Self, KeyError>;
}

/// A route segment that did not parse into its key component.
#[derive(Debug)]
pub struct KeyError {
    /// Zero-based position of the offending segment in the key.
    pub position: usize,
    /// The raw text that failed to parse.
    pub raw: String,
}

impl IntoResponse for KeyError {
    fn into_response(self) -> Response {
        (
            axum::http::StatusCode::BAD_REQUEST,
            format!("invalid identifier: {}", self.raw),
        )
            .into_response()
    }
}

/// Nothing to identify — collection and capability routes.
impl RouteKey for () {
    const SEGMENTS: &'static [ResourceIdType] = &[];

    fn parse(_raw: &[&str]) -> Result<Self, KeyError> {
        Ok(())
    }
}

/// One value inside a key.
///
/// Separate from [`RouteKey`] because a tuple has to build its own
/// `SEGMENTS` from its parts' kinds, and slices cannot be concatenated
/// in a const context — a `KIND` per part can.
pub trait KeySegment: Sized + Send {
    /// Schema kind for this segment, driving the OpenAPI parameter type.
    const KIND: ResourceIdType;

    /// Parse one raw segment. The caller attaches the position.
    fn parse_segment(raw: &str) -> Option<Self>;
}

macro_rules! scalar_key {
    ($ty:ty, $kind:expr) => {
        impl KeySegment for $ty {
            const KIND: ResourceIdType = $kind;

            fn parse_segment(raw: &str) -> Option<Self> {
                raw.parse().ok()
            }
        }

        impl RouteKey for $ty {
            const SEGMENTS: &'static [ResourceIdType] = &[$kind];

            fn parse(raw: &[&str]) -> Result<Self, KeyError> {
                let text = raw.first().copied().unwrap_or_default();
                <$ty as KeySegment>::parse_segment(text).ok_or_else(|| KeyError {
                    position: 0,
                    raw: text.to_owned(),
                })
            }
        }
    };
}

scalar_key!(String, ResourceIdType::String);
scalar_key!(i64, ResourceIdType::Integer);
scalar_key!(u32, ResourceIdType::Integer);
scalar_key!(u64, ResourceIdType::Integer);

macro_rules! tuple_key {
    ($($name:ident @ $index:tt),+) => {
        impl<$($name: KeySegment),+> RouteKey for ($($name,)+) {
            const SEGMENTS: &'static [ResourceIdType] = &[$($name::KIND),+];

            fn parse(raw: &[&str]) -> Result<Self, KeyError> {
                Ok(($(
                    {
                        let text = raw.get($index).copied().unwrap_or_default();
                        $name::parse_segment(text).ok_or_else(|| KeyError {
                            position: $index,
                            raw: text.to_owned(),
                        })?
                    },
                )+))
            }
        }
    };
}

tuple_key!(A @ 0, B @ 1);
tuple_key!(A @ 0, B @ 1, C @ 2);
tuple_key!(A @ 0, B @ 1, C @ 2, D @ 3);

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// Why a subject would not hand its value over.
///
/// [`Denied`](Refusal::Denied) is the policy saying no, and is the only
/// variant the guard records; the rest describe a request that never
/// reached a decision. Nothing is rendered here — the refusal travels as
/// itself and meets `IntoResponse` once, at the extractor boundary, so a
/// loader error arrives with whatever audit outcome it attaches intact.
#[derive(Debug)]
pub enum Refusal<E> {
    /// The policy refused. Recorded once, by the extractor.
    Denied {
        /// Capability name, or the Cedar action for an instance check.
        action: Cow<'static, str>,
        /// Cedar entity type of the refused resource.
        resource_type: Cow<'static, str>,
        /// Cedar entity id of the refused resource.
        resource_id: Cow<'static, str>,
        /// Short reason, used for both the log field and the audit
        /// event's error text.
        reason: &'static str,
    },
    /// The key named no object the loader could find.
    NotFound {
        /// Cedar entity type that was looked up.
        entity_type: &'static str,
    },
    /// A route segment did not parse into its key component.
    Key(KeyError),
    /// No auth context, no checker, or a policy that failed to decide.
    Auth(AuthError),
    /// The loader failed with the consumer's own error type.
    Load(E),
}

impl<E> From<AuthError> for Refusal<E> {
    fn from(error: AuthError) -> Self {
        Refusal::Auth(error)
    }
}

impl<E> From<KeyError> for Refusal<E> {
    fn from(error: KeyError) -> Self {
        Refusal::Key(error)
    }
}

impl<E: IntoResponse> IntoResponse for Refusal<E> {
    fn into_response(self) -> Response {
        match self {
            // The denial was recorded on the way out; the caller is told
            // only that it was refused.
            Refusal::Denied { .. } => AuthError::Forbidden.into_response(),
            Refusal::NotFound { entity_type } => (
                axum::http::StatusCode::NOT_FOUND,
                format!("{entity_type} not found"),
            )
                .into_response(),
            Refusal::Key(error) => error.into_response(),
            Refusal::Auth(error) => error.into_response(),
            Refusal::Load(error) => error.into_response(),
        }
    }
}

// ---------------------------------------------------------------------------
// Call sites
// ---------------------------------------------------------------------------

/// Route-specific facts the macro bakes in per call site: which segments
/// carry the key, and which Cedar action the verb implies.
///
/// Hand-written routes implement it directly — it is two consts. The site
/// rides on the form marker rather than on [`Granted`] itself, so a route
/// names `Granted<One<Widget, __Site>>` and the guard stays a plain pair
/// of caller and subject that a handler can destructure.
pub trait GrantSite: Send + Sync + 'static {
    /// Path parameters feeding the key, in key order. Empty for
    /// collection and capability routes.
    const PARAMS: &'static [&'static str];
    /// Cedar action to authorize, from the HTTP verb.
    const ACTION: &'static str;
    /// OpenAPI security scheme the requirement references.
    const SCHEME: &'static str = "bearer";
}

/// Site used by hand-written routes: no path parameters, `read`, bearer.
/// The route macro generates a real one per call site.
pub struct DefaultSite;

impl GrantSite for DefaultSite {
    const PARAMS: &'static [&'static str] = &[];
    const ACTION: &'static str = "read";
}

// ---------------------------------------------------------------------------
// Subjects
// ---------------------------------------------------------------------------

/// Which of the three forms a subject is. Documentation words itself
/// from this, and only the instance form can answer 400 or 404.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectForm {
    /// One object, named by a key in the route.
    Instance,
    /// The subset of a collection a caller may see.
    Collection,
    /// A bare capability with no asset behind it.
    Capability,
}

/// The three forms, and the chain that runs them.
///
/// Both traits here are unnameable outside this crate, which is what
/// makes [`authorize`] the only way to reach a policy decision. A raw
/// chain records nothing, so a second door onto it would be a way to
/// authorize something and leave no audit row — the failure this module
/// is built to prevent. There is no such door.
///
/// [`Subject`] stays public because it is the bound on [`Granted`] and on
/// [`authorize`], and a route signature names it. It is sealed rather
/// than open: the three forms are the three questions a policy can be
/// asked, and everything asset-specific belongs on [`Granting`].
mod sealed {
    use std::borrow::Cow;
    use std::future::Future;

    use doxa_policy::CapabilityChecker;

    use super::{Refusal, Subject};

    /// Blocks outside implementations of [`Subject`].
    pub trait Sealed {}

    /// What a subject's chain produced: the value the handler receives,
    /// alongside the identity the policy decided against.
    ///
    /// The identity is not recoverable from the value — a collection
    /// yields a query filter and a capability yields nothing at all — so
    /// the chain hands it back rather than have the caller reconstruct
    /// it. It is the whole of what the audit event needs from an
    /// authorization, and every form already computes it on the way to a
    /// verdict.
    pub struct Authorized<T> {
        /// What the handler receives.
        pub loaded: T,
        /// What was checked: the Cedar action for an instance or
        /// collection, the capability name for a bare gate.
        ///
        /// Not always the route's own `GrantSite::ACTION` — a `Cap<M>`
        /// route ignores the verb and asks about the capability. Naming
        /// what was actually checked is what keeps a grant and a refusal
        /// on the same route describing the same thing.
        pub action: Cow<'static, str>,
        /// Cedar entity type the decision concerned.
        pub resource_type: Cow<'static, str>,
        /// Cedar entity id the decision concerned.
        pub resource_id: Cow<'static, str>,
    }

    /// The decision itself: coarse gate, then whatever the subject is
    /// about.
    ///
    /// Separate from [`Subject`] — which describes what a route
    /// authorizes — so that describing a subject and *deciding* one are
    /// not the same capability. This half records nothing, and
    /// [`authorize`](super::authorize) is the only caller there is.
    pub trait Chain: Subject {
        /// Domain event category this subject's routes are filed under,
        /// for `action`.
        ///
        /// Forwards to `Granting::event_type` for the two asset-backed
        /// forms; a bare capability has no asset to ask, so it declares
        /// nothing.
        fn event_type(_action: &str) -> Option<&'static str> {
            None
        }

        /// Reach a verdict. Records nothing — that is
        /// [`authorize`](super::authorize)'s half, and the reason this
        /// one has no other caller.
        fn authorize(
            key: Self::Key,
            action: &'static str,
            state: &Self::State,
            ctx: &Self::Ctx,
            checker: &dyn CapabilityChecker,
        ) -> impl Future<Output = Result<Authorized<Self::Loaded>, Refusal<Self::Error>>> + Send;
    }
}

use sealed::{Authorized, Chain};

/// What a route authorizes: an object, a collection, or a bare
/// capability.
///
/// Sealed — [`One<R>`], [`Many<R>`] and [`Cap<M>`] are the three forms,
/// and they are the three questions a policy can be asked. Everything
/// asset-specific lives on [`Granting`], which is the trait to implement.
///
/// Named here because it is the bound on [`Granted`] and [`authorize`],
/// so a route signature and a manual call both mention it.
pub trait Subject: sealed::Sealed + Send + Sync + 'static {
    /// What the handler receives alongside the caller.
    type Loaded: Send;
    /// Caller shape this subject's chain needs.
    type Ctx: FromAuthExtensions;
    /// State the chain reaches through `FromRef`.
    type State: Send + Sync;
    /// Identifying values the route must supply.
    type Key: RouteKey;
    /// Loader failure this subject's chain can raise. [`Cap`] loads
    /// nothing and uses [`Infallible`](std::convert::Infallible).
    type Error: IntoResponse + Send;
    /// The call site: which segments carry the key, which action to
    /// check, which security scheme to document.
    ///
    /// Each form takes it as a second parameter defaulting to
    /// [`DefaultSite`], so `One<Widget>` is a subject on its own and the
    /// macro's generated site slots in as `One<Widget, __Site>`. Carrying
    /// it here rather than on [`Granted`] is what leaves the guard two
    /// fields wide.
    type Site: GrantSite;

    /// Which of the three forms this is.
    const FORM: SubjectForm;

    /// What this subject is about, for documentation prose — the Cedar
    /// entity type for a resource, the capability name for a bare gate.
    fn doc_name() -> Cow<'static, str>;

    /// Permission name for the OpenAPI badge, given the route's action.
    fn permission(action: &str) -> Cow<'static, str>;
}

/// Everything asset-specific: how to load one, which coarse capability
/// covers an action, and what the caller's authorized subset looks like.
///
/// One impl per asset serves every route that guards it. The route
/// supplies only what is route-specific — which segments carry the key,
/// and which action the verb implies.
pub trait Granting: PolicyResource + Sized + Send + Sync + 'static {
    /// Identifying values [`load`](Self::load) needs.
    type Key: RouteKey;
    /// Caller shape this asset's chain needs. [`CapabilityContext`] is
    /// enough for instance routes; a collection route needs
    /// [`AuthContext<S, C>`] to reach the assembled session.
    type Ctx: FromAuthExtensions;
    /// State the loader reaches through `FromRef`.
    type State: Send + Sync;
    /// Loader failure. Reaches the client through its own
    /// `IntoResponse`, so any audit outcome it attaches survives.
    type Error: IntoResponse + Send;
    /// The caller's authorized subset, as this asset's queries take it.
    type Filter: Send;

    /// Coarse capability covering `action`, run before any load so an
    /// unauthorized caller costs no query. `None` — the default — goes
    /// straight to the instance or scope check.
    fn capability(_action: &str) -> Option<&'static Capability> {
        None
    }

    /// Domain event category covering `action` — the `event_type` field
    /// on the audit event.
    ///
    /// Declared once per asset rather than once per route, so every route
    /// guarding this asset files under the same vocabulary and a verb
    /// cannot end up disagreeing with the category it was recorded as. It
    /// is the one part of an audit event a guard cannot work out for
    /// itself: what counts as a category is the application's to say.
    ///
    /// Return the `'static` string a variant of your own event enum
    /// stands for — `doxa_audit::EventType::as_static` is the shape to
    /// copy. `None` — the default — leaves the field for the handler to
    /// name, or empty if it does not.
    fn event_type(_action: &str) -> Option<&'static str> {
        None
    }

    /// Fetch one object, or `None` if there is no such thing.
    fn load(
        key: Self::Key,
        state: &Self::State,
        ctx: &Self::Ctx,
    ) -> impl Future<Output = Result<Option<Self>, Self::Error>> + Send;

    /// The caller's authorized scope on this asset, read out of the
    /// session the policy already assembled.
    ///
    /// `Ok(None)` means the policy granted nothing here, which
    /// [`empty_scope`](Self::empty_scope) then turns into a refusal or an
    /// empty page.
    fn scope(_ctx: &Self::Ctx) -> Result<Option<Self::Filter>, AuthError> {
        Ok(None)
    }

    /// The scope to use when the policy granted this caller nothing.
    ///
    /// `None` — the default — refuses the request, so a misconfigured
    /// policy is visible instead of looking like an empty table. Return a
    /// filter that matches nothing to let the handler answer with an
    /// empty page instead; only the asset knows how to say "nothing" in
    /// its own query language.
    fn empty_scope() -> Option<Self::Filter> {
        None
    }
}

/// Authorize one object: load it, then decide with its own attributes in
/// scope.
pub struct One<R, S = DefaultSite>(PhantomData<fn() -> (R, S)>);

/// Authorize the whole collection rather than one member: the policy's
/// residual becomes a filter the handler applies to its query.
///
/// Costs no policy call at request time — partial evaluation already ran
/// in [`AuthLayer`](crate::AuthLayer), so this is a lookup into the
/// session it assembled.
pub struct Many<R, S = DefaultSite>(PhantomData<fn() -> (R, S)>);

/// Authorize a bare capability with no asset behind it.
pub struct Cap<M, S = DefaultSite>(PhantomData<fn() -> (M, S)>);

/// The permission an asset-backed route advertises: the coarse
/// capability where the asset declares one, and the Cedar action
/// otherwise.
///
/// Shared by the instance and collection forms, which ask the same
/// question of the same asset — so a listing and a fetch cannot end up
/// documenting different permissions for the same verb.
fn asset_permission<R: Granting>(action: &str) -> Cow<'static, str> {
    match R::capability(action) {
        Some(cap) => Cow::Borrowed(cap.name),
        None => Cow::Owned(format!("{}:{action}", R::ENTITY_TYPE)),
    }
}

impl<R: Granting, S: GrantSite> sealed::Sealed for One<R, S> {}

impl<R: Granting, S: GrantSite> Subject for One<R, S> {
    type Loaded = R;
    type Ctx = R::Ctx;
    type State = R::State;
    type Key = R::Key;
    type Error = R::Error;
    type Site = S;

    const FORM: SubjectForm = SubjectForm::Instance;

    fn doc_name() -> Cow<'static, str> {
        Cow::Borrowed(R::ENTITY_TYPE)
    }

    fn permission(action: &str) -> Cow<'static, str> {
        asset_permission::<R>(action)
    }
}

impl<R: Granting, S: GrantSite> Chain for One<R, S> {
    fn event_type(action: &str) -> Option<&'static str> {
        R::event_type(action)
    }

    async fn authorize(
        key: Self::Key,
        action: &'static str,
        state: &Self::State,
        ctx: &Self::Ctx,
        checker: &dyn CapabilityChecker,
    ) -> Result<Authorized<R>, Refusal<R::Error>> {
        // Coarse gate first: a caller who may not touch this kind of
        // thing at all should not cost a query, and must not be able to
        // tell a missing object from one they may not see.
        coarse_gate::<R>(action, ctx, checker).await?;

        let resource = R::load(key, state, ctx)
            .await
            .map_err(Refusal::Load)?
            .ok_or(Refusal::NotFound {
                entity_type: R::ENTITY_TYPE,
            })?;

        let entity = ResourceEntity::of(&resource);
        let allowed = checker
            .check_instance(ctx.tenant().unwrap_or(""), ctx.roles(), action, &entity)
            .await?;

        if !allowed {
            return Err(Refusal::Denied {
                action: Cow::Borrowed(action),
                resource_type: Cow::Borrowed(R::ENTITY_TYPE),
                resource_id: Cow::Owned(entity.entity_id),
                reason: "instance denied",
            });
        }

        // The loaded row's Cedar id, not the key the route parsed: a
        // route addressing an object by a bare name decides — and so must
        // record — the qualified identity the policy actually saw.
        Ok(Authorized {
            loaded: resource,
            action: Cow::Borrowed(action),
            resource_type: Cow::Borrowed(R::ENTITY_TYPE),
            resource_id: Cow::Owned(entity.entity_id),
        })
    }
}

impl<R: Granting, S: GrantSite> sealed::Sealed for Many<R, S> {}

impl<R: Granting, S: GrantSite> Subject for Many<R, S> {
    type Loaded = R::Filter;
    type Ctx = R::Ctx;
    type State = R::State;
    type Key = ();
    type Error = R::Error;
    type Site = S;

    const FORM: SubjectForm = SubjectForm::Collection;

    fn doc_name() -> Cow<'static, str> {
        Cow::Borrowed(R::ENTITY_TYPE)
    }

    fn permission(action: &str) -> Cow<'static, str> {
        asset_permission::<R>(action)
    }
}

impl<R: Granting, S: GrantSite> Chain for Many<R, S> {
    fn event_type(action: &str) -> Option<&'static str> {
        R::event_type(action)
    }

    async fn authorize(
        _key: (),
        action: &'static str,
        _state: &Self::State,
        ctx: &Self::Ctx,
        checker: &dyn CapabilityChecker,
    ) -> Result<Authorized<R::Filter>, Refusal<R::Error>> {
        coarse_gate::<R>(action, ctx, checker).await?;

        let scope = match R::scope(ctx)? {
            Some(scope) => scope,
            // The policy granted nothing on this asset. Whether that is a
            // refusal or an empty page is the asset's call.
            None => R::empty_scope().ok_or(Refusal::Denied {
                action: Cow::Borrowed(action),
                resource_type: Cow::Borrowed(R::ENTITY_TYPE),
                resource_id: Cow::Borrowed("collection"),
                reason: "no authorized scope",
            })?,
        };

        // The same id the refusal above names, so a listing and a refused
        // listing sit under one resource in the trail.
        Ok(Authorized {
            loaded: scope,
            action: Cow::Borrowed(action),
            resource_type: Cow::Borrowed(R::ENTITY_TYPE),
            resource_id: Cow::Borrowed("collection"),
        })
    }
}

impl<M: Capable, S: GrantSite> sealed::Sealed for Cap<M, S> {}

impl<M: Capable, S: GrantSite> Subject for Cap<M, S> {
    type Loaded = ();
    type Ctx = CapabilityContext;
    type State = ();
    type Key = ();
    type Error = std::convert::Infallible;
    type Site = S;

    const FORM: SubjectForm = SubjectForm::Capability;

    fn doc_name() -> Cow<'static, str> {
        Cow::Borrowed(M::CAPABILITY.name)
    }

    fn permission(_action: &str) -> Cow<'static, str> {
        Cow::Borrowed(M::CAPABILITY.name)
    }
}

impl<M: Capable, S: GrantSite> Chain for Cap<M, S> {
    async fn authorize(
        _key: (),
        _action: &'static str,
        _state: &(),
        ctx: &CapabilityContext,
        checker: &dyn CapabilityChecker,
    ) -> Result<Authorized<()>, Refusal<Self::Error>> {
        let allowed = checker
            .check(ctx.tenant().unwrap_or(""), ctx.roles(), M::CAPABILITY)
            .await?;

        let (resource_type, resource_id) = capability_resource(M::CAPABILITY);

        if !allowed {
            return Err(Refusal::Denied {
                action: Cow::Borrowed(M::CAPABILITY.name),
                resource_type: Cow::Borrowed(resource_type),
                resource_id: Cow::Borrowed(resource_id),
                reason: "capability denied",
            });
        }

        // The capability, not the verb: this chain never asked about the
        // route's action, and the refusal above names the capability too.
        Ok(Authorized {
            loaded: (),
            action: Cow::Borrowed(M::CAPABILITY.name),
            resource_type: Cow::Borrowed(resource_type),
            resource_id: Cow::Borrowed(resource_id),
        })
    }
}

/// The resource a capability's verdict is about.
///
/// A capability is granted only when every one of its checks passes, so
/// the first is the one whose denial short-circuits the evaluation — and
/// the one worth naming in the trail. A capability with no checks at all
/// names itself.
pub(crate) fn capability_resource(cap: &'static Capability) -> (&'static str, &'static str) {
    cap.checks
        .first()
        .map(|check| (check.entity_type, check.entity_id))
        .unwrap_or(("capability", cap.name))
}

/// The coarse capability gate shared by the instance and collection
/// chains. A no-op for assets that declare no capability.
async fn coarse_gate<R: Granting>(
    action: &str,
    ctx: &R::Ctx,
    checker: &dyn CapabilityChecker,
) -> Result<(), Refusal<R::Error>> {
    let Some(cap) = R::capability(action) else {
        return Ok(());
    };

    if checker
        .check(ctx.tenant().unwrap_or(""), ctx.roles(), cap)
        .await?
    {
        return Ok(());
    }

    let (resource_type, resource_id) = capability_resource(cap);

    Err(Refusal::Denied {
        action: Cow::Borrowed(cap.name),
        resource_type: Cow::Borrowed(resource_type),
        resource_id: Cow::Borrowed(resource_id),
        reason: "capability denied",
    })
}

// ---------------------------------------------------------------------------
// The extractor
// ---------------------------------------------------------------------------

/// An authorized subject, handed over with the caller that was
/// authorized for it.
///
/// Extraction fails with 400 (unparseable key), 401 (no auth context),
/// 403 (policy denial) or 404 (no such object). Either verdict reaches
/// the request's audit event without the handler doing anything; a
/// denial is additionally logged at `warn`.
///
/// A plain pair: the call site is not carried here but on the subject, as
/// [`Subject::Site`], so the type holds exactly the two things the
/// handler asked for and both fields are public. `Granted(caller,
/// widget)` is therefore a pattern a handler can write — in the argument
/// list, even, since the guard is nothing but those two values.
pub struct Granted<T: Subject>(pub T::Ctx, pub T::Loaded);

impl<T: Subject> Granted<T> {
    /// Consume the guard and return just the authorized value.
    pub fn into_inner(self) -> T::Loaded {
        self.1
    }

    /// The caller this subject was authorized for.
    ///
    /// An inherent method, so it wins method resolution over anything
    /// [`Deref`](std::ops::Deref) would reach on the subject.
    pub fn caller(&self) -> &T::Ctx {
        &self.0
    }
}

/// Reach the authorized subject without naming it.
///
/// A guard carries two things, which is normally an argument against
/// `Deref` — but only one of them is what the route is *about*, and the
/// caller stays reachable through [`caller`](Granted::caller), an
/// inherent method that outranks anything found through here.
///
/// What it buys is the borrow case, which is most of them: a field read,
/// or a `#[tracing::instrument]` span field, evaluated before the handler
/// body can unwrap anything. Without it a consumer has to write an
/// extension trait whose whole job is to hand back `&self.1`.
impl<T: Subject> std::ops::Deref for Granted<T> {
    type Target = T::Loaded;

    fn deref(&self) -> &T::Loaded {
        &self.1
    }
}

impl<T, St> axum::extract::FromRequestParts<St> for Granted<T>
where
    T: Chain,
    St: Send + Sync,
    T::State: axum::extract::FromRef<St>,
{
    type Rejection = Refusal<T::Error>;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &St,
    ) -> Result<Self, Self::Rejection> {
        let ctx = T::Ctx::from_extensions(&parts.extensions)
            .ok_or(Refusal::Auth(AuthError::MissingCredentials))?;

        let key = fetch_key::<T, St>(parts, state).await?;
        let state = <T::State as axum::extract::FromRef<St>>::from_ref(state);

        // Same entry point a handler uses, so the refusal is recorded by
        // the same code either way.
        let loaded = authorize::<T>(key, T::Site::ACTION, &state, &parts.extensions).await?;
        Ok(Granted(ctx, loaded))
    }
}

/// Authorize a subject against the caller and checker already resolved
/// into `extensions`, recording the verdict either way.
///
/// This is the body of [`Granted`], exposed for a subject the extractor
/// cannot reach. A guard runs in `FromRequestParts`, which sees no
/// request body, so an id named in a payload — a pipeline referring to
/// its source, a query naming the models it reads — can only be
/// authorized from inside the handler that parsed it. The same applies
/// to a row inside an open transaction, which a [`Granting::State`]
/// holding a separate connection would not find.
///
/// This and [`Granted`] are the only ways to reach a policy decision.
/// The chain underneath is sealed and records nothing, so there is no
/// third path that authorizes something and leaves no audit row — the
/// choice of whether a check is auditable was removed rather than
/// documented.
///
/// ## What reaches the audit event
///
/// The verdict is *deposited*, not stamped: what was checked, on what,
/// and under which category, folded into the request's event at emit time
/// for whatever the handler did not name itself. So a handler that has
/// its own view of the event simply writes it, in any order, and wins —
/// there is nothing to call first and nothing to guard on.
///
/// One request may authorize several things. The route's own subject is
/// authorized before the body is even parsed, so it is the one the event
/// names; a dependency checked later does not displace it. A *refusal*
/// does, because a request that ends on a denial is about that denial.
pub async fn authorize<T: Chain>(
    key: T::Key,
    action: &'static str,
    state: &T::State,
    extensions: &Extensions,
) -> Result<T::Loaded, Refusal<T::Error>> {
    let ctx =
        T::Ctx::from_extensions(extensions).ok_or(Refusal::Auth(AuthError::MissingCredentials))?;
    let checker = extensions
        .get::<std::sync::Arc<dyn CapabilityChecker>>()
        .cloned()
        .ok_or_else(|| {
            Refusal::Auth(AuthError::PolicyFailed(
                "capability checker not configured on AuthLayer".into(),
            ))
        })?;

    match T::authorize(key, action, state, &ctx, checker.as_ref()).await {
        Ok(authorized) => {
            crate::record::grant(
                extensions,
                crate::record::Grant {
                    event_type: T::event_type(action),
                    action: authorized.action,
                    resource_type: authorized.resource_type,
                    resource_id: authorized.resource_id,
                },
            );
            Ok(authorized.loaded)
        }
        Err(refusal) => {
            record_refusal(&refusal, extensions, ctx.tenant());
            Err(refusal)
        }
    }
}

/// The one place a denial is recorded, whichever door the check came in
/// by. Everything else is a request that never reached a decision, so
/// there is nothing to record — it renders through `IntoResponse` like
/// any other rejection.
fn record_refusal<E>(refusal: &Refusal<E>, extensions: &Extensions, tenant: Option<&str>) {
    let Refusal::Denied {
        action,
        resource_type,
        resource_id,
        reason,
    } = refusal
    else {
        return;
    };

    crate::record::record(
        extensions,
        crate::record::Denial {
            tenant,
            action,
            resource_type,
            resource_id,
            reason,
        },
    );
}

/// Pull the key's segments out of the route, in the order the site names
/// them.
async fn fetch_key<T: Subject, St: Send + Sync>(
    parts: &mut http::request::Parts,
    state: &St,
) -> Result<T::Key, Refusal<T::Error>> {
    let params_named = <T::Site as GrantSite>::PARAMS;

    // A site that names fewer segments than the key parses would have
    // the surplus silently dropped — a folder-scoped route loading an
    // object from another folder. Refuse instead.
    if params_named.len() != T::Key::SEGMENTS.len() {
        return Err(Refusal::Auth(AuthError::PolicyFailed(format!(
            "route names {} key segment(s) but the key takes {}",
            params_named.len(),
            T::Key::SEGMENTS.len(),
        ))));
    }

    if T::Key::SEGMENTS.is_empty() {
        return Ok(T::Key::parse(&[])?);
    }

    // `RawPathParams` borrows `UrlParams` rather than removing it, so a
    // handler may still take its own `Path`.
    let params = axum::extract::RawPathParams::from_request_parts(parts, state)
        .await
        // A route that names key segments but exposes no path parameters
        // is a router the macro and the site disagree about, not a bad
        // request.
        .map_err(|rejection| {
            Refusal::Auth(AuthError::PolicyFailed(format!(
                "route path parameters unavailable: {rejection}"
            )))
        })?;

    let mut raw = Vec::with_capacity(params_named.len());
    for name in params_named {
        let value = params
            .iter()
            .find(|(param, _)| param == name)
            .map(|(_, value)| value)
            .ok_or_else(|| {
                Refusal::Auth(AuthError::PolicyFailed(format!(
                    "route has no path parameter `{name}`"
                )))
            })?;
        raw.push(value);
    }

    Ok(T::Key::parse(&raw)?)
}

// ---------------------------------------------------------------------------
// OpenAPI
// ---------------------------------------------------------------------------

/// Map a [`ResourceIdType`] to the OpenAPI schema for one key segment.
fn segment_schema(kind: ResourceIdType) -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
    use utoipa::openapi::schema::{KnownFormat, SchemaFormat};
    use utoipa::openapi::{ObjectBuilder, RefOr, Schema, Type};

    let mut b = ObjectBuilder::new();
    b = match kind {
        ResourceIdType::String => b.schema_type(Type::String),
        ResourceIdType::Integer => b
            .schema_type(Type::Integer)
            .format(Some(SchemaFormat::KnownFormat(KnownFormat::Int64))),
        ResourceIdType::Uuid => b
            .schema_type(Type::String)
            .format(Some(SchemaFormat::KnownFormat(KnownFormat::Uuid))),
    };
    RefOr::T(Schema::Object(b.build()))
}

/// Segments come from [`GrantSite::PARAMS`] paired with the key's own
/// [`RouteKey::SEGMENTS`], never from the positional template list — the
/// site is authoritative about which segments feed the key, and in what
/// order.
impl<T: Subject> doxa::DocPathParams for Granted<T> {
    fn describe(op: &mut utoipa::openapi::path::Operation, _positional: &[&'static str]) {
        use utoipa::openapi::path::{ParameterBuilder, ParameterIn};
        use utoipa::openapi::Required;

        let name_of = T::doc_name();
        let params_named = <T::Site as GrantSite>::PARAMS;
        let composite = params_named.len() > 1;

        for (segment, kind) in params_named.iter().zip(T::Key::SEGMENTS) {
            let description = if composite {
                format!("`{segment}` segment of the {name_of} identifier")
            } else {
                format!("Identifier of the {name_of}")
            };

            let param = ParameterBuilder::new()
                .name(*segment)
                .parameter_in(ParameterIn::Path)
                .required(Required::True)
                .description(Some(description))
                .schema(Some(segment_schema(*kind)))
                .build();
            op.parameters.get_or_insert_with(Vec::new).push(param);
        }
    }
}

impl<T: Subject> doxa::DocOperationSecurity for Granted<T> {
    fn describe(op: &mut utoipa::openapi::path::Operation) {
        let name_of = T::doc_name();
        let action = <T::Site as GrantSite>::ACTION;
        let display = match T::FORM {
            SubjectForm::Instance => format!("{action} on {name_of} (instance)"),
            SubjectForm::Collection => format!("{action} on {name_of} (collection)"),
            SubjectForm::Capability => format!("`{name_of}` capability"),
        };
        let scheme = <T::Site as GrantSite>::SCHEME;
        doxa::record_required_permission(op, scheme, &T::permission(action), &display);
    }
}

impl<T: Subject> doxa::DocOperationContribution for Granted<T> {
    fn contribution() -> doxa::OperationContribution {
        let name_of = T::doc_name();
        let action = <T::Site as GrantSite>::ACTION;

        let denied = match T::FORM {
            SubjectForm::Instance => format!("Policy denied `{action}` on this {name_of}"),
            SubjectForm::Collection => format!("No authorized scope on {name_of}"),
            SubjectForm::Capability => format!("Capability `{name_of}` denied"),
        };

        let contribution = doxa::OperationContribution::new()
            .with_response(doxa::ResponseContribution::unauthorized())
            .with_response(doxa::ResponseContribution::new("403", denied));

        // Only the instance form reads a key out of the route and loads
        // an object, so only it can answer 400 or 404.
        if T::FORM != SubjectForm::Instance {
            return contribution;
        }

        contribution
            .with_response(doxa::ResponseContribution::new(
                "400",
                format!("Malformed {name_of} identifier"),
            ))
            .with_response(doxa::ResponseContribution::new(
                "404",
                format!("No such {name_of}"),
            ))
    }
}
