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
//! ## When the guard cannot see it
//!
//! A guard runs in `FromRequestParts`, before the body exists. For what a
//! handler finds in that body there are three more doors, all recording
//! exactly as the guard does:
//!
//! | Door | For |
//! |------|-----|
//! | [`authorize::<One<R>>`](authorize) | an id the handler parsed, loaded through [`Granting::State`] |
//! | [`AuthorizeLoaded`] | an object the handler already holds, or one inside its open transaction |
//! | [`AuthorizeLoadedAll`] | *several* such objects, decided in one pass and named individually in the trail |
//! | [`AuthorizeScope`] / [`Scoped`] | *which* objects it may query for at all, as a filter |
//!
//! ```ignore
//! // the route's own subject, where no extractor could reach it
//! let widget = find_widget(&txn, tenant, &name).await?
//!     .authorize::<WidgetByName, _>(widget_action::Read, &parts.extensions).await?;
//!
//! // something its body merely refers to: this route's guard already
//! // answered the coarse question, and it was a different one
//! let folder = find_folder(&txn, tenant, &body.folder).await?
//!     .authorize_dependency::<FolderByName, _>(folder_action::Read, &parts.extensions).await?;
//!
//! // several of them, in one query and one pass through the policy — and
//! // the refusal still names the folder that caused it
//! let folders = Folder::load_all_scoped(body.folders, &txn, tenant).await?
//!     .authorize_all_dependency::<FolderByName, _>(folder_action::Read, &parts.extensions).await?;
//!
//! // or, when the handler is building the query rather than holding the
//! // rows: the subset itself, as a filter
//! let scope = FolderByName::authorize_scope_dependency(
//!     folder_action::Read, &parts.extensions,
//! )?;
//! let folders = scope.filter(Column::Name.is_in(body.folders)).all(&txn).await?;
//! ```
//!
//! The last two answer different questions. [`AuthorizeLoadedAll`] decides
//! about rows the caller *named*, so a refusal can say which one; the scope
//! decides what the caller may see at all, so it records one verdict about
//! the collection and the rows never leave the database.
//!
//! The turbofish on the first two is the *descriptor* — the asset whose
//! vocabulary governs the check — because a row does not imply one. See
//! [`AuthorizeLoaded`](AuthorizeLoaded#naming-the-descriptor).
//!
//! The action is a type rather than a string — one of the markers
//! `#[derive(Actions)]` emits — so an asset that does not permit it fails
//! the build, as it does for a route.
//!
//! ## What the handler owes the audit trail
//!
//! Nothing. The chain already knows which action it checked, which object
//! it checked it against, and — from the [`Action`] row in the asset's
//! [`Granting::ACTIONS`] — which category to file that under, so it
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
//!
//! The typed context is shared rather than copied — [`AuthLayer`] builds
//! one per request and every reader after that holds an `Arc` of it — so
//! a handler taking both a guard and an `Auth<S, C>` pays for the
//! assembled session once.
//!
//! [`AuthLayer`]: crate::AuthLayer

use std::borrow::Cow;
use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::response::{IntoResponse, Response};
use http::Extensions;

use doxa_policy::{
    AuthError, Capability, CapabilityChecker, Capable, PolicyResource, ResourceEntity, ResourceId,
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
/// generics) and for `Arc<`[`AuthContext<S, C>`]`>` (claims + resolved
/// session). An asset picks one as its [`Subject::Ctx`]; a collection
/// asset needs the typed form, because the authorized scope lives in the
/// session the policy assembled.
///
/// The typed form is behind an `Arc` because recovering it is a move,
/// not a borrow — the guard hands the context to the handler, so it has
/// to own one. `AuthLayer` builds it once per request and every reader
/// after that costs a refcount bump. Field access reads straight
/// through, so `ctx.claims.sub()` is unchanged.
pub trait FromAuthExtensions: Clone + Send + Sync + 'static {
    /// Recover the context, or `None` when the auth layer never ran.
    fn from_extensions(extensions: &Extensions) -> Option<Self>;

    /// Tenancy boundary the policy check runs within.
    fn tenant(&self) -> Option<&str>;

    /// Roles asserted for the caller.
    fn roles(&self) -> &[String];

    /// Whether the policy resolved this caller as unrestricted.
    ///
    /// Read where a door reaches a verdict *without* consulting the
    /// checker — [`Scoping::scope`], which is a function of the context
    /// alone. Every other door goes through the capability checker, which
    /// applies whatever admin rule the policy has for itself; the scope
    /// path has nowhere else to learn it, and without this an
    /// administrator would be handed the filtered subset a filter-aware
    /// asset builds while every other route gave them everything.
    ///
    /// Default: `false`. A context that does not model an administrator
    /// has none, which is the safe direction.
    fn is_admin(&self) -> bool {
        false
    }
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

impl<S, C> FromAuthExtensions for Arc<AuthContext<S, C>>
where
    S: Send + Sync + 'static,
    C: Claims,
{
    fn from_extensions(extensions: &Extensions) -> Option<Self> {
        extensions.get::<Arc<AuthContext<S, C>>>().cloned()
    }

    fn tenant(&self) -> Option<&str> {
        self.claims.scope()
    }

    fn roles(&self) -> &[String] {
        self.claims.roles()
    }

    /// The flag `AuthLayer` set when it resolved the session — the same
    /// answer the policy's own admin rule gave, carried rather than
    /// re-derived.
    fn is_admin(&self) -> bool {
        self.is_admin
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

// Both halves of the pair are foreign, so a consumer whose rows are
// keyed by UUID — most of them — cannot write this impl and has to
// wrap the type. Declaring it here is what keeps `{id}` a `Uuid` in
// the handler and `format: uuid` in the generated OpenAPI without a
// newtype in between.
#[cfg(feature = "uuid")]
scalar_key!(uuid::Uuid, ResourceIdType::Uuid);

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
    /// The loader's state could not be extracted from the request.
    ///
    /// Only reachable for a [`Granting::Source`] that is a real extractor;
    /// [`FromState`] cannot fail. The rejection is already rendered,
    /// because an extractor's own is the right answer here — a missing
    /// `Extension<Txn>` is a wiring fault and should say so rather than
    /// being flattened into a denial the caller would read as a 403.
    ///
    /// Boxed because it is the rarest variant and by far the largest: a
    /// `Response` is a header map and a body handle, and inlining it would
    /// widen every `Result<_, Refusal<_>>` on the success path — which is
    /// every guard in the service.
    Source(Box<Response>),
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
            Refusal::Source(response) => *response,
            Refusal::Load(error) => error.into_response(),
        }
    }
}

/// Why a decision about an object *already in hand* went against the
/// caller.
///
/// [`Refusal`] spans everything that can go wrong between a route segment
/// and a verdict, which is right for an extractor: it parses a key, it
/// loads a row, and either can fail. [`AuthorizeLoaded`] does neither, so
/// [`Refusal::Key`], [`Refusal::NotFound`] and [`Refusal::Load`] are
/// unreachable through it — arms a `match` has to carry, that nothing can
/// ever exercise, and that reviewers still have to keep correct.
///
/// Note the missing type parameter. `Refusal<E>` is generic only because
/// of [`Refusal::Load`], so a door that cannot load has no use for `E`
/// either.
///
/// Converts into a [`Refusal`], so a handler whose own error type is the
/// wider one loses nothing by starting here:
///
/// ```ignore
/// // `?` widens the denial; the three impossible variants are simply
/// // never constructed.
/// let folder = find_folder(&txn, tenant, name)
///     .await?
///     .authorize_dependency::<FolderByName, _>(folder_action::Read, &parts.extensions)
///     .await?;
/// ```
#[derive(Debug)]
pub enum Denial {
    /// The policy refused. Recorded once, by whichever door reached it.
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
    /// No auth context, no checker, or a policy that failed to decide.
    Auth(AuthError),
}

impl From<AuthError> for Denial {
    fn from(error: AuthError) -> Self {
        Denial::Auth(error)
    }
}

impl<E> From<Denial> for Refusal<E> {
    fn from(denial: Denial) -> Self {
        match denial {
            Denial::Denied {
                action,
                resource_type,
                resource_id,
                reason,
            } => Refusal::Denied {
                action,
                resource_type,
                resource_id,
                reason,
            },
            Denial::Auth(error) => Refusal::Auth(error),
        }
    }
}

impl IntoResponse for Denial {
    fn into_response(self) -> Response {
        match self {
            Denial::Denied { .. } => AuthError::Forbidden.into_response(),
            Denial::Auth(error) => error.into_response(),
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
/// Both traits here are unnameable outside this crate. A raw chain
/// records nothing, so a door onto it would be a way to authorize
/// something and leave no audit row — the failure this module is built to
/// prevent. There is no such door: every entry point that reaches a
/// verdict goes on to record it.
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
        /// Read off the asset's `Action` row for the two asset-backed
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
    /// What the chain's loader is handed.
    type State: Send + Sync;
    /// How the guard gets hold of it out of a request. See
    /// [`LoaderSource`].
    type Source: LoaderSource<State = Self::State>;
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

    /// Compile-time proof that this subject's action table is coherent
    /// and permits the action its [`Site`](Self::Site) names.
    ///
    /// Forced where the extractor is instantiated, so a route whose
    /// [`GrantSite::ACTION`] is missing from its asset's
    /// [`Granting::ACTIONS`] — or whose asset names one action twice, so
    /// that the gate would silently use whichever row came first — fails
    /// to build rather than being discovered the first time someone
    /// exercises it.
    #[doc(hidden)]
    const SITE_DECLARED: ();

    /// What this subject is about, for documentation prose — the Cedar
    /// entity type for a resource, the capability name for a bare gate.
    fn doc_name() -> Cow<'static, str>;

    /// Permission name for the OpenAPI badge, given the route's action.
    fn permission(action: &str) -> Cow<'static, str>;
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

/// What one action costs on one asset.
///
/// A row in [`Granting::ACTIONS`], which is the whole vocabulary of what
/// may be done to an asset and the only place any of it is declared: the
/// coarse capability, the audit category, and the existence of the action
/// at all come off this one row, so they cannot drift apart the way three
/// separate `match` arms could.
///
/// Built in a `const`:
///
/// ```
/// # use doxa_auth::granted::Action;
/// # use doxa_policy::{Capability, CapabilityCheck, ResourceId};
/// # const SOURCES_READ: Capability = Capability {
/// #     name: "sources.read",
/// #     description: "Read sources",
/// #     checks: &[CapabilityCheck {
/// #         action: "read_source",
/// #         entity_type: "SourceCollection",
/// #         entity_id: ResourceId::Literal("collection"),
/// #     }],
/// # };
/// const ACTIONS: &[Action] = &[
///     Action::new("read_source")
///         .capability(&SOURCES_READ)
///         .event("data_access"),
///     Action::new("ping"),
/// ];
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Action {
    /// Cedar action name, as a route's [`GrantSite::ACTION`] names it.
    pub name: &'static str,
    /// Coarse capability covering it, checked before any load so an
    /// unauthorized caller costs no query.
    pub capability: Option<&'static Capability>,
    /// Domain event category routes using this action are filed under —
    /// the `event_type` field on the audit event.
    ///
    /// The one part of an audit event a guard cannot work out for itself:
    /// what counts as a category is the application's to say. Declaring
    /// it beside the action rather than per route is what stops a verb
    /// disagreeing with the category it was recorded as.
    pub event_type: Option<&'static str>,
}

impl Action {
    /// An action with no coarse capability and no audit category: the
    /// instance check alone decides it.
    pub const fn new(name: &'static str) -> Self {
        Action {
            name,
            capability: None,
            event_type: None,
        }
    }

    /// Gate this action behind a capability, checked before any load.
    pub const fn capability(mut self, capability: &'static Capability) -> Self {
        self.capability = Some(capability);
        self
    }

    /// File this action's audit events under `event_type`.
    ///
    /// Pass the `'static` string a variant of your own event enum stands
    /// for — `doxa_audit::EventType::as_static` is the shape to copy.
    pub const fn event(mut self, event_type: &'static str) -> Self {
        self.event_type = Some(event_type);
        self
    }
}

#[cfg(feature = "catalog")]
inventory::collect!(&'static Action);

/// Every action declared by a `#[derive(Actions)]` enum anywhere in the
/// linked binary, sorted by name.
///
/// The sibling of [`doxa_policy::capabilities`], and needed for the same
/// reason: something outside the guard consumes this vocabulary and
/// cannot name it. A Cedar policy set is evaluated against an entity for
/// each action, and that entity set is built at startup — from a list
/// which, without this, is hand-maintained. An action added to a catalog
/// enum and forgotten there does not fail: Cedar simply never matches the
/// entity, and the policy that mentions it never fires.
///
/// The capability catalog answers half the question already, since every
/// [`CapabilityCheck`](doxa_policy::CapabilityCheck) names an action. What
/// it cannot see is an `#[action(instance_only)]` row, which declares no
/// capability precisely because the instance check is the whole of it.
///
/// ## What it cannot see
///
/// A hand-written [`Granting::ACTIONS`] table. Registration happens in the
/// derive, so a table written out by hand is absent here with no error —
/// as is any action in a crate the binary does not link. Assert the count
/// in a test if the set matters.
///
/// One name may appear more than once: two assets declaring `"read"` are
/// two rows, with two capabilities and possibly two audit categories, and
/// collapsing them here would lose that. Deduplicate on the way out if
/// what you want is the Cedar vocabulary:
///
/// ```ignore
/// let names: BTreeSet<_> = doxa::auth::actions()
///     .into_iter()
///     .map(|action| action.name)
///     .collect();
/// ```
///
/// ## Ordering
///
/// Sorted by [`Action::name`], and that is a promise rather than an
/// accident of the registry. Duplicates are therefore adjacent, so a
/// caller building a Cedar `Action` entity set — where a repeated UID is
/// not merely untidy but a parse failure — can use [`Vec::dedup`] instead
/// of a set. Nothing else about the order is specified: two rows sharing a
/// name may come back either way round.
///
/// Requires the `catalog` feature, on by default.
#[cfg(feature = "catalog")]
pub fn actions() -> Vec<&'static Action> {
    let mut all: Vec<&'static Action> = inventory::iter::<&'static Action>
        .into_iter()
        .copied()
        .collect();
    all.sort_unstable_by_key(|action| action.name);
    all
}

/// An asset's action vocabulary, as a bound rather than an inherent const.
///
/// `#[derive(Actions)]` has always emitted `WidgetAction::ACTIONS`, and for
/// the ordinary wiring — `const ACTIONS = WidgetAction::ACTIONS;` — that is
/// enough, because a path substitution resolves an inherent const as
/// readily as a trait one. The derive still emits it, and this trait is
/// where the array now lives.
///
/// The bound is for the code that cannot name the enum: something generic
/// over the vocabulary it authorizes against, or a startup seeding Cedar's
/// action entities from whatever tables it was handed. Neither can write
/// `WidgetAction::` at all.
///
/// ```
/// # use doxa_auth::granted::{Action, ActionTable};
/// /// Every action, whichever vocabulary declared it.
/// fn names<A: ActionTable>() -> Vec<&'static str> {
///     A::ACTIONS.iter().map(|action| action.name).collect()
/// }
///
/// enum WidgetAction {}
/// impl ActionTable for WidgetAction {
///     const ACTIONS: &'static [Action] = &[Action::new("read"), Action::new("delete")];
/// }
///
/// assert_eq!(names::<WidgetAction>(), ["read", "delete"]);
/// ```
///
/// It also moves the diagnosis. A type with no vocabulary passed where one
/// is wanted fails as ``no associated item named `ACTIONS` `` somewhere
/// inside a macro expansion; with the bound the error names this trait and
/// the type that does not implement it.
///
/// The supertraits are the ones [`Granting`] already imposes on the asset,
/// so a type parameterized by its vocabulary carries them without adding
/// any of its own.
pub trait ActionTable: Send + Sync + 'static {
    /// Every action this vocabulary permits, as [`Granting::ACTIONS`]
    /// takes it.
    const ACTIONS: &'static [Action];
}

/// A type standing for one Cedar action.
///
/// Actions are named by string almost everywhere — [`Action::new`] takes
/// one, [`GrantSite::ACTION`] is one — because a `const` table is what
/// makes [`Subject::SITE_DECLARED`] possible, and a trait method cannot be
/// called in a `const`. A route pays nothing for that: the macro's site
/// type carries the string, and the assertion runs where the route is
/// instantiated.
///
/// [`AuthorizeLoaded`] has no site, so until this trait existed it was the
/// one door that checked its action when the request arrived. Naming a
/// type instead of a string moves that check back to the build, and
/// `#[derive(Actions)]` emits one of these per variant, so an asset with a
/// derived vocabulary has the types already.
///
/// For a hand-written [`Granting::ACTIONS`] table it is three lines:
///
/// ```
/// # use doxa_auth::granted::DeclaredAction;
/// pub struct ReadWidget;
/// impl DeclaredAction for ReadWidget {
///     const ACTION: &'static str = "read_widget";
/// }
/// ```
pub trait DeclaredAction: Send + Sync + 'static {
    /// The Cedar action name, as [`Granting::ACTIONS`] spells it.
    const ACTION: &'static str;
}

/// `&str` equality in a const context, which `==` is not.
const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Whether `actions` permits `name`.
///
/// `const`, so a route can prove at build time that the action it names is
/// one its asset declares — which is what [`Subject::SITE_DECLARED`] does
/// for every route the macro generates.
pub const fn declares(actions: &[Action], name: &str) -> bool {
    let mut i = 0;
    while i < actions.len() {
        if str_eq(actions[i].name, name) {
            return true;
        }
        i += 1;
    }
    false
}

/// Whether every row in `actions` names a different action.
///
/// A repeated name is always a mistake, and a quiet one: the gate takes
/// the first row it matches, so the second row's capability and audit
/// category are simply never used. That reads as a capability being
/// enforced when it is not — the failure mode this module exists to make
/// impossible — so a route guarding such an asset fails the build rather
/// than picking one. See [`Subject::SITE_DECLARED`].
///
/// Two capabilities over one Cedar action cannot be told apart by a
/// coarse gate, which has only the action to go on. Where they really are
/// different permissions, they need different actions; where they are
/// not, one of them is redundant.
pub const fn distinct(actions: &[Action]) -> bool {
    let mut i = 0;
    while i < actions.len() {
        let mut j = i + 1;
        while j < actions.len() {
            if str_eq(actions[i].name, actions[j].name) {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

/// The row covering `action`, or `None` if the asset does not permit it.
///
/// Takes the first match; [`distinct`] is what makes that unambiguous.
///
/// Deliberately not a [`Granting`] method: the gate reads the table
/// directly, so no override can put the capability an action is checked
/// against out of step with whether that action exists.
fn declared<R: Granting>(action: &str) -> Option<&'static Action> {
    R::ACTIONS.iter().find(|declared| declared.name == action)
}

/// The caller shape, state and loader failure an application uses
/// everywhere, stated once.
///
/// These three are properties of the *application*, not of any asset:
/// every route in a service reaches the same database through the same
/// session type and fails the same way. [`Granting`] used to ask for them
/// per asset, so a service with six assets wrote them six times and the
/// declaration was mostly transcription.
///
/// ```
/// # use doxa_auth::granted::{FromState, GrantProfile};
/// # use doxa_auth::CapabilityContext;
/// # use axum::http::StatusCode;
/// pub struct AppGrants;
///
/// impl GrantProfile for AppGrants {
///     type Ctx = CapabilityContext;
///     type State = ();
///     type Source = FromState<()>;
///     type Error = StatusCode;
/// }
/// ```
///
/// An asset that genuinely differs — a loader that answers 409 on an
/// ambiguous name, say — overrides that one associated type on its own
/// [`Granting`] impl and keeps the profile for the rest.
pub trait GrantProfile: Send + Sync + 'static {
    /// Caller shape this application's chains need. [`CapabilityContext`]
    /// is enough for instance routes; a collection route needs
    /// [`AuthContext<S, C>`] to reach the assembled session.
    type Ctx: FromAuthExtensions;
    /// What loaders are handed.
    type State: Send + Sync;
    /// How the guard gets hold of it out of a request.
    ///
    /// [`FromState<Self::State>`](FromState) for state that lives in the
    /// router, which is nearly always the answer. Any other extractor
    /// works — see [`LoaderSource`] for the case that wants one.
    type Source: LoaderSource<State = Self::State>;
    /// Loader failure. Reaches the client through its own
    /// `IntoResponse`, so any audit outcome it attaches survives.
    type Error: IntoResponse + Send;
}

/// Everything asset-specific about reaching one object: which actions
/// the asset permits and what each one costs, and how to load one.
///
/// One impl per *route key* serves every route that guards it. The route
/// supplies only what is route-specific — which segments carry the key,
/// and which action the verb implies.
///
/// # The descriptor and the row
///
/// [`Row`](Self::Row) is what gets loaded and what Cedar is asked about;
/// `Self` is the descriptor that says how to reach it. Usually they are
/// the same type and `type Row = Self;` is the whole of it.
///
/// They come apart when one row is addressed two ways — by name on one
/// route and by id on another. [`Key`](Self::Key) is a single associated
/// type, so that is two impls and therefore two types; making the row a
/// separate one means the second descriptor is a unit struct rather than
/// a newtype:
///
/// ```ignore
/// pub struct WidgetById;
///
/// impl Granting for WidgetById {
///     type Row = Source;      // same Cedar entity as the by-name route
///     type Key = Uuid;
///     // …
/// }
/// ```
///
/// That matters beyond tidiness. A newtype would carry its own
/// [`PolicyResource`] forwarding, so two routes over one row could come
/// to disagree about the object's Cedar id — and a policy granting on one
/// identity silently fails to govern the route that names the other. With
/// the row named rather than wrapped there is one identity and no way to
/// state a second.
///
/// Listing is [`Scoping`], a separate trait, because not every asset can
/// be listed — a staged batch or a singleton is reached by name and by
/// nothing else. Splitting them is what lets the compiler say so.
pub trait Granting: Sized + Send + Sync + 'static {
    /// What the loader returns and the policy decides about.
    ///
    /// `Self` in the ordinary case. See the note above for when it is not.
    type Row: PolicyResource;
    /// Identifying values [`load`](Self::load) needs.
    type Key: RouteKey;
    /// Caller shape this asset's chain needs. Usually
    /// `<Self::Profile as GrantProfile>::Ctx`, which the `#[asset]`
    /// attribute writes for you.
    type Ctx: FromAuthExtensions;
    /// What [`load`](Self::load) is handed.
    type State: Send + Sync;
    /// How the guard gets hold of it out of a request. See
    /// [`LoaderSource`].
    type Source: LoaderSource<State = Self::State>;
    /// Loader failure. Reaches the client through its own
    /// `IntoResponse`, so any audit outcome it attaches survives.
    type Error: IntoResponse + Send;

    /// Every action this asset permits, and what each one costs.
    ///
    /// The vocabulary, not a hint: an action absent from here is refused
    /// before anything is loaded and before [`Scoping::scope`] is
    /// consulted, so a route that names one an asset does not declare
    /// cannot fall through to an unchecked grant. Routes are held to it at
    /// compile time — see [`Subject::SITE_DECLARED`].
    ///
    /// ```
    /// # use doxa_auth::granted::Action;
    /// const ACTIONS: &[Action] = &[
    ///     Action::new("read_source").event("data_access"),
    ///     Action::new("delete_source").event("admin_delete"),
    /// ];
    /// ```
    const ACTIONS: &'static [Action];

    /// Fetch one object, or `None` if there is no such thing.
    fn load(
        key: Self::Key,
        state: &Self::State,
        ctx: &Self::Ctx,
    ) -> impl Future<Output = Result<Option<Self::Row>, Self::Error>> + Send;
}

/// An asset a caller can be granted a *subset* of, rather than one
/// object at a time.
///
/// [`Many<R>`] requires it, so `Granted<Many<Widget>>` does not compile
/// unless listing a widget is a thing the asset says it supports.
/// Without the split every asset declared a `Filter` whether or not it
/// had a listing route, and a collection guard over one that did not
/// answered 403 at runtime — the right status for what is really a
/// category error the compiler could have caught.
pub trait Scoping: Granting {
    /// The caller's authorized subset, as this asset's queries take it.
    type Filter: Send;

    /// The caller's authorized scope on this asset for `action`, read out
    /// of the session the policy already assembled.
    ///
    /// `Ok(None)` means the policy granted nothing here, which
    /// [`empty_scope`](Self::empty_scope) then turns into a refusal or an
    /// empty page.
    ///
    /// The action is supplied because a collection route runs no
    /// instance check — there is no instance yet — so this and the
    /// capability on the [`Action`] row are the whole of what separates
    /// listing an asset from bulk-deleting it. An impl that ignores the
    /// action grants the same subset to both.
    fn scope(action: &str, ctx: &Self::Ctx) -> Result<Option<Self::Filter>, AuthError>;

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

    /// The scope for a caller the policy resolved as unrestricted, when
    /// this asset has one.
    ///
    /// Consulted before [`scope`](Self::scope) whenever
    /// [`FromAuthExtensions::is_admin`] holds, because this is the one
    /// door that reaches a verdict without the capability checker — and so
    /// the one place an administrator would otherwise be handed the same
    /// filtered subset as anyone else. Every other door asks the checker,
    /// which applies the policy's own admin rule.
    ///
    /// `None` — the default — means this asset draws no distinction, and
    /// an admin gets whatever [`scope`](Self::scope) returns. That is right
    /// for a scope that is only tenancy: an administrator of a tenant is
    /// still inside it. It is wrong for a scope carrying a policy
    /// condition, where "unrestricted" has to be sayable, and only the
    /// asset can say it — `Entity::find()` for a SeaORM listing, whatever
    /// the equivalent is elsewhere.
    ///
    /// It cannot widen a check anything else performed: a collection route
    /// still passes the coarse capability first, and an admin who fails
    /// that is refused before this is reached.
    fn unscoped() -> Option<Self::Filter> {
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
///
/// Requires [`Scoping`] rather than [`Granting`]: an asset that cannot
/// be listed does not implement it, and this form will not compile
/// against one.
pub struct Many<R, S = DefaultSite>(PhantomData<fn() -> (R, S)>);

/// Authorize a bare capability with no asset behind it.
///
/// Reads nothing out of the router, so it mounts on any state — see
/// [`NoState`].
pub struct Cap<M, S = DefaultSite>(PhantomData<fn() -> (M, S)>);

// ---------------------------------------------------------------------------
// Loader state
// ---------------------------------------------------------------------------

/// Where a loader's state comes from, and how the guard gets hold of it.
///
/// [`Granting::State`] is what a loader queries — a connection, a client,
/// a store. This is what the *request* yields, which is not always the
/// same thing: state living in the router arrives through `FromRef`, and
/// state living in the request — a transaction a layer opened, a handle
/// keyed to the caller — arrives through an extractor. Both are
/// `FromRequestParts`, so the guard extracts [`Granting::Source`] and then
/// asks it for the state.
///
/// Splitting the two is what keeps the loader signature honest. Were the
/// guard to extract the state directly, an asset wanting an extractor
/// would have to *name* the wrapper as its state, and every loader — the
/// ones `#[asset]` writes, and every manual call to [`authorize`] — would
/// be unwrapping a `State<DatabaseConnection>` to reach a database. The
/// wrapper is the guard's business, so it stays there.
pub trait LoaderSource: Send + Sync + 'static {
    /// What the loader is handed.
    type State: Send + Sync;

    /// Borrow it out of whatever the request produced.
    fn state(&self) -> &Self::State;
}

/// Loader state taken from the router's state.
///
/// The ordinary case, and what `#[asset]` writes unless told otherwise:
/// `FromState<DatabaseConnection>` as an asset's source means the loader
/// receives `&DatabaseConnection`, reached through `FromRef` exactly as it
/// was before there was anywhere else to reach.
///
/// The alternative is any other extractor. `Extension<Txn>` as a source
/// hands the loader `&Txn`, which is the case
/// [`ScopedTable::load_by_id`] is generic over the connection *for*: a
/// pool cannot see rows the request has written and not committed, so a
/// loader pinned to one answers `None` for an object the caller is
/// holding — and the route 404s on something it just created.
///
/// [`ScopedTable::load_by_id`]: https://docs.rs/doxa-policy/latest/doxa_policy/scoped/trait.ScopedTable.html#method.load_by_id
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FromState<T>(pub T);

impl<T: Send + Sync + 'static> LoaderSource for FromState<T> {
    type State = T;

    fn state(&self) -> &T {
        &self.0
    }
}

impl<St, T> FromRequestParts<St> for FromState<T>
where
    St: Send + Sync,
    T: axum::extract::FromRef<St>,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        _: &mut http::request::Parts,
        state: &St,
    ) -> Result<Self, Self::Rejection> {
        Ok(FromState(T::from_ref(state)))
    }
}

/// So a request-scoped handle is a source without a wrapper around a
/// wrapper: `type Source = Extension<Txn>` hands the loader `&Txn`.
impl<T: Send + Sync + 'static> LoaderSource for axum::Extension<T> {
    type State = T;

    fn state(&self) -> &T {
        &self.0
    }
}

/// [`Subject::State`] for a form that reads nothing from the router.
///
/// [`Cap`] has no loader, but [`Subject::State`] and [`Subject::Source`]
/// are bounds on the impl, so they still have to be satisfied by
/// something. Naming `()` would mean every stateful router owed an `impl
/// FromRef<AppState> for ()`, which is not a thing a consumer should have
/// to write and which the orphan rule makes awkward anyway. This is a
/// local type, so the impls below cover every router state there will
/// ever be.
///
/// It is its own source: there is nothing to extract, so going through
/// [`FromState`] would be a `FromRef` hop to reach a zero-sized value that
/// was already known.
#[derive(Debug, PartialEq, Eq, Default)]
pub struct NoState;

impl LoaderSource for NoState {
    type State = Self;

    fn state(&self) -> &Self {
        self
    }
}

impl<St: Send + Sync> FromRequestParts<St> for NoState {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        _: &mut http::request::Parts,
        _: &St,
    ) -> Result<Self, Self::Rejection> {
        Ok(NoState)
    }
}

/// The permission an asset-backed route advertises: the coarse
/// capability where the asset declares one, and the Cedar action
/// otherwise.
///
/// Shared by the instance and collection forms, which ask the same
/// question of the same asset — so a listing and a fetch cannot end up
/// documenting different permissions for the same verb.
fn asset_permission<R: Granting>(action: &str) -> Cow<'static, str> {
    match declared::<R>(action).and_then(|declared| declared.capability) {
        Some(cap) => Cow::Borrowed(cap.name),
        None => Cow::Owned(format!("{}:{action}", entity_type::<R>())),
    }
}

/// The Cedar entity type a descriptor's row names itself by.
///
/// Read through [`Granting::Row`] rather than off the descriptor, so two
/// routes over one row document and record the same entity.
const fn entity_type<R: Granting>() -> &'static str {
    <R::Row as PolicyResource>::ENTITY_TYPE
}

impl<R: Granting, S: GrantSite> sealed::Sealed for One<R, S> {}

impl<R: Granting, S: GrantSite> Subject for One<R, S> {
    type Loaded = R::Row;
    type Ctx = R::Ctx;
    type State = R::State;
    type Source = R::Source;
    type Key = R::Key;
    type Error = R::Error;
    type Site = S;

    const FORM: SubjectForm = SubjectForm::Instance;
    const SITE_DECLARED: () = {
        assert!(
            distinct(R::ACTIONS),
            "`Granting::ACTIONS` names one action twice; the later row never runs",
        );
        assert!(
            declares(R::ACTIONS, S::ACTION),
            "this route's action is missing from the asset's `Granting::ACTIONS`",
        );
    };

    fn doc_name() -> Cow<'static, str> {
        Cow::Borrowed(entity_type::<R>())
    }

    fn permission(action: &str) -> Cow<'static, str> {
        asset_permission::<R>(action)
    }
}

impl<R: Granting, S: GrantSite> Chain for One<R, S> {
    fn event_type(action: &str) -> Option<&'static str> {
        declared::<R>(action).and_then(|declared| declared.event_type)
    }

    async fn authorize(
        key: Self::Key,
        action: &'static str,
        state: &Self::State,
        ctx: &Self::Ctx,
        checker: &dyn CapabilityChecker,
    ) -> Result<Authorized<R::Row>, Refusal<R::Error>> {
        // Gate first: a caller who may not touch this kind of thing at
        // all should not cost a query, and must not be able to tell a
        // missing object from one they may not see.
        gate::<R>(action, ctx, checker).await?;

        let resource = R::load(key, state, ctx)
            .await
            .map_err(Refusal::Load)?
            .ok_or(Refusal::NotFound {
                entity_type: entity_type::<R>(),
            })?;

        let tenant = ctx.tenant().unwrap_or("");
        let entity = ResourceEntity::of(&resource, tenant);
        let allowed = checker
            .check_instance(tenant, ctx.roles(), action, &entity)
            .await?;

        if !allowed {
            return Err(Refusal::Denied {
                action: Cow::Borrowed(action),
                resource_type: Cow::Borrowed(entity_type::<R>()),
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
            resource_type: Cow::Borrowed(entity_type::<R>()),
            resource_id: Cow::Owned(entity.entity_id),
        })
    }
}

impl<R: Scoping, S: GrantSite> sealed::Sealed for Many<R, S> {}

impl<R: Scoping, S: GrantSite> Subject for Many<R, S> {
    type Loaded = R::Filter;
    type Ctx = R::Ctx;
    type State = R::State;
    type Source = R::Source;
    type Key = ();
    type Error = R::Error;
    type Site = S;

    const FORM: SubjectForm = SubjectForm::Collection;
    const SITE_DECLARED: () = {
        assert!(
            distinct(R::ACTIONS),
            "`Granting::ACTIONS` names one action twice; the later row never runs",
        );
        assert!(
            declares(R::ACTIONS, S::ACTION),
            "this route's action is missing from the asset's `Granting::ACTIONS`",
        );
    };

    fn doc_name() -> Cow<'static, str> {
        Cow::Borrowed(entity_type::<R>())
    }

    fn permission(action: &str) -> Cow<'static, str> {
        asset_permission::<R>(action)
    }
}

impl<R: Scoping, S: GrantSite> Chain for Many<R, S> {
    fn event_type(action: &str) -> Option<&'static str> {
        declared::<R>(action).and_then(|declared| declared.event_type)
    }

    async fn authorize(
        _key: (),
        action: &'static str,
        _state: &Self::State,
        ctx: &Self::Ctx,
        checker: &dyn CapabilityChecker,
    ) -> Result<Authorized<R::Filter>, Refusal<R::Error>> {
        gate::<R>(action, ctx, checker).await?;

        let scope = match R::scope(action, ctx)? {
            Some(scope) => scope,
            // The policy granted nothing on this asset. Whether that is a
            // refusal or an empty page is the asset's call.
            None => R::empty_scope().ok_or(Refusal::Denied {
                action: Cow::Borrowed(action),
                resource_type: Cow::Borrowed(entity_type::<R>()),
                resource_id: Cow::Borrowed("collection"),
                reason: "no authorized scope",
            })?,
        };

        // The same id the refusal above names, so a listing and a refused
        // listing sit under one resource in the trail.
        Ok(Authorized {
            loaded: scope,
            action: Cow::Borrowed(action),
            resource_type: Cow::Borrowed(entity_type::<R>()),
            resource_id: Cow::Borrowed("collection"),
        })
    }
}

impl<M: Capable, S: GrantSite> sealed::Sealed for Cap<M, S> {}

impl<M: Capable, S: GrantSite> Subject for Cap<M, S> {
    type Loaded = ();
    type Ctx = CapabilityContext;
    type State = NoState;
    type Source = NoState;
    type Key = ();
    type Error = std::convert::Infallible;
    type Site = S;

    const FORM: SubjectForm = SubjectForm::Capability;
    // Nothing to hold to a vocabulary: this form ignores the route's
    // action and asks about the capability itself.
    const SITE_DECLARED: () = ();

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
        _state: &NoState,
        ctx: &CapabilityContext,
        checker: &dyn CapabilityChecker,
    ) -> Result<Authorized<()>, Refusal<Self::Error>> {
        let tenant = ctx.tenant().unwrap_or("");
        let allowed = checker.check(tenant, ctx.roles(), M::CAPABILITY).await?;

        let (resource_type, resource_id) = capability_resource(M::CAPABILITY, tenant);

        if !allowed {
            return Err(Refusal::Denied {
                action: Cow::Borrowed(M::CAPABILITY.name),
                resource_type: Cow::Borrowed(resource_type),
                resource_id,
                reason: "capability denied",
            });
        }

        // The capability, not the verb: this chain never asked about the
        // route's action, and the refusal above names the capability too.
        Ok(Authorized {
            loaded: (),
            action: Cow::Borrowed(M::CAPABILITY.name),
            resource_type: Cow::Borrowed(resource_type),
            resource_id,
        })
    }
}

/// The resource a capability's verdict is about.
///
/// A capability is granted only when every one of its checks passes, so
/// the first is the one whose denial short-circuits the evaluation — and
/// the one worth naming in the trail. A capability with no checks at all
/// names itself.
///
/// Takes the tenant because a [`ResourceId::Tenant`] check is about that
/// tenant's collection, so the trail should say which one. It used to
/// record the literal sentinel, which named no resource that exists.
pub(crate) fn capability_resource(
    cap: &'static Capability,
    tenant: &str,
) -> (&'static str, Cow<'static, str>) {
    cap.checks
        .first()
        .map(|check| {
            let id = match check.entity_id {
                ResourceId::Literal(id) => Cow::Borrowed(id),
                ResourceId::Tenant => Cow::Owned(tenant.to_owned()),
            };
            (check.entity_type, id)
        })
        .unwrap_or(("capability", Cow::Borrowed(cap.name)))
}

/// The asset's own row for this action, or a refusal.
///
/// What makes [`Granting::ACTIONS`] a vocabulary rather than a lookup
/// table: an action absent from it is refused before anything else runs.
/// A collection route performs no instance check, so without this an
/// action the asset never heard of would reach [`Scoping::scope`] and be
/// answered with whatever subset that returns.
///
/// Every door checks it — [`gate`] on the way to a capability, and
/// [`AuthorizeLoaded`] on a resource that is already in hand — so an
/// undeclared action is refused identically however the check was
/// reached.
fn declared_action<R: Granting>(action: &'static str) -> Result<&'static Action, Denial> {
    declared::<R>(action).ok_or(Denial::Denied {
        action: Cow::Borrowed(action),
        resource_type: Cow::Borrowed(entity_type::<R>()),
        // The refusal is about the action, not about an object: for a
        // collection there will never be one, and for a resource already
        // loaded the asset does not admit the verb being asked about.
        resource_id: Cow::Borrowed("*"),
        reason: "action not declared",
    })
}

/// The gate both asset-backed chains pass through before they load or
/// scope anything: is this action one the asset permits, and if it is
/// gated behind a capability, does the caller hold it?
async fn gate<R: Granting>(
    action: &'static str,
    ctx: &R::Ctx,
    checker: &dyn CapabilityChecker,
) -> Result<&'static Action, Denial> {
    let declared = declared_action::<R>(action)?;

    let Some(cap) = declared.capability else {
        return Ok(declared);
    };

    if checker
        .check(ctx.tenant().unwrap_or(""), ctx.roles(), cap)
        .await?
    {
        return Ok(declared);
    }

    let (resource_type, resource_id) = capability_resource(cap, ctx.tenant().unwrap_or(""));

    Err(Denial::Denied {
        action: Cow::Borrowed(cap.name),
        resource_type: Cow::Borrowed(resource_type),
        resource_id,
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
    T::Source: FromRequestParts<St>,
{
    type Rejection = Refusal<T::Error>;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &St,
    ) -> Result<Self, Self::Rejection> {
        // Forces the assertion that the site's action is one the asset
        // declares. Costs nothing at runtime; fails the build if not.
        let () = T::SITE_DECLARED;

        let ctx = T::Ctx::from_extensions(&parts.extensions)
            .ok_or(Refusal::Auth(AuthError::MissingCredentials))?;

        let key = fetch_key::<T, St>(parts, state).await?;

        // The source is extracted, not read out of the router state, so a
        // loader may be handed something the request owns — a transaction
        // an earlier layer opened — rather than only a slice of `St`.
        let source = <T::Source as FromRequestParts<St>>::from_request_parts(parts, state)
            .await
            .map_err(|rejection| Refusal::Source(Box::new(rejection.into_response())))?;

        // Same entry point a handler uses, so the refusal is recorded by
        // the same code either way.
        let loaded =
            authorize::<T>(key, T::Site::ACTION, source.state(), &parts.extensions).await?;
        Ok(Granted(ctx, loaded))
    }
}

/// Authorize a subject against the caller and checker already resolved
/// into `extensions`, recording the verdict either way.
///
/// This is the body of [`Granted`], exposed for a subject the extractor
/// cannot reach. A guard runs in `FromRequestParts`, which sees no
/// request body, so an id named in a payload — one object referring to
/// another, or a request naming everything it means to touch — can only
/// be authorized from inside the handler that parsed it.
///
/// Like [`Granted`], it *loads* through [`Granting::State`] before
/// deciding. When the object is already in hand — or lives in a
/// transaction that state cannot see — reach for [`AuthorizeLoaded`]
/// instead, which decides without loading.
///
/// This, [`Granted`] and [`AuthorizeLoaded`] are the only ways to reach a
/// policy decision, and all three record through the same path. The chain
/// underneath is sealed and records nothing, so there is no fourth that
/// authorizes something and leaves no audit row — the choice of whether a
/// check is auditable was removed rather than documented.
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
    let (ctx, checker) = caller_and_checker::<T::Ctx>(extensions)?;

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

/// Recover the caller and the checker the auth layer put in extensions.
///
/// Shared by every door so that a request reaching one without an
/// [`AuthLayer`](crate::AuthLayer) above it fails the same way whichever
/// door it was.
fn caller_and_checker<C: FromAuthExtensions>(
    extensions: &Extensions,
) -> Result<(C, Arc<dyn CapabilityChecker>), Denial> {
    let ctx = C::from_extensions(extensions).ok_or(Denial::Auth(AuthError::MissingCredentials))?;

    let checker = extensions
        .get::<Arc<dyn CapabilityChecker>>()
        .cloned()
        .ok_or_else(|| {
            Denial::Auth(AuthError::PolicyFailed(
                "capability checker not configured on AuthLayer".into(),
            ))
        })?;

    Ok((ctx, checker))
}

/// Authorize an object the handler already has.
///
/// [`Granted`] and [`authorize`] both *load* before they decide, through
/// [`Granting::State`]. That is right for an id the route names, and
/// wrong for two cases a handler hits as soon as it authorizes anything
/// it read out of a request body:
///
/// - **The row is not visible to `State`.** It lives in a transaction the
///   handler has open and has not committed — an object declaring a
///   relationship to one the same request just wrote. A loader on the
///   state's own connection would not find it, and the request would be
///   answered `404` for something it had in hand.
/// - **The row is already loaded.** Resolving it a second time to decide
///   about it is a query bought for nothing.
///
/// Implemented for every [`PolicyResource`], so there is nothing to write
/// per asset — the vocabulary in [`Granting::ACTIONS`] and the identity
/// from [`PolicyResource`] are all this needs, and both already exist.
///
/// ```ignore
/// let folder = find_folder(&txn, tenant, &body.folder)
///     .await?
///     .ok_or(Error::NoSuchFolder)?
///     .authorize_dependency::<FolderByName, _>(folder_action::Read, &parts.extensions)
///     .await?;
/// ```
///
/// ## Naming the descriptor
///
/// The turbofish is the asset whose vocabulary and capability govern the
/// decision — not the row, which is the value the method is called on.
/// They are usually the same type and it reads as `::<Folder, _>`; they
/// come apart when one table is addressed two ways, and then the choice is
/// a real one, because each descriptor carries its own
/// [`ACTIONS`](Granting::ACTIONS).
///
/// It cannot be inferred. A descriptor knows its row, but a row does not
/// know its descriptors — there may be several — so leaving it out would
/// mean picking whichever impl existed today and breaking every call site
/// the day a second one was added. The load-through door names it the same
/// way, as `authorize::<One<R>>`.
///
/// ## Which of the two
///
/// [`authorize`](Self::authorize) is the whole check, the same one
/// `Granted<One<R>>` runs: the coarse capability gate, then the instance
/// check. Reach for it when nothing has gated this route — a handler
/// authorizing its own subject because no extractor could see it.
///
/// [`authorize_dependency`](Self::authorize_dependency) runs the instance
/// check alone, for an object the *route's own guard* has already cleared
/// the coarse question for. Re-asking it there is not merely redundant,
/// it is wrong: a caller who may write a widget naming a folder they may
/// read would be refused because they may not *list* folders, which is a
/// different question from the one the route is about.
///
/// Both refuse an action absent from [`Granting::ACTIONS`], and both
/// record — through the same path the guard does, so a decision reached
/// here is indistinguishable in the trail from one the extractor reached.
///
/// ## What reaches the audit event
///
/// The same deposit [`authorize`] makes, with the same precedence: the
/// route's own subject is authorized before the body is parsed, so it is
/// the one the event names and a dependency checked afterwards does not
/// displace it. A refusal displaces a grant, because a request that ends
/// on a denial is about that denial.
pub trait AuthorizeLoaded: PolicyResource {
    /// Coarse gate, then instance check, on an object already in hand.
    ///
    /// Returns the object, so an unauthorized binding never exists:
    ///
    /// ```ignore
    /// let widget = find_widget(&txn, tenant, name)
    ///     .await?
    ///     .authorize::<WidgetByName, _>(widget_action::Read, &parts.extensions)
    ///     .await?;
    /// ```
    ///
    /// The action is a type, so an asset that does not permit it is a
    /// build failure rather than a `403` at request time. `Widget`
    /// declares `read` and nothing else:
    ///
    /// ```
    /// # use doxa_auth::granted::{
    /// #     Action, AuthorizeLoaded, DeclaredAction, FromState, Granting,
    /// # };
    /// # use doxa_auth::CapabilityContext;
    /// # use doxa_policy::PolicyResource;
    /// # use std::convert::Infallible;
    /// # struct Widget;
    /// # impl PolicyResource for Widget {
    /// #     const ENTITY_TYPE: &'static str = "Widget";
    /// #     fn resource_id(&self) -> String { String::new() }
    /// # }
    /// # impl Granting for Widget {
    /// #     type Row = Self;
    /// #     type Key = String;
    /// #     type Ctx = CapabilityContext;
    /// #     type State = ();
    /// #     type Source = FromState<()>;
    /// #     type Error = Infallible;
    /// #     const ACTIONS: &'static [Action] = &[Action::new("read")];
    /// #     async fn load(_: String, _: &(), _: &CapabilityContext)
    /// #         -> Result<Option<Self>, Infallible> { Ok(None) }
    /// # }
    /// struct Read;
    /// impl DeclaredAction for Read {
    ///     const ACTION: &'static str = "read";
    /// }
    ///
    /// # let extensions = http::Extensions::new();
    /// let _ = Widget.authorize::<Widget, _>(Read, &extensions);
    /// ```
    ///
    /// Name one it does not, and the same call will not build:
    ///
    /// ```compile_fail
    /// # use doxa_auth::granted::{
    /// #     Action, AuthorizeLoaded, DeclaredAction, FromState, Granting,
    /// # };
    /// # use doxa_auth::CapabilityContext;
    /// # use doxa_policy::PolicyResource;
    /// # use std::convert::Infallible;
    /// # struct Widget;
    /// # impl PolicyResource for Widget {
    /// #     const ENTITY_TYPE: &'static str = "Widget";
    /// #     fn resource_id(&self) -> String { String::new() }
    /// # }
    /// # impl Granting for Widget {
    /// #     type Row = Self;
    /// #     type Key = String;
    /// #     type Ctx = CapabilityContext;
    /// #     type State = ();
    /// #     type Source = FromState<()>;
    /// #     type Error = Infallible;
    /// #     const ACTIONS: &'static [Action] = &[Action::new("read")];
    /// #     async fn load(_: String, _: &(), _: &CapabilityContext)
    /// #         -> Result<Option<Self>, Infallible> { Ok(None) }
    /// # }
    /// struct Purge;
    /// impl DeclaredAction for Purge {
    ///     const ACTION: &'static str = "purge";
    /// }
    ///
    /// # let extensions = http::Extensions::new();
    /// // error: this action is missing from the asset's `Granting::ACTIONS`
    /// let _ = Widget.authorize::<Widget, _>(Purge, &extensions);
    /// ```
    fn authorize<R: Granting<Row = Self>, A: DeclaredAction>(
        self,
        action: A,
        extensions: &Extensions,
    ) -> impl Future<Output = Result<Self, Denial>> + Send;

    /// Instance check only, for an object this route's guard has already
    /// cleared the coarse question for.
    ///
    /// Skips the capability gate *and nothing else* — the action must
    /// still be one the asset declares, and the policy must still permit
    /// it on this object. See [the trait docs](Self#which-of-the-two) for
    /// why the coarse question is the wrong one to ask about a dependency.
    ///
    /// This is also where the descriptor stops being a formality. The row
    /// below is reached by a unit struct rather than by itself — the shape
    /// an entity crate forces, since a row in one crate cannot name the
    /// application's caller or vocabulary in another — and the vocabulary
    /// governing the check is the descriptor's:
    ///
    /// ```
    /// # use doxa_auth::granted::{
    /// #     Action, AuthorizeLoaded, DeclaredAction, FromState, Granting,
    /// # };
    /// # use doxa_auth::CapabilityContext;
    /// # use doxa_policy::PolicyResource;
    /// # use std::convert::Infallible;
    /// # struct Widget;
    /// # impl PolicyResource for Widget {
    /// #     const ENTITY_TYPE: &'static str = "Widget";
    /// #     fn resource_id(&self) -> String { String::new() }
    /// # }
    /// struct WidgetById;
    ///
    /// impl Granting for WidgetById {
    ///     type Row = Widget;
    /// #     type Key = String;
    /// #     type Ctx = CapabilityContext;
    /// #     type State = ();
    /// #     type Source = FromState<()>;
    /// #     type Error = Infallible;
    ///     const ACTIONS: &'static [Action] = &[Action::new("read")];
    /// #     async fn load(_: String, _: &(), _: &CapabilityContext)
    /// #         -> Result<Option<Widget>, Infallible> { Ok(None) }
    ///     // …
    /// }
    ///
    /// # struct Read;
    /// # impl DeclaredAction for Read {
    /// #     const ACTION: &'static str = "read";
    /// # }
    /// # let extensions = http::Extensions::new();
    /// let _ = Widget.authorize_dependency::<WidgetById, _>(Read, &extensions);
    /// ```
    ///
    /// In particular the vocabulary check is not skipped, and it is the
    /// same build-time one, so the dependency form is not a way around
    /// it. The only difference from the call above is the action named,
    /// which is what makes this a test of the vocabulary rather than of
    /// the turbofish:
    ///
    /// ```compile_fail
    /// # use doxa_auth::granted::{
    /// #     Action, AuthorizeLoaded, DeclaredAction, FromState, Granting,
    /// # };
    /// # use doxa_auth::CapabilityContext;
    /// # use doxa_policy::PolicyResource;
    /// # use std::convert::Infallible;
    /// # struct Widget;
    /// # impl PolicyResource for Widget {
    /// #     const ENTITY_TYPE: &'static str = "Widget";
    /// #     fn resource_id(&self) -> String { String::new() }
    /// # }
    /// # struct WidgetById;
    /// # impl Granting for WidgetById {
    /// #     type Row = Widget;
    /// #     type Key = String;
    /// #     type Ctx = CapabilityContext;
    /// #     type State = ();
    /// #     type Source = FromState<()>;
    /// #     type Error = Infallible;
    /// #     const ACTIONS: &'static [Action] = &[Action::new("read")];
    /// #     async fn load(_: String, _: &(), _: &CapabilityContext)
    /// #         -> Result<Option<Widget>, Infallible> { Ok(None) }
    /// # }
    /// # struct Purge;
    /// # impl DeclaredAction for Purge {
    /// #     const ACTION: &'static str = "purge";
    /// # }
    /// # let extensions = http::Extensions::new();
    /// // error: this action is missing from the asset's `Granting::ACTIONS`
    /// let _ = Widget.authorize_dependency::<WidgetById, _>(Purge, &extensions);
    /// ```
    fn authorize_dependency<R: Granting<Row = Self>, A: DeclaredAction>(
        self,
        action: A,
        extensions: &Extensions,
    ) -> impl Future<Output = Result<Self, Denial>> + Send;
}

/// Blanket, and therefore the only implementation there can be: an asset
/// cannot override [`AuthorizeLoaded::authorize`] into something that
/// decides differently — or does not decide at all — because coherence
/// leaves no room for a second impl.
///
/// Implemented for the *row* rather than for the descriptor, which is what
/// keeps the call a method and the loader's `?` in front of it. The
/// descriptor is named on the method instead, because a row does not imply
/// one: [`Granting::Row`] is a separate associated type precisely so two
/// descriptors can address the same table, and picking whichever impl
/// happened to exist would silently change vocabulary the day a second one
/// was written.
impl<T: PolicyResource> AuthorizeLoaded for T {
    // Written as `-> impl Future` rather than `async fn` so the proof is
    // discharged when the method is *called*, not when the future is
    // first polled. A caller who names an action their asset does not
    // permit gets the error at the call site, awaited or not.
    fn authorize<R: Granting<Row = Self>, A: DeclaredAction>(
        self,
        _action: A,
        extensions: &Extensions,
    ) -> impl Future<Output = Result<Self, Denial>> + Send {
        let () = Declares::<R, A>::PROOF;
        decide::<R>(self, A::ACTION, extensions, Coarse::Check)
    }

    fn authorize_dependency<R: Granting<Row = Self>, A: DeclaredAction>(
        self,
        _action: A,
        extensions: &Extensions,
    ) -> impl Future<Output = Result<Self, Denial>> + Send {
        let () = Declares::<R, A>::PROOF;
        decide::<R>(self, A::ACTION, extensions, Coarse::Skip)
    }
}

/// [`AuthorizeLoaded`] for rows that arrived together.
///
/// A request body naming its references names several at once — a pipeline
/// declaring the models it reads, a document declaring the folders it
/// links. Authorized one at a time that is one policy call per row, and
/// each one assembles the same entity hierarchy before evaluating
/// anything. Asked together it is one assembly and one pass.
///
/// ```ignore
/// let sources = Source::load_all_scoped(body.sources, &txn, tenant).await?
///     .authorize_all_dependency::<SourceByName, _>(source_action::Read, &ext)
///     .await?;
/// ```
///
/// It is the same decision the singular door reaches, recorded the same
/// way: every row is deposited under its own id, and the request's event
/// keeps what the audit builder keeps — the refusal if there was one,
/// otherwise the first grant. That is what a loop of
/// [`AuthorizeLoaded::authorize_dependency`] already left, and it is the
/// useful half: a refused row is named, so a body reference and a path
/// segment are indistinguishable in the trail.
///
/// What it is *not* is [`AuthorizeScope`], which answers "which rows may
/// this caller see" as a filter and therefore records one verdict about a
/// collection, under the id `collection`. Reach for this when the caller
/// named the rows and has to be told which one was refused; reach for that
/// when the handler is building a query.
///
/// ## All or nothing
///
/// The first refusal, in order, refuses the whole call — matching what a
/// `?` inside a loop already did. Rows before it are recorded as granted,
/// because they were; rows after it are never asked about, because the
/// request is over.
pub trait AuthorizeLoadedAll<T: PolicyResource>: Sized {
    /// The coarse capability once, then an instance check per row.
    fn authorize_all<R: Granting<Row = T>, A: DeclaredAction>(
        self,
        action: A,
        extensions: &Extensions,
    ) -> impl Future<Output = Result<Vec<T>, Denial>> + Send;

    /// An instance check per row, for rows this route's own guard has
    /// already cleared the coarse question for.
    ///
    /// The plural of [`AuthorizeLoaded::authorize_dependency`], and skips
    /// exactly what that skips: a caller who may write a pipeline naming
    /// sources they may read should not be refused because they may not
    /// *list* sources.
    fn authorize_all_dependency<R: Granting<Row = T>, A: DeclaredAction>(
        self,
        action: A,
        extensions: &Extensions,
    ) -> impl Future<Output = Result<Vec<T>, Denial>> + Send;
}

/// Blanket for the same reason [`AuthorizeLoaded`]'s is, and on `Vec` so
/// the rows a plural loader returns go straight through.
impl<T: PolicyResource> AuthorizeLoadedAll<T> for Vec<T> {
    fn authorize_all<R: Granting<Row = T>, A: DeclaredAction>(
        self,
        _action: A,
        extensions: &Extensions,
    ) -> impl Future<Output = Result<Vec<T>, Denial>> + Send {
        let () = Declares::<R, A>::PROOF;
        decide_all::<R>(self, A::ACTION, extensions, Coarse::Check)
    }

    fn authorize_all_dependency<R: Granting<Row = T>, A: DeclaredAction>(
        self,
        _action: A,
        extensions: &Extensions,
    ) -> impl Future<Output = Result<Vec<T>, Denial>> + Send {
        let () = Declares::<R, A>::PROOF;
        decide_all::<R>(self, A::ACTION, extensions, Coarse::Skip)
    }
}

/// Authorize a *subset* of an asset the handler will query itself.
///
/// [`AuthorizeLoaded`] decides about rows already in hand, one at a time.
/// That is the right shape for a row the handler holds and the wrong one
/// for a request naming several — a body referring to three sources by
/// name is three instance checks, and each rebuilds the policy's entity set
/// before evaluating. This asks the other question: *which rows may this
/// caller see*, answered once, as a filter the handler ANDs into its own
/// query.
///
/// The filter is [`Scoping::Filter`], so what it costs to apply is the
/// asset's business — a `Select` for a SeaORM row, something else for
/// another store — and the rows a caller may not see never leave the
/// database.
///
/// ```ignore
/// // one query, inside the handler's own transaction
/// let scope = SourceByName::authorize_scope_dependency(
///     source_action::Read, &parts.extensions,
/// )?;
/// let sources = scope.filter(Column::Name.is_in(body.sources)).all(&txn).await?;
/// ```
///
/// ## Which of the two
///
/// [`authorize_scope`](Self::authorize_scope) is the whole check, the one
/// `Granted<Many<R>>` runs: the coarse capability, then the scope. Reach
/// for it when nothing has gated this route.
///
/// [`authorize_scope_dependency`](Self::authorize_scope_dependency) drops
/// the coarse gate, for an asset the route merely *refers* to. The reason
/// is [`AuthorizeLoaded`]'s: the coarse question on a dependency is the
/// wrong question. A caller who may write a widget naming folders they may
/// read would be refused because they may not *list* folders.
///
/// It is also the only one of the four doors that reaches a verdict without
/// awaiting. There is no policy call to make — partial evaluation ran in
/// [`AuthLayer`](crate::AuthLayer) and the scope is a lookup into the
/// session it assembled — so once the coarse gate is gone, nothing is left
/// to await, and a filter can be built in the middle of assembling a query.
///
/// Both hold the action to the asset's vocabulary at build time, and both
/// record, exactly as the other doors do.
pub trait AuthorizeScope: Scoping {
    /// Coarse gate, then the caller's authorized subset.
    fn authorize_scope<A: DeclaredAction>(
        action: A,
        extensions: &Extensions,
    ) -> impl Future<Output = Result<Self::Filter, Denial>> + Send;

    /// The caller's authorized subset, for an asset this route's own guard
    /// has already cleared the coarse question for.
    ///
    /// Skips the capability gate *and nothing else* — the action must still
    /// be one the asset declares, and the scope is still the one the policy
    /// assembled.
    fn authorize_scope_dependency<A: DeclaredAction>(
        action: A,
        extensions: &Extensions,
    ) -> Result<Self::Filter, Denial>;
}

/// Blanket for the same reason [`AuthorizeLoaded`]'s is: an asset supplies
/// the scope, through [`Scoping`], and cannot supply a way of reaching one
/// that records nothing.
impl<R: Scoping> AuthorizeScope for R {
    fn authorize_scope<A: DeclaredAction>(
        _action: A,
        extensions: &Extensions,
    ) -> impl Future<Output = Result<Self::Filter, Denial>> + Send {
        let () = Declares::<R, A>::PROOF;
        gated_scope::<R>(A::ACTION, extensions)
    }

    fn authorize_scope_dependency<A: DeclaredAction>(
        _action: A,
        extensions: &Extensions,
    ) -> Result<Self::Filter, Denial> {
        let () = Declares::<R, A>::PROOF;
        dependency_scope::<R>(A::ACTION, extensions).map(|(_, filter)| filter)
    }
}

/// [`AuthorizeScope::authorize_scope_dependency`]'s body, handing back the
/// caller as well so [`Scoped`] does not have to recover it a second time.
fn dependency_scope<R: Scoping>(
    action: &'static str,
    extensions: &Extensions,
) -> Result<(R::Ctx, R::Filter), Denial> {
    // The checker is recovered and dropped on purpose: this path makes no
    // policy call, but a route reaching it without an `AuthLayer` above it
    // is misconfigured, and it should fail the way every other door fails
    // rather than quietly answering from an empty session.
    let (ctx, _) = caller_and_checker::<R::Ctx>(extensions)?;

    let reached = declared_action::<R>(action)
        .and_then(|declared| Ok((declared, subset::<R>(action, &ctx)?)));

    let filter = record_scope::<R>(reached, action, &ctx, extensions)?;
    Ok((ctx, filter))
}

/// [`AuthorizeScope::authorize_scope`]'s body, split out so the trait
/// method can discharge its proof before the future is polled.
async fn gated_scope<R: Scoping>(
    action: &'static str,
    extensions: &Extensions,
) -> Result<R::Filter, Denial> {
    let (ctx, checker) = caller_and_checker::<R::Ctx>(extensions)?;

    let reached = match gate::<R>(action, &ctx, checker.as_ref()).await {
        Ok(declared) => subset::<R>(action, &ctx).map(|filter| (declared, filter)),
        Err(denial) => Err(denial),
    };

    record_scope::<R>(reached, action, &ctx, extensions)
}

/// The scope itself, with the asset's answer for a caller who was granted
/// nothing. Records nothing — [`record_scope`] is that half.
fn subset<R: Scoping>(action: &'static str, ctx: &R::Ctx) -> Result<R::Filter, Denial> {
    // The only door that does not go through the capability checker, so
    // the only one that has to apply the policy's admin verdict itself.
    // An asset that draws no distinction answers `None` and is scoped as
    // anyone else would be.
    if ctx.is_admin() {
        if let Some(everything) = R::unscoped() {
            return Ok(everything);
        }
    }

    match R::scope(action, ctx)? {
        Some(filter) => Ok(filter),
        // The policy granted nothing on this asset. Whether that is a
        // refusal or an empty page is the asset's call, exactly as it is
        // for a collection route.
        None => R::empty_scope().ok_or(Denial::Denied {
            action: Cow::Borrowed(action),
            resource_type: Cow::Borrowed(entity_type::<R>()),
            resource_id: Cow::Borrowed("collection"),
            reason: "no authorized scope",
        }),
    }
}

/// Deposit the verdict, whichever way it went.
///
/// The id is `collection`, as [`Many`]'s chain records — what was decided
/// is a subset of an asset, not anything about a row, and a listing and a
/// filtered dependency over the same asset should sit under one resource in
/// the trail.
fn record_scope<R: Scoping>(
    reached: Result<(&'static Action, R::Filter), Denial>,
    action: &'static str,
    ctx: &R::Ctx,
    extensions: &Extensions,
) -> Result<R::Filter, Denial> {
    match reached {
        Ok((declared, filter)) => {
            crate::record::grant(
                extensions,
                crate::record::Grant {
                    event_type: declared.event_type,
                    action: Cow::Borrowed(action),
                    resource_type: Cow::Borrowed(entity_type::<R>()),
                    resource_id: Cow::Borrowed("collection"),
                },
            );
            Ok(filter)
        }
        Err(denial) => {
            record_denial(&denial, extensions, ctx.tenant());
            Err(denial)
        }
    }
}

/// A dependency's authorized subset, extracted rather than asked for.
///
/// [`AuthorizeScope::authorize_scope_dependency`] with the call moved into
/// the signature, for the common case where the handler knows before it
/// runs which asset its body will refer to:
///
/// ```ignore
/// async fn create(
///     Granted(caller, pipeline): Granted<One<Pipeline>>,
///     sources: Scoped<SourceByName, source_action::Read>,
///     Json(body): Json<NewPipeline>,
/// ) -> Result<StatusCode, Error> {
///     let txn = db.begin().await?;
///     let named = sources.filter(Column::Name.is_in(body.sources)).all(&txn).await?;
///     // …
/// }
/// ```
///
/// Everything it needs is in extensions, so unlike [`Granted`] it reads
/// nothing out of the router and mounts on any state — there is no loader
/// here, and therefore no [`Granting::State`] to reach through `FromRef`.
///
/// What it deliberately does *not* hold is the connection. The transaction
/// this filter is meant to run inside is opened in the handler body, after
/// every extractor has finished, so the extractor carries the authorization
/// and the handler supplies the connection at the point of use. An
/// extractor that tried to own both would be back to querying the pool,
/// which is the thing this whole path exists to avoid.
///
/// Named fields rather than [`Granted`]'s pair: the action rides along as a
/// type parameter, so a tuple struct would have a third element that is
/// nothing but [`PhantomData`] and would spoil
/// the destructuring the pair form exists for.
pub struct Scoped<R: Scoping, A: DeclaredAction> {
    /// The caller the subset was computed for.
    pub caller: R::Ctx,
    /// The authorized subset, as this asset's queries take it.
    pub filter: R::Filter,
    _action: PhantomData<fn() -> A>,
}

impl<R: Scoping, A: DeclaredAction> Scoped<R, A> {
    /// Consume the guard and return just the filter.
    pub fn into_inner(self) -> R::Filter {
        self.filter
    }

    /// The caller this subset was computed for.
    pub fn caller(&self) -> &R::Ctx {
        &self.caller
    }
}

/// Reach the filter without naming it, so a query builds straight off the
/// guard.
impl<R: Scoping, A: DeclaredAction> std::ops::Deref for Scoped<R, A> {
    type Target = R::Filter;

    fn deref(&self) -> &R::Filter {
        &self.filter
    }
}

impl<R, A, St> FromRequestParts<St> for Scoped<R, A>
where
    R: Scoping,
    A: DeclaredAction,
    St: Send + Sync,
{
    type Rejection = Denial;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &St,
    ) -> Result<Self, Self::Rejection> {
        // Forces the assertion that the action is one the asset declares.
        // Costs nothing at runtime; fails the build if not.
        let () = Declares::<R, A>::PROOF;

        let (caller, filter) = dependency_scope::<R>(A::ACTION, &parts.extensions)?;

        Ok(Scoped {
            caller,
            filter,
            _action: PhantomData,
        })
    }
}

impl<R: Scoping, A: DeclaredAction> doxa::DocOperationSecurity for Scoped<R, A> {
    fn describe(op: &mut utoipa::openapi::path::Operation) {
        let display = format!("{} on {} (subset)", A::ACTION, entity_type::<R>());
        doxa::record_required_permission(
            op,
            DefaultSite::SCHEME,
            &asset_permission::<R>(A::ACTION),
            &display,
        );
    }
}

impl<R: Scoping, A: DeclaredAction> doxa::DocOperationContribution for Scoped<R, A> {
    fn contribution() -> doxa::OperationContribution {
        doxa::OperationContribution::new()
            .with_response(doxa::ResponseContribution::unauthorized())
            .with_response(doxa::ResponseContribution::new(
                "403",
                format!("No authorized scope on {}", entity_type::<R>()),
            ))
    }
}

/// Compile-time proof that `R` permits `A`, forced by both
/// [`AuthorizeLoaded`] methods.
///
/// The same two assertions [`Subject::SITE_DECLARED`] makes for a route,
/// reached the same way — a const in a generic impl, evaluated where the
/// pair is instantiated. Without it this door checked its action at
/// request time and answered an undeclared one with a `403`, which is the
/// status a real denial uses: a handler naming an action its asset does
/// not have would read, in the trail and to the caller, exactly like a
/// caller who was refused.
struct Declares<R, A>(PhantomData<fn() -> (R, A)>);

impl<R: Granting, A: DeclaredAction> Declares<R, A> {
    const PROOF: () = {
        assert!(
            distinct(R::ACTIONS),
            "`Granting::ACTIONS` names one action twice; the later row never runs",
        );
        assert!(
            declares(R::ACTIONS, A::ACTION),
            "this action is missing from the asset's `Granting::ACTIONS`",
        );
    };
}

/// Whether the capability gate runs, which is the only thing the two
/// methods of [`AuthorizeLoaded`] differ by.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Coarse {
    Check,
    Skip,
}

/// The body of both [`AuthorizeLoaded`] methods, and the third door onto
/// a decision — recording through the same path as the other two.
async fn decide<R: Granting>(
    resource: R::Row,
    action: &'static str,
    extensions: &Extensions,
    coarse: Coarse,
) -> Result<R::Row, Denial> {
    let (ctx, checker) = caller_and_checker::<R::Ctx>(extensions)?;

    match verdict::<R>(&resource, action, &ctx, checker.as_ref(), coarse).await {
        Ok((declared, entity_id)) => {
            crate::record::grant(
                extensions,
                crate::record::Grant {
                    event_type: declared.event_type,
                    action: Cow::Borrowed(action),
                    resource_type: Cow::Borrowed(entity_type::<R>()),
                    resource_id: Cow::Owned(entity_id),
                },
            );
            Ok(resource)
        }
        Err(denial) => {
            record_denial(&denial, extensions, ctx.tenant());
            Err(denial)
        }
    }
}

/// The body of both [`AuthorizeLoadedAll`] methods.
///
/// One coarse gate for the set — it is a question about the asset, not
/// about any row — then one entity per row through
/// [`CapabilityChecker::check_instance_many`], which is where the saving
/// is: a checker that can hoist its evaluation does, and one that cannot
/// falls back to the loop this replaces.
///
/// Recording walks the verdicts in order and stops at the first refusal,
/// so the trail is exactly what a loop of
/// [`AuthorizeLoaded::authorize_dependency`] would have left: every row up
/// to the refusal deposited as a grant, then the refusal — which the audit
/// builder keeps in preference to any of them, because one event carries
/// one decision and a denial outranks a grant.
async fn decide_all<R: Granting>(
    resources: Vec<R::Row>,
    action: &'static str,
    extensions: &Extensions,
    coarse: Coarse,
) -> Result<Vec<R::Row>, Denial> {
    let (ctx, checker) = caller_and_checker::<R::Ctx>(extensions)?;

    let declared = match coarse {
        Coarse::Check => gate::<R>(action, &ctx, checker.as_ref()).await,
        Coarse::Skip => declared_action::<R>(action),
    };
    let declared = match declared {
        Ok(declared) => declared,
        Err(denial) => {
            record_denial(&denial, extensions, ctx.tenant());
            return Err(denial);
        }
    };

    // An empty set asks nothing, so it deposits nothing. Recording a
    // grant here would file a decision about rows that do not exist.
    if resources.is_empty() {
        return Ok(resources);
    }

    let tenant = ctx.tenant().unwrap_or("");
    let entities: Vec<ResourceEntity> = resources
        .iter()
        .map(|resource| ResourceEntity::of(resource, tenant))
        .collect();

    let allowed = match checker
        .check_instance_many(tenant, ctx.roles(), action, &entities)
        .await
    {
        Ok(allowed) => allowed,
        Err(error) => return Err(Denial::Auth(error)),
    };

    // A checker answering a different number of verdicts than it was
    // asked about cannot be lined up with the rows, and guessing which
    // row an answer belongs to is how a grant lands on the wrong object.
    if allowed.len() != entities.len() {
        return Err(Denial::Auth(AuthError::PolicyFailed(format!(
            "capability checker answered {} verdict(s) for {} resource(s)",
            allowed.len(),
            entities.len(),
        ))));
    }

    for (entity, allowed) in entities.into_iter().zip(allowed) {
        if !allowed {
            let denial = Denial::Denied {
                action: Cow::Borrowed(action),
                resource_type: Cow::Borrowed(entity_type::<R>()),
                resource_id: Cow::Owned(entity.entity_id),
                reason: "instance denied",
            };
            record_denial(&denial, extensions, ctx.tenant());
            return Err(denial);
        }
        crate::record::grant(
            extensions,
            crate::record::Grant {
                event_type: declared.event_type,
                action: Cow::Borrowed(action),
                resource_type: Cow::Borrowed(entity_type::<R>()),
                resource_id: Cow::Owned(entity.entity_id),
            },
        );
    }

    Ok(resources)
}

/// The decision itself, split out for the same reason the sealed chain is
/// split from [`authorize`]: this half records nothing, so there is one
/// place a verdict becomes an audit row rather than one per door.
///
/// Hands back the object's Cedar id rather than recomputing it — the
/// qualified identity the policy actually saw, which is not always what
/// the handler used to find the row.
async fn verdict<R: Granting>(
    resource: &R::Row,
    action: &'static str,
    ctx: &R::Ctx,
    checker: &dyn CapabilityChecker,
    coarse: Coarse,
) -> Result<(&'static Action, String), Denial> {
    let declared = match coarse {
        Coarse::Check => gate::<R>(action, ctx, checker).await?,
        // Still the asset's vocabulary, just not its capability: a
        // dependency is exempt from the coarse question, not from the
        // rule that an asset only permits what it declares.
        Coarse::Skip => declared_action::<R>(action)?,
    };

    let tenant = ctx.tenant().unwrap_or("");
    let entity = ResourceEntity::of(resource, tenant);
    let allowed = checker
        .check_instance(tenant, ctx.roles(), action, &entity)
        .await?;

    if !allowed {
        return Err(Denial::Denied {
            action: Cow::Borrowed(action),
            resource_type: Cow::Borrowed(entity_type::<R>()),
            resource_id: Cow::Owned(entity.entity_id),
            reason: "instance denied",
        });
    }

    Ok((declared, entity.entity_id))
}

/// A denial the extractor reached. Everything else is a request that
/// never got to a decision, so there is nothing to record — it renders
/// through `IntoResponse` like any other rejection.
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
        crate::record::Denied {
            tenant,
            action,
            resource_type,
            resource_id,
            reason,
        },
    );
}

/// The same, for a denial [`AuthorizeLoaded`] reached. Both end in
/// [`crate::record::record`], which is the one place a refusal becomes a
/// log line and an audit row — the two doors differ in what can go wrong
/// on the way, not in what a verdict costs once reached.
fn record_denial(denial: &Denial, extensions: &Extensions, tenant: Option<&str>) {
    let Denial::Denied {
        action,
        resource_type,
        resource_id,
        reason,
    } = denial
    else {
        return;
    };

    crate::record::record(
        extensions,
        crate::record::Denied {
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
