//! [`Granted<T>`]: a route's one guard. `Granted<Widget>` loads and checks an object,
//! `Granted<Many<Widget>>` yields a query filter, `Granted<Cap<M>>` checks a capability.
//! What only the body names goes through [`authorize`], [`AuthorizeLoaded`],
//! [`AuthorizeLoadedAll`] or [`AuthorizeScope`], which record to the audit trail as the guard does.

use std::borrow::Cow;
use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;

use axum::extract::rejection::PathRejection;
use axum::extract::FromRequestParts;
use axum::response::{IntoResponse, Response};
use http::Extensions;
use serde::de::value::UnitDeserializer;
use serde::de::DeserializeOwned;
use serde::Deserialize;

use doxa_policy::{
    AuthError, Capability, CapabilityChecker, Capable, PolicyResource, ResourceEntity, ResourceId,
};

// For `route_key!`, through `$crate`.
pub use doxa_policy::ResourceIdType;

use crate::claims::Claims;
use crate::context::{AuthContext, CapabilityContext};

// ---- caller context ----

/// A caller read from request extensions: [`CapabilityContext`], or `Arc<AuthContext<S, C>>`
/// when the asset's scope lives in the session.
pub trait FromAuthExtensions: Clone + Send + Sync + 'static {
    /// Recover the context, or `None` when the auth layer never ran.
    fn from_extensions(extensions: &Extensions) -> Option<Self>;

    /// Tenancy boundary the policy check runs within.
    fn tenant(&self) -> Option<&str>;

    /// Roles asserted for the caller.
    fn roles(&self) -> &[String];

    /// Whether the caller is unrestricted; [`Scoping::scope`] reads it, never asking the checker.
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

    /// The flag `AuthLayer` set from the token's roles.
    fn is_admin(&self) -> bool {
        self.is_admin
    }
}

// ---- route keys ----

/// A struct with one named field per route parameter, so `Path`/`Query` bind by name, not position.
pub trait RouteKey: Sized + Send + DeserializeOwned {
    /// Schema kind per segment, in key order.
    const SEGMENTS: &'static [ResourceIdType];

    /// The parameter each segment binds to, in key order. Only `()` leaves it empty; a non-empty
    /// list wins over the lookup's [`KEY_NAMES`](doxa_policy::fetch::FetchByKey::KEY_NAMES).
    const NAMES: &'static [&'static str] = &[];
}

/// Whether every name in `needles` appears in `haystack`; `const` for the route macro's build-time check.
pub const fn names_within(needles: &[&str], haystack: &[&str]) -> bool {
    let mut i = 0;
    while i < needles.len() {
        let mut found = false;
        let mut j = 0;
        while j < haystack.len() {
            if str_eq(needles[i], haystack[j]) {
                found = true;
                break;
            }
            j += 1;
        }
        if !found {
            return false;
        }
        i += 1;
    }
    true
}

/// Whichever of two name lists is not empty, preferring the first; `#[asset]` resolves
/// [`Granting::KEY_NAMES`] with it.
pub const fn key_names(
    preferred: &'static [&'static str],
    fallback: &'static [&'static str],
) -> &'static [&'static str] {
    if preferred.is_empty() {
        fallback
    } else {
        preferred
    }
}

/// A missing or unparseable key; both answer the same 400.
#[derive(Debug)]
pub struct KeyError {
    /// What went wrong, as the extractor described it.
    pub detail: String,
}

impl IntoResponse for KeyError {
    fn into_response(self) -> Response {
        error_body(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_key",
            format!("invalid identifier: {}", self.detail),
        )
    }
}

/// A guard's own refusal, in the envelope `#[derive(ApiError)]` uses, so a
/// client decodes every error the same way.
fn error_body(status: axum::http::StatusCode, code: &str, message: String) -> Response {
    let body = doxa::ApiErrorBody::new(status.as_u16(), code, message, serde_json::Value::Null);
    (status, axum::Json(body)).into_response()
}

/// Nothing to identify — collection and capability routes.
impl RouteKey for () {
    const SEGMENTS: &'static [ResourceIdType] = &[];
}

/// One field of a key: its OpenAPI type, which serde can't say. Per field because const slices
/// can't be concatenated.
pub trait KeySegment {
    /// Schema kind for this segment, driving the OpenAPI parameter type.
    const KIND: ResourceIdType;
}

macro_rules! scalar_key {
    ($ty:ty, $kind:expr) => {
        impl KeySegment for $ty {
            const KIND: ResourceIdType = $kind;
        }
    };
}

scalar_key!(String, ResourceIdType::String);
scalar_key!(i64, ResourceIdType::Integer);
scalar_key!(i32, ResourceIdType::Integer);
scalar_key!(u32, ResourceIdType::Integer);
scalar_key!(u64, ResourceIdType::Integer);

// Here because the orphan rule stops a consumer writing it.
#[cfg(feature = "uuid")]
scalar_key!(uuid::Uuid, ResourceIdType::Uuid);

/// A [`RouteKey`] struct for a hand-written loader: `route_key!(pub WidgetKey { name: String })`.
/// Field names are the route parameters; each type implements [`KeySegment`].
#[macro_export]
macro_rules! route_key {
    (
        $(#[$meta:meta])*
        $vis:vis $name:ident { $($field:ident : $ty:ty),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, ::serde::Serialize, ::serde::Deserialize)]
        $vis struct $name {
            $(
                #[allow(missing_docs)]
                pub $field: $ty,
            )+
        }

        impl $crate::granted::RouteKey for $name {
            const SEGMENTS: &'static [$crate::granted::ResourceIdType] =
                &[$(<$ty as $crate::granted::KeySegment>::KIND),+];

            const NAMES: &'static [&'static str] = &[$(::core::stringify!($field)),+];
        }

        impl $crate::__wire::KeyNames for $name {
            const NAMES: &'static [&'static str] = &[$(::core::stringify!($field)),+];
        }
    };
}

// ---- refusals ----

/// Why a subject would not hand its value over. Only [`Denied`](Refusal::Denied) is a decision,
/// and the only variant the guard records.
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
        /// The log field and the audit event's error text.
        reason: &'static str,
        /// Answered as `404`, so the caller can't tell a refused object from a missing one.
        hidden: bool,
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
    /// The [`Granting::Source`] extractor's own rejection. Boxed: it is rare and the largest.
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
            Refusal::Denied {
                hidden: true,
                resource_type,
                ..
            } => error_body(
                axum::http::StatusCode::NOT_FOUND,
                "not_found",
                format!("{resource_type} not found"),
            ),
            Refusal::Denied { .. } => AuthError::Forbidden.into_response(),
            Refusal::NotFound { entity_type } => error_body(
                axum::http::StatusCode::NOT_FOUND,
                "not_found",
                format!("{entity_type} not found"),
            ),
            Refusal::Key(error) => error.into_response(),
            Refusal::Auth(error) => error.into_response(),
            Refusal::Source(response) => *response,
            Refusal::Load(error) => error.into_response(),
        }
    }
}

/// A [`Refusal`] about an object already in hand, so without the key, not-found and load arms.
/// `?` widens it into a `Refusal`.
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
        /// The log field and the audit event's error text.
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
                hidden: false,
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

// ---- where the key comes from ----

/// Where a key's parameters are read from; the guard and the OpenAPI document both read this one value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyIn {
    /// Path segments, matched by name against the route template.
    Path,
    /// Query string parameters.
    Query,
}

// ---- call sites ----

/// Per-route facts the macro writes for each call site: where the key arrives, and the security
/// scheme. It rides on the form marker, so `Granted(caller, widget)` stays a pair.
pub trait GrantSite: Send + Sync + 'static {
    /// Where the key arrives; the route macro infers `Query` for an instance route with no path parameters.
    const IN: KeyIn = KeyIn::Path;
    /// OpenAPI security scheme; the docs builder refuses one that was never registered.
    const SCHEME: &'static str = "bearer";
}

/// The key from the path, bearer: for hand-written routes.
pub struct DefaultSite;

impl GrantSite for DefaultSite {}

// ---- subjects ----

/// Which of the three forms a subject is; only the instance form can answer 400 or 404.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectForm {
    /// One object, named by a key in the route.
    Instance,
    /// The subset of a collection a caller may see.
    Collection,
    /// A bare capability with no asset behind it.
    Capability,
}

/// The chain records nothing, so it can't be named outside this crate: every verdict is recorded.
mod sealed {
    use std::borrow::Cow;
    use std::future::Future;

    use doxa_policy::CapabilityChecker;

    use super::{Refusal, Subject};

    /// Blocks outside implementations of [`Subject`].
    pub trait Sealed {}

    /// The value the handler receives, and what the policy decided about, for the audit event.
    pub struct Authorized<T> {
        /// What the handler receives.
        pub loaded: T,
        /// What was checked: the Cedar action, or the capability name for a bare gate.
        pub action: Cow<'static, str>,
        /// Cedar entity type the decision concerned.
        pub resource_type: Cow<'static, str>,
        /// Cedar entity id the decision concerned.
        pub resource_id: Cow<'static, str>,
    }

    /// The decision: coarse gate, then the subject. Records nothing; only
    /// [`authorize`](super::authorize) calls it.
    pub trait Chain: Subject {
        /// The audit category, from the action's row; a bare capability has none.
        fn event_type() -> Option<&'static str> {
            None
        }

        /// Reach a verdict, recording nothing.
        fn authorize(
            key: Self::Key,
            state: &Self::State,
            ctx: &Self::Ctx,
            checker: &dyn CapabilityChecker,
        ) -> impl Future<Output = Result<Authorized<Self::Loaded>, Refusal<Self::Error>>> + Send;
    }
}

use sealed::Authorized;

// For `off_request`'s bound.
pub(crate) use sealed::Chain;

/// What a route authorizes: [`One<R>`], [`Many<R>`] or [`Cap<M>`]. Sealed; implement [`Granting`].
pub trait Subject: sealed::Sealed + Send + Sync + 'static {
    /// What the handler receives alongside the caller.
    type Loaded: Send;
    /// Caller shape this subject's chain needs.
    type Ctx: FromAuthExtensions;
    /// What the chain's loader is handed.
    type State: Send + Sync;
    /// How the guard gets the state out of a request.
    type Source: LoaderSource<State = Self::State>;
    /// Identifying values the route must supply.
    type Key: RouteKey;
    /// Loader failure; [`Cap`] loads nothing and uses [`Infallible`](std::convert::Infallible).
    type Error: IntoResponse + Send;
    /// The call site, defaulting to [`DefaultSite`] so `One<Widget>` stands alone.
    type Site: GrantSite;

    /// Which of the three forms this is.
    const FORM: SubjectForm;

    /// The key's parameter names, in key order; empty for a capability.
    const KEY_NAMES: &'static [&'static str] = &[];

    /// The Cedar action, or for a capability the capability's name.
    const ACTION: &'static str;

    /// Fails the build where the extractor is instantiated if the asset names an action twice
    /// or its key names don't match the key's segments.
    #[doc(hidden)]
    const SITE_DECLARED: ();

    /// The Cedar entity type, or the capability name, for documentation prose.
    fn doc_name() -> Cow<'static, str>;

    /// Permission name for the OpenAPI badge.
    fn permission() -> Cow<'static, str>;
}

/// The parameter names a subject's key is read from: the key struct's field names.
pub const fn resolved_params<T: Subject>() -> &'static [&'static str] {
    T::KEY_NAMES
}

// ---- actions ----

/// One row of [`Granting::ACTIONS`]: an action, its coarse capability and its audit category.
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
    /// Cedar action name, as the marker naming this row spells it.
    pub name: &'static str,
    /// Coarse capability, checked before any load so a refused caller costs no query.
    pub capability: Option<&'static Capability>,
    /// The audit event's `event_type` for routes using this action.
    pub event_type: Option<&'static str>,
}

impl Action {
    /// An action the instance check alone decides, with no audit category.
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

    /// File this action's audit events under `event_type`, as `EventType::as_static` gives it.
    pub const fn event(mut self, event_type: &'static str) -> Self {
        self.event_type = Some(event_type);
        self
    }
}

#[cfg(feature = "catalog")]
inventory::collect!(&'static Action);

/// Every action a `#[derive(Actions)]` enum in the binary declares, sorted by name so repeats
/// are adjacent for [`Vec::dedup`]. A hand-written [`ActionTable`] is not here.
#[cfg(feature = "catalog")]
pub fn actions() -> Vec<&'static Action> {
    let mut all: Vec<&'static Action> = inventory::iter::<&'static Action>
        .into_iter()
        .copied()
        .collect();
    all.sort_unstable_by_key(|action| action.name);
    all
}

/// An asset's action vocabulary as a bound, for code generic over it.
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
pub trait ActionTable: Send + Sync + 'static {
    /// Every action this vocabulary permits.
    const ACTIONS: &'static [Action];
}

/// One Cedar action as a type. Forms bound on `Table = R::Actions`, so another asset's
/// action doesn't compile even when spelled the same. `#[derive(Actions)]` emits one per variant.
///
/// ```
/// # use doxa_auth::granted::{Action, ActionTable, DeclaredAction};
/// pub enum WidgetActions {}
/// const READ_WIDGET: Action = Action::new("read_widget");
///
/// impl ActionTable for WidgetActions {
///     const ACTIONS: &'static [Action] = &[READ_WIDGET];
/// }
///
/// pub struct ReadWidget;
/// impl DeclaredAction for ReadWidget {
///     type Table = WidgetActions;
///     const ROW: &'static Action = &READ_WIDGET;
/// }
/// ```
pub trait DeclaredAction: Send + Sync + 'static {
    /// The vocabulary this action belongs to.
    type Table: ActionTable;

    /// This action's row in [`ActionTable::ACTIONS`], by reference.
    const ROW: &'static Action;

    /// The Cedar action name, from [`ROW`](Self::ROW).
    const ACTION: &'static str = Self::ROW.name;
}

/// The action a route's HTTP verb means when it names none, from `#[action(verb = …)]`.
/// A vocabulary without the verb's trait fails the build.
pub mod verb {
    use super::{ActionTable, DeclaredAction};

    /// The action `GET` and any verb without a mapping of its own means.
    pub trait ReadAction: ActionTable {
        /// The action this vocabulary reads with.
        type Action: DeclaredAction<Table = Self>;
    }

    /// The action `POST` means.
    pub trait CreateAction: ActionTable {
        /// The action this vocabulary creates with.
        type Action: DeclaredAction<Table = Self>;
    }

    /// The action `PUT` and `PATCH` mean.
    pub trait UpdateAction: ActionTable {
        /// The action this vocabulary updates with.
        type Action: DeclaredAction<Table = Self>;
    }

    /// The action `DELETE` means.
    pub trait DeleteAction: ActionTable {
        /// The action this vocabulary deletes with.
        type Action: DeclaredAction<Table = Self>;
    }
}

/// The asset a route's `Grant<Self>` guards with in the crate `C` marks: the
/// `#[asset(entity = Self)]` there that doesn't say `default = false`.
#[diagnostic::on_unimplemented(
    message = "no asset guards `{Self}` by default",
    note = "add `entity = {Self}` to its `#[doxa::asset(…)]`, or name one: `Grant<{Self}, by = …>`"
)]
pub trait AssetFor<C = ()> {
    /// The asset.
    type Asset;
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

/// Whether every row names a different action. A repeat's capability would never be checked,
/// so it fails the build.
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

/// The caller shape, state and loader failure an application's assets share; an asset may override one.
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
pub trait GrantProfile: Send + Sync + 'static {
    /// Caller shape; a collection route needs [`AuthContext<S, C>`] to reach the session.
    type Ctx: FromAuthExtensions;
    /// What loaders are handed.
    type State: Send + Sync;
    /// How the guard gets the state out of a request, usually [`FromState`].
    type Source: LoaderSource<State = Self::State>;
    /// Loader failure, answered through its own `IntoResponse`.
    type Error: IntoResponse + Send;
}

/// How to reach one object of an asset, and which actions it permits. `Self` is the descriptor;
/// a second key for the same [`Row`](Self::Row) is a second unit struct, so the Cedar id stays one.
pub trait Granting: Sized + Send + Sync + 'static {
    /// What the loader returns and the policy decides about; usually `Self`.
    type Row: PolicyResource;
    /// Identifying values [`load`](Self::load) needs.
    type Key: RouteKey;
    /// Caller shape; `#[asset]` writes the profile's.
    type Ctx: FromAuthExtensions;
    /// What [`load`](Self::load) is handed.
    type State: Send + Sync;
    /// How the guard gets the state out of a request.
    type Source: LoaderSource<State = Self::State>;
    /// Loader failure, answered through its own `IntoResponse`.
    type Error: IntoResponse + Send;

    /// This asset's `#[derive(Actions)]` vocabulary.
    type Actions: ActionTable;

    /// The vocabulary's rows.
    const ACTIONS: &'static [Action] = <Self::Actions as ActionTable>::ACTIONS;

    /// The route parameters the key binds, in key order; override for a lookup whose columns
    /// aren't its segments.
    const KEY_NAMES: &'static [&'static str] = <Self::Key as RouteKey>::NAMES;

    /// Fetch one object, or `None` if there is no such thing.
    fn load(
        key: Self::Key,
        state: &Self::State,
        ctx: &Self::Ctx,
    ) -> impl Future<Output = Result<Option<Self::Row>, Self::Error>> + Send;
}

/// An asset a caller can be granted a subset of; [`Many<R>`] requires it, so an unlistable
/// asset's collection route doesn't compile.
pub trait Scoping: Granting {
    /// The caller's authorized subset, as this asset's queries take it.
    type Filter: Send;

    /// Whether [`scope`](Self::scope) asks the policy. When it doesn't, only an action's
    /// capability guards a listing, so an action without one fails the build.
    const FROM_POLICY: bool = true;

    /// The caller's scope for `action`, from the session the policy assembled; `Ok(None)` if
    /// nothing was granted. Ignoring `action` grants listing and bulk-deleting alike.
    fn scope(action: &str, ctx: &Self::Ctx) -> Result<Option<Self::Filter>, AuthError>;

    /// The scope when nothing was granted. `None` refuses; a match-nothing filter answers an empty page.
    fn empty_scope() -> Option<Self::Filter> {
        None
    }

    /// The scope for an admin caller, used before [`scope`](Self::scope); `None` gives an admin
    /// [`scope`](Self::scope) too. The coarse capability is still checked first.
    fn unscoped() -> Option<Self::Filter> {
        None
    }
}

/// Authorize one object: load it, then decide with its attributes. `A` is the asset's action
/// marker; the route macro writes the site `S`.
// `fn() -> …` for variance and auto traits, not ownership.
#[allow(clippy::type_complexity)]
pub struct One<R, A, S = DefaultSite>(PhantomData<fn() -> (R, A, S)>);

/// Authorize a collection: the policy's residual, already evaluated by
/// [`AuthLayer`](crate::AuthLayer), becomes a query filter. Requires [`Scoping`].
// `fn() -> …` for variance and auto traits, not ownership.
#[allow(clippy::type_complexity)]
pub struct Many<R, A, S = DefaultSite>(PhantomData<fn() -> (R, A, S)>);

/// Authorize a bare capability; mounts on any router state through [`NoState`].
pub struct Cap<M, S = DefaultSite>(PhantomData<fn() -> (M, S)>);

// ---- loader state ----

/// The extractor the guard takes from the request, and the loader state it holds: router
/// state through [`FromState`], or a request-scoped handle such as `Extension<Txn>`.
pub trait LoaderSource: Send + Sync + 'static {
    /// What the loader is handed.
    type State: Send + Sync;

    /// Borrow it out of whatever the request produced.
    fn state(&self) -> &Self::State;
}

/// Loader state from the router's state, through `FromRef`; what `#[asset]` writes by default.
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

/// `type Source = Extension<Txn>` hands the loader `&Txn`.
impl<T: Send + Sync + 'static> LoaderSource for axum::Extension<T> {
    type State = T;

    fn state(&self) -> &T {
        &self.0
    }
}

/// The state of a form with no loader, extractable on any router state (unlike `()`, which
/// would need `FromRef`).
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

/// The permission an asset-backed route advertises: the coarse capability, else `Entity:action`.
fn asset_permission<R: Granting, A: DeclaredAction>() -> Cow<'static, str> {
    match A::ROW.capability {
        Some(cap) => Cow::Borrowed(cap.name),
        None => Cow::Owned(format!("{}:{}", entity_type::<R>(), A::ACTION)),
    }
}

/// The Cedar entity type of a descriptor's row, so two descriptors of one row record alike.
const fn entity_type<R: Granting>() -> &'static str {
    <R::Row as PolicyResource>::ENTITY_TYPE
}

impl<R: Granting, A: DeclaredAction<Table = R::Actions>, S: GrantSite> sealed::Sealed
    for One<R, A, S>
{
}

impl<R: Granting, A: DeclaredAction<Table = R::Actions>, S: GrantSite> Subject for One<R, A, S> {
    type Loaded = R::Row;
    type Ctx = R::Ctx;
    type State = R::State;
    type Source = R::Source;
    type Key = R::Key;
    type Error = R::Error;
    type Site = S;

    const FORM: SubjectForm = SubjectForm::Instance;
    const KEY_NAMES: &'static [&'static str] = R::KEY_NAMES;
    const ACTION: &'static str = A::ACTION;
    const SITE_DECLARED: () = {
        assert!(
            distinct(R::ACTIONS),
            "`Granting::ACTIONS` names one action twice; the later row never runs",
        );
        // Only an overridden `KEY_NAMES` can differ.
        assert!(
            R::KEY_NAMES.len() == <R::Key as RouteKey>::SEGMENTS.len(),
            "`Granting::KEY_NAMES` has a different length than the key's segments; \
             it needs one name per segment",
        );
    };

    fn doc_name() -> Cow<'static, str> {
        Cow::Borrowed(entity_type::<R>())
    }

    fn permission() -> Cow<'static, str> {
        asset_permission::<R, A>()
    }
}

impl<R: Granting, A: DeclaredAction<Table = R::Actions>, S: GrantSite> Chain for One<R, A, S> {
    fn event_type() -> Option<&'static str> {
        A::ROW.event_type
    }

    async fn authorize(
        key: Self::Key,
        state: &Self::State,
        ctx: &Self::Ctx,
        checker: &dyn CapabilityChecker,
    ) -> Result<Authorized<R::Row>, Refusal<R::Error>> {
        let action = A::ACTION;

        // Gate first, so a caller who may not touch this kind of thing at all costs no query.
        gate::<A>(ctx, checker).await?;

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
                hidden: true,
            });
        }

        // The id the policy saw, not the key the route parsed.
        Ok(Authorized {
            loaded: resource,
            action: Cow::Borrowed(action),
            resource_type: Cow::Borrowed(entity_type::<R>()),
            resource_id: Cow::Owned(entity.entity_id),
        })
    }
}

impl<R: Scoping, A: DeclaredAction<Table = R::Actions>, S: GrantSite> sealed::Sealed
    for Many<R, A, S>
{
}

impl<R: Scoping, A: DeclaredAction<Table = R::Actions>, S: GrantSite> Subject for Many<R, A, S> {
    type Loaded = R::Filter;
    type Ctx = R::Ctx;
    type State = R::State;
    type Source = R::Source;
    type Key = ();
    type Error = R::Error;
    type Site = S;

    const FORM: SubjectForm = SubjectForm::Collection;
    const ACTION: &'static str = A::ACTION;
    const SITE_DECLARED: () = {
        assert!(
            distinct(R::ACTIONS),
            "`Granting::ACTIONS` names one action twice; the later row never runs",
        );
        Gated::<R, A>::PROOF
    };

    fn doc_name() -> Cow<'static, str> {
        Cow::Borrowed(entity_type::<R>())
    }

    fn permission() -> Cow<'static, str> {
        asset_permission::<R, A>()
    }
}

impl<R: Scoping, A: DeclaredAction<Table = R::Actions>, S: GrantSite> Chain for Many<R, A, S> {
    fn event_type() -> Option<&'static str> {
        A::ROW.event_type
    }

    async fn authorize(
        _key: (),
        _state: &Self::State,
        ctx: &Self::Ctx,
        checker: &dyn CapabilityChecker,
    ) -> Result<Authorized<R::Filter>, Refusal<R::Error>> {
        let action = A::ACTION;

        gate::<A>(ctx, checker).await?;

        let scope = subset::<R>(action, ctx)?;

        // The id a refused listing names too.
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
    const ACTION: &'static str = M::CAPABILITY.name;
    const SITE_DECLARED: () = ();

    fn doc_name() -> Cow<'static, str> {
        Cow::Borrowed(M::CAPABILITY.name)
    }

    fn permission() -> Cow<'static, str> {
        Cow::Borrowed(M::CAPABILITY.name)
    }
}

impl<M: Capable, S: GrantSite> Chain for Cap<M, S> {
    async fn authorize(
        _key: (),
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
                hidden: false,
            });
        }

        Ok(Authorized {
            loaded: (),
            action: Cow::Borrowed(M::CAPABILITY.name),
            resource_type: Cow::Borrowed(resource_type),
            resource_id,
        })
    }
}

/// The resource a capability's verdict names: its first check's, with [`ResourceId::Tenant`]
/// as the caller's tenant, or the capability itself when it has none.
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

/// Whether the caller holds the action's capability, if it has one; checked before any load.
async fn gate<A: DeclaredAction>(
    ctx: &impl FromAuthExtensions,
    checker: &dyn CapabilityChecker,
) -> Result<&'static Action, Denial> {
    let declared = A::ROW;

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

// ---- the extractor ----

/// An authorized subject with its caller: `Granted(caller, widget)`. Fails 400, 401, 403 or 404,
/// and the verdict reaches the request's audit event either way.
pub struct Granted<T: Subject>(pub T::Ctx, pub T::Loaded);

impl<T: Subject> Granted<T> {
    /// Consume the guard and return just the authorized value.
    pub fn into_inner(self) -> T::Loaded {
        self.1
    }

    /// The caller this subject was authorized for; inherent, so it outranks the subject's methods.
    pub fn caller(&self) -> &T::Ctx {
        &self.0
    }
}

/// Reads through to the authorized subject, so `widget.name` and span fields borrow it.
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
        // Instantiates the build-time checks.
        let () = T::SITE_DECLARED;

        let (ctx, checker) = caller_and_checker::<T::Ctx>(&parts.extensions)?;

        let key = fetch_key::<T, St>(parts, state).await?;

        let source = <T::Source as FromRequestParts<St>>::from_request_parts(parts, state)
            .await
            .map_err(|rejection| Refusal::Source(Box::new(rejection.into_response())))?;

        let loaded =
            authorize_as::<T>(key, source.state(), &ctx, &*checker, &parts.extensions).await?;
        Ok(Granted(ctx, loaded))
    }
}

/// [`Granted`]'s check from inside a handler, for a key only the body names: loads, decides and
/// records. The first grant names the event; a refusal replaces it, and the handler's own fields win.
pub async fn authorize<T: Chain>(
    key: T::Key,
    state: &T::State,
    extensions: &Extensions,
) -> Result<T::Loaded, Refusal<T::Error>> {
    let (ctx, checker) = caller_and_checker::<T::Ctx>(extensions)?;
    authorize_as::<T>(key, state, &ctx, checker.as_ref(), extensions).await
}

/// [`authorize`] for a caller and checker already recovered from `extensions`.
async fn authorize_as<T: Chain>(
    key: T::Key,
    state: &T::State,
    ctx: &T::Ctx,
    checker: &dyn CapabilityChecker,
    extensions: &Extensions,
) -> Result<T::Loaded, Refusal<T::Error>> {
    match T::authorize(key, state, ctx, checker).await {
        Ok(authorized) => {
            crate::record::grant(
                extensions,
                crate::record::Grant {
                    event_type: T::event_type(),
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

/// The caller and checker [`AuthLayer`](crate::AuthLayer) put in extensions.
pub(crate) fn caller_and_checker<C: FromAuthExtensions>(
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

/// Authorize an object already in hand, such as one in an uncommitted transaction, without
/// loading it. The turbofish names the governing descriptor, which a row can't imply.
pub trait AuthorizeLoaded: PolicyResource {
    /// Coarse gate, then instance check, returning the object. An action the asset doesn't
    /// declare fails the build:
    ///
    /// ```
    /// # use doxa_auth::granted::{
    /// #     Action, ActionTable, AuthorizeLoaded, DeclaredAction, FromState, Granting,
    /// # };
    /// # use doxa_auth::CapabilityContext;
    /// # use doxa_policy::PolicyResource;
    /// # use std::convert::Infallible;
    /// # doxa_auth::route_key!(pub WidgetKey { name: String });
    /// # const READ: Action = Action::new("read");
    /// # pub enum WidgetActions {}
    /// # impl ActionTable for WidgetActions {
    /// #     const ACTIONS: &'static [Action] = &[READ];
    /// # }
    /// # struct Widget;
    /// # impl PolicyResource for Widget {
    /// #     const ENTITY_TYPE: &'static str = "Widget";
    /// #     fn resource_id(&self) -> String { String::new() }
    /// # }
    /// # impl Granting for Widget {
    /// #     type Row = Self;
    /// #     type Key = WidgetKey;
    /// #     type Ctx = CapabilityContext;
    /// #     type State = ();
    /// #     type Source = FromState<()>;
    /// #     type Error = Infallible;
    /// #     type Actions = WidgetActions;
    /// #     async fn load(_: WidgetKey, _: &(), _: &CapabilityContext)
    /// #         -> Result<Option<Self>, Infallible> { Ok(None) }
    /// # }
    /// struct Read;
    /// impl DeclaredAction for Read {
    ///     type Table = WidgetActions;
    ///     const ROW: &'static Action = &READ;
    /// }
    ///
    /// # let extensions = http::Extensions::new();
    /// let _ = Widget.authorize::<Widget, _>(Read, &extensions);
    /// ```
    ///
    /// ```compile_fail
    /// # use doxa_auth::granted::{
    /// #     Action, ActionTable, AuthorizeLoaded, DeclaredAction, FromState, Granting,
    /// # };
    /// # use doxa_auth::CapabilityContext;
    /// # use doxa_policy::PolicyResource;
    /// # use std::convert::Infallible;
    /// # doxa_auth::route_key!(pub WidgetKey { name: String });
    /// # const READ: Action = Action::new("read");
    /// # pub enum WidgetActions {}
    /// # impl ActionTable for WidgetActions {
    /// #     const ACTIONS: &'static [Action] = &[READ];
    /// # }
    /// # struct Widget;
    /// # impl PolicyResource for Widget {
    /// #     const ENTITY_TYPE: &'static str = "Widget";
    /// #     fn resource_id(&self) -> String { String::new() }
    /// # }
    /// # impl Granting for Widget {
    /// #     type Row = Self;
    /// #     type Key = WidgetKey;
    /// #     type Ctx = CapabilityContext;
    /// #     type State = ();
    /// #     type Source = FromState<()>;
    /// #     type Error = Infallible;
    /// #     type Actions = WidgetActions;
    /// #     async fn load(_: WidgetKey, _: &(), _: &CapabilityContext)
    /// #         -> Result<Option<Self>, Infallible> { Ok(None) }
    /// # }
    /// // Another asset's vocabulary.
    /// # const PURGE: Action = Action::new("purge");
    /// # pub enum OtherActions {}
    /// # impl ActionTable for OtherActions {
    /// #     const ACTIONS: &'static [Action] = &[PURGE];
    /// # }
    /// struct Purge;
    /// impl DeclaredAction for Purge {
    ///     type Table = OtherActions;
    ///     const ROW: &'static Action = &PURGE;
    /// }
    ///
    /// # let extensions = http::Extensions::new();
    /// // error: this action is missing from the asset's `Granting::ACTIONS`
    /// let _ = Widget.authorize::<Widget, _>(Purge, &extensions);
    /// ```
    fn authorize<R: Granting<Row = Self>, A: DeclaredAction<Table = R::Actions>>(
        self,
        action: A,
        extensions: &Extensions,
    ) -> impl Future<Output = Result<Self, Denial>> + Send;

    /// The instance check alone, for an object the route's own guard already gated: its coarse
    /// capability is a different question. The descriptor's vocabulary still governs:
    ///
    /// ```
    /// # use doxa_auth::granted::{
    /// #     Action, ActionTable, AuthorizeLoaded, DeclaredAction, FromState, Granting,
    /// # };
    /// # use doxa_auth::CapabilityContext;
    /// # use doxa_policy::PolicyResource;
    /// # use std::convert::Infallible;
    /// # doxa_auth::route_key!(pub WidgetKey { name: String });
    /// # const READ: Action = Action::new("read");
    /// # pub enum WidgetActions {}
    /// # impl ActionTable for WidgetActions {
    /// #     const ACTIONS: &'static [Action] = &[READ];
    /// # }
    /// # struct Widget;
    /// # impl PolicyResource for Widget {
    /// #     const ENTITY_TYPE: &'static str = "Widget";
    /// #     fn resource_id(&self) -> String { String::new() }
    /// # }
    /// struct WidgetById;
    ///
    /// impl Granting for WidgetById {
    ///     type Row = Widget;
    /// #     type Key = WidgetKey;
    /// #     type Ctx = CapabilityContext;
    /// #     type State = ();
    /// #     type Source = FromState<()>;
    /// #     type Error = Infallible;
    ///     type Actions = WidgetActions;
    /// #     async fn load(_: WidgetKey, _: &(), _: &CapabilityContext)
    /// #         -> Result<Option<Widget>, Infallible> { Ok(None) }
    ///     // …
    /// }
    ///
    /// # struct Read;
    /// # impl DeclaredAction for Read {
    /// #     type Table = WidgetActions;
    /// #     const ROW: &'static Action = &READ;
    /// # }
    /// # let extensions = http::Extensions::new();
    /// let _ = Widget.authorize_dependency::<WidgetById, _>(Read, &extensions);
    /// ```
    ///
    /// ```compile_fail
    /// # use doxa_auth::granted::{
    /// #     Action, ActionTable, AuthorizeLoaded, DeclaredAction, FromState, Granting,
    /// # };
    /// # use doxa_auth::CapabilityContext;
    /// # use doxa_policy::PolicyResource;
    /// # use std::convert::Infallible;
    /// # doxa_auth::route_key!(pub WidgetKey { name: String });
    /// # const READ: Action = Action::new("read");
    /// # pub enum WidgetActions {}
    /// # impl ActionTable for WidgetActions {
    /// #     const ACTIONS: &'static [Action] = &[READ];
    /// # }
    /// # struct Widget;
    /// # impl PolicyResource for Widget {
    /// #     const ENTITY_TYPE: &'static str = "Widget";
    /// #     fn resource_id(&self) -> String { String::new() }
    /// # }
    /// # struct WidgetById;
    /// # impl Granting for WidgetById {
    /// #     type Row = Widget;
    /// #     type Key = WidgetKey;
    /// #     type Ctx = CapabilityContext;
    /// #     type State = ();
    /// #     type Source = FromState<()>;
    /// #     type Error = Infallible;
    /// #     type Actions = WidgetActions;
    /// #     async fn load(_: WidgetKey, _: &(), _: &CapabilityContext)
    /// #         -> Result<Option<Widget>, Infallible> { Ok(None) }
    /// # }
    /// # const PURGE: Action = Action::new("purge");
    /// # pub enum OtherActions {}
    /// # impl ActionTable for OtherActions {
    /// #     const ACTIONS: &'static [Action] = &[PURGE];
    /// # }
    /// # struct Purge;
    /// # impl DeclaredAction for Purge {
    /// #     type Table = OtherActions;
    /// #     const ROW: &'static Action = &PURGE;
    /// # }
    /// # let extensions = http::Extensions::new();
    /// // error: this action is missing from the asset's `Granting::ACTIONS`
    /// let _ = Widget.authorize_dependency::<WidgetById, _>(Purge, &extensions);
    /// ```
    fn authorize_dependency<R: Granting<Row = Self>, A: DeclaredAction<Table = R::Actions>>(
        self,
        action: A,
        extensions: &Extensions,
    ) -> impl Future<Output = Result<Self, Denial>> + Send;
}

/// Blanket, so no asset can supply one that skips the decision or the record.
impl<T: PolicyResource> AuthorizeLoaded for T {
    // `-> impl Future`, not `async fn`, so the proof runs at the call, awaited or not.
    fn authorize<R: Granting<Row = Self>, A: DeclaredAction<Table = R::Actions>>(
        self,
        _action: A,
        extensions: &Extensions,
    ) -> impl Future<Output = Result<Self, Denial>> + Send {
        let () = Declares::<R, A>::PROOF;
        decide::<R, A>(self, extensions, Coarse::Check)
    }

    fn authorize_dependency<R: Granting<Row = Self>, A: DeclaredAction<Table = R::Actions>>(
        self,
        _action: A,
        extensions: &Extensions,
    ) -> impl Future<Output = Result<Self, Denial>> + Send {
        let () = Declares::<R, A>::PROOF;
        decide::<R, A>(self, extensions, Coarse::Skip)
    }
}

/// [`AuthorizeLoaded`] for several rows in one policy pass, each recorded under its own id.
/// The first refusal, in order, refuses the call and names that row.
pub trait AuthorizeLoadedAll<T: PolicyResource>: Sized {
    /// The coarse capability once, then an instance check per row.
    fn authorize_all<R: Granting<Row = T>, A: DeclaredAction<Table = R::Actions>>(
        self,
        action: A,
        extensions: &Extensions,
    ) -> impl Future<Output = Result<Vec<T>, Denial>> + Send;

    /// An instance check per row, as [`AuthorizeLoaded::authorize_dependency`].
    fn authorize_all_dependency<R: Granting<Row = T>, A: DeclaredAction<Table = R::Actions>>(
        self,
        action: A,
        extensions: &Extensions,
    ) -> impl Future<Output = Result<Vec<T>, Denial>> + Send;
}

impl<T: PolicyResource> AuthorizeLoadedAll<T> for Vec<T> {
    fn authorize_all<R: Granting<Row = T>, A: DeclaredAction<Table = R::Actions>>(
        self,
        _action: A,
        extensions: &Extensions,
    ) -> impl Future<Output = Result<Vec<T>, Denial>> + Send {
        let () = Declares::<R, A>::PROOF;
        decide_all::<R, A>(self, extensions, Coarse::Check)
    }

    fn authorize_all_dependency<R: Granting<Row = T>, A: DeclaredAction<Table = R::Actions>>(
        self,
        _action: A,
        extensions: &Extensions,
    ) -> impl Future<Output = Result<Vec<T>, Denial>> + Send {
        let () = Declares::<R, A>::PROOF;
        decide_all::<R, A>(self, extensions, Coarse::Skip)
    }
}

/// The subset of an asset a caller may see, as a [`Scoping::Filter`] the handler applies to its
/// own query; recorded as one verdict about the collection.
pub trait AuthorizeScope: Scoping {
    /// Coarse gate, then the caller's authorized subset, as `Granted<Many<R>>` runs it.
    fn authorize_scope<A: DeclaredAction<Table = Self::Actions>>(
        action: A,
        extensions: &Extensions,
    ) -> impl Future<Output = Result<Self::Filter, Denial>> + Send;

    /// The caller's subset without the capability gate. An asset whose scope is only the tenant
    /// (`#[asset(list = tenant)]`) then checks nothing about the action.
    fn authorize_scope_dependency<A: DeclaredAction<Table = Self::Actions>>(
        action: A,
        extensions: &Extensions,
    ) -> Result<Self::Filter, Denial>;
}

/// Blanket, so no asset can supply one that records nothing.
impl<R: Scoping> AuthorizeScope for R {
    fn authorize_scope<A: DeclaredAction<Table = Self::Actions>>(
        _action: A,
        extensions: &Extensions,
    ) -> impl Future<Output = Result<Self::Filter, Denial>> + Send {
        let () = Gated::<R, A>::PROOF;
        async move {
            gated_scope::<R, A>(extensions)
                .await
                .map(|(_, filter)| filter)
        }
    }

    fn authorize_scope_dependency<A: DeclaredAction<Table = Self::Actions>>(
        _action: A,
        extensions: &Extensions,
    ) -> Result<Self::Filter, Denial> {
        dependency_scope::<R, A>(extensions).map(|(_, filter)| filter)
    }
}

/// Fails the build when `A` has no capability and `R`'s scope ignores the policy, which would hand
/// every tenant member the whole scope.
struct Gated<R, A>(PhantomData<fn() -> (R, A)>);

impl<R: Scoping, A: DeclaredAction> Gated<R, A> {
    const PROOF: () = assert!(
        A::ROW.capability.is_some() || R::FROM_POLICY,
        "listing an asset whose scope is only the tenant needs an action with a capability",
    );
}

/// [`AuthorizeScope::authorize_scope_dependency`], handing back the caller too.
fn dependency_scope<R: Scoping, A: DeclaredAction<Table = R::Actions>>(
    extensions: &Extensions,
) -> Result<(R::Ctx, R::Filter), Denial> {
    let () = Gated::<R, A>::PROOF;
    // Recovered only so a route with no `AuthLayer` fails as every other door does.
    let (ctx, _) = caller_and_checker::<R::Ctx>(extensions)?;

    let reached = subset::<R>(A::ACTION, &ctx).map(|filter| (A::ROW, filter));

    let filter = record_scope::<R>(reached, A::ACTION, &ctx, extensions)?;
    Ok((ctx, filter))
}

/// The capability gate, then the caller's subset, handing back the caller too.
async fn gated_scope<R: Scoping, A: DeclaredAction<Table = R::Actions>>(
    extensions: &Extensions,
) -> Result<(R::Ctx, R::Filter), Denial> {
    let (ctx, checker) = caller_and_checker::<R::Ctx>(extensions)?;

    let reached = match gate::<A>(&ctx, checker.as_ref()).await {
        Ok(declared) => subset::<R>(A::ACTION, &ctx).map(|filter| (declared, filter)),
        Err(denial) => Err(denial),
    };

    let filter = record_scope::<R>(reached, A::ACTION, &ctx, extensions)?;
    Ok((ctx, filter))
}

/// The caller's scope, or the asset's answer for nothing granted. Records nothing.
fn subset<R: Scoping>(action: &'static str, ctx: &R::Ctx) -> Result<R::Filter, Denial> {
    // The checker decides reach, never rows, so the admin seat is applied here.
    if ctx.is_admin() {
        if let Some(everything) = R::unscoped() {
            return Ok(everything);
        }
    }

    match R::scope(action, ctx)? {
        Some(filter) => Ok(filter),
        None => R::empty_scope().ok_or(Denial::Denied {
            action: Cow::Borrowed(action),
            resource_type: Cow::Borrowed(entity_type::<R>()),
            resource_id: Cow::Borrowed("collection"),
            reason: "no authorized scope",
        }),
    }
}

/// Deposit a scope verdict under the id `collection`, as [`Many`] records.
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

/// The caller's authorized subset of an asset, as an extractor: [`AuthorizeScope::authorize_scope`],
/// capability gate included. It holds no connection; the handler runs the filter in its own transaction.
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
pub struct Scoped<R: Scoping, A: DeclaredAction<Table = R::Actions>> {
    /// The caller the subset was computed for.
    pub caller: R::Ctx,
    /// The authorized subset, as this asset's queries take it.
    pub filter: R::Filter,
    _action: PhantomData<fn() -> A>,
}

impl<R: Scoping, A: DeclaredAction<Table = R::Actions>> Scoped<R, A> {
    /// Consume the guard and return just the filter.
    pub fn into_inner(self) -> R::Filter {
        self.filter
    }

    /// The caller this subset was computed for.
    pub fn caller(&self) -> &R::Ctx {
        &self.caller
    }
}

/// Reads through to the filter, so a query builds straight off the guard.
impl<R: Scoping, A: DeclaredAction<Table = R::Actions>> std::ops::Deref for Scoped<R, A> {
    type Target = R::Filter;

    fn deref(&self) -> &R::Filter {
        &self.filter
    }
}

impl<R, A, St> FromRequestParts<St> for Scoped<R, A>
where
    R: Scoping,
    A: DeclaredAction<Table = R::Actions>,
    St: Send + Sync,
{
    type Rejection = Denial;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &St,
    ) -> Result<Self, Self::Rejection> {
        let () = Declares::<R, A>::PROOF;
        let () = Gated::<R, A>::PROOF;

        let (caller, filter) = gated_scope::<R, A>(&parts.extensions).await?;

        Ok(Scoped {
            caller,
            filter,
            _action: PhantomData,
        })
    }
}

impl<R: Scoping, A: DeclaredAction<Table = R::Actions>> doxa::DocOperationSecurity
    for Scoped<R, A>
{
    fn describe(op: &mut utoipa::openapi::path::Operation) {
        let display = format!("{} on {} (subset)", A::ACTION, entity_type::<R>());
        doxa::record_required_permission(
            op,
            DefaultSite::SCHEME,
            &asset_permission::<R, A>(),
            &display,
        );
    }
}

impl<R: Scoping, A: DeclaredAction<Table = R::Actions>> doxa::DocOperationContribution
    for Scoped<R, A>
{
    fn contribution() -> doxa::OperationContribution {
        doxa::OperationContribution::new()
            .with_response(doxa::ResponseContribution::unauthorized())
            .with_response(doxa::ResponseContribution::new(
                "403",
                format!("No authorized scope on {}", entity_type::<R>()),
            ))
    }
}

/// Fails the build where instantiated if `R` names an action twice, as [`Subject::SITE_DECLARED`].
struct Declares<R, A>(PhantomData<fn() -> (R, A)>);

impl<R: Granting, A: DeclaredAction<Table = R::Actions>> Declares<R, A> {
    const PROOF: () = {
        assert!(
            distinct(R::ACTIONS),
            "`Granting::ACTIONS` names one action twice; the later row never runs",
        );
    };
}

/// Whether the capability gate runs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Coarse {
    Check,
    Skip,
}

/// The body of both [`AuthorizeLoaded`] methods.
async fn decide<R: Granting, A: DeclaredAction<Table = R::Actions>>(
    resource: R::Row,
    extensions: &Extensions,
    coarse: Coarse,
) -> Result<R::Row, Denial> {
    let action = A::ACTION;
    let (ctx, checker) = caller_and_checker::<R::Ctx>(extensions)?;

    match verdict::<R, A>(&resource, &ctx, checker.as_ref(), coarse).await {
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

/// The body of both [`AuthorizeLoadedAll`] methods: one gate, then
/// [`CapabilityChecker::check_instance_many`], recorded in order up to the first refusal.
async fn decide_all<R: Granting, A: DeclaredAction<Table = R::Actions>>(
    resources: Vec<R::Row>,
    extensions: &Extensions,
    coarse: Coarse,
) -> Result<Vec<R::Row>, Denial> {
    let action = A::ACTION;
    let (ctx, checker) = caller_and_checker::<R::Ctx>(extensions)?;

    let declared = match coarse {
        Coarse::Check => match gate::<A>(&ctx, checker.as_ref()).await {
            Ok(declared) => declared,
            Err(denial) => {
                record_denial(&denial, extensions, ctx.tenant());
                return Err(denial);
            }
        },
        Coarse::Skip => A::ROW,
    };

    // No rows, no decision to record.
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

    // Miscounted verdicts can't be lined up with rows.
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

/// The decision, recording nothing, with the Cedar id the policy saw.
async fn verdict<R: Granting, A: DeclaredAction<Table = R::Actions>>(
    resource: &R::Row,
    ctx: &R::Ctx,
    checker: &dyn CapabilityChecker,
    coarse: Coarse,
) -> Result<(&'static Action, String), Denial> {
    let action = A::ACTION;
    let declared = match coarse {
        Coarse::Check => gate::<A>(ctx, checker).await?,
        Coarse::Skip => A::ROW,
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

/// Record a refusal if it is a decision; the other variants never reached one.
fn record_refusal<E>(refusal: &Refusal<E>, extensions: &Extensions, tenant: Option<&str>) {
    let Refusal::Denied {
        action,
        resource_type,
        resource_id,
        reason,
        hidden,
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
            status: if *hidden { 404 } else { 403 },
        },
    );
}

/// [`record_refusal`] for a [`Denial`].
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
            status: 403,
        },
    );
}

/// The route's key, through axum's `Path` or `Query` as [`GrantSite::IN`] says.
async fn fetch_key<T: Subject, St: Send + Sync>(
    parts: &mut http::request::Parts,
    state: &St,
) -> Result<T::Key, Refusal<T::Error>> {
    // `Path` rejects a route with no captures, so an empty key comes from a unit.
    if T::Key::SEGMENTS.is_empty() {
        return T::Key::deserialize(UnitDeserializer::<serde::de::value::Error>::new()).map_err(
            |error| {
                Refusal::Key(KeyError {
                    detail: error.to_string(),
                })
            },
        );
    }

    match <T::Site as GrantSite>::IN {
        KeyIn::Path => axum::extract::Path::<T::Key>::from_request_parts(parts, state)
            .await
            .map(|axum::extract::Path(key)| key)
            .map_err(|rejection| match rejection {
                // A wiring fault, not the caller's.
                PathRejection::MissingPathParams(error) => Refusal::Auth(AuthError::PolicyFailed(
                    format!("route path parameters unavailable: {error}"),
                )),
                other => Refusal::Key(KeyError {
                    detail: other.body_text(),
                }),
            }),
        KeyIn::Query => axum::extract::Query::<T::Key>::from_request_parts(parts, state)
            .await
            .map(|axum::extract::Query(key)| key)
            .map_err(|rejection| {
                Refusal::Key(KeyError {
                    detail: rejection.body_text(),
                })
            }),
    }
}

// ---- OpenAPI ----

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

/// The key's parameters by [`resolved_params`], in the place [`GrantSite::IN`] gives the guard.
impl<T: Subject> doxa::DocPathParams for Granted<T> {
    fn describe(op: &mut utoipa::openapi::path::Operation, _positional: &[&'static str]) {
        use utoipa::openapi::path::{ParameterBuilder, ParameterIn};
        use utoipa::openapi::Required;

        let name_of = T::doc_name();
        let params_named = resolved_params::<T>();
        let composite = params_named.len() > 1;
        let location = match <T::Site as GrantSite>::IN {
            KeyIn::Path => ParameterIn::Path,
            KeyIn::Query => ParameterIn::Query,
        };

        for (segment, kind) in params_named.iter().zip(T::Key::SEGMENTS) {
            let description = if composite {
                format!("`{segment}` part of the {name_of} identifier")
            } else {
                format!("Identifier of the {name_of}")
            };

            let param = ParameterBuilder::new()
                .name(*segment)
                .parameter_in(location.clone())
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
        let action = T::ACTION;
        let display = match T::FORM {
            SubjectForm::Instance => format!("{action} on {name_of} (instance)"),
            SubjectForm::Collection => format!("{action} on {name_of} (collection)"),
            SubjectForm::Capability => format!("`{name_of}` capability"),
        };
        let scheme = <T::Site as GrantSite>::SCHEME;
        doxa::record_required_permission(op, scheme, &T::permission(), &display);
    }
}

impl<T: Subject> doxa::DocOperationContribution for Granted<T> {
    fn contribution() -> doxa::OperationContribution {
        let name_of = T::doc_name();
        let action = T::ACTION;

        let denied = match T::FORM {
            SubjectForm::Instance => format!("Policy denied `{action}` on this {name_of}"),
            SubjectForm::Collection => format!("No authorized scope on {name_of}"),
            SubjectForm::Capability => format!("Capability `{name_of}` denied"),
        };

        let contribution = doxa::OperationContribution::new()
            .with_response(doxa::ResponseContribution::unauthorized())
            .with_response(doxa::ResponseContribution::new("403", denied));

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
