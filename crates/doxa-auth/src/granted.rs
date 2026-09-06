//! One way to authorize a route, whatever it is guarding.
//!
//! [`Granted<T>`] replaces the split between a coarse capability gate and
//! an instance gate. A route names what it is about and gets back the
//! caller alongside it:
//!
//! ```ignore
//! async fn get(Granted(caller, widget): Granted<Widget>) -> Json<Widget>
//! async fn list(Granted(caller, scope): Granted<Many<Widget>>) -> Json<Vec<Widget>>
//! async fn flush(Granted(caller, ()): Granted<Cap<FlushCaches>>) -> StatusCode
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
//! Every refusal leaves through one place, so the log line and the audit
//! record cannot drift apart the way they did when each guard owned its
//! own deny branch.
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
/// Implemented for any [`FromStr`](std::str::FromStr) scalar and for
/// tuples of them. A composite key is better written as a struct
/// deriving `RouteKey`, so the route binds by field name instead of by
/// position — a two-`String` tuple bound in the wrong order parses
/// cleanly and loads the wrong object.
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

macro_rules! scalar_key {
    ($ty:ty, $kind:expr) => {
        impl RouteKey for $ty {
            const SEGMENTS: &'static [ResourceIdType] = &[$kind];

            fn parse(raw: &[&str]) -> Result<Self, KeyError> {
                let text = raw.first().copied().unwrap_or_default();
                text.parse().map_err(|_| KeyError {
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

/// What a route authorizes: an object, a collection, or a bare
/// capability.
///
/// Consumers rarely implement this. `#[derive(PolicyResource)]` emits it
/// for the instance form, [`Many<R>`] and [`Cap<M>`] carry the other two,
/// and everything asset-specific lives on [`Granting`] instead.
pub trait Subject: Send + Sync + 'static {
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

    /// Which of the three forms this is.
    const FORM: SubjectForm;

    /// What this subject is about, for documentation prose — the Cedar
    /// entity type for a resource, the capability name for a bare gate.
    fn doc_name() -> Cow<'static, str>;

    /// Permission name for the OpenAPI badge, given the route's action.
    fn permission(action: &str) -> Cow<'static, str>;

    /// Run the chain: coarse gate, then whatever this subject is about.
    fn authorize(
        key: Self::Key,
        action: &'static str,
        state: &Self::State,
        ctx: &Self::Ctx,
        checker: &dyn CapabilityChecker,
    ) -> impl Future<Output = Result<Self::Loaded, Refusal<Self::Error>>> + Send;
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
pub struct One<R>(PhantomData<fn() -> R>);

/// Authorize the whole collection rather than one member: the policy's
/// residual becomes a filter the handler applies to its query.
///
/// Costs no policy call at request time — partial evaluation already ran
/// in [`AuthLayer`](crate::AuthLayer), so this is a lookup into the
/// session it assembled.
pub struct Many<R>(PhantomData<fn() -> R>);

/// Authorize a bare capability with no asset behind it.
pub struct Cap<M>(PhantomData<fn() -> M>);

impl<R: Granting> Subject for One<R> {
    type Loaded = R;
    type Ctx = R::Ctx;
    type State = R::State;
    type Key = R::Key;
    type Error = R::Error;

    const FORM: SubjectForm = SubjectForm::Instance;

    fn doc_name() -> Cow<'static, str> {
        Cow::Borrowed(R::ENTITY_TYPE)
    }

    fn permission(action: &str) -> Cow<'static, str> {
        match R::capability(action) {
            Some(cap) => Cow::Borrowed(cap.name),
            None => Cow::Owned(format!("{}:{action}", R::ENTITY_TYPE)),
        }
    }

    async fn authorize(
        key: Self::Key,
        action: &'static str,
        state: &Self::State,
        ctx: &Self::Ctx,
        checker: &dyn CapabilityChecker,
    ) -> Result<R, Refusal<R::Error>> {
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

        if allowed {
            Ok(resource)
        } else {
            Err(Refusal::Denied {
                action: Cow::Borrowed(action),
                resource_type: Cow::Borrowed(R::ENTITY_TYPE),
                resource_id: Cow::Owned(entity.entity_id),
                reason: "instance denied",
            })
        }
    }
}

impl<R: Granting> Subject for Many<R> {
    type Loaded = R::Filter;
    type Ctx = R::Ctx;
    type State = R::State;
    type Key = ();
    type Error = R::Error;

    const FORM: SubjectForm = SubjectForm::Collection;

    fn doc_name() -> Cow<'static, str> {
        Cow::Borrowed(R::ENTITY_TYPE)
    }

    fn permission(action: &str) -> Cow<'static, str> {
        match R::capability(action) {
            Some(cap) => Cow::Borrowed(cap.name),
            None => Cow::Owned(format!("{}:{action}", R::ENTITY_TYPE)),
        }
    }

    async fn authorize(
        _key: (),
        action: &'static str,
        _state: &Self::State,
        ctx: &Self::Ctx,
        checker: &dyn CapabilityChecker,
    ) -> Result<R::Filter, Refusal<R::Error>> {
        coarse_gate::<R>(action, ctx, checker).await?;

        if let Some(scope) = R::scope(ctx)? {
            return Ok(scope);
        }

        // The policy granted nothing on this asset. Whether that is a
        // refusal or an empty page is the asset's call.
        R::empty_scope().ok_or(Refusal::Denied {
            action: Cow::Borrowed(action),
            resource_type: Cow::Borrowed(R::ENTITY_TYPE),
            resource_id: Cow::Borrowed("collection"),
            reason: "no authorized scope",
        })
    }
}

impl<M: Capable> Subject for Cap<M> {
    type Loaded = ();
    type Ctx = CapabilityContext;
    type State = ();
    type Key = ();
    type Error = std::convert::Infallible;

    const FORM: SubjectForm = SubjectForm::Capability;

    fn doc_name() -> Cow<'static, str> {
        Cow::Borrowed(M::CAPABILITY.name)
    }

    fn permission(_action: &str) -> Cow<'static, str> {
        Cow::Borrowed(M::CAPABILITY.name)
    }

    async fn authorize(
        _key: (),
        _action: &'static str,
        _state: &(),
        ctx: &CapabilityContext,
        checker: &dyn CapabilityChecker,
    ) -> Result<(), Refusal<Self::Error>> {
        let allowed = checker
            .check(ctx.tenant().unwrap_or(""), ctx.roles(), M::CAPABILITY)
            .await?;

        if allowed {
            return Ok(());
        }

        // A capability is granted only when every check passes, so the
        // first is the one whose denial short-circuits the evaluation.
        let (resource_type, resource_id) = M::CAPABILITY
            .checks
            .first()
            .map(|check| (check.entity_type, check.entity_id))
            .unwrap_or(("capability", M::CAPABILITY.name));

        Err(Refusal::Denied {
            action: Cow::Borrowed(M::CAPABILITY.name),
            resource_type: Cow::Borrowed(resource_type),
            resource_id: Cow::Borrowed(resource_id),
            reason: "capability denied",
        })
    }
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

    let (resource_type, resource_id) = cap
        .checks
        .first()
        .map(|check| (check.entity_type, check.entity_id))
        .unwrap_or(("capability", cap.name));

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
/// 403 (policy denial) or 404 (no such object). A denial is logged and
/// recorded before the response is built.
pub struct Granted<T: Subject, S: GrantSite = DefaultSite>(
    pub T::Ctx,
    pub T::Loaded,
    PhantomData<fn() -> S>,
);

/// Site used by hand-written routes: no path parameters, `read`, bearer.
/// The route macro generates a real one per call site.
pub struct DefaultSite;

impl GrantSite for DefaultSite {
    const PARAMS: &'static [&'static str] = &[];
    const ACTION: &'static str = "read";
}

impl<T: Subject, S: GrantSite> Granted<T, S> {
    /// Consume the guard and return just the authorized value.
    pub fn into_inner(self) -> T::Loaded {
        self.1
    }

    /// The caller this subject was authorized for.
    pub fn caller(&self) -> &T::Ctx {
        &self.0
    }
}

/// Route-specific facts the macro bakes in per call site: which segments
/// carry the key, and which Cedar action the verb implies.
///
/// Hand-written routes implement it directly — it is two consts.
pub trait GrantSite: Send + Sync + 'static {
    /// Path parameters feeding the key, in key order. Empty for
    /// collection and capability routes.
    const PARAMS: &'static [&'static str];
    /// Cedar action to authorize, from the HTTP verb.
    const ACTION: &'static str;
    /// OpenAPI security scheme the requirement references.
    const SCHEME: &'static str = "bearer";
}

impl<T, S, St> axum::extract::FromRequestParts<St> for Granted<T, S>
where
    T: Subject,
    S: GrantSite,
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
        let checker = parts
            .extensions
            .get::<std::sync::Arc<dyn CapabilityChecker>>()
            .cloned()
            .ok_or_else(|| {
                Refusal::Auth(AuthError::PolicyFailed(
                    "capability checker not configured on AuthLayer".into(),
                ))
            })?;

        let key = fetch_key::<T, S, St>(parts, state).await?;
        let state = <T::State as axum::extract::FromRef<St>>::from_ref(state);

        let refusal = match T::authorize(key, S::ACTION, &state, &ctx, checker.as_ref()).await {
            Ok(loaded) => return Ok(Granted(ctx, loaded, PhantomData)),
            Err(refusal) => refusal,
        };

        // The one place a denial is recorded. Everything else is a
        // request that never reached a decision, so there is nothing to
        // record — it renders through `IntoResponse` like any rejection.
        if let Refusal::Denied {
            action,
            resource_type,
            resource_id,
            reason,
        } = &refusal
        {
            crate::denial::record(
                &parts.extensions,
                crate::denial::Denial {
                    tenant: ctx.tenant(),
                    action,
                    resource_type,
                    resource_id,
                    reason,
                },
            );
        }

        Err(refusal)
    }
}

/// Pull the key's segments out of the route, in the order the site names
/// them.
async fn fetch_key<T: Subject, S: GrantSite, St: Send + Sync>(
    parts: &mut http::request::Parts,
    state: &St,
) -> Result<T::Key, Refusal<T::Error>> {
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

    let mut raw = Vec::with_capacity(S::PARAMS.len());
    for name in S::PARAMS {
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
impl<T: Subject, S: GrantSite> doxa::DocPathParams for Granted<T, S> {
    fn describe(op: &mut utoipa::openapi::path::Operation, _positional: &[&'static str]) {
        use utoipa::openapi::path::{ParameterBuilder, ParameterIn};
        use utoipa::openapi::Required;

        let name_of = T::doc_name();
        let composite = S::PARAMS.len() > 1;

        for (segment, kind) in S::PARAMS.iter().zip(T::Key::SEGMENTS) {
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

impl<T: Subject, S: GrantSite> doxa::DocOperationSecurity for Granted<T, S> {
    fn describe(op: &mut utoipa::openapi::path::Operation) {
        let name_of = T::doc_name();
        let display = match T::FORM {
            SubjectForm::Instance => format!("{} on {name_of} (instance)", S::ACTION),
            SubjectForm::Collection => format!("{} on {name_of} (collection)", S::ACTION),
            SubjectForm::Capability => format!("`{name_of}` capability"),
        };
        doxa::record_required_permission(op, S::SCHEME, &T::permission(S::ACTION), &display);
    }
}

impl<T: Subject, S: GrantSite> doxa::DocOperationContribution for Granted<T, S> {
    fn contribution() -> doxa::OperationContribution {
        let name_of = T::doc_name();

        let denied = match T::FORM {
            SubjectForm::Instance => format!("Policy denied `{}` on this {name_of}", S::ACTION),
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
