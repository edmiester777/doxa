//! `#[asset]` — the `Granting` impl an application would otherwise
//! transcribe.
//!
//! Six of `Granting`'s seven items are not decisions. `Ctx`, `State`,
//! `Source` and `Error` belong to the application and are the same for
//! every asset in it; `Key` and `load` are the lookup the row already
//! declares through [`FetchByKey`] — or, for `key = pk`, through
//! [`FetchById`], which is why the id route reaches a row that declares no
//! key column at all; `Row` is `Self` unless the attribute says otherwise.
//! Only `ACTIONS` is a fact about this asset, and the attribute takes it
//! as one word.
//!
//! `with` names a [`Lookup`] instead — one of the markers
//! `#[resource(key(Name))]` emits, for the row reached more ways than
//! `FetchByKey` and `FetchById` can spell between them. A marker carries
//! its row and its key, so `with = FindByPair` needs no `row =` beside it
//! and two assets over one row cannot come to name different rows.
//!
//! `ctx`, `error` and `source` override the profile for the asset that
//! genuinely differs — a loader answering 409 on an ambiguous name, a
//! `Scoping` impl that needs the assembled session to read the policy's
//! residual, a lookup that must run inside the request's open transaction
//! — without the rest of the service restating anything.
//!
//! ```ignore
//! #[doxa::asset(profile = AppGrants, actions = WidgetAction)]
//! pub struct WidgetByName;
//! ```
//!
//! # No backend is assumed
//!
//! The lookups are named through [`fetch`], which no backend owns, so what
//! this writes is the same whether the row lives in Postgres, behind an
//! HTTP control plane or in a process-local map. `#[derive(PolicyResource)]`
//! answers those traits for a SeaORM model; anything else answers them
//! itself, in about fifteen lines.
//!
//! # `load_with`, and what taking the caller costs
//!
//! [`FetchByKey::fetch`] is handed a `&str` scope and nothing else. That
//! is not a thin signature, it is the guarantee: a lookup that cannot see
//! the caller cannot ignore the caller's tenant, so the generated loader
//! confines every fetch and refuses to guess when there is no tenant to
//! confine to.
//!
//! `load_with` is handed the whole `Ctx`, and exists for the lookup that
//! needs more than the scope — one that varies by role, or reads the
//! assembled session. Those two facts are the same fact. Taking the `Ctx`
//! is what makes such a lookup expressible, and it is what makes
//! confinement the consumer's to write: a `load_with` that takes `_ctx`
//! and means it compiles, passes its tests, and serves one tenant's rows
//! to another, with the capability gate and the instance check both
//! passing on the way. `asset_load_with.rs` in the `doxa` crate pins that
//! boundary as a runnable fact.
//!
//! Everything around the loader is unchanged either way: the coarse gate
//! still runs first and still costs no load, the instance check still runs
//! on whatever came back, and the verdict still reaches the audit trail
//! under the row's Cedar identity. The scope is the only thing that moves.
//!
//! The struct is left exactly as written. That is the whole reason this
//! is an attribute on a descriptor rather than something that generates
//! one: `Granting::Row` is a separate associated type, so a second route
//! key over the same row is a unit struct naming `row = …`, not a newtype
//! wrapping it. Two descriptors over one row therefore share one
//! `PolicyResource` impl and cannot come to disagree about the object's
//! Cedar identity.
//!
//! [`fetch`]: https://docs.rs/doxa-policy/latest/doxa_policy/fetch/index.html
//! [`FetchByKey`]: https://docs.rs/doxa-policy/latest/doxa_policy/fetch/trait.FetchByKey.html
//! [`FetchById`]: https://docs.rs/doxa-policy/latest/doxa_policy/fetch/trait.FetchById.html
//! [`Lookup`]: https://docs.rs/doxa-policy/latest/doxa_policy/fetch/trait.Lookup.html

use proc_macro2::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;
use syn::{Ident, Item, Path, Type};

/// Parsed `#[asset(…)]` arguments.
#[derive(Default)]
struct Args {
    /// The row this descriptor reaches. `Self` when absent.
    row: Option<Type>,
    /// The application's `GrantProfile`.
    profile: Option<Path>,
    /// The vocabulary, as an `ActionTable`.
    actions: Option<Path>,
    /// Route key. `<Row as FetchByKey<State>>::Key` when absent.
    key: Option<Type>,
    /// `key = pk`: the row's own identifier rather than a key column, and
    /// `FetchById` rather than `FetchByKey`. Asks nothing of
    /// `#[resource(key)]`, so a row that declares no key column still has
    /// an id route.
    by_primary_key: bool,
    /// Loader failure, overriding the profile's.
    error: Option<Type>,
    /// Caller shape, overriding the profile's.
    ctx: Option<Type>,
    /// Where the loader's state comes from, overriding the profile's. The
    /// state follows it, so `source = Extension<Txn>` is also `State = Txn`.
    source: Option<Type>,
    /// A named `Lookup` to reach the row through, rather than the row's
    /// own unnamed one. Carries the row with it, so `row` is implied.
    with: Option<Path>,
    /// A loader to call instead of the row's own fetch.
    load_with: Option<Path>,
    /// `list = tenant`: emit a `Scoping` confined to the caller's tenant.
    list: Option<Ident>,
}

impl Parse for Args {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut out = Args::default();

        while !input.is_empty() {
            let key: Ident = input.parse()?;
            input.parse::<syn::Token![=]>()?;

            if key == "row" {
                out.row = Some(input.parse()?);
            } else if key == "profile" {
                out.profile = Some(input.parse()?);
            } else if key == "actions" {
                out.actions = Some(input.parse()?);
            } else if key == "key" {
                // `pk` is a word rather than a type because it names a
                // *lookup*, not a key type: the type follows from the
                // row's primary key, and the loader changes with it.
                if input.peek(syn::Ident) && input.fork().parse::<Ident>()? == "pk" {
                    input.parse::<Ident>()?;
                    out.by_primary_key = true;
                } else {
                    out.key = Some(input.parse()?);
                }
            } else if key == "list" {
                let which: Ident = input.parse()?;
                if which != "tenant" {
                    return Err(syn::Error::new(
                        which.span(),
                        "expected `list = tenant`. The generated listing is confined to the \
                         caller's tenant and applies no other policy condition, so it says so \
                         at the call site; anything finer is a hand-written `Scoping`",
                    ));
                }
                out.list = Some(which);
            } else if key == "error" {
                out.error = Some(input.parse()?);
            } else if key == "ctx" {
                out.ctx = Some(input.parse()?);
            } else if key == "source" {
                out.source = Some(input.parse()?);
            } else if key == "with" {
                out.with = Some(input.parse()?);
            } else if key == "load_with" {
                out.load_with = Some(input.parse()?);
            } else {
                return Err(syn::Error::new(
                    key.span(),
                    "unknown `asset` option; expected `profile`, `actions`, `row`, `key`, \
                     `with`, `list`, `ctx`, `source`, `error` or `load_with`",
                ));
            }

            if input.is_empty() {
                break;
            }
            input.parse::<syn::Token![,]>()?;
        }

        Ok(out)
    }
}

pub fn expand(args: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let args: Args = syn::parse2(args)?;
    let item: Item = syn::parse2(item)?;

    let name = match &item {
        Item::Struct(item) => &item.ident,
        Item::Enum(item) => &item.ident,
        other => {
            return Err(syn::Error::new(
                other.span(),
                "`asset` describes one route's way into a resource, so it goes on a struct",
            ))
        }
    };

    // Both are facts the attribute cannot work out: the profile is the
    // application's, and an asset's vocabulary is the whole of what it
    // permits — defaulting either would be inventing a permission.
    let profile = args.profile.as_ref().ok_or_else(|| {
        syn::Error::new(
            name.span(),
            "`asset` needs `profile = …`, the application's `GrantProfile`",
        )
    })?;
    let actions = args.actions.as_ref().ok_or_else(|| {
        syn::Error::new(
            name.span(),
            "`asset` needs `actions = …`, the enum deriving `Actions` that says what this \
             asset permits",
        )
    })?;

    if args.by_primary_key {
        if let Some(key) = &args.key {
            return Err(syn::Error::new(
                key.span(),
                "`key = pk` already says what the key is: the row's primary key",
            ));
        }
    }

    // Both are answers to "how is this row reached", and a descriptor has
    // one way in. Silently preferring either would mean a declaration that
    // names a lookup and does not use it.
    if let (Some(with), Some(_)) = (&args.with, &args.load_with) {
        return Err(syn::Error::new(
            with.span(),
            "`with` and `load_with` are two answers to how this asset loads: `with` names a \
             lookup that already knows the query, `load_with` replaces it entirely",
        ));
    }
    if let Some(with) = &args.with {
        if args.by_primary_key {
            return Err(syn::Error::new(
                with.span(),
                "`with` names the lookup, and a lookup already says which columns it matches: \
                 `key = pk` would be a second, different way in",
            ));
        }
    }

    // The source and the state move together: naming a source is naming
    // where the loader's handle comes from, and the handle it yields is
    // then what the loader gets. Letting them be set apart would allow a
    // profile whose `State` no source produces, which is a type error
    // stated in two places instead of one.
    //
    // Resolved before the row, because a named lookup is reached *through*
    // the state — one lookup serves every connection type — and carries the
    // row with it.
    let (source, state) = match &args.source {
        Some(source) => (
            quote!(#source),
            quote!(<#source as ::doxa::auth::LoaderSource>::State),
        ),
        None => (
            quote!(<#profile as ::doxa::auth::GrantProfile>::Source),
            quote!(<#profile as ::doxa::auth::GrantProfile>::State),
        ),
    };

    // A marker means "this row, by these columns", so naming one is naming
    // the row too — and two lookups over one row cannot come to disagree
    // about which row that is. An explicit `row` still wins, for the
    // descriptor whose lookup produces a type it wants to call something
    // else.
    let row = match (&args.row, &args.with) {
        (Some(row), _) => quote!(#row),
        (None, Some(with)) => quote!(<#with as ::doxa::policy::Lookup<#state>>::Row),
        (None, None) => quote!(Self),
    };

    let key = match (&args.key, &args.with, args.by_primary_key) {
        (Some(key), _, _) => quote!(#key),
        (None, Some(with), _) => quote!(<#with as ::doxa::policy::Lookup<#state>>::Key),
        (None, None, true) => quote!(<#row as ::doxa::policy::FetchById<#state>>::Id),
        (None, None, false) => quote!(<#row as ::doxa::policy::FetchByKey<#state>>::Key),
    };

    let error = match &args.error {
        Some(error) => quote!(#error),
        None => quote!(<#profile as ::doxa::auth::GrantProfile>::Error),
    };

    // The caller shape is the profile's, and overridable for the one asset
    // that needs a different one. A `Scoping` impl reading the policy's
    // residual needs the assembled session rather than tenant + roles, and
    // without this the whole application would have to switch context types
    // to give one asset a filter — or that asset would drop the attribute
    // and write `Granting` out by hand.
    let ctx = match &args.ctx {
        Some(ctx) => quote!(#ctx),
        None => quote!(<#profile as ::doxa::auth::GrantProfile>::Ctx),
    };

    let load = match &args.load_with {
        Some(path) => quote! {
            async fn load(
                key: Self::Key,
                state: &Self::State,
                ctx: &Self::Ctx,
            ) -> ::std::result::Result<::std::option::Option<Self::Row>, Self::Error> {
                #path(key, state, ctx).await
            }
        },
        None => {
            // `fetch_by_id` is a `FetchById` method and `fetch` a
            // `FetchByKey` one, so the trait is part of the choice rather
            // than a constant around it. That is the whole reach of
            // `key = pk` on a row that declares no key column: an
            // identifier belongs to the collection, so the id route asks
            // nothing of `#[resource(key)]`.
            let lookup = match (&args.with, args.by_primary_key) {
                (Some(with), _) => quote!(<#with as ::doxa::policy::Lookup<#state>>::fetch),
                (None, true) => quote!(<#row as ::doxa::policy::FetchById<#state>>::fetch_by_id),
                (None, false) => quote!(<#row as ::doxa::policy::FetchByKey<#state>>::fetch),
            };
            quote! {
                async fn load(
                    key: Self::Key,
                    state: &Self::State,
                    ctx: &Self::Ctx,
                ) -> ::std::result::Result<::std::option::Option<Self::Row>, Self::Error> {
                    // Every lookup is confined to the caller's tenant, so a
                    // key belonging to someone else answers `None` exactly as
                    // a key that does not exist would.
                    //
                    // A caller with no tenant has no scope to be confined
                    // to, and the answer is that nothing is there. Defaulting
                    // to the empty string instead would issue a real query
                    // for `scope = ''` — which finds nothing on any sane
                    // schema, and is a row somebody could create on the
                    // wrong one.
                    let ::std::option::Option::Some(scope) =
                        ::doxa::auth::FromAuthExtensions::tenant(ctx)
                    else {
                        return ::std::result::Result::Ok(::std::option::Option::None);
                    };
                    ::std::result::Result::Ok(#lookup(key, state, scope).await?)
                }
            }
        }
    };

    // Listing, and only the tenant-confined kind. `Scoping::scope` is
    // meant to carry the policy's residual, which is a per-row condition
    // this cannot see — so the option names its filter rather than
    // implying it is that. An asset needing the residual writes `Scoping`
    // itself, and the compiler asks for it the moment a route says
    // `Many<…>`.
    let scoping = match &args.list {
        None => quote!(),
        // Bounded on `FetchSubset` rather than `FetchByKey`: listing needs
        // the owning column and nothing else, so a collection no route
        // addresses by a key can still be paged.
        Some(_) => quote! {
            impl ::doxa::auth::Scoping for #name {
                type Filter = <#row as ::doxa::policy::FetchSubset>::Filter;

                fn scope(
                    _action: &str,
                    ctx: &Self::Ctx,
                ) -> ::std::result::Result<
                    ::std::option::Option<Self::Filter>,
                    ::doxa::policy::AuthError,
                > {
                    // The coarse capability already decided whether this
                    // caller may list at all; what is left is which rows,
                    // and that is the tenant.
                    //
                    // No tenant is no scope, which `empty_scope` turns into
                    // a refusal — rather than a listing of whatever happens
                    // to sit under the empty string.
                    let ::std::option::Option::Some(scope) =
                        ::doxa::auth::FromAuthExtensions::tenant(ctx)
                    else {
                        return ::std::result::Result::Ok(::std::option::Option::None);
                    };
                    ::std::result::Result::Ok(::std::option::Option::Some(
                        <#row as ::doxa::policy::FetchSubset>::subset(scope),
                    ))
                }

                // Forwarded rather than left at the default, so a backend
                // that can say "everything" is asked. `FetchSubset` answers
                // `None` unless it overrides this, which is the right
                // reading of a scope that is only tenancy: an administrator
                // of a tenant is still inside it.
                fn unscoped() -> ::std::option::Option<Self::Filter> {
                    <#row as ::doxa::policy::FetchSubset>::everything()
                }
            }
        },
    };

    Ok(quote! {
        #item

        #scoping

        impl ::doxa::auth::Granting for #name {
            type Row = #row;
            type Key = #key;
            type Ctx = #ctx;
            type State = #state;
            type Source = #source;
            type Error = #error;

            const ACTIONS: &'static [::doxa::auth::Action] =
                <#actions as ::doxa::auth::ActionTable>::ACTIONS;

            #load
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expand_ok(args: TokenStream, item: TokenStream) -> String {
        expand(args, item).expect("expands").to_string()
    }

    fn expand_err(args: TokenStream, item: TokenStream) -> String {
        expand(args, item).expect_err("rejected").to_string()
    }

    /// The common case: the row is its own descriptor, so six of the seven
    /// items come from the profile and the row's own `FetchByKey`.
    #[test]
    fn the_profile_supplies_the_application_types() {
        let out = expand_ok(
            quote!(profile = AppGrants, actions = WidgetAction),
            quote!(
                pub struct Widget;
            ),
        );

        assert!(out.contains("type Row = Self ;"), "{out}");
        assert!(
            out.contains("type Key = < Self as :: doxa :: policy :: FetchByKey <"),
            "{out}",
        );
        assert!(
            out.contains("type Ctx = < AppGrants as :: doxa :: auth :: GrantProfile > :: Ctx"),
            "{out}",
        );
        assert!(
            out.contains("type State = < AppGrants as :: doxa :: auth :: GrantProfile > :: State"),
            "{out}",
        );
        assert!(
            out.contains(
                "type Source = < AppGrants as :: doxa :: auth :: GrantProfile > :: Source"
            ),
            "{out}",
        );
        assert!(
            out.contains("type Error = < AppGrants as :: doxa :: auth :: GrantProfile > :: Error"),
            "{out}",
        );
        assert!(
            out.contains("< WidgetAction as :: doxa :: auth :: ActionTable > :: ACTIONS"),
            "{out}",
        );
    }

    /// Nothing the attribute writes names an ORM, so the whole of it is
    /// available to a row that lives somewhere else. This is the test that
    /// would have failed before `fetch` existed: the loader arm used to
    /// refuse outright without the `sea-orm` feature, and `list` with it.
    #[test]
    fn no_backend_is_named_anywhere_in_the_output() {
        let out = expand_ok(
            quote!(profile = AppGrants, actions = WidgetAction, list = tenant),
            quote!(
                pub struct Widget;
            ),
        );

        assert!(!out.contains("sea_orm"), "{out}");
        assert!(!out.contains("ScopedRow"), "{out}");
        assert!(!out.contains("ScopedTable"), "{out}");
    }

    /// The source and the state move together, so `source = …` is also the
    /// answer to "which handle does the loader get". A request-scoped
    /// transaction is the case: naming it as the source is the whole of
    /// what an asset does to be loaded inside one.
    #[test]
    fn a_source_override_carries_the_state_with_it() {
        let out = expand_ok(
            quote!(
                profile = AppGrants,
                actions = WidgetAction,
                source = axum::Extension<Txn>
            ),
            quote!(
                pub struct Widget;
            ),
        );

        assert!(
            out.contains("type Source = axum :: Extension < Txn >"),
            "{out}"
        );
        assert!(
            out.contains(
                "type State = < axum :: Extension < Txn > as :: doxa :: auth :: LoaderSource > \
                 :: State"
            ),
            "{out}",
        );
        // And the profile is not consulted for either of them.
        assert!(
            !out.contains("GrantProfile > :: State"),
            "state should follow the source: {out}",
        );
    }

    /// The one asset that needs a different caller shape says so, and the
    /// rest of the application keeps the profile's.
    ///
    /// `Scoping` reading the policy's residual needs the assembled session,
    /// not tenant + roles. Without an override, giving one asset a filter
    /// would mean changing the context type of every asset in the service.
    #[test]
    fn an_asset_may_override_the_callers_shape() {
        let out = expand_ok(
            quote!(
                profile = AppGrants,
                actions = WidgetAction,
                ctx = std::sync::Arc<AuthContext<Session, Claims>>,
                load_with = load
            ),
            quote!(
                pub struct Source;
            ),
        );

        assert!(
            out.contains("type Ctx = std :: sync :: Arc < AuthContext < Session , Claims > >"),
            "{out}",
        );
        // The rest still comes off the profile: an override is one item,
        // not an escape from the profile.
        assert!(
            out.contains("type State = < AppGrants as :: doxa :: auth :: GrantProfile > :: State"),
            "{out}",
        );
    }

    /// The struct is emitted untouched. A descriptor that came out a
    /// different shape than it was written would be a surprise in the one
    /// place surprises are least welcome — the type a handler receives.
    #[test]
    fn the_item_is_left_exactly_as_written() {
        let out = expand_ok(
            quote!(
                profile = AppGrants,
                actions = WidgetAction,
                load_with = load
            ),
            quote!(
                pub struct WidgetById;
            ),
        );

        assert!(out.contains("pub struct WidgetById ;"), "{out}");
        assert!(!out.contains("WidgetById ("), "no newtype: {out}");
    }

    /// A second key over one row names the row rather than wrapping it,
    /// so both descriptors share its `PolicyResource` impl.
    #[test]
    fn a_second_descriptor_names_the_row_it_shares() {
        let out = expand_ok(
            quote!(
                row = Source,
                profile = AppGrants,
                actions = WidgetAction,
                key = Uuid,
                load_with = load
            ),
            quote!(
                pub struct WidgetById;
            ),
        );

        assert!(out.contains("type Row = Source ;"), "{out}");
        assert!(out.contains("type Key = Uuid ;"), "{out}");
    }

    /// The generated lookup is confined to the caller's tenant, which is
    /// the security property `FetchByKey` exists for: a key owned by
    /// someone else answers `None`, exactly as a key that does not exist.
    #[test]
    fn the_default_loader_is_the_scoped_one() {
        let out = expand_ok(
            quote!(profile = AppGrants, actions = WidgetAction),
            quote!(
                pub struct Widget;
            ),
        );

        assert!(out.contains("fetch (key , state , scope)"), "{out}");
        assert!(out.contains("tenant (ctx)"), "{out}");
    }

    /// A caller with no tenant has no scope to confine the lookup to, and
    /// the loader answers that nothing is there rather than querying for
    /// the empty string.
    ///
    /// Paired with the test above because the two halves are separable:
    /// a loader that reads the tenant and then falls back to `""` also
    /// contains `tenant (ctx)`, and is the bug this arm exists to avoid.
    #[test]
    fn no_tenant_is_no_row_rather_than_an_empty_scope() {
        let out = expand_ok(
            quote!(profile = AppGrants, actions = WidgetAction),
            quote!(
                pub struct Widget;
            ),
        );

        assert!(
            out.contains(
                "let :: std :: option :: Option :: Some (scope) = :: doxa :: auth :: \
                 FromAuthExtensions :: tenant (ctx) else { return :: std :: result :: Result :: \
                 Ok (:: std :: option :: Option :: None) ; }"
            ),
            "{out}",
        );
        assert!(!out.contains("unwrap_or"), "{out}");
    }

    #[test]
    fn a_custom_loader_replaces_the_scoped_one() {
        let out = expand_ok(
            quote!(
                profile = AppGrants,
                actions = ModelAction,
                load_with = find_by_name
            ),
            quote!(
                pub struct GadgetByName;
            ),
        );

        assert!(out.contains("find_by_name (key , state , ctx)"), "{out}");
        assert!(!out.contains("load_scoped"), "{out}");
    }

    #[test]
    fn an_error_override_wins_over_the_profile() {
        let out = expand_ok(
            quote!(
                profile = AppGrants,
                actions = ModelAction,
                error = AmbiguousName,
                load_with = find_by_name
            ),
            quote!(
                pub struct GadgetByName;
            ),
        );

        assert!(out.contains("type Error = AmbiguousName ;"), "{out}");
    }

    /// Neither can be defaulted: one is the application's to choose and
    /// the other is the asset's whole permission surface.
    #[test]
    fn the_profile_and_the_vocabulary_are_both_required() {
        assert!(expand_err(
            quote!(actions = WidgetAction),
            quote!(
                pub struct Source;
            )
        )
        .contains("`profile = …`"),);
        assert!(expand_err(
            quote!(profile = AppGrants),
            quote!(
                pub struct Source;
            )
        )
        .contains("`actions = …`"),);
    }

    /// `pk` changes the lookup, not just the key type — which is why it
    /// is a word rather than `key = Uuid`. The generated call is
    /// `fetch_by_id`, which keeps the scope filter that a hand-written
    /// `find_by_id` drops.
    ///
    /// The trait it is qualified with is asserted too, and is not
    /// incidental: `FetchById` is the half a row gets from
    /// `#[resource(scope)]` alone, so naming `FetchByKey` here would put
    /// the id route out of reach of every collection that declares no key
    /// column — and back into a hand-written `find_by_id`.
    #[test]
    fn key_pk_selects_the_scoped_identifier_lookup() {
        let out = expand_ok(
            quote!(
                row = Widget,
                key = pk,
                profile = AppGrants,
                actions = WidgetAction
            ),
            quote!(
                pub struct WidgetById;
            ),
        );

        assert!(
            out.contains("type Key = < Widget as :: doxa :: policy :: FetchById <"),
            "{out}",
        );
        assert!(out.contains(">> :: Id ;"), "{out}");
        assert!(
            out.contains(":: fetch_by_id (key , state , scope)"),
            "{out}",
        );
        assert!(!out.contains(":: fetch (key"), "{out}");
    }

    /// A marker means "this row, by these columns", so naming a lookup
    /// names the row too — and the key comes off the same place. That is
    /// what leaves `with = …` as the entire declaration.
    #[test]
    fn with_takes_the_row_and_the_key_off_the_lookup() {
        let out = expand_ok(
            quote!(
                with = FindByPair,
                profile = AppGrants,
                actions = VersionAction
            ),
            quote!(
                pub struct VersionByPair;
            ),
        );

        assert!(
            out.contains("type Row = < FindByPair as :: doxa :: policy :: Lookup <"),
            "{out}",
        );
        assert!(
            out.contains("type Key = < FindByPair as :: doxa :: policy :: Lookup <"),
            "{out}",
        );
        assert!(out.contains(":: fetch (key , state , scope)"), "{out}",);
        // Still confined: `with` changes which columns are matched, not
        // whether the caller's tenant is.
        assert!(out.contains("tenant (ctx)"), "{out}");
    }

    /// Both are answers to "how is this row reached", and silently
    /// preferring one would mean a declaration naming a lookup it never
    /// uses.
    #[test]
    fn with_and_load_with_together_are_refused() {
        let message = expand_err(
            quote!(
                with = FindByPair,
                load_with = find_it,
                profile = AppGrants,
                actions = VersionAction
            ),
            quote!(
                pub struct VersionByPair;
            ),
        );

        assert!(message.contains("two answers"), "{message}");
    }

    /// A lookup already says which columns it matches, so `key = pk` beside
    /// it is a second and different way in.
    #[test]
    fn with_and_key_pk_together_are_refused() {
        let message = expand_err(
            quote!(
                with = FindByPair,
                key = pk,
                profile = AppGrants,
                actions = VersionAction
            ),
            quote!(
                pub struct VersionByPair;
            ),
        );

        assert!(message.contains("already says which columns"), "{message}");
    }

    /// An explicit `row` still wins, for the descriptor whose lookup
    /// produces a type it wants to call something else.
    #[test]
    fn an_explicit_row_wins_over_the_lookups() {
        let out = expand_ok(
            quote!(
                row = Version,
                with = FindByPair,
                profile = AppGrants,
                actions = VersionAction
            ),
            quote!(
                pub struct VersionByPair;
            ),
        );

        assert!(out.contains("type Row = Version ;"), "{out}");
        // The key is still the lookup's: only the row was overridden.
        assert!(
            out.contains("type Key = < FindByPair as :: doxa :: policy :: Lookup <"),
            "{out}",
        );
    }

    /// `key = pk` says what the key is, so a type beside it is a second
    /// answer to the same question.
    #[test]
    fn key_pk_and_a_key_type_together_are_refused() {
        let message = expand_err(
            quote!(
                key = pk,
                key = Uuid,
                profile = AppGrants,
                actions = WidgetAction
            ),
            quote!(
                pub struct WidgetById;
            ),
        );

        assert!(
            message.contains("already says what the key is"),
            "{message}"
        );
    }

    /// Listing is opt-in and names its filter. The generated `Scoping`
    /// applies the tenant and no other policy condition, so `list = tenant`
    /// rather than a bare `list` — the call site says which listing this
    /// is, and an asset needing the policy's residual writes its own.
    #[test]
    fn list_tenant_emits_a_tenant_confined_scoping() {
        let out = expand_ok(
            quote!(
                row = Widget,
                profile = AppGrants,
                actions = WidgetAction,
                list = tenant
            ),
            quote!(
                pub struct WidgetByName;
            ),
        );

        assert!(
            out.contains("impl :: doxa :: auth :: Scoping for WidgetByName"),
            "{out}",
        );
        assert!(
            out.contains("type Filter = < Widget as :: doxa :: policy :: FetchSubset > :: Filter"),
            "{out}",
        );
        assert!(out.contains(":: subset (scope)"), "{out}");
    }

    /// `unscoped` is forwarded rather than left at `Scoping`'s default, so
    /// a backend that can say "everything" is the one that decides whether
    /// an administrator gets it.
    ///
    /// Worth its own test because the default is silent: leaving the
    /// method off compiles, and the only symptom is an admin quietly
    /// receiving the tenant-filtered subset on a collection whose backend
    /// had a wider answer to give.
    #[test]
    fn list_tenant_forwards_the_backends_unrestricted_subset() {
        let out = expand_ok(
            quote!(
                row = Widget,
                profile = AppGrants,
                actions = WidgetAction,
                list = tenant
            ),
            quote!(
                pub struct WidgetByName;
            ),
        );

        assert!(
            out.contains(
                "fn unscoped () -> :: std :: option :: Option < Self :: Filter > { < Widget as \
                 :: doxa :: policy :: FetchSubset > :: everything () }"
            ),
            "{out}",
        );
    }

    /// No `list`, no `Scoping` — so `Granted<Many<…>>` over an asset that
    /// did not ask for a listing does not compile, which is the split
    /// `Scoping` exists for.
    #[test]
    fn without_list_there_is_no_scoping() {
        let out = expand_ok(
            quote!(
                profile = AppGrants,
                actions = WidgetAction,
                load_with = load
            ),
            quote!(
                pub struct WidgetByName;
            ),
        );

        assert!(!out.contains("Scoping"), "{out}");
    }

    #[test]
    fn a_listing_that_is_not_the_tenant_is_refused() {
        let message = expand_err(
            quote!(
                profile = AppGrants,
                actions = WidgetAction,
                list = everything
            ),
            quote!(
                pub struct WidgetByName;
            ),
        );

        assert!(message.contains("expected `list = tenant`"), "{message}");
        assert!(message.contains("hand-written `Scoping`"), "{message}");
    }

    #[test]
    fn an_unknown_option_names_the_ones_there_are() {
        let message = expand_err(
            quote!(profile = AppGrants, actions = WidgetAction, lookup = Thing),
            quote!(
                pub struct Source;
            ),
        );

        assert!(message.contains("unknown `asset` option"), "{message}");
        assert!(message.contains("load_with"), "{message}");
    }

    #[test]
    fn a_function_is_refused() {
        let message = expand_err(
            quote!(profile = AppGrants, actions = WidgetAction),
            quote!(
                fn source() {}
            ),
        );

        assert!(message.contains("goes on a struct"), "{message}");
    }
}
