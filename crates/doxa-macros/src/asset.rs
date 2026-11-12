//! `#[asset]`: a descriptor's `Granting` impl, from its profile, its actions and the row's lookup
//! (`FetchByKey`, `FetchById` for `key = pk`, or a named `Lookup` via `with`). The lookup gets only
//! the tenant, so it is confined to it; `load_with` gets the whole `Ctx`, and confinement is then
//! the consumer's to write. The struct is left as written.

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
    /// `key = pk`: the row's identifier through `FetchById`, needing no key column.
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
    /// The `#[doxa::entity]` this asset guards.
    entity: Option<Path>,
    /// `default = false`: a route reaches it only as `Grant<E, by = …>`.
    not_default: bool,
}

impl Parse for Args {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut out = Args::default();
        let mut seen = std::collections::HashSet::new();

        while !input.is_empty() {
            let key: Ident = input.parse()?;
            input.parse::<syn::Token![=]>()?;
            if !seen.insert(key.to_string()) {
                return Err(syn::Error::new(
                    key.span(),
                    format!("`{key}` is given twice"),
                ));
            }

            if key == "row" {
                out.row = Some(input.parse()?);
            } else if key == "profile" {
                out.profile = Some(input.parse()?);
            } else if key == "actions" {
                out.actions = Some(input.parse()?);
            } else if key == "key" {
                // `pk` names a lookup; the key type follows from it.
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
            } else if key == "entity" {
                out.entity = Some(input.parse()?);
            } else if key == "default" {
                out.not_default = !input.parse::<syn::LitBool>()?.value;
            } else {
                return Err(syn::Error::new(
                    key.span(),
                    "unknown `asset` option; expected `profile`, `actions`, `row`, `key`, \
                     `with`, `list`, `ctx`, `source`, `error`, `load_with`, `entity` or \
                     `default`",
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

/// The client half: the descriptor and the key that names one.
pub fn expand_client(args: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let args: Args = syn::parse2(args)?;
    let item: Item = syn::parse2(item)?;
    let name = match &item {
        Item::Struct(item) => &item.ident,
        Item::Enum(item) => &item.ident,
        other => return Err(syn::Error::new(other.span(), "`asset` goes on a struct")),
    };
    let Some(key) = &args.key else {
        return Err(syn::Error::new(
            name.span(),
            "the browser names this asset by its key, so a client-visible asset needs \
             `key = …`: a `route_key!` struct shared with the client",
        ));
    };
    let Some(actions) = &args.actions else {
        return Err(syn::Error::new(name.span(), "`asset` needs `actions = …`"));
    };
    let pkg_name = crate::role::package();
    Ok(quote! {
        #item

        impl ::doxa::wire::Keyed for #name {
            type Key = #key;
            const ENTITY_TYPE: &'static str = <#actions as ::doxa::wire::Vocabulary>::ENTITY_TYPE;
            const PACKAGE: &'static str = #pkg_name;
        }
    })
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

    // No defaults: either would invent a permission.
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

    // A descriptor has one way in.
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

    // The state is what the source yields. Resolved before the row, which a lookup reaches through it.
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

    // A lookup marker names its row; an explicit `row` wins.
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

    // `KEY_NAMES`' fallback, behind the key's own `RouteKey::NAMES`; `key = T` names no lookup.
    let lookup_names = match (&args.key, &args.with, args.by_primary_key) {
        (Some(_), _, _) => quote!(&[]),
        (None, Some(with), _) => {
            quote!(<#with as ::doxa::policy::Lookup<#state>>::KEY_NAMES)
        }
        (None, None, true) => {
            quote!(<#row as ::doxa::policy::FetchById<#state>>::ID_NAMES)
        }
        (None, None, false) => {
            quote!(<#row as ::doxa::policy::FetchByKey<#state>>::KEY_NAMES)
        }
    };

    let error = match &args.error {
        Some(error) => quote!(#error),
        None => quote!(<#profile as ::doxa::auth::GrantProfile>::Error),
    };

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
            let lookup = match (&args.with, args.by_primary_key) {
                (Some(with), _) => quote!(<#with as ::doxa::policy::Lookup<#state>>::fetch),
                (None, true) => quote!(<#row as ::doxa::policy::FetchById<#state>>::fetch_by_id),
                (None, false) => quote!(<#row as ::doxa::policy::FetchByKey<#state>>::fetch),
            };
            quote! {
                // The `?` converts the lookup's error, which may differ from `Self::Error`.
                #[allow(clippy::needless_question_mark)]
                async fn load(
                    key: Self::Key,
                    state: &Self::State,
                    ctx: &Self::Ctx,
                ) -> ::std::result::Result<::std::option::Option<Self::Row>, Self::Error> {
                    // Confined to the caller's tenant; no tenant finds nothing, never `scope = ''`.
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

    // Tenant-confined listing only; an asset needing the policy's residual writes `Scoping` itself.
    let scoping = match &args.list {
        None => quote!(),
        // `FetchSubset`, so a collection with no key column can still be listed.
        Some(_) => quote! {
            impl ::doxa::auth::Scoping for #name {
                type Filter = <#row as ::doxa::policy::FetchSubset>::Filter;
                const FROM_POLICY: bool = false;

                fn scope(
                    _action: &str,
                    ctx: &Self::Ctx,
                ) -> ::std::result::Result<
                    ::std::option::Option<Self::Filter>,
                    ::doxa::policy::AuthError,
                > {
                    // The action's capability (required, since `FROM_POLICY` is false) decided
                    // whether to list; the tenant decides which rows. No tenant is a refusal.
                    let ::std::option::Option::Some(scope) =
                        ::doxa::auth::FromAuthExtensions::tenant(ctx)
                    else {
                        return ::std::result::Result::Ok(::std::option::Option::None);
                    };
                    ::std::result::Result::Ok(::std::option::Option::Some(
                        <#row as ::doxa::policy::FetchSubset>::subset(scope),
                    ))
                }

                // Forwarded, so a backend that can answer "everything" is asked.
                fn unscoped() -> ::std::option::Option<Self::Filter> {
                    <#row as ::doxa::policy::FetchSubset>::everything()
                }
            }
        },
    };
    if args.not_default && args.entity.is_none() {
        return Err(syn::Error::new(
            name.span(),
            "`default = false` steps aside for another asset of the same entity: add `entity = …`",
        ));
    }
    let of_entity = of_entity(name, args.entity.as_ref(), !args.not_default);

    let pkg_name = crate::role::package();
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

            type Actions = #actions;

            const KEY_NAMES: &'static [&'static str] = ::doxa::auth::key_names(
                <#key as ::doxa::auth::RouteKey>::NAMES,
                #lookup_names,
            );

            #load
        }

        // What the spec tells a generated client about routes this asset guards.
        impl ::doxa::wire::Keyed for #name {
            type Key = #key;
            const ENTITY_TYPE: &'static str = <#actions as ::doxa::wire::Vocabulary>::ENTITY_TYPE;
            const PACKAGE: &'static str = #pkg_name;
        }

        #of_entity
    })
}

/// `entity = …`: the entity, held to this asset's entity type and key, and unless `default`
/// is off the asset a route's `Grant<entity>` guards with.
fn of_entity(name: &Ident, entity: Option<&Path>, default: bool) -> TokenStream {
    let Some(entity) = entity else {
        return TokenStream::new();
    };
    let asset_for = default.then(|| {
        let krate = crate::role::asset_crate();
        quote! {
            impl ::doxa::auth::AssetFor<#krate> for #entity {
                type Asset = #name;
            }
        }
    });
    let named = format!(
        "`{name}` guards a different entity type than `{}` declares; name the asset's \
         vocabulary after it, or give the entity `name = \"…\"`",
        quote!(#entity).to_string().replace(' ', "")
    );
    let keyed = format!(
        "`{name}` is named by different route parameters than `{}`'s key",
        quote!(#entity).to_string().replace(' ', "")
    );
    quote! {
        impl ::doxa::wire::contract::OfEntity for #name {
            type Entity = #entity;
        }
        #asset_for

        const _: () = ::core::assert!(
            ::doxa::wire::str_eq(
                <#name as ::doxa::wire::Keyed>::ENTITY_TYPE,
                <#entity as ::doxa::wire::Keyed>::ENTITY_TYPE,
            ),
            #named,
        );
        const _: () = ::core::assert!(
            ::doxa::wire::contract::same_names(
                <#name as ::doxa::auth::Granting>::KEY_NAMES,
                <<#entity as ::doxa::wire::Keyed>::Key as ::doxa::wire::KeyNames>::NAMES,
            ),
            #keyed,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_asset_names_the_entity_it_guards_and_is_held_to_its_name_and_key() {
        let out = expand_ok(
            quote!(
                profile = AppGrants,
                actions = OrderAction,
                entity = orders_api::Order
            ),
            quote!(
                pub struct OrderById;
            ),
        );
        assert!(
            out.contains("OfEntity for OrderById { type Entity = orders_api :: Order ; }"),
            "{out}"
        );
        assert!(out.contains("str_eq"), "{out}");
        assert!(out.contains("same_names"), "{out}");
        let plain = expand_ok(
            quote!(profile = AppGrants, actions = OrderAction),
            quote!(
                pub struct OrderById;
            ),
        );
        assert!(!plain.contains("OfEntity"), "{plain}");
    }

    #[test]
    fn the_entitys_default_asset_is_the_one_that_doesnt_step_aside() {
        let item = quote!(
            pub struct OrderById;
        );
        let default = expand_ok(
            quote!(profile = P, actions = A, entity = Order),
            item.clone(),
        );
        assert!(
            default.contains("AssetFor < () > for Order { type Asset = OrderById ; }"),
            "{default}"
        );
        let aside = expand_ok(
            quote!(profile = P, actions = A, entity = Order, default = false),
            item.clone(),
        );
        assert!(!aside.contains("AssetFor"), "{aside}");
        assert!(aside.contains("OfEntity for OrderById"), "{aside}");
        let err = expand(quote!(profile = P, actions = A, default = false), item).unwrap_err();
        assert!(err.to_string().contains("add `entity = …`"), "{err}");
    }

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
        // The vocabulary as a type, not flattened to its rows: that is
        // what holds a route's action to this asset.
        assert!(out.contains("type Actions = WidgetAction ;"), "{out}");
    }

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

    /// A loader falling back to `""` would pass the test above, so this one checks there is no fallback.
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

    #[test]
    fn the_key_names_come_off_the_lookup_that_was_selected() {
        let out = expand_ok(
            quote!(profile = AppGrants, actions = WidgetAction),
            quote!(
                pub struct Widget;
            ),
        );

        assert!(
            out.contains(
                "const KEY_NAMES : & 'static [& 'static str] = :: doxa :: auth :: key_names \
                 (< < Self as :: doxa :: policy :: FetchByKey"
            ),
            "{out}",
        );
        assert!(out.contains(":: KEY_NAMES ,) ;"), "{out}");
    }

    #[test]
    fn key_pk_takes_its_name_from_the_identifier() {
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
            out.contains("< Widget as :: doxa :: policy :: FetchById <"),
            "{out}",
        );
        assert!(out.contains(":: ID_NAMES ,) ;"), "{out}");
        assert!(!out.contains("KEY_NAMES ,) ;"), "{out}");
    }

    /// A named lookup carries its own columns, so `with = …` reaches those
    /// rather than the row's unnamed key — which it may not have.
    #[test]
    fn with_takes_its_names_off_the_named_lookup() {
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
            out.contains("< FindByPair as :: doxa :: policy :: Lookup <"),
            "{out}",
        );
        assert!(out.contains(":: KEY_NAMES ,) ;"), "{out}");
    }

    #[test]
    fn the_keys_own_names_are_preferred_over_the_lookups() {
        let out = expand_ok(
            quote!(
                with = ByQualifiedName,
                profile = AppGrants,
                actions = ModelAction
            ),
            quote!(
                pub struct ModelByName;
            ),
        );

        let call = out
            .split("key_names (")
            .nth(1)
            .expect("the resolution is emitted");
        let (preferred, _) = call.split_once(", <").expect("two arguments");
        assert!(
            preferred.contains(":: doxa :: auth :: RouteKey > :: NAMES"),
            "the key's own names come first: {preferred}",
        );
    }

    #[test]
    fn an_explicit_key_type_consults_no_lookup() {
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

        assert!(
            out.contains("key_names (< Uuid as :: doxa :: auth :: RouteKey > :: NAMES , & [] ,)"),
            "{out}",
        );
    }

    /// `FetchById` is what `#[resource(scope)]` alone gives a row, so the id route needs no key column.
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

        assert!(message.contains("`key` is given twice"), "{message}");
    }

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

    /// Leaving `unscoped` at the default compiles and silently narrows an admin's listing.
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
