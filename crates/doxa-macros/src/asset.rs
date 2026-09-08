//! `#[asset]` — the `Granting` impl an application would otherwise
//! transcribe.
//!
//! Five of `Granting`'s six items are not decisions. `Ctx`, `State` and
//! `Error` belong to the application and are the same for every asset in
//! it; `Key` and `load` are the lookup the row already declares through
//! [`ScopedRow`]; `Row` is `Self` unless the attribute says otherwise.
//! Only `ACTIONS` is a fact about this asset, and the attribute takes it
//! as one word.
//!
//! `ctx` and `error` override the profile for the asset that genuinely
//! differs — a loader answering 409 on an ambiguous name, or a `Scoping`
//! impl that needs the assembled session to read the policy's residual —
//! without the rest of the service restating anything.
//!
//! ```ignore
//! #[doxa::asset(profile = AppGrants, actions = WidgetAction)]
//! pub struct WidgetByName;
//! ```
//!
//! The struct is left exactly as written. That is the whole reason this
//! is an attribute on a descriptor rather than something that generates
//! one: `Granting::Row` is a separate associated type, so a second route
//! key over the same row is a unit struct naming `row = …`, not a newtype
//! wrapping it. Two descriptors over one row therefore share one
//! `PolicyResource` impl and cannot come to disagree about the object's
//! Cedar identity.
//!
//! [`ScopedRow`]: https://docs.rs/doxa-policy/latest/doxa_policy/trait.ScopedRow.html

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
    /// Route key. `<Row as ScopedRow>::Key` when absent.
    key: Option<Type>,
    /// `key = pk`: the row's primary key rather than its key column.
    by_primary_key: bool,
    /// Loader failure, overriding the profile's.
    error: Option<Type>,
    /// Caller shape, overriding the profile's.
    ctx: Option<Type>,
    /// A loader to call instead of `ScopedRow::load_scoped`.
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
            } else if key == "load_with" {
                out.load_with = Some(input.parse()?);
            } else {
                return Err(syn::Error::new(
                    key.span(),
                    "unknown `asset` option; expected `profile`, `actions`, `row`, `key`, \
                     `list`, `ctx`, `error` or `load_with`",
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

    let row = match &args.row {
        Some(row) => quote!(#row),
        None => quote!(Self),
    };

    if args.by_primary_key {
        if let Some(key) = &args.key {
            return Err(syn::Error::new(
                key.span(),
                "`key = pk` already says what the key is: the row's primary key",
            ));
        }
    }

    let key = match (&args.key, args.by_primary_key) {
        (Some(key), _) => quote!(#key),
        (None, true) => quote!(::doxa::policy::PrimaryKeyOf<#row>),
        (None, false) => quote!(<#row as ::doxa::policy::ScopedRow>::Key),
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

    // The loader is the one generated item that needs the ORM, so it is
    // the one gated on the feature. Without it the attribute still writes
    // the five associated items and asks only for `load_with`.
    let load =
        match &args.load_with {
            Some(path) => quote! {
                async fn load(
                    key: Self::Key,
                    state: &Self::State,
                    ctx: &Self::Ctx,
                ) -> ::std::result::Result<::std::option::Option<Self::Row>, Self::Error> {
                    #path(key, state, ctx).await
                }
            },
            None if cfg!(feature = "sea-orm") => {
                let lookup = if args.by_primary_key {
                    quote!(load_by_id)
                } else {
                    quote!(load_scoped)
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
                        ::std::result::Result::Ok(
                            <#row as ::doxa::policy::ScopedRow>::#lookup(key, state, scope).await?,
                        )
                    }
                }
            }
            None => return Err(syn::Error::new(
                name.span(),
                "`asset` writes the loader from `ScopedRow`, which needs the `sea-orm` feature \
                 on `doxa-macros`. Enable it, or supply `load_with = <fn>`",
            )),
        };

    // Listing, and only the tenant-confined kind. `Scoping::scope` is
    // meant to carry the policy's residual, which is a per-row condition
    // this cannot see — so the option names its filter rather than
    // implying it is that. An asset needing the residual writes `Scoping`
    // itself, and the compiler asks for it the moment a route says
    // `Many<…>`.
    let scoping =
        match &args.list {
            None => quote!(),
            Some(_) if !cfg!(feature = "sea-orm") => return Err(syn::Error::new(
                name.span(),
                "`list = tenant` builds the listing from `ScopedTable`, which needs the `sea-orm` \
                 feature on `doxa-macros`. Enable it, or write `Scoping` by hand",
            )),
            // Bounded on `ScopedTable` rather than `ScopedRow`: listing needs
            // the owning column and nothing else, so a table no route addresses
            // by a key column can still be paged.
            Some(_) => quote! {
                impl ::doxa::auth::Scoping for #name {
                    type Filter = ::doxa::policy::__private::sea_orm::Select<
                        <#row as ::doxa::policy::ScopedTable>::Entity,
                    >;

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
                            <#row as ::doxa::policy::ScopedTable>::scoped(scope),
                        ))
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
            type State = <#profile as ::doxa::auth::GrantProfile>::State;
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

    /// The common case: the row is its own descriptor, so five of the six
    /// items come from the profile and the row's own `ScopedRow`.
    ///
    /// `load_with` only so the assertions hold whether or not `sea-orm`
    /// is on; none of them are about the loader.
    #[test]
    fn the_profile_supplies_the_three_application_types() {
        let out = expand_ok(
            quote!(
                profile = AppGrants,
                actions = WidgetAction,
                load_with = load
            ),
            quote!(
                pub struct Source;
            ),
        );

        assert!(out.contains("type Row = Self ;"), "{out}");
        assert!(
            out.contains("type Key = < Self as :: doxa :: policy :: ScopedRow > :: Key"),
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
            out.contains("type Error = < AppGrants as :: doxa :: auth :: GrantProfile > :: Error"),
            "{out}",
        );
        assert!(
            out.contains("< WidgetAction as :: doxa :: auth :: ActionTable > :: ACTIONS"),
            "{out}",
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
    /// the security property `ScopedRow` exists for: a key owned by
    /// someone else answers `None`, exactly as a key that does not exist.
    #[cfg(feature = "sea-orm")]
    #[test]
    fn the_default_loader_is_the_scoped_one() {
        let out = expand_ok(
            quote!(profile = AppGrants, actions = WidgetAction),
            quote!(
                pub struct Source;
            ),
        );

        assert!(out.contains("load_scoped (key , state , scope)"), "{out}");
        assert!(out.contains("tenant (ctx)"), "{out}");
    }

    /// Without the ORM there is no lookup to write, and the error says
    /// which feature rather than leaving a missing method at the call
    /// site.
    #[cfg(not(feature = "sea-orm"))]
    #[test]
    fn without_the_orm_the_error_names_the_feature() {
        let message = expand_err(
            quote!(profile = AppGrants, actions = WidgetAction),
            quote!(
                pub struct Source;
            ),
        );

        assert!(message.contains("`sea-orm` feature"), "{message}");
        assert!(message.contains("load_with"), "{message}");
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
    /// `load_by_id`, whose default body keeps the scope filter that a
    /// hand-written `find_by_id` drops.
    #[cfg(feature = "sea-orm")]
    #[test]
    fn key_pk_selects_the_scoped_primary_key_lookup() {
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
            out.contains("type Key = :: doxa :: policy :: PrimaryKeyOf < Widget >"),
            "{out}",
        );
        assert!(out.contains("load_by_id (key , state , scope)"), "{out}");
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
    #[cfg(feature = "sea-orm")]
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
        assert!(out.contains("scoped (scope)"), "{out}");
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
