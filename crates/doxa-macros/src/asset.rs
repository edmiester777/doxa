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
//! ```ignore
//! #[doxa::asset(profile = AppGrants, actions = SourceAction)]
//! pub struct SourceByName;
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
    /// Loader failure, overriding the profile's.
    error: Option<Type>,
    /// A loader to call instead of `ScopedRow::load_scoped`.
    load_with: Option<Path>,
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
                out.key = Some(input.parse()?);
            } else if key == "error" {
                out.error = Some(input.parse()?);
            } else if key == "load_with" {
                out.load_with = Some(input.parse()?);
            } else {
                return Err(syn::Error::new(
                    key.span(),
                    "unknown `asset` option; expected `profile`, `actions`, `row`, `key`, \
                     `error` or `load_with`",
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

    let key = match &args.key {
        Some(key) => quote!(#key),
        None => quote!(<#row as ::doxa::policy::ScopedRow>::Key),
    };

    let error = match &args.error {
        Some(error) => quote!(#error),
        None => quote!(<#profile as ::doxa::auth::GrantProfile>::Error),
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
            None if cfg!(feature = "sea-orm") => quote! {
                async fn load(
                    key: Self::Key,
                    state: &Self::State,
                    ctx: &Self::Ctx,
                ) -> ::std::result::Result<::std::option::Option<Self::Row>, Self::Error> {
                    use ::doxa::auth::FromAuthExtensions as _;
                    // Every lookup is confined to the caller's tenant, so a
                    // key belonging to someone else answers `None` exactly as
                    // a key that does not exist would.
                    let scope = ::doxa::auth::FromAuthExtensions::tenant(ctx).unwrap_or_default();
                    ::std::result::Result::Ok(
                        <#row as ::doxa::policy::ScopedRow>::load_scoped(key, state, scope).await?,
                    )
                }
            },
            None => return Err(syn::Error::new(
                name.span(),
                "`asset` writes the loader from `ScopedRow`, which needs the `sea-orm` feature \
                 on `doxa-macros`. Enable it, or supply `load_with = <fn>`",
            )),
        };

    Ok(quote! {
        #item

        impl ::doxa::auth::Granting for #name {
            type Row = #row;
            type Key = #key;
            type Ctx = <#profile as ::doxa::auth::GrantProfile>::Ctx;
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
                actions = SourceAction,
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
            out.contains("< SourceAction as :: doxa :: auth :: ActionTable > :: ACTIONS"),
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
                actions = SourceAction,
                load_with = load
            ),
            quote!(
                pub struct SourceById;
            ),
        );

        assert!(out.contains("pub struct SourceById ;"), "{out}");
        assert!(!out.contains("SourceById ("), "no newtype: {out}");
    }

    /// A second key over one row names the row rather than wrapping it,
    /// so both descriptors share its `PolicyResource` impl.
    #[test]
    fn a_second_descriptor_names_the_row_it_shares() {
        let out = expand_ok(
            quote!(
                row = Source,
                profile = AppGrants,
                actions = SourceAction,
                key = Uuid,
                load_with = load
            ),
            quote!(
                pub struct SourceById;
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
            quote!(profile = AppGrants, actions = SourceAction),
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
            quote!(profile = AppGrants, actions = SourceAction),
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
                pub struct ModelByName;
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
                pub struct ModelByName;
            ),
        );

        assert!(out.contains("type Error = AmbiguousName ;"), "{out}");
    }

    /// Neither can be defaulted: one is the application's to choose and
    /// the other is the asset's whole permission surface.
    #[test]
    fn the_profile_and_the_vocabulary_are_both_required() {
        assert!(expand_err(
            quote!(actions = SourceAction),
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
    fn an_unknown_option_names_the_ones_there_are() {
        let message = expand_err(
            quote!(profile = AppGrants, actions = SourceAction, lookup = Thing),
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
            quote!(profile = AppGrants, actions = SourceAction),
            quote!(
                fn source() {}
            ),
        );

        assert!(message.contains("goes on a struct"), "{message}");
    }
}
