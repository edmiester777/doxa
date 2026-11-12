//! `#[doxa::entity(key = OrderKey)]`: a type a route's `Grant<…>` guards.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Item, LitStr, Type};

pub fn expand(args: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let mut key: Option<Type> = None;
    let mut name: Option<LitStr> = None;
    let mut actions: Option<Type> = None;
    let mut seen = std::collections::HashSet::new();
    let parser = syn::meta::parser(|meta| {
        crate::given_once(&mut seen, &meta)?;
        if meta.path.is_ident("key") {
            key = Some(meta.value()?.parse()?);
        } else if meta.path.is_ident("name") {
            name = Some(meta.value()?.parse()?);
        } else if meta.path.is_ident("actions") {
            actions = Some(meta.value()?.parse()?);
        } else {
            return Err(meta.error("unknown `entity` option; expected `key`, `name` or `actions`"));
        }
        Ok(())
    });
    syn::parse::Parser::parse2(parser, args)?;
    let item: Item = syn::parse2(item)?;
    let ident = match &item {
        Item::Struct(s) => &s.ident,
        Item::Enum(e) => &e.ident,
        other => {
            return Err(syn::Error::new_spanned(
                other,
                "`entity` goes on a struct or an enum",
            ))
        }
    };
    let key = key.ok_or_else(|| {
        syn::Error::new_spanned(
            ident,
            "an entity is named by a key: add `key = …`, a `route_key!` struct",
        )
    })?;
    let name = match (name, actions) {
        (Some(_), Some(actions)) => {
            return Err(syn::Error::new_spanned(
                actions,
                "`actions` names the entity already: drop `name`",
            ))
        }
        (Some(name), None) => quote!(#name),
        (None, Some(actions)) => quote!(<#actions as ::doxa::wire::Vocabulary>::ENTITY_TYPE),
        (None, None) => {
            let name = LitStr::new(&ident.to_string(), ident.span());
            quote!(#name)
        }
    };
    let pkg_name = crate::role::package();
    Ok(quote! {
        #item

        impl ::doxa::wire::Keyed for #ident {
            type Key = #key;
            const ENTITY_TYPE: &'static str = #name;
            const PACKAGE: &'static str = #pkg_name;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_entity_type_is_the_name_unless_given() {
        let out = expand(
            quote!(key = OrderKey),
            quote!(
                pub struct Order;
            ),
        )
        .unwrap();
        assert!(
            out.to_string()
                .contains("ENTITY_TYPE : & 'static str = \"Order\""),
            "{out}"
        );
        let named = expand(
            quote!(key = OrderKey, name = "Purchase"),
            quote!(
                pub struct Order;
            ),
        )
        .unwrap();
        assert!(named.to_string().contains("\"Purchase\""), "{named}");
    }

    #[test]
    fn a_vocabulary_names_the_entity() {
        let out = expand(
            quote!(key = OrderKey, actions = OrderAction),
            quote!(
                pub struct Order;
            ),
        )
        .unwrap();
        assert!(
            out.to_string()
                .contains("< OrderAction as :: doxa :: wire :: Vocabulary > :: ENTITY_TYPE"),
            "{out}"
        );
        let both = expand(
            quote!(key = OrderKey, name = "Order", actions = OrderAction),
            quote!(
                pub struct Order;
            ),
        )
        .unwrap_err();
        assert!(both.to_string().contains("drop `name`"), "{both}");
    }

    #[test]
    fn an_entity_needs_a_key() {
        let err = expand(
            quote!(),
            quote!(
                pub struct Order;
            ),
        )
        .unwrap_err();
        assert!(err.to_string().contains("add `key = …`"), "{err}");
    }
}
