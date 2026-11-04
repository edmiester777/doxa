//! `#[doxa::mirror(api::OnError)]`: `From` both ways between a type and its wire copy.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Fields, Item, Path};

pub fn expand(args: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let there: Path = syn::parse2(args)?;
    let item: Item = syn::parse2(item)?;
    let (ident, generics, arms) = match &item {
        Item::Struct(s) => {
            let ident = &s.ident;
            (
                ident,
                &s.generics,
                vec![arms(&quote!(#ident), &quote!(#there), &s.fields)],
            )
        }
        Item::Enum(e) => {
            let ident = &e.ident;
            let arms = e
                .variants
                .iter()
                .map(|v| {
                    let name = &v.ident;
                    arms(&quote!(#ident::#name), &quote!(#there::#name), &v.fields)
                })
                .collect();
            (ident, &e.generics, arms)
        }
        other => {
            return Err(syn::Error::new_spanned(
                other,
                "`mirror` goes on a struct or an enum",
            ))
        }
    };
    if !generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            generics,
            "`mirror` doesn't take a generic type",
        ));
    }
    let (to, from): (Vec<_>, Vec<_>) = arms.into_iter().unzip();
    Ok(quote! {
        #item

        impl ::core::convert::From<#ident> for #there {
            fn from(value: #ident) -> Self {
                match value { #(#to)* }
            }
        }

        impl ::core::convert::From<#there> for #ident {
            fn from(value: #there) -> Self {
                match value { #(#from)* }
            }
        }
    })
}

/// The arms converting `here` to `there` and back, every field through `Into`.
///
/// Neither pattern has `..` and no arm is a catch-all, so what only one side has is an error.
fn arms(here: &TokenStream, there: &TokenStream, fields: &Fields) -> (TokenStream, TokenStream) {
    let into = quote!(::core::convert::Into::into);
    match fields {
        Fields::Unit => (quote!(#here => #there,), quote!(#there => #here,)),
        Fields::Unnamed(f) => {
            let b: Vec<_> = (0..f.unnamed.len())
                .map(|i| format_ident!("f{i}"))
                .collect();
            (
                quote!(#here(#(#b),*) => #there(#(#into(#b)),*),),
                quote!(#there(#(#b),*) => #here(#(#into(#b)),*),),
            )
        }
        Fields::Named(f) => {
            let n: Vec<_> = f.named.iter().map(|f| f.ident.clone()).collect();
            (
                quote!(#here { #(#n),* } => #there { #(#n: #into(#n)),* },),
                quote!(#there { #(#n),* } => #here { #(#n: #into(#n)),* },),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_converts_both_ways_with_no_catch_all() {
        let out = expand(
            quote!(api::OnError),
            quote!(
                pub enum OnError {
                    Skip,
                    Retry(u32),
                }
            ),
        )
        .unwrap()
        .to_string();
        assert!(out.contains("From < OnError > for api :: OnError"), "{out}");
        assert!(out.contains("From < api :: OnError > for OnError"), "{out}");
        assert!(out.contains("api :: OnError :: Retry (f0)"), "{out}");
        assert!(!out.contains("_ =>"), "{out}");
    }

    #[test]
    fn a_generic_type_is_refused() {
        let err = expand(
            quote!(api::Page),
            quote!(
                pub struct Page<T>(T);
            ),
        )
        .unwrap_err();
        assert!(err.to_string().contains("generic"), "{err}");
    }
}
