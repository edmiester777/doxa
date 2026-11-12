//! `#[doxa::mirror(api::OnError)]`: `From` both ways between a type and its wire copy.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Fields, Item, Path, Type};

use crate::ty::inner_of;

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
    match fields {
        Fields::Unit => (quote!(#here => #there,), quote!(#there => #here,)),
        Fields::Unnamed(f) => {
            let b: Vec<_> = (0..f.unnamed.len())
                .map(|i| format_ident!("f{i}"))
                .collect();
            let v: Vec<_> = f
                .unnamed
                .iter()
                .zip(&b)
                .map(|(f, b)| converted(&f.ty, quote!(#b)))
                .collect();
            (
                quote!(#here(#(#b),*) => #there(#(#v),*),),
                quote!(#there(#(#b),*) => #here(#(#v),*),),
            )
        }
        Fields::Named(f) => {
            let n: Vec<_> = f.named.iter().map(|f| f.ident.clone()).collect();
            let v: Vec<_> = f
                .named
                .iter()
                .zip(&n)
                .map(|(f, n)| converted(&f.ty, quote!(#n)))
                .collect();
            (
                quote!(#here { #(#n),* } => #there { #(#n: #v),* },),
                quote!(#there { #(#n),* } => #here { #(#n: #v),* },),
            )
        }
    }
}

/// `value` of type `ty` as the other side's copy, through any `Option` and `Vec` around it.
fn converted(ty: &Type, value: TokenStream) -> TokenStream {
    if let Some(inner) = inner_of(ty, "Option") {
        let item = converted(inner, quote!(item));
        quote!(#value.map(|item| #item))
    } else if let Some(inner) = inner_of(ty, "Vec") {
        let item = converted(inner, quote!(item));
        quote!(#value.into_iter().map(|item| #item).collect())
    } else {
        quote!(::core::convert::Into::into(#value))
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
    fn a_field_converts_inside_its_option_and_vec() {
        let out = expand(
            quote!(api::Run),
            quote!(
                pub struct Run {
                    kind: Option<Kind>,
                    steps: Vec<Option<Step>>,
                    name: String,
                }
            ),
        )
        .unwrap()
        .to_string();
        assert!(
            out.contains("kind : kind . map (| item | :: core :: convert :: Into :: into (item))"),
            "{out}"
        );
        assert!(
            out.contains("steps : steps . into_iter () . map (| item | item . map"),
            "{out}"
        );
        assert!(
            out.contains("name : :: core :: convert :: Into :: into (name)"),
            "{out}"
        );
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
