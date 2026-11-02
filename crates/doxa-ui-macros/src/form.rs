//! `#[derive(Form)]`: a struct of `Field`s, one per field, each named by its garde path.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::spanned::Spanned;
use syn::{Data, DeriveInput, Fields};

pub(crate) fn expand(input: DeriveInput) -> syn::Result<TokenStream> {
    let name = &input.ident;
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new(
            input.generics.span(),
            "`#[derive(Form)]` structs can't be generic",
        ));
    }
    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new(
            input.span(),
            "`#[derive(Form)]` goes on a struct with named fields",
        ));
    };
    let Fields::Named(fields) = &data.fields else {
        return Err(syn::Error::new(
            data.fields.span(),
            "`#[derive(Form)]` goes on a struct with named fields",
        ));
    };
    let vis = &input.vis;
    let fields_ty = format_ident!("{}Fields", name);
    let doc = format!("The fields of a [`{name}`] form, from `form.fields()`.");
    let decls = fields.named.iter().map(|f| {
        let (n, ty) = (f.ident.as_ref().expect("named"), &f.ty);
        let doc = format!("`{n}`.");
        quote! { #[doc = #doc] pub #n: ::doxa::ui::Field<#name, #ty> }
    });
    let inits = fields.named.iter().map(|f| {
        let n = f.ident.as_ref().expect("named");
        let path = n.to_string();
        quote! { #n: ::doxa::ui::Field::new(form, #path, |v| &v.#n, |v| &mut v.#n) }
    });
    Ok(quote! {
        #[doc = #doc]
        #[derive(Clone, Copy)]
        #vis struct #fields_ty { #(#decls,)* }

        impl ::doxa::ui::FormFields for #name {
            type Fields = #fields_ty;
            fn fields(form: ::doxa::ui::Form<Self>) -> #fields_ty {
                #fields_ty { #(#inits,)* }
            }
        }
    })
}
