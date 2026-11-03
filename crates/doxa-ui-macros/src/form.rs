//! `#[derive(Form)]`: a struct of fields, one per field, each named by its path in the rules'
//! errors and generic over the form that holds it.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::spanned::Spanned;
use syn::{Data, DeriveInput, Field, Fields, GenericArgument, PathArguments, Type};

/// What one struct field becomes.
enum Shape {
    Value,
    Nested,
    List,
}

fn shape(field: &Field) -> syn::Result<Shape> {
    let mut out = Shape::Value;
    for attr in field.attrs.iter().filter(|a| a.path().is_ident("form")) {
        attr.parse_nested_meta(|meta| {
            out = if meta.path.is_ident("nested") {
                Shape::Nested
            } else if meta.path.is_ident("list") {
                Shape::List
            } else {
                return Err(meta.error("expected `#[form(nested)]` or `#[form(list)]`"));
            };
            Ok(())
        })?;
    }
    Ok(out)
}

/// `E` in `Vec<E>`.
fn element(ty: &Type) -> Option<&Type> {
    let Type::Path(p) = ty else { return None };
    let seg = p.path.segments.last().filter(|s| s.ident == "Vec")?;
    let PathArguments::AngleBracketed(args) = &seg.arguments else {
        return None;
    };
    args.args.iter().find_map(|a| match a {
        GenericArgument::Type(t) => Some(t),
        _ => None,
    })
}

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

    let mut decls = Vec::new();
    let mut inits = Vec::new();
    for f in &fields.named {
        let (n, ty) = (f.ident.as_ref().expect("named"), &f.ty);
        let path = n.to_string();
        let field_doc = format!("`{n}`.");
        let (decl, init) = match shape(f)? {
            Shape::Value => (
                quote!(::doxa::ui::Field<__R, #ty>),
                quote!(at.field(#path, |v| &v.#n, |v| &mut v.#n)),
            ),
            Shape::Nested => (
                quote!(<#ty as ::doxa::ui::FormFields>::Fields<__R>),
                quote!(at.nested(#path, |v| &v.#n, |v| &mut v.#n)),
            ),
            Shape::List => {
                let elem = element(ty).ok_or_else(|| {
                    syn::Error::new_spanned(ty, "`#[form(list)]` goes on a `Vec<T>` field")
                })?;
                (
                    quote!(::doxa::ui::FieldList<__R, #elem>),
                    quote!(at.list(#path, |v| &v.#n, |v| &mut v.#n)),
                )
            }
        };
        decls.push(quote! { #[doc = #field_doc] pub #n: #decl });
        inits.push(quote! { #n: #init });
    }

    Ok(quote! {
        #[doc = #doc]
        #vis struct #fields_ty<__R: 'static = #name> { #(#decls,)* }

        impl<__R: 'static> ::core::clone::Clone for #fields_ty<__R> {
            fn clone(&self) -> Self {
                *self
            }
        }

        impl<__R: 'static> ::core::marker::Copy for #fields_ty<__R> {}

        impl ::doxa::ui::FormFields for #name {
            type Fields<__R: 'static> = #fields_ty<__R>;
            fn project<__R: 'static>(at: ::doxa::ui::At<__R, Self>) -> #fields_ty<__R> {
                #fields_ty { #(#inits,)* }
            }
        }
    })
}
