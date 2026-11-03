//! `#[derive(Form)]`: a struct of fields, one per field, each named by its path in the rules'
//! errors and generic over the form that holds it. An enum's has its variant and, per variant,
//! the fields it holds while it is the one chosen.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::spanned::Spanned;
use syn::{
    Attribute, Data, DataEnum, DeriveInput, Field, Fields, GenericArgument, Ident, PathArguments,
    Type,
};

/// What one struct field becomes.
enum Shape {
    Value,
    Nested,
    List,
}

fn shape(field: &Field) -> syn::Result<Shape> {
    shape_of(&field.attrs)
}

fn shape_of(attrs: &[Attribute]) -> syn::Result<Shape> {
    let mut out = Shape::Value;
    for attr in attrs.iter().filter(|a| a.path().is_ident("form")) {
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
    let data = match &input.data {
        Data::Struct(data) => data,
        Data::Enum(data) => return expand_enum(&input, data),
        Data::Union(_) => {
            return Err(syn::Error::new(
                input.span(),
                "`#[derive(Form)]` goes on a struct with named fields or an enum",
            ))
        }
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

/// What a `ty` reached at `at`, an `At<__R, ty>`, becomes under `shape`: its type and value.
fn part(shape: Shape, ty: &Type, at: TokenStream) -> syn::Result<(TokenStream, TokenStream)> {
    Ok(match shape {
        Shape::Value => (quote!(::doxa::ui::Field<__R, #ty>), quote!(#at.value())),
        Shape::Nested => (
            quote!(<#ty as ::doxa::ui::FormFields>::Fields<__R>),
            quote!(<#ty as ::doxa::ui::FormFields>::project(#at)),
        ),
        Shape::List => {
            let elem = element(ty).ok_or_else(|| {
                syn::Error::new_spanned(ty, "`#[form(list)]` goes on a `Vec<T>` field")
            })?;
            (
                quote!(::doxa::ui::FieldList<__R, #elem>),
                quote!(#at.rows()),
            )
        }
    })
}

/// `name` as a method name, raw if it is a keyword.
fn method(name: &str) -> Ident {
    syn::parse_str::<Ident>(name).unwrap_or_else(|_| match name {
        "self" | "super" | "crate" => format_ident!("{name}_"),
        _ => Ident::new_raw(name, proc_macro2::Span::call_site()),
    })
}

fn expand_enum(input: &DeriveInput, data: &DataEnum) -> syn::Result<TokenStream> {
    let (name, vis) = (&input.ident, &input.vis);
    let fields_ty = format_ident!("{}Fields", name);
    let doc = format!(
        "The fields of a [`{name}`] form: `variant` picks one, and each variant's method gives \
         its fields while it is the one chosen."
    );
    let count = data.variants.len();
    let names: Vec<String> = data.variants.iter().map(|v| v.ident.to_string()).collect();

    let mut patterns = Vec::new();
    let mut defaults = Vec::new();
    let mut methods = Vec::new();
    let mut extra = Vec::new();
    for v in &data.variants {
        let (vn, label) = (&v.ident, v.ident.to_string());
        let acc = method(&crate::component::snake(&label));
        let acc_doc = format!("`{label}`'s fields, while it is the variant chosen.");
        match &v.fields {
            Fields::Unit => {
                patterns.push(quote!(#name::#vn));
                defaults.push(quote!(#name::#vn));
            }
            Fields::Unnamed(f) if f.unnamed.len() == 1 => {
                let field = &f.unnamed[0];
                let ty = &field.ty;
                let shape = match shape_of(&v.attrs)? {
                    Shape::Value => shape(field)?,
                    s => s,
                };
                let at = quote! {
                    self.__at.case(
                        #label,
                        "[0]",
                        |v| match v { #name::#vn(x) => Some(x), #[allow(unreachable_patterns)] _ => None },
                        |v| match v { #name::#vn(x) => Some(x), #[allow(unreachable_patterns)] _ => None },
                    )
                };
                let (decl, value) = part(shape, ty, at)?;
                patterns.push(quote!(#name::#vn(..)));
                defaults.push(quote!(#name::#vn(::core::default::Default::default())));
                methods.push(quote! {
                    #[doc = #acc_doc]
                    pub fn #acc(&self) -> ::core::option::Option<#decl> {
                        self.__at
                            .is(|v| ::core::matches!(v, #name::#vn(..)))
                            .then(|| #value)
                    }
                });
            }
            Fields::Named(f) => {
                let variant_ty = format_ident!("{}{}Fields", name, vn);
                let variant_doc = format!("The fields of [`{name}::{vn}`].");
                let mut decls = Vec::new();
                let mut inits = Vec::new();
                let mut zero = Vec::new();
                for field in &f.named {
                    let (n, ty) = (field.ident.as_ref().expect("named"), &field.ty);
                    let seg = n.to_string();
                    let at = quote! {
                        at.case(
                            #label,
                            #seg,
                            |v| match v { #name::#vn { #n, .. } => Some(#n), #[allow(unreachable_patterns)] _ => None },
                            |v| match v { #name::#vn { #n, .. } => Some(#n), #[allow(unreachable_patterns)] _ => None },
                        )
                    };
                    let (decl, value) = part(shape(field)?, ty, at)?;
                    let field_doc = format!("`{n}`.");
                    decls.push(quote! { #[doc = #field_doc] pub #n: #decl });
                    inits.push(quote! { #n: #value });
                    zero.push(quote! { #n: ::core::default::Default::default() });
                }
                patterns.push(quote!(#name::#vn { .. }));
                defaults.push(quote!(#name::#vn { #(#zero,)* }));
                extra.push(quote! {
                    #[doc = #variant_doc]
                    #vis struct #variant_ty<__R: 'static = #name> { #(#decls,)* }

                    impl<__R: 'static> ::core::clone::Clone for #variant_ty<__R> {
                        fn clone(&self) -> Self {
                            *self
                        }
                    }

                    impl<__R: 'static> ::core::marker::Copy for #variant_ty<__R> {}
                });
                methods.push(quote! {
                    #[doc = #acc_doc]
                    pub fn #acc(&self) -> ::core::option::Option<#variant_ty<__R>> {
                        let at = self.__at;
                        at.is(|v| ::core::matches!(v, #name::#vn { .. }))
                            .then(|| #variant_ty { #(#inits,)* })
                    }
                });
            }
            Fields::Unnamed(f) => {
                return Err(syn::Error::new(
                    f.span(),
                    "`#[derive(Form)]` takes an enum variant with one unnamed field, named ones, or none",
                ))
            }
        }
    }
    let index = 0..count;
    let index2 = 0..count;

    Ok(quote! {
        #[doc = #doc]
        #vis struct #fields_ty<__R: 'static = #name> {
            /// Which variant it is, by name; choosing another starts it at its default.
            pub variant: ::doxa::ui::Field<__R, ::std::string::String>,
            __at: ::doxa::ui::At<__R, #name>,
        }

        impl<__R: 'static> ::core::clone::Clone for #fields_ty<__R> {
            fn clone(&self) -> Self {
                *self
            }
        }

        impl<__R: 'static> ::core::marker::Copy for #fields_ty<__R> {}

        impl<__R: 'static> #fields_ty<__R> {
            /// Every variant's name, in order.
            pub const VARIANTS: &'static [&'static str] = &[#(#names),*];

            #(#methods)*
        }

        #(#extra)*

        impl ::doxa::ui::FormFields for #name {
            type Fields<__R: 'static> = #fields_ty<__R>;
            fn project<__R: 'static>(at: ::doxa::ui::At<__R, Self>) -> #fields_ty<__R> {
                fn name(v: &#name) -> &'static ::std::string::String {
                    static NAMES: ::std::sync::LazyLock<[::std::string::String; #count]> =
                        ::std::sync::LazyLock::new(|| [#(::std::string::String::from(#names)),*]);
                    match v { #(#patterns => &NAMES[#index],)* }
                }
                fn switch(v: &mut #name, to: ::std::string::String) {
                    if *name(v) == to {
                        return;
                    }
                    *v = match #fields_ty::<#name>::VARIANTS.iter().position(|n| *n == to) {
                        #(::core::option::Option::Some(#index2) => #defaults,)*
                        _ => return,
                    };
                }
                #fields_ty { variant: at.variant(name, switch), __at: at }
            }
        }
    })
}
