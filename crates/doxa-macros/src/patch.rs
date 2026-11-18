//! `#[derive(Patch)]` on a DTO and `#[derive(PatchTarget)]` on a sea-orm `Model`, joined by
//! field names spelled as types so a DTO field without a matching column fails to compile.

use proc_macro2::{Span, TokenStream};
use quote::{quote, quote_spanned};
use syn::{Data, DeriveInput, Fields, Ident, LitStr, Type};

use crate::policy_resource::is_primary_key;
use crate::ty::{inner_of, last_ident};

/// `(Ch<'n'>, Ch<'a'>, …,)`: always a tuple, even for one letter.
fn key(name: &str, span: Span) -> TokenStream {
    let chars = name.chars();
    quote_spanned!(span=> ( #( ::doxa::patch::Ch<#chars>, )* ))
}

fn unraw(ident: &Ident) -> String {
    let name = ident.to_string();
    name.strip_prefix("r#").map(str::to_owned).unwrap_or(name)
}

fn named_fields<'a>(input: &'a DeriveInput, derive: &str) -> syn::Result<&'a syn::FieldsNamed> {
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &input.generics,
            format!("`{derive}` doesn't take a generic type"),
        ));
    }
    match &input.data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(named) => Ok(named),
            other => Err(syn::Error::new_spanned(
                other,
                format!("`{derive}` needs named fields"),
            )),
        },
        _ => Err(syn::Error::new_spanned(
            &input.ident,
            format!("`{derive}` goes on a struct"),
        )),
    }
}

/// A field's `#[patch(skip)]` and `#[patch(column = "…")]`.
struct FieldArgs {
    skip: bool,
    column: Option<LitStr>,
}

fn field_args(field: &syn::Field, column_allowed: bool) -> syn::Result<FieldArgs> {
    let mut out = FieldArgs {
        skip: false,
        column: None,
    };
    for attr in field.attrs.iter().filter(|a| a.path().is_ident("patch")) {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("skip") {
                out.skip = true;
            } else if column_allowed && meta.path.is_ident("column") {
                out.column = Some(meta.value()?.parse()?);
            } else if column_allowed {
                return Err(meta.error("expected `skip` or `column = \"…\"`"));
            } else {
                return Err(meta.error("expected `skip`"));
            }
            Ok(())
        })?;
    }
    if out.skip && out.column.is_some() {
        return Err(syn::Error::new_spanned(
            &field.ident,
            "a skipped field names no column: drop `column`",
        ));
    }
    Ok(out)
}

fn has_serde_default(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .filter(|a| a.path().is_ident("serde"))
        .any(|a| {
            let mut found = false;
            let _ = a.parse_nested_meta(|meta| {
                found |= meta.path.is_ident("default");
                if meta.input.peek(syn::Token![=]) {
                    meta.value()?.parse::<syn::Expr>()?;
                } else if meta.input.peek(syn::token::Paren) {
                    meta.parse_nested_meta(|_| Ok(()))?;
                }
                Ok(())
            });
            found
        })
}

pub fn expand_patch(input: TokenStream) -> syn::Result<TokenStream> {
    let input: DeriveInput = syn::parse2(input)?;
    let ident = &input.ident;
    let fields = named_fields(&input, "Patch")?;
    let container_default = has_serde_default(&input.attrs);
    let field_trait = quote!(::doxa::patch::Field);
    let nullable_trait = quote!(::doxa::patch::NullableColumn);
    let mut bounds = Vec::new();
    let mut writes = Vec::new();

    for field in &fields.named {
        let args = field_args(field, true)?;
        if args.skip {
            continue;
        }
        let name = field.ident.as_ref().expect("named");
        let column = args
            .column
            .map(|c| c.value())
            .unwrap_or_else(|| unraw(name));
        let k = key(&column, name.span());
        let col = quote!(<__A as #field_trait<#k>>);
        if let Some(inner) = inner_of(&field.ty, "Nullable") {
            if !container_default && !has_serde_default(&field.attrs) {
                return Err(syn::Error::new_spanned(
                    &field.ty,
                    "a `Nullable` field needs `#[serde(default)]`, or a missing field reads as `Null`; `#[dto]` adds it",
                ));
            }
            bounds.push(quote!(__A: #field_trait<#k>));
            bounds.push(quote!(#col::Value: #nullable_trait));
            bounds.push(
                quote!(#inner: ::core::convert::Into<<#col::Value as #nullable_trait>::Inner>),
            );
            writes.push(quote! {
                match &self.#name {
                    ::doxa::wire::Nullable::Absent => {}
                    ::doxa::wire::Nullable::Null => #col::set(active, <#col::Value as #nullable_trait>::null()),
                    ::doxa::wire::Nullable::Value(v) => #col::set(
                        active,
                        <#col::Value as #nullable_trait>::value(
                            ::core::convert::Into::into(::core::clone::Clone::clone(v)),
                        ),
                    ),
                }
            });
        } else if let Some(inner) = inner_of(&field.ty, "Option") {
            bounds.push(quote!(__A: #field_trait<#k>));
            bounds.push(quote!(#inner: ::core::convert::Into<#col::Value>));
            writes.push(quote! {
                if let ::core::option::Option::Some(v) = &self.#name {
                    #col::set(active, ::core::convert::Into::into(::core::clone::Clone::clone(v)));
                }
            });
        } else {
            return Err(syn::Error::new_spanned(
                &field.ty,
                "a patch field is `Option<T>`, sent when `Some`, or `Nullable<T>`; mark it `#[patch(skip)]` to set it in the handler",
            ));
        }
    }

    Ok(quote! {
        impl<__A> ::doxa::patch::Patch<__A> for #ident
        where
            #(#bounds,)*
        {
            fn apply(&self, active: &mut __A) {
                let _ = &active;
                #(#writes)*
            }
        }
    })
}

/// Fields sea-orm leaves off the `ActiveModel`: `#[sea_orm(ignore)]` and relation wrappers.
fn not_a_column(field: &syn::Field) -> bool {
    if matches!(
        last_ident(&field.ty).as_deref(),
        Some("HasOne" | "HasMany" | "BelongsTo")
    ) {
        return true;
    }
    field.attrs.iter().any(|attr| {
        let syn::Meta::List(list) = &attr.meta else {
            return false;
        };
        attr.path().is_ident("sea_orm")
            && list
                .tokens
                .clone()
                .into_iter()
                .any(|t| matches!(t, proc_macro2::TokenTree::Ident(ident) if ident == "ignore"))
    })
}

pub fn expand_target(input: TokenStream) -> syn::Result<TokenStream> {
    let input: DeriveInput = syn::parse2(input)?;
    let fields = named_fields(&input, "PatchTarget")?;
    let mut out = TokenStream::new();

    for field in &fields.named {
        let args = field_args(field, false)?;
        if args.skip || is_primary_key(field) || not_a_column(field) {
            continue;
        }
        let name = field.ident.as_ref().expect("named");
        let ty: &Type = &field.ty;
        let k = key(&unraw(name), name.span());
        out.extend(quote! {
            impl ::doxa::patch::Field<#k> for ActiveModel {
                type Value = #ty;
                fn set(&mut self, value: #ty) {
                    self.#name.set_ne(value)
                }
            }
        });
        if field.attrs.iter().any(|a| a.path().is_ident("resource")) {
            let note = LitStr::new(
                &format!(
                    "`{}` is a policy resource column and patchable: mark it `#[patch(skip)]`",
                    unraw(name)
                ),
                Span::call_site(),
            );
            // The use keeps the field's own span: rustc drops deprecation warnings in derive spans.
            let used = name.clone();
            out.extend(quote! {
                const _: () = {
                    #[deprecated(note = #note)]
                    #[allow(non_upper_case_globals)]
                    const #name: () = ();
                    #used
                };
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patch(item: TokenStream) -> syn::Result<String> {
        expand_patch(item).map(|t| t.to_string())
    }

    #[test]
    fn option_and_nullable_fields_bound_their_columns() {
        let out = patch(quote! {
            pub struct Edit {
                pub name: Option<String>,
                #[serde(default)]
                pub note: Nullable<String>,
                #[patch(skip)]
                pub source: Option<String>,
            }
        })
        .unwrap();
        assert!(
            out.contains("Ch < 'n' > , :: doxa :: patch :: Ch < 'a' >"),
            "{out}"
        );
        assert!(out.contains("NullableColumn"), "{out}");
        assert!(!out.contains("source"), "{out}");
    }

    #[test]
    fn a_column_renames_the_key() {
        let out = patch(quote! {
            pub struct Edit {
                #[patch(column = "q")]
                pub quantity: Option<i32>,
            }
        })
        .unwrap();
        assert!(out.contains("(:: doxa :: patch :: Ch < 'q' > ,)"), "{out}");
    }

    #[test]
    fn a_plain_field_must_be_skipped() {
        let err = patch(quote!(
            pub struct Edit {
                pub name: String,
            }
        ))
        .unwrap_err();
        assert!(err.to_string().contains("`#[patch(skip)]`"), "{err}");
    }

    #[test]
    fn a_nullable_needs_a_default() {
        let err = patch(quote!(
            pub struct Edit {
                pub note: Nullable<String>,
            }
        ))
        .unwrap_err();
        assert!(err.to_string().contains("serde(default)"), "{err}");
        assert!(patch(quote! {
            #[serde(default)]
            pub struct Edit { pub note: Nullable<String> }
        })
        .is_ok());
    }

    #[test]
    fn the_target_leaves_out_the_key_and_non_columns() {
        let out = expand_target(quote! {
            pub struct Model {
                #[sea_orm(primary_key)]
                pub id: i32,
                pub name: String,
                #[sea_orm(ignore)]
                pub cached: u8,
                pub lines: HasMany<line::Entity>,
                #[patch(skip)]
                pub created_at: i64,
            }
        })
        .unwrap()
        .to_string();
        assert!(out.contains("self . name . set_ne"), "{out}");
        for gone in ["self . id", "cached", "lines", "created_at"] {
            assert!(!out.contains(gone), "{gone}: {out}");
        }
    }

    #[test]
    fn a_resource_column_warns_until_skipped() {
        let out = expand_target(quote! {
            pub struct Model {
                #[resource(scope)]
                pub tenant_id: String,
            }
        })
        .unwrap()
        .to_string();
        assert!(out.contains("deprecated"), "{out}");
        let skipped = expand_target(quote! {
            pub struct Model {
                #[resource(scope)]
                #[patch(skip)]
                pub tenant_id: String,
            }
        })
        .unwrap()
        .to_string();
        assert!(skipped.is_empty(), "{skipped}");
    }
}
