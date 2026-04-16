//! Implementation of `#[derive(SseEvent)]`.
//!
//! Generates a [`SseEventMeta`][meta] impl for the enum, mapping each
//! variant to an SSE event name. The name defaults to the variant's
//! snake-case form and can be overridden per variant with
//! `#[sse(name = "…")]`.
//!
//! This derive does *not* generate `serde::Serialize` or
//! `utoipa::ToSchema` — callers combine it with those upstream derives
//! and their `#[serde(tag = "event", content = "data")]` attribute, so
//! the wire format stays aligned with the schema description without
//! the macro re-implementing serde's renaming rules.
//!
//! [meta]: ../../doxa/trait.SseEventMeta.html

use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    parse2, Attribute, Data, DeriveInput, Error, Expr, ExprLit, Fields, Lit, Result, Variant,
};

/// Top-level entry point invoked from `lib.rs`.
pub fn expand(input: TokenStream) -> Result<TokenStream> {
    let derive_input: DeriveInput = parse2(input)?;
    let enum_name = derive_input.ident.clone();

    let data = match &derive_input.data {
        Data::Enum(data) => data,
        _ => {
            return Err(Error::new_spanned(
                &derive_input,
                "SseEvent can only be derived for enums",
            ))
        }
    };

    let variants = data
        .variants
        .iter()
        .map(parse_variant)
        .collect::<Result<Vec<_>>>()?;

    if variants.is_empty() {
        return Err(Error::new_spanned(
            &derive_input,
            "SseEvent requires at least one variant",
        ));
    }

    // `event_name(&self)` arms must match by shape (unit / tuple /
    // struct) so we don't require `PartialEq` on inner types.
    let name_arms = variants.iter().map(|v| {
        let ident = &v.ident;
        let name_lit = &v.name;
        match &v.fields_kind {
            FieldsKind::Unit => quote! { Self::#ident => #name_lit, },
            FieldsKind::Tuple => quote! { Self::#ident(..) => #name_lit, },
            FieldsKind::Named => quote! { Self::#ident { .. } => #name_lit, },
        }
    });

    let all_names: Vec<&str> = variants.iter().map(|v| v.name.as_str()).collect();

    let (impl_generics, ty_generics, where_clause) = derive_input.generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics ::doxa::SseEventMeta for #enum_name #ty_generics #where_clause {
            fn event_name(&self) -> &'static str {
                match self {
                    #(#name_arms)*
                }
            }

            fn all_event_names() -> &'static [&'static str] {
                &[#(#all_names),*]
            }
        }
    })
}

/// Parsed metadata for one variant.
struct ParsedVariant {
    ident: syn::Ident,
    name: String,
    fields_kind: FieldsKind,
}

enum FieldsKind {
    Unit,
    Tuple,
    Named,
}

fn parse_variant(variant: &Variant) -> Result<ParsedVariant> {
    let explicit = parse_sse_name_attr(&variant.attrs)?;
    let name = explicit.unwrap_or_else(|| to_snake_case(&variant.ident.to_string()));

    let fields_kind = match &variant.fields {
        Fields::Unit => FieldsKind::Unit,
        Fields::Unnamed(_) => FieldsKind::Tuple,
        Fields::Named(_) => FieldsKind::Named,
    };

    Ok(ParsedVariant {
        ident: variant.ident.clone(),
        name,
        fields_kind,
    })
}

/// Parse `#[sse(name = "…")]` from a variant's attribute list.
///
/// Supports exactly one key (`name`). Any other key or repeated
/// attribute is a compile error so typos surface early.
fn parse_sse_name_attr(attrs: &[Attribute]) -> Result<Option<String>> {
    let mut found: Option<String> = None;
    for attr in attrs {
        if !attr.path().is_ident("sse") {
            continue;
        }
        let mut this_name: Option<String> = None;
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("name") {
                let value = meta.value()?;
                let lit: Expr = value.parse()?;
                let Expr::Lit(ExprLit {
                    lit: Lit::Str(s), ..
                }) = lit
                else {
                    return Err(meta.error("expected `name = \"...\"` string literal"));
                };
                this_name = Some(s.value());
                Ok(())
            } else {
                Err(meta.error("unknown key in #[sse(...)]; expected `name`"))
            }
        })?;
        if found.is_some() {
            return Err(Error::new_spanned(
                attr,
                "duplicate #[sse(...)] attribute on variant",
            ));
        }
        found = this_name;
    }
    Ok(found)
}

/// Convert `PascalCase` identifier into `snake_case`.
///
/// Matches the simple rule serde applies for `rename_all =
/// "snake_case"` on PascalCase variants: every uppercase character
/// becomes lowercase, and `_` is inserted before each uppercase
/// character that is not at the start of the string. This keeps the
/// event-name line aligned with the `event` field produced by a
/// `#[serde(tag = "event", content = "data", rename_all =
/// "snake_case")]` attribute.
///
/// Acronym runs (`HTTPError`) intentionally produce `h_t_t_p_error`
/// to match serde's behavior — callers who want a different shape
/// can override per variant with `#[sse(name = "…")]`.
fn to_snake_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        if c.is_ascii_uppercase() {
            if !out.is_empty() {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::to_snake_case;

    #[test]
    fn snake_case_pascal_case_variants() {
        assert_eq!(to_snake_case("Started"), "started");
        assert_eq!(to_snake_case("InProgress"), "in_progress");
        assert_eq!(to_snake_case("Done"), "done");
    }
}
