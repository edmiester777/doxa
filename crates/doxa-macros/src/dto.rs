//! `#[dto]`: a wire type's derives, written once and correct in both halves.

use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::punctuated::Punctuated;
use syn::{Attribute, Data, DeriveInput, Fields, Ident, Path, Token};

/// A derive `#[dto]` adds unless the item already lists it or skips it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stock {
    Serialize,
    Deserialize,
    ToSchema,
    Debug,
    PartialEq,
    Clone,
    IntoParams,
}

impl Stock {
    const ALL: [Stock; 7] = [
        Stock::Serialize,
        Stock::Deserialize,
        Stock::ToSchema,
        Stock::Debug,
        Stock::PartialEq,
        Stock::Clone,
        Stock::IntoParams,
    ];

    fn name(self) -> &'static str {
        match self {
            Stock::Serialize => "Serialize",
            Stock::Deserialize => "Deserialize",
            Stock::ToSchema => "ToSchema",
            Stock::Debug => "Debug",
            Stock::PartialEq => "PartialEq",
            Stock::Clone => "Clone",
            Stock::IntoParams => "IntoParams",
        }
    }

    fn parse(ident: &Ident) -> syn::Result<Stock> {
        Stock::ALL
            .into_iter()
            .find(|d| ident == d.name())
            .ok_or_else(|| {
                syn::Error::new_spanned(
                    ident,
                    "`skip` takes `Serialize`, `Deserialize`, `ToSchema`, `Debug`, `PartialEq`, `Clone` or `IntoParams`",
                )
            })
    }

    /// The client needs serde both ways and `Clone` to call a route, so it never skips them.
    fn client_must_keep(self) -> bool {
        matches!(self, Stock::Serialize | Stock::Deserialize | Stock::Clone)
    }

    /// Only the server describes a type to OpenAPI.
    fn server_only(self) -> bool {
        matches!(self, Stock::ToSchema | Stock::IntoParams)
    }

    fn path(self) -> TokenStream {
        match self {
            Stock::Serialize => quote!(::doxa::__serde::Serialize),
            Stock::Deserialize => quote!(::doxa::__serde::Deserialize),
            Stock::ToSchema => quote!(::doxa::ToSchema),
            Stock::Debug => quote!(::core::fmt::Debug),
            Stock::PartialEq => quote!(::core::cmp::PartialEq),
            Stock::Clone => quote!(::core::clone::Clone),
            Stock::IntoParams => quote!(::doxa::IntoParams),
        }
    }
}

/// `#[dto]`, `#[dto(query)]`, `#[dto(skip(Debug, ToSchema))]`.
struct Args {
    query: bool,
    skip: Vec<Stock>,
}

impl Args {
    fn parse(args: TokenStream) -> syn::Result<Args> {
        let mut out = Args {
            query: false,
            skip: Vec::new(),
        };
        let parser = syn::meta::parser(|meta| {
            if meta.path.is_ident("query") {
                out.query = true;
            } else if meta.path.is_ident("skip") {
                meta.parse_nested_meta(|inner| {
                    let ident = inner.path.require_ident()?;
                    out.skip.push(Stock::parse(ident)?);
                    Ok(())
                })?;
            } else {
                return Err(meta.error("unknown `dto` option; expected `query` or `skip(…)`"));
            }
            Ok(())
        });
        syn::parse::Parser::parse2(parser, args)?;
        Ok(out)
    }

    fn wants(&self, d: Stock, client: bool) -> bool {
        if d == Stock::IntoParams && !self.query {
            return false;
        }
        if client {
            return d.client_must_keep() || (!d.server_only() && !self.skip.contains(&d));
        }
        !self.skip.contains(&d)
    }
}

/// Derives a client keeps from the item's own list, by last path segment.
const CLIENT_DERIVES: &[&str] = &[
    "Serialize",
    "Deserialize",
    "Debug",
    "Clone",
    "Copy",
    "PartialEq",
    "Eq",
    "PartialOrd",
    "Ord",
    "Hash",
    "Default",
    "Error",
    "Validate",
    "ApiError",
    "SseEvent",
    "Identity",
    "PolicyResource",
    "Form",
];

/// Attributes a client keeps; every other helper belongs to a derive it stripped.
const CLIENT_ATTRS: &[&str] = &[
    "doc",
    "serde",
    "garde",
    "validate",
    "api",
    "api_error",
    "api_default",
    "sse",
    "identity",
    "resource",
    "error",
    "source",
    "from",
    "backtrace",
    "form",
    "cfg",
    "cfg_attr",
    "allow",
    "warn",
    "deny",
    "forbid",
    "expect",
    "non_exhaustive",
    "repr",
    "default",
    "must_use",
    "deprecated",
];

fn last(path: &Path) -> String {
    path.segments
        .last()
        .map(|s| s.ident.to_string())
        .unwrap_or_default()
}

fn derives(attr: &Attribute) -> syn::Result<Vec<Path>> {
    Ok(attr
        .parse_args_with(Punctuated::<Path, Token![,]>::parse_terminated)?
        .into_iter()
        .collect())
}

fn keep_on_client(attr: &Attribute) -> bool {
    let path = attr.path();
    // Tool attributes (`rustfmt::skip`, `clippy::…`) are never a derive's helper.
    path.segments.len() > 1 || CLIENT_ATTRS.iter().any(|a| path.is_ident(a))
}

fn strip_fields(fields: &mut Fields) {
    for field in fields.iter_mut() {
        field.attrs.retain(keep_on_client);
    }
}

/// The item with `#[dto]`'s derives added, and in the client half its server-only ones removed.
pub fn expand(args: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let args = Args::parse(args)?;
    let mut input: DeriveInput = syn::parse2(item)?;
    let client = doxa_macro_support::is_client();

    if args.query && !matches!(&input.data, Data::Struct(s) if matches!(s.fields, Fields::Named(_)))
    {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "`#[dto(query)]` needs a struct with named fields, since each field is one query parameter",
        ));
    }

    let mut listed = Vec::new();
    let mut attrs = Vec::with_capacity(input.attrs.len());
    for attr in std::mem::take(&mut input.attrs) {
        if !attr.path().is_ident("derive") {
            if !client || keep_on_client(&attr) {
                attrs.push(attr);
            }
            continue;
        }
        let paths = derives(&attr)?;
        listed.extend(paths.iter().map(last));
        if client {
            let kept: Vec<Path> = paths
                .into_iter()
                .filter(|p| CLIENT_DERIVES.contains(&last(p).as_str()))
                .collect();
            if !kept.is_empty() {
                attrs.push(syn::parse_quote!(#[derive(#(#kept),*)]));
            }
        } else {
            attrs.push(attr);
        }
    }

    // `SseEvent` writes its own `ToSchema`, a discriminated `oneOf`.
    if listed.iter().any(|l| l == "SseEvent") {
        listed.push(Stock::ToSchema.name().to_owned());
    }
    let added: Vec<Stock> = Stock::ALL
        .into_iter()
        .filter(|d| args.wants(*d, client) && !listed.iter().any(|l| l == d.name()))
        .collect();
    let adds_serde = added
        .iter()
        .any(|d| matches!(d, Stock::Serialize | Stock::Deserialize));
    let serde_crate = (adds_serde && !has_serde_crate(&attrs))
        .then(|| quote!(#[serde(crate = "::doxa::__serde")]));
    let added: Vec<TokenStream> = added.into_iter().map(Stock::path).collect();

    if client {
        match &mut input.data {
            Data::Struct(s) => strip_fields(&mut s.fields),
            Data::Enum(e) => {
                for variant in &mut e.variants {
                    variant.attrs.retain(keep_on_client);
                    strip_fields(&mut variant.fields);
                }
            }
            Data::Union(u) => {
                return Err(syn::Error::new_spanned(
                    u.union_token,
                    "`#[dto]` is for structs and enums",
                ))
            }
        }
    }
    input.attrs = attrs;

    let derive = (!added.is_empty()).then(|| quote!(#[derive(#(#added),*)]));
    let mut out = TokenStream::new();
    derive.to_tokens(&mut out);
    serde_crate.to_tokens(&mut out);
    input.to_tokens(&mut out);
    Ok(out)
}

fn has_serde_crate(attrs: &[Attribute]) -> bool {
    attrs
        .iter()
        .filter(|a| a.path().is_ident("serde"))
        .any(|a| {
            let mut found = false;
            let _ = a.parse_nested_meta(|meta| {
                found |= meta.path.is_ident("crate");
                if meta.input.peek(Token![=]) {
                    meta.value()?.parse::<syn::Expr>()?;
                } else if meta.input.peek(syn::token::Paren) {
                    meta.parse_nested_meta(|_| Ok(()))?;
                }
                Ok(())
            });
            found
        })
}
