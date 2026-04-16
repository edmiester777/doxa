//! HTTP method shortcut attribute macros.
//!
//! `#[get("/path", ...)]` expands to `#[utoipa::path(get, path = "/path",
//! ...)]` placed on the same function. The shortcut does two things the
//! upstream macro does not:
//!
//! 1. **Auto-fills `operation_id`** from the function name when the caller
//!    doesn't supply one.
//! 2. **Reads the function signature** via [`crate::sig::infer`] and injects
//!    `request_body`, `params`, and `responses` entries based on the handler's
//!    parameters and return type. Explicit overrides in the macro arguments
//!    always win — anything the caller declares by hand suppresses inference
//!    for that field.
//!
//! See [`crate::sig`] for the inference rules.

use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{
    parse::Parser, parse2, punctuated::Punctuated, ItemFn, LitStr, Meta, Result, Token, Type,
};

use crate::sig;

/// Expand `#[get("/path", ...)]` and friends.
pub fn expand(method: &str, args: TokenStream, item: TokenStream) -> Result<TokenStream> {
    let parsed_args = parse_method_args(args)?;
    let item_fn: ItemFn = parse2(item)?;
    let method_ident = syn::Ident::new(method, proc_macro2::Span::call_site());
    let path_lit = parsed_args.path;
    let extra = parsed_args.extra;

    let utoipa_attr = build_utoipa_attr(&method_ident, &path_lit, &extra, &item_fn)?;

    Ok(quote! {
        #utoipa_attr
        #item_fn
    })
}

/// Expand `#[operation(get, "/path", ...)]` — same as the shortcut but
/// the method is the first positional argument.
pub fn expand_operation(args: TokenStream, item: TokenStream) -> Result<TokenStream> {
    let parsed = parse_operation_args(args)?;
    let item_fn: ItemFn = parse2(item)?;

    let utoipa_attr = build_utoipa_attr(&parsed.method, &parsed.path, &parsed.extra, &item_fn)?;

    Ok(quote! {
        #utoipa_attr
        #item_fn
    })
}

struct MethodArgs {
    path: LitStr,
    extra: Vec<Meta>,
}

struct OperationArgs {
    method: syn::Ident,
    path: LitStr,
    extra: Vec<Meta>,
}

/// Parse `("/path", key = value, ...)`. The path is the first
/// positional argument; everything after the first comma is forwarded
/// to `utoipa::path` as-is.
fn parse_method_args(args: TokenStream) -> Result<MethodArgs> {
    let parser = Punctuated::<MethodArg, Token![,]>::parse_terminated;
    let parsed = parser.parse2(args)?;

    let mut iter = parsed.into_iter();
    let first = iter
        .next()
        .ok_or_else(|| syn::Error::new(proc_macro2::Span::call_site(), "expected a path string"))?;

    let path = match first {
        MethodArg::Path(lit) => lit,
        MethodArg::Meta(meta) => {
            return Err(syn::Error::new_spanned(
                meta,
                "first argument must be a path literal like \"/api/v1/foo\"",
            ))
        }
    };

    let extra = iter
        .map(|arg| match arg {
            MethodArg::Meta(meta) => Ok(*meta),
            MethodArg::Path(lit) => Err(syn::Error::new_spanned(
                lit,
                "only the first argument may be a path literal",
            )),
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(MethodArgs { path, extra })
}

/// Parse `(get, "/path", key = value, ...)` for `#[operation]`.
fn parse_operation_args(args: TokenStream) -> Result<OperationArgs> {
    let parser = Punctuated::<OperationArg, Token![,]>::parse_terminated;
    let parsed = parser.parse2(args)?;

    let mut iter = parsed.into_iter();
    let method = match iter.next() {
        Some(OperationArg::Method(ident)) => ident,
        Some(other) => {
            return Err(syn::Error::new_spanned(
                other.token_stream_for_error(),
                "first argument to operation must be an HTTP method identifier",
            ))
        }
        None => {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                "operation requires `(method, \"/path\", ...)`",
            ))
        }
    };

    let path = match iter.next() {
        Some(OperationArg::Path(lit)) => lit,
        Some(other) => {
            return Err(syn::Error::new_spanned(
                other.token_stream_for_error(),
                "second argument to operation must be a path literal",
            ))
        }
        None => {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                "operation requires a path literal after the method",
            ))
        }
    };

    let extra = iter
        .map(|arg| match arg {
            OperationArg::Meta(meta) => Ok(*meta),
            OperationArg::Method(ident) => Err(syn::Error::new_spanned(
                ident,
                "only the first argument may be the HTTP method",
            )),
            OperationArg::Path(lit) => Err(syn::Error::new_spanned(
                lit,
                "only the second argument may be a path literal",
            )),
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(OperationArgs {
        method,
        path,
        extra,
    })
}

/// One argument inside `#[get(...)]`. Either a string literal (path) or
/// a `key = value` / `key(...)` meta entry forwarded to `utoipa::path`.
/// `Meta` is boxed because the `syn::Meta` type is significantly larger
/// than the other variant — boxing keeps the enum compact.
enum MethodArg {
    Path(LitStr),
    Meta(Box<Meta>),
}

impl syn::parse::Parse for MethodArg {
    fn parse(input: syn::parse::ParseStream) -> Result<Self> {
        if input.peek(LitStr) {
            let lit: LitStr = input.parse()?;
            Ok(MethodArg::Path(lit))
        } else {
            let meta: Meta = input.parse()?;
            Ok(MethodArg::Meta(Box::new(meta)))
        }
    }
}

/// One argument inside `#[operation(...)]`. The first should be a bare
/// HTTP method identifier (`get`, `post`, ...), the second a path
/// literal, the rest meta entries.
enum OperationArg {
    Method(syn::Ident),
    Path(LitStr),
    Meta(Box<Meta>),
}

impl OperationArg {
    fn token_stream_for_error(&self) -> TokenStream {
        match self {
            OperationArg::Method(i) => i.to_token_stream(),
            OperationArg::Path(l) => l.to_token_stream(),
            OperationArg::Meta(m) => m.to_token_stream(),
        }
    }
}

impl syn::parse::Parse for OperationArg {
    fn parse(input: syn::parse::ParseStream) -> Result<Self> {
        if input.peek(LitStr) {
            Ok(OperationArg::Path(input.parse()?))
        } else if input.peek(syn::Ident)
            && !input.peek2(Token![=])
            && !input.peek2(syn::token::Paren)
        {
            Ok(OperationArg::Method(input.parse()?))
        } else {
            Ok(OperationArg::Meta(Box::new(input.parse()?)))
        }
    }
}

/// Build the `#[utoipa::path(method, path = "...", operation_id = "...", ...)]`
/// attribute. Operation ID defaults to the function name if not
/// supplied in `extra`. `request_body`, `params`, and `responses` are
/// inferred from the function signature unless the caller already
/// supplied them.
///
/// `headers(Type1, Type2, ...)` is recognized as a top-level macro
/// argument and removed from the forwarded `extra` list — each type
/// is treated as a [`DocumentedHeader`][doc] marker and emitted as a
/// `::doxa::DocHeaderEntry<T>` entry inside the synthesized
/// `params(...)` block, alongside any header markers inferred from
/// the signature via the [`Header<H>`][hdr] extractor. Duplicates
/// (same type token from both sources) are emitted only once.
///
/// [doc]: ../../doxa/trait.DocumentedHeader.html
/// [hdr]: ../../doxa/struct.Header.html
fn build_utoipa_attr(
    method: &syn::Ident,
    path: &LitStr,
    extra: &[Meta],
    item_fn: &ItemFn,
) -> Result<TokenStream> {
    let has_operation_id = extra.iter().any(|m| m.path().is_ident("operation_id"));
    let fn_name = item_fn.sig.ident.to_string();

    let operation_id_tt = if has_operation_id {
        quote! {}
    } else {
        let id = LitStr::new(&fn_name, proc_macro2::Span::call_site());
        quote! { , operation_id = #id }
    };

    // Strip `headers(...)` and `tags(...)` out of `extra` so they
    // don't get forwarded verbatim to `utoipa::path` (which doesn't
    // know these keys). Headers are merged into inferred markers;
    // tags are emitted as a `tags = [...]` array.
    let (explicit_headers, after_headers) = extract_headers_arg(extra)?;
    let (explicit_tags, forwarded_extra) = extract_tags_arg(&after_headers)?;

    // Infer from the signature, then merge in the explicit headers.
    let user_keys = sig::collect_user_keys(&forwarded_extra);
    let mut inferred = sig::infer(item_fn);
    merge_explicit_headers(&mut inferred.header_marker_types, explicit_headers);
    let path_param_names = sig::parse_path_names(&path.value());
    let sig::InferredTokens {
        pre_items,
        attr_additions,
    } = inferred.into_tokens(&item_fn.sig.ident, &path_param_names, &user_keys);

    // Emit `tags = ["A", "B"]` if the caller supplied `tags(...)`
    // and didn't already supply `tag = "..."` via forwarded args.
    let tags_tt = if !explicit_tags.is_empty() && !user_keys.contains(&"tag") {
        quote! { , tags = [#(#explicit_tags),*] }
    } else {
        quote! {}
    };

    let extra_tt = if forwarded_extra.is_empty() {
        quote! {}
    } else {
        let metas = forwarded_extra.iter();
        quote! { , #(#metas),* }
    };

    Ok(quote! {
        #pre_items
        #[::utoipa::path(
            #method,
            path = #path
            #operation_id_tt
            #attr_additions
            #tags_tt
            #extra_tt
        )]
    })
}

/// Pull `headers(Type1, Type2, ...)` out of an `extra` meta list and
/// return both the parsed marker types and the remaining metas (which
/// are forwarded verbatim to `utoipa::path`).
fn extract_headers_arg(extra: &[Meta]) -> Result<(Vec<Type>, Vec<Meta>)> {
    let mut header_types = Vec::new();
    let mut forwarded = Vec::with_capacity(extra.len());
    for meta in extra {
        if meta.path().is_ident("headers") {
            let Meta::List(list) = meta else {
                return Err(syn::Error::new_spanned(
                    meta,
                    "expected `headers(Type1, Type2, ...)`",
                ));
            };
            let parser = Punctuated::<Type, Token![,]>::parse_terminated;
            let parsed = parser.parse2(list.tokens.clone())?;
            header_types.extend(parsed.into_iter());
        } else {
            forwarded.push(meta.clone());
        }
    }
    Ok((header_types, forwarded))
}

/// Pull `tags("Tag1", "Tag2", ...)` out of an `extra` meta list and
/// return both the parsed string literals and the remaining metas.
/// Unlike `headers(...)`, tags are string literals (not types) because
/// they map to OpenAPI tag names.
fn extract_tags_arg(extra: &[Meta]) -> Result<(Vec<LitStr>, Vec<Meta>)> {
    let mut tag_lits = Vec::new();
    let mut forwarded = Vec::with_capacity(extra.len());
    for meta in extra {
        if meta.path().is_ident("tags") {
            let Meta::List(list) = meta else {
                return Err(syn::Error::new_spanned(
                    meta,
                    "expected `tags(\"Tag1\", \"Tag2\", ...)`",
                ));
            };
            let parser = Punctuated::<LitStr, Token![,]>::parse_terminated;
            let parsed = parser.parse2(list.tokens.clone())?;
            tag_lits.extend(parsed.into_iter());
        } else {
            forwarded.push(meta.clone());
        }
    }
    Ok((tag_lits, forwarded))
}

/// Merge explicitly-listed header marker types into the inferred set,
/// dedup-ing on the canonical token-string form. Order is preserved:
/// inferred first, then explicit additions that weren't already
/// matched by inference.
fn merge_explicit_headers(inferred: &mut Vec<Type>, explicit: Vec<Type>) {
    let mut seen: Vec<String> = inferred
        .iter()
        .map(|t| t.to_token_stream().to_string())
        .collect();
    for ty in explicit {
        let key = ty.to_token_stream().to_string();
        if !seen.contains(&key) {
            seen.push(key);
            inferred.push(ty);
        }
    }
}
