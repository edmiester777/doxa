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

use crate::{app, client_stub, grant, sig};

/// Expand `#[get("/path", ...)]` and friends.
pub fn expand(method: &str, args: TokenStream, item: TokenStream) -> Result<TokenStream> {
    let parsed_args = parse_method_args(args)?;
    let method_ident = syn::Ident::new(method, proc_macro2::Span::call_site());
    let path_lit = parsed_args.path;
    let (mount, extra) = take_mount_arg(parsed_args.extra)?;
    let (client, extra) = take_client_arg(extra)?;
    let mut item_fn = match routed(item)? {
        Routed::Handler(f) => f,
        Routed::Declaration(f) => return declaration(method, &path_lit, &extra, client, &f),
    };

    if doxa_macro_support::is_client() {
        return client_half(method, &path_lit, &extra, client, &item_fn);
    }
    strip_server_params(&mut item_fn);
    let meta = client_meta(method, client, &item_fn);

    // Rewrite `Granted<T>` arguments before inference runs, so the
    // signature the doc probes see is the one that actually compiles.
    let path_names = sig::parse_path_names(&path_lit.value());
    let sites = grant::rewrite(&mut item_fn, method, &path_names)?;

    let utoipa_attr = build_utoipa_attr(&method_ident, &path_lit, &extra, &item_fn)?;
    let mount = mount.then(|| app::mount(&item_fn, None));

    Ok(quote! {
        #meta
        #sites
        #utoipa_attr
        #item_fn
        #mount
    })
}

/// Expand `#[operation(get, "/path", ...)]` — same as the shortcut but
/// the method is the first positional argument.
pub fn expand_operation(args: TokenStream, item: TokenStream) -> Result<TokenStream> {
    let parsed = parse_operation_args(args)?;
    let (mount, extra) = take_mount_arg(parsed.extra)?;
    let (client, extra) = take_client_arg(extra)?;
    let parsed = OperationArgs { extra, ..parsed };
    let mut item_fn = match routed(item)? {
        Routed::Handler(f) => f,
        Routed::Declaration(f) => {
            let method = parsed.method.to_string();
            return declaration(&method, &parsed.path, &parsed.extra, client, &f);
        }
    };

    if doxa_macro_support::is_client() {
        let method = parsed.method.to_string();
        return client_half(&method, &parsed.path, &parsed.extra, client, &item_fn);
    }
    strip_server_params(&mut item_fn);
    let meta = client_meta(&parsed.method.to_string(), client, &item_fn);

    let path_names = sig::parse_path_names(&parsed.path.value());
    let sites = grant::rewrite(&mut item_fn, &parsed.method.to_string(), &path_names)?;

    let utoipa_attr = build_utoipa_attr(&parsed.method, &parsed.path, &parsed.extra, &item_fn)?;
    let mount = mount.then(|| app::mount(&item_fn, None));

    Ok(quote! {
        #meta
        #sites
        #utoipa_attr
        #item_fn
        #mount
    })
}

/// A route attribute's item: a handler, or in an API crate a declaration ending in `;`.
enum Routed {
    Handler(ItemFn),
    /// The signature, with an empty body standing in for the missing one.
    Declaration(ItemFn),
}

fn routed(item: TokenStream) -> Result<Routed> {
    let declares = matches!(
        item.clone().into_iter().last(),
        Some(proc_macro2::TokenTree::Punct(p)) if p.as_char() == ';'
    );
    let api = doxa_macro_support::is_api();
    if !declares {
        let item_fn: ItemFn = parse2(item)?;
        if api {
            return Err(syn::Error::new_spanned(
                &item_fn.sig,
                "an API crate declares routes rather than serving them: end the signature \
                 with `;`, and serve it from the server with `#[doxa::implements(…)]`",
            ));
        }
        return Ok(Routed::Handler(item_fn));
    }
    let parser = |input: syn::parse::ParseStream| -> Result<ItemFn> {
        let attrs = input.call(syn::Attribute::parse_outer)?;
        let vis: syn::Visibility = input.parse()?;
        let sig: syn::Signature = input.parse()?;
        input.parse::<Token![;]>()?;
        Ok(ItemFn {
            attrs,
            vis,
            sig,
            block: Box::new(syn::parse_quote!({})),
        })
    };
    let item_fn = parser.parse2(item)?;
    if !api {
        return Err(syn::Error::new_spanned(
            &item_fn.sig,
            "a route without a body is a declaration, which only an API crate makes: \
             call `doxa_role::api()` from its `build.rs`",
        ));
    }
    Ok(Routed::Declaration(item_fn))
}

/// A declared route: the call to it, and the `Route` marker a server implements it against.
fn declaration(
    method: &str,
    path: &LitStr,
    extra: &[Meta],
    client: bool,
    item_fn: &ItemFn,
) -> Result<TokenStream> {
    if !client {
        return Err(syn::Error::new_spanned(
            &item_fn.sig,
            "a declared route is one clients call, so it can't take `client = false`",
        ));
    }
    if let syn::Visibility::Inherited = item_fn.vis {
        return Err(syn::Error::new_spanned(
            &item_fn.sig,
            "a declared route is part of the API: make it `pub`",
        ));
    }
    let mut item_fn = item_fn.clone();
    for arg in &mut item_fn.sig.inputs {
        if let syn::FnArg::Typed(pt) = arg {
            grant_as_granted(&mut pt.ty)?;
        }
    }
    let mut tags = Vec::new();
    for meta in extra {
        match meta {
            Meta::NameValue(nv) if nv.path.is_ident("operation_id") => {}
            Meta::NameValue(nv) if nv.path.is_ident("tag") => match &nv.value {
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(lit),
                    ..
                }) => tags.push(lit.clone()),
                other => return Err(syn::Error::new_spanned(other, "expected `tag = \"…\"`")),
            },
            Meta::List(_) if meta.path().is_ident("tags") => {
                tags.extend(extract_tags_arg(std::slice::from_ref(meta))?.0);
            }
            other => {
                return Err(syn::Error::new_spanned(
                    other,
                    "a declaration takes `operation_id`, `tag` and `tags(…)`; the rest of the \
                     operation is documented by the server that implements it",
                ))
            }
        }
    }
    let operation_id = extra.iter().find_map(operation_id);
    let route = client_stub::Route {
        method,
        path,
        operation_id,
    };
    let declared = client_stub::declared(&route, &item_fn, &tags)?;
    client_stub::expand(&route, &item_fn, declared)
}

/// `#[doxa::implements(api::route)]`: the handler serving a declared route, at its method and
/// path, held to its arguments and answers.
pub fn expand_implements(args: TokenStream, item: TokenStream) -> Result<TokenStream> {
    let (declaration, mount) = implements_args(args)?;
    let mut item_fn: ItemFn = parse2(item)?;
    if doxa_macro_support::is_client() || doxa_macro_support::is_api() {
        return Err(syn::Error::new_spanned(
            &item_fn.sig,
            "a server implements a declared route; this crate is a client half or an API crate",
        ));
    }
    let r = quote!(#declaration::Route);
    strip_server_params(&mut item_fn);
    let path = syn::Ident::new(
        &format!("__path_{}", item_fn.sig.ident),
        item_fn.sig.ident.span(),
    );
    let checks = client_stub::implemented(&item_fn, &r);
    let meta = client_stub::server_meta("", Some(&r), &item_fn, &path);
    let sites = grant::rewrite_for(&mut item_fn, &grant::RouteIs::Declared(&r))?;
    let operation = declared_operation(&item_fn, &r, &path);
    let mount = mount.then(|| app::mount(&item_fn, Some(&r)));
    Ok(quote! {
        #meta
        #sites
        #operation
        #checks
        // The guard's action is spelled through the declaration's verb.
        #[allow(clippy::type_complexity)]
        #item_fn
        #mount
    })
}

/// `api::route` and an optional `, mount = false`.
fn implements_args(args: TokenStream) -> Result<(syn::Path, bool)> {
    let parser = |input: syn::parse::ParseStream| -> Result<(syn::Path, Vec<Meta>)> {
        let path: syn::Path = input.parse()?;
        let mut rest = Vec::new();
        while input.parse::<Option<Token![,]>>()?.is_some() && !input.is_empty() {
            rest.push(input.parse::<Meta>()?);
        }
        Ok((path, rest))
    };
    let (path, rest) = parser.parse2(args)?;
    let (mount, rest) = take_mount_arg(rest)?;
    if let Some(extra) = rest.first() {
        return Err(syn::Error::new_spanned(
            extra,
            "`#[implements]` takes the declaration and `mount = false`",
        ));
    }
    Ok((path, mount))
}

/// The handler's OpenAPI operation, written by `utoipa::path` on a stand-in with no
/// arguments, at the declaration's method and path.
fn declared_operation(item_fn: &ItemFn, r: &TokenStream, path: &syn::Ident) -> TokenStream {
    let fn_ident = &item_fn.sig.ident;
    let stand_in = syn::Ident::new(&format!("__doxa_op_{fn_ident}"), fn_ident.span());
    let stand_in_path = syn::Ident::new(&format!("__path_{stand_in}"), fn_ident.span());
    let mut inferred = sig::infer(item_fn);
    if let Some(inner) = inferred.error_type.as_ref().and_then(fail_inner) {
        inferred.error_type = Some(inner);
    }
    let spec = quote!(<#r as ::doxa::wire::contract::Declared>::SPEC);
    let sig::InferredTokens {
        pre_items,
        attr_additions,
    } = inferred.into_tokens(fn_ident, &[], Some(&quote!(#spec.path)), &[]);
    let docs = item_fn.attrs.iter().filter(|a| a.path().is_ident("doc"));
    let op_id = LitStr::new(&fn_ident.to_string(), fn_ident.span());
    let dev = quote!(::utoipa::__dev);
    quote! {
        #[doc(hidden)]
        #[allow(non_camel_case_types)]
        pub struct #path;

        #pre_items

        #[::utoipa::path(get, path = "/", operation_id = #op_id #attr_additions)]
        #(#docs)*
        #[doc(hidden)]
        #[allow(dead_code, non_snake_case)]
        fn #stand_in() {}

        impl #dev::PathConfig for #path {
            fn path() -> ::std::string::String {
                ::std::string::ToString::to_string(#spec.path)
            }

            fn methods() -> ::std::vec::Vec<::utoipa::openapi::path::HttpMethod> {
                ::std::vec![::doxa::__private::contract::method(#spec.method)]
            }

            fn tags_and_operation() -> (
                ::std::vec::Vec<&'static str>,
                ::utoipa::openapi::path::Operation,
            ) {
                let mut tags = ::std::vec::Vec::new();
                let mut op = <#stand_in_path as ::utoipa::Path>::operation();
                ::doxa::__private::contract::document(
                    &mut op,
                    #spec,
                    <#r as ::doxa::wire::contract::Declared>::DOCS,
                );
                tags.extend_from_slice(<#r as ::doxa::wire::contract::Declared>::TAGS);
                (tags, op)
            }
        }

        impl<'t> #dev::Tags<'t> for #path {
            fn tags() -> ::std::vec::Vec<&'t str> {
                <#stand_in_path as #dev::Tags<'t>>::tags()
            }
        }

        impl #dev::SchemaReferences for #path {
            fn schemas(
                schemas: &mut ::std::vec::Vec<(
                    ::std::string::String,
                    ::utoipa::openapi::RefOr<::utoipa::openapi::schema::Schema>,
                )>,
            ) {
                <#stand_in_path as #dev::SchemaReferences>::schemas(schemas)
            }
        }
    }
}

/// `E` in `Fail<E>`, which `doxa::serves!` defines and documents as `E`.
fn fail_inner(ty: &Type) -> Option<Type> {
    let Type::Path(tp) = ty else { return None };
    let last = tp.path.segments.last()?;
    if last.ident != "Fail" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &last.arguments else {
        return None;
    };
    match args.args.first()? {
        syn::GenericArgument::Type(t) if args.args.len() == 1 => Some(t.clone()),
        _ => None,
    }
}

/// `Grant<E>` as the client's `Granted<E>`: `E`'s key is the argument.
fn grant_as_granted(ty: &mut Type) -> Result<()> {
    let Type::Path(tp) = ty else { return Ok(()) };
    let Some(last) = tp.path.segments.last() else {
        return Ok(());
    };
    if last.ident != "Grant" {
        return Ok(());
    }
    let syn::PathArguments::AngleBracketed(args) = &last.arguments else {
        return Err(syn::Error::new_spanned(
            &*tp,
            "`Grant` names the entity: `Grant<Order>`",
        ));
    };
    if args.args.len() != 1 {
        return Err(syn::Error::new_spanned(
            &*tp,
            "`Grant` takes the entity alone; the server's guard names the action",
        ));
    }
    let entity = &args.args[0];
    *ty = syn::parse_quote!(::doxa::client::Granted<#entity>);
    Ok(())
}

fn operation_id(m: &Meta) -> Option<&LitStr> {
    match m {
        Meta::NameValue(nv) if nv.path.is_ident("operation_id") => match &nv.value {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(lit),
                ..
            }) => Some(lit),
            _ => None,
        },
        _ => None,
    }
}

/// The `x-doxa` stamp for this route's operation; `{"client": false}` when it has no client half.
fn client_meta(method: &str, client: bool, item_fn: &ItemFn) -> TokenStream {
    let path = syn::Ident::new(
        &format!("__path_{}", item_fn.sig.ident),
        item_fn.sig.ident.span(),
    );
    if client {
        return client_stub::server_meta(method, None, item_fn, &path);
    }
    quote! {
        impl ::doxa::__private::ClientMeta for #path {
            fn meta() -> ::doxa::__private::serde_json::Value {
                ::doxa::__private::serde_json::json!({ "client": false })
            }
        }
    }
}

/// Expand every `#[get]` / `#[post]` / … in `input` as the client half, whatever the role.
pub fn expand_as_client(input: TokenStream) -> Result<TokenStream> {
    let file: syn::File = parse2(input)?;
    let mut out = TokenStream::new();
    for item in file.items {
        let syn::Item::Fn(mut item_fn) = item else {
            out.extend(item.into_token_stream());
            continue;
        };
        let position = item_fn.attrs.iter().position(|a| {
            a.path().segments.last().is_some_and(|s| {
                ["get", "post", "put", "patch", "delete"].contains(&s.ident.to_string().as_str())
            })
        });
        let Some(position) = position else {
            out.extend(item_fn.into_token_stream());
            continue;
        };
        let attr = item_fn.attrs.remove(position);
        let method = attr.path().segments.last().unwrap().ident.to_string();
        let args = parse_method_args(attr.meta.require_list()?.tokens.clone())?;
        let (client, extra) = take_client_arg(args.extra)?;
        out.extend(client_half(&method, &args.path, &extra, client, &item_fn)?);
    }
    Ok(out)
}

/// `#[server]` on a parameter: the client half drops it, the server half keeps it as is.
pub(crate) fn is_server_attr(attr: &syn::Attribute) -> bool {
    matches!(attr.meta, Meta::Path(_))
        && attr
            .path()
            .segments
            .last()
            .is_some_and(|s| s.ident == "server")
}

fn strip_server_params(item_fn: &mut ItemFn) {
    for arg in &mut item_fn.sig.inputs {
        if let syn::FnArg::Typed(pt) = arg {
            pt.attrs.retain(|a| !is_server_attr(a));
        }
    }
}

/// The client half: a typed call to this route, unless `client = false`.
fn client_half(
    method: &str,
    path: &LitStr,
    extra: &[Meta],
    client: bool,
    item_fn: &ItemFn,
) -> Result<TokenStream> {
    if !client {
        return Ok(TokenStream::new());
    }
    let operation_id = extra.iter().find_map(operation_id);
    client_stub::expand(
        &client_stub::Route {
            method,
            path,
            operation_id,
        },
        item_fn,
        TokenStream::new(),
    )
}

/// Pull `client = false` out of the arguments; it is doxa's, not utoipa's.
fn take_client_arg(extra: Vec<Meta>) -> Result<(bool, Vec<Meta>)> {
    let (flags, rest) = take_flags(extra, &["client"])?;
    Ok((flags[0], rest))
}

/// Pull `mount = false` out of the arguments, which leaves the handler to be routed by hand.
fn take_mount_arg(extra: Vec<Meta>) -> Result<(bool, Vec<Meta>)> {
    let (flags, rest) = take_flags(extra, &["mount"])?;
    Ok((flags[0], rest))
}

/// Each named boolean flag, `true` unless given as `false`, and the remaining arguments.
fn take_flags(extra: Vec<Meta>, names: &[&str]) -> Result<(Vec<bool>, Vec<Meta>)> {
    let mut flags = vec![true; names.len()];
    let mut rest = Vec::with_capacity(extra.len());
    for meta in extra {
        let at = match &meta {
            Meta::NameValue(nv) => names.iter().position(|n| nv.path.is_ident(n)),
            _ => None,
        };
        let (Some(at), Meta::NameValue(nv)) = (at, &meta) else {
            rest.push(meta);
            continue;
        };
        match &nv.value {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Bool(b),
                ..
            }) => flags[at] = b.value,
            other => {
                return Err(syn::Error::new_spanned(
                    other,
                    format!("expected `{0} = false` or `{0} = true`", names[at]),
                ))
            }
        }
    }
    Ok((flags, rest))
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
    } = inferred.into_tokens(&item_fn.sig.ident, &path_param_names, None, &user_keys);

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
            header_types.extend(parsed);
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
            tag_lits.extend(parsed);
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
