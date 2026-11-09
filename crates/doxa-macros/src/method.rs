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

use crate::client_stub::Flags;
use crate::{app, client_stub, grant, sig};

/// Expand `#[get("/path", ...)]` and friends.
pub fn expand(method: &str, args: TokenStream, item: TokenStream) -> Result<TokenStream> {
    let parsed = parse_method_args(args)?;
    route(method, &parsed.path, parsed.extra, item)
}

/// Expand `#[operation(get, "/path", ...)]` — same as the shortcut but
/// the method is the first positional argument.
pub fn expand_operation(args: TokenStream, item: TokenStream) -> Result<TokenStream> {
    let parsed = parse_operation_args(args)?;
    route(&parsed.method.to_string(), &parsed.path, parsed.extra, item)
}

/// A route, as this crate's role builds it.
fn route(method: &str, path: &LitStr, extra: Vec<Meta>, item: TokenStream) -> Result<TokenStream> {
    let (mount, extra) = take_mount_arg(extra)?;
    let (client, extra) = take_client_arg(extra)?;
    let (flags, extra) = take_route_flags(extra)?;
    let (touches, extra) = take_touches(extra)?;
    let item_fn = handler(item)?;
    let r = Parts {
        method,
        path,
        extra: &extra,
        mount,
        client,
        flags,
        touches: &touches,
    };
    match doxa_macro_support::Role::current() {
        doxa_macro_support::Role::Client => {
            client_half(method, path, &extra, client, flags, &touches, &item_fn)
        }
        doxa_macro_support::Role::Server => serve(&r, item_fn),
        doxa_macro_support::Role::Api => both_halves(&r, item_fn),
    }
}

/// A route attribute's arguments, past the path.
#[derive(Clone, Copy)]
struct Parts<'a> {
    method: &'a str,
    path: &'a LitStr,
    extra: &'a [Meta],
    mount: bool,
    client: bool,
    flags: Flags,
    touches: &'a [syn::Path],
}

fn handler(item: TokenStream) -> Result<ItemFn> {
    let bodiless = matches!(
        item.clone().into_iter().last(),
        Some(proc_macro2::TokenTree::Punct(p)) if p.as_char() == ';'
    );
    if bodiless {
        return Err(syn::Error::new_spanned(
            item,
            "a route has a body: the server runs it, and the browser's call drops it",
        ));
    }
    parse2(item)
}

/// The server half: the handler, its docs, its guards' sites and its mount.
fn serve(r: &Parts<'_>, mut item_fn: ItemFn) -> Result<TokenStream> {
    let method_ident = syn::Ident::new(r.method, proc_macro2::Span::call_site());
    strip_server_params(&mut item_fn);
    let meta = client_meta(r.method, r.client, r.flags, r.touches, &item_fn);

    // Rewrite `Granted<T>` arguments before inference runs, so the
    // signature the doc probes see is the one that actually compiles.
    let path_names = sig::parse_path_names(&r.path.value());
    let sites = grant::rewrite(&mut item_fn, r.method, &path_names)?;

    let utoipa_attr = build_utoipa_attr(&method_ident, r.path, r.extra, &item_fn)?;
    let mount = r.mount.then(|| app::mount(&item_fn));
    grant::stop_dry_runs(&mut item_fn);

    Ok(quote! {
        #meta
        #sites
        #utoipa_attr
        #item_fn
        #mount
    })
}

/// An API crate's route: the call on every target, and off wasm the handler beside it as
/// `name::serve`, so the two can share the name.
fn both_halves(r: &Parts<'_>, item_fn: ItemFn) -> Result<TokenStream> {
    use doxa_macro_support::{tag, Side};
    if let Some(granted) = typed_args(&item_fn).find(|t| grant::guarded_asset(t).is_some()) {
        return Err(syn::Error::new_spanned(
            granted,
            "an API crate's route guards by entity, which the browser knows too: \
             `Grant<Widget>`, or `Grant<Widget, by = WidgetById>` for an asset other than \
             the entity's default",
        ));
    }
    let mut server_fn = item_fn.clone();
    let by = grant_for_server(&mut server_fn)?;
    if !r.client {
        let served = serve(r, server_fn)?;
        return Ok(tag(Side::Server, quote!(#served #by)));
    }
    let name = &item_fn.sig.ident;
    let mut extra = r.extra.to_vec();
    if extra.iter().find_map(operation_id).is_none() {
        let id = LitStr::new(&name.to_string(), name.span());
        extra.push(syn::parse_quote!(operation_id = #id));
    }
    server_fn.sig.ident = syn::Ident::new("serve", name.span());
    let served = serve(
        &Parts {
            extra: &extra,
            ..*r
        },
        server_fn,
    )?;
    let server = tag(Side::Server, quote!(#served #by));

    let mut client_fn = item_fn;
    for arg in &mut client_fn.sig.inputs {
        if let syn::FnArg::Typed(pt) = arg {
            grant_as_granted(&mut pt.ty)?;
        }
    }
    let route = client_stub::Route {
        method: r.method,
        path: r.path,
        operation_id: extra.iter().find_map(operation_id),
        touches: r.touches,
        dry_run: r.flags.dry_run,
        invalidates: r.flags.invalidates,
    };
    client_stub::expand(&route, &client_fn, server)
}

fn typed_args(item_fn: &ItemFn) -> impl Iterator<Item = &Type> {
    item_fn.sig.inputs.iter().filter_map(|a| match a {
        syn::FnArg::Typed(pt) => Some(&*pt.ty),
        syn::FnArg::Receiver(_) => None,
    })
}

/// `Grant<S>` or `Grant<S, by = Asset>`: the subject and the asset it names, if any.
fn parse_grant(ty: &Type) -> Result<Option<(Type, Option<Type>)>> {
    let Type::Path(tp) = ty else { return Ok(None) };
    let Some(last) = tp.path.segments.last() else {
        return Ok(None);
    };
    if last.ident != "Grant" {
        return Ok(None);
    }
    let shape = || {
        syn::Error::new_spanned(
            tp,
            "`Grant` names the entity, and optionally its asset: `Grant<Order>`, \
             `Grant<Many<Order>>`, `Grant<Order, by = OrderById>`",
        )
    };
    let syn::PathArguments::AngleBracketed(args) = &last.arguments else {
        return Err(shape());
    };
    let mut args = args.args.iter();
    let Some(syn::GenericArgument::Type(subject)) = args.next() else {
        return Err(shape());
    };
    let by = match args.next() {
        None => None,
        Some(syn::GenericArgument::AssocType(a)) if a.ident == "by" && a.generics.is_none() => {
            Some(a.ty.clone())
        }
        Some(_) => return Err(shape()),
    };
    if args.next().is_some() {
        return Err(shape());
    }
    Ok(Some((subject.clone(), by)))
}

/// `Grant<E>` as the client's `Granted<E>`: `E`'s key is the argument, whichever asset guards it.
fn grant_as_granted(ty: &mut Type) -> Result<()> {
    if let Some((subject, _)) = parse_grant(ty)? {
        *ty = syn::parse_quote!(::doxa::client::Granted<#subject>);
    }
    Ok(())
}

/// Each `Grant<…>` as the server's `Granted<…>` over the entity's asset, and a check that
/// every `by = Asset` guards that entity.
fn grant_for_server(item_fn: &mut ItemFn) -> Result<TokenStream> {
    let mut checks = TokenStream::new();
    for arg in &mut item_fn.sig.inputs {
        let syn::FnArg::Typed(pt) = arg else { continue };
        let Some((subject, by)) = parse_grant(&pt.ty)? else {
            continue;
        };
        let (form, entity) =
            match type_arg_of(&subject, "Many").or_else(|| type_arg_of(&subject, "Cap")) {
                Some((form, inner)) => (Some(form), inner),
                None => (None, subject.clone()),
            };
        if form.as_deref() == Some("Cap") {
            if let Some(by) = by {
                return Err(syn::Error::new_spanned(
                    by,
                    "`Grant<Cap<…>>` asks for a capability, which no asset guards",
                ));
            }
            pt.ty = syn::parse_quote!(::doxa::auth::Granted<::doxa::auth::Cap<#entity>>);
            continue;
        }
        let asset: Type = match &by {
            Some(asset) => {
                checks.extend(quote! {
                    const _: fn() = ::doxa::wire::contract::guards::<#asset, #entity>;
                });
                asset.clone()
            }
            None => syn::parse_quote!(<#entity as ::doxa::auth::AssetFor>::Asset),
        };
        pt.ty = match form {
            Some(_) => syn::parse_quote!(::doxa::auth::Granted<::doxa::auth::Many<#asset>>),
            None => syn::parse_quote!(::doxa::auth::Granted<#asset>),
        };
    }
    Ok(checks)
}

/// `(form, T)` when `ty` is `form<T>`.
fn type_arg_of(ty: &Type, form: &str) -> Option<(String, Type)> {
    let Type::Path(tp) = ty else { return None };
    let last = tp.path.segments.last()?;
    if last.ident != form {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &last.arguments else {
        return None;
    };
    match args.args.first()? {
        syn::GenericArgument::Type(t) if args.args.len() == 1 => Some((form.to_owned(), t.clone())),
        _ => None,
    }
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
fn client_meta(
    method: &str,
    client: bool,
    flags: Flags,
    touches: &[syn::Path],
    item_fn: &ItemFn,
) -> TokenStream {
    let path = syn::Ident::new(
        &format!("__path_{}", item_fn.sig.ident),
        item_fn.sig.ident.span(),
    );
    if client {
        return client_stub::server_meta(method, touches, flags, item_fn, &path);
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
        let (flags, extra) = take_route_flags(extra)?;
        let (touches, extra) = take_touches(extra)?;
        out.extend(client_half(
            &method, &args.path, &extra, client, flags, &touches, &item_fn,
        )?);
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
    flags: Flags,
    touches: &[syn::Path],
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
            touches,
            dry_run: flags.dry_run,
            invalidates: flags.invalidates,
        },
        item_fn,
        TokenStream::new(),
    )
}

/// Pull `touches = [Entity, …]` out of the arguments: entities a call changes beyond its guards
/// and answer.
fn take_touches(extra: Vec<Meta>) -> Result<(Vec<syn::Path>, Vec<Meta>)> {
    let mut touches = Vec::new();
    let mut rest = Vec::with_capacity(extra.len());
    for meta in extra {
        let Meta::NameValue(nv) = &meta else {
            rest.push(meta);
            continue;
        };
        if !nv.path.is_ident("touches") {
            rest.push(meta);
            continue;
        }
        let syn::Expr::Array(list) = &nv.value else {
            return Err(syn::Error::new_spanned(
                &nv.value,
                "expected `touches = [Entity, …]`",
            ));
        };
        for e in &list.elems {
            match e {
                syn::Expr::Path(p) => touches.push(p.path.clone()),
                other => {
                    return Err(syn::Error::new_spanned(
                        other,
                        "`touches` names `#[entity]` types",
                    ))
                }
            }
        }
    }
    Ok((touches, rest))
}

/// Pull `client = false` out of the arguments; it is doxa's, not utoipa's.
fn take_client_arg(extra: Vec<Meta>) -> Result<(bool, Vec<Meta>)> {
    let (flags, rest) = take_flags(extra, &["client"])?;
    Ok((flags[0], rest))
}

/// Pull `dry_run = false`, which leaves `<Can>` answering `Unknown`, and `invalidates = false`,
/// for a route that only reads, out of the arguments.
fn take_route_flags(extra: Vec<Meta>) -> Result<(Flags, Vec<Meta>)> {
    let (flags, rest) = take_flags(extra, &["dry_run", "invalidates"])?;
    Ok((
        Flags {
            dry_run: flags[0],
            invalidates: flags[1],
        },
        rest,
    ))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn server(f: TokenStream) -> (String, String) {
        let mut item: ItemFn = syn::parse2(f).unwrap();
        let checks = grant_for_server(&mut item).unwrap();
        (item.sig.to_token_stream().to_string(), checks.to_string())
    }

    #[test]
    fn a_grant_guards_with_the_entitys_asset_unless_it_names_one() {
        let (sig, checks) = server(quote! { async fn f(w: Grant<Widget>) {} });
        assert!(
            sig.contains(
                ":: doxa :: auth :: Granted < < Widget as :: doxa :: auth :: AssetFor > :: Asset >"
            ),
            "{sig}"
        );
        assert!(checks.is_empty());

        let (sig, checks) = server(quote! { async fn f(w: Grant<Widget, by = WidgetById>) {} });
        assert!(
            sig.contains(":: doxa :: auth :: Granted < WidgetById >"),
            "{sig}"
        );
        assert!(
            checks.contains("guards :: < WidgetById , Widget >"),
            "{checks}"
        );
    }

    #[test]
    fn a_list_grant_scopes_the_asset_and_a_capability_names_none() {
        let (sig, _) = server(quote! { async fn f(_: Grant<Many<Order>, by = OrderById>) {} });
        assert!(
            sig.contains(":: doxa :: auth :: Granted < :: doxa :: auth :: Many < OrderById > >"),
            "{sig}"
        );
        let (sig, _) = server(quote! { async fn f(_: Grant<Cap<Place>>) {} });
        assert!(
            sig.contains(":: doxa :: auth :: Granted < :: doxa :: auth :: Cap < Place > >"),
            "{sig}"
        );
        let mut item: ItemFn =
            syn::parse2(quote! { async fn f(_: Grant<Cap<Place>, by = A>) {} }).unwrap();
        let err = grant_for_server(&mut item).unwrap_err();
        assert!(err.to_string().contains("no asset guards"), "{err}");
    }

    #[test]
    fn the_browser_sends_the_entitys_key_whichever_asset_guards_it() {
        let mut ty: Type = syn::parse_quote!(Grant<Widget, by = WidgetById>);
        grant_as_granted(&mut ty).unwrap();
        assert_eq!(
            ty.to_token_stream().to_string(),
            ":: doxa :: client :: Granted < Widget >"
        );
    }

    #[test]
    fn a_grant_takes_an_entity_and_at_most_its_asset() {
        for bad in [
            quote!(Grant),
            quote!(Grant<Widget, Other>),
            quote!(Grant<Widget, with = A>),
            quote!(Grant<Widget, by = A, by = B>),
        ] {
            let ty: Type = syn::parse2(bad).unwrap();
            let err = parse_grant(&ty).unwrap_err();
            assert!(
                err.to_string().contains("`Grant` names the entity"),
                "{err}"
            );
        }
    }

    #[test]
    fn a_route_has_a_body() {
        let err = handler(quote! { pub async fn f() -> Json<u32>; }).unwrap_err();
        assert!(err.to_string().contains("a route has a body"), "{err}");
    }
}
