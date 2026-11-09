//! The client half of `#[get]` / `#[post]` / …: the same function name, as a
//! typed HTTP call to the same route.
//!
//! Types are rewritten by their last path segment, never resolved, so what
//! the user imported on the server side does not matter here.

use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::{FnArg, GenericArgument, ItemFn, LitStr, Pat, PathArguments, ReturnType, Type, TypePath};

use crate::grant;

/// Extractors the browser never sends: the server reads them off its own state.
const SERVER_ONLY: &[&str] = &[
    "State",
    "Extension",
    "Auth",
    "AuthContext",
    "CapabilityContext",
    "Require",
    "Scoped",
    "HeaderMap",
    "ConnectInfo",
    "OriginalUri",
    "MatchedPath",
    "Method",
    "Uri",
    "Request",
    "Parts",
    "Version",
];

enum Arg {
    Dropped,
    /// `#[server]`: read only on the server, and unknown to doxa.
    Server,
    Sent {
        name: syn::Ident,
        ty: TokenStream,
        kind: Kind,
        check: Option<Box<Check>>,
    },
}

/// A validating wrapper around a sent argument: `Valid<Json<T>>`, checked before sending.
struct Check {
    /// The wrapper around the client's extractor: `Valid<::doxa::client::Json<T>>`.
    wrapper: TokenStream,
    /// `T`.
    value: Type,
}

impl Arg {
    /// An extractor doxa can't vouch for: a dry run that stops at an earlier guard
    /// never runs it, so may say yes to a call it would refuse.
    fn unknown(&self) -> bool {
        matches!(
            self,
            Arg::Server
                | Arg::Sent {
                    kind: Kind::Foreign,
                    ..
                }
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Guard,
    Path,
    Plain,
    Body,
    Foreign,
}

/// Everything the client half needs from the route attribute.
pub struct Route<'a> {
    pub method: &'a str,
    pub path: &'a LitStr,
    pub operation_id: Option<&'a LitStr>,
    /// Entities a call changes beyond its guards and answer.
    pub touches: &'a [syn::Path],
    /// `false` when the route says `dry_run = false`: its guards don't tell the whole story.
    pub dry_run: bool,
    /// `false` when the route says `invalidates = false`: it reads, whatever its method.
    pub invalidates: bool,
}

/// A route's boolean arguments, each `true` unless it says otherwise.
#[derive(Clone, Copy)]
pub struct Flags {
    pub dry_run: bool,
    pub invalidates: bool,
}

impl Default for Flags {
    fn default() -> Self {
        Self {
            dry_run: true,
            invalidates: true,
        }
    }
}

/// Server-only extractors a handler body could authorize with, where no guard sees it.
const MAY_AUTHORIZE: &[&str] = &["Extension", "HeaderMap", "Request", "Parts", "ConnectInfo"];

fn may_authorize(item_fn: &ItemFn) -> bool {
    item_fn.sig.inputs.iter().any(|arg| match arg {
        FnArg::Typed(pt) => last_ident(&pt.ty).is_some_and(|n| MAY_AUTHORIZE.contains(&n.as_str())),
        FnArg::Receiver(_) => false,
    })
}

fn args(item_fn: &ItemFn) -> Vec<Arg> {
    item_fn
        .sig
        .inputs
        .iter()
        .enumerate()
        .filter_map(|(i, arg)| match arg {
            FnArg::Typed(pt) if pt.attrs.iter().any(crate::method::is_server_attr) => {
                Some(Arg::Server)
            }
            FnArg::Typed(pt) => Some(classify(&pt.pat, &pt.ty, i)),
            FnArg::Receiver(_) => None,
        })
        .collect()
}

/// Whether a dry run's answer means anything: it needs a guard to have asked, and nothing a
/// guard can't speak for.
fn dry_run(item_fn: &ItemFn, args: &[Arg]) -> bool {
    let typed: Vec<usize> = item_fn
        .sig
        .inputs
        .iter()
        .enumerate()
        .filter(|(_, a)| matches!(a, FnArg::Typed(_)))
        .map(|(i, _)| i)
        .collect();
    match grant::last_guard(item_fn) {
        Some(gate) if !may_authorize(item_fn) => {
            let after = typed.iter().position(|i| *i == gate).map_or(0, |p| p + 1);
            !args[after..].iter().any(Arg::unknown)
        }
        _ => false,
    }
}

/// The server half's `x-doxa` stamp: what a client generated from the spec needs that
/// OpenAPI can't say. `path` is the handler's utoipa path struct.
pub fn server_meta(
    method: &str,
    touches: &[syn::Path],
    flags: Flags,
    item_fn: &ItemFn,
    path: &syn::Ident,
) -> TokenStream {
    let invalidates = flags.invalidates;
    let dry_run = flags.dry_run && dry_run(item_fn, &args(item_fn));
    let typed = || {
        item_fn.sig.inputs.iter().filter_map(|arg| match arg {
            FnArg::Typed(pt) => Some(&*pt.ty),
            FnArg::Receiver(_) => None,
        })
    };
    let mut entities: Vec<TokenStream> = typed()
        .filter_map(grant::guarded_asset)
        .map(|asset| quote!((&::doxa::__private::EntityOf::<#asset>::new()).entity()))
        .chain(
            touches
                .iter()
                .map(|t| quote!(Some(<#t as ::doxa::wire::Keyed>::ENTITY_TYPE))),
        )
        .collect();
    entities.push(answered(&item_fn.sig.output));
    let key = match typed().find_map(grant::instance_asset) {
        Some(asset) => quote! {
            ::doxa::__private::serde_json::json!({
                "asset": ::core::any::type_name::<#asset>(),
                "entity": (&::doxa::__private::EntityOf::<#asset>::new()).entity(),
                "type": ::core::any::type_name::<<#asset as ::doxa::auth::Granting>::Key>(),
                "names": <#asset as ::doxa::auth::Granting>::KEY_NAMES,
            })
        },
        None => quote!(::doxa::__private::serde_json::Value::Null),
    };
    let ret = match &item_fn.sig.output {
        ReturnType::Default => None,
        ReturnType::Type(_, ty) => Some(&**ty),
    };
    let stream = match ret.and_then(|t| find_named(t, "SseStream")) {
        Some(_) if method == "get" => quote!("events"),
        Some(_) => quote!("once"),
        None => quote!(::doxa::__private::serde_json::Value::Null),
    };
    let error = match ret.and_then(error_type) {
        Some(e) => quote! {{
            #[allow(unused_imports)]
            use ::doxa::__private::{SchemaKnown as _, SchemaUnknown as _};
            (&::doxa::__private::SchemaOf::<#e>::new()).name()
        }},
        None => quote!(::core::option::Option::<::std::string::String>::None),
    };
    let seen: Vec<(String, &Type)> = typed().filter_map(seen_extractor).collect();
    let body = seen
        .iter()
        .find_map(|(n, _)| match n.as_str() {
            "Json" => Some("json"),
            "Form" => Some("form"),
            "Bytes" => Some("bytes"),
            "Multipart" => Some("multipart"),
            _ => None,
        })
        .map_or(
            quote!(::doxa::__private::serde_json::Value::Null),
            |b| quote!(#b),
        );
    let query = seen
        .iter()
        .find(|(n, _)| n == "Query")
        .and_then(|(_, t)| first_type_arg(t))
        .and_then(last_ident)
        .map_or(
            quote!(::doxa::__private::serde_json::Value::Null),
            |q| quote!(#q),
        );
    let identity = match ret.and_then(entity_type) {
        Some(t) => quote! {{
            #[allow(unused_imports)]
            use ::doxa::__private::{IdentityKnown as _, IdentityUnknown as _};
            (&::doxa::__private::IdentityOf::<#t>::new()).describe()
        }},
        None => quote!(::doxa::__private::serde_json::Value::Null),
    };
    quote! {
        impl ::doxa::__private::ClientMeta for #path {
            fn meta() -> ::doxa::__private::serde_json::Value {
                #[allow(unused_imports)]
                use ::doxa::__private::{EntityKnown as _, EntityUnknown as _};
                let key: ::doxa::__private::serde_json::Value = #key;
                let identity: ::doxa::__private::serde_json::Value = #identity;
                let error: ::core::option::Option<::std::string::String> = #error;
                #[allow(unused_imports)]
                use ::doxa::__private::{EntityKnown as _, EntityUnknown as _};
                let found: &[::core::option::Option<&'static str>] = &[#(#entities),*];
                let mut entities: ::std::vec::Vec<&str> = ::std::vec::Vec::new();
                for e in found.iter().flatten().copied() {
                    if !entities.contains(&e) {
                        entities.push(e);
                    }
                }
                ::doxa::__private::serde_json::json!({
                    "entities": entities,
                    "key": key,
                    "dry_run": #dry_run,
                    "invalidates": #invalidates,
                    "stream": #stream,
                    "identity": identity,
                    "error": error,
                    "body": #body,
                    "query": #query,
                })
            }
        }
    }
}

/// `X` in `Granted<Form<X>>`, for the guard form `form`.
fn guard_of<'a>(ty: &'a Type, form: &str) -> Option<&'a Type> {
    if last_ident(ty).as_deref() != Some("Granted") {
        return None;
    }
    let subject = first_type_arg(ty)?;
    (last_ident(subject).as_deref() == Some(form))
        .then(|| first_type_arg(subject))
        .flatten()
}

/// `M` in each `Granted<Cap<M>>` argument.
fn caps(item_fn: &ItemFn) -> Vec<&Type> {
    typed(item_fn).filter_map(|t| guard_of(t, "Cap")).collect()
}

/// `M` when `Granted<Cap<M>>` is the route's one guard, so the caller's capabilities answer it.
fn only_cap(item_fn: &ItemFn) -> Option<&Type> {
    let mut guards = typed(item_fn).filter(|t| grant::is_guard(t));
    let cap = guard_of(guards.next()?, "Cap")?;
    guards.next().is_none().then_some(cap)
}

fn typed(item_fn: &ItemFn) -> impl Iterator<Item = &Type> {
    item_fn.sig.inputs.iter().filter_map(|arg| match arg {
        FnArg::Typed(pt) => Some(&*pt.ty),
        FnArg::Receiver(_) => None,
    })
}

/// The entity a route answering `output` is about, found by autoref where it's called.
fn answered(output: &ReturnType) -> TokenStream {
    let body = match output {
        ReturnType::Type(_, ty) => find_named(ty, "Json").and_then(first_type_arg),
        ReturnType::Default => None,
    };
    match body {
        Some(t) => quote! {{
            #[allow(unused_imports)]
            use ::doxa::wire::{
                AnswersList as _, AnswersMaybe as _, AnswersNothing as _, AnswersOne as _,
            };
            (&&&::doxa::wire::AnswerOf::<#t>::new()).answered()
        }},
        None => quote!(::core::option::Option::None),
    }
}

/// `E` in a return type of `Result<_, E>`.
fn error_type(ret: &Type) -> Option<&Type> {
    match (last_ident(ret).as_deref(), type_args(ret).as_slice()) {
        (Some("Result" | "ApiResult"), [_, e]) => Some(e),
        _ => None,
    }
}

/// The extractor an argument reads, seen through one wrapper such as `Valid<…>`.
fn seen_extractor(ty: &Type) -> Option<(String, &Type)> {
    if let Some(body) = optional_body(ty).or_else(|| first_type_arg(ty).and_then(optional_body)) {
        return seen_extractor(body);
    }
    let last = last_ident(ty)?;
    if ["Json", "Form", "Query", "Path", "Bytes", "Multipart"].contains(&last.as_str()) {
        return Some((last, ty));
    }
    let inner = first_type_arg(ty)?;
    let name = last_ident(inner)?;
    EXTRACTORS.contains(&name.as_str()).then_some((name, inner))
}

/// The first type named `name` anywhere in `ty`.
fn find_named<'a>(ty: &'a Type, name: &str) -> Option<&'a Type> {
    if last_ident(ty).as_deref() == Some(name) {
        return Some(ty);
    }
    match ty {
        Type::Tuple(t) => t.elems.iter().find_map(|e| find_named(e, name)),
        Type::Paren(p) => find_named(&p.elem, name),
        Type::Group(g) => find_named(&g.elem, name),
        Type::Path(_) => type_args(ty).into_iter().find_map(|t| find_named(t, name)),
        _ => None,
    }
}

/// `T` in a success body of `Json<T>` or `Json<Vec<T>>`, where `T` may be an entity.
fn entity_type(ret: &Type) -> Option<&Type> {
    let json = find_named(ret, "Json")?;
    let inner = first_type_arg(json)?;
    match last_ident(inner).as_deref() {
        Some("Vec") => first_type_arg(inner),
        _ => Some(inner),
    }
}

/// Emit the stub and its `ROUTE` module, with `extra` items inside the module.
pub fn expand(route: &Route<'_>, item_fn: &ItemFn, extra: TokenStream) -> syn::Result<TokenStream> {
    let name = &item_fn.sig.ident;
    let docs = item_fn.attrs.iter().filter(|a| a.path().is_ident("doc"));

    let args = args(item_fn);
    let dry_run = route.dry_run && dry_run(item_fn, &args);
    let invalidates = route.invalidates;

    let entities: Vec<TokenStream> = item_fn
        .sig
        .inputs
        .iter()
        .filter_map(|arg| match arg {
            FnArg::Typed(pt) => grant::guarded_asset(&pt.ty),
            FnArg::Receiver(_) => None,
        })
        .map(|asset| quote!(<#asset as ::doxa::wire::Keyed>::ENTITY_TYPE))
        .chain(
            caps(item_fn)
                .into_iter()
                .map(|m| quote!(<#m as ::doxa::wire::Capability>::ENTITY_TYPE)),
        )
        .chain(
            route
                .touches
                .iter()
                .map(|t| quote!(<#t as ::doxa::wire::Keyed>::ENTITY_TYPE)),
        )
        .collect();
    let answered = answered(&item_fn.sig.output);

    let keys: Vec<TokenStream> = item_fn
        .sig
        .inputs
        .iter()
        .filter_map(|arg| match arg {
            FnArg::Typed(pt) => grant::instance_asset(&pt.ty),
            FnArg::Receiver(_) => None,
        })
        .map(
            |asset| quote!(<<#asset as ::doxa::wire::Keyed>::Key as ::doxa::wire::KeyNames>::NAMES),
        )
        .collect();
    let fills_by_path_type = args.iter().any(|a| {
        matches!(
            a,
            Arg::Sent {
                kind: Kind::Path | Kind::Foreign,
                ..
            }
        )
    });

    let path = route.path;
    let route_names: Vec<LitStr> = crate::sig::parse_path_names(&path.value())
        .iter()
        .map(|n| LitStr::new(n, Span::call_site()))
        .collect();
    let coverage = if fills_by_path_type || route_names.is_empty() {
        quote!()
    } else {
        let message = format!(
            "`{}` has a path parameter no client argument fills: every `{{name}}` in the \
             template must be a field of a guarded asset's key or of a `Path<…>` argument",
            path.value()
        )
        .replace('{', "{{")
        .replace('}', "}}");
        quote! {
            const _: () = ::core::assert!(
                ::doxa::wire::names_covered(&[#(#route_names),*], &[#(#keys),*]),
                #message,
            );
        }
    };

    let method = format_ident!("{}", capitalize(route.method));
    let op_id = match route.operation_id {
        Some(lit) => lit.clone(),
        None => LitStr::new(&name.to_string(), name.span()),
    };

    let (params, pushes): (Vec<_>, Vec<_>) = args
        .iter()
        .filter_map(|a| match a {
            Arg::Sent {
                name,
                ty,
                check: Some(check),
                ..
            } => {
                let Check { wrapper, value } = &**check;
                Some((
                    quote!(#name: impl ::doxa::client::Arg<#value>),
                    quote!(.checked::<#wrapper, #ty>(::doxa::client::Arg::into_arg(#name))),
                ))
            }
            Arg::Sent { name, ty, .. } => Some((
                quote!(#name: impl ::doxa::client::ArgFor<#ty>),
                quote!(.arg::<#ty, _>(#name)),
            )),
            Arg::Dropped | Arg::Server => None,
        })
        .unzip();

    let check = args.iter().find_map(|a| match a {
        Arg::Sent {
            check: Some(check), ..
        } => {
            let Check { wrapper, value } = &**check;
            Some(quote! {
                /// The rules the route checks its input with, as the server runs them.
                pub fn check(value: &#value) -> ::core::result::Result<(), ::doxa::wire::FieldErrors> {
                    <#wrapper as ::doxa::wire::Validates>::check(value)
                }
            })
        }
        _ => None,
    });

    let (probe_params, probe_pushes): (Vec<_>, Vec<_>) = args
        .iter()
        .filter_map(|a| match a {
            Arg::Sent { name, ty, kind, .. } if *kind != Kind::Body => Some((
                quote!(#name: impl ::doxa::client::ArgFor<#ty>),
                quote!(.arg::<#ty, _>(#name)),
            )),
            _ => None,
        })
        .unzip();
    let by_capability = only_cap(item_fn)
        .filter(|_| dry_run)
        .map(|m| quote!(.by_capability::<#m>()));

    let mut bad = None;
    let ret = match &item_fn.sig.output {
        ReturnType::Default => quote!(()),
        ReturnType::Type(_, ty) => {
            let mut unread = None;
            let ret = response_type(ty, route.method != "get", &mut bad, &mut unread);
            if let Some(ty) = unread {
                let name = last_ident(ty).unwrap_or_default();
                return Err(syn::Error::new_spanned(
                    ty,
                    format!(
                        "doxa can't tell what `{name}` returns in the browser\n\
                         help: write `SseStream<…>`, `Json<…>` or `Result<…, …>` (or the `doxa::` path), \
                         or set `client = false` on the route"
                    ),
                ));
            }
            ret
        }
    };
    // The bound names a lifetime so it is checked where the stub is called, not here.
    let (refusal, refused) = match bad {
        None => (quote!(), quote!()),
        Some(ty) => {
            let message = format!(
                "`{name}` returns `{}`, which the browser can't decode",
                type_text(ty)
            )
            .replace('{', "{{")
            .replace('}', "}}");
            (
                quote! {
                    #[doc(hidden)]
                    #[diagnostic::on_unimplemented(
                        message = #message,
                        label = "not callable from the browser",
                        note = "set `client = false` on the route to keep it server-only, or return `Json<T>`"
                    )]
                    pub trait ClientCallable {}
                },
                quote!(where &'__doxa (): #name::ClientCallable),
            )
        }
    };
    let lifetime = (!refused.is_empty()).then(|| quote!(<'__doxa>));

    Ok(quote! {
        #[allow(non_snake_case, missing_docs)]
        pub mod #name {
            #[allow(unused_imports)]
            use super::*;
            /// The route this call is made to.
            pub static ROUTE: ::doxa::wire::RouteSpec = ::doxa::wire::RouteSpec {
                method: ::doxa::wire::Method::#method,
                path: #path,
                operation_id: #op_id,
                entities: &[#(#entities),*],
                dry_run: #dry_run,
                invalidates: #invalidates,
                package: ::core::env!("CARGO_PKG_NAME"),
            };
            #coverage
            #refusal
            #check
            #extra

            /// Whether this caller may call the route with these arguments, from a dry run.
            pub fn can(#(#probe_params),*) -> ::doxa::client::Probe {
                ::doxa::client::Probe::new(&ROUTE) #(#probe_pushes)* #by_capability
            }
        }

        #(#docs)*
        #[allow(clippy::too_many_arguments)]
        pub fn #name #lifetime (#(#params),*) -> ::doxa::client::Call<#ret> #refused {
            ::doxa::client::Call::new(&#name::ROUTE)
                .answers(#answered)
                #(#pushes)*
        }
    })
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn last_ident(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(TypePath { path, .. }) => path.segments.last().map(|s| s.ident.to_string()),
        _ => None,
    }
}

fn first_type_arg(ty: &Type) -> Option<&Type> {
    let Type::Path(TypePath { path, .. }) = ty else {
        return None;
    };
    let PathArguments::AngleBracketed(args) = &path.segments.last()?.arguments else {
        return None;
    };
    args.args.iter().find_map(|a| match a {
        GenericArgument::Type(t) => Some(t),
        _ => None,
    })
}

fn type_args(ty: &Type) -> Vec<&Type> {
    let Type::Path(TypePath { path, .. }) = ty else {
        return Vec::new();
    };
    let Some(PathArguments::AngleBracketed(args)) = path.segments.last().map(|s| &s.arguments)
    else {
        return Vec::new();
    };
    args.args
        .iter()
        .filter_map(|a| match a {
            GenericArgument::Type(t) => Some(t),
            _ => None,
        })
        .collect()
}

/// A binding name for the stub parameter: the pattern's own, or the one inside `Json(x)`.
fn binding(pat: &Pat, index: usize) -> syn::Ident {
    match pat {
        Pat::Ident(p) => match p.ident.to_string().trim_start_matches('_') {
            "" => format_ident!("arg{}", index),
            name => format_ident!("{}", name),
        },
        Pat::TupleStruct(ts) if ts.elems.len() == 1 => binding(&ts.elems[0], index),
        Pat::Type(pt) => binding(&pt.pat, index),
        _ => format_ident!("arg{}", index),
    }
}

/// Extractors a wrapper such as `Valid<…>` is seen through.
const EXTRACTORS: &[&str] = &["Path", "Query", "Json", "Form"];

/// `inner`, classified, seen through the wrapper `ty`; its value checked first unless it is a path.
fn wrapped(inner: Arg, ty: &Type, extractor: &str, inner_ty: &Type) -> Arg {
    let value = match (extractor, first_type_arg(inner_ty)) {
        ("Path", _) | (_, None) => None,
        (_, Some(v)) => Some(v.clone()),
    };
    wrapped_as(inner, ty, value)
}

/// `X` in `Option<X>`, where `X` is a body extractor.
fn optional_body(ty: &Type) -> Option<&Type> {
    if last_ident(ty).as_deref() != Some("Option") {
        return None;
    }
    first_type_arg(ty)
        .filter(|t| matches!(last_ident(t).as_deref(), Some("Json" | "Form" | "Bytes")))
}

/// `inner`, seen through the wrapper `ty` that checks `value` before it is sent.
fn wrapped_as(inner: Arg, ty: &Type, value: Option<Type>) -> Arg {
    let Arg::Sent {
        name,
        ty: client_ty,
        kind,
        ..
    } = inner
    else {
        return inner;
    };
    let check = match (value, ty) {
        (Some(value), Type::Path(tp)) => {
            let mut wrapper = tp.clone();
            if let Some(seg) = wrapper.path.segments.last_mut() {
                seg.arguments = PathArguments::AngleBracketed(syn::parse_quote!(<#client_ty>));
            }
            Some(Box::new(Check {
                wrapper: quote!(#wrapper),
                value,
            }))
        }
        _ => None,
    };
    Arg::Sent {
        name,
        ty: client_ty,
        kind,
        check,
    }
}

fn classify(pat: &Pat, ty: &Type, index: usize) -> Arg {
    let name = binding(pat, index);
    let sent = |kind: Kind, ty: TokenStream| Arg::Sent {
        name: name.clone(),
        ty,
        kind,
        check: None,
    };
    let last = last_ident(ty).unwrap_or_default();
    if SERVER_ONLY.contains(&last.as_str()) {
        return Arg::Dropped;
    }
    if let Some(body) = optional_body(ty) {
        return match classify(pat, body, index) {
            Arg::Sent { name, ty, kind, .. } => Arg::Sent {
                name,
                ty: quote!(::core::option::Option<#ty>),
                kind,
                check: None,
            },
            other => other,
        };
    }
    if let Some(inner) = first_type_arg(ty).filter(|_| !EXTRACTORS.contains(&last.as_str())) {
        if let Some(extractor) = last_ident(inner).filter(|n| EXTRACTORS.contains(&n.as_str())) {
            return wrapped(classify(pat, inner, index), ty, &extractor, inner);
        }
        if let Some(value) = optional_body(inner).and_then(first_type_arg) {
            let value: Type = syn::parse_quote!(::core::option::Option<#value>);
            return wrapped_as(classify(pat, inner, index), ty, Some(value));
        }
    }
    match (last.as_str(), first_type_arg(ty)) {
        ("Path", Some(t)) => sent(Kind::Path, quote!(::doxa::client::Path<#t>)),
        ("Query", Some(t)) => sent(Kind::Plain, quote!(::doxa::client::Query<#t>)),
        ("Json", Some(t)) => sent(Kind::Body, quote!(::doxa::client::Json<#t>)),
        ("Form", Some(t)) => sent(Kind::Body, quote!(::doxa::client::Form<#t>)),
        ("Bytes", None) => sent(Kind::Body, quote!(::doxa::client::Bytes)),
        ("Multipart", None) => sent(Kind::Body, quote!(::doxa::client::Multipart)),
        ("Granted", Some(_)) => match grant::instance_asset(ty) {
            Some(asset) => sent(Kind::Guard, quote!(::doxa::client::Granted<#asset>)),
            None => Arg::Dropped,
        },
        _ => sent(Kind::Foreign, quote!(::doxa::client::Foreign<#ty>)),
    }
}

/// Response types doxa knows and the browser can't decode; the call is refused where it's made.
const UNDECODABLE: &[&str] = &[
    "Html",
    "Redirect",
    "Response",
    "Sse",
    "Body",
    "Bytes",
    "Vec",
    "Box",
    "Cow",
    "AppendHeaders",
    "HeaderMap",
];

/// The handler's return type, with every wrapper named under `::doxa::client`. `bad` gets
/// the first part the browser can't decode, `unread` the first name doxa doesn't know. A
/// stream from a route that isn't a GET (`once`) is sent once and never reopened.
fn response_type<'a>(
    ty: &'a Type,
    once: bool,
    bad: &mut Option<&'a Type>,
    unread: &mut Option<&'a Type>,
) -> TokenStream {
    let unsupported = |ty: &'a Type, bad: &mut Option<&'a Type>| {
        bad.get_or_insert(ty);
        quote!(::doxa::client::Unsupported)
    };
    match ty {
        Type::Tuple(t) if t.elems.is_empty() => quote!(()),
        Type::Tuple(t) => {
            let elems: Vec<_> = t
                .elems
                .iter()
                .map(|e| response_type(e, once, bad, unread))
                .collect();
            quote!((#(#elems),*))
        }
        Type::Path(_) => {
            let last = last_ident(ty).unwrap_or_default();
            let args = type_args(ty);
            match (last.as_str(), args.as_slice()) {
                ("Result" | "ApiResult", [ok, err]) => {
                    let ok = response_type(ok, once, bad, unread);
                    quote!(::core::result::Result<#ok, #err>)
                }
                ("Result", [ok]) => {
                    let ok = response_type(ok, once, bad, unread);
                    quote!(::doxa::client::AliasedResult<#ok>)
                }
                ("Json", [t]) => quote!(::doxa::client::Json<#t>),
                ("SseStream", [e, ..]) if once => quote!(::doxa::client::SseOnce<#e>),
                ("SseStream", [e, ..]) => quote!(::doxa::client::SseStream<#e>),
                ("StatusCode", []) => quote!(::doxa::client::StatusCode),
                ("NoContent", []) => quote!(::doxa::client::StatusCode),
                ("String", []) => quote!(::std::string::String),
                ("Attachment", []) => quote!(::doxa::client::Attachment),
                ("Cached", [t]) => quote!(::doxa::client::Json<#t>),
                (name, _) if UNDECODABLE.contains(&name) => unsupported(ty, bad),
                _ => {
                    unread.get_or_insert(ty);
                    quote!(::doxa::client::Unsupported)
                }
            }
        }
        Type::Paren(p) => response_type(&p.elem, once, bad, unread),
        Type::Group(g) => response_type(&g.elem, once, bad, unread),
        _ => unsupported(ty, bad),
    }
}

/// `Html < String >` as `Html<String>`, for a message.
fn type_text(ty: &Type) -> String {
    let mut s = quote!(#ty).to_string();
    for (from, to) in [
        (" <", "<"),
        ("< ", "<"),
        (" >", ">"),
        (" ::", "::"),
        (":: ", "::"),
        (" ,", ","),
        ("& ", "&"),
    ] {
        s = s.replace(from, to);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stub(method: &str, path: &str, f: TokenStream) -> String {
        let item: ItemFn = syn::parse2(f).unwrap();
        let path = LitStr::new(path, Span::call_site());
        expand(
            &Route {
                method,
                path: &path,
                operation_id: None,
                touches: &[],
                dry_run: true,
                invalidates: true,
            },
            &item,
            TokenStream::new(),
        )
        .unwrap()
        .to_string()
    }

    #[test]
    fn a_route_can_opt_out_of_dry_runs() {
        let item: ItemFn = syn::parse2(quote! { async fn f(w: Granted<W>) {} }).unwrap();
        let path = LitStr::new("/w/{name}", Span::call_site());
        let out = expand(
            &Route {
                method: "post",
                path: &path,
                operation_id: None,
                touches: &[],
                dry_run: false,
                invalidates: true,
            },
            &item,
            TokenStream::new(),
        )
        .unwrap()
        .to_string();
        assert!(out.contains("dry_run : false"), "{out}");
    }

    #[test]
    fn server_only_extractors_are_dropped() {
        let out = stub(
            "post",
            "/api/widgets/{name}/rename",
            quote! {
                pub async fn rename_widget(
                    w: Granted<WidgetByName>,
                    State(db): State<Db>,
                    Json(r): Json<Rename>,
                ) -> Result<Json<Widget>, WidgetError> { todo!() }
            },
        );
        assert!(out.contains("pub fn rename_widget (w : impl :: doxa :: client :: ArgFor < :: doxa :: client :: Granted < WidgetByName > >"), "{out}");
        assert!(
            out.contains(
                "r : impl :: doxa :: client :: ArgFor < :: doxa :: client :: Json < Rename > >"
            ),
            "{out}"
        );
        assert!(!out.contains("Db"), "{out}");
        assert!(out.contains(":: doxa :: client :: Call < :: core :: result :: Result < :: doxa :: client :: Json < Widget > , WidgetError > >"), "{out}");
    }

    #[test]
    fn a_server_param_is_no_client_param_and_after_the_guard_ends_the_dry_run() {
        let before = stub(
            "post",
            "/w/{name}",
            quote! { async fn f(#[server] t: CallerToken, w: Granted<W>, Valid(Json(m)): Valid<Json<M>>) {} },
        );
        assert!(!before.contains("CallerToken"), "{before}");
        assert!(
            before.contains(
                "fn f (w : impl :: doxa :: client :: ArgFor < :: doxa :: client :: Granted < W > >"
            ),
            "{before}"
        );
        assert!(
            before.contains("m : impl :: doxa :: client :: Arg < M >"),
            "{before}"
        );
        assert!(before.contains("dry_run : true"), "{before}");

        let after = stub(
            "post",
            "/w/{name}",
            quote! { async fn f(w: Granted<W>, #[server] t: CallerToken) {} },
        );
        assert!(!after.contains("CallerToken"), "{after}");
        assert!(after.contains("dry_run : false"), "{after}");
    }

    #[test]
    fn the_route_module_carries_method_path_and_entity() {
        let out = stub(
            "get",
            "/api/widgets/{name}",
            quote! { pub async fn get_widget(w: Granted<WidgetByName>) -> Json<Widget> { todo!() } },
        );
        assert!(out.contains("pub mod get_widget"), "{out}");
        assert!(
            out.contains("method : :: doxa :: wire :: Method :: Get"),
            "{out}"
        );
        assert!(
            out.contains("< WidgetByName as :: doxa :: wire :: Keyed > :: ENTITY_TYPE"),
            "{out}"
        );
        assert!(out.contains("names_covered"), "{out}");
    }

    #[test]
    fn sse_streams_lose_their_impl_trait() {
        let out = stub(
            "get",
            "/events",
            quote! { async fn events() -> SseStream<Ev, impl Stream<Item = Result<Ev, Infallible>>> { todo!() } },
        );
        assert!(
            out.contains(":: doxa :: client :: SseStream < Ev >"),
            "{out}"
        );
    }

    #[test]
    fn a_stream_from_a_post_is_sent_once() {
        let out = stub(
            "post",
            "/turns",
            quote! { async fn turn() -> SseStream<Ev, impl Stream<Item = Result<Ev, Infallible>>> { todo!() } },
        );
        assert!(out.contains(":: doxa :: client :: SseOnce < Ev >"), "{out}");
    }

    #[test]
    fn an_unknown_extractor_after_the_guard_disables_the_dry_run() {
        let out = stub(
            "post",
            "/w/{name}",
            quote! { async fn f(w: Granted<W>, g: MyGuard) {} },
        );
        assert!(out.contains("dry_run : false"), "{out}");
        assert!(
            out.contains(":: doxa :: client :: Foreign < MyGuard >"),
            "{out}"
        );
    }

    #[test]
    fn any_guard_answers_a_dry_run() {
        let open = stub(
            "post",
            "/notes",
            quote! { async fn f(State(s): State<S>, Json(n): Json<Note>) {} },
        );
        assert!(open.contains("dry_run : false"), "{open}");
        let granted = stub(
            "post",
            "/w/{name}",
            quote! { async fn f(State(s): State<S>, w: Granted<W>) {} },
        );
        assert!(granted.contains("dry_run : true"), "{granted}");
        let required = stub(
            "post",
            "/notes",
            quote! { async fn f(_: Require<NotesWrite>, Json(n): Json<Note>) {} },
        );
        assert!(required.contains("dry_run : true"), "{required}");
        let both = stub(
            "post",
            "/w/{name}",
            quote! { async fn f(w: Granted<W>, _: Require<NotesWrite>) {} },
        );
        assert!(both.contains("dry_run : true"), "{both}");
        let custom = stub("post", "/notes", quote! { async fn f(g: MyGuard) {} });
        assert!(custom.contains("dry_run : false"), "{custom}");
    }

    #[test]
    fn an_extractor_a_body_could_authorize_with_disables_the_dry_run() {
        for arg in [
            quote!(h: HeaderMap),
            quote!(Extension(u): Extension<User>),
            quote!(r: Request),
            quote!(p: Parts),
            quote!(ConnectInfo(a): ConnectInfo<SocketAddr>),
        ] {
            let after = stub(
                "post",
                "/w/{name}",
                quote! { async fn f(w: Granted<W>, #arg) {} },
            );
            assert!(after.contains("dry_run : false"), "{after}");
            let before = stub(
                "post",
                "/w/{name}",
                quote! { async fn f(#arg, w: Granted<W>) {} },
            );
            assert!(before.contains("dry_run : false"), "{before}");
        }
    }

    #[test]
    fn an_undecodable_return_type_refuses_the_call_by_name() {
        let out = stub(
            "get",
            "/",
            quote! { async fn home() -> Result<Html<String>, E> { todo!() } },
        );
        assert!(
            out.contains("`home` returns `Html<String>`, which the browser can't decode"),
            "{out}"
        );
        assert!(
            out.contains("where & '__doxa () : home :: ClientCallable"),
            "{out}"
        );
        let json = stub(
            "get",
            "/n",
            quote! { async fn n() -> Json<u32> { todo!() } },
        );
        assert!(!json.contains("ClientCallable"), "{json}");
    }

    #[test]
    fn a_wrapped_body_is_checked_before_it_is_sent() {
        let out = stub(
            "post",
            "/orders",
            quote! { async fn create(Checked(Json(o)): app::Checked<Json<NewOrder>>) -> StatusCode { todo!() } },
        );
        assert!(
            out.contains(". checked :: < app :: Checked < :: doxa :: client :: Json < NewOrder > > , :: doxa :: client :: Json < NewOrder > >"),
            "{out}"
        );
        assert!(out.contains("pub fn check (value : & NewOrder)"), "{out}");
        let path = stub(
            "get",
            "/orders/{id}",
            quote! { async fn get(Valid(Path(id)): Valid<Path<u32>>) -> StatusCode { todo!() } },
        );
        assert!(!path.contains("checked"), "{path}");
        assert!(
            path.contains("ArgFor < :: doxa :: client :: Path < u32 > >"),
            "{path}"
        );
    }

    #[test]
    fn a_renamed_return_type_is_an_error_at_the_route() {
        let item: ItemFn = syn::parse2(quote! {
            async fn chat() -> DoxaSseStream<Ev, impl Stream<Item = Result<Ev, Infallible>>> { todo!() }
        })
        .unwrap();
        let path = LitStr::new("/chat", Span::call_site());
        let route = Route {
            method: "get",
            path: &path,
            operation_id: None,
            touches: &[],
            dry_run: true,
            invalidates: true,
        };
        let err = expand(&route, &item, TokenStream::new())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("doxa can't tell what `DoxaSseStream` returns in the browser"),
            "{err}"
        );
        let aliased = stub(
            "get",
            "/n",
            quote! { async fn n() -> ApiResult<Json<u32>, E> { todo!() } },
        );
        assert!(
            aliased
                .contains(":: core :: result :: Result < :: doxa :: client :: Json < u32 > , E >"),
            "{aliased}"
        );
    }

    #[test]
    fn many_and_cap_read_no_key() {
        let out = stub(
            "get",
            "/w",
            quote! { async fn f(w: Granted<Many<W>>, Query(q): Query<Filter>) -> Json<Vec<Widget>> { todo!() } },
        );
        assert!(out.contains("fn f (q : impl"), "{out}");
        assert!(
            out.contains("< W as :: doxa :: wire :: Keyed > :: ENTITY_TYPE"),
            "{out}"
        );
    }
}
