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
    },
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
}

/// Server-only extractors a handler body could authorize with, where no guard sees it.
const MAY_AUTHORIZE: &[&str] = &["Extension", "HeaderMap", "Request", "Parts", "ConnectInfo"];

fn may_authorize(item_fn: &ItemFn) -> bool {
    item_fn.sig.inputs.iter().any(|arg| match arg {
        FnArg::Typed(pt) => last_ident(&pt.ty).is_some_and(|n| MAY_AUTHORIZE.contains(&n.as_str())),
        FnArg::Receiver(_) => false,
    })
}

/// Emit the stub and its `ROUTE` module.
pub fn expand(route: &Route<'_>, item_fn: &ItemFn) -> syn::Result<TokenStream> {
    let vis = &item_fn.vis;
    let name = &item_fn.sig.ident;
    let docs = item_fn.attrs.iter().filter(|a| a.path().is_ident("doc"));

    let args: Vec<Arg> = item_fn
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
        .collect();

    let typed: Vec<usize> = item_fn
        .sig
        .inputs
        .iter()
        .enumerate()
        .filter(|(_, a)| matches!(a, FnArg::Typed(_)))
        .map(|(i, _)| i)
        .collect();
    // Only a `Granted` guard answers a dry run wherever the route is mounted; an
    // unguarded route is answered only by `routes!`, so a probe of it stays Unknown.
    let dry_run = match grant::dry_run_gate(item_fn) {
        Some(gate) if !may_authorize(item_fn) => {
            let after = typed.iter().position(|i| *i == gate).map_or(0, |p| p + 1);
            !args[after..].iter().any(Arg::unknown)
        }
        _ => false,
    };

    let entities: Vec<TokenStream> = item_fn
        .sig
        .inputs
        .iter()
        .filter_map(|arg| match arg {
            FnArg::Typed(pt) => grant::guarded_asset(&pt.ty),
            FnArg::Receiver(_) => None,
        })
        .map(|asset| quote!(<#asset as ::doxa::wire::Keyed>::ENTITY_TYPE))
        .collect();

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
            Arg::Sent { name, ty, .. } => Some((
                quote!(#name: impl ::doxa::client::ArgFor<#ty>),
                quote!(.arg::<#ty, _>(#name)),
            )),
            Arg::Dropped | Arg::Server => None,
        })
        .unzip();

    let (probe_params, probe_pushes): (Vec<_>, Vec<_>) = args
        .iter()
        .filter_map(|a| match a {
            Arg::Sent { name, ty, kind } if *kind != Kind::Body => Some((
                quote!(#name: impl ::doxa::client::ArgFor<#ty>),
                quote!(.arg::<#ty, _>(#name)),
            )),
            _ => None,
        })
        .unzip();

    let mut bad = None;
    let ret = match &item_fn.sig.output {
        ReturnType::Default => quote!(()),
        ReturnType::Type(_, ty) => response_type(ty, route.method != "get", &mut bad),
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
        #vis mod #name {
            #[allow(unused_imports)]
            use super::*;
            /// The route this call is made to.
            pub static ROUTE: ::doxa::wire::RouteSpec = ::doxa::wire::RouteSpec {
                method: ::doxa::wire::Method::#method,
                path: #path,
                operation_id: #op_id,
                entities: &[#(#entities),*],
                dry_run: #dry_run,
                package: ::core::env!("CARGO_PKG_NAME"),
            };
            #coverage
            #refusal

            /// Whether this caller may call the route with these arguments, from a dry run.
            pub fn can(#(#probe_params),*) -> ::doxa::client::Probe {
                ::doxa::client::Probe::new(&ROUTE) #(#probe_pushes)*
            }
        }

        #(#docs)*
        #[allow(clippy::too_many_arguments)]
        #vis fn #name #lifetime (#(#params),*) -> ::doxa::client::Call<#ret> #refused {
            #[allow(unused_imports)]
            use ::doxa::client::__private::{IsEntity as _, NotEntity as _};
            ::doxa::client::Call::new(&#name::ROUTE)
                .entity((&::doxa::client::__private::EntityOf::<#ret>::new()).entity())
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

fn classify(pat: &Pat, ty: &Type, index: usize) -> Arg {
    let name = binding(pat, index);
    let sent = |kind: Kind, ty: TokenStream| Arg::Sent {
        name: name.clone(),
        ty,
        kind,
    };
    let last = last_ident(ty).unwrap_or_default();
    if SERVER_ONLY.contains(&last.as_str()) {
        return Arg::Dropped;
    }
    match (last.as_str(), first_type_arg(ty)) {
        ("Valid", Some(t)) => classify(pat, t, index),
        ("Path", Some(t)) => sent(Kind::Path, quote!(::doxa::client::Path<#t>)),
        ("Query", Some(t)) => sent(Kind::Plain, quote!(::doxa::client::Query<#t>)),
        ("Json", Some(t)) => sent(Kind::Body, quote!(::doxa::client::Json<#t>)),
        ("Form", Some(t)) => sent(Kind::Body, quote!(::doxa::client::Form<#t>)),
        ("Granted", Some(_)) => match grant::instance_asset(ty) {
            Some(asset) => sent(Kind::Guard, quote!(::doxa::client::Granted<#asset>)),
            None => Arg::Dropped,
        },
        _ => sent(Kind::Foreign, quote!(::doxa::client::Foreign<#ty>)),
    }
}

/// The handler's return type, with every wrapper named under `::doxa::client`;
/// `bad` gets the first part the browser can't decode. A stream from a route that
/// isn't a GET (`once`) is sent once and never reopened.
fn response_type<'a>(ty: &'a Type, once: bool, bad: &mut Option<&'a Type>) -> TokenStream {
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
                .map(|e| response_type(e, once, bad))
                .collect();
            quote!((#(#elems),*))
        }
        Type::Path(_) => {
            let last = last_ident(ty).unwrap_or_default();
            let args = type_args(ty);
            match (last.as_str(), args.as_slice()) {
                ("Result", [ok, err]) => {
                    let ok = response_type(ok, once, bad);
                    quote!(::core::result::Result<#ok, #err>)
                }
                ("Result", [ok]) => {
                    let ok = response_type(ok, once, bad);
                    quote!(::doxa::client::AliasedResult<#ok>)
                }
                ("Json", [t]) => quote!(::doxa::client::Json<#t>),
                ("SseStream", [e, ..]) if once => quote!(::doxa::client::SseOnce<#e>),
                ("SseStream", [e, ..]) => quote!(::doxa::client::SseStream<#e>),
                ("StatusCode", []) => quote!(::doxa::client::StatusCode),
                ("NoContent", []) => quote!(::doxa::client::StatusCode),
                ("String", []) => quote!(::std::string::String),
                ("Cached", [t]) => quote!(::doxa::client::Json<#t>),
                _ => unsupported(ty, bad),
            }
        }
        Type::Paren(p) => response_type(&p.elem, once, bad),
        Type::Group(g) => response_type(&g.elem, once, bad),
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
            },
            &item,
        )
        .unwrap()
        .to_string()
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
            before.contains(
                "m : impl :: doxa :: client :: ArgFor < :: doxa :: client :: Json < M > >"
            ),
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
    fn only_a_granted_guard_answers_a_dry_run() {
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
        assert!(required.contains("dry_run : false"), "{required}");
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
