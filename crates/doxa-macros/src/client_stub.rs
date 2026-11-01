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
    Sent {
        name: syn::Ident,
        ty: TokenStream,
        kind: Kind,
    },
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
    let dry_run = grant::dry_run_gate(item_fn).is_some_and(|gate| {
        let after = typed.iter().position(|i| *i == gate).map_or(0, |p| p + 1);
        !args[after..].iter().any(|a| {
            matches!(
                a,
                Arg::Sent {
                    kind: Kind::Foreign,
                    ..
                }
            )
        })
    });

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
            Arg::Dropped => None,
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

    let ret = match &item_fn.sig.output {
        ReturnType::Default => quote!(()),
        ReturnType::Type(_, ty) => response_type(ty),
    };

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
            };
            #coverage

            /// Whether this caller may call the route with these arguments, from a dry run.
            pub fn can(#(#probe_params),*) -> ::doxa::client::Probe {
                ::doxa::client::Probe::new(&ROUTE) #(#probe_pushes)*
            }
        }

        #(#docs)*
        #[allow(clippy::too_many_arguments)]
        #vis fn #name(#(#params),*) -> ::doxa::client::Call<#ret> {
            ::doxa::client::Call::new(&#name::ROUTE) #(#pushes)*
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

/// The handler's return type, with every wrapper named under `::doxa::client`.
fn response_type(ty: &Type) -> TokenStream {
    match ty {
        Type::Tuple(t) if t.elems.is_empty() => quote!(()),
        Type::Tuple(t) => {
            let elems = t.elems.iter().map(response_type);
            quote!((#(#elems),*))
        }
        Type::ImplTrait(_) => quote!(::doxa::client::Unsupported),
        Type::Path(_) => {
            let last = last_ident(ty).unwrap_or_default();
            let args = type_args(ty);
            match (last.as_str(), args.as_slice()) {
                ("Result", [ok, err]) => {
                    let ok = response_type(ok);
                    quote!(::core::result::Result<#ok, #err>)
                }
                ("Result", [ok]) => {
                    let ok = response_type(ok);
                    quote!(::doxa::client::Result1<#ok>)
                }
                ("Json", [t]) => quote!(::doxa::client::Json<#t>),
                ("SseStream", [e, ..]) => quote!(::doxa::client::SseStream<#e>),
                ("StatusCode", []) => quote!(::doxa::client::StatusCode),
                ("NoContent", []) => quote!(::doxa::client::StatusCode),
                ("String", []) => quote!(::std::string::String),
                ("Cached", [t]) => quote!(::doxa::client::Json<#t>),
                _ => quote!(::doxa::client::Unsupported),
            }
        }
        Type::Paren(p) => response_type(&p.elem),
        Type::Group(g) => response_type(&g.elem),
        _ => quote!(::doxa::client::Unsupported),
    }
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
