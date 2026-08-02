//! `#[param(...)]` handling for the `Permitted<R>` guard extractor.
//!
//! The extractor needs three things the handler body never states: which
//! path parameter carries the resource id, which Cedar action to check,
//! and which OpenAPI security scheme to reference. The route macro knows
//! the last two (the verb, and the default scheme) and the annotation
//! supplies the first, so this module folds them into one generated
//! marker type per call site:
//!
//! ```ignore
//! #[get("/folders/{fid}/widgets/{id}")]
//! async fn get_widget(#[param("id")] widget: Permitted<Widget>) -> Json<Widget>
//! ```
//!
//! becomes a `PermitSite` impl carrying `PARAM = "id"` / `ACTION =
//! "read"`, with the argument's type rewritten to name it. The
//! annotation may be omitted only when the route has exactly one path
//! parameter — then there is nothing to choose, and the macro verifies
//! that rather than guessing.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;
use syn::{FnArg, GenericArgument, Ident, ItemFn, LitStr, Pat, PathArguments, Result, Token, Type};

/// Parsed `#[param("name", action = "...", scheme = "...")]`.
struct ParamArgs {
    name: LitStr,
    action: Option<LitStr>,
    scheme: Option<LitStr>,
}

impl Parse for ParamArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        let name: LitStr = input.parse()?;
        let mut action = None;
        let mut scheme = None;

        while !input.is_empty() {
            input.parse::<Token![,]>()?;
            if input.is_empty() {
                break;
            }
            let key: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            let value: LitStr = input.parse()?;
            match key.to_string().as_str() {
                "action" => action = Some(value),
                "scheme" => scheme = Some(value),
                other => {
                    return Err(syn::Error::new(
                        key.span(),
                        format!("unknown `param` key `{other}` — expected `action` or `scheme`"),
                    ))
                }
            }
        }

        Ok(Self {
            name,
            action,
            scheme,
        })
    }
}

/// Cedar action implied by an HTTP verb, used when `#[param]` does not
/// name one.
fn default_action(method: &str) -> &'static str {
    match method {
        "post" => "create",
        "put" | "patch" => "update",
        "delete" => "delete",
        _ => "read",
    }
}

/// Number of generic arguments on a `Permitted<…>` type, or `None` if
/// this isn't one. Matches on the last path segment so `Permitted<T>`,
/// `doxa::auth::Permitted<T>`, and `doxa_auth::Permitted<T>` all
/// resolve.
fn permitted_arity(ty: &Type) -> Option<usize> {
    let Type::Path(type_path) = ty else {
        return None;
    };
    let last = type_path.path.segments.last()?;
    if last.ident != "Permitted" {
        return None;
    }
    match &last.arguments {
        PathArguments::AngleBracketed(args) => Some(args.args.len()),
        _ => Some(0),
    }
}

/// Append the site marker as a second type argument.
fn append_site(ty: &mut Type, marker: &Ident) {
    let Type::Path(type_path) = ty else { return };
    let Some(last) = type_path.path.segments.last_mut() else {
        return;
    };
    if let PathArguments::AngleBracketed(args) = &mut last.arguments {
        args.args
            .push(GenericArgument::Type(syn::parse_quote!(#marker)));
    }
}

/// Binding name for marker naming; falls back to the position for
/// wildcard or destructuring patterns.
fn binding_name(pat: &Pat, index: usize) -> String {
    match pat {
        Pat::Ident(pat_ident) => pat_ident.ident.to_string(),
        _ => format!("arg{index}"),
    }
}

/// Strip `#[param(...)]` off every argument, generate a `PermitSite`
/// impl per `Permitted<…>` argument, and rewrite those arguments to name
/// their marker. Returns the generated items.
pub fn rewrite(item_fn: &mut ItemFn, method: &str, path_names: &[String]) -> Result<TokenStream> {
    let fn_ident = item_fn.sig.ident.clone();
    let action_default = default_action(method);
    let mut items = TokenStream::new();

    for (index, arg) in item_fn.sig.inputs.iter_mut().enumerate() {
        let FnArg::Typed(pat_type) = arg else {
            continue;
        };

        // Pull the annotation off regardless of the argument type — an
        // unstripped `#[param]` would not compile.
        let mut annotation: Option<ParamArgs> = None;
        let mut kept = Vec::new();
        for attr in std::mem::take(&mut pat_type.attrs) {
            if attr.path().is_ident("param") {
                if annotation.is_some() {
                    return Err(syn::Error::new_spanned(
                        attr,
                        "duplicate `#[param(...)]` on one argument",
                    ));
                }
                annotation = Some(attr.parse_args::<ParamArgs>()?);
            } else {
                kept.push(attr);
            }
        }
        pat_type.attrs = kept;

        let arity = permitted_arity(&pat_type.ty);

        // Resolve the parameter name, erroring rather than guessing.
        let (param_name, span) = match (&annotation, arity) {
            (Some(p), Some(1)) => (p.name.value(), p.name.span()),
            (Some(p), Some(_)) => {
                return Err(syn::Error::new(
                    p.name.span(),
                    "this `Permitted<…>` already names a site — drop `#[param(...)]` \
                     or the second type argument",
                ))
            }
            (Some(p), None) => {
                return Err(syn::Error::new(
                    p.name.span(),
                    "`#[param(...)]` applies to a `Permitted<R>` argument",
                ))
            }
            (None, Some(1)) => match path_names.len() {
                1 => (path_names[0].clone(), pat_type.ty.span()),
                0 => {
                    return Err(syn::Error::new_spanned(
                        &pat_type.ty,
                        "`Permitted<R>` needs a path parameter, but this route has none",
                    ))
                }
                _ => {
                    return Err(syn::Error::new_spanned(
                        &pat_type.ty,
                        format!(
                            "ambiguous: this route has {} path parameters ({}) — \
                             annotate the argument with `#[param(\"…\")]`",
                            path_names.len(),
                            path_names.join(", "),
                        ),
                    ))
                }
            },
            (None, _) => continue,
        };

        if !path_names.contains(&param_name) {
            let available = if path_names.is_empty() {
                "none".to_string()
            } else {
                path_names.join(", ")
            };
            return Err(syn::Error::new(
                span,
                format!("route has no path parameter `{param_name}` — available: {available}"),
            ));
        }

        let binding = binding_name(&pat_type.pat, index);
        let marker = format_ident!("__doxa_site_{}_{}", fn_ident, binding);

        let action = annotation
            .as_ref()
            .and_then(|p| p.action.as_ref())
            .map(LitStr::value)
            .unwrap_or_else(|| action_default.to_string());

        // Omitted `scheme` leaves the trait's own default in place.
        let scheme_const = match annotation.as_ref().and_then(|p| p.scheme.as_ref()) {
            Some(s) => quote! { const SCHEME: &'static str = #s; },
            None => quote! {},
        };

        items.extend(quote! {
            #[doc(hidden)]
            #[allow(non_camel_case_types)]
            pub struct #marker;

            impl ::doxa::auth::PermitSite for #marker {
                const PARAM: &'static str = #param_name;
                const ACTION: &'static str = #action;
                #scheme_const
            }
        });

        append_site(&mut pat_type.ty, &marker);
    }

    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    /// Run `rewrite` and return the error message, or the rewritten
    /// signature rendered as a string on success.
    fn run(
        method: &str,
        path_names: &[&str],
        tokens: TokenStream,
    ) -> std::result::Result<(String, String), String> {
        let mut item_fn: ItemFn = syn::parse2(tokens).expect("parses");
        match rewrite(&mut item_fn, method, &names(path_names)) {
            Ok(items) => Ok((
                items.to_string(),
                quote::ToTokens::to_token_stream(&item_fn.sig).to_string(),
            )),
            Err(e) => Err(e.to_string()),
        }
    }

    #[test]
    fn annotation_names_the_parameter_and_verb_supplies_the_action() {
        let (items, _) = run(
            "delete",
            &["fid", "id"],
            quote! {
                async fn drop_widget(#[param("id")] w: Permitted<Widget>) {}
            },
        )
        .expect("rewrites");

        assert!(
            items.contains(r#"const PARAM : & 'static str = "id""#),
            "{items}"
        );
        assert!(
            items.contains(r#"const ACTION : & 'static str = "delete""#),
            "{items}"
        );
        // No `scheme` given, so the trait default stands.
        assert!(!items.contains("SCHEME"), "{items}");
    }

    #[test]
    fn explicit_action_and_scheme_win_over_the_verb() {
        let (items, _) = run(
            "post",
            &["id"],
            quote! {
                async fn archive(#[param("id", action = "archive", scheme = "oauth")] w: Permitted<Widget>) {}
            },
        )
        .expect("rewrites");

        assert!(
            items.contains(r#"const ACTION : & 'static str = "archive""#),
            "{items}"
        );
        assert!(
            items.contains(r#"const SCHEME : & 'static str = "oauth""#),
            "{items}"
        );
    }

    #[test]
    fn the_marker_is_appended_and_the_annotation_stripped() {
        let (_, sig) = run(
            "get",
            &["id"],
            quote! {
                async fn get_widget(#[param("id")] w: Permitted<Widget>) {}
            },
        )
        .expect("rewrites");

        assert!(sig.contains("__doxa_site_get_widget_w"), "{sig}");
        assert!(!sig.contains("param"), "annotation must not survive: {sig}");
    }

    #[test]
    fn a_single_path_parameter_needs_no_annotation() {
        let (items, _) = run(
            "get",
            &["id"],
            quote! {
                async fn get_widget(w: Permitted<Widget>) {}
            },
        )
        .expect("rewrites");

        assert!(
            items.contains(r#"const PARAM : & 'static str = "id""#),
            "{items}"
        );
    }

    #[test]
    fn two_path_parameters_without_an_annotation_is_an_error() {
        let err = run(
            "get",
            &["fid", "id"],
            quote! {
                async fn get_widget(w: Permitted<Widget>) {}
            },
        )
        .expect_err("ambiguous");

        assert!(err.contains("ambiguous"), "{err}");
        assert!(
            err.contains("fid, id"),
            "error should list candidates: {err}"
        );
    }

    #[test]
    fn no_path_parameters_is_an_error() {
        let err = run(
            "get",
            &[],
            quote! {
                async fn list_widgets(w: Permitted<Widget>) {}
            },
        )
        .expect_err("no parameters");

        assert!(err.contains("has none"), "{err}");
    }

    #[test]
    fn naming_a_parameter_the_route_lacks_is_an_error() {
        let err = run(
            "get",
            &["fid", "id"],
            quote! {
                async fn get_widget(#[param("widget_id")] w: Permitted<Widget>) {}
            },
        )
        .expect_err("unknown parameter");

        assert!(err.contains("no path parameter `widget_id`"), "{err}");
        assert!(err.contains("available: fid, id"), "{err}");
    }

    #[test]
    fn annotating_a_non_permitted_argument_is_an_error() {
        let err = run(
            "get",
            &["id"],
            quote! {
                async fn get_widget(#[param("id")] p: Path<u32>) {}
            },
        )
        .expect_err("wrong argument type");

        assert!(err.contains("applies to a `Permitted<R>`"), "{err}");
    }

    #[test]
    fn handlers_without_the_guard_are_left_alone() {
        let (items, sig) = run(
            "get",
            &["id"],
            quote! {
                async fn get_widget(Path(id): Path<u32>) -> Json<Widget> {}
            },
        )
        .expect("no-op");

        assert!(items.is_empty(), "nothing to generate: {items}");
        assert!(sig.contains("Path"), "{sig}");
    }

    #[test]
    fn qualified_paths_are_recognized() {
        let (items, _) = run(
            "get",
            &["id"],
            quote! {
                async fn get_widget(w: doxa::auth::Permitted<Widget>) {}
            },
        )
        .expect("rewrites");

        assert!(!items.is_empty(), "a qualified `Permitted` still matches");
    }
}
