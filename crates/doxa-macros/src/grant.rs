//! `#[key(...)]` handling for the `Granted<T>` guard extractor.
//!
//! The extractor needs three things the handler body never states: which
//! path segments carry the key, which Cedar action to check, and which
//! OpenAPI security scheme to reference. The route macro knows the last
//! two (the verb, and the default scheme) and the annotation supplies the
//! first, so this module folds them into one generated marker type per
//! call site:
//!
//! ```ignore
//! #[get("/folders/{fid}/widgets/{id}")]
//! async fn get_widget(#[key("id")] widget: Granted<Widget>) -> Json<Widget>
//! ```
//!
//! becomes a `GrantSite` impl carrying `PARAMS = ["id"]` / `ACTION =
//! "read"`, with the argument rewritten to `Granted<One<Widget>, __Site>`.
//! The annotation may be omitted only when the route has exactly one path
//! parameter — then there is nothing to choose, and the macro verifies
//! that rather than guessing.
//!
//! `Many<R>` and `Cap<M>` name no object, so they take no key and need no
//! annotation at all.

use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;
use syn::{FnArg, GenericArgument, Ident, ItemFn, LitStr, Pat, PathArguments, Result, Token, Type};

/// Parsed `#[key("a", "b", action = "...", scheme = "...")]`.
struct KeyArgs {
    /// Path parameters feeding the key, in key order.
    names: Vec<LitStr>,
    action: Option<LitStr>,
    scheme: Option<LitStr>,
}

impl Parse for KeyArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut names = Vec::new();
        let mut action = None;
        let mut scheme = None;
        let mut first = true;

        while !input.is_empty() {
            if !first {
                input.parse::<Token![,]>()?;
                if input.is_empty() {
                    break;
                }
            }
            first = false;

            // Segment names are positional and come first, so a
            // composite key reads in the order the route binds it.
            if input.peek(LitStr) {
                if action.is_some() || scheme.is_some() {
                    return Err(input.error("segment names must come before `action` / `scheme`"));
                }
                names.push(input.parse()?);
                continue;
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
                        format!(
                            "unknown `#[key]` option `{other}` — expected `action` or `scheme`"
                        ),
                    ))
                }
            }
        }

        Ok(Self {
            names,
            action,
            scheme,
        })
    }
}

/// Cedar action implied by an HTTP verb, used when `#[key]` does not name
/// one.
fn default_action(method: &str) -> &'static str {
    match method {
        "post" => "create",
        "put" | "patch" => "update",
        "delete" => "delete",
        _ => "read",
    }
}

/// Number of generic arguments on a `Granted<…>` type, or `None` if this
/// isn't one. Matches on the last path segment so `Granted<T>`,
/// `doxa::auth::Granted<T>` and `doxa_auth::Granted<T>` all resolve.
fn granted_arity(ty: &Type) -> Option<usize> {
    let Type::Path(type_path) = ty else {
        return None;
    };
    let last = type_path.path.segments.last()?;
    if last.ident != "Granted" {
        return None;
    }
    match &last.arguments {
        PathArguments::AngleBracketed(args) => Some(args.args.len()),
        _ => Some(0),
    }
}

/// The subject named inside `Granted<…>`.
fn subject_arg(ty: &Type) -> Option<&Type> {
    let Type::Path(type_path) = ty else {
        return None;
    };
    let last = type_path.path.segments.last()?;
    let PathArguments::AngleBracketed(args) = &last.arguments else {
        return None;
    };
    match args.args.first()? {
        GenericArgument::Type(inner) => Some(inner),
        _ => None,
    }
}

/// The mode wrapper the subject already names, if any.
fn subject_mode(ty: &Type) -> Option<String> {
    let Type::Path(type_path) = ty else {
        return None;
    };
    let last = type_path.path.segments.last()?;
    let name = last.ident.to_string();
    matches!(name.as_str(), "One" | "Many" | "Cap").then_some(name)
}

/// Wrap the subject in `One<…>`, the instance form's mode marker.
fn wrap_in_one(ty: &mut Type) {
    let Type::Path(type_path) = ty else { return };
    let Some(last) = type_path.path.segments.last_mut() else {
        return;
    };
    let PathArguments::AngleBracketed(args) = &mut last.arguments else {
        return;
    };
    if let Some(GenericArgument::Type(inner)) = args.args.first_mut() {
        let subject = inner.clone();
        *inner = syn::parse_quote!(::doxa::auth::One<#subject>);
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

/// Strip `#[key(...)]` off every argument, generate a `GrantSite` impl
/// per `Granted<…>` argument, and rewrite those arguments to name their
/// marker. Returns the generated items.
pub fn rewrite(item_fn: &mut ItemFn, method: &str, path_names: &[String]) -> Result<TokenStream> {
    let fn_ident = item_fn.sig.ident.clone();
    let action_default = default_action(method);
    let mut items = TokenStream::new();

    for (index, arg) in item_fn.sig.inputs.iter_mut().enumerate() {
        let FnArg::Typed(pat_type) = arg else {
            continue;
        };

        // Pull the annotation off regardless of the argument type — an
        // unstripped `#[key]` would not compile.
        let mut annotation: Option<(KeyArgs, Span)> = None;
        let mut kept = Vec::new();
        for attr in std::mem::take(&mut pat_type.attrs) {
            if attr.path().is_ident("key") {
                if annotation.is_some() {
                    return Err(syn::Error::new_spanned(
                        attr,
                        "duplicate `#[key(...)]` on one argument",
                    ));
                }
                let span = attr.span();
                annotation = Some((attr.parse_args::<KeyArgs>()?, span));
            } else {
                kept.push(attr);
            }
        }
        pat_type.attrs = kept;

        let Some(arity) = granted_arity(&pat_type.ty) else {
            if let Some((_, span)) = &annotation {
                return Err(syn::Error::new(
                    *span,
                    "`#[key(...)]` applies to a `Granted<T>` argument",
                ));
            }
            continue;
        };

        if arity != 1 {
            if let Some((_, span)) = &annotation {
                return Err(syn::Error::new(
                    *span,
                    "this `Granted<…>` already names a site — drop `#[key(...)]` \
                     or the second type argument",
                ));
            }
            continue;
        }

        let mode = subject_arg(&pat_type.ty).and_then(subject_mode);
        // Only the instance form reads segments out of the route.
        let takes_key = !matches!(mode.as_deref(), Some("Many") | Some("Cap"));

        let params: Vec<String> = if !takes_key {
            if let Some((args, span)) = &annotation {
                if !args.names.is_empty() {
                    return Err(syn::Error::new(
                        *span,
                        "`Many<…>` and `Cap<…>` authorize no single object, so they take \
                         no key segments",
                    ));
                }
            }
            Vec::new()
        } else {
            match annotation.as_ref().map(|(args, _)| &args.names) {
                Some(names) if !names.is_empty() => names.iter().map(LitStr::value).collect(),
                // Nothing to choose between: one path parameter is the
                // key. Verified rather than guessed.
                _ => match path_names.len() {
                    1 => vec![path_names[0].clone()],
                    0 => {
                        return Err(syn::Error::new_spanned(
                            &pat_type.ty,
                            "`Granted<R>` needs a path parameter, but this route has none",
                        ))
                    }
                    _ => {
                        return Err(syn::Error::new_spanned(
                            &pat_type.ty,
                            format!(
                                "ambiguous: this route has {} path parameters ({}) — \
                                 annotate the argument with `#[key(\"…\")]`",
                                path_names.len(),
                                path_names.join(", "),
                            ),
                        ))
                    }
                },
            }
        };

        for name in &params {
            if !path_names.contains(name) {
                let available = if path_names.is_empty() {
                    "none".to_string()
                } else {
                    path_names.join(", ")
                };
                let span = annotation
                    .as_ref()
                    .map(|(_, span)| *span)
                    .unwrap_or_else(|| pat_type.ty.span());
                return Err(syn::Error::new(
                    span,
                    format!("route has no path parameter `{name}` — available: {available}"),
                ));
            }
        }

        let binding = binding_name(&pat_type.pat, index);
        let marker = format_ident!("__doxa_grant_site_{}_{}", fn_ident, binding);

        let action = annotation
            .as_ref()
            .and_then(|(args, _)| args.action.as_ref())
            .map(LitStr::value)
            .unwrap_or_else(|| action_default.to_string());

        // Omitted `scheme` leaves the trait's own default in place.
        let scheme_const = match annotation
            .as_ref()
            .and_then(|(args, _)| args.scheme.as_ref())
        {
            Some(scheme) => quote! { const SCHEME: &'static str = #scheme; },
            None => quote! {},
        };

        let param_lits = params
            .iter()
            .map(|name| LitStr::new(name, Span::call_site()));

        items.extend(quote! {
            #[doc(hidden)]
            #[allow(non_camel_case_types)]
            pub struct #marker;

            impl ::doxa::auth::GrantSite for #marker {
                const PARAMS: &'static [&'static str] = &[#(#param_lits),*];
                const ACTION: &'static str = #action;
                #scheme_const
            }
        });

        // A bare `Granted<Widget>` means the instance form; the mode
        // marker is what the extractor actually dispatches on.
        if takes_key && mode.is_none() {
            wrap_in_one(&mut pat_type.ty);
        }
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

    /// Run `rewrite` and return the generated items plus the rewritten
    /// signature, or the error message.
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
    fn a_bare_subject_becomes_the_instance_form() {
        let (items, sig) = run(
            "get",
            &["id"],
            quote! {
                async fn get_widget(w: Granted<Widget>) {}
            },
        )
        .expect("rewrites");

        assert!(
            items.contains(r#"const PARAMS : & 'static [& 'static str] = & ["id"]"#),
            "{items}"
        );
        assert!(
            items.contains(r#"const ACTION : & 'static str = "read""#),
            "{items}"
        );
        assert!(
            sig.contains(":: doxa :: auth :: One < Widget >"),
            "the bare subject is wrapped in the instance mode marker: {sig}"
        );
    }

    #[test]
    fn the_annotation_names_the_segment_and_the_verb_supplies_the_action() {
        let (items, _) = run(
            "delete",
            &["fid", "id"],
            quote! {
                async fn drop_widget(#[key("id")] w: Granted<Widget>) {}
            },
        )
        .expect("rewrites");

        assert!(
            items.contains(r#"const PARAMS : & 'static [& 'static str] = & ["id"]"#),
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
    fn a_composite_key_binds_segments_in_the_order_named() {
        let (items, _) = run(
            "get",
            &["fid", "id"],
            quote! {
                async fn get_widget(#[key("fid", "id")] w: Granted<Widget>) {}
            },
        )
        .expect("rewrites");

        assert!(
            items.contains(r#"const PARAMS : & 'static [& 'static str] = & ["fid" , "id"]"#),
            "{items}"
        );
    }

    #[test]
    fn explicit_action_and_scheme_win_over_the_verb() {
        let (items, _) = run(
            "post",
            &["id"],
            quote! {
                async fn archive(#[key("id", action = "archive", scheme = "oauth")] w: Granted<Widget>) {}
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
    fn a_collection_takes_no_key_and_needs_no_annotation() {
        let (items, sig) = run(
            "get",
            &[],
            quote! {
                async fn list_widgets(w: Granted<Many<Widget>>) {}
            },
        )
        .expect("rewrites");

        assert!(
            items.contains(r#"const PARAMS : & 'static [& 'static str] = & []"#),
            "{items}"
        );
        assert!(
            !sig.contains("One <"),
            "an explicit mode marker is left alone: {sig}"
        );
    }

    #[test]
    fn a_capability_takes_no_key() {
        let (items, _) = run(
            "post",
            &[],
            quote! {
                async fn flush(w: Granted<Cap<FlushCaches>>) {}
            },
        )
        .expect("rewrites");

        assert!(
            items.contains(r#"const PARAMS : & 'static [& 'static str] = & []"#),
            "{items}"
        );
        assert!(
            items.contains(r#"const ACTION : & 'static str = "create""#),
            "{items}"
        );
    }

    #[test]
    fn an_explicit_one_is_not_double_wrapped() {
        let (_, sig) = run(
            "get",
            &["id"],
            quote! {
                async fn get_widget(w: Granted<One<Widget>>) {}
            },
        )
        .expect("rewrites");

        assert!(
            !sig.contains("One < One <"),
            "an explicit `One<…>` stays as written: {sig}"
        );
    }

    #[test]
    fn several_path_parameters_without_an_annotation_is_ambiguous() {
        let error = run(
            "get",
            &["fid", "id"],
            quote! {
                async fn get_widget(w: Granted<Widget>) {}
            },
        )
        .expect_err("ambiguous");

        assert!(error.contains("ambiguous"), "{error}");
        assert!(error.contains("fid, id"), "{error}");
    }

    #[test]
    fn an_instance_route_with_no_path_parameter_is_rejected() {
        let error = run(
            "get",
            &[],
            quote! {
                async fn get_widget(w: Granted<Widget>) {}
            },
        )
        .expect_err("no parameter");

        assert!(error.contains("needs a path parameter"), "{error}");
    }

    #[test]
    fn a_segment_the_route_does_not_have_is_rejected() {
        let error = run(
            "get",
            &["id"],
            quote! {
                async fn get_widget(#[key("widget_id")] w: Granted<Widget>) {}
            },
        )
        .expect_err("unknown segment");

        assert!(
            error.contains("route has no path parameter `widget_id`"),
            "{error}"
        );
        assert!(error.contains("available: id"), "{error}");
    }

    #[test]
    fn a_collection_may_not_name_key_segments() {
        let error = run(
            "get",
            &["id"],
            quote! {
                async fn list_widgets(#[key("id")] w: Granted<Many<Widget>>) {}
            },
        )
        .expect_err("no key on a collection");

        assert!(error.contains("take no key segments"), "{error}");
    }

    #[test]
    fn an_argument_that_already_names_a_site_rejects_the_annotation() {
        let error = run(
            "get",
            &["id"],
            quote! {
                async fn get_widget(#[key("id")] w: Granted<One<Widget>, MySite>) {}
            },
        )
        .expect_err("already sited");

        assert!(error.contains("already names a site"), "{error}");
    }

    #[test]
    fn other_arguments_are_left_alone() {
        let (items, sig) = run(
            "get",
            &["id"],
            quote! {
                async fn get_widget(state: State<AppState>) {}
            },
        )
        .expect("rewrites");

        assert!(items.is_empty(), "nothing generated: {items}");
        assert!(sig.contains("State < AppState >"), "{sig}");
    }
}
