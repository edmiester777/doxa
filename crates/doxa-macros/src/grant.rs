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
//! "read"`, with the argument rewritten to `Granted<One<Widget, __Site>>`.
//! The site rides on the subject rather than on `Granted` itself, which is
//! what leaves the guard a two-field pair a handler can destructure.
//!
//! # When the annotation can be left off
//!
//! Most of the time. The names are resolved in three steps, and only the
//! first is written here:
//!
//! 1. `#[key("a", "b")]`, for the route whose parameter is spelled
//!    differently from the column behind it.
//! 2. The route's single path parameter, when it has exactly one — there is
//!    nothing to choose, and the macro verifies that rather than guessing.
//! 3. Otherwise nothing is emitted, and `GrantSite::PARAMS` keeps its empty
//!    default so the asset's own `Granting::KEY_NAMES` answers. That is the
//!    column the lookup matches, which `#[asset]` already knows — so
//!    `/widgets/{name}/revisions/{rev}` binds `{name}` without being told,
//!    and a route naming a parameter the asset's key does not have fails
//!    the build with a `names_within` assertion rather than at runtime.
//!
//! # Where the key comes from
//!
//! `#[key(with = "Query")]` reads the key out of the query string instead
//! of the path, and sets `GrantSite::IN` so the guard and the OpenAPI
//! parameter cannot come to disagree about where to look. `with = "Path"`
//! is the default and may be written out. Step 2 above does not apply to a
//! query key, which has no route template to count.
//!
//! It is an option on the annotation rather than a second argument to
//! `Granted` because a source is a fact about the *call site* — the same
//! asset is read from the path on one route and the query on another —
//! and because a type parameter would need a third `PhantomData` field to
//! be used at all, which every `Granted(caller, row)` destructure would
//! then have to spell.
//!
//! `Many<R>` and `Cap<M>` name no object, so they take no key and need no
//! annotation at all.

use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;
use syn::{FnArg, GenericArgument, Ident, ItemFn, LitStr, Pat, PathArguments, Result, Token, Type};

/// Which half of the request line a key arrives in — `#[key(with = "…")]`,
/// and `GrantSite::IN` on the other side.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    /// The route template, which is the default.
    Path,
    /// The query string.
    Query,
}

/// Parsed `#[key("a", "b", action = "...", scheme = "...", with = "...")]`.
struct KeyArgs {
    /// Path parameters feeding the key, in key order.
    names: Vec<LitStr>,
    action: Option<LitStr>,
    scheme: Option<LitStr>,
    with: Option<Source>,
}

impl Parse for KeyArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut names = Vec::new();
        let mut action = None;
        let mut scheme = None;
        let mut with = None;
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
                if action.is_some() || scheme.is_some() || with.is_some() {
                    return Err(input.error("segment names must come before the named options"));
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
                "with" => {
                    with = Some(match value.value().as_str() {
                        "Path" | "path" => Source::Path,
                        "Query" | "query" => Source::Query,
                        other => {
                            return Err(syn::Error::new_spanned(
                                &value,
                                format!(
                                    "unknown key source `{other}` — expected \
                                     `\"Path\"` or `\"Query\"`"
                                ),
                            ))
                        }
                    })
                }
                other => {
                    return Err(syn::Error::new(
                        key.span(),
                        format!(
                            "unknown `#[key]` option `{other}` — expected `action`, \
                             `scheme` or `with`"
                        ),
                    ))
                }
            }
        }

        Ok(Self {
            names,
            action,
            scheme,
            with,
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

/// The mode wrapper the subject already names, with the number of
/// arguments it carries — two of them means the site is spelled out by
/// hand and there is nothing here to generate.
fn subject_mode(ty: &Type) -> Option<(String, usize)> {
    let Type::Path(type_path) = ty else {
        return None;
    };
    let last = type_path.path.segments.last()?;
    let name = last.ident.to_string();
    if !matches!(name.as_str(), "One" | "Many" | "Cap") {
        return None;
    }
    let arity = match &last.arguments {
        PathArguments::AngleBracketed(args) => args.args.len(),
        _ => 0,
    };
    Some((name, arity))
}

/// The subject named inside `Granted<…>`, to write through.
fn subject_arg_mut(ty: &mut Type) -> Option<&mut Type> {
    let Type::Path(type_path) = ty else {
        return None;
    };
    let last = type_path.path.segments.last_mut()?;
    let PathArguments::AngleBracketed(args) = &mut last.arguments else {
        return None;
    };
    match args.args.first_mut()? {
        GenericArgument::Type(inner) => Some(inner),
        _ => None,
    }
}

/// Name the site on the subject. A subject with no mode wrapper of its
/// own means the instance form, so it gains one on the way in — the site
/// is the wrapper's second argument either way.
fn site_subject(ty: &mut Type, marker: &Ident, wrap: bool) {
    let Some(inner) = subject_arg_mut(ty) else {
        return;
    };

    if wrap {
        let subject = inner.clone();
        *inner = syn::parse_quote!(::doxa::auth::One<#subject, #marker>);
        return;
    }

    let Type::Path(type_path) = inner else { return };
    let Some(last) = type_path.path.segments.last_mut() else {
        return;
    };
    if let PathArguments::AngleBracketed(args) = &mut last.arguments {
        args.args
            .push(GenericArgument::Type(syn::parse_quote!(#marker)));
    }
}

/// The asset behind an instance-form `Granted<…>`, for the assertion that
/// checks its key names against the route.
///
/// `Granted<Widget>` and `Granted<One<Widget>>` are the same subject
/// written two ways, so both answer `Widget`. A subject that already names
/// its site never reaches here, and `Many` / `Cap` have no key to check.
fn instance_asset(ty: &Type) -> Option<Type> {
    let subject = subject_arg(ty)?;
    match subject_mode(subject) {
        Some((name, _)) if name == "One" => subject_arg(subject).cloned(),
        Some(_) => None,
        None => Some(subject.clone()),
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
                    "`Granted<…>` takes one type argument — the subject, which names \
                     its own site as `One<Widget, MySite>`",
                ));
            }
            continue;
        }

        let source = annotation
            .as_ref()
            .and_then(|(args, _)| args.with)
            .unwrap_or(Source::Path);
        let mode = subject_arg(&pat_type.ty).and_then(subject_mode);

        // A subject that spells out its own site was written by hand.
        // Leave it alone, and refuse an annotation that would contradict
        // the site already named.
        if mode.as_ref().is_some_and(|(_, arity)| *arity >= 2) {
            if let Some((_, span)) = &annotation {
                return Err(syn::Error::new(
                    *span,
                    "this subject already names a site — drop `#[key(...)]` \
                     or the site argument",
                ));
            }
            continue;
        }

        let mode = mode.map(|(name, _)| name);
        // Only the instance form reads segments out of the route.
        let takes_key = !matches!(mode.as_deref(), Some("Many") | Some("Cap"));

        // `None` means the site says nothing and the asset's own
        // `Granting::KEY_NAMES` answers instead — the ordinary case, and
        // the reason most routes carry no annotation at all.
        let params: Option<Vec<String>> = if !takes_key {
            if let Some((args, span)) = &annotation {
                if !args.names.is_empty() || args.with.is_some() {
                    return Err(syn::Error::new(
                        *span,
                        "`Many<…>` and `Cap<…>` authorize no single object, so they read \
                         no key — drop the segment names and `with`",
                    ));
                }
            }
            None
        } else {
            match annotation.as_ref().map(|(args, _)| &args.names) {
                Some(names) if !names.is_empty() => Some(names.iter().map(LitStr::value).collect()),
                // Nothing to choose between: one path parameter is the
                // key, whatever the asset calls it. Verified rather than
                // guessed, and only for a key that comes out of the path
                // — a query source has no template to count.
                _ if source == Source::Path && path_names.len() == 1 => {
                    Some(vec![path_names[0].clone()])
                }
                // A path key with nothing in the path to read is a route
                // the asset's names cannot rescue.
                _ if source == Source::Path && path_names.is_empty() => {
                    return Err(syn::Error::new_spanned(
                        &pat_type.ty,
                        "`Granted<R>` needs a path parameter, but this route has none. \
                         For a key that arrives in the query string, say so: \
                         `#[key(with = \"Query\")]`",
                    ))
                }
                _ => None,
            }
        };

        // Names written here are checked against the route; names left to
        // the asset are checked by the assertion below, which is the same
        // check one indirection later.
        if source == Source::Path {
            for name in params.iter().flatten() {
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

        // One constant the guard and the OpenAPI parameter both read, so
        // a route documented `in: query` cannot be one that looks in the
        // path. `Path` is the default and stays unwritten.
        let in_const = match source {
            Source::Path => quote! {},
            Source::Query => {
                quote! { const IN: ::doxa::auth::KeyIn = ::doxa::auth::KeyIn::Query; }
            }
        };

        // Emitted only when this call site has something to say. Left off,
        // the trait's empty default stands and the asset's `KEY_NAMES`
        // answer — so the column a lookup matches is stated once, beside
        // the lookup, rather than on every route that reaches it.
        let params_const = params.as_ref().map(|params| {
            let lits = params
                .iter()
                .map(|name| LitStr::new(name, Span::call_site()));
            quote! { const PARAMS: &'static [&'static str] = &[#(#lits),*]; }
        });

        // The route half of the deferred case: the asset names its key's
        // parameters, and this is where they meet the template. Without it
        // an asset keyed on a column the route does not expose would be a
        // 500 on the first request instead of a build failure.
        let route_check = match (&params, source, takes_key) {
            (None, Source::Path, true) => instance_asset(&pat_type.ty).map(|asset| {
                let route_lits = path_names
                    .iter()
                    .map(|name| LitStr::new(name, Span::call_site()));
                let message = format!(
                    "this route's path parameters ({}) do not include the ones this asset's \
                     key is named after — annotate the argument with `#[key(\"…\")]`, one \
                     name per key segment",
                    path_names.join(", "),
                );
                quote! {
                    const _: () = assert!(
                        ::doxa::auth::names_within(
                            <#asset as ::doxa::auth::Granting>::KEY_NAMES,
                            &[#(#route_lits),*],
                        ),
                        #message,
                    );
                }
            }),
            _ => None,
        };

        items.extend(quote! {
            #[doc(hidden)]
            #[allow(non_camel_case_types)]
            pub struct #marker;

            impl ::doxa::auth::GrantSite for #marker {
                #params_const
                const ACTION: &'static str = #action;
                #scheme_const
                #in_const
            }

            #route_check
        });

        // A bare `Granted<Widget>` means the instance form; the mode
        // marker is what the extractor actually dispatches on.
        site_subject(&mut pat_type.ty, &marker, mode.is_none());
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
            sig.contains(":: doxa :: auth :: One < Widget , __doxa_grant_site_get_widget_w >"),
            "the bare subject is wrapped in the instance mode marker, carrying the site: {sig}"
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

        // Nothing emitted: the trait's empty default is already right for
        // a form that names no object, and writing it out would be a
        // second statement of the same thing.
        assert!(!items.contains("PARAMS"), "{items}");
        assert!(
            !sig.contains("One <"),
            "an explicit mode marker is left alone: {sig}"
        );
        assert!(
            sig.contains("Many < Widget , __doxa_grant_site_list_widgets_w >"),
            "the site lands inside the mode marker the subject already named: {sig}"
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

        assert!(!items.contains("PARAMS"), "{items}");
        assert!(
            items.contains(r#"const ACTION : & 'static str = "create""#),
            "{items}"
        );
        // Nothing to check against a template either: a capability names
        // no object, so there is no key that could miss one.
        assert!(!items.contains("names_within"), "{items}");
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

    /// Several path parameters and no annotation is no longer a choice the
    /// macro has to make: the asset's key names which one it is, and the
    /// route is only checked for having it.
    #[test]
    fn several_path_parameters_defer_to_the_assets_key_names() {
        let (items, _) = run(
            "get",
            &["fid", "id"],
            quote! {
                async fn get_widget(w: Granted<Widget>) {}
            },
        )
        .expect("rewrites");

        assert!(
            !items.contains("PARAMS"),
            "the site says nothing, so `Granting::KEY_NAMES` answers: {items}",
        );
        assert!(
            items.contains(
                "names_within (< Widget as :: doxa :: auth :: Granting > :: KEY_NAMES , \
                 & [\"fid\" , \"id\"] ,)"
            ),
            "{items}",
        );
    }

    /// The deferred case is still checked, just one indirection later: an
    /// asset keyed on a column this route does not expose fails the build
    /// rather than the first request.
    #[test]
    fn the_deferred_case_names_the_routes_parameters_in_its_message() {
        let (items, _) = run(
            "get",
            &["fid", "id"],
            quote! {
                async fn get_widget(w: Granted<Widget>) {}
            },
        )
        .expect("rewrites");

        assert!(
            items.contains("do not include the ones this asset's key"),
            "{items}"
        );
        assert!(items.contains("(fid, id)"), "{items}");
    }

    /// A key that arrives in the query string sets the source constant the
    /// guard and the spec both read, and consults no route template.
    #[test]
    fn a_query_key_says_so_on_the_site() {
        let (items, sig) = run(
            "get",
            &[],
            quote! {
                async fn get_widget(#[key(with = "Query")] w: Granted<Widget>) {}
            },
        )
        .expect("rewrites");

        assert!(
            items.contains(
                "const IN : :: doxa :: auth :: KeyIn = :: doxa :: auth :: KeyIn :: Query"
            ),
            "{items}",
        );
        assert!(
            sig.contains(":: doxa :: auth :: One < Widget , __doxa_grant_site_get_widget_w >"),
            "the subject is still sited: {sig}",
        );
        assert!(!items.contains("PARAMS"), "{items}");
        assert!(
            !items.contains("names_within"),
            "there is no route template to check a query key against: {items}",
        );
    }

    /// `with = "Path"` is the default written out, so it leaves the
    /// trait's own constant in place rather than restating it.
    #[test]
    fn a_path_key_written_out_emits_no_source_constant() {
        let (items, _) = run(
            "get",
            &["id"],
            quote! {
                async fn get_widget(#[key(with = "Path")] w: Granted<Widget>) {}
            },
        )
        .expect("rewrites");

        assert!(!items.contains("KeyIn"), "{items}");
        assert!(
            items.contains(r#"const PARAMS : & 'static [& 'static str] = & ["id"]"#),
            "the single path parameter is still found: {items}",
        );
    }

    /// A source is one of two things, and anything else is a typo caught
    /// where it was written.
    #[test]
    fn an_unknown_source_is_rejected() {
        let error = run(
            "get",
            &["id"],
            quote! {
                async fn get_widget(#[key(with = "Header")] w: Granted<Widget>) {}
            },
        )
        .expect_err("not a source");

        assert!(error.contains("unknown key source `Header`"), "{error}");
    }

    #[test]
    fn an_unknown_option_names_the_ones_that_exist() {
        let error = run(
            "get",
            &["id"],
            quote! {
                async fn get_widget(#[key(from = "Query")] w: Granted<Widget>) {}
            },
        )
        .expect_err("not an option");

        assert!(error.contains("unknown `#[key]` option `from`"), "{error}");
        assert!(error.contains("`with`"), "{error}");
    }

    /// A path key with nothing in the path is the one instance route the
    /// asset's names cannot rescue, and the message says what to do about
    /// it.
    #[test]
    fn an_instance_route_with_no_path_parameter_points_at_the_query_form() {
        let error = run(
            "get",
            &[],
            quote! {
                async fn get_widget(w: Granted<Widget>) {}
            },
        )
        .expect_err("no parameter");

        assert!(error.contains("needs a path parameter"), "{error}");
        assert!(error.contains(r#"#[key(with = "Query")]"#), "{error}");
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

        assert!(error.contains("read no key"), "{error}");
    }

    /// Nor may it say where the key it does not read arrives.
    #[test]
    fn a_collection_may_not_name_a_source() {
        let error = run(
            "get",
            &["id"],
            quote! {
                async fn list_widgets(#[key(with = "Query")] w: Granted<Many<Widget>>) {}
            },
        )
        .expect_err("no key on a collection");

        assert!(error.contains("read no key"), "{error}");
    }

    #[test]
    fn an_argument_that_already_names_a_site_rejects_the_annotation() {
        let error = run(
            "get",
            &["id"],
            quote! {
                async fn get_widget(#[key("id")] w: Granted<One<Widget, MySite>>) {}
            },
        )
        .expect_err("already sited");

        assert!(error.contains("already names a site"), "{error}");
    }

    /// A hand-written site is left exactly as it stands — no marker
    /// generated, no second one appended behind the first.
    #[test]
    fn a_subject_that_names_its_own_site_is_left_alone() {
        let (items, sig) = run(
            "get",
            &["id"],
            quote! {
                async fn get_widget(w: Granted<One<Widget, MySite>>) {}
            },
        )
        .expect("rewrites");

        assert!(items.is_empty(), "nothing generated: {items}");
        assert!(sig.contains("One < Widget , MySite >"), "{sig}");
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
