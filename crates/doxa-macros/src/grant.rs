//! `#[grant(...)]` handling for the `Granted<T>` guard extractor.
//!
//! A route states two things the handler body never does: which action to
//! authorize, and which OpenAPI security scheme to reference. This module
//! resolves both per call site and rewrites the argument to name them:
//!
//! ```ignore
//! #[get("/folders/{fid}/widgets/{id}")]
//! async fn get_widget(widget: Granted<Widget>) -> Json<Widget>
//! ```
//!
//! becomes `Granted<One<Widget, ReadAction, __Site>>`. The action and the
//! site both ride on the subject rather than on `Granted` itself, which is
//! what leaves the guard a two-field pair a handler can destructure.
//!
//! # Which action
//!
//! A type, always — one of the asset's own `DeclaredAction` markers, which
//! `#[derive(Actions)]` emits per variant. Naming it as a path rather than
//! a string is what lets `One`'s bound hold it to *this* asset's
//! vocabulary: an action belonging to another asset does not resolve, even
//! where the two spell it the same.
//!
//! Unannotated, it resolves through the verb: `#[get]` asks the asset's
//! vocabulary for its `ReadAction`, `#[delete]` for its `DeleteAction`, and
//! so on. That mapping is declared once on the vocabulary itself —
//! `#[action(verb = get)]` — rather than derived from a name here, so a
//! vocabulary calling its read action `View` needs no special case and one
//! with no read action at all fails the build naming the missing impl.
//!
//! # Which parameter carries the key
//!
//! The key's own field names. A key is a struct deriving `Deserialize` and
//! the guard reads it with axum's `Path` or `Query`, so `{id}` binds
//! `struct WidgetKey { id: Uuid }` and no route says so. A route whose
//! parameters do not include the key's fails the build, on the
//! `names_within` assertion emitted below.
//!
//! Renaming happens at the row — `#[resource(key = "slug")]` — rather than
//! per route: the name is one fact about a way into a row, and restating it
//! per call site is how the two came to disagree.
//!
//! # Where the key comes from
//!
//! Inferred, and not sayable. An instance route with no path parameters
//! cannot be reading its key from the path, so it reads it from the query
//! string and `GrantSite::IN` says so — which is what keeps the guard and
//! the published parameter from disagreeing about where to look. With a
//! path parameter present the key comes from the path, and the assertion
//! below holds the route to having the ones the key is named after.
//!
//! `Many<R>` and `Cap<M>` name no object, so they read no key at all.

use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;
use syn::{
    FnArg, GenericArgument, Ident, ItemFn, LitStr, Pat, Path, PathArguments, Result, Token, Type,
};

/// Which half of the request line a key arrives in, and `GrantSite::IN`
/// on the other side. Inferred from the route template.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    /// The route template, which is where a key comes from whenever the
    /// route has parameters at all.
    Path,
    /// The query string, which is the only remaining reading for an
    /// instance route whose template names nothing.
    Query,
}

/// Parsed `#[grant(action = Marker, scheme = "...")]`.
struct GrantArgs {
    action: Option<Path>,
    scheme: Option<LitStr>,
}

impl Parse for GrantArgs {
    fn parse(input: ParseStream) -> Result<Self> {
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

            // A bare string used to rename the route's parameter. A key
            // is a struct whose field names *are* the parameters, so
            // there is nothing left for a route to rename — say it here
            // rather than letting the name be silently ignored.
            if input.peek(LitStr) {
                return Err(input.error(
                    "a route does not name its key's segments: the key struct's field names \
                     are the route parameters. Spell the parameter the way the key spells the \
                     field, or rename the field itself with `#[resource(key = \"…\")]`",
                ));
            }

            let key: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            match key.to_string().as_str() {
                // A path, not a string: the marker is a type that already
                // exists, so a typo is a resolution error naming the
                // vocabulary rather than an action nothing declares.
                "action" => {
                    if input.peek(LitStr) {
                        let literal: LitStr = input.parse()?;
                        return Err(syn::Error::new_spanned(
                            &literal,
                            format!(
                                "an action is named by its marker type, not by a string: \
                                 write `action = {}` and bring it into scope with \
                                 `use widget_action::{};`",
                                upper_camel(&literal.value()),
                                upper_camel(&literal.value()),
                            ),
                        ));
                    }
                    action = Some(input.parse::<Path>()?);
                }
                "scheme" => scheme = Some(input.parse::<LitStr>()?),
                other => {
                    return Err(syn::Error::new(
                        key.span(),
                        format!(
                            "unknown `#[grant]` option `{other}` — expected `action` \
                             or `scheme`"
                        ),
                    ))
                }
            }
        }

        Ok(Self { action, scheme })
    }
}

/// A snake_case action name as its marker would be spelled, for the
/// diagnostic that points a string at the type to write instead.
///
/// Only ever used in an error message — nothing resolves through it, which
/// is the whole point of the change it is explaining.
fn upper_camel(name: &str) -> String {
    name.split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// The `verb` trait an unannotated route resolves its action through.
fn verb_trait(method: &str) -> Ident {
    let name = match method {
        "post" => "CreateAction",
        "put" | "patch" => "UpdateAction",
        "delete" => "DeleteAction",
        _ => "ReadAction",
    };
    format_ident!("{}", name)
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

/// Complete the subject: give it a mode wrapper if it had none, then
/// append whatever of the action and the site it is still missing.
///
/// A bare `Granted<Widget>` is the instance form written short, so it
/// gains `One<…>` on the way in. `One<Widget>` is missing both its action
/// and its site; `One<Widget, Delete>` named the action itself and is
/// missing only the site.
fn complete_subject(ty: &mut Type, appended: &[TokenStream], wrap: bool) {
    let Some(inner) = subject_arg_mut(ty) else {
        return;
    };

    if wrap {
        let subject = inner.clone();
        *inner = syn::parse_quote!(::doxa::auth::One<#subject, #(#appended),*>);
        return;
    }

    let Type::Path(type_path) = inner else { return };
    let Some(last) = type_path.path.segments.last_mut() else {
        return;
    };
    if let PathArguments::AngleBracketed(args) = &mut last.arguments {
        for extra in appended {
            args.args
                .push(GenericArgument::Type(syn::parse_quote!(#extra)));
        }
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

/// The asset a subject is about, for resolving its action from the verb.
///
/// Wider than [`instance_asset`] because a collection authorizes an action
/// on an asset too — it just reads no key while doing it. Only `Cap` has
/// no asset to name, and it has no action either.
fn subject_asset(ty: &Type) -> Option<Type> {
    let subject = subject_arg(ty)?;
    match subject_mode(subject) {
        Some((name, _)) if name == "One" || name == "Many" => subject_arg(subject).cloned(),
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

/// Strip `#[grant(...)]` off every argument, generate a `GrantSite` impl
/// per `Granted<…>` argument, and rewrite those arguments to name their
/// action and their site. Returns the generated items.
pub fn rewrite(item_fn: &mut ItemFn, method: &str, path_names: &[String]) -> Result<TokenStream> {
    let fn_ident = item_fn.sig.ident.clone();
    let verb = verb_trait(method);
    let mut items = TokenStream::new();

    for (index, arg) in item_fn.sig.inputs.iter_mut().enumerate() {
        let FnArg::Typed(pat_type) = arg else {
            continue;
        };

        // Pull the annotation off regardless of the argument type — an
        // unstripped `#[grant]` would not compile.
        let mut annotation: Option<(GrantArgs, Span)> = None;
        let mut kept = Vec::new();
        for attr in std::mem::take(&mut pat_type.attrs) {
            if attr.path().is_ident("grant") {
                if annotation.is_some() {
                    return Err(syn::Error::new_spanned(
                        attr,
                        "duplicate `#[grant(...)]` on one argument",
                    ));
                }
                let span = attr.span();
                annotation = Some((attr.parse_args::<GrantArgs>()?, span));
            } else if attr.path().is_ident("key") {
                return Err(syn::Error::new_spanned(
                    attr,
                    "`#[key(...)]` is now `#[grant(...)]`: it never named the key, and \
                     two of its three options were about the grant. `with` is gone — the \
                     key's source is inferred from the route — and `action` takes the \
                     action's marker type rather than a string",
                ));
            } else {
                kept.push(attr);
            }
        }
        pat_type.attrs = kept;

        let Some(arity) = granted_arity(&pat_type.ty) else {
            if let Some((_, span)) = &annotation {
                return Err(syn::Error::new(
                    *span,
                    "`#[grant(...)]` applies to a `Granted<T>` argument",
                ));
            }
            continue;
        };

        if arity != 1 {
            if let Some((_, span)) = &annotation {
                return Err(syn::Error::new(
                    *span,
                    "`Granted<…>` takes one type argument — the subject, which names \
                     its own action and site as `One<Widget, Read, MySite>`",
                ));
            }
            continue;
        }

        let mode = subject_arg(&pat_type.ty).and_then(subject_mode);
        // `Cap<M, S>` carries no action, so it is full one argument
        // earlier than the two asset-backed forms.
        let sited_arity = match mode.as_ref().map(|(name, _)| name.as_str()) {
            Some("Cap") => 2,
            _ => 3,
        };

        // A subject that spells out its own site was written by hand.
        // Leave it alone, and refuse an annotation that would contradict
        // what it already names.
        if mode.as_ref().is_some_and(|(_, a)| *a >= sited_arity) {
            if let Some((_, span)) = &annotation {
                return Err(syn::Error::new(
                    *span,
                    "this subject already names a site — drop `#[grant(...)]` \
                     or the site argument",
                ));
            }
            continue;
        }

        let named_arity = mode.as_ref().map_or(1, |(_, a)| *a);
        let mode = mode.map(|(name, _)| name);
        // Only the instance form reads segments out of the route.
        let takes_key = !matches!(mode.as_deref(), Some("Many") | Some("Cap"));

        // An instance route whose template names nothing cannot be
        // reading its key from the path, so it reads it from the query
        // string. Nothing to infer where there is a parameter to bind, or
        // for a form that reads no key at all.
        let source = if takes_key && path_names.is_empty() {
            Source::Query
        } else {
            Source::Path
        };

        let binding = binding_name(&pat_type.pat, index);
        let marker = format_ident!("__doxa_grant_site_{}_{}", fn_ident, binding);

        let named_action = annotation
            .as_ref()
            .and_then(|(args, _)| args.action.as_ref());
        let is_capability = mode.as_deref() == Some("Cap");

        // A capability gates on a capability, not on an action against an
        // asset — so there is no action for one to name, and `Cap` has no
        // parameter to put it in.
        if is_capability {
            if let (Some(_), Some((_, span))) = (named_action, annotation.as_ref()) {
                return Err(syn::Error::new(
                    *span,
                    "`Cap<…>` authorizes a capability rather than an action on an asset, so \
                     there is no action to name — drop `action`",
                ));
            }
        }

        // The other two forms resolve one, either from the annotation or
        // through the trait this route's verb selects.
        let action = if is_capability {
            None
        } else if let Some(path) = named_action {
            Some(quote!(#path))
        } else {
            let asset = subject_asset(&pat_type.ty).ok_or_else(|| {
                syn::Error::new_spanned(
                    &pat_type.ty,
                    "cannot tell which asset this subject is about, so its action cannot \
                     be resolved from the verb — name it with `#[grant(action = …)]`",
                )
            })?;
            Some(quote! {
                <<#asset as ::doxa::auth::Granting>::Actions
                    as ::doxa::auth::verb::#verb>::Action
            })
        };

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

        // The asset names its key's parameters and this is where they
        // meet the template. Without it an asset keyed on a column the
        // route does not expose would be a 500 on the first request
        // instead of a build failure.
        let route_check = match (source, takes_key) {
            (Source::Path, true) => instance_asset(&pat_type.ty).map(|asset| {
                let route_lits = path_names
                    .iter()
                    .map(|name| LitStr::new(name, Span::call_site()));
                let message = format!(
                    "this route's path parameters ({}) do not include the ones this asset's \
                     key is named after — spell the segment the way the key spells its field, \
                     or rename the field with `#[resource(key = \"…\")]`",
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
                #scheme_const
                #in_const
            }

            #route_check
        });

        // A bare `Granted<Widget>` means the instance form; the mode
        // marker is what the extractor actually dispatches on. A subject
        // that named its own action keeps it and gains only the site.
        let wrap = mode.is_none();
        let mut appended = Vec::new();
        if let Some(action) = action {
            if wrap || named_arity < 2 {
                appended.push(action);
            }
        }
        appended.push(quote!(#marker));
        complete_subject(&mut pat_type.ty, &appended, wrap);
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
        let (_, sig) = run(
            "get",
            &["id"],
            quote! {
                async fn get_widget(w: Granted<Widget>) {}
            },
        )
        .expect("rewrites");

        assert!(
            sig.contains(":: doxa :: auth :: One < Widget ,"),
            "the bare subject is wrapped in the instance mode marker: {sig}"
        );
        assert!(
            sig.contains("__doxa_grant_site_get_widget_w"),
            "and carries the site: {sig}"
        );
    }

    /// An unannotated route resolves its action through the trait its verb
    /// selects, off the asset's own vocabulary — never off a name.
    #[test]
    fn the_verb_selects_the_trait_the_action_resolves_through() {
        let (_, sig) = run(
            "delete",
            &["fid", "id"],
            quote! {
                async fn drop_widget(w: Granted<Widget>) {}
            },
        )
        .expect("rewrites");

        assert!(
            sig.contains(
                "< < Widget as :: doxa :: auth :: Granting > :: Actions as \
                 :: doxa :: auth :: verb :: DeleteAction > :: Action"
            ),
            "{sig}",
        );
    }

    #[test]
    fn get_resolves_through_the_read_slot() {
        let (_, sig) = run(
            "get",
            &["id"],
            quote! {
                async fn get_widget(w: Granted<Widget>) {}
            },
        )
        .expect("rewrites");

        assert!(sig.contains("verb :: ReadAction"), "{sig}");
    }

    /// `PUT` and `PATCH` are one slot, because both mean "update" and a
    /// vocabulary telling them apart would be naming two actions.
    #[test]
    fn put_and_patch_share_the_update_slot() {
        for method in ["put", "patch"] {
            let (_, sig) = run(
                method,
                &["id"],
                quote! {
                    async fn edit_widget(w: Granted<Widget>) {}
                },
            )
            .expect("rewrites");

            assert!(sig.contains("verb :: UpdateAction"), "{method}: {sig}");
        }
    }

    #[test]
    fn a_named_action_is_used_verbatim() {
        let (items, sig) = run(
            "post",
            &["id"],
            quote! {
                async fn archive(#[grant(action = widget_action::Archive)] w: Granted<Widget>) {}
            },
        )
        .expect("rewrites");

        assert!(
            sig.contains("One < Widget , widget_action :: Archive ,"),
            "the marker lands in the action slot as written: {sig}",
        );
        assert!(
            !sig.contains("verb ::"),
            "and the verb is not consulted at all: {sig}",
        );
        assert!(!items.contains("SCHEME"), "no scheme given: {items}");
    }

    /// The action is a type. A string used to name one, and the message
    /// says what to write instead rather than only what is wrong.
    #[test]
    fn a_string_action_is_rejected_and_spells_the_marker() {
        let error = run(
            "post",
            &["id"],
            quote! {
                async fn archive(#[grant(action = "read_secrets")] w: Granted<Widget>) {}
            },
        )
        .expect_err("not a string");

        assert!(error.contains("named by its marker type"), "{error}");
        assert!(error.contains("action = ReadSecrets"), "{error}");
    }

    #[test]
    fn an_explicit_scheme_is_written_out() {
        let (items, _) = run(
            "get",
            &["id"],
            quote! {
                async fn get_widget(#[grant(scheme = "oauth")] w: Granted<Widget>) {}
            },
        )
        .expect("rewrites");

        assert!(
            items.contains(r#"const SCHEME : & 'static str = "oauth""#),
            "{items}"
        );
    }

    #[test]
    fn a_collection_resolves_its_action_from_the_asset_too() {
        let (_, sig) = run(
            "get",
            &[],
            quote! {
                async fn list_widgets(w: Granted<Many<Widget>>) {}
            },
        )
        .expect("rewrites");

        assert!(
            sig.contains("Many < Widget , < < Widget as :: doxa :: auth :: Granting >"),
            "a listing authorizes an action on an asset, it just reads no key: {sig}",
        );
        assert!(
            sig.contains("__doxa_grant_site_list_widgets_w"),
            "and still carries the site: {sig}",
        );
    }

    /// A capability names no asset and no action, so it takes neither —
    /// which is why `Cap` has no action parameter to fill.
    #[test]
    fn a_capability_takes_no_action() {
        let (items, sig) = run(
            "post",
            &[],
            quote! {
                async fn flush(w: Granted<Cap<FlushCaches>>) {}
            },
        )
        .expect("rewrites");

        assert!(
            sig.contains("Cap < FlushCaches , __doxa_grant_site_flush_w >"),
            "the site is the only thing appended: {sig}",
        );
        assert!(!sig.contains("verb ::"), "{sig}");
        assert!(
            !items.contains("names_within"),
            "a capability names no object, so no key can miss a segment: {items}",
        );
    }

    #[test]
    fn a_capability_may_not_name_an_action() {
        let error = run(
            "post",
            &[],
            quote! {
                async fn flush(#[grant(action = Purge)] w: Granted<Cap<FlushCaches>>) {}
            },
        )
        .expect_err("no action on a capability");

        assert!(error.contains("no action to name"), "{error}");
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
        assert!(
            sig.contains("verb :: ReadAction"),
            "and still has its action filled in: {sig}"
        );
    }

    /// A subject that named its own action keeps it and gains only the
    /// site — the action slot is already full.
    #[test]
    fn a_subject_that_names_its_action_gains_only_the_site() {
        let (_, sig) = run(
            "get",
            &["id"],
            quote! {
                async fn get_widget(w: Granted<One<Widget, widget_action::Read>>) {}
            },
        )
        .expect("rewrites");

        assert!(
            sig.contains("One < Widget , widget_action :: Read , __doxa_grant_site_get_widget_w >"),
            "{sig}",
        );
    }

    /// Several path parameters are not a choice the macro makes: the
    /// asset's key names which one it is, and the route is only checked
    /// for having them.
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
            items.contains(
                "names_within (< Widget as :: doxa :: auth :: Granting > :: KEY_NAMES , \
                 & [\"fid\" , \"id\"] ,)"
            ),
            "{items}",
        );
    }

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

    /// An instance route whose template names nothing can only be reading
    /// its key from the query string, so it says so without being told.
    #[test]
    fn a_route_with_no_path_parameter_infers_the_query_source() {
        let (items, _) = run(
            "get",
            &[],
            quote! {
                async fn find_widget(w: Granted<Widget>) {}
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
            !items.contains("names_within"),
            "there is no template to check a query key against: {items}",
        );
    }

    /// The path is the default and stays unwritten, so a route with
    /// parameters emits no source constant at all.
    #[test]
    fn a_route_with_path_parameters_emits_no_source_constant() {
        let (items, _) = run(
            "get",
            &["id"],
            quote! {
                async fn get_widget(w: Granted<Widget>) {}
            },
        )
        .expect("rewrites");

        assert!(!items.contains("KeyIn"), "{items}");
    }

    /// A collection reads no key, so it is `Path` either way and never
    /// picks up the query inference an instance route would.
    #[test]
    fn a_collection_never_infers_a_query_source() {
        let (items, _) = run(
            "get",
            &[],
            quote! {
                async fn list_widgets(w: Granted<Many<Widget>>) {}
            },
        )
        .expect("rewrites");

        assert!(!items.contains("KeyIn"), "{items}");
    }

    #[test]
    fn an_unknown_option_names_the_ones_that_exist() {
        let error = run(
            "get",
            &["id"],
            quote! {
                async fn get_widget(#[grant(from = "Query")] w: Granted<Widget>) {}
            },
        )
        .expect_err("not an option");

        assert!(
            error.contains("unknown `#[grant]` option `from`"),
            "{error}"
        );
        assert!(error.contains("`scheme`"), "{error}");
    }

    /// The old spelling fails loudly rather than being ignored, and says
    /// what became of each of its three options.
    #[test]
    fn the_old_key_attribute_is_rejected_with_a_pointer() {
        let error = run(
            "get",
            &["id"],
            quote! {
                async fn get_widget(#[key(with = "Query")] w: Granted<Widget>) {}
            },
        )
        .expect_err("renamed");

        assert!(
            error.contains("`#[key(...)]` is now `#[grant(...)]`"),
            "{error}"
        );
        assert!(error.contains("`with` is gone"), "{error}");
    }

    /// Renaming a segment at the call site is gone: the key's fields are
    /// the parameters. A route that tries is told where the rename lives.
    #[test]
    fn naming_a_segment_at_the_call_site_is_rejected() {
        let error = run(
            "get",
            &["id"],
            quote! {
                async fn get_widget(#[grant("widget_id")] w: Granted<Widget>) {}
            },
        )
        .expect_err("no longer a thing");

        assert!(
            error.contains("a route does not name its key's segments"),
            "{error}"
        );
        assert!(error.contains(r#"#[resource(key = "…")]"#), "{error}");
    }

    #[test]
    fn an_argument_that_already_names_a_site_rejects_the_annotation() {
        let error = run(
            "get",
            &["id"],
            quote! {
                async fn get_widget(
                    #[grant(scheme = "oauth")] w: Granted<One<Widget, Read, MySite>>,
                ) {}
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
                async fn get_widget(w: Granted<One<Widget, Read, MySite>>) {}
            },
        )
        .expect("rewrites");

        assert!(items.is_empty(), "nothing generated: {items}");
        assert!(sig.contains("One < Widget , Read , MySite >"), "{sig}");
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
