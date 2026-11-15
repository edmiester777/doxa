//! `#[faults(…)]`: failure classes an error enum inherits, doxa's `common` four and any set an app
//! registers with `fault_set!`. A set reaches the attribute through a `macro_rules!` callback,
//! since one proc macro can't read another item.

use std::collections::{HashMap, HashSet};

use proc_macro2::{Span, TokenStream, TokenTree};
use quote::{quote, ToTokens};
use syn::parse::{Parse, ParseStream, Parser};
use syn::punctuated::Punctuated;
use syn::{
    bracketed, parse2, parse_quote, Attribute, Fields, Ident, ItemEnum, LitInt, LitStr, Token,
    Variant, Visibility,
};

/// One class: the variant it lands on, and how that variant answers.
#[derive(Clone)]
struct Class {
    docs: Vec<Attribute>,
    key: Ident,
    variant: Ident,
    status: LitInt,
    code: LitStr,
    outcome: Option<LitStr>,
    redact: bool,
}

impl Parse for Class {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let docs = input.call(Attribute::parse_outer)?;
        let key: Ident = input.parse()?;
        input.parse::<Token![:]>()?;
        let variant: Ident = input.parse()?;
        input.parse::<Token![=]>()?;
        let status: LitInt = input.parse()?;
        let code: LitStr = input.parse()?;
        let (mut outcome, mut redact) = (None, false);
        if input.peek(syn::token::Paren) {
            let content;
            syn::parenthesized!(content in input);
            let opts = Punctuated::<syn::Meta, Token![,]>::parse_terminated(&content)?;
            for opt in opts {
                match &opt {
                    syn::Meta::Path(p) if p.is_ident("redact") => redact = true,
                    syn::Meta::NameValue(nv) if nv.path.is_ident("outcome") => {
                        outcome = Some(parse2(nv.value.to_token_stream())?);
                    }
                    other => {
                        return Err(syn::Error::new_spanned(
                            other,
                            "a class takes `(outcome = \"…\")` and `(redact)`",
                        ))
                    }
                }
            }
        }
        Ok(Class {
            docs,
            key,
            variant,
            status,
            code,
            outcome,
            redact,
        })
    }
}

impl ToTokens for Class {
    fn to_tokens(&self, out: &mut TokenStream) {
        let Class {
            docs,
            key,
            variant,
            status,
            code,
            outcome,
            redact,
        } = self;
        let mut opts = Vec::new();
        if let Some(o) = outcome {
            opts.push(quote!(outcome = #o));
        }
        if *redact {
            opts.push(quote!(redact));
        }
        let opts = (!opts.is_empty()).then(|| quote!((#(#opts),*)));
        out.extend(quote!(#(#docs)* #key: #variant = #status #code #opts));
    }
}

fn status(class: &Class) -> u16 {
    class.status.base10_parse().unwrap_or_default()
}

/// doxa's four, which `#[faults(common)]` names.
fn common() -> Vec<Class> {
    vec![
        parse_quote! {
            /// The request's content broke a rule; fix it before retrying.
            validation: Validation = 400 "validation_error"
        },
        parse_quote! {
            /// Nothing by that name is visible to the caller.
            not_found: NotFound = 404 "not_found"
        },
        parse_quote! {
            /// The caller may not do this.
            forbidden: Forbidden = 403 "forbidden" (outcome = "denied")
        },
        parse_quote! {
            /// Something failed on the server; the cause is logged, not sent.
            internal: Internal = 500 "internal" (redact)
        },
    ]
}

struct SetDecl {
    attrs: Vec<Attribute>,
    vis: Visibility,
    name: Ident,
    from: Option<syn::Path>,
    classes: Vec<Class>,
}

impl Parse for SetDecl {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let attrs = input.call(Attribute::parse_outer)?;
        let vis: Visibility = input.parse()?;
        let name: Ident = input.parse()?;
        let from = if input.peek(syn::Ident) && input.fork().parse::<Ident>()? == "from" {
            input.parse::<Ident>()?;
            Some(input.parse()?)
        } else {
            None
        };
        let content;
        syn::braced!(content in input);
        let classes = Punctuated::<Class, Token![,]>::parse_terminated(&content)?;
        Ok(SetDecl {
            attrs,
            vis,
            name,
            from,
            classes: classes.into_iter().collect(),
        })
    }
}

/// `fault_set!`: the set's carrier enum, and the callback `#[faults(Set)]` invokes.
pub fn fault_set(input: TokenStream) -> syn::Result<TokenStream> {
    let SetDecl {
        attrs,
        vis,
        name,
        from,
        classes,
    } = parse2(input)?;
    let mut seen = HashSet::new();
    for class in &classes {
        if !seen.insert(class.key.to_string()) {
            return Err(syn::Error::new_spanned(
                &class.key,
                "a class is declared once",
            ));
        }
    }
    let variants = classes.iter().map(|c| {
        let (docs, v) = (&c.docs, &c.variant);
        quote!(#(#docs)* #v(::std::string::String))
    });
    let arms = classes.iter().map(|c| {
        let v = &c.variant;
        quote!(Self::#v(m) => m)
    });
    let from = from.map(|f| absolute(&f)).transpose()?.unwrap_or_default();
    let callback = quote::format_ident!("__doxa_faults_{}", name);
    Ok(quote! {
        #(#attrs)*
        #[derive(Debug, Clone, PartialEq, Eq)]
        #vis enum #name { #(#variants,)* }

        impl #name {
            /// The message the failure carries.
            pub fn message(&self) -> &str {
                match self { #(#arms,)* }
            }
        }

        impl ::core::fmt::Display for #name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(self.message())
            }
        }

        #[doc(hidden)]
        #[macro_export]
        macro_rules! #callback {
            ($($rest:tt)*) => {
                ::doxa::__faults_chain! {
                    @def { ty: $crate::#name, from: [#from], classes: [#(#classes),*] }
                    $($rest)*
                }
            };
        }
        #[doc(hidden)]
        #vis use #callback as #name;
    })
}

/// `path` as the exported callback must spell it: `crate::` becomes `$crate::`.
fn absolute(path: &syn::Path) -> syn::Result<TokenStream> {
    let first = &path.segments[0].ident;
    if path.leading_colon.is_some() {
        return Ok(quote!(#path));
    }
    if first == "crate" {
        let rest = path.segments.iter().skip(1);
        return Ok(quote!($crate #(:: #rest)*));
    }
    Err(syn::Error::new_spanned(
        path,
        "other crates expand this set, so name the source from the root: `crate::…` or `::dep::…`",
    ))
}

/// What one registered set contributes.
struct SetDef {
    ty: TokenStream,
    from: TokenStream,
    classes: Vec<Class>,
}

impl Parse for SetDef {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let content;
        syn::braced!(content in input);
        expect_ident(&content, "ty")?;
        content.parse::<Token![:]>()?;
        let ty = until_comma(&content)?;
        content.parse::<Token![,]>()?;
        expect_ident(&content, "from")?;
        content.parse::<Token![:]>()?;
        let from;
        bracketed!(from in content);
        let from: TokenStream = from.parse()?;
        content.parse::<Token![,]>()?;
        expect_ident(&content, "classes")?;
        content.parse::<Token![:]>()?;
        let classes;
        bracketed!(classes in content);
        let classes = Punctuated::<Class, Token![,]>::parse_terminated(&classes)?;
        Ok(SetDef {
            ty,
            from,
            classes: classes.into_iter().collect(),
        })
    }
}

fn expect_ident(input: ParseStream, name: &str) -> syn::Result<()> {
    let ident: Ident = input.parse()?;
    if ident != name {
        return Err(syn::Error::new_spanned(ident, format!("expected `{name}`")));
    }
    Ok(())
}

/// Tokens up to the next top-level `,`, so `$crate::Set` passes through unparsed.
fn until_comma(input: ParseStream) -> syn::Result<TokenStream> {
    input.step(|cursor| {
        let mut out = TokenStream::new();
        let mut rest = *cursor;
        while let Some((tt, next)) = rest.token_tree() {
            if matches!(&tt, TokenTree::Punct(p) if p.as_char() == ',') {
                break;
            }
            out.extend([tt]);
            rest = next;
        }
        Ok((out, rest))
    })
}

/// One argument of `#[faults(…)]`.
enum Arg {
    Common,
    Wire,
    Set(syn::Path),
    Override(Ident, Ident),
}

impl Parse for Arg {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.peek(Ident) && input.peek2(Token![=]) {
            let key: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            return Ok(Arg::Override(key, input.parse()?));
        }
        let path: syn::Path = input.parse()?;
        Ok(if path.is_ident("common") {
            Arg::Common
        } else if path.is_ident("wire") {
            Arg::Wire
        } else {
            Arg::Set(path)
        })
    }
}

/// `#[faults(…)]`: `common`, registered sets by path, `class = Variant` overrides, and `wire`
/// to write no `From<source>`.
pub fn attribute(args: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let parsed = Punctuated::<Arg, Token![,]>::parse_terminated.parse2(args.clone())?;
    let sets: Vec<syn::Path> = parsed
        .iter()
        .filter_map(|a| match a {
            Arg::Set(p) => Some(p.clone()),
            _ => None,
        })
        .collect();
    if sets.is_empty() {
        return expand(&parsed, Vec::new(), parse2(item)?);
    }
    Ok(chain(&[], &sets, &args, &item))
}

/// Invoke the next set's callback, carrying what's been collected.
fn chain(
    collected: &[TokenStream],
    remaining: &[syn::Path],
    args: &TokenStream,
    item: &TokenStream,
) -> TokenStream {
    let (next, rest) = remaining.split_first().expect("a set remains");
    quote! {
        #next! {
            collected: [#(#collected)*]
            remaining: [#(#rest),*]
            args: [#args]
            item: { #item }
        }
    }
}

/// `__faults_chain!`: one set's definition arrives; collect it, and call the next or expand.
pub fn chain_step(input: TokenStream) -> syn::Result<TokenStream> {
    struct Step {
        def: TokenStream,
        collected: Vec<TokenStream>,
        remaining: Vec<syn::Path>,
        args: TokenStream,
        item: TokenStream,
    }
    impl Parse for Step {
        fn parse(input: ParseStream) -> syn::Result<Self> {
            input.parse::<Token![@]>()?;
            expect_ident(input, "def")?;
            let def: proc_macro2::Group = input.parse()?;
            expect_ident(input, "collected")?;
            input.parse::<Token![:]>()?;
            let collected;
            bracketed!(collected in input);
            let mut groups = Vec::new();
            while !collected.is_empty() {
                let g: proc_macro2::Group = collected.parse()?;
                groups.push(g.into_token_stream());
            }
            expect_ident(input, "remaining")?;
            input.parse::<Token![:]>()?;
            let remaining;
            bracketed!(remaining in input);
            let remaining = Punctuated::<syn::Path, Token![,]>::parse_terminated(&remaining)?;
            expect_ident(input, "args")?;
            input.parse::<Token![:]>()?;
            let args;
            bracketed!(args in input);
            let args: TokenStream = args.parse()?;
            expect_ident(input, "item")?;
            input.parse::<Token![:]>()?;
            let item;
            syn::braced!(item in input);
            let item: TokenStream = item.parse()?;
            Ok(Step {
                def: def.into_token_stream(),
                collected: groups,
                remaining: remaining.into_iter().collect(),
                args,
                item,
            })
        }
    }
    let Step {
        def,
        mut collected,
        remaining,
        args,
        item,
    } = parse2(input)?;
    collected.push(def);
    if !remaining.is_empty() {
        return Ok(chain(&collected, &remaining, &args, &item));
    }
    let parsed = Punctuated::<Arg, Token![,]>::parse_terminated.parse2(args)?;
    let defs = collected
        .into_iter()
        .map(parse2::<SetDef>)
        .collect::<syn::Result<Vec<_>>>()?;
    expand(&parsed, defs, parse2(item)?)
}

/// How one class builds a value of the enum from a `message` in scope.
struct Landing {
    build: TokenStream,
}

fn expand(
    args: &Punctuated<Arg, Token![,]>,
    defs: Vec<SetDef>,
    mut item: ItemEnum,
) -> syn::Result<TokenStream> {
    let mut overrides = HashMap::new();
    let mut wire = false;
    let mut classes: Vec<Class> = Vec::new();
    for arg in args {
        match arg {
            Arg::Common => classes.extend(common()),
            Arg::Wire => wire = true,
            Arg::Override(key, variant) => {
                if overrides.insert(key.to_string(), variant.clone()).is_some() {
                    return Err(syn::Error::new_spanned(
                        key,
                        "a class is given a target once",
                    ));
                }
            }
            Arg::Set(_) => {}
        }
    }
    for def in &defs {
        classes.extend(def.classes.iter().cloned());
    }
    if classes.is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            "`#[faults]` names `common`, a registered set, or both",
        ));
    }

    // One key, one landing; two sets may name a class if they agree on how it answers.
    let mut unique: Vec<Class> = Vec::new();
    for class in classes {
        match unique.iter().find(|c| c.key == class.key) {
            Some(prior)
                if status(prior) != status(&class) || prior.code.value() != class.code.value() =>
            {
                return Err(syn::Error::new_spanned(
                    &item.ident,
                    format!(
                        "two sets declare the `{}` class differently: {} \"{}\" and {} \"{}\"",
                        class.key,
                        status(prior),
                        prior.code.value(),
                        status(&class),
                        class.code.value(),
                    ),
                ));
            }
            Some(_) => {}
            None => unique.push(class),
        }
    }
    for key in overrides.keys() {
        if !unique.iter().any(|c| c.key == key) {
            let known: Vec<String> = unique.iter().map(|c| c.key.to_string()).collect();
            return Err(syn::Error::new(
                Span::call_site(),
                format!("unknown class `{key}`; this enum has: {}", known.join(", ")),
            ));
        }
    }

    let declared: HashSet<String> = item.variants.iter().filter_map(variant_code).collect();
    let mut landings = HashMap::new();
    for class in &unique {
        let landing = land(
            class,
            &mut item,
            overrides.get(&class.key.to_string()),
            &declared,
        )?;
        landings.insert(class.key.to_string(), landing);
    }

    let name = &item.ident;
    let mut impls = TokenStream::new();
    for def in &defs {
        let ty = &def.ty;
        let arms = def.classes.iter().map(|c| {
            let v = &c.variant;
            let build = &landings[&c.key.to_string()].build;
            quote!(#ty::#v(message) => #build)
        });
        impls.extend(quote! {
            #[automatically_derived]
            impl ::core::convert::From<#ty> for #name {
                fn from(fault: #ty) -> Self {
                    match fault { #(#arms,)* }
                }
            }
        });
        if !wire && !def.from.is_empty() {
            let source = &def.from;
            impls.extend(doxa_macro_support::tag(
                doxa_macro_support::Side::Server,
                quote! {
                    #[automatically_derived]
                    impl ::core::convert::From<#source> for #name {
                        fn from(error: #source) -> Self {
                            <#ty as ::core::convert::From<#source>>::from(error).into()
                        }
                    }
                },
            ));
        }
    }
    Ok(quote!(#item #impls))
}

/// Land `class` on the variant of its name or the override, injecting one when there's none.
fn land(
    class: &Class,
    item: &mut ItemEnum,
    requested: Option<&Ident>,
    declared: &HashSet<String>,
) -> syn::Result<Landing> {
    let target = requested.cloned().unwrap_or_else(|| class.variant.clone());
    let code = class.code.value();
    if let Some(existing) = item.variants.iter().find(|v| v.ident == target) {
        // A name match is a guess; take it only when the variant already answers this code.
        if requested.is_none() && variant_code(existing).as_deref() != Some(code.as_str()) {
            return Err(syn::Error::new_spanned(
                &existing.ident,
                format!(
                    "the `{}` class would land on `{target}`, which answers \"{}\", not \"{code}\"; \
                     say where it goes with `#[faults(…, {} = SomeVariant)]`",
                    class.key,
                    variant_code(existing).unwrap_or_else(|| "(none)".into()),
                    class.key,
                ),
            ));
        }
        return Ok(Landing {
            build: build_existing(&target, &existing.fields, class)?,
        });
    }
    if let Some(ident) = requested {
        return Err(syn::Error::new_spanned(
            ident,
            format!("`{ident}` is not a variant of `{}`", item.ident),
        ));
    }
    if declared.contains(&code) {
        return Err(syn::Error::new_spanned(
            &item.ident,
            format!(
                "`{}` already answers \"{code}\" under another name; say which variant the `{}` \
                 class lands on with `#[faults(…, {} = SomeVariant)]`",
                item.ident, class.key, class.key,
            ),
        ));
    }
    let has_internal = item.variants.iter().any(is_internal);
    item.variants.push(inject(class, !has_internal));
    Ok(Landing {
        build: quote!(Self::#target(message)),
    })
}

fn is_internal(variant: &Variant) -> bool {
    variant
        .attrs
        .iter()
        .filter(|a| a.path().is_ident("api"))
        .any(|a| {
            let mut found = false;
            let _ = a.parse_nested_meta(|meta| {
                found |= meta.path.is_ident("internal");
                if meta.input.peek(Token![=]) {
                    meta.value()?.parse::<syn::Expr>()?;
                }
                Ok(())
            });
            found
        })
}

fn build_existing(target: &Ident, fields: &Fields, class: &Class) -> syn::Result<TokenStream> {
    match fields {
        // A unit variant's message is its `#[error]`; the class's is dropped.
        Fields::Unit => Ok(quote!({ let _ = message; Self::#target })),
        Fields::Unnamed(f) if f.unnamed.len() == 1 => Ok(quote!(Self::#target(message.into()))),
        Fields::Named(f) if f.named.len() == 1 => {
            let field = f.named[0].ident.as_ref().expect("a named field");
            Ok(quote!(Self::#target { #field: message.into() }))
        }
        _ => Err(syn::Error::new_spanned(
            target,
            format!(
                "the `{}` class lands on `{target}`, which must hold one field for the message",
                class.key
            ),
        )),
    }
}

fn inject(class: &Class, may_be_internal: bool) -> Variant {
    let Class {
        docs,
        variant,
        status,
        code,
        outcome,
        redact,
        ..
    } = class;
    let outcome = outcome.as_ref().map(|o| quote!(, outcome = #o));
    if *redact {
        let internal =
            (may_be_internal && status.base10_digits() == "500").then(|| quote!(, internal));
        parse_quote! {
            #(#docs)*
            #[error("an internal error occurred")]
            #[api(status = #status, code = #code #outcome #internal)]
            #variant(#[serde(skip)] ::std::string::String)
        }
    } else {
        parse_quote! {
            #(#docs)*
            #[error("{0}")]
            #[api(status = #status, code = #code #outcome)]
            #variant(::std::string::String)
        }
    }
}

/// The code a variant answers with, as `#[derive(ApiError)]` defaults it.
fn variant_code(variant: &Variant) -> Option<String> {
    let attr = variant.attrs.iter().find(|a| a.path().is_ident("api"))?;
    let mut code = None;
    let _ = attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("code") {
            code = Some(meta.value()?.parse::<LitStr>()?.value());
        } else if meta.input.peek(Token![=]) {
            meta.value()?.parse::<syn::Expr>()?;
        }
        Ok(())
    });
    Some(code.unwrap_or_else(|| snake(&variant.ident.to_string())))
}

fn snake(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 4);
    for (i, c) in input.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            out.push('_');
        }
        out.extend(c.to_lowercase());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expanded(args: TokenStream, item: TokenStream) -> syn::Result<String> {
        attribute(args, item).map(|t| t.to_string().replace(' ', ""))
    }

    #[test]
    fn common_injects_the_four_it_lacks() {
        let out = expanded(
            quote!(common),
            quote!(
                enum E {}
            ),
        )
        .unwrap();
        for v in [
            "Validation(",
            "NotFound(",
            "Forbidden(",
            "Internal(#[serde(skip)]",
        ] {
            assert!(out.contains(v), "{v} missing: {out}");
        }
        assert!(out.contains(r#"outcome="denied""#), "{out}");
    }

    #[test]
    fn a_variant_of_the_name_and_code_is_kept() {
        let out = expanded(
            quote!(common),
            quote!(
                enum E {
                    #[api(status = 404, code = "not_found")]
                    NotFound(String),
                }
            ),
        )
        .unwrap();
        assert_eq!(out.matches("NotFound(").count(), 1, "{out}");
    }

    #[test]
    fn a_name_answering_another_code_is_refused() {
        let err = expanded(
            quote!(common),
            quote!(
                enum E {
                    #[api(status = 404, code = "missing")]
                    NotFound(String),
                }
            ),
        )
        .unwrap_err();
        assert!(err.to_string().contains("not_found"), "{err}");
    }

    #[test]
    fn an_override_lands_where_it_says() {
        let out = expanded(
            quote!(common, not_found = Missing),
            quote!(
                enum E {
                    #[api(status = 404, code = "missing")]
                    Missing(String),
                }
            ),
        )
        .unwrap();
        assert!(!out.contains("NotFound("), "{out}");
    }

    #[test]
    fn a_code_taken_under_another_name_is_refused() {
        let err = expanded(
            quote!(common),
            quote!(
                enum E {
                    #[api(status = 404, code = "not_found")]
                    Gone(String),
                }
            ),
        )
        .unwrap_err();
        assert!(err.to_string().contains("another name"), "{err}");
    }

    #[test]
    fn a_registered_set_goes_through_its_callback() {
        let out = attribute(
            quote!(common, my::Faults),
            quote!(
                enum E {}
            ),
        )
        .unwrap()
        .to_string()
        .replace(' ', "");
        assert!(
            out.starts_with("my::Faults!{collected:[]remaining:[]"),
            "{out}"
        );
    }

    #[test]
    fn a_set_s_definition_writes_its_conversions() {
        let out = chain_step(quote! {
            @def { ty: ::lake::Faults, from: [::lake::OpError], classes: [
                conflict: Contended = 409 "conflict"
            ] }
            collected: []
            remaining: []
            args: [common, ::lake::Faults]
            item: { enum E {} }
        })
        .unwrap()
        .to_string()
        .replace(' ', "");
        assert!(out.contains("Contended("), "{out}");
        assert!(out.contains("From<::lake::Faults>forE"), "{out}");
        assert!(out.contains("From<::lake::OpError>forE"), "{out}");
    }

    #[test]
    fn wire_writes_no_source_conversion() {
        let out = chain_step(quote! {
            @def { ty: ::lake::Faults, from: [::lake::OpError], classes: [
                conflict: Contended = 409 "conflict"
            ] }
            collected: []
            remaining: []
            args: [::lake::Faults, wire]
            item: { enum E {} }
        })
        .unwrap()
        .to_string()
        .replace(' ', "");
        assert!(!out.contains("OpError>forE"), "{out}");
    }
}
