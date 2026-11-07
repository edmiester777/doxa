//! `view!`: HTML-like markup lowered to `doxa::ui` builder calls.

use std::collections::HashSet;

use proc_macro2::TokenStream;
use quote::{quote, quote_spanned, ToTokens};
use rstml::node::{KeyedAttribute, Node, NodeAttribute, NodeBlock, NodeElement, NodeName};
use rstml::{Parser, ParserConfig};
use syn::spanned::Spanned;
use syn::{Expr, Lit};

/// Elements that never have children; the formatter uses the same list.
pub(crate) const VOID_ELEMENTS: [&str; 14] = [
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

/// Attributes holding a URL, set through `SafeUrl` so `javascript:` can't slip in.
const URL_ATTRS: [&str; 6] = ["href", "src", "action", "formaction", "poster", "cite"];

pub(crate) fn expand(input: TokenStream) -> syn::Result<TokenStream> {
    let config = ParserConfig::new()
        .always_self_closed_elements(VOID_ELEMENTS.into_iter().collect::<HashSet<_>>());
    let nodes = Parser::new(config).parse_simple(input)?;
    let views = children(&nodes)?;
    Ok(match views.as_slice() {
        [one] => quote! { ::doxa::ui::IntoView::into_view(#one) },
        many => fragment(many),
    })
}

fn fragment(views: &[TokenStream]) -> TokenStream {
    quote! { ::doxa::ui::View::fragment([#(::doxa::ui::IntoView::into_view(#views)),*]) }
}

fn children(nodes: &[Node]) -> syn::Result<Vec<TokenStream>> {
    let mut out = Vec::new();
    for node in nodes {
        match node {
            Node::Element(e) => out.push(element(e)?),
            Node::Fragment(f) => out.push(fragment(&children(&f.children)?)),
            Node::Block(b) => out.push(block(b)?),
            Node::Text(t) => out.push(t.value.to_token_stream()),
            Node::RawText(t) => {
                let text = t.to_string_best();
                if !text.trim().is_empty() {
                    out.push(quote_spanned! { t.span() => #text });
                }
            }
            Node::Comment(_) | Node::Doctype(_) => {}
            Node::Custom(_) => {}
        }
    }
    Ok(out)
}

fn block(b: &NodeBlock) -> syn::Result<TokenStream> {
    match b {
        NodeBlock::ValidBlock(block) => Ok(unblock(block)),
        NodeBlock::Invalid(i) => Err(syn::Error::new(
            i.span(),
            "expected a Rust expression in `{…}`",
        )),
    }
}

/// `{expr}` without the braces, so `{&name}` stays a borrow instead of a block value.
fn unblock(block: &syn::Block) -> TokenStream {
    match block.stmts.as_slice() {
        [syn::Stmt::Expr(e, None)] => e.to_token_stream(),
        _ => block.to_token_stream(),
    }
}

fn is_component(name: &NodeName) -> bool {
    match name {
        NodeName::Path(p) => {
            p.path.segments.len() > 1
                || p.path.segments[0]
                    .ident
                    .to_string()
                    .starts_with(|c: char| c.is_ascii_uppercase())
        }
        _ => false,
    }
}

fn element(e: &NodeElement<rstml::Infallible>) -> syn::Result<TokenStream> {
    if is_component(e.name()) {
        return component(e);
    }
    let tag = e.name().to_string();
    let span = e.name().span();
    let mut out = quote_spanned! { span => ::doxa::ui::el(#tag) };
    let mut key = None;
    // `bind:group` needs the radio's own `value`, wherever it is written.
    let radio_value = e.attributes().iter().find_map(|attr| {
        let a = keyed(attr).ok()?;
        (a.key.to_string() == "value").then(|| value(a)).flatten()
    });
    let mut spreads = Vec::new();
    for attr in e.attributes() {
        if let NodeAttribute::Block(b) = attr {
            spreads.push(spread(b)?);
            continue;
        }
        let a = keyed(attr)?;
        let name = a.key.to_string();
        let value = value(a);
        let span = a.key.span();
        out = match (name.as_str(), value) {
            ("key", Some(v)) => {
                key = Some(v);
                out
            }
            ("inner_html", Some(v)) => quote_spanned! { span => #out.inner_html(#v) },
            ("ref", Some(v)) => quote_spanned! { span => #out.node_ref(#v) },
            (n, Some(v)) if n.starts_with("on:") => {
                let (event, opts) = listen(n, span)?;
                let method = match (is_async_closure(a), opts.is_some()) {
                    (true, false) => quote!(on_async),
                    (false, false) => quote!(on),
                    (true, true) => quote!(on_async_with),
                    (false, true) => quote!(on_with),
                };
                let opts = opts.map(|o| quote!(#o,));
                let v = handler(a, v);
                quote_spanned! { span => #out.#method(#event, #opts #v) }
            }
            (n, v) if n.starts_with("use:") => {
                let Ok(name) = syn::parse_str::<syn::Path>(&n[4..]) else {
                    return Err(syn::Error::new(
                        span,
                        "`use:` names a function returning a `Directive`, e.g. `use:exit={\"fade\"}`",
                    ));
                };
                let name = quote_spanned! { span => #name };
                let args = v.into_iter();
                quote_spanned! { span => #out.directive(#name(#(#args)*)) }
            }
            (n, v) if n.starts_with("class:") => {
                let class = class_name(n, span)?;
                let v = v.unwrap_or_else(|| quote!(true));
                quote_spanned! { span => #out.class_toggle(#class, #v) }
            }
            (n, Some(v)) if n.starts_with("prop:") => {
                let prop = &n[5..];
                quote_spanned! { span => #out.prop(#prop, #v) }
            }
            ("bind:value", Some(v)) => quote_spanned! { span => #out.bind_value(#v) },
            ("bind:checked", Some(v)) => quote_spanned! { span => #out.bind_checked(#v) },
            ("bind:selected", Some(v)) => quote_spanned! { span => #out.bind_selected(#v) },
            ("bind:group", Some(v)) => {
                let Some(value) = radio_value.clone() else {
                    return Err(syn::Error::new(
                        span,
                        "`bind:group` goes on a radio button with a `value`, e.g. `<input type=\"radio\" value=\"a\" bind:group={kind}/>`",
                    ));
                };
                quote_spanned! { span => #out.bind_group(#v, #value) }
            }
            (n, _) if n.starts_with("bind:") => {
                return Err(syn::Error::new(
                    span,
                    "`bind:` takes `value`, `checked`, `group` or `selected`, with a `State` or a form field",
                ));
            }
            (n, Some(v)) if URL_ATTRS.contains(&n) => {
                let url = url(a, v)?;
                quote_spanned! { span => #out.url(#n, #url) }
            }
            (n, Some(v)) => quote_spanned! { span => #out.attr(#n, #v) },
            (n, None) => quote_spanned! { span => #out.attr(#n, true) },
        };
    }
    // Last, so an attribute the element sets itself is already there to win.
    for s in spreads {
        out = quote! { #out.spread(#s) };
    }
    for child in children(&e.children)? {
        out = quote! { #out.child(#child) };
    }
    if let Some(k) = key {
        out = quote! { #out.key(#k) };
    }
    Ok(out)
}

fn component(e: &NodeElement<rstml::Infallible>) -> syn::Result<TokenStream> {
    let NodeName::Path(path) = e.name() else {
        unreachable!()
    };
    let is_can = path.path.segments.last().is_some_and(|s| s.ident == "Can");
    let mut out = quote_spanned! { path.span() => #path::props() };
    let (mut key, mut route, mut args, mut cap) = (None, None, None, None);
    for attr in e.attributes() {
        if let NodeAttribute::Block(b) = attr {
            let s = spread(b)?;
            out = quote! { #out.__spread(#s) };
            continue;
        }
        let a = keyed(attr)?;
        let name = a.key.to_string();
        let span = a.key.span();
        let v = value(a);
        match (name.as_str(), v) {
            ("key", Some(v)) => key = Some(v),
            ("route", Some(v)) if is_can => route = Some(v),
            ("cap", Some(v)) if is_can => cap = Some(v),
            ("args", Some(_)) if is_can => args = expr(a).cloned(),
            // An `#[attrs]` prop collects these; a component without one refuses them.
            (n, Some(v)) if n.starts_with("on:") => {
                let (event, opts) = listen(n, span)?;
                let opts = opts.unwrap_or_else(|| quote!(::core::default::Default::default()));
                let method = if is_async_closure(a) {
                    quote!(__on_async)
                } else {
                    quote!(__on)
                };
                let v = handler(a, v);
                out = quote_spanned! { span => #out.#method(#event, #opts, #v) };
            }
            (n, v) if n.starts_with("use:") => {
                let Ok(name) = syn::parse_str::<syn::Path>(&n[4..]) else {
                    return Err(syn::Error::new(
                        span,
                        "`use:` names a function returning a `Directive`, e.g. `use:exit={\"fade\"}`",
                    ));
                };
                let name = quote_spanned! { span => #name };
                let args = v.into_iter();
                out = quote_spanned! { span => #out.__directive(#name(#(#args)*)) };
            }
            (n, v) if n.starts_with("class:") => {
                let class = class_name(n, span)?;
                let v = v.unwrap_or_else(|| quote!(true));
                out = quote_spanned! { span => #out.__class(#class, #v) };
            }
            (n, v) if n.starts_with("aria-") || n.starts_with("data-") => {
                let v = v.unwrap_or_else(|| quote!(true));
                out = quote_spanned! { span => #out.__attr(#n, #v) };
            }
            (n, v) => {
                let n = n.replace('-', "_");
                if is_none(a) {
                    let none = quote::format_ident!("__none_{}", n, span = span);
                    out = quote_spanned! { span => #out.#none() };
                    continue;
                }
                if let (Some(closure), Some(v)) = (literal_closure(a), &v) {
                    let prefix = match (closure.asyncness.is_some(), closure.inputs.is_empty()) {
                        (true, true) => "afn0",
                        (true, false) => "afn",
                        (false, true) => "fn0",
                        (false, false) => "fn",
                    };
                    let setter = quote::format_ident!("__{}_{}", prefix, n, span = span);
                    out = quote_spanned! { span => #out.#setter(#v) };
                    continue;
                }
                let ident = syn::parse_str::<syn::Ident>(&n)
                    .map(|i| syn::Ident::new(&i.to_string(), span))
                    .unwrap_or_else(|_| syn::Ident::new_raw(&n, span));
                let v = match v {
                    Some(v) if URL_ATTRS.contains(&n.as_str()) => url(a, v)?,
                    Some(v) => v,
                    None => quote!(true),
                };
                out = quote_spanned! { span => #out.#ident(#v) };
            }
        }
    }
    if let (true, Some(cap)) = (is_can, &cap) {
        if route.is_some() {
            return Err(syn::Error::new(
                path.span(),
                "`<Can>` asks a route or a capability: drop `route` or `cap`",
            ));
        }
        out = quote! { #out.probe(::doxa::client::Probe::capability(#cap)) };
    } else if is_can {
        let Some(route) = route else {
            return Err(syn::Error::new(
                path.span(),
                "`<Can>` needs `route={the_route_fn}` or `cap={a_capability}`",
            ));
        };
        let args = match args {
            Some(Expr::Tuple(t)) => t.elems.iter().map(ToTokens::to_token_stream).collect(),
            Some(e) => vec![e.to_token_stream()],
            None => vec![],
        };
        out = quote! { #out.probe(#route::can(#(#args),*)) };
    }
    let kids = children(&e.children)?;
    if !kids.is_empty() {
        let kids = fragment(&kids);
        out = quote! { #out.children(#kids) };
    }
    let key = key.map(|k| quote!(.key(#k)));
    Ok(quote_spanned! { path.span() => {
        #[allow(unused_imports)]
        use ::doxa::ui::__private::RestAttrs as _;
        ::doxa::ui::__private::comp_for(#out.build()) #key
    } })
}

fn keyed(attr: &NodeAttribute) -> syn::Result<&KeyedAttribute> {
    match attr {
        NodeAttribute::Attribute(a) => Ok(a),
        NodeAttribute::Block(b) => Err(syn::Error::new(
            b.span(),
            "a `{…}` attribute spreads `Attrs`: `{..rest}`",
        )),
    }
}

/// `{..rest}`: the `Attrs` expression it spreads.
fn spread(b: &NodeBlock) -> syn::Result<TokenStream> {
    let refuse = || syn::Error::new(b.span(), "a `{…}` attribute spreads `Attrs`: `{..rest}`");
    let NodeBlock::ValidBlock(block) = b else {
        return Err(refuse());
    };
    match block.stmts.as_slice() {
        [syn::Stmt::Expr(Expr::Range(r), None)]
            if r.start.is_none() && matches!(r.limits, syn::RangeLimits::HalfOpen(_)) =>
        {
            r.end
                .as_ref()
                .map(|e| e.to_token_stream())
                .ok_or_else(refuse)
        }
        _ => Err(refuse()),
    }
}

/// `class:is-active` as the class it toggles.
fn class_name(name: &str, span: proc_macro2::Span) -> syn::Result<String> {
    let class = &name["class:".len()..];
    if class.is_empty() || class.contains(char::is_whitespace) {
        return Err(syn::Error::new(
            span,
            "`class:` names one class: `class:active={is_active}`",
        ));
    }
    Ok(class.to_owned())
}

/// `on:scroll.passive` as its event name and, with modifiers, its `Listen`.
fn listen(name: &str, span: proc_macro2::Span) -> syn::Result<(String, Option<TokenStream>)> {
    let mut parts = name[3..].split('.');
    let event = parts.next().unwrap_or_default().to_owned();
    let (mut capture, mut passive, mut once) = (false, false, false);
    for m in parts {
        match m {
            "capture" => capture = true,
            "passive" => passive = true,
            "once" => once = true,
            _ => {
                return Err(syn::Error::new(
                    span,
                    format!("unknown `on:` modifier `{m}`: use `capture`, `passive` or `once`"),
                ))
            }
        }
    }
    let opts = (capture || passive || once).then(|| {
        quote! { ::doxa::ui::Listen { capture: #capture, passive: #passive, once: #once } }
    });
    Ok((event, opts))
}

/// An attribute's expression, looking through `{…}` around a single expression.
fn expr(a: &KeyedAttribute) -> Option<&Expr> {
    let mut e = a.value()?;
    while let Expr::Block(b) = e {
        match b.block.stmts.as_slice() {
            [syn::Stmt::Expr(inner, None)] if b.attrs.is_empty() && b.label.is_none() => e = inner,
            _ => break,
        }
    }
    Some(e)
}

fn value(a: &KeyedAttribute) -> Option<TokenStream> {
    let e = expr(a)?;
    // `{view! { … }}` is a block holding a macro statement; unwrap it too, or `unused_braces` fires.
    if let Expr::Block(b) = e {
        if let [syn::Stmt::Macro(m)] = b.block.stmts.as_slice() {
            if m.semi_token.is_none() && m.attrs.is_empty() && b.attrs.is_empty() {
                return Some(m.mac.to_token_stream());
            }
        }
    }
    Some(e.to_token_stream())
}

fn is_async_closure(a: &KeyedAttribute) -> bool {
    matches!(expr(a), Some(Expr::Closure(c)) if c.asyncness.is_some())
}

/// A handler's tokens; `on:click={move || …}` ignores its event.
fn handler(a: &KeyedAttribute, v: TokenStream) -> TokenStream {
    match expr(a) {
        Some(Expr::Closure(c)) if c.inputs.is_empty() => {
            let mut c = c.clone();
            c.inputs.push(syn::parse_quote!(_));
            c.to_token_stream()
        }
        _ => v,
    }
}

/// The closure an attribute evaluates to, including `{ let x = …; move |y| … }`.
fn literal_closure(a: &KeyedAttribute) -> Option<&syn::ExprClosure> {
    let mut e = expr(a)?;
    loop {
        match e {
            Expr::Closure(c) => return Some(c),
            Expr::Block(b) => match b.block.stmts.last() {
                Some(syn::Stmt::Expr(tail, None)) => e = tail,
                _ => return None,
            },
            _ => return None,
        }
    }
}

/// `prop={None}`, which no conversion could infer a type for.
fn is_none(a: &KeyedAttribute) -> bool {
    matches!(expr(a), Some(Expr::Path(p)) if p.qself.is_none() && p.path.is_ident("None"))
}

/// A literal URL is checked here; anything else must already be a `SafeUrl`.
fn url(a: &KeyedAttribute, v: TokenStream) -> syn::Result<TokenStream> {
    let lit = match expr(a) {
        Some(Expr::Lit(l)) => Some(l),
        _ => None,
    };
    match lit.map(|l| &l.lit) {
        Some(Lit::Str(s)) => {
            let squeezed: String = s
                .value()
                .chars()
                .filter(|c| !c.is_whitespace() && !c.is_control())
                .collect();
            let squeezed = squeezed.to_ascii_lowercase();
            if let Some(scheme) = ["javascript:", "vbscript:", "data:"]
                .iter()
                .find(|p| squeezed.starts_with(*p))
            {
                return Err(syn::Error::new(
                    s.span(),
                    format!("`{scheme}` URLs can run script; they aren't allowed"),
                ));
            }
            Ok(quote_spanned! { s.span() => ::doxa::ui::SafeUrl::literal(#s) })
        }
        _ => Ok(v),
    }
}
