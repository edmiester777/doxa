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
    for attr in e.attributes() {
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
            (n, Some(v)) if n.starts_with("on:") => {
                let event = &n[3..];
                let method = if is_async_closure(a) {
                    quote!(on_async)
                } else {
                    quote!(on)
                };
                quote_spanned! { span => #out.#method(#event, #v) }
            }
            (n, Some(v)) if n.starts_with("prop:") => {
                let prop = &n[5..];
                quote_spanned! { span => #out.prop(#prop, #v) }
            }
            ("bind:value", Some(v)) => quote_spanned! { span =>
                #out.prop("value", ::doxa::ui::State::get(&#v))
                    .on("input", { let s = #v; move |e: ::doxa::ui::Event| s.set(e.value()) })
            },
            ("bind:checked", Some(v)) => quote_spanned! { span =>
                #out.prop("checked", ::doxa::ui::State::get(&#v))
                    .on("change", { let s = #v; move |e: ::doxa::ui::Event| s.set(e.checked()) })
            },
            (n, _) if n.starts_with("bind:") => {
                return Err(syn::Error::new(
                    span,
                    "`bind:` takes `value` or `checked`, with a `State`",
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
    let is_can = path.path.is_ident("Can");
    let mut out = quote_spanned! { path.span() => #path::props() };
    let (mut key, mut route, mut args) = (None, None, None);
    for attr in e.attributes() {
        let a = keyed(attr)?;
        let name = a.key.to_string();
        let v = value(a);
        match (name.as_str(), v) {
            ("key", Some(v)) => key = Some(v),
            ("route", Some(v)) if is_can => route = Some(v),
            ("args", Some(_)) if is_can => args = expr(a).cloned(),
            (n, v) => {
                let ident = syn::Ident::new(&n.replace('-', "_"), a.key.span());
                let v = v.unwrap_or_else(|| quote!(true));
                out = quote_spanned! { a.key.span() => #out.#ident(#v) };
            }
        }
    }
    if is_can {
        let Some(route) = route else {
            return Err(syn::Error::new(
                path.span(),
                "`<Can>` needs `route={the_route_fn}`",
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
    let mut view = quote_spanned! { path.span() => ::doxa::ui::comp::<#path>(#out.build()) };
    if let Some(k) = key {
        view = quote! { #view.key(#k) };
    }
    Ok(view)
}

fn keyed(attr: &NodeAttribute) -> syn::Result<&KeyedAttribute> {
    match attr {
        NodeAttribute::Attribute(a) => Ok(a),
        NodeAttribute::Block(b) => Err(syn::Error::new(
            b.span(),
            "spread attributes aren't supported; name each one",
        )),
    }
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
    expr(a).map(ToTokens::to_token_stream)
}

fn is_async_closure(a: &KeyedAttribute) -> bool {
    matches!(expr(a), Some(Expr::Closure(c)) if c.asyncness.is_some())
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
