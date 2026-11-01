//! Pretty-printer for rstml node trees, reading every leaf back from the original source text.

use std::cell::RefCell;
use std::collections::HashSet;
use std::ops::Range;

use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens;
use rstml::node::{
    KVAttributeValue, KeyedAttribute, KeyedAttributeValue, Node, NodeAttribute, NodeBlock,
    NodeElement, NodeName,
};
use rstml::{Parser, ParserConfig};
use syn::visit::Visit;

use crate::lex::comments;
use crate::Config;

type Res<T> = Result<T, String>;

/// Rendered text whose first line is relative to the caller's cursor; later lines carry
/// their own absolute indentation.
type Frag = Vec<String>;

const VOID_ELEMENTS: [&str; 14] = [
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

pub(crate) struct Printer<'a> {
    src: &'a str,
    cfg: &'a Config,
    warnings: RefCell<Vec<String>>,
}

struct Attr {
    is_key: bool,
    lead: Vec<String>,
    frag: Frag,
    trail: Vec<String>,
}

impl<'a> Printer<'a> {
    pub(crate) fn new(src: &'a str, cfg: &'a Config) -> Self {
        Printer {
            src,
            cfg,
            warnings: RefCell::new(Vec::new()),
        }
    }

    pub(crate) fn take_warnings(&self) -> Vec<String> {
        self.warnings.take()
    }

    pub(crate) fn warn(&self, mac: &syn::Macro, msg: String) {
        let line = first_span(mac.to_token_stream()).map_or(0, |s| s.start().line);
        self.warnings
            .borrow_mut()
            .push(format!("line {line}: view! left unformatted: {msg}"));
    }

    /// Formats one `view!` invocation, returning the source range it replaces.
    pub(crate) fn format_macro(
        &self,
        mac: &syn::Macro,
        base: Option<usize>,
    ) -> Res<(Range<usize>, String)> {
        let path = self.range_of(&mac.path)?;
        let group = mac.delimiter.span().join().byte_range();
        self.check_range(&group)?;
        let base = base.unwrap_or_else(|| self.line_indent(path.start));
        let inner = group.start + 1..group.end - 1;

        // A brace-delimited macro followed by `.`/`?` would parse as a statement.
        let postfix = self.src[group.end..].trim_start();
        let (open, close) = match mac.delimiter {
            syn::MacroDelimiter::Paren(_) if postfix.starts_with(['.', '?']) => ("(", ")"),
            syn::MacroDelimiter::Bracket(_) if postfix.starts_with(['.', '?']) => ("[", "]"),
            _ => (" {", "}"),
        };
        let mut out = format!("{}!{open}", squash(&self.src[path.clone()]));

        let nodes = parser()
            .parse_simple(mac.tokens.clone())
            .map_err(|e| format!("parse error: {e}"))?;
        let body = self.render_seq(&nodes, inner.clone(), base + self.cfg.tab_spaces)?;
        // One short line stays inline, as rustfmt keeps short expressions.
        let column = path.start - self.src[..path.start].rfind('\n').map_or(0, |n| n + 1);
        let inline = match body.as_slice() {
            [one] if open == " {" => Some(format!("{out} {} {close}", one.trim_start())),
            [one] => Some(format!("{out}{}{close}", one.trim_start())),
            _ => None,
        };
        if let Some(line) = inline.filter(|l| column + width(l) <= self.cfg.max_width) {
            out = line;
        } else if !body.is_empty() {
            out.push('\n');
            out.push_str(&body.join("\n"));
            out.push('\n');
            out.push_str(&spaces(base));
            out.push_str(close);
        } else {
            out.push_str(close);
        }

        let before = comments(&self.src[inner]).len();
        if comments(&out).len() != before {
            return Err("a comment could not be placed".into());
        }
        Ok((path.start..group.end, out))
    }

    fn render_seq(&self, nodes: &[Node], gap: Range<usize>, indent: usize) -> Res<Vec<String>> {
        let mut out = Vec::new();
        let mut pos = gap.start;
        for node in nodes {
            let r = self.range_of(node)?;
            self.emit_gap(pos..r.start, indent, &mut out, false)?;
            out.extend(self.render_node(node, indent)?);
            pos = r.end;
        }
        self.emit_gap(pos..gap.end, indent, &mut out, true)?;
        Ok(out)
    }

    /// Emits comments found between nodes; a comment on the same line as the previous
    /// node stays trailing. One blank line between nodes is kept.
    fn emit_gap(
        &self,
        gap: Range<usize>,
        indent: usize,
        out: &mut Vec<String>,
        at_end: bool,
    ) -> Res<()> {
        let text = &self.src[gap.clone()];
        let mut cursor = 0;
        for c in comments(text) {
            let ws = &text[cursor..c.range.start];
            if !ws.trim().is_empty() {
                return Err(format!("unexpected text `{}`", ws.trim()));
            }
            let mut lines = text[c.range.clone()].lines();
            let first = lines.next().unwrap_or_default();
            match out.last_mut() {
                Some(last) if !ws.contains('\n') => {
                    last.push(' ');
                    last.push_str(first);
                }
                _ => {
                    if !out.is_empty() && blank_line(ws) {
                        out.push(String::new());
                    }
                    out.push(format!("{}{first}", spaces(indent)));
                }
            }
            out.extend(lines.map(str::to_string));
            cursor = c.range.end;
        }
        let ws = &text[cursor..];
        if !ws.trim().is_empty() {
            return Err(format!("unexpected text `{}`", ws.trim()));
        }
        if !at_end && !out.is_empty() && blank_line(ws) {
            out.push(String::new());
        }
        Ok(())
    }

    /// Like [`Self::emit_gap`] but only collects comments, for the inside of tags.
    fn gap_comments(&self, gap: Range<usize>) -> Res<Vec<(bool, String)>> {
        let mut found = Vec::new();
        let text = &self.src[gap];
        let mut cursor = 0;
        for c in comments(text) {
            let ws = &text[cursor..c.range.start];
            if !ws.trim().is_empty() {
                return Err(format!("unexpected text `{}`", ws.trim()));
            }
            found.push((!ws.contains('\n'), text[c.range.clone()].to_string()));
            cursor = c.range.end;
        }
        if !text[cursor..].trim().is_empty() {
            return Err(format!("unexpected text `{}`", text[cursor..].trim()));
        }
        Ok(found)
    }

    fn render_node(&self, node: &Node, indent: usize) -> Res<Vec<String>> {
        let frag = match node {
            Node::Element(el) => return self.render_element(el, indent),
            Node::Fragment(f) => {
                let open = self.range_of(&f.tag_open)?;
                let close = f.tag_close.as_ref().map(|c| self.range_of(c)).transpose()?;
                self.no_comments(open.clone())?;
                if let Some(c) = &close {
                    self.no_comments(c.clone())?;
                }
                let body = open.end..close.map_or(open.end, |c| c.start);
                return self.render_children(
                    vec![format!("{}<>", spaces(indent))],
                    &f.children,
                    body,
                    "</>",
                    indent,
                );
            }
            Node::Comment(c) => {
                let r = self.range_of(&c.value)?;
                vec![format!("<!-- {} -->", &self.src[r])]
            }
            Node::Doctype(d) => vec![squash_spaces(&self.src[self.range_of(d)?])],
            Node::Text(t) => self.raw(self.range_of(t)?, indent),
            Node::RawText(t) => {
                let r = self.range_of(t)?;
                self.no_comments(r.clone())?;
                // Unquoted text may be read back from source, so its whitespace is kept verbatim.
                self.src[r].split('\n').map(str::to_string).collect()
            }
            Node::Block(NodeBlock::ValidBlock(b)) => self.braced(b, indent)?,
            _ => return Err("unsupported node".into()),
        };
        Ok(place(indent, "", frag))
    }

    fn render_element(
        &self,
        el: &NodeElement<rstml::Infallible>,
        indent: usize,
    ) -> Res<Vec<String>> {
        let tag = &el.open_tag;
        let lt = self.range_of(&tag.token_lt)?;
        let name_r = self.range_of(&tag.name)?;
        self.no_comments(lt.end..name_r.start)?;
        let mut name = self.name_text(&tag.name)?;
        let mut pos = name_r.end;
        if tag.generics.lt_token.is_some() {
            let g = self.range_of(&tag.generics)?;
            self.no_comments(pos..g.start)?;
            self.no_comments(g.clone())?;
            name.push_str(&squash_spaces(&self.src[g.clone()]));
            pos = g.end;
        }
        let end_r = self.range_of(&tag.end_tag)?;

        let inner = indent + self.cfg.tab_spaces;
        let mut attrs: Vec<Attr> = Vec::new();
        let mut lead = Vec::new();
        for attr in &tag.attributes {
            let r = self.range_of(attr)?;
            absorb(self.gap_comments(pos..r.start)?, &mut attrs, &mut lead);
            attrs.push(Attr {
                is_key: matches!(attr, NodeAttribute::Attribute(kv) if kv.key.to_string() == "key"),
                lead: std::mem::take(&mut lead),
                frag: self.render_attr(attr, inner)?,
                trail: Vec::new(),
            });
            pos = r.end;
        }
        absorb(self.gap_comments(pos..end_r.start)?, &mut attrs, &mut lead);
        let tail = lead;
        attrs.sort_by_key(|a| !a.is_key);

        let close_r = el
            .close_tag
            .as_ref()
            .map(|c| self.range_of(c))
            .transpose()?;
        if let Some(c) = &close_r {
            self.no_comments(c.clone())?;
        }
        let body = end_r.end..close_r.as_ref().map_or(end_r.end, |c| c.start);
        let self_close = el.children.is_empty() && comments(&self.src[body.clone()]).is_empty();
        let end = if self_close { "/>" } else { ">" };

        let has_comments = !tail.is_empty()
            || attrs
                .iter()
                .any(|a| !a.lead.is_empty() || !a.trail.is_empty());
        let mut one_line = format!("{}<{name}", spaces(indent));
        for a in &attrs {
            one_line.push(' ');
            one_line.push_str(&a.frag[0]);
        }
        one_line.push_str(end);
        let open = if !has_comments
            && attrs.iter().all(|a| a.frag.len() == 1)
            && width(&one_line) <= self.cfg.max_width
        {
            vec![one_line]
        } else {
            let mut lines = vec![format!("{}<{name}", spaces(indent))];
            for a in attrs {
                lines.extend(a.lead.iter().map(|c| format!("{}{c}", spaces(inner))));
                let mut placed = place(inner, "", a.frag);
                if let Some(last) = placed.last_mut() {
                    for t in &a.trail {
                        last.push(' ');
                        last.push_str(t);
                    }
                }
                lines.extend(placed);
            }
            lines.extend(tail.iter().map(|c| format!("{}{c}", spaces(inner))));
            lines.push(format!("{}{end}", spaces(indent)));
            lines
        };
        if self_close {
            return Ok(open);
        }
        self.render_children(open, &el.children, body, &format!("</{name}>"), indent)
    }

    fn render_children(
        &self,
        mut open: Vec<String>,
        children: &[Node],
        body: Range<usize>,
        close: &str,
        indent: usize,
    ) -> Res<Vec<String>> {
        if let ([child @ (Node::Text(_) | Node::Block(_) | Node::RawText(_))], [_]) =
            (children, open.as_slice())
        {
            let r = self.range_of(child)?;
            let quiet = comments(&self.src[body.start..r.start]).is_empty()
                && comments(&self.src[r.end..body.end]).is_empty();
            if quiet {
                let child = self.render_node(child, indent)?;
                if let [line] = child.as_slice() {
                    let candidate = format!("{}{}{close}", open[0], line.trim_start());
                    if width(&candidate) <= self.cfg.max_width {
                        return Ok(vec![candidate]);
                    }
                }
            }
        }
        open.extend(self.render_seq(children, body, indent + self.cfg.tab_spaces)?);
        open.push(format!("{}{close}", spaces(indent)));
        Ok(open)
    }

    fn render_attr(&self, attr: &NodeAttribute, indent: usize) -> Res<Frag> {
        let kv: &KeyedAttribute = match attr {
            NodeAttribute::Block(NodeBlock::ValidBlock(b)) => return self.braced(b, indent),
            NodeAttribute::Block(_) => return Err("invalid attribute block".into()),
            NodeAttribute::Attribute(kv) => kv,
        };
        let key = self.name_text(&kv.key)?;
        let key_end = self.range_of(&kv.key)?.end;
        match &kv.possible_value {
            KeyedAttributeValue::None => Ok(vec![key]),
            KeyedAttributeValue::Binding(b) => {
                let r = self.range_of(b)?;
                self.no_comments(key_end..r.end)?;
                Ok(vec![format!("{key}{}", squash_spaces(&self.src[r]))])
            }
            KeyedAttributeValue::Value(v) => {
                let (value_start, mut frag) = match &v.value {
                    KVAttributeValue::Expr(syn::Expr::Block(eb))
                        if eb.attrs.is_empty() && eb.label.is_none() =>
                    {
                        (
                            self.range_of(&eb.block)?.start,
                            self.braced(&eb.block, indent)?,
                        )
                    }
                    KVAttributeValue::Expr(e) => {
                        let r = self.range_of(e)?;
                        (r.start, self.raw(r, indent))
                    }
                    KVAttributeValue::InvalidBraced(_) => {
                        return Err("invalid attribute value".into())
                    }
                };
                self.no_comments(key_end..value_start)?;
                frag[0] = format!("{key}={}", frag[0]);
                Ok(frag)
            }
        }
    }

    /// Formats a `{ … }` block, through prettyplease when that loses nothing.
    fn braced(&self, block: &syn::Block, indent: usize) -> Res<Frag> {
        let r = self.range_of(block)?;
        if r.len() < 2
            || !self.src[r.clone()].starts_with('{')
            || !self.src[r.clone()].ends_with('}')
        {
            return Err("block without braces in source".into());
        }
        let inner = &self.src[r.start + 1..r.end - 1];
        let scan = Scan::of_block(block);
        if comments(inner).is_empty()
            && !scan.has_macro
            && self.multiline_literals(block).is_empty()
        {
            if let Some(frag) = self.pretty(block, indent) {
                return Ok(frag);
            }
        }

        let lead = inner.len() - inner.trim_start().len();
        let content = r.start + 1 + lead..r.end - 1 - (inner.len() - inner.trim_end().len());
        if content.is_empty() {
            return Ok(vec!["{}".into()]);
        }
        let block_style = inner[..lead].contains('\n');
        let target = if block_style {
            indent + self.cfg.tab_spaces
        } else {
            indent
        };
        let from = if block_style {
            self.line_indent(content.start)
        } else {
            self.line_indent(r.start)
        };
        let shift = target as isize - from as isize;
        let protected = self.multiline_literals(block);
        let text = self.reindent(content, shift, block_style, target, &protected, &scan.views);

        let ends_in_line_comment = comments(&text)
            .last()
            .is_some_and(|c| c.line && c.range.end == text.len());
        let mut s = String::from("{");
        if block_style {
            s.push('\n');
        }
        s.push_str(&text);
        if block_style || ends_in_line_comment {
            s.push('\n');
            s.push_str(&spaces(indent));
        }
        s.push('}');
        Ok(s.split('\n').map(str::to_string).collect())
    }

    fn pretty(&self, block: &syn::Block, indent: usize) -> Option<Frag> {
        if block.stmts.is_empty() {
            return Some(vec!["{}".into()]);
        }
        let file: syn::File = syn::parse_quote! { fn __doxa_fmt() #block };
        let printed = prettyplease::unparse(&file);
        let mut lines = printed.lines();
        if lines.next()? != "fn __doxa_fmt() {" {
            return None;
        }
        let mut body: Vec<String> = lines
            .map(|l| {
                let l = l.strip_prefix("    ").unwrap_or(l);
                let n = l.len() - l.trim_start_matches(' ').len();
                format!("{}{}", spaces(n / 4 * self.cfg.tab_spaces + n % 4), &l[n..])
            })
            .collect();
        if body.pop()? != "}" {
            return None;
        }
        let single_expr = matches!(block.stmts.as_slice(), [syn::Stmt::Expr(_, None)]);
        let pad = |n: usize, l: &String| {
            if l.is_empty() {
                String::new()
            } else {
                format!("{}{l}", spaces(n))
            }
        };
        if body.len() == 1 {
            Some(vec![format!("{{{}}}", body[0])])
        } else if single_expr {
            let mut frag = vec![format!("{{{}", body[0])];
            frag.extend(body[1..].iter().map(|l| pad(indent, l)));
            frag.last_mut()?.push('}');
            Some(frag)
        } else {
            let mut frag = vec!["{".to_string()];
            frag.extend(body.iter().map(|l| pad(indent + self.cfg.tab_spaces, l)));
            frag.push(format!("{}}}", spaces(indent)));
            Some(frag)
        }
    }

    /// Source text of a non-block expression or literal, with continuation lines re-indented.
    fn raw(&self, r: Range<usize>, indent: usize) -> Frag {
        let shift = indent as isize - self.line_indent(r.start) as isize;
        let tokens = self.src[r.clone()].parse::<TokenStream>().ok();
        let mut protected = Vec::new();
        if let Some(t) = tokens {
            collect_literals(t, &mut protected);
            let offset = r.start;
            for p in &mut protected {
                *p = p.start + offset..p.end + offset;
            }
        }
        let text = self.reindent(r, shift, false, indent, &protected, &[]);
        text.split('\n').map(str::to_string).collect()
    }

    /// Copies `range`, moving each line after the first by `shift` columns (the first too if
    /// `shift_first`), formatting nested `view!` calls in place.
    fn reindent(
        &self,
        range: Range<usize>,
        shift: isize,
        shift_first: bool,
        first_indent: usize,
        protected: &[Range<usize>],
        views: &[&syn::Macro],
    ) -> String {
        let mut nested = Vec::new();
        for mac in views {
            if let Ok(r) = self.range_of(&mac.path) {
                nested.push((r.start, *mac));
            }
        }
        let mut out = String::new();
        let mut line_indent = first_indent;
        if shift_first {
            out.push_str(&spaces(first_indent));
        }
        let mut i = range.start;
        while i < range.end {
            if let Some((_, mac)) = nested.iter().find(|(s, _)| *s == i) {
                match self.format_macro(mac, Some(line_indent)) {
                    Ok((r, text)) if r.end <= range.end => {
                        out.push_str(&text);
                        i = r.end;
                        continue;
                    }
                    Ok(_) => {}
                    Err(e) => self.warn(mac, e),
                }
            }
            let ch = self.src[i..].chars().next().unwrap_or('\n');
            i += ch.len_utf8();
            out.push(ch);
            if ch != '\n' || protected.iter().any(|p| p.start < i && i < p.end) {
                continue;
            }
            let rest = &self.src[i..range.end];
            let ws = rest.len() - rest.trim_start_matches([' ', '\t']).len();
            let orig = self.indent_width(&rest[..ws]);
            i += ws;
            if i < range.end && !self.src[i..].starts_with('\n') {
                line_indent = (orig as isize + shift).max(0) as usize;
                out.push_str(&spaces(line_indent));
            }
        }
        out
    }

    fn multiline_literals(&self, block: &syn::Block) -> Vec<Range<usize>> {
        let mut found = Vec::new();
        collect_literals(block.to_token_stream(), &mut found);
        found.retain(|r| self.src.get(r.clone()).is_some_and(|s| s.contains('\n')));
        found
    }

    fn name_text(&self, name: &NodeName) -> Res<String> {
        let r = self.range_of(name)?;
        self.no_comments(r.clone())?;
        let text = &self.src[r];
        Ok(if text.starts_with('{') {
            squash_spaces(text)
        } else {
            squash(text)
        })
    }

    fn no_comments(&self, r: Range<usize>) -> Res<()> {
        if comments(&self.src[r]).is_empty() {
            Ok(())
        } else {
            Err("comment inside a tag name or attribute is not supported".into())
        }
    }

    fn range_of(&self, t: &impl ToTokens) -> Res<Range<usize>> {
        let tokens = t.to_token_stream();
        let first = first_span(tokens.clone()).ok_or("empty node")?;
        let last = tokens.into_iter().last().ok_or("empty node")?.span();
        let r = first.byte_range().start..last.byte_range().end;
        self.check_range(&r)?;
        Ok(r)
    }

    fn check_range(&self, r: &Range<usize>) -> Res<()> {
        if r.start < r.end && r.end <= self.src.len() && self.src.is_char_boundary(r.start) {
            Ok(())
        } else {
            Err("token without a source location".into())
        }
    }

    fn line_indent(&self, pos: usize) -> usize {
        let start = self.src[..pos].rfind('\n').map_or(0, |n| n + 1);
        let line = &self.src[start..];
        self.indent_width(&line[..line.len() - line.trim_start_matches([' ', '\t']).len()])
    }

    fn indent_width(&self, ws: &str) -> usize {
        ws.chars()
            .map(|c| if c == '\t' { self.cfg.tab_spaces } else { 1 })
            .sum()
    }
}

fn parser() -> Parser<rstml::Infallible> {
    Parser::new(
        ParserConfig::new()
            .always_self_closed_elements(VOID_ELEMENTS.into_iter().collect::<HashSet<_>>()),
    )
}

#[derive(Default)]
struct Scan<'ast> {
    has_macro: bool,
    views: Vec<&'ast syn::Macro>,
}

impl<'ast> Scan<'ast> {
    fn of_block(block: &'ast syn::Block) -> Self {
        let mut scan = Scan::default();
        scan.visit_block(block);
        scan
    }
}

impl<'ast> Visit<'ast> for Scan<'ast> {
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.has_macro = true;
        if crate::is_view(mac) {
            self.views.push(mac);
        }
    }
}

fn collect_literals(tokens: TokenStream, out: &mut Vec<Range<usize>>) {
    for tt in tokens {
        match tt {
            TokenTree::Literal(l) => out.push(l.span().byte_range()),
            TokenTree::Group(g) => collect_literals(g.stream(), out),
            _ => {}
        }
    }
}

/// Files tag-internal comments: same-line ones trail the previous attribute, others lead the next.
fn absorb(found: Vec<(bool, String)>, attrs: &mut [Attr], lead: &mut Vec<String>) {
    for (same_line, text) in found {
        match attrs.last_mut() {
            Some(prev) if same_line && lead.is_empty() => prev.trail.push(text),
            _ => lead.push(text),
        }
    }
}

fn first_span(tokens: TokenStream) -> Option<proc_macro2::Span> {
    tokens.into_iter().next().map(|t| t.span())
}

fn place(indent: usize, prefix: &str, mut frag: Frag) -> Vec<String> {
    frag[0] = format!("{}{prefix}{}", spaces(indent), frag[0]);
    frag
}

fn blank_line(ws: &str) -> bool {
    ws.matches('\n').count() >= 2
}

fn spaces(n: usize) -> String {
    " ".repeat(n)
}

fn width(s: &str) -> usize {
    s.chars().count()
}

fn squash(s: &str) -> String {
    s.split_whitespace().collect()
}

fn squash_spaces(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}
