//! ARIA roles and accessible names over a `MemDom`: the explicit `role`, or the implicit one
//! for common tags; the name from `aria-labelledby`, `aria-label`, a `<label>`, or text.

use crate::dom::{MemDom, NodeId, Peek};

/// What an element is to assistive technology.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Alert,
    Article,
    Banner,
    Button,
    Cell,
    Checkbox,
    ColumnHeader,
    Combobox,
    Complementary,
    ContentInfo,
    Dialog,
    Form,
    Group,
    Heading,
    Img,
    Link,
    List,
    Listbox,
    ListItem,
    Main,
    Menu,
    MenuItem,
    Navigation,
    Option,
    ProgressBar,
    Radio,
    Region,
    Row,
    Searchbox,
    Separator,
    Slider,
    SpinButton,
    Status,
    Switch,
    Tab,
    Table,
    TabList,
    TabPanel,
    Textbox,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        use Role::*;
        match self {
            Alert => "alert",
            Article => "article",
            Banner => "banner",
            Button => "button",
            Cell => "cell",
            Checkbox => "checkbox",
            ColumnHeader => "columnheader",
            Combobox => "combobox",
            Complementary => "complementary",
            ContentInfo => "contentinfo",
            Dialog => "dialog",
            Form => "form",
            Group => "group",
            Heading => "heading",
            Img => "img",
            Link => "link",
            List => "list",
            Listbox => "listbox",
            ListItem => "listitem",
            Main => "main",
            Menu => "menu",
            MenuItem => "menuitem",
            Navigation => "navigation",
            Option => "option",
            ProgressBar => "progressbar",
            Radio => "radio",
            Region => "region",
            Row => "row",
            Searchbox => "searchbox",
            Separator => "separator",
            Slider => "slider",
            SpinButton => "spinbutton",
            Status => "status",
            Switch => "switch",
            Tab => "tab",
            Table => "table",
            TabList => "tablist",
            TabPanel => "tabpanel",
            Textbox => "textbox",
        }
    }

    /// Roles whose name comes from their content when nothing labels them.
    fn named_by_content(role: &str) -> bool {
        matches!(
            role,
            "button"
                | "cell"
                | "checkbox"
                | "columnheader"
                | "heading"
                | "link"
                | "menuitem"
                | "option"
                | "radio"
                | "row"
                | "switch"
                | "tab"
        )
    }
}

/// `node`'s role: its own `role`, else the one its tag implies.
pub(crate) fn role_of(dom: &MemDom, node: NodeId) -> Option<String> {
    if let Some(r) = dom.attr(node, "role") {
        return r.split_whitespace().next().map(str::to_owned);
    }
    let Peek::Element(tag) = dom.peek(node) else {
        return None;
    };
    let attr = |n: &str| dom.attr(node, n);
    let role = match tag.as_str() {
        "a" | "area" if attr("href").is_some() => "link",
        "button" | "summary" => "button",
        "input" => match attr("type")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "button" | "submit" | "reset" | "image" => "button",
            "checkbox" => "checkbox",
            "radio" => "radio",
            "range" => "slider",
            "number" => "spinbutton",
            "search" => "searchbox",
            "hidden" => return None,
            _ => "textbox",
        },
        "textarea" => "textbox",
        "select" if attr("multiple").is_some() => "listbox",
        "select" => "combobox",
        "option" => "option",
        "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => "heading",
        "ul" | "ol" | "menu" => "list",
        "li" => "listitem",
        "nav" => "navigation",
        "main" => "main",
        "header" => "banner",
        "footer" => "contentinfo",
        "aside" => "complementary",
        "form" => "form",
        "dialog" => "dialog",
        "article" => "article",
        "section" if name_from_labels(dom, node).is_some() => "region",
        "table" => "table",
        "tr" => "row",
        "td" => "cell",
        "th" => "columnheader",
        "img" if attr("alt").as_deref() == Some("") => return None,
        "img" => "img",
        "progress" => "progressbar",
        "hr" => "separator",
        "fieldset" | "details" => "group",
        "output" => "status",
        _ => return None,
    };
    Some(role.to_owned())
}

/// `node`'s accessible name, whitespace collapsed.
pub(crate) fn name_of(dom: &MemDom, node: NodeId) -> String {
    if let Some(n) = name_from_labels(dom, node) {
        return n;
    }
    let attr = |n: &str| dom.attr(node, n);
    if let Peek::Element(tag) = dom.peek(node) {
        match tag.as_str() {
            "img" | "area" => {
                if let Some(alt) = attr("alt") {
                    return squash(&alt);
                }
            }
            "input" => {
                let ty = attr("type").unwrap_or_default();
                if matches!(ty.as_str(), "button" | "submit" | "reset") {
                    return squash(&attr("value").unwrap_or_else(|| match ty.as_str() {
                        "submit" => "Submit".into(),
                        "reset" => "Reset".into(),
                        _ => String::new(),
                    }));
                }
            }
            _ => {}
        }
    }
    if role_of(dom, node).is_some_and(|r| Role::named_by_content(&r)) {
        return squash(&dom.text(node));
    }
    attr("title").map(|t| squash(&t)).unwrap_or_default()
}

/// A name from `aria-labelledby`, `aria-label`, or a `<label>` for a form control.
fn name_from_labels(dom: &MemDom, node: NodeId) -> Option<String> {
    if let Some(ids) = dom.attr(node, "aria-labelledby") {
        let text: Vec<String> = ids
            .split_whitespace()
            .filter_map(|id| dom.find("id", id))
            .map(|n| dom.text(n))
            .collect();
        if !text.is_empty() {
            return Some(squash(&text.join(" ")));
        }
    }
    if let Some(l) = dom
        .attr(node, "aria-label")
        .filter(|l| !l.trim().is_empty())
    {
        return Some(squash(&l));
    }
    labels_of(dom, node).map(|l| squash(&dom.text(l)))
}

/// The `<label>` naming a form control: `for` its id, or wrapped around it.
pub(crate) fn labels_of(dom: &MemDom, node: NodeId) -> Option<NodeId> {
    let Peek::Element(tag) = dom.peek(node) else {
        return None;
    };
    if !matches!(
        tag.as_str(),
        "input" | "textarea" | "select" | "button" | "meter" | "progress" | "output"
    ) {
        return None;
    }
    if let Some(id) = dom.attr(node, "id") {
        if let Some(l) = elements(dom).into_iter().find(|&l| {
            matches!(dom.peek(l), Peek::Element(t) if t == "label")
                && dom.attr(l, "for").as_deref() == Some(id.as_str())
        }) {
            return Some(l);
        }
    }
    elements(dom).into_iter().find(|&l| {
        matches!(dom.peek(l), Peek::Element(t) if t == "label") && contains(dom, l, node)
    })
}

fn contains(dom: &MemDom, at: NodeId, node: NodeId) -> bool {
    dom.children(at)
        .into_iter()
        .any(|c| c == node || contains(dom, c, node))
}

/// Every element in document order, leaving out `hidden` and `aria-hidden` subtrees.
pub(crate) fn elements(dom: &MemDom) -> Vec<NodeId> {
    fn walk(dom: &MemDom, at: NodeId, out: &mut Vec<NodeId>) {
        for c in dom.children(at) {
            if !matches!(dom.peek(c), Peek::Element(_)) {
                continue;
            }
            if dom.attr(c, "hidden").is_some()
                || dom.attr(c, "aria-hidden").as_deref() == Some("true")
            {
                continue;
            }
            out.push(c);
            walk(dom, c, out);
        }
    }
    let mut out = Vec::new();
    walk(dom, dom.body(), &mut out);
    out
}

/// The text of `node`'s own text children, not its descendants'.
pub(crate) fn own_text(dom: &MemDom, node: NodeId) -> String {
    let text: String = dom
        .children(node)
        .into_iter()
        .filter_map(|c| match dom.peek(c) {
            Peek::Text(t) => Some(t),
            _ => None,
        })
        .collect();
    squash(&text)
}

fn squash(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}
