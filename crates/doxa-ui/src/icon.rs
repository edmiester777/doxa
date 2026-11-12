//! Icon enums. `#[icons]` compiles SVG files into `view!` nodes; `#[react(module = …)]` on an
//! enum renders each variant as a React island. Both take [`IconProps`].

use serde::Serialize;

use crate::view::{el, Element, IntoView, View};

/// Size, stroke, colour and class for one icon; React receives it as props.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IconProps {
    /// Width and height, in pixels.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stroke_width: Option<f32>,
    /// A CSS colour, which `currentColor` strokes and fills follow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    /// Added to the icon's own class.
    #[serde(rename = "className", skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
}

/// An enum of icons, implemented by `#[icons]` and by `#[react]` on an enum.
pub trait IconSet: Copy + 'static {
    /// What one icon is given.
    type Props: Clone + Default + 'static;
    fn render(self, props: Self::Props) -> View;
}

/// Props whose size, stroke, colour and class `.size(…)` and the rest set.
pub trait IconStyle {
    fn style(&mut self) -> &mut IconProps;
}

impl IconStyle for IconProps {
    fn style(&mut self) -> &mut IconProps {
        self
    }
}

/// One icon and its props: `Lucide::Plus.size(16).class("muted")`.
#[derive(Clone)]
pub struct Icon<S: IconSet> {
    pub name: S,
    pub props: S::Props,
}

impl<S: IconSet> Icon<S> {
    pub fn new(name: S) -> Self {
        Icon {
            name,
            props: S::Props::default(),
        }
    }

    /// Replace every prop.
    pub fn props(mut self, props: S::Props) -> Self {
        self.props = props;
        self
    }
}

impl<S: IconSet> Icon<S>
where
    S::Props: IconStyle,
{
    pub fn size(mut self, px: u32) -> Self {
        self.props.style().size = Some(px);
        self
    }

    pub fn stroke_width(mut self, width: f32) -> Self {
        self.props.style().stroke_width = Some(width);
        self
    }

    pub fn color(mut self, color: impl Into<String>) -> Self {
        self.props.style().color = Some(color.into());
        self
    }

    pub fn class(mut self, class: impl Into<String>) -> Self {
        self.props.style().class = Some(class.into());
        self
    }
}

impl<S: IconSet> IntoView for Icon<S> {
    fn into_view(self) -> View {
        self.name.render(self.props)
    }
}

/// `.size(…)` and the rest on a variant itself.
pub trait IconExt: IconSet {
    fn props(self, props: Self::Props) -> Icon<Self> {
        Icon::new(self).props(props)
    }

    fn size(self, px: u32) -> Icon<Self>
    where
        Self::Props: IconStyle,
    {
        Icon::new(self).size(px)
    }

    fn stroke_width(self, width: f32) -> Icon<Self>
    where
        Self::Props: IconStyle,
    {
        Icon::new(self).stroke_width(width)
    }

    fn color(self, color: impl Into<String>) -> Icon<Self>
    where
        Self::Props: IconStyle,
    {
        Icon::new(self).color(color)
    }

    fn class(self, class: impl Into<String>) -> Icon<Self>
    where
        Self::Props: IconStyle,
    {
        Icon::new(self).class(class)
    }
}

impl<S: IconSet> IconExt for S {}

/// An element in the SVG namespace, whatever its tag.
#[doc(hidden)]
pub fn svg_el(tag: &'static str) -> Element {
    let mut e = el(tag);
    e.ns = Some("http://www.w3.org/2000/svg");
    e
}

/// The `<svg>` root of an `#[icons]` variant: its own attributes, then `props` over them.
#[doc(hidden)]
pub fn svg_root(
    attrs: &'static [(&'static str, &'static str)],
    body: View,
    props: &IconProps,
) -> View {
    let mut root = svg_el("svg");
    let size = props.size.map(|s| s.to_string());
    let stroke = props.stroke_width.map(|w| w.to_string());
    for &(name, value) in attrs {
        let value = match name {
            "width" | "height" => size.as_deref().unwrap_or(value),
            "stroke-width" => stroke.as_deref().unwrap_or(value),
            "class" => continue,
            _ => value,
        };
        root = root.attr(name, value);
    }
    let has = |n: &str| attrs.iter().any(|(a, _)| *a == n);
    if let Some(size) = size.as_deref().filter(|_| !has("width")) {
        root = root.attr("width", size).attr("height", size);
    }
    if let Some(stroke) = stroke.as_deref().filter(|_| !has("stroke-width")) {
        root = root.attr("stroke-width", stroke);
    }
    let own = attrs.iter().find(|(a, _)| *a == "class").map(|(_, v)| *v);
    let class = [own, props.class.as_deref()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    if !class.is_empty() {
        root = root.attr("class", class);
    }
    if let Some(color) = &props.color {
        root = root.attr("style", format!("color: {color}"));
    }
    root.child(body).into_view()
}
