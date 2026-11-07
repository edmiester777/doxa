//! `#[attrs] rest: Attrs`: the attributes, `on:` handlers and `use:` directives a component's
//! tag carries that aren't its props, spread onto one element with `{..rest}`.

use std::rc::Rc;

use crate::directive::{Directive, Proto};
use crate::dom::{Event, Listen};
use crate::view::{async_handler, Element, Handler, IntoAttr};

/// What a tag passed that its component doesn't declare.
#[derive(Clone, Default)]
pub struct Attrs {
    attrs: Vec<(&'static str, Option<String>)>,
    classes: Vec<(&'static str, bool)>,
    events: Vec<(&'static str, Listen, Handler)>,
    directives: Vec<Rc<dyn Proto>>,
}

impl Attrs {
    /// The `class` given, for merging into the element's own; `{..rest}` never overrides it.
    pub fn class(&self) -> Option<&str> {
        self.get("class")
    }

    /// An attribute's value; `None` when it's absent or was given `false`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .rev()
            .find(|(n, _)| *n == name)
            .and_then(|(_, v)| v.as_deref())
    }

    pub fn is_empty(&self) -> bool {
        self.attrs.is_empty()
            && self.classes.is_empty()
            && self.events.is_empty()
            && self.directives.is_empty()
    }

    fn set(&mut self, name: &'static str, value: impl IntoAttr) {
        self.attrs.retain(|(n, _)| *n != name);
        self.attrs.push((name, value.into_attr()));
    }

    fn extend(&mut self, other: Attrs) {
        for (n, v) in other.attrs {
            self.attrs.retain(|(m, _)| *m != n);
            self.attrs.push((n, v));
        }
        self.classes.extend(other.classes);
        self.events.extend(other.events);
        self.directives.extend(other.directives);
    }
}

impl Element {
    /// `{..rest}`: every attribute the element doesn't set itself, and every handler and directive.
    pub fn spread(mut self, rest: Attrs) -> Self {
        for (name, value) in rest.attrs {
            if !self.attrs.iter().any(|(n, _)| *n == name) {
                self.attrs.push((name, value));
            }
        }
        for (class, on) in rest.classes {
            self = self.class_toggle(class, on);
        }
        self.events.extend(rest.events);
        self.directives.extend(rest.directives);
        self
    }
}

macro_rules! html_attrs {
    ($($method:ident => $name:literal),* $(,)?) => {
        /// The tag attributes an `#[attrs]` component collects; a declared prop of the same name wins.
        #[doc(hidden)]
        pub trait RestAttrs: Sized {
            fn __rest(&mut self) -> &mut Attrs;

            fn __attr(mut self, name: &'static str, value: impl IntoAttr) -> Self {
                self.__rest().set(name, value);
                self
            }

            fn __class(mut self, class: &'static str, on: bool) -> Self {
                self.__rest().classes.push((class, on));
                self
            }

            fn __on(mut self, event: &'static str, opts: Listen, handler: impl Fn(Event) + 'static) -> Self {
                self.__rest().events.push((event, opts, Rc::new(handler)));
                self
            }

            fn __on_async<F, R>(mut self, event: &'static str, opts: Listen, handler: F) -> Self
            where
                F: AsyncFn(Event) -> R + 'static,
                R: crate::Outcome,
            {
                self.__rest().events.push((event, opts, async_handler(handler)));
                self
            }

            fn __directive(mut self, d: impl Directive) -> Self {
                self.__rest().directives.push(Rc::new(d));
                self
            }

            /// A URL attribute is a [`SafeUrl`](crate::SafeUrl) here too, so a spread can't carry `javascript:`.
            fn href(self, value: impl Into<crate::SafeUrl>) -> Self {
                self.__attr("href", value.into().0.to_string())
            }

            fn src(self, value: impl Into<crate::SafeUrl>) -> Self {
                self.__attr("src", value.into().0.to_string())
            }

            /// `{..rest}` on a component's tag: pass its `Attrs` on.
            fn __spread(mut self, rest: Attrs) -> Self {
                self.__rest().extend(rest);
                self
            }

            $(
                fn $method(self, value: impl IntoAttr) -> Self {
                    self.__attr($name, value)
                }
            )*
        }
    };
}

html_attrs!(
    accept => "accept", alt => "alt", autocomplete => "autocomplete", autofocus => "autofocus",
    checked => "checked", class => "class", dir => "dir", disabled => "disabled",
    draggable => "draggable", r#for => "for", form => "form", height => "height",
    hidden => "hidden", id => "id", inert => "inert", lang => "lang",
    max => "max", min => "min", multiple => "multiple", name => "name",
    pattern => "pattern", placeholder => "placeholder", readonly => "readonly", rel => "rel",
    required => "required", role => "role", slot => "slot", step => "step",
    style => "style", tabindex => "tabindex", target => "target", title => "title",
    r#type => "type", value => "value", width => "width",
);
