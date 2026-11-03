//! `classes![…]`: class lists joined, with empty, `None` and switched-off parts dropped.

/// One part of `classes![…]`: a string, an `Option` of one, or `(on, class)`.
pub trait ClassPart {
    fn push_to(self, out: &mut String);
}

impl ClassPart for &str {
    fn push_to(self, out: &mut String) {
        for class in self.split_whitespace() {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(class);
        }
    }
}

impl ClassPart for String {
    fn push_to(self, out: &mut String) {
        self.as_str().push_to(out)
    }
}

impl ClassPart for &String {
    fn push_to(self, out: &mut String) {
        self.as_str().push_to(out)
    }
}

impl<T: ClassPart> ClassPart for Option<T> {
    fn push_to(self, out: &mut String) {
        if let Some(part) = self {
            part.push_to(out)
        }
    }
}

impl<T: ClassPart> ClassPart for (bool, T) {
    fn push_to(self, out: &mut String) {
        if self.0 {
            self.1.push_to(out)
        }
    }
}

/// `classes!["btn", variant.class(), (pending, "opacity-50"), rest.class()]`, as one `String`.
#[macro_export]
macro_rules! classes {
    ($($part:expr),* $(,)?) => {{
        #[allow(unused_mut)]
        let mut out = ::std::string::String::new();
        $($crate::ClassPart::push_to($part, &mut out);)*
        out
    }};
}

#[cfg(test)]
mod tests {
    #[test]
    fn parts_join_and_falsy_ones_drop() {
        let rest: Option<&str> = Some("ml-2  mt-1");
        let none: Option<String> = None;
        assert_eq!(
            classes![
                "btn",
                "",
                (true, "on"),
                (false, "off"),
                rest,
                none,
                String::from("x")
            ],
            "btn on ml-2 mt-1 x"
        );
        assert_eq!(classes![], "");
    }
}
