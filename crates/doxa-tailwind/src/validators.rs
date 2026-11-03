//! tailwind-merge's validators: what an arbitrary or numeric class value may be.

use std::sync::OnceLock;

use regex_lite::Regex;

/// One of tailwind-merge's validators, named as it names them without `is`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Validator {
    Any,
    AnyNonArbitrary,
    ArbitraryFamilyName,
    ArbitraryImage,
    ArbitraryLength,
    ArbitraryNumber,
    ArbitraryPosition,
    ArbitraryShadow,
    ArbitrarySize,
    ArbitraryValue,
    ArbitraryVariable,
    ArbitraryVariableFamilyName,
    ArbitraryVariableImage,
    ArbitraryVariableLength,
    ArbitraryVariablePosition,
    ArbitraryVariableShadow,
    ArbitraryVariableSize,
    ArbitraryVariableWeight,
    ArbitraryWeight,
    Fraction,
    Integer,
    Number,
    Percent,
    TshirtSize,
}

macro_rules! regex {
    ($re:literal) => {{
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new($re).expect("a valid regex"))
    }};
}

fn arbitrary_value() -> &'static Regex {
    regex!(r"(?i)^\[(?:(\w[\w-]*):)?(.+)\]$")
}

fn arbitrary_variable() -> &'static Regex {
    regex!(r"(?i)^\((?:(\w[\w-]*):)?(.+)\)$")
}

impl Validator {
    pub(crate) fn check(self, v: &str) -> bool {
        use Validator::*;
        match self {
            Any => true,
            AnyNonArbitrary => !arbitrary_value().is_match(v) && !arbitrary_variable().is_match(v),
            ArbitraryFamilyName => arbitrary(v, |l| l == "family-name", |_| false),
            ArbitraryImage => arbitrary(v, |l| l == "image" || l == "url", image),
            ArbitraryLength => arbitrary(v, |l| l == "length", length_only),
            ArbitraryNumber => arbitrary(v, |l| l == "number", number),
            ArbitraryPosition => arbitrary(v, position_label, |_| false),
            ArbitraryShadow => arbitrary(v, |l| l == "shadow", shadow),
            ArbitrarySize => arbitrary(v, size_label, |_| false),
            ArbitraryValue => arbitrary_value().is_match(v),
            ArbitraryVariable => arbitrary_variable().is_match(v),
            ArbitraryVariableFamilyName => variable(v, |l| l == "family-name", false),
            ArbitraryVariableImage => variable(v, |l| l == "image" || l == "url", false),
            ArbitraryVariableLength => variable(v, |l| l == "length", false),
            ArbitraryVariablePosition => variable(v, position_label, false),
            ArbitraryVariableShadow => variable(v, |l| l == "shadow", true),
            ArbitraryVariableSize => variable(v, size_label, false),
            ArbitraryVariableWeight => variable(v, weight_label, true),
            ArbitraryWeight => arbitrary(v, weight_label, |_| true),
            Fraction => regex!(r"^\d+(?:\.\d+)?/\d+(?:\.\d+)?$").is_match(v),
            Integer => js_number(v).is_some_and(|n| n.is_finite() && n.fract() == 0.0),
            Number => number(v),
            Percent => v.strip_suffix('%').is_some_and(number),
            TshirtSize => regex!(r"^(\d+(\.\d+)?)?(xs|sm|md|lg|xl)$").is_match(v),
        }
    }
}

fn position_label(l: &str) -> bool {
    l == "position" || l == "percentage"
}

fn size_label(l: &str) -> bool {
    l == "length" || l == "size" || l == "bg-size"
}

fn weight_label(l: &str) -> bool {
    l == "number" || l == "weight"
}

fn arbitrary(v: &str, label: fn(&str) -> bool, value: fn(&str) -> bool) -> bool {
    match arbitrary_value().captures(v) {
        Some(c) => match c.get(1) {
            Some(l) => label(l.as_str()),
            None => value(&c[2]),
        },
        None => false,
    }
}

fn variable(v: &str, label: fn(&str) -> bool, unlabelled: bool) -> bool {
    match arbitrary_variable().captures(v) {
        Some(c) => c.get(1).map_or(unlabelled, |l| label(l.as_str())),
        None => false,
    }
}

fn number(v: &str) -> bool {
    !v.is_empty() && js_number(v).is_some()
}

fn length_only(v: &str) -> bool {
    // Colour functions hold percentages that would otherwise read as lengths.
    regex!(r"\d+(%|px|r?em|[sdl]?v([hwib]|min|max)|pt|pc|in|cm|mm|cap|ch|ex|r?lh|cq(w|h|i|b|min|max))|\b(calc|min|max|clamp)\(.+\)|^0$").is_match(v)
        && !regex!(r"^(rgba?|hsla?|hwb|(ok)?(lab|lch)|color-mix)\(.+\)$").is_match(v)
}

fn shadow(v: &str) -> bool {
    regex!(r"^(inset_)?-?((\d+)?\.?(\d+)[a-z]+|0)_-?((\d+)?\.?(\d+)[a-z]+|0)").is_match(v)
}

fn image(v: &str) -> bool {
    regex!(r"^(url|image|image-set|cross-fade|element|(repeating-)?(linear|radial|conic)-gradient)\(.+\)$").is_match(v)
}

/// JavaScript's `Number(v)`, as `None` where it gives `NaN`.
fn js_number(v: &str) -> Option<f64> {
    let t = v.trim();
    if t.is_empty() {
        return Some(0.0);
    }
    for (prefix, radix) in [
        ("0x", 16),
        ("0X", 16),
        ("0o", 8),
        ("0O", 8),
        ("0b", 2),
        ("0B", 2),
    ] {
        if let Some(digits) = t.strip_prefix(prefix) {
            return u64::from_str_radix(digits, radix).ok().map(|n| n as f64);
        }
    }
    match t {
        "Infinity" | "+Infinity" => return Some(f64::INFINITY),
        "-Infinity" => return Some(f64::NEG_INFINITY),
        _ => {}
    }
    if !t
        .bytes()
        .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-'))
    {
        return None;
    }
    t.parse::<f64>().ok()
}

#[cfg(test)]
mod tests {
    use super::Validator::*;

    #[test]
    fn numbers_follow_javascript() {
        assert!(Number.check("1.5") && Number.check("0x10") && Number.check(".5"));
        assert!(!Number.check("") && !Number.check("1px") && !Number.check("inf"));
        assert!(Integer.check("3") && !Integer.check("3.5"));
        assert!(Percent.check("50%") && !Percent.check("%"));
    }

    #[test]
    fn arbitrary_values_read_their_label() {
        assert!(ArbitraryLength.check("[length:var(--x)]"));
        assert!(ArbitraryLength.check("[3px]") && !ArbitraryLength.check("[#fff]"));
        assert!(!ArbitraryLength.check("[hsl(0_0%_0%)]"));
        assert!(ArbitraryVariableShadow.check("(--s)") && !ArbitraryVariableLength.check("(--s)"));
        assert!(Fraction.check("1/2") && TshirtSize.check("2xl"));
    }
}
