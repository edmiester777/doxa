//! Documentation UI mounting.
//!
//! Each UI is a separate module gated by its own cargo feature so
//! consumers only pay for the ones they enable. The default feature
//! `docs-scalar` mounts a CDN-loaded Scalar UI rendered in the
//! three-pane `modern` layout with dark mode on. Every visible knob
//! is overridable via [`ScalarConfig`](crate::ScalarConfig); see
//! [`scalar`] for the per-option documentation.

#[cfg(feature = "docs-scalar")]
pub(crate) mod config;
#[cfg(feature = "docs-scalar")]
pub(crate) mod scalar;

#[cfg(feature = "docs-scalar")]
pub use config::{DeveloperTools, DocumentDownload, ScalarConfig, ScalarLayout, ScalarTheme};

/// Minimal HTML attribute escaping shared by every UI renderer that
/// templates user-supplied strings into the page (title, spec URL).
/// Replaces the five characters that can break out of an attribute
/// context. Sufficient for the limited set of values we render.
#[cfg(feature = "docs-scalar")]
pub(crate) fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(feature = "docs-scalar")]
    fn html_escape_replaces_dangerous_chars() {
        assert_eq!(super::html_escape("&"), "&amp;");
        assert_eq!(super::html_escape("<"), "&lt;");
        assert_eq!(super::html_escape(">"), "&gt;");
        assert_eq!(super::html_escape("\""), "&quot;");
        assert_eq!(super::html_escape("'"), "&#39;");
        assert_eq!(super::html_escape("plain"), "plain");
    }
}
