//! Scalar UI mount.
//!
//! Renders an OpenAPI document with [Scalar API Reference](https://github.com/scalar/scalar)
//! (open-source, MIT-licensed). The page is a single small HTML
//! template that loads the `@scalar/api-reference` web component
//! from a CDN at runtime; binary impact is one HTML string.
//!
//! Chosen for:
//!
//! - **Active maintenance**: regular releases through 2026 (compared to
//!   RapiDoc, which has been quiet since Oct 2024).
//! - **OpenAPI 3.2 parsing**: merged in Oct 2025, which lets us emit the
//!   `itemSchema` keyword for SSE responses without custom tooling on our side.
//! - **Native `x-badges` rendering** with Scalar's `{name, color}` schema —
//!   covers the OAuth-scope and admin-gate badges already emitted by the
//!   contribution layer.
//! - **First-class dark theme** with a user-facing toggle.
//!
//! ## Default rendering
//!
//! Out of the box the page renders with the three-pane `modern`
//! Scalar layout (nav / description / always-on request-response
//! playground), dark mode on, the schemas index hidden, the codegen
//! sidebar suppressed, the header download button removed, and
//! Scalar's paid product upsells (`Ask AI` / `Generate MCP`) disabled.
//! Search and the dark-mode toggle stay visible — genuine navigation
//! aids, not upsell surface.
//!
//! ## Customizing
//!
//! All of those choices are overridable via
//! [`ScalarConfig`](crate::ScalarConfig), which is set on
//! [`MountOpts::scalar`](crate::MountOpts::scalar). The serialized default of
//! [`ScalarConfig::default()`](crate::ScalarConfig) is byte-identical to the
//! historical hard-coded blob, so the out-of-the-box appearance is preserved.

use super::html_escape;
use crate::ui::config::ScalarConfig;

/// Render the Scalar HTML page that points at the given OpenAPI JSON URL.
///
/// `spec_url` is the path the Scalar bundle fetches the spec from at
/// runtime; `title` is rendered in the browser tab. `config` controls
/// every Scalar UI option exposed by the crate — see
/// [`ScalarConfig`](crate::ScalarConfig) for the full list.
pub(crate) fn render(spec_url: &str, title: &str, config: &ScalarConfig) -> String {
    // CDN URL pin lives in source so binary contents stay deterministic
    // by default. Consumers override via `ScalarConfig::cdn_url` — most
    // commonly for air-gapped deployments or self-hosted mirrors.
    const DEFAULT_CDN: &str = "https://cdn.jsdelivr.net/npm/@scalar/api-reference";
    let cdn = config.cdn_url.as_deref().unwrap_or(DEFAULT_CDN);
    let cdn = html_escape(cdn);

    let title = html_escape(title);
    let spec_url = html_escape(spec_url);

    // The configuration object is attribute-encoded JSON so there is
    // no inline script — keeps the template immune to CSP script-src
    // restrictions. HTML-escape the serialized JSON before embedding;
    // the JSON itself contains crate-controlled values, but
    // attribute-context safety still requires escaping `&` `<` `>` `"` `'`.
    //
    // Serialization is infallible for `ScalarConfig` (a flat struct of
    // owned primitives + serde-derived enums with no custom error
    // surface), so unwrap is safe here.
    let config_json = serde_json::to_string(config)
        .expect("ScalarConfig serialization is infallible for a flat owned struct");
    let config_json = html_escape(&config_json);

    format!(
        r##"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{title}</title>
    <style>
      html, body {{ margin: 0; padding: 0; height: 100%; }}
    </style>
  </head>
  <body>
    <script
      id="api-reference"
      data-url="{spec_url}"
      data-configuration="{config_json}"
    ></script>
    <script src="{cdn}"></script>
  </body>
</html>
"##
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_cfg() -> ScalarConfig {
        ScalarConfig::default()
    }

    #[test]
    fn renders_with_supplied_spec_url() {
        let html = render("/openapi.json", "Test API", &default_cfg());
        assert!(html.contains(r#"data-url="/openapi.json""#));
        assert!(html.contains("<title>Test API</title>"));
        assert!(html.contains("@scalar/api-reference"));
        assert!(html.contains(r#"id="api-reference""#));
    }

    #[test]
    fn escapes_dangerous_characters_in_title() {
        let html = render("/openapi.json", "<script>alert(1)</script>", &default_cfg());
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<title><script>alert(1)</script></title>"));
    }

    #[test]
    fn escapes_quotes_in_spec_url() {
        let html = render(r#"/openapi.json" onload="alert(1)"#, "x", &default_cfg());
        assert!(html.contains("&quot;"));
        assert!(!html.contains(r#"data-url="/openapi.json" onload="alert(1)"#));
    }

    #[test]
    fn renders_with_default_cdn_when_cdn_url_is_none() {
        let html = render("/openapi.json", "t", &default_cfg());
        assert!(html.contains("cdn.jsdelivr.net/npm/@scalar/api-reference"));
    }

    #[test]
    fn renders_with_overridden_cdn_url_when_set() {
        let cfg = default_cfg().cdn_url("https://internal.example.com/scalar.js");
        let html = render("/openapi.json", "t", &cfg);
        assert!(html.contains("https://internal.example.com/scalar.js"));
        assert!(!html.contains("cdn.jsdelivr.net"));
    }

    #[test]
    fn cdn_url_is_not_serialized_into_scalar_config() {
        let cfg = default_cfg().cdn_url("https://internal.example.com/scalar.js");
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(!json.contains("cdnUrl"));
        assert!(!json.contains("cdn_url"));
        assert!(!json.contains("internal.example.com"));
    }
}
