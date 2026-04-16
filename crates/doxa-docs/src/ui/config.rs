//! Typed configuration for the [Scalar API Reference](https://github.com/scalar/scalar) UI.
//!
//! [`ScalarConfig`] mirrors the subset of Scalar's `data-configuration`
//! options the crate surfaces, with strongly typed enums for fields
//! whose values come from a fixed vocabulary. The default values are
//! chosen to render the docs page exactly as the crate has shipped it
//! historically — a three-pane `modern` layout with dark mode on, the
//! schemas index hidden, the codegen sidebar suppressed, and Scalar's
//! paid product upsells (Agent / MCP) disabled.
//!
//! Pass an instance to [`MountOpts::scalar`](crate::MountOpts::scalar)
//! to override individual fields. The whole struct serializes to the
//! attribute-encoded JSON Scalar reads at boot, so adding a field here
//! is the only change required to expose a new toggle.

use serde::Serialize;

/// Scalar UI rendering options.
///
/// All fields default to the values the crate has shipped since the
/// initial Scalar adoption — constructing `ScalarConfig::default()` and
/// passing it to [`MountOpts::scalar`](crate::MountOpts::scalar) is a
/// no-op compared to omitting the call entirely.
///
/// # Example
///
/// ```
/// use doxa::{ScalarConfig, ScalarLayout, ScalarTheme};
///
/// let cfg = ScalarConfig::default()
///     .layout(ScalarLayout::Classic)
///     .theme(ScalarTheme::Solarized)
///     .dark_mode(false);
/// # let _ = cfg;
/// ```
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScalarConfig {
    /// Visual theme. Defaults to [`ScalarTheme::Default`].
    pub theme: ScalarTheme,

    /// Initial dark mode state. Defaults to `true`. The user-facing
    /// toggle remains visible unless [`Self::hide_dark_mode_toggle`] is
    /// set.
    pub dark_mode: bool,

    /// Hide the search box. Defaults to `false`.
    pub hide_search: bool,

    /// Hide the dark-mode toggle in the header. Defaults to `false`.
    pub hide_dark_mode_toggle: bool,

    /// Show the left sidebar. Defaults to `true`.
    pub show_sidebar: bool,

    /// Page layout. Defaults to [`ScalarLayout::Modern`] (three-pane
    /// nav / description / playground).
    pub layout: ScalarLayout,

    /// Hide the standalone "Models" / schemas index. Defaults to `true`
    /// — referenced schemas still render inline under each operation.
    pub hide_models: bool,

    /// Hide the "copy as curl/node/..." codegen button row. Defaults to
    /// `true`. The interactive try-it-out panel is unaffected.
    pub hide_client_button: bool,

    /// Format offered by the header "Download OpenAPI" button. Defaults
    /// to [`DocumentDownload::None`] — the spec is still reachable at
    /// the mounted JSON path.
    #[serde(rename = "documentDownloadType")]
    pub document_download: DocumentDownload,

    /// When the developer-tools drawer is exposed. Defaults to
    /// [`DeveloperTools::Never`].
    pub show_developer_tools: DeveloperTools,

    /// Enable Scalar's "Ask AI" assistant. Defaults to `false`. Scalar
    /// charges for production use of this feature; leaving it off keeps
    /// the docs UI free of upsell surface.
    #[serde(serialize_with = "serialize_agent", rename = "agent")]
    pub agent_enabled: bool,

    /// Enable Scalar's "Generate MCP" integration. Defaults to `false`
    /// for the same reason as [`Self::agent_enabled`].
    #[serde(serialize_with = "serialize_mcp", rename = "mcp")]
    pub mcp_enabled: bool,

    /// Override the Scalar CDN URL. `None` keeps the crate's default
    /// (`https://cdn.jsdelivr.net/npm/@scalar/api-reference`). Useful
    /// for air-gapped deployments, CDN mirrors, or self-hosted Scalar
    /// bundles — set this to the URL of the `@scalar/api-reference`
    /// script the browser should load.
    ///
    /// This field is skipped during JSON serialization — it is a
    /// server-side concern only (the URL is written into the HTML
    /// template, not handed to Scalar as configuration).
    #[serde(skip_serializing)]
    pub cdn_url: Option<String>,
}

impl Default for ScalarConfig {
    fn default() -> Self {
        Self {
            theme: ScalarTheme::Default,
            layout: ScalarLayout::Modern,
            dark_mode: true,
            hide_dark_mode_toggle: false,
            hide_search: false,
            show_sidebar: true,
            hide_models: true,
            hide_client_button: true,
            document_download: DocumentDownload::None,
            show_developer_tools: DeveloperTools::Never,
            agent_enabled: false,
            mcp_enabled: false,
            cdn_url: None,
        }
    }
}

impl ScalarConfig {
    /// Override the visual theme.
    pub fn theme(mut self, theme: ScalarTheme) -> Self {
        self.theme = theme;
        self
    }

    /// Override the page layout.
    pub fn layout(mut self, layout: ScalarLayout) -> Self {
        self.layout = layout;
        self
    }

    /// Set the initial dark mode state.
    pub fn dark_mode(mut self, on: bool) -> Self {
        self.dark_mode = on;
        self
    }

    /// Hide or show the dark-mode toggle.
    pub fn hide_dark_mode_toggle(mut self, hide: bool) -> Self {
        self.hide_dark_mode_toggle = hide;
        self
    }

    /// Hide or show the search box.
    pub fn hide_search(mut self, hide: bool) -> Self {
        self.hide_search = hide;
        self
    }

    /// Show or hide the left sidebar.
    pub fn show_sidebar(mut self, show: bool) -> Self {
        self.show_sidebar = show;
        self
    }

    /// Hide or show the standalone schemas index.
    pub fn hide_models(mut self, hide: bool) -> Self {
        self.hide_models = hide;
        self
    }

    /// Hide or show the codegen button row.
    pub fn hide_client_button(mut self, hide: bool) -> Self {
        self.hide_client_button = hide;
        self
    }

    /// Configure the header download button format.
    pub fn document_download(mut self, format: DocumentDownload) -> Self {
        self.document_download = format;
        self
    }

    /// Configure when the developer-tools drawer is exposed.
    pub fn show_developer_tools(mut self, when: DeveloperTools) -> Self {
        self.show_developer_tools = when;
        self
    }

    /// Enable or disable Scalar's "Ask AI" agent.
    pub fn agent_enabled(mut self, on: bool) -> Self {
        self.agent_enabled = on;
        self
    }

    /// Enable or disable Scalar's "Generate MCP" integration.
    pub fn mcp_enabled(mut self, on: bool) -> Self {
        self.mcp_enabled = on;
        self
    }

    /// Override the Scalar CDN URL. See [`Self::cdn_url`] for when to
    /// use this.
    pub fn cdn_url(mut self, url: impl Into<String>) -> Self {
        self.cdn_url = Some(url.into());
        self
    }
}

/// Visual theme presets recognized by Scalar.
///
/// The string each variant serializes to matches Scalar's documented
/// theme keys. New themes published upstream can be added without a
/// breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ScalarTheme {
    /// The Scalar default theme.
    Default,
    /// Alternate light theme.
    Alternate,
    /// Moon (low-contrast dark) theme.
    Moon,
    /// Purple accent theme.
    Purple,
    /// Solarized theme.
    Solarized,
    /// Blue Planet theme.
    BluePlanet,
    /// Saturn theme.
    Saturn,
    /// Kepler theme.
    Kepler,
    /// Mars theme.
    Mars,
    /// Deep Space theme.
    DeepSpace,
    /// No theme — render with Scalar's bare defaults.
    None,
}

/// Page layout variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScalarLayout {
    /// Three-pane layout (nav / description / always-on
    /// request-response playground). The historical default.
    Modern,
    /// Single-column Redoc-style layout.
    Classic,
}

/// Format(s) offered by the header "Download OpenAPI" button.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DocumentDownload {
    /// Hide the download button entirely. The spec is still reachable
    /// at the mounted JSON path.
    None,
    /// Offer JSON download.
    Json,
    /// Offer YAML download.
    Yaml,
    /// Offer both JSON and YAML downloads.
    Both,
}

/// Visibility of Scalar's developer-tools drawer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DeveloperTools {
    /// Never expose the drawer.
    Never,
    /// Always expose the drawer.
    Always,
    /// Expose the drawer on hover.
    OnHover,
}

// Scalar represents agent and MCP toggles as nested objects rather
// than top-level booleans:  `agent: { disabled: true }` /
// `mcp: { disabled: true }`. Encode that shape from a single bool so
// the public surface stays flat.
fn serialize_agent<S: serde::Serializer>(enabled: &bool, ser: S) -> Result<S::Ok, S::Error> {
    serialize_disabled_object(*enabled, ser)
}

fn serialize_mcp<S: serde::Serializer>(enabled: &bool, ser: S) -> Result<S::Ok, S::Error> {
    serialize_disabled_object(*enabled, ser)
}

fn serialize_disabled_object<S: serde::Serializer>(
    enabled: bool,
    ser: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    let mut map = ser.serialize_map(Some(1))?;
    map.serialize_entry("disabled", &!enabled)?;
    map.end()
}
