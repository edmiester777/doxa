//! `[package.metadata.doxa.native]`, and the `tauri.conf.json` doxa generates from it.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// `[package.metadata.doxa.native]` on the web crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeConfig {
    /// Reverse-DNS bundle identifier, e.g. `com.acme.shop`.
    pub identifier: String,
    /// The product name; the package name when absent.
    pub name: Option<String>,
    /// Where the API runs.
    #[serde(default)]
    pub server: Server,
    /// `local`: the port the in-process server binds; see [`NativeConfig::port`].
    pub port: Option<u16>,
    /// `remote`: the API's base URL.
    pub url: Option<String>,
    /// Custom URL schemes the app opens, on every platform.
    #[serde(default)]
    pub schemes: Vec<String>,
    /// Verified `https` links the app opens on mobile.
    #[serde(default)]
    pub app_links: Vec<String>,
    /// The Apple signing team.
    pub apple_team: Option<String>,
    /// Loopback ports a native sign-in may capture its redirect on.
    #[serde(default)]
    pub oidc_loopback: Vec<u16>,
}

/// Where a native app's API runs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Server {
    /// In the app's own process, on `127.0.0.1`.
    #[default]
    Local,
    /// A deployed server at `url`.
    Remote,
}

/// Build-time overrides of [`NativeConfig`]: `$DOXA_NATIVE_URL` and `$APPLE_DEVELOPMENT_TEAM`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Overrides {
    /// Replaces `url`.
    pub url: Option<String>,
    /// Replaces `apple_team`.
    pub apple_team: Option<String>,
}

impl Overrides {
    /// The overrides set in this process's environment.
    pub fn from_env() -> Self {
        let var = |k| std::env::var(k).ok().filter(|v: &String| !v.is_empty());
        Overrides {
            url: var("DOXA_NATIVE_URL"),
            apple_team: var("APPLE_DEVELOPMENT_TEAM"),
        }
    }
}

const JAVA_KEYWORDS: &[&str] = &[
    "abstract",
    "assert",
    "boolean",
    "break",
    "byte",
    "case",
    "catch",
    "char",
    "class",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extends",
    "final",
    "finally",
    "float",
    "for",
    "goto",
    "if",
    "implements",
    "import",
    "instanceof",
    "int",
    "interface",
    "long",
    "native",
    "new",
    "package",
    "private",
    "protected",
    "public",
    "return",
    "short",
    "static",
    "strictfp",
    "super",
    "switch",
    "synchronized",
    "this",
    "throw",
    "throws",
    "transient",
    "try",
    "void",
    "volatile",
    "while",
    "true",
    "false",
    "null",
];

impl NativeConfig {
    /// Parses and validates `[package.metadata.doxa.native]` from a whole `Cargo.toml`; `None`
    /// when the table is absent.
    pub fn from_manifest(manifest: &str) -> Result<Option<NativeConfig>, String> {
        let table: toml::Table = manifest
            .parse()
            .map_err(|e| format!("Cargo.toml doesn't parse: {e}"))?;
        let Some(native) = table
            .get("package")
            .and_then(|p| p.get("metadata"))
            .and_then(|m| m.get("doxa"))
            .and_then(|d| d.get("native"))
        else {
            return Ok(None);
        };
        let cfg: NativeConfig = native
            .clone()
            .try_into()
            .map_err(|e| format!("`[package.metadata.doxa.native]`: {e}"))?;
        cfg.validate()?;
        Ok(Some(cfg))
    }

    /// Applies build-time overrides.
    pub fn with(mut self, o: &Overrides) -> Self {
        if let Some(url) = &o.url {
            self.url = Some(url.clone());
        }
        if let Some(team) = &o.apple_team {
            self.apple_team = Some(team.clone());
        }
        self
    }

    /// Checks what Tauri and the platforms would reject later, naming the key.
    pub fn validate(&self) -> Result<(), String> {
        let key = |k: &str, why: String| format!("`[package.metadata.doxa.native] {k}`: {why}");
        valid_identifier(&self.identifier).map_err(|e| key("identifier", e))?;
        if self.server == Server::Remote {
            match &self.url {
                None => {
                    return Err(key(
                        "url",
                        "`server = \"remote\"` needs the API's base URL".into(),
                    ))
                }
                Some(u) if !(u.starts_with("https://") || u.starts_with("http://")) => {
                    return Err(key("url", format!("`{u}` isn't an http(s) URL")))
                }
                Some(_) => {}
            }
        }
        for s in &self.schemes {
            if !valid_scheme(s) {
                return Err(key("schemes", format!("`{s}` isn't a URL scheme")));
            }
            if matches!(s.as_str(), "http" | "https" | "file") {
                return Err(key(
                    "schemes",
                    format!("`{s}` belongs to the system; use `app_links` for https"),
                ));
            }
        }
        for l in &self.app_links {
            if parse_link(l).is_none() {
                return Err(key(
                    "app_links",
                    format!("`{l}` isn't an `https://host/path` link"),
                ));
            }
        }
        if let Some(p) = self.oidc_loopback.iter().find(|p| **p < 1024) {
            return Err(key("oidc_loopback", format!("{p} is a privileged port")));
        }
        Ok(())
    }

    /// The local server's port: `port`, else one derived from the identifier, so an app's origin
    /// is the same on every launch.
    pub fn port(&self) -> u16 {
        self.port.unwrap_or_else(|| {
            let h = self
                .identifier
                .bytes()
                .fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
                    (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
                });
            30000 + (h % 20000) as u16
        })
    }
}

fn valid_identifier(id: &str) -> Result<(), String> {
    let segments: Vec<&str> = id.split('.').collect();
    if segments.len() < 2 {
        return Err(format!("`{id}` isn't reverse-DNS, like `com.acme.shop`"));
    }
    if id.ends_with(".app") {
        return Err(format!("`{id}` ends in `.app`, which macOS rejects"));
    }
    for s in segments {
        let mut chars = s.chars();
        let ok = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !ok {
            return Err(format!(
                "segment `{s}` of `{id}` must start with a letter and hold only letters, digits \
                 and `_` (Android package names allow no `-`)"
            ));
        }
        if JAVA_KEYWORDS.contains(&s) {
            return Err(format!(
                "segment `{s}` of `{id}` is a Java keyword, which Android rejects"
            ));
        }
    }
    Ok(())
}

fn valid_scheme(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "+-.".contains(c))
}

/// `https://host/path` into its host and path.
fn parse_link(link: &str) -> Option<(&str, &str)> {
    let rest = link.strip_prefix("https://")?;
    let (host, path) = rest.split_once('/').map_or((rest, ""), |(h, p)| (h, p));
    (!host.is_empty() && !host.contains(['?', '#', ' '])).then_some((host, path))
}

/// The package fields `tauri.conf.json` takes.
pub struct Package<'a> {
    /// The package name.
    pub name: &'a str,
    /// The package version.
    pub version: &'a str,
}

/// The icon files `tauri icon` makes, in the order `bundle.icon` lists them.
const ICONS: &[&str] = &[
    "icons/32x32.png",
    "icons/128x128.png",
    "icons/128x128@2x.png",
    "icons/icon.icns",
    "icons/icon.ico",
    "icons/icon.png",
];

/// The directory of a one-file page, the `frontendDist` of a build whose page comes from
/// elsewhere.
pub const STUB_DIST: &str = "gen/doxa/stub";

/// `tauri.conf.json` for the crate at `dir`.
pub fn tauri_config(cfg: &NativeConfig, pkg: &Package, dir: &Path) -> Value {
    let exists = |p: &str| dir.join(p).is_file();
    let icons: Vec<&str> = ICONS.iter().copied().filter(|i| exists(i)).collect();
    let mut macos = serde_json::Map::new();
    if exists("native/Info.plist") {
        macos.insert("infoPlist".into(), json!("native/Info.plist"));
    }
    if exists("native/Entitlements.plist") {
        macos.insert("entitlements".into(), json!("native/Entitlements.plist"));
    }
    let mut ios = serde_json::Map::new();
    ios.insert("infoPlist".into(), json!(IOS_PLIST));
    if let Some(team) = &cfg.apple_team {
        ios.insert("developmentTeam".into(), json!(team));
    }
    let mut mobile: Vec<Value> = cfg
        .schemes
        .iter()
        .map(|s| json!({ "scheme": [s], "appLink": false }))
        .collect();
    for (host, path) in cfg.app_links.iter().filter_map(|l| parse_link(l)) {
        let mut link = json!({ "scheme": ["https"], "host": host, "appLink": true });
        if !path.is_empty() {
            link["pathPrefix"] = json!([format!("/{path}")]);
        }
        mobile.push(link);
    }
    json!({
        "productName": cfg.name.as_deref().unwrap_or(pkg.name),
        "version": pkg.version,
        "identifier": cfg.identifier,
        "build": { "frontendDist": STUB_DIST },
        "app": {
            "windows": [],
            "security": { "capabilities": [] },
        },
        "bundle": {
            "active": true,
            "targets": "all",
            "icon": icons,
            "macOS": macos,
            "iOS": ios,
        },
        "plugins": {
            "deep-link": {
                "desktop": { "schemes": cfg.schemes },
                "mobile": mobile,
            },
        },
    })
}

/// The iOS app's extra `Info.plist` keys: `native/Info.plist`, then `native/Info.ios.plist`,
/// then what local mode needs.
pub const IOS_PLIST: &str = "gen/doxa/Info.ios.plist";

/// [`IOS_PLIST`]'s content for the crate at `dir`; later sources win key by key.
pub fn ios_plist(cfg: &NativeConfig, dir: &Path) -> std::io::Result<String> {
    let mut merged = plist::Dictionary::new();
    for src in ["native/Info.plist", "native/Info.ios.plist"] {
        let path = dir.join(src);
        if !path.is_file() {
            continue;
        }
        let v = plist::Value::from_file(&path)
            .map_err(|e| std::io::Error::other(format!("{}: {e}", path.display())))?;
        let Some(d) = v.into_dictionary() else {
            return Err(std::io::Error::other(format!(
                "{}: not a <dict>",
                path.display()
            )));
        };
        merged.extend(d);
    }
    if cfg.server == Server::Local {
        // The window loads http://127.0.0.1, which App Transport Security blocks otherwise.
        let mut ats = merged
            .remove("NSAppTransportSecurity")
            .and_then(plist::Value::into_dictionary)
            .unwrap_or_default();
        ats.insert("NSAllowsLocalNetworking".into(), true.into());
        merged.insert("NSAppTransportSecurity".into(), ats.into());
    }
    let mut out = Vec::new();
    plist::Value::Dictionary(merged)
        .to_writer_xml(&mut out)
        .map_err(std::io::Error::other)?;
    Ok(String::from_utf8_lossy(&out).into_owned() + "\n")
}

/// Writes `tauri.conf.json`, the iOS plist and the stub page under `dir`, each only when its
/// content changed.
pub fn write_generated(cfg: &NativeConfig, pkg: &Package, dir: &Path) -> std::io::Result<()> {
    let conf = serde_json::to_string_pretty(&tauri_config(cfg, pkg, dir))? + "\n";
    write_if_changed(&dir.join("tauri.conf.json"), &conf)?;
    write_if_changed(&dir.join(IOS_PLIST), &ios_plist(cfg, dir)?)?;
    write_if_changed(
        &dir.join(STUB_DIST).join("index.html"),
        "<!doctype html><title></title>\n",
    )
}

/// The `doxa` plugin's commands; `doxa-native` registers handlers by these names.
pub const DOXA_COMMANDS: &[&str] = &[
    "menu_set",
    "menu_popup",
    "tray_set",
    "shortcut_set",
    "window",
    "sign_in",
    "take_open_urls",
];

/// Where the CLI leaves the overrides it resolved, for build scripts run without its env.
pub const OVERRIDES: &str = "gen/doxa/overrides.json";

/// The env `rustc` gets the [`Shell`] in, as JSON.
pub const CONFIG_ENV: &str = "DOXA_NATIVE_CONFIG";

/// What a web crate's `build.rs` hands its shell: the resolved config and the app's commands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shell {
    /// `[package.metadata.doxa.native]` with overrides applied.
    pub config: NativeConfig,
    /// The app's own commands, as `build.rs` listed them.
    pub commands: Vec<String>,
}

/// `doxa-native`'s `links` prefix: each `DEP_DOXA_NATIVE_FWD<n>` holds `<KEY>=<value>`, a plugin's
/// `DEP_*` var forwarded under a name `tauri-build` doesn't scan.
#[cfg(feature = "native-build")]
const FORWARDED: &str = "DEP_DOXA_NATIVE_FWD";

/// The shell half of a web crate's `build.rs`.
#[cfg(feature = "native-build")]
pub(crate) fn shell(commands: &'static [&'static str]) {
    use tauri_build::{AppManifest, Attributes, DefaultPermissionRule, InlinedPlugin};

    let dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("build.rs"));
    let manifest = std::fs::read_to_string(dir.join("Cargo.toml")).expect("read Cargo.toml");
    let cfg = NativeConfig::from_manifest(&manifest)
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| {
            panic!("`--features native` needs a `[package.metadata.doxa.native]` table")
        });
    let overrides = match std::fs::read_to_string(dir.join(OVERRIDES)) {
        Ok(json) => serde_json::from_str(&json).unwrap_or_else(|e| panic!("{OVERRIDES}: {e}")),
        Err(_) => Overrides::from_env(),
    };
    let cfg = cfg.with(&overrides);
    let shell = Shell {
        config: cfg.clone(),
        commands: commands.iter().map(|c| (*c).to_owned()).collect(),
    };
    println!(
        "cargo::rustc-env={CONFIG_ENV}={}",
        serde_json::to_string(&shell).expect("config serializes")
    );
    let name = std::env::var("CARGO_PKG_NAME").expect("build.rs");
    let version = std::env::var("CARGO_PKG_VERSION").expect("build.rs");
    fallback_icons(&dir).unwrap_or_else(|e| panic!("writing fallback icons: {e}"));
    write_generated(
        &cfg,
        &Package {
            name: &name,
            version: &version,
        },
        &dir,
    )
    .unwrap_or_else(|e| panic!("writing tauri.conf.json: {e}"));
    for (key, value) in std::env::vars() {
        if key.starts_with(FORWARDED) {
            if let Some((k, v)) = value.split_once('=') {
                std::env::set_var(k, v);
            }
        }
    }
    println!("cargo::rerun-if-changed=native");
    println!("cargo::rerun-if-changed={OVERRIDES}");
    println!("cargo::rerun-if-env-changed=DOXA_NATIVE_URL");
    println!("cargo::rerun-if-env-changed=APPLE_DEVELOPMENT_TEAM");
    tauri_build::try_build(
        Attributes::new()
            .app_manifest(AppManifest::new().commands(commands))
            .plugin(
                "doxa",
                InlinedPlugin::new()
                    .commands(DOXA_COMMANDS)
                    .default_permission(DefaultPermissionRule::AllowAllCommands),
            ),
    )
    .unwrap_or_else(|e| panic!("tauri-build: {e:#}"));
}

/// `icons/icon.png` and an `icons/icon.ico` wrapping it, from `native/icon.png`, when `icons/`
/// has neither; `doxa build` writes the full set.
#[cfg(feature = "native-build")]
fn fallback_icons(dir: &Path) -> std::io::Result<()> {
    let (src, png, ico) = (
        dir.join("native/icon.png"),
        dir.join("icons/icon.png"),
        dir.join("icons/icon.ico"),
    );
    if png.exists() || ico.exists() || !src.exists() {
        return Ok(());
    }
    let bytes = std::fs::read(&src)?;
    std::fs::create_dir_all(png.parent().expect("icons/"))?;
    std::fs::write(&png, &bytes)?;
    std::fs::write(&ico, ico_of_png(&bytes))
}

/// An `.ico` holding one PNG image; Windows reads PNG-compressed entries.
#[cfg(any(feature = "native-build", test))]
fn ico_of_png(png: &[u8]) -> Vec<u8> {
    // IHDR width and height, big-endian at bytes 16..24; an entry stores 0 for 256 and up.
    let dim = |at: usize| {
        let d = png
            .get(at..at + 4)
            .map_or(0, |b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
        if d >= 256 {
            0
        } else {
            d as u8
        }
    };
    let mut ico = vec![0, 0, 1, 0, 1, 0];
    ico.extend([dim(16), dim(20), 0, 0, 1, 0, 32, 0]);
    ico.extend((png.len() as u32).to_le_bytes());
    ico.extend(22u32.to_le_bytes());
    ico.extend(png);
    ico
}

fn write_if_changed(path: &Path, content: &str) -> std::io::Result<()> {
    if std::fs::read_to_string(path).is_ok_and(|c| c == content) {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(native: &str) -> Result<Option<NativeConfig>, String> {
        NativeConfig::from_manifest(&format!("[package.metadata.doxa.native]\n{native}"))
    }

    fn cfg(native: &str) -> NativeConfig {
        parse(native).unwrap().unwrap()
    }

    #[test]
    fn local_is_the_default_and_the_port_is_stable() {
        let c = cfg("identifier = \"com.acme.shop\"");
        assert_eq!(c.server, Server::Local);
        assert_eq!(c.port(), cfg("identifier = \"com.acme.shop\"").port());
        assert!((30000..50000).contains(&c.port()));
        assert_ne!(c.port(), cfg("identifier = \"com.acme.other\"").port());
        assert_eq!(
            cfg("identifier = \"com.acme.shop\"\nport = 47213").port(),
            47213
        );
        assert_eq!(
            NativeConfig::from_manifest("[package]\nname = \"a\""),
            Ok(None)
        );
    }

    #[test]
    fn refuses_what_the_platforms_would() {
        let err = |native: &str| parse(native).unwrap_err();
        assert!(err("identifier = \"shop\"").contains("reverse-DNS"));
        assert!(err("identifier = \"com.acme-co.shop\"").contains("no `-`"));
        assert!(err("identifier = \"com.acme.new\"").contains("Java keyword"));
        assert!(err("identifier = \"com.acme.app\"").contains("`.app`"));
        assert!(err("identifier = \"com.acme.shop\"\nserver = \"remote\"").contains("url"));
        assert!(
            err("identifier = \"com.a.b\"\nserver = \"remote\"\nurl = \"api.acme.com\"")
                .contains("http(s)")
        );
        assert!(err("identifier = \"com.a.b\"\nschemes = [\"Acme!\"]").contains("URL scheme"));
        assert!(err("identifier = \"com.a.b\"\nschemes = [\"https\"]").contains("app_links"));
        assert!(err("identifier = \"com.a.b\"\napp_links = [\"http://a.com\"]").contains("https"));
        assert!(err("identifier = \"com.a.b\"\noidc_loopback = [80]").contains("privileged"));
        assert!(err("identifier = \"com.a.b\"\nport = \"x\"").contains("port"));
        assert!(err("identifier = \"com.a.b\"\ncolour = 1").contains("colour"));
    }

    #[test]
    fn overrides_replace_url_and_team() {
        let c = cfg("identifier = \"com.a.b\"\nurl = \"https://a\"").with(&Overrides {
            url: Some("https://b".into()),
            apple_team: Some("T".into()),
        });
        assert_eq!(c.url.as_deref(), Some("https://b"));
        assert_eq!(c.apple_team.as_deref(), Some("T"));
    }

    fn dir_with(files: &[&str]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "doxa-native-{}-{}",
            std::process::id(),
            files.join("-").replace('/', "_")
        ));
        let _ = std::fs::remove_dir_all(&dir);
        for f in files {
            let p = dir.join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "").unwrap();
        }
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const PKG: Package = Package {
        name: "shop-web",
        version: "1.2.3",
    };

    #[test]
    fn the_config_names_the_app_and_lists_only_files_that_exist() {
        let dir = dir_with(&["icons/icon.png", "native/Info.plist"]);
        let c = tauri_config(&cfg("identifier = \"com.acme.shop\""), &PKG, &dir);
        assert_eq!(c["productName"], "shop-web");
        assert_eq!(c["version"], "1.2.3");
        assert_eq!(c["identifier"], "com.acme.shop");
        assert_eq!(c["bundle"]["icon"], json!(["icons/icon.png"]));
        assert_eq!(
            c["bundle"]["macOS"],
            json!({ "infoPlist": "native/Info.plist" })
        );
        assert_eq!(c["app"]["windows"], json!([]));
        assert_eq!(c["build"]["frontendDist"], STUB_DIST);
        let named = tauri_config(
            &cfg("identifier = \"com.a.b\"\nname = \"Acme\""),
            &PKG,
            &dir,
        );
        assert_eq!(named["productName"], "Acme");
    }

    #[test]
    fn schemes_and_app_links_become_deep_links() {
        let dir = dir_with(&[]);
        let c = tauri_config(
            &cfg("identifier = \"com.a.b\"\nschemes = [\"acme\"]\napp_links = [\"https://acme.com/open\", \"https://acme.com\"]\napple_team = \"T1\""),
            &PKG,
            &dir,
        );
        let deep = &c["plugins"]["deep-link"];
        assert_eq!(deep["desktop"]["schemes"], json!(["acme"]));
        assert_eq!(
            deep["mobile"],
            json!([
                { "scheme": ["acme"], "appLink": false },
                { "scheme": ["https"], "host": "acme.com", "appLink": true, "pathPrefix": ["/open"] },
                { "scheme": ["https"], "host": "acme.com", "appLink": true },
            ])
        );
        assert_eq!(c["bundle"]["iOS"]["developmentTeam"], "T1");
    }

    #[test]
    fn the_ios_plist_merges_the_sources_and_lets_local_mode_reach_its_server() {
        let dir = dir_with(&["native/plist-test"]);
        let p = |body: &str| {
            format!("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>{body}</dict></plist>")
        };
        std::fs::write(
            dir.join("native/Info.plist"),
            p("<key>A</key><string>shared</string><key>B</key><string>shared</string>"),
        )
        .unwrap();
        std::fs::write(
            dir.join("native/Info.ios.plist"),
            p("<key>B</key><string>ios</string>"),
        )
        .unwrap();
        let local = ios_plist(&cfg("identifier = \"com.a.b\""), &dir).unwrap();
        let v = plist::Value::from_reader_xml(local.as_bytes()).unwrap();
        let d = v.as_dictionary().unwrap();
        assert_eq!(d["A"].as_string(), Some("shared"));
        assert_eq!(d["B"].as_string(), Some("ios"));
        let ats = d["NSAppTransportSecurity"].as_dictionary().unwrap();
        assert_eq!(ats["NSAllowsLocalNetworking"].as_boolean(), Some(true));
        let remote = ios_plist(
            &cfg("identifier = \"com.a.b\"\nserver = \"remote\"\nurl = \"https://a.b\""),
            &dir,
        )
        .unwrap();
        assert!(!remote.contains("NSAppTransportSecurity"));
    }

    #[test]
    fn an_ico_wraps_the_png_with_its_size() {
        let mut png = vec![0u8; 24];
        png[16..20].copy_from_slice(&32u32.to_be_bytes());
        png[20..24].copy_from_slice(&1024u32.to_be_bytes());
        let ico = ico_of_png(&png);
        assert_eq!(&ico[..6], [0, 0, 1, 0, 1, 0]);
        assert_eq!((ico[6], ico[7]), (32, 0));
        assert_eq!(&ico[14..18], 24u32.to_le_bytes());
        assert_eq!(&ico[18..22], 22u32.to_le_bytes());
        assert_eq!(&ico[22..], png);
    }

    #[test]
    fn writes_only_on_change() {
        let dir = dir_with(&[]);
        let c = cfg("identifier = \"com.a.b\"");
        write_generated(&c, &PKG, &dir).unwrap();
        let conf = dir.join("tauri.conf.json");
        let before = std::fs::metadata(&conf).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        write_generated(&c, &PKG, &dir).unwrap();
        assert_eq!(
            std::fs::metadata(&conf).unwrap().modified().unwrap(),
            before
        );
        assert!(dir.join(STUB_DIST).join("index.html").is_file());
    }
}
