//! Marks a crate as the client or server half of a doxa app, or an API both depend on, from
//! `build.rs`.
//!
//! ```ignore
//! // api/build.rs
//! fn main() { doxa_role::api() }
//! ```

#![deny(missing_docs)]

use std::path::{Path, PathBuf};

#[cfg(feature = "native")]
pub mod native;

/// Environment variable doxa's macros read to pick which half to emit.
pub const ROLE_ENV: &str = "DOXA_ROLE";
/// The lib target's root file, absolute: where `doxa::prelude!()` declares the modules below.
pub const LIB_ENV: &str = "DOXA_LIB";
/// The `server_only` directories, as comma-separated module names.
pub const SERVER_ONLY_ENV: &str = "DOXA_SERVER_ONLY";
/// The `client_only` directories, as comma-separated module names.
pub const CLIENT_ONLY_ENV: &str = "DOXA_CLIENT_ONLY";
/// `[package.metadata.doxa] service`: the package whose service the crate's entities belong to.
pub const SERVICE_ENV: &str = "DOXA_SERVICE";
/// `[package.metadata.doxa] tenant_field`: the `route` span's field for the caller's tenant.
pub const TENANT_FIELD_ENV: &str = "DOXA_TENANT_FIELD";

/// The native target a build is for: `desktop`, `ios` or `android`. doxa sets it for the page's
/// wasm and the desktop shell; mobile shells are recognised by their `target_os`.
pub const TARGET_ENV: &str = "DOXA_TARGET";

/// A native shell target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// macOS, Windows or Linux.
    Desktop,
    /// iOS.
    Ios,
    /// Android.
    Android,
}

impl Target {
    /// The `cfg`s a build for this target gets.
    pub fn cfgs(self) -> &'static [&'static str] {
        match self {
            Target::Desktop => &["doxa_native", "doxa_desktop"],
            Target::Ios => &["doxa_native", "doxa_mobile", "doxa_ios"],
            Target::Android => &["doxa_native", "doxa_mobile", "doxa_android"],
        }
    }

    /// `desktop`, `ios` or `android`.
    pub fn as_str(self) -> &'static str {
        match self {
            Target::Desktop => "desktop",
            Target::Ios => "ios",
            Target::Android => "android",
        }
    }

    /// Parses `desktop`, `ios` or `android`.
    pub fn parse(s: &str) -> Option<Target> {
        match s {
            "desktop" => Some(Target::Desktop),
            "ios" => Some(Target::Ios),
            "android" => Some(Target::Android),
            _ => None,
        }
    }

    /// The target of this build: `$DOXA_TARGET`, else an iOS/Android `target_os`.
    fn of(doxa_target: Option<&str>, target_os: &str) -> Result<Option<Target>, String> {
        match doxa_target.filter(|t| !t.is_empty()) {
            Some(t) => Target::parse(t).map(Some).ok_or_else(|| {
                format!("`{TARGET_ENV}={t}`: expected `desktop`, `ios` or `android`")
            }),
            None => Ok(match target_os {
                "ios" => Some(Target::Ios),
                "android" => Some(Target::Android),
                _ => None,
            }),
        }
    }
}

/// Emits this build's `doxa_native`-family cfgs, which `#[doxa::native]` and its siblings test.
/// Panics on a bad `$DOXA_TARGET`.
pub fn target_cfgs() -> Option<Target> {
    println!(
        "cargo::rustc-check-cfg=cfg(doxa_native, doxa_desktop, doxa_mobile, doxa_ios, doxa_android)"
    );
    println!("cargo::rerun-if-env-changed={TARGET_ENV}");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target = Target::of(std::env::var(TARGET_ENV).ok().as_deref(), &os)
        .unwrap_or_else(|e| panic!("{e}"));
    for cfg in target.map(Target::cfgs).unwrap_or_default() {
        println!("cargo::rustc-cfg={cfg}");
    }
    target
}

/// Build this crate as the client half: routes become typed HTTP calls. With `--features native`
/// on a native target, it is also the app's shell; see [`Client`].
pub fn client() {
    Client::new().build();
}

/// [`client`], with the app's own shell commands.
#[derive(Debug, Default)]
pub struct Client {
    commands: &'static [&'static str],
}

impl Client {
    /// The defaults [`client`] uses.
    pub fn new() -> Self {
        Self::default()
    }

    /// The app's `#[tauri::command]`s the page may call; each gets an `allow-<command>`.
    pub fn commands(mut self, commands: &'static [&'static str]) -> Self {
        self.commands = commands;
        self
    }

    /// Emits the build. Panics when a native shell build can't be set up.
    pub fn build(self) {
        emit("client");
        println!("cargo::rustc-cfg=doxa_client");
        let target = target_cfgs();
        let shell = target.is_some()
            && std::env::var_os("CARGO_FEATURE_NATIVE").is_some()
            && std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("wasm32");
        if !shell {
            return;
        }
        #[cfg(feature = "native-build")]
        native::shell(self.commands);
        #[cfg(not(feature = "native-build"))]
        panic!(
            "building the native shell needs `doxa-role = {{ features = [\"native-build\"] }}` in \
             [build-dependencies]"
        );
    }
}

/// Build this crate for both halves: routes serve off wasm and are calls everywhere.
///
/// Panics on a bad `server_only` / `client_only` in `[package.metadata.doxa]`.
pub fn api() {
    emit("api");
    target_cfgs();
    let split = manifest();
    println!("cargo::rustc-env={LIB_ENV}={}", split.lib.display());
    println!(
        "cargo::rustc-env={SERVER_ONLY_ENV}={}",
        split.server.join(",")
    );
    println!(
        "cargo::rustc-env={CLIENT_ONLY_ENV}={}",
        split.client.join(",")
    );
    if let Some(service) = &split.service {
        println!("cargo::rustc-env={SERVICE_ENV}={service}");
    }
}

/// Build this crate as the server half. The default; only needed to say so, or to read
/// `[package.metadata.doxa] tenant_field`.
pub fn server() {
    emit("server");
    manifest();
}

/// Reads `[package.metadata.doxa]` and emits the keys every half shares.
fn manifest() -> Split {
    println!("cargo::rerun-if-changed=Cargo.toml");
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("run from build.rs"));
    let manifest = std::fs::read_to_string(dir.join("Cargo.toml")).expect("read Cargo.toml");
    let split = Split::read(&dir, &manifest).unwrap_or_else(|e| panic!("{e}"));
    if let Some(field) = &split.tenant_field {
        println!("cargo::rustc-env={TENANT_FIELD_ENV}={field}");
    }
    split
}

fn emit(role: &str) {
    println!("cargo::rustc-env={ROLE_ENV}={role}");
    println!("cargo::rustc-check-cfg=cfg(doxa_client)");
    println!("cargo::rerun-if-changed=build.rs");
}

/// An API crate's lib root and the directories beside it that only one half compiles.
#[derive(Debug, PartialEq, Eq)]
struct Split {
    lib: PathBuf,
    server: Vec<String>,
    client: Vec<String>,
    service: Option<String>,
    tenant_field: Option<String>,
}

impl Split {
    fn read(dir: &Path, manifest: &str) -> Result<Split, String> {
        let table: toml::Table = manifest
            .parse()
            .map_err(|e| format!("Cargo.toml doesn't parse: {e}"))?;
        let lib = table
            .get("lib")
            .and_then(|l| l.get("path"))
            .and_then(|p| p.as_str())
            .unwrap_or("src/lib.rs");
        let lib = dir.join(lib);
        let doxa = table
            .get("package")
            .and_then(|p| p.get("metadata"))
            .and_then(|m| m.get("doxa"));
        let list = |key: &str| -> Result<Vec<String>, String> {
            let Some(value) = doxa.and_then(|d| d.get(key)) else {
                return Ok(Vec::new());
            };
            let entries = value.as_array().ok_or_else(|| {
                format!("`[package.metadata.doxa] {key}` is a list of directories")
            })?;
            entries
                .iter()
                .map(|e| {
                    let e = e.as_str().ok_or_else(|| {
                        format!("`[package.metadata.doxa] {key}` lists directories as strings")
                    })?;
                    module(dir, &lib, key, e)
                })
                .collect()
        };
        let server = list("server_only")?;
        let client = list("client_only")?;
        let mut all: Vec<&String> = server.iter().chain(&client).collect();
        all.sort();
        if let Some(pair) = all.windows(2).find(|p| p[0] == p[1]) {
            return Err(format!(
                "`{}` is listed twice in `[package.metadata.doxa]`: a directory belongs to one half",
                pair[0]
            ));
        }
        let service = match doxa.and_then(|d| d.get("service")) {
            None => None,
            Some(v) => Some(
                v.as_str()
                    .ok_or("`[package.metadata.doxa] service` is a package name")?
                    .to_owned(),
            ),
        };
        let tenant_field = match doxa.and_then(|d| d.get("tenant_field")) {
            None => None,
            Some(v) => Some(
                v.as_str()
                    .filter(|f| is_ident(f))
                    .ok_or("`[package.metadata.doxa] tenant_field` is a Rust identifier")?
                    .to_owned(),
            ),
        };
        Ok(Split {
            lib,
            server,
            client,
            service,
            tenant_field,
        })
    }
}

/// The module name of `entry`, a directory beside the lib root holding a `mod.rs`.
fn module(dir: &Path, lib: &Path, key: &str, entry: &str) -> Result<String, String> {
    let path = dir.join(entry);
    let beside = path.parent().map(Path::to_path_buf) == lib.parent().map(Path::to_path_buf);
    if !beside {
        return Err(format!(
            "`{key}` lists `{entry}`, which isn't beside `{}`: doxa declares it as a module of \
             the crate root",
            lib.strip_prefix(dir).unwrap_or(lib).display()
        ));
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| is_ident(n))
        .ok_or_else(|| format!("`{key}` lists `{entry}`, whose name isn't a Rust identifier"))?;
    if !path.join("mod.rs").is_file() {
        return Err(format!("`{key}` lists `{entry}`, which has no `mod.rs`"));
    }
    Ok(name.to_owned())
}

fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    chars
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crate_with(dirs: &[&str]) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "doxa-role-{}-{}",
            std::process::id(),
            dirs.join("-").replace('/', "_")
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        for d in dirs {
            std::fs::create_dir_all(root.join(d)).unwrap();
            std::fs::write(root.join(d).join("mod.rs"), "").unwrap();
        }
        root
    }

    #[test]
    fn lists_directories_beside_the_lib_as_modules() {
        let root = crate_with(&["src/server", "src/browser"]);
        let split = Split::read(
            &root,
            "[package.metadata.doxa]\nserver_only = [\"src/server\"]\nclient_only = [\"src/browser\"]",
        )
        .unwrap();
        assert_eq!(
            split,
            Split {
                lib: root.join("src/lib.rs"),
                server: vec!["server".into()],
                client: vec!["browser".into()],
                service: None,
                tenant_field: None,
            }
        );
    }

    #[test]
    fn names_the_route_span_s_tenant_field() {
        let root = crate_with(&[]);
        let read = |toml: &str| Split::read(&root, toml);
        let split = read("[package.metadata.doxa]\ntenant_field = \"company_id\"").unwrap();
        assert_eq!(split.tenant_field.as_deref(), Some("company_id"));
        assert!(
            read("[package.metadata.doxa]\ntenant_field = \"company id\"")
                .unwrap_err()
                .contains("identifier")
        );
        assert!(read("[package.metadata.doxa]\ntenant_field = 1").is_err());
    }

    #[test]
    fn names_the_service_its_entities_belong_to() {
        let root = crate_with(&[]);
        let read = |toml: &str| Split::read(&root, toml);
        let split = read("[package.metadata.doxa]\nservice = \"shop-api\"").unwrap();
        assert_eq!(split.service.as_deref(), Some("shop-api"));
        assert!(read("[package.metadata.doxa]\nservice = 1").is_err());
    }

    #[test]
    fn no_lists_split_nothing() {
        let root = crate_with(&[]);
        let split = Split::read(&root, "[package]\nname = \"a\"").unwrap();
        assert!(split.server.is_empty() && split.client.is_empty());
    }

    #[test]
    fn refuses_a_directory_it_cant_declare() {
        let root = crate_with(&["src/a/server", "src/no-ident"]);
        std::fs::create_dir_all(root.join("src/empty")).unwrap();
        let err = |toml: &str| Split::read(&root, toml).unwrap_err();
        assert!(
            err("[package.metadata.doxa]\nserver_only = [\"src/a/server\"]")
                .contains("isn't beside")
        );
        assert!(
            err("[package.metadata.doxa]\nserver_only = [\"src/no-ident\"]").contains("identifier")
        );
        assert!(err("[package.metadata.doxa]\nserver_only = [\"src/empty\"]").contains("mod.rs"));
        assert!(err("[package.metadata.doxa]\nserver_only = \"src/a\"").contains("list"));
    }

    #[test]
    fn the_target_comes_from_doxa_target_else_a_mobile_target_os() {
        assert_eq!(Target::of(None, "macos"), Ok(None));
        assert_eq!(Target::of(Some(""), "linux"), Ok(None));
        assert_eq!(Target::of(None, "ios"), Ok(Some(Target::Ios)));
        assert_eq!(Target::of(None, "android"), Ok(Some(Target::Android)));
        assert_eq!(
            Target::of(Some("desktop"), "unknown"),
            Ok(Some(Target::Desktop))
        );
        assert_eq!(Target::of(Some("ios"), "unknown"), Ok(Some(Target::Ios)));
        assert!(Target::of(Some("tvos"), "macos")
            .unwrap_err()
            .contains("expected"));
    }

    #[test]
    fn every_target_is_native_and_mobile_ones_are_mobile() {
        assert_eq!(Target::Desktop.cfgs(), ["doxa_native", "doxa_desktop"]);
        assert_eq!(
            Target::Ios.cfgs(),
            ["doxa_native", "doxa_mobile", "doxa_ios"]
        );
        assert_eq!(
            Target::Android.cfgs(),
            ["doxa_native", "doxa_mobile", "doxa_android"]
        );
    }

    #[test]
    fn refuses_a_directory_in_both_halves() {
        let root = crate_with(&["src/shared"]);
        let err = Split::read(
            &root,
            "[package.metadata.doxa]\nserver_only = [\"src/shared\"]\nclient_only = [\"src/shared\"]",
        )
        .unwrap_err();
        assert!(err.contains("twice"), "{err}");
    }
}
