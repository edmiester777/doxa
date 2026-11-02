//! The app's shape, read from `cargo metadata` and `[package.metadata.doxa]`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use crate::error::{Error, Result};

/// `[package.metadata.doxa]` on the web crate.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoxaConfig {
    /// `"client"` marks the crate that compiles to wasm.
    pub role: Option<String>,
    /// The server package `doxa dev` runs.
    pub server: Option<String>,
    /// Stylesheet entries, relative to the web crate.
    #[serde(default)]
    pub css: Vec<String>,
    /// Extra directories Tailwind scans, relative to the web crate.
    #[serde(default)]
    pub css_sources: Vec<String>,
    /// A directory copied into the dist as-is, relative to the web crate.
    pub public: Option<String>,
    /// npm dependencies, name to version range.
    #[serde(default)]
    pub npm: BTreeMap<String, String>,
    /// A release build fails when the optimized app wasm is larger, in KiB.
    pub wasm_budget_kb: Option<u64>,
    /// Client crate to base URL, written to `services.json`; unlisted ones are same-origin.
    #[serde(default)]
    pub services: BTreeMap<String, String>,
    /// Stylesheet extension (`scss`) to the command that turns it into CSS.
    #[serde(default)]
    pub preprocess: BTreeMap<String, Preprocess>,
}

/// A command run on each `css` entry with its extension, before Tailwind and bundling.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preprocess {
    /// The program and its arguments; `{input}` and `{output}` become file paths.
    pub command: Vec<String>,
    /// Globs, relative to the web crate, whose changes rebuild stylesheets in `doxa dev`.
    #[serde(default)]
    pub watch: Vec<String>,
}

/// The workspace as `cargo metadata --no-deps` describes it.
#[derive(Debug, Clone, Deserialize)]
pub struct Workspace {
    /// The workspace root.
    pub workspace_root: PathBuf,
    /// Cargo's target directory.
    pub target_directory: PathBuf,
    /// Every workspace member.
    pub packages: Vec<Package>,
}

/// One workspace member.
#[derive(Debug, Clone, Deserialize)]
pub struct Package {
    /// Package name.
    pub name: String,
    /// Path to its `Cargo.toml`.
    pub manifest_path: PathBuf,
    /// Its build targets.
    pub targets: Vec<Target>,
    /// Its dependencies.
    #[serde(default)]
    pub dependencies: Vec<Dependency>,
    /// `[package.metadata]`.
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// A build target of a [`Package`].
#[derive(Debug, Clone, Deserialize)]
pub struct Target {
    /// Target name.
    pub name: String,
    /// Target kinds, e.g. `lib`, `cdylib`, `bin`.
    pub kind: Vec<String>,
    /// The target's root source file.
    pub src_path: PathBuf,
}

/// A dependency of a [`Package`].
#[derive(Debug, Clone, Deserialize)]
pub struct Dependency {
    /// Package name.
    pub name: String,
    /// Set for path dependencies.
    pub path: Option<PathBuf>,
}

/// The crate `doxa build` compiles to wasm.
#[derive(Debug, Clone)]
pub struct WebCrate {
    /// Package name.
    pub name: String,
    /// Directory holding its `Cargo.toml`.
    pub dir: PathBuf,
    /// Its library name, as the `.wasm` file is named.
    pub lib_name: String,
    /// Its `[package.metadata.doxa]`.
    pub config: DoxaConfig,
}

impl Package {
    /// Directory holding the manifest.
    pub fn dir(&self) -> &Path {
        self.manifest_path.parent().unwrap_or(Path::new("."))
    }

    /// `[package.metadata.doxa]`, if present.
    pub fn doxa(&self) -> Result<Option<DoxaConfig>> {
        match self.metadata.get("doxa") {
            None => Ok(None),
            Some(v) => serde_json::from_value(v.clone()).map(Some).map_err(|e| {
                Error::config(
                    format!(
                        "[package.metadata.doxa] in {}: {e}",
                        self.manifest_path.display()
                    ),
                    "keys are role, server, css, css_sources, public, wasm_budget_kb, and npm, services and preprocess tables",
                )
            }),
        }
    }
}

impl Workspace {
    /// Run `cargo metadata` from `cwd`.
    pub fn load(cwd: &Path) -> Result<Self> {
        let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
        cmd.args(["metadata", "--format-version", "1", "--no-deps"])
            .current_dir(cwd);
        let out = cmd.output().map_err(|e| {
            Error::tool(
                "cargo",
                &cmd,
                format!("could not start: {e}"),
                "install Rust from https://rustup.rs",
            )
        })?;
        if !out.status.success() {
            return Err(Error::tool(
                "cargo",
                &cmd,
                String::from_utf8_lossy(&out.stderr).trim().to_owned(),
                "run doxa from inside a cargo workspace",
            ));
        }
        Self::from_json(&String::from_utf8_lossy(&out.stdout))
            .map_err(|e| Error::tool("cargo", &cmd, e.to_string(), "upgrade cargo"))
    }

    /// Parse `cargo metadata --format-version 1` output.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// A member by name.
    pub fn package(&self, name: &str) -> Option<&Package> {
        self.packages.iter().find(|p| p.name == name)
    }

    /// `name`, or else the one member whose metadata says `role = "client"`.
    pub fn web_crate(&self, name: Option<&str>) -> Result<WebCrate> {
        let pkg = match name {
            Some(name) => self.package(name).ok_or_else(|| {
                Error::config(
                    format!("no package `{name}` in the workspace"),
                    "pass the web crate's package name to -p",
                )
            })?,
            None => {
                let mut candidates = Vec::new();
                for p in &self.packages {
                    if p.doxa()?.and_then(|c| c.role).as_deref() == Some("client") {
                        candidates.push(p);
                    }
                }
                match candidates.as_slice() {
                    [one] => *one,
                    [] => return Err(Error::config(
                        "no crate in the workspace has [package.metadata.doxa] role = \"client\"",
                        "add it to the web crate's Cargo.toml, or pass -p <web-crate>",
                    )),
                    many => {
                        let names: Vec<_> = many.iter().map(|p| p.name.as_str()).collect();
                        return Err(Error::config(
                            format!("several client crates: {}", names.join(", ")),
                            "pick one with -p <web-crate>",
                        ));
                    }
                }
            }
        };
        let lib = pkg
            .targets
            .iter()
            .find(|t| t.kind.iter().any(|k| k == "cdylib"))
            .ok_or_else(|| {
                Error::config(
                    format!("`{}` has no cdylib target", pkg.name),
                    "add [lib] crate-type = [\"cdylib\", \"rlib\"] to its Cargo.toml",
                )
            })?;
        Ok(WebCrate {
            name: pkg.name.clone(),
            dir: pkg.dir().to_owned(),
            lib_name: lib.name.replace('-', "_"),
            config: pkg.doxa()?.unwrap_or_default(),
        })
    }

    /// Directories whose sources feed `name`: its own, its targets', and those of
    /// its workspace path dependencies, transitively.
    pub fn source_dirs(&self, name: &str) -> Vec<PathBuf> {
        let mut seen = Vec::<&str>::new();
        let mut stack = vec![name];
        let mut dirs = Vec::new();
        while let Some(n) = stack.pop() {
            if seen.contains(&n) {
                continue;
            }
            seen.push(n);
            let Some(p) = self.package(n) else { continue };
            dirs.push(p.dir().to_owned());
            for t in &p.targets {
                if let Some(d) = t.src_path.parent() {
                    if !d.starts_with(p.dir()) {
                        dirs.push(d.to_owned());
                    }
                }
            }
            stack.extend(
                p.dependencies
                    .iter()
                    .filter(|d| d.path.is_some())
                    .map(|d| d.name.as_str()),
            );
        }
        dirs.sort();
        dirs.dedup();
        dirs
    }

    /// Where doxa keeps its outputs.
    pub fn layout(&self) -> Layout {
        Layout {
            root: self.target_directory.join("doxa"),
        }
    }
}

/// Directories under `target/doxa`.
#[derive(Debug, Clone)]
pub struct Layout {
    /// `target/doxa`.
    pub root: PathBuf,
}

impl Layout {
    /// `CARGO_TARGET_DIR` for the wasm build, apart from the server's.
    pub fn wasm_target(&self) -> PathBuf {
        self.root.join("wasm")
    }
    /// Where synced npm dependencies are installed.
    pub fn js(&self) -> PathBuf {
        self.root.join("js")
    }
    /// Intermediate outputs.
    pub fn stage(&self) -> PathBuf {
        self.root.join("stage")
    }
    /// The served output.
    pub fn dist(&self) -> PathBuf {
        self.root.join("dist")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const METADATA: &str = r#"{
      "workspace_root": "/app",
      "target_directory": "/app/target",
      "packages": [
        {"name": "app-api", "manifest_path": "/app/api/Cargo.toml",
         "targets": [{"name": "app_api", "kind": ["lib"], "src_path": "/app/api/src/lib.rs"}],
         "dependencies": [{"name": "doxa", "path": null}], "metadata": null},
        {"name": "app-client", "manifest_path": "/app/client/Cargo.toml",
         "targets": [{"name": "app_client", "kind": ["lib"], "src_path": "/app/api/src/lib.rs"}],
         "dependencies": [], "metadata": null},
        {"name": "app-web", "manifest_path": "/app/web/Cargo.toml",
         "targets": [{"name": "app-web", "kind": ["cdylib", "rlib"], "src_path": "/app/web/src/lib.rs"}],
         "dependencies": [{"name": "app-client", "path": "/app/client"}],
         "metadata": {"doxa": {"role": "client", "server": "app-server", "css": ["style/app.css"],
                      "public": "public", "npm": {"react": "^19"}}}},
        {"name": "app-server", "manifest_path": "/app/server/Cargo.toml",
         "targets": [{"name": "app-server", "kind": ["bin"], "src_path": "/app/server/src/main.rs"}],
         "dependencies": [{"name": "app-api", "path": "/app/api"}], "metadata": null}
      ]
    }"#;

    #[test]
    fn finds_the_client_crate_and_its_config() {
        let ws = Workspace::from_json(METADATA).unwrap();
        let web = ws.web_crate(None).unwrap();
        assert_eq!(web.name, "app-web");
        assert_eq!(web.lib_name, "app_web");
        assert_eq!(web.dir, Path::new("/app/web"));
        assert_eq!(web.config.server.as_deref(), Some("app-server"));
        assert_eq!(web.config.css, ["style/app.css"]);
        assert_eq!(web.config.npm["react"], "^19");
        assert!(web.config.css_sources.is_empty());
        assert_eq!(ws.layout().dist(), Path::new("/app/target/doxa/dist"));
    }

    #[test]
    fn a_named_crate_needs_a_cdylib() {
        let ws = Workspace::from_json(METADATA).unwrap();
        let err = ws.web_crate(Some("app-api")).unwrap_err().to_string();
        assert!(err.contains("cdylib"), "{err}");
        assert!(ws.web_crate(Some("nope")).is_err());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let json = METADATA.replace("\"public\": \"public\"", "\"publik\": \"public\"");
        let ws = Workspace::from_json(&json).unwrap();
        let err = ws.web_crate(None).unwrap_err().to_string();
        assert!(err.contains("publik"), "{err}");
    }

    #[test]
    fn source_dirs_follow_path_dependencies() {
        let ws = Workspace::from_json(METADATA).unwrap();
        let web = ws.source_dirs("app-web");
        assert!(web.contains(&PathBuf::from("/app/web")));
        assert!(web.contains(&PathBuf::from("/app/client")));
        assert!(web.contains(&PathBuf::from("/app/api/src")));
        let server = ws.source_dirs("app-server");
        assert_eq!(
            server,
            [PathBuf::from("/app/api"), PathBuf::from("/app/server")]
        );
    }
}
