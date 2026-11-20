//! The app's shape, read from `cargo metadata` and `[package.metadata.doxa]`.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use crate::error::{Error, Result};

/// `[package.metadata.doxa]` on the web crate.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoxaConfig {
    /// `"client"` marks the crate that compiles to wasm; `"server"`, the server of a workspace without one.
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
    /// The path the app is served under, e.g. `/docs/`; `/` when unset.
    pub base: Option<String>,
    /// npm dependencies, name to version range.
    #[serde(default)]
    pub npm: BTreeMap<String, String>,
    /// A release build fails when the optimized app wasm is larger, in KiB.
    pub wasm_budget_kb: Option<u64>,
    /// A release build fails when any module split off for a `#[page(lazy)]` is larger, in KiB.
    pub chunk_budget_kb: Option<u64>,
    /// Client crate to base URL, written to `services.json`; unlisted ones are same-origin.
    #[serde(default)]
    pub services: BTreeMap<String, String>,
    /// Stylesheet extension (`scss`) to the command that turns it into CSS.
    #[serde(default)]
    pub preprocess: BTreeMap<String, Preprocess>,
    /// The npm package `doxa build --lib` writes from the `#[component(export)]` components.
    pub library: Option<Library>,
    /// Path prefix to the upstream `doxa dev` forwards it to.
    #[serde(default)]
    pub proxy: BTreeMap<String, Upstream>,
    /// In an API crate, directories beside the lib root that only the server compiles.
    #[serde(default)]
    pub server_only: Vec<String>,
    /// In an API crate, directories beside the lib root that only the browser compiles.
    #[serde(default)]
    pub client_only: Vec<String>,
    /// The service a types crate's entities and actions belong to, when it isn't this package.
    pub service: Option<String>,
    /// How `doxa dev` runs this package.
    pub dev: Option<DevConfig>,
    /// The tenant column; `doxa-role` passes it to the macros as `DOXA_TENANT_FIELD`.
    pub tenant_field: Option<String>,
}

/// `[package.metadata.doxa.dev]`: `port = 8081`, and `bin` when the package has several.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevConfig {
    /// The port `doxa dev` starts it on.
    pub port: u16,
    /// The binary to run; inferred when the package has exactly one.
    pub bin: Option<String>,
}

/// A `[workspace.metadata.doxa.dev.services]` entry: `api = { path = "../api" }`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevService {
    /// The service's workspace root.
    pub path: PathBuf,
    /// Services that listen before this one first launches, and build first when builds are serial.
    #[serde(default)]
    pub after: Vec<String>,
}

/// `"/reports" = { to = "http://localhost:3100", env = "REPORTS_URL", strip = true }`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// The upstream's URL, unless `env` or `service` gives one.
    pub to: Option<String>,
    /// An environment variable holding the upstream's URL, which wins over the rest.
    pub env: Option<String>,
    /// A `[workspace.metadata.doxa.dev.services]` entry whose dev port this forwards to.
    pub service: Option<String>,
    /// Leave the prefix off the forwarded path.
    #[serde(default)]
    pub strip: bool,
}

/// `library = { name = "@acme/kit", scope = ".kit-root" }`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Library {
    /// The npm package name.
    pub name: String,
    /// A selector every stylesheet rule is scoped under, so the host's page is untouched.
    pub scope: Option<String>,
    /// How React is had: `"peer"`, the host's own, is the only kind.
    pub react: Option<String>,
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
    /// `[workspace.metadata]`.
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// One workspace member.
#[derive(Debug, Clone, Deserialize)]
pub struct Package {
    /// Package name.
    pub name: String,
    /// Package version.
    #[serde(default)]
    pub version: String,
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
    /// `default-run`.
    #[serde(default)]
    pub default_run: Option<String>,
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
    /// Package version.
    pub version: String,
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
                    "keys are role, server, css, css_sources, public, base, wasm_budget_kb, chunk_budget_kb, library, server_only, client_only, service, tenant_field, and npm, services, preprocess, proxy and dev tables",
                )
            }),
        }
    }

    /// `[package.metadata.doxa.dev]` alone, so a sibling on another doxa revision still loads.
    pub fn dev(&self) -> Result<Option<DevConfig>> {
        let Some(v) = self.metadata.pointer("/doxa/dev") else {
            return Ok(None);
        };
        serde_json::from_value(v.clone()).map(Some).map_err(|e| {
            Error::config(
                format!(
                    "[package.metadata.doxa.dev] in {}: {e}",
                    self.manifest_path.display()
                ),
                "keys are port and bin",
            )
        })
    }

    /// `bin`, else `default-run`, else the package's only `bin` target.
    pub fn dev_bin(&self, bin: Option<&str>) -> Result<String> {
        if let Some(bin) = bin.or(self.default_run.as_deref()) {
            return Ok(bin.to_owned());
        }
        let bins: Vec<_> = self
            .targets
            .iter()
            .filter(|t| t.kind.iter().any(|k| k == "bin"))
            .map(|t| t.name.as_str())
            .collect();
        match bins.as_slice() {
            [one] => Ok((*one).to_owned()),
            _ => Err(Error::config(
                format!("`{}` has {} binaries", self.name, bins.len()),
                "set [package.metadata.doxa.dev] bin = \"<name>\"",
            )),
        }
    }

    /// The directories `key` (`server_only` or `client_only`) names, absolute.
    fn sided(&self, key: &str) -> Vec<PathBuf> {
        let dirs = self.metadata.pointer(&format!("/doxa/{key}"));
        dirs.and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter_map(|d| d.as_str())
            .map(|d| self.dir().join(d))
            .collect()
    }
}

impl Workspace {
    /// Run `cargo metadata` from `cwd`.
    pub fn load(cwd: &Path) -> Result<Self> {
        let cargo = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
        Self::load_with(cwd, "run doxa from inside a cargo workspace", cargo)
    }

    /// `cargo metadata` in another workspace, with its own toolchain rather than ours.
    pub fn load_sibling(root: &Path, hint: &str) -> Result<Self> {
        if !root.join("Cargo.toml").is_file() {
            return Err(Error::config(
                format!("{} has no Cargo.toml", root.display()),
                hint,
            ));
        }
        Self::load_with(root, hint, sibling_cargo())
    }

    fn load_with(cwd: &Path, hint: &str, mut cmd: Command) -> Result<Self> {
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
                hint,
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
                let candidates = self.with_role("client")?;
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
            version: pkg.version.clone(),
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

    /// Every member's `server_only` and `client_only` directories, absolute.
    pub fn sided_dirs(&self) -> (Vec<PathBuf>, Vec<PathBuf>) {
        let (mut server, mut client) = (Vec::new(), Vec::new());
        for p in &self.packages {
            server.extend(p.sided("server_only"));
            client.extend(p.sided("client_only"));
        }
        (server, client)
    }

    /// `[workspace.metadata.doxa.dev.services]` in build order, paths made absolute.
    pub fn dev_services(&self) -> Result<Vec<(String, DevService)>> {
        let Some(v) = self.metadata.pointer("/doxa/dev/services") else {
            return Ok(Vec::new());
        };
        let mut services: BTreeMap<String, DevService> = serde_json::from_value(v.clone())
            .map_err(|e| {
                Error::config(
                    format!("[workspace.metadata.doxa.dev.services]: {e}"),
                    "write each entry as name = { path = \"../repo\" }",
                )
            })?;
        for s in services.values_mut() {
            s.path = self.workspace_root.join(&s.path);
        }
        build_order(services)
    }

    /// `[workspace.metadata.doxa.dev.patch]`: `name = "../repo"`, paths made absolute.
    pub fn dev_patches(&self) -> Result<Vec<(String, PathBuf)>> {
        let Some(v) = self.metadata.pointer("/doxa/dev/patch") else {
            return Ok(Vec::new());
        };
        let table: BTreeMap<String, PathBuf> = serde_json::from_value(v.clone()).map_err(|e| {
            Error::config(
                format!("[workspace.metadata.doxa.dev.patch]: {e}"),
                "write each entry as name = \"../repo\"",
            )
        })?;
        Ok(table
            .into_iter()
            .map(|(name, path)| (name, self.workspace_root.join(path)))
            .collect())
    }

    /// The members whose `[package.metadata.doxa]` has `role = role`.
    fn with_role(&self, role: &str) -> Result<Vec<&Package>> {
        let mut found = Vec::new();
        for p in &self.packages {
            if p.doxa()?.and_then(|c| c.role).as_deref() == Some(role) {
                found.push(p);
            }
        }
        Ok(found)
    }

    /// Whether a member has `role = "client"`.
    pub fn has_client(&self) -> Result<bool> {
        Ok(!self.with_role("client")?.is_empty())
    }

    /// The one member with `role = "server"`.
    pub fn server_crate(&self) -> Result<&Package> {
        match self.with_role("server")?.as_slice() {
            [one] => Ok(one),
            [] => Err(Error::config(
                "no crate in the workspace has [package.metadata.doxa] role = \"client\" or \"server\"",
                "add role = \"server\" to the server crate's Cargo.toml",
            )),
            many => {
                let names: Vec<_> = many.iter().map(|p| p.name.as_str()).collect();
                Err(Error::config(
                    format!("several server crates: {}", names.join(", ")),
                    "keep role = \"server\" on one",
                ))
            }
        }
    }

    /// `[workspace.metadata.doxa.dev] max_parallel_build`: how many startup builds run at once.
    pub fn max_parallel_build(&self) -> Result<Option<NonZeroUsize>> {
        let Some(v) = self.metadata.pointer("/doxa/dev/max_parallel_build") else {
            return Ok(None);
        };
        serde_json::from_value(v.clone()).map(Some).map_err(|e| {
            Error::config(
                format!("[workspace.metadata.doxa.dev] max_parallel_build: {e}"),
                "set it to a whole number, 1 or more",
            )
        })
    }

    /// Where doxa keeps its outputs.
    pub fn layout(&self) -> Layout {
        let root = self.target_directory.join("doxa");
        Layout {
            work: root.clone(),
            root,
        }
    }
}

/// Each service after those its `after` names; ties in name order.
fn build_order(mut services: BTreeMap<String, DevService>) -> Result<Vec<(String, DevService)>> {
    const TABLE: &str = "[workspace.metadata.doxa.dev.services]";
    for (name, s) in &services {
        if let Some(missing) = s.after.iter().find(|a| !services.contains_key(*a)) {
            return Err(Error::config(
                format!("{TABLE} {name}: after names `{missing}`, which isn't listed"),
                "name only entries of this table in `after`",
            ));
        }
    }
    let mut order = Vec::with_capacity(services.len());
    while !services.is_empty() {
        let ready = services
            .iter()
            .find(|(_, s)| s.after.iter().all(|a| !services.contains_key(a)))
            .map(|(name, _)| name.clone());
        let Some(name) = ready else {
            let left: Vec<&str> = services.keys().map(String::as_str).collect();
            return Err(Error::config(
                format!("{TABLE}: `after` loops among {}", left.join(", ")),
                "remove one `after` entry from the loop",
            ));
        };
        let s = services.remove(&name).expect("found above");
        order.push((name, s));
    }
    Ok(order)
}

/// `cargo` for another workspace: from `PATH`, so its own `rust-toolchain.toml` applies.
pub fn sibling_cargo() -> Command {
    let mut cmd = Command::new("cargo");
    cmd.env_remove("CARGO").env_remove("RUSTUP_TOOLCHAIN");
    cmd
}

/// Directories under `target/doxa`.
#[derive(Debug, Clone)]
pub struct Layout {
    /// `target/doxa`.
    pub root: PathBuf,
    /// Holds a build's wasm target and stage.
    pub work: PathBuf,
}

impl Layout {
    /// This layout with its own wasm target and stage, so its build can run beside another's.
    pub fn apart(mut self, name: &str) -> Self {
        self.work = self.root.join(name);
        self
    }
    /// `CARGO_TARGET_DIR` for the wasm build, apart from the server's.
    pub fn wasm_target(&self) -> PathBuf {
        self.work.join("wasm")
    }
    /// Where synced npm dependencies are installed.
    pub fn js(&self) -> PathBuf {
        self.root.join("js")
    }
    /// Intermediate outputs.
    pub fn stage(&self) -> PathBuf {
        self.work.join("stage")
    }
    /// The served output.
    pub fn dist(&self) -> PathBuf {
        self.root.join("dist")
    }
    /// The `#[story]` gallery `doxa gallery` serves.
    pub fn gallery(&self) -> PathBuf {
        self.root.join("gallery")
    }
    /// The npm package `doxa build --lib` writes.
    pub fn lib(&self) -> PathBuf {
        self.root.join("lib")
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
    fn the_patch_table_resolves_against_the_root_and_role_server_finds_one_crate() {
        let mut ws = Workspace::from_json(METADATA).unwrap();
        assert!(ws.dev_patches().unwrap().is_empty());
        assert!(ws.has_client().unwrap());
        assert!(ws.server_crate().is_err());
        ws.metadata = serde_json::json!({"doxa": {"dev": {"patch": {"ledger": "../ledger"}}}});
        assert_eq!(
            ws.dev_patches().unwrap(),
            [("ledger".to_owned(), PathBuf::from("/app/../ledger"))]
        );
        ws.packages[3].metadata = serde_json::json!({"doxa": {"role": "server"}});
        assert_eq!(ws.server_crate().unwrap().name, "app-server");
        ws.packages[0].metadata = serde_json::json!({"doxa": {"role": "server"}});
        assert!(ws.server_crate().is_err());
    }

    #[test]
    fn a_proxy_table_names_each_upstream() {
        let config: DoxaConfig = serde_json::from_value(serde_json::json!({
            "proxy": { "/reports": { "to": "http://a", "env": "A", "strip": true }, "/api": { "env": "B" } }
        }))
        .unwrap();
        let reports = &config.proxy["/reports"];
        assert_eq!(reports.to.as_deref(), Some("http://a"));
        assert_eq!(reports.env.as_deref(), Some("A"));
        assert!(reports.strip);
        assert!(!config.proxy["/api"].strip);
    }

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
        assert!(web.config.proxy.is_empty());
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
    fn dev_services_resolve_against_the_workspace_root() {
        let mut ws = Workspace::from_json(METADATA).unwrap();
        assert!(ws.dev_services().unwrap().is_empty());
        ws.metadata =
            serde_json::json!({"doxa": {"dev": {"services": {"b-api": {"path": "../b"}}}}});
        let services = ws.dev_services().unwrap();
        assert_eq!(services[0].0, "b-api");
        assert_eq!(services[0].1.path, Path::new("/app/../b"));
        ws.metadata =
            serde_json::json!({"doxa": {"dev": {"services": {"b-api": {"dir": "../b"}}}}});
        assert!(ws.dev_services().unwrap_err().to_string().contains("dir"));
    }

    #[test]
    fn dev_services_build_after_what_they_name() {
        let mut ws = Workspace::from_json(METADATA).unwrap();
        let order = |ws: &mut Workspace, services: serde_json::Value| {
            ws.metadata = serde_json::json!({"doxa": {"dev": {"services": services}}});
            ws.dev_services()
                .map(|s| s.into_iter().map(|(n, _)| n).collect::<Vec<_>>())
                .map_err(|e| e.to_string())
        };
        let chain = serde_json::json!({
            "a": {"path": "a", "after": ["c"]},
            "b": {"path": "b"},
            "c": {"path": "c", "after": ["d"]},
            "d": {"path": "d"},
        });
        assert_eq!(order(&mut ws, chain).unwrap(), ["b", "d", "c", "a"]);

        let missing = serde_json::json!({"a": {"path": "a", "after": ["z"]}});
        assert!(order(&mut ws, missing).unwrap_err().contains("`z`"));

        let looped = serde_json::json!({
            "a": {"path": "a", "after": ["b"]},
            "b": {"path": "b", "after": ["a"]},
            "c": {"path": "c"},
        });
        let err = order(&mut ws, looped).unwrap_err();
        assert!(err.contains("loops among a, b"), "{err}");
    }

    #[test]
    fn max_parallel_build_reads_from_the_workspace_dev_table() {
        let mut ws = Workspace::from_json(METADATA).unwrap();
        assert_eq!(ws.max_parallel_build().unwrap(), None);
        ws.metadata = serde_json::json!({"doxa": {"dev": {"max_parallel_build": 2}}});
        assert_eq!(ws.max_parallel_build().unwrap(), NonZeroUsize::new(2));
        ws.metadata = serde_json::json!({"doxa": {"dev": {"max_parallel_build": 0}}});
        let err = ws.max_parallel_build().unwrap_err().to_string();
        assert!(err.contains("max_parallel_build"), "{err}");
    }

    #[test]
    fn a_dev_table_reads_alone_and_a_tenant_field_parses() {
        let json = METADATA.replace(
            "\"metadata\": null},\n        {\"name\": \"app-client\"",
            "\"metadata\": {\"doxa\": {\"server_only\": [\"src/server\"], \"tenant_field\": \"tenant_id\", \"someday\": 1, \"dev\": {\"port\": 8081}}}},\n        {\"name\": \"app-client\"",
        );
        let ws = Workspace::from_json(&json).unwrap();
        let api = ws.package("app-api").unwrap();
        assert_eq!(
            api.dev().unwrap(),
            Some(DevConfig {
                port: 8081,
                bin: None
            })
        );
        assert_eq!(ws.sided_dirs().0, [PathBuf::from("/app/api/src/server")]);
        let config: DoxaConfig =
            serde_json::from_value(serde_json::json!({"tenant_field": "tenant_id"})).unwrap();
        assert_eq!(config.tenant_field.as_deref(), Some("tenant_id"));
    }

    #[test]
    fn the_dev_binary_is_named_defaulted_or_the_only_one() {
        let ws = Workspace::from_json(METADATA).unwrap();
        let server = ws.package("app-server").unwrap();
        assert_eq!(server.dev_bin(None).unwrap(), "app-server");
        assert_eq!(server.dev_bin(Some("other")).unwrap(), "other");
        let mut two = server.clone();
        two.targets.push(two.targets[0].clone());
        assert!(two
            .dev_bin(None)
            .unwrap_err()
            .to_string()
            .contains("2 binaries"));
        two.default_run = Some("app-server".into());
        assert_eq!(two.dev_bin(None).unwrap(), "app-server");
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
