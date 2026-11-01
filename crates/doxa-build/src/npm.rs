//! npm dependencies: synced from metadata, or the app's own `package.json`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::config::{Layout, WebCrate};
use crate::error::{run, IoContext, Result};

/// A JS package manager, chosen by the lockfile beside `package.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Manager {
    /// `bun.lock` or `bun.lockb`.
    Bun,
    /// `pnpm-lock.yaml`.
    Pnpm,
    /// `package-lock.json`, or no lockfile.
    Npm,
}

impl Manager {
    /// The manager whose lockfile is in `dir`; npm when there is none.
    pub fn detect(dir: &Path) -> Manager {
        if dir.join("bun.lock").exists() || dir.join("bun.lockb").exists() {
            Manager::Bun
        } else if dir.join("pnpm-lock.yaml").exists() {
            Manager::Pnpm
        } else {
            Manager::Npm
        }
    }

    /// The executable to run.
    pub fn program(self) -> &'static str {
        match (self, cfg!(windows)) {
            (Manager::Bun, _) => "bun",
            (Manager::Pnpm, false) => "pnpm",
            (Manager::Pnpm, true) => "pnpm.cmd",
            (Manager::Npm, false) => "npm",
            (Manager::Npm, true) => "npm.cmd",
        }
    }

    /// Install arguments; `frozen` refuses to change the lockfile.
    pub fn install_args(self, frozen: bool) -> &'static [&'static str] {
        match (self, frozen) {
            (Manager::Npm, true) => &["ci"],
            (Manager::Npm, false) => &["install"],
            (_, true) => &["install", "--frozen-lockfile"],
            (_, false) => &["install"],
        }
    }

    fn fix(self) -> &'static str {
        match self {
            Manager::Bun => "install bun from https://bun.sh, or check the dependency names in [package.metadata.doxa.npm]",
            Manager::Pnpm => "install pnpm from https://pnpm.io, or check the dependency names in [package.metadata.doxa.npm]",
            Manager::Npm => "install Node.js from https://nodejs.org, or check the dependency names in [package.metadata.doxa.npm]",
        }
    }
}

/// Where JS dependencies come from, if anywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// No npm dependencies: Node is not needed.
    None,
    /// The app's own `package.json` in this directory.
    Own(PathBuf),
    /// `[package.metadata.doxa.npm]`, written to a generated `package.json` here.
    Synced(PathBuf, BTreeMap<String, String>),
}

impl Source {
    /// The app's `package.json` beside the web crate or at the workspace root wins
    /// over metadata.
    pub fn for_app(web: &WebCrate, workspace_root: &Path, layout: &Layout) -> Source {
        for dir in [web.dir.as_path(), workspace_root] {
            if dir.join("package.json").is_file() {
                return Source::Own(dir.to_owned());
            }
        }
        if web.config.npm.is_empty() {
            Source::None
        } else {
            Source::Synced(layout.js(), web.config.npm.clone())
        }
    }

    /// The directory whose `node_modules` the bundler resolves from.
    pub fn dir(&self) -> Option<&Path> {
        match self {
            Source::None => None,
            Source::Own(d) | Source::Synced(d, _) => Some(d),
        }
    }
}

/// The generated `package.json` for synced dependencies.
pub fn package_json(deps: &BTreeMap<String, String>) -> String {
    let doc = serde_json::json!({
        "name": "doxa-app-deps",
        "private": true,
        "dependencies": deps,
    });
    serde_json::to_string_pretty(&doc).expect("json") + "\n"
}

/// Whether installs must not touch the lockfile.
pub fn frozen(locked: bool) -> bool {
    locked || std::env::var_os("CI").is_some()
}

/// Install dependencies for `source`, skipping when nothing changed since the last
/// install.
pub fn install(source: &Source, locked: bool) -> Result<()> {
    let dir = match source {
        Source::None => return Ok(()),
        Source::Own(dir) => dir,
        Source::Synced(dir, deps) => {
            std::fs::create_dir_all(dir).at(dir)?;
            let path = dir.join("package.json");
            let body = package_json(deps);
            if std::fs::read_to_string(&path).ok().as_deref() != Some(body.as_str()) {
                std::fs::write(&path, body).at(&path)?;
            }
            dir
        }
    };
    let manager = Manager::detect(dir);
    let stamp_path = dir.join("node_modules").join(".doxa-stamp");
    if std::fs::read_to_string(&stamp_path).ok() == Some(stamp(dir)) {
        return Ok(());
    }
    let mut cmd = Command::new(manager.program());
    cmd.args(manager.install_args(frozen(locked)))
        .current_dir(dir);
    run(manager.program(), &mut cmd, manager.fix())?;
    // Taken after the install, which may have written the lockfile.
    std::fs::write(&stamp_path, stamp(dir)).at(&stamp_path)
}

fn stamp(dir: &Path) -> String {
    let mut hash = Sha256::new();
    for name in [
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "bun.lock",
        "bun.lockb",
    ] {
        if let Ok(bytes) = std::fs::read(dir.join(name)) {
            hash.update(name.as_bytes());
            hash.update(&bytes);
        }
    }
    hex::encode(hash.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DoxaConfig;

    #[test]
    fn manager_by_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Manager::detect(dir.path()), Manager::Npm);
        std::fs::write(dir.path().join("pnpm-lock.yaml"), "").unwrap();
        assert_eq!(Manager::detect(dir.path()), Manager::Pnpm);
        std::fs::write(dir.path().join("bun.lock"), "").unwrap();
        assert_eq!(Manager::detect(dir.path()), Manager::Bun);
    }

    #[test]
    fn frozen_install_arguments() {
        assert_eq!(Manager::Npm.install_args(true), ["ci"]);
        assert_eq!(Manager::Npm.install_args(false), ["install"]);
        assert_eq!(
            Manager::Pnpm.install_args(true),
            ["install", "--frozen-lockfile"]
        );
        assert_eq!(
            Manager::Bun.install_args(true),
            ["install", "--frozen-lockfile"]
        );
        assert!(frozen(true));
    }

    #[test]
    fn synced_package_json() {
        let deps = BTreeMap::from([
            ("react".to_owned(), "^19".to_owned()),
            ("@monaco-editor/react".to_owned(), "^4.7".to_owned()),
        ]);
        let json: serde_json::Value = serde_json::from_str(&package_json(&deps)).unwrap();
        assert_eq!(json["private"], true);
        assert_eq!(json["dependencies"]["react"], "^19");
        assert_eq!(json["dependencies"]["@monaco-editor/react"], "^4.7");
    }

    #[test]
    fn own_package_json_wins_and_no_deps_needs_no_node() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout {
            root: dir.path().join("target/doxa"),
        };
        let mut web = WebCrate {
            name: "web".into(),
            dir: dir.path().join("web"),
            lib_name: "web".into(),
            config: DoxaConfig::default(),
        };
        std::fs::create_dir_all(&web.dir).unwrap();
        assert_eq!(Source::for_app(&web, dir.path(), &layout), Source::None);

        web.config.npm.insert("react".into(), "^19".into());
        assert!(matches!(
            Source::for_app(&web, dir.path(), &layout),
            Source::Synced(d, _) if d == layout.js()
        ));

        std::fs::write(web.dir.join("package.json"), "{}").unwrap();
        assert_eq!(
            Source::for_app(&web, dir.path(), &layout),
            Source::Own(web.dir.clone())
        );
    }
}
