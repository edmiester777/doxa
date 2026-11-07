//! npm dependencies: synced from metadata, or the app's own `package.json`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::config::{Layout, WebCrate};
use crate::error::{run, Error, IoContext, Result};

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
    /// `[package.metadata.doxa.npm]`, written to a generated `package.json`.
    Synced {
        /// Where the `package.json` and `node_modules` go.
        dir: PathBuf,
        /// Package name to version range.
        deps: BTreeMap<String, String>,
        /// Where its lockfile is kept and committed: the web crate.
        lock_dir: PathBuf,
    },
}

const LOCKFILES: [&str; 4] = [
    "package-lock.json",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
];

const APPLIED_PATCHES: &str = ".doxa-patches";

impl Source {
    /// The app's `package.json` beside the web crate or at the workspace root, which must list
    /// everything `needed` names; or else `needed`, the graph's merged
    /// `[package.metadata.doxa.npm]`, written to one.
    pub fn for_app(
        web: &WebCrate,
        workspace_root: &Path,
        layout: &Layout,
        needed: &BTreeMap<String, (String, String)>,
    ) -> Result<Source> {
        for dir in [web.dir.as_path(), workspace_root] {
            let path = dir.join("package.json");
            if !path.is_file() {
                continue;
            }
            let text = std::fs::read_to_string(&path).at(&path)?;
            let json: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| Error::config(format!("{}: {e}", path.display()), "fix the JSON"))?;
            let missing = crate::graph::missing_from(&json, needed);
            if !missing.is_empty() {
                return Err(Error::config(
                    format!("{} doesn't list {}", path.display(), missing.join(", ")),
                    "add them to its dependencies, or remove it and doxa writes one",
                ));
            }
            return Ok(Source::Own(dir.to_owned()));
        }
        Ok(if needed.is_empty() {
            Source::None
        } else {
            Source::Synced {
                dir: layout.js(),
                deps: needed
                    .iter()
                    .map(|(k, (range, _))| (k.clone(), range.clone()))
                    .collect(),
                lock_dir: web.dir.clone(),
            }
        })
    }

    /// The directory whose `node_modules` the bundler resolves from.
    pub fn dir(&self) -> Option<&Path> {
        match self {
            Source::None => None,
            Source::Own(d) | Source::Synced { dir: d, .. } => Some(d),
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
    let frozen = frozen(locked);
    let (dir, lock_dir) = match source {
        Source::None => return Ok(()),
        Source::Own(dir) => (dir, None),
        Source::Synced {
            dir,
            deps,
            lock_dir,
        } => {
            std::fs::create_dir_all(dir).at(dir)?;
            let path = dir.join("package.json");
            let body = package_json(deps);
            if std::fs::read_to_string(&path).ok().as_deref() != Some(body.as_str()) {
                std::fs::write(&path, body).at(&path)?;
            }
            if !copy_lockfiles(lock_dir, dir)? && frozen {
                return Err(Error::config(
                    format!("no npm lockfile in {}", lock_dir.display()),
                    "run `doxa build` once without --locked, then commit the lockfile it writes there",
                ));
            }
            (dir, Some(lock_dir))
        }
    };
    let manager = Manager::detect(dir);
    let stamp_path = dir.join("node_modules").join(".doxa-stamp");
    if std::fs::read_to_string(&stamp_path).ok() != Some(stamp(dir)) {
        clear_if_patches_changed(dir)?;
        let mut cmd = Command::new(manager.program());
        cmd.args(manager.install_args(frozen)).current_dir(dir);
        run(manager.program(), &mut cmd, manager.fix())?;
        // Taken after the install, which may have written the lockfile.
        std::fs::write(&stamp_path, stamp(dir)).at(&stamp_path)?;
        let applied = dir.join("node_modules").join(APPLIED_PATCHES);
        std::fs::write(&applied, patches_hash(dir)).at(&applied)?;
    }
    if let (Some(lock_dir), false) = (lock_dir, frozen) {
        copy_lockfiles(dir, lock_dir)?;
    }
    Ok(())
}

/// Copy whichever lockfiles `from` has into `to`, where they differ; whether there were any.
fn copy_lockfiles(from: &Path, to: &Path) -> Result<bool> {
    let mut any = false;
    for name in LOCKFILES {
        let src = from.join(name);
        let Ok(bytes) = std::fs::read(&src) else {
            continue;
        };
        any = true;
        let dst = to.join(name);
        if std::fs::read(&dst).ok().as_deref() != Some(bytes.as_slice()) {
            std::fs::write(&dst, bytes).at(&dst)?;
        }
    }
    Ok(any)
}

fn stamp(dir: &Path) -> String {
    let mut hash = Sha256::new();
    for name in std::iter::once("package.json").chain(LOCKFILES) {
        if let Ok(bytes) = std::fs::read(dir.join(name)) {
            hash.update(name.as_bytes());
            hash.update(&bytes);
        }
    }
    hash.update(patches_hash(dir));
    hex::encode(hash.finalize())
}

/// Remove `node_modules` when `patches/` differs from what it was installed with: an edited patch
/// can't apply over a package already patched.
fn clear_if_patches_changed(dir: &Path) -> Result<()> {
    let modules = dir.join("node_modules");
    let applied = std::fs::read_to_string(modules.join(APPLIED_PATCHES)).unwrap_or_default();
    if applied != patches_hash(dir) && modules.is_dir() {
        std::fs::remove_dir_all(&modules).at(&modules)?;
    }
    Ok(())
}

/// A hash of every file under `dir/patches`; empty when there are none.
fn patches_hash(dir: &Path) -> String {
    let mut files = Vec::new();
    collect_files(&dir.join("patches"), &mut files);
    if files.is_empty() {
        return String::new();
    }
    files.sort();
    let mut hash = Sha256::new();
    for file in files {
        hash.update(file.to_string_lossy().as_bytes());
        hash.update(std::fs::read(&file).unwrap_or_default());
    }
    hex::encode(hash.finalize())
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out);
        } else {
            out.push(path);
        }
    }
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
    fn a_synced_lockfile_lives_beside_the_web_crate() {
        let root = tempfile::tempdir().unwrap();
        let (dir, web) = (root.path().join("js"), root.path().join("web"));
        std::fs::create_dir_all(&web).unwrap();
        let source = Source::Synced {
            dir: dir.clone(),
            deps: BTreeMap::new(),
            lock_dir: web.clone(),
        };
        let err = install(&source, true).unwrap_err().to_string();
        assert!(err.contains("no npm lockfile"), "{err}");

        std::fs::create_dir_all(dir.join("node_modules")).unwrap();
        std::fs::write(web.join("package-lock.json"), "{}").unwrap();
        std::fs::write(dir.join("package.json"), package_json(&BTreeMap::new())).unwrap();
        std::fs::write(dir.join("node_modules/.doxa-stamp"), "stale").unwrap();
        assert!(copy_lockfiles(&web, &dir).unwrap());
        assert_eq!(
            std::fs::read_to_string(dir.join("package-lock.json")).unwrap(),
            "{}"
        );

        std::fs::write(dir.join("package-lock.json"), "{\"v\":2}").unwrap();
        copy_lockfiles(&dir, &web).unwrap();
        assert_eq!(
            std::fs::read_to_string(web.join("package-lock.json")).unwrap(),
            "{\"v\":2}",
            "an install's lockfile goes back to be committed"
        );
    }

    #[test]
    fn an_edited_patch_forces_a_clean_install() {
        let dir = tempfile::tempdir().unwrap();
        let (root, modules) = (dir.path(), dir.path().join("node_modules"));
        std::fs::create_dir_all(&modules).unwrap();
        std::fs::write(modules.join("kept"), "").unwrap();

        clear_if_patches_changed(root).unwrap();
        assert!(
            modules.join("kept").exists(),
            "no patches, nothing to clear"
        );

        let before = stamp(root);
        std::fs::create_dir_all(root.join("patches")).unwrap();
        std::fs::write(root.join("patches/a+1.0.0.patch"), "one").unwrap();
        assert_ne!(stamp(root), before, "a new patch reinstalls");
        clear_if_patches_changed(root).unwrap();
        assert!(!modules.exists(), "installed without that patch");

        std::fs::create_dir_all(&modules).unwrap();
        std::fs::write(modules.join(APPLIED_PATCHES), patches_hash(root)).unwrap();
        clear_if_patches_changed(root).unwrap();
        assert!(modules.exists(), "installed with this patch");

        std::fs::write(root.join("patches/a+1.0.0.patch"), "two").unwrap();
        clear_if_patches_changed(root).unwrap();
        assert!(!modules.exists(), "installed with an older patch");
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
            work: dir.path().join("target/doxa"),
        };
        let mut web = WebCrate {
            name: "web".into(),
            version: "0.0.0".into(),
            dir: dir.path().join("web"),
            lib_name: "web".into(),
            config: DoxaConfig::default(),
        };
        std::fs::create_dir_all(&web.dir).unwrap();
        let none = BTreeMap::new();
        assert_eq!(
            Source::for_app(&web, dir.path(), &layout, &none).unwrap(),
            Source::None
        );

        let react = BTreeMap::from([("react".to_owned(), ("^19".to_owned(), "kit".to_owned()))]);
        assert!(matches!(
            Source::for_app(&web, dir.path(), &layout, &react).unwrap(),
            Source::Synced { dir: d, lock_dir, deps } if d == layout.js() && lock_dir == web.dir && deps["react"] == "^19"
        ));

        std::fs::write(web.dir.join("package.json"), "{}").unwrap();
        let err = Source::for_app(&web, dir.path(), &layout, &react).unwrap_err();
        assert!(
            err.to_string().contains("`react` (`^19`, for `kit`)"),
            "{err}"
        );
        std::fs::write(
            web.dir.join("package.json"),
            r#"{"dependencies":{"react":"^19.1.0"}}"#,
        )
        .unwrap();
        web.config.npm.clear();
        assert_eq!(
            Source::for_app(&web, dir.path(), &layout, &react).unwrap(),
            Source::Own(web.dir.clone())
        );
    }
}
