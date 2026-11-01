//! `#[react]`'s check that an npm module is a dependency the app declares, in
//! `[package.metadata.doxa.npm]` or a `package.json` beside the crate or above it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The npm packages an app crate declares.
#[derive(Debug, Default)]
pub(crate) struct Declared {
    names: BTreeSet<String>,
    /// Read for the check, so a change to it recompiles the crate.
    pub package_json: Vec<PathBuf>,
}

/// What the crate at `dir` declares, or `None` when its `Cargo.toml` can't be read.
pub(crate) fn declared(dir: &Path) -> Option<Declared> {
    let mut out = Declared::default();
    let manifest = std::fs::read_to_string(dir.join("Cargo.toml")).ok()?;
    let manifest: toml::Table = manifest.parse().ok()?;
    let doxa = manifest
        .get("package")
        .and_then(|p| p.get("metadata"))
        .and_then(|m| m.get("doxa"));
    if let Some(npm) = doxa.and_then(|d| d.get("npm")).and_then(|n| n.as_table()) {
        out.names.extend(npm.keys().cloned());
    }
    for at in dir.ancestors() {
        let path = at.join("package.json");
        if let Ok(json) = std::fs::read_to_string(&path) {
            out.names.extend(package_json_deps(&json));
            out.package_json.push(path);
        }
        if at.join("Cargo.toml").exists() && is_workspace_root(&at.join("Cargo.toml")) {
            break;
        }
    }
    Some(out)
}

fn is_workspace_root(manifest: &Path) -> bool {
    std::fs::read_to_string(manifest)
        .ok()
        .and_then(|s| s.parse::<toml::Table>().ok())
        .is_some_and(|t| t.contains_key("workspace"))
}

fn package_json_deps(json: &str) -> Vec<String> {
    let Ok(serde_json::Value::Object(pkg)) = serde_json::from_str(json) else {
        return Vec::new();
    };
    [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ]
    .iter()
    .filter_map(|k| pkg.get(*k)?.as_object())
    .flat_map(|deps| deps.keys().cloned())
    .collect()
}

/// The package a specifier imports from: `@scope/pkg/sub` is `@scope/pkg`, `pkg/sub` is `pkg`.
pub(crate) fn package_of(specifier: &str) -> &str {
    let parts = if specifier.starts_with('@') { 2 } else { 1 };
    match specifier.match_indices('/').nth(parts - 1) {
        Some((at, _)) => &specifier[..at],
        None => specifier,
    }
}

/// `Err` naming the fix when `specifier`'s package isn't declared.
pub(crate) fn check(specifier: &str, declared: &Declared) -> Result<(), String> {
    let package = package_of(specifier);
    if declared.names.contains(package) {
        return Ok(());
    }
    Err(format!(
        "`{package}` isn't an npm dependency of this app; add `\"{package}\" = \"<version>\"` \
         to [package.metadata.doxa.npm], or add it to package.json"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("doxa-npm-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_specifier_names_its_package() {
        assert_eq!(package_of("react-select"), "react-select");
        assert_eq!(package_of("lodash/debounce"), "lodash");
        assert_eq!(package_of("@monaco-editor/react"), "@monaco-editor/react");
        assert_eq!(
            package_of("@radix-ui/react-dialog/dist"),
            "@radix-ui/react-dialog"
        );
    }

    #[test]
    fn metadata_declares_packages() {
        let dir = temp("meta");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"web\"\n[package.metadata.doxa.npm]\n\"@monaco-editor/react\" = \"^4\"\n[workspace]\n",
        )
        .unwrap();
        let d = declared(&dir).expect("an app crate");
        assert!(check("@monaco-editor/react", &d).is_ok());
        let err = check("react-select/async", &d).unwrap_err();
        assert!(err.contains("`react-select`"), "{err}");
        assert!(err.contains("[package.metadata.doxa.npm]"), "{err}");
    }

    #[test]
    fn package_json_declares_packages() {
        let dir = temp("pkg");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"web\"\n[workspace]\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"react-select": "^5"}, "devDependencies": {"x": "1"}}"#,
        )
        .unwrap();
        let d = declared(&dir).expect("an app crate");
        assert!(check("react-select", &d).is_ok());
        assert!(check("x", &d).is_ok());
        assert!(check("y", &d).is_err());
        assert_eq!(d.package_json, [dir.join("package.json")]);
    }

    #[test]
    fn a_crate_declaring_nothing_rejects_every_package() {
        let dir = temp("plain");
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"lib\"\n[workspace]\n",
        )
        .unwrap();
        assert!(check("react", &declared(&dir).unwrap()).is_err());
    }
}
