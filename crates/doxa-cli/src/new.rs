//! `doxa new`: the four-crate layout, from templates compiled into the binary.

use std::path::Path;

const FILES: &[(&str, &str)] = &[
    ("Cargo.toml", include_str!("../templates/Cargo.toml.tmpl")),
    (
        "api/Cargo.toml",
        include_str!("../templates/api/Cargo.toml.tmpl"),
    ),
    (
        "api/src/lib.rs",
        include_str!("../templates/api/src/lib.rs"),
    ),
    (
        "api/src/greeting.rs",
        include_str!("../templates/api/src/greeting.rs"),
    ),
    (
        "client/Cargo.toml",
        include_str!("../templates/client/Cargo.toml.tmpl"),
    ),
    (
        "client/build.rs",
        include_str!("../templates/client/build.rs"),
    ),
    (
        "server/Cargo.toml",
        include_str!("../templates/server/Cargo.toml.tmpl"),
    ),
    (
        "server/src/main.rs",
        include_str!("../templates/server/src/main.rs"),
    ),
    (
        "web/Cargo.toml",
        include_str!("../templates/web/Cargo.toml.tmpl"),
    ),
    (
        "web/src/lib.rs",
        include_str!("../templates/web/src/lib.rs"),
    ),
    (
        "web/style/app.css",
        include_str!("../templates/web/style/app.css"),
    ),
    (
        ".vscode/settings.json",
        include_str!("../templates/vscode-settings.json"),
    ),
];

/// Why an app could not be created.
#[derive(Debug, thiserror::Error)]
pub enum NewError {
    /// Not usable as a package name prefix.
    #[error("`{0}` is not a valid name: use letters, digits, `-` and `_`, starting with a letter")]
    BadName(String),
    /// Something is already there.
    #[error("{0} already exists")]
    Exists(String),
    /// Writing failed.
    #[error("{path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
}

/// Fill a template's placeholders.
pub fn render(template: &str, name: &str) -> String {
    template
        .replace("{{name}}", name)
        .replace("{{crate}}", &name.replace('-', "_"))
        .replace("{{doxa_version}}", env!("CARGO_PKG_VERSION"))
        .replace(
            "{{wasm_bindgen_version}}",
            doxa_build::bindgen::WASM_BINDGEN_VERSION,
        )
}

/// Write a new app named `name` under `parent`.
pub fn scaffold(parent: &Path, name: &str) -> Result<(), NewError> {
    let valid = name.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !valid {
        return Err(NewError::BadName(name.to_owned()));
    }
    let root = parent.join(name);
    if root.exists() {
        return Err(NewError::Exists(root.display().to_string()));
    }
    for (rel, template) in FILES {
        let path = root.join(rel);
        let io = |source| NewError::Io {
            path: path.display().to_string(),
            source,
        };
        std::fs::create_dir_all(path.parent().expect("has a parent")).map_err(io)?;
        std::fs::write(&path, render(template, name)).map_err(io)?;
    }
    eprintln!("created {}\n\n  cd {name}\n  doxa dev", root.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaffolds_the_four_crates() {
        let dir = tempfile::tempdir().unwrap();
        scaffold(dir.path(), "shop-app").unwrap();
        let root = dir.path().join("shop-app");
        let read = |p: &str| std::fs::read_to_string(root.join(p)).unwrap();

        for (rel, _) in FILES {
            assert!(!read(rel).contains("{{"), "unfilled placeholder in {rel}");
        }
        let web = read("web/Cargo.toml");
        assert!(web.contains("name = \"shop-app-web\""));
        assert!(web.contains("crate-type = [\"cdylib\", \"rlib\"]"));
        assert!(web.contains("role = \"client\""));
        assert!(web.contains("server = \"shop-app-server\""));
        assert!(web.contains(&format!(
            "wasm-bindgen = \"={}\"",
            doxa_build::bindgen::WASM_BINDGEN_VERSION
        )));
        assert!(read("client/Cargo.toml").contains("path = \"../api/src/lib.rs\""));
        assert!(read("web/src/lib.rs").contains("#[doxa::start]"));
        assert!(read("client/build.rs").contains("doxa_role::client()"));
        assert!(read("server/src/main.rs").contains("doxa::app(&shop_app_api::NoState)"));
        let settings: serde_json::Value =
            serde_json::from_str(&read(".vscode/settings.json")).unwrap();
        assert_eq!(
            settings["rust-analyzer.rustfmt.overrideCommand"],
            serde_json::json!(["doxa", "fmt", "--stdin"])
        );
    }

    #[test]
    fn refuses_bad_names_and_existing_dirs() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            scaffold(dir.path(), "1app"),
            Err(NewError::BadName(_))
        ));
        assert!(matches!(
            scaffold(dir.path(), "a/b"),
            Err(NewError::BadName(_))
        ));
        std::fs::create_dir(dir.path().join("taken")).unwrap();
        assert!(matches!(
            scaffold(dir.path(), "taken"),
            Err(NewError::Exists(_))
        ));
    }
}
