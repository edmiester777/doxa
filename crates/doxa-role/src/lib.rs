//! Marks a crate as the client or server half of a doxa app, or an API both depend on, from
//! `build.rs`.
//!
//! ```ignore
//! // api/build.rs
//! fn main() { doxa_role::api() }
//! ```

#![deny(missing_docs)]

use std::path::{Path, PathBuf};

/// Environment variable doxa's macros read to pick which half to emit.
pub const ROLE_ENV: &str = "DOXA_ROLE";
/// The lib target's root file, absolute: where `doxa::prelude!()` declares the modules below.
pub const LIB_ENV: &str = "DOXA_LIB";
/// The `server_only` directories, as comma-separated module names.
pub const SERVER_ONLY_ENV: &str = "DOXA_SERVER_ONLY";
/// The `client_only` directories, as comma-separated module names.
pub const CLIENT_ONLY_ENV: &str = "DOXA_CLIENT_ONLY";

/// Build this crate as the client half: routes become typed HTTP calls.
pub fn client() {
    emit("client");
    println!("cargo::rustc-cfg=doxa_client");
}

/// Build this crate for both halves: routes serve off wasm and are calls everywhere.
///
/// Panics on a bad `server_only` / `client_only` in `[package.metadata.doxa]`.
pub fn api() {
    emit("api");
    println!("cargo::rerun-if-changed=Cargo.toml");
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("run from build.rs"));
    let manifest = std::fs::read_to_string(dir.join("Cargo.toml")).expect("read Cargo.toml");
    let split = Split::read(&dir, &manifest).unwrap_or_else(|e| panic!("{e}"));
    println!("cargo::rustc-env={LIB_ENV}={}", split.lib.display());
    println!(
        "cargo::rustc-env={SERVER_ONLY_ENV}={}",
        split.server.join(",")
    );
    println!(
        "cargo::rustc-env={CLIENT_ONLY_ENV}={}",
        split.client.join(",")
    );
}

/// Build this crate as the server half. The default; only needed to say so.
pub fn server() {
    emit("server");
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
        Ok(Split {
            lib,
            server,
            client,
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
            }
        );
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
