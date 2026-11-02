//! wasm-bindgen, linked as a library, and the optional `wasm-opt` pass.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use crate::error::{run, Error, IoContext, Result};

/// The `wasm-bindgen` version the app must lock; the schema is not stable across
/// releases, so the macro and the CLI must match exactly.
pub const WASM_BINDGEN_VERSION: &str = "0.2.117";

#[derive(Deserialize)]
struct Lockfile {
    #[serde(default)]
    package: Vec<Locked>,
}

#[derive(Deserialize)]
struct Locked {
    name: String,
    version: String,
}

/// Every `wasm-bindgen` version in a Cargo.lock.
pub fn locked_versions(lock: &str) -> Result<Vec<String>, toml::de::Error> {
    let lock: Lockfile = toml::from_str(lock)?;
    Ok(lock
        .package
        .into_iter()
        .filter(|p| p.name == "wasm-bindgen")
        .map(|p| p.version)
        .collect())
}

/// Fail unless the lockfile's `wasm-bindgen` is [`WASM_BINDGEN_VERSION`].
pub fn check_lock(lock: &str, path: &Path) -> Result<()> {
    let versions = locked_versions(lock).map_err(|e| {
        Error::config(
            format!("{}: {e}", path.display()),
            "run `cargo generate-lockfile`",
        )
    })?;
    if versions.is_empty() {
        return Err(Error::config(
            format!("{} has no wasm-bindgen", path.display()),
            format!(
                "add wasm-bindgen = \"={WASM_BINDGEN_VERSION}\" to the web crate's dependencies"
            ),
        ));
    }
    match versions.into_iter().find(|v| v != WASM_BINDGEN_VERSION) {
        Some(locked) => Err(Error::WasmBindgenMismatch {
            locked,
            expected: WASM_BINDGEN_VERSION,
        }),
        None => Ok(()),
    }
}

/// Generate `--target web` bindings for `wasm` into `out_dir` as `app.js` and
/// `app_bg.wasm`. A wasm to be split or hot-patched keeps its symbols as the linker
/// wrote them; a hot one also keeps the exports a patch links against.
pub fn generate(wasm: &Path, out_dir: &Path, release: bool, split: bool, hot: bool) -> Result<()> {
    if out_dir.exists() {
        std::fs::remove_dir_all(out_dir).at(out_dir)?;
    }
    let mut b = wasm_bindgen_cli_support::Bindgen::new();
    b.input_path(wasm)
        .out_name("app")
        .typescript(false)
        .debug(!release)
        .keep_debug(!release)
        .demangle(!split && !hot)
        .keep_lld_exports(hot);
    b.web(true)
        .and_then(|b| b.generate(out_dir))
        .map_err(|e| Error::Tool {
            tool: "wasm-bindgen",
            command: format!(
                "wasm-bindgen --target web --out-name app --out-dir {} {}",
                out_dir.display(),
                wasm.display()
            ),
            detail: format!("{e:#}"),
            fix: format!(
                "make sure the web crate depends on wasm-bindgen = \"={WASM_BINDGEN_VERSION}\""
            ),
        })
}

/// Optimize `wasm` in place. `Ok(false)` when `wasm-opt` is not on `PATH`.
pub fn wasm_opt(wasm: &Path) -> Result<bool> {
    let Some(bin) = which("wasm-opt") else {
        return Ok(false);
    };
    let out = wasm.with_extension("opt.wasm");
    let mut cmd = Command::new(bin);
    // The feature flags match what rustc enables for wasm32-unknown-unknown.
    cmd.arg("-Oz")
        .args([
            "--enable-bulk-memory",
            "--enable-mutable-globals",
            "--enable-nontrapping-float-to-int",
            "--enable-sign-ext",
            "--enable-reference-types",
            "--enable-multivalue",
        ])
        .arg(wasm)
        .arg("-o")
        .arg(&out);
    run(
        "wasm-opt",
        &mut cmd,
        "update binaryen (https://github.com/WebAssembly/binaryen), or remove wasm-opt from PATH to skip it",
    )?;
    std::fs::rename(&out, wasm).at(wasm)?;
    Ok(true)
}

/// The first `name` on `PATH`.
pub fn which(name: &str) -> Option<PathBuf> {
    let exe = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(&exe))
        .find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock(version: &str) -> String {
        format!(
            "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n\n\
             [[package]]\nname = \"wasm-bindgen\"\nversion = \"{version}\"\n"
        )
    }

    #[test]
    fn matching_lock_passes() {
        check_lock(&lock(WASM_BINDGEN_VERSION), Path::new("Cargo.lock")).unwrap();
    }

    #[test]
    fn mismatch_names_both_versions_and_the_fix() {
        let err = check_lock(&lock("0.2.100"), Path::new("Cargo.lock"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("0.2.100"), "{err}");
        assert!(err.contains(WASM_BINDGEN_VERSION), "{err}");
        assert!(
            err.contains(&format!(
                "cargo update -p wasm-bindgen --precise {WASM_BINDGEN_VERSION}"
            )),
            "{err}"
        );
    }

    #[test]
    fn missing_wasm_bindgen_says_what_to_add() {
        let err = check_lock("version = 4\n", Path::new("Cargo.lock"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("add wasm-bindgen"), "{err}");
    }
}
