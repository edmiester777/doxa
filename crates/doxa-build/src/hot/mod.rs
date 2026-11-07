//! Hot-patching for `doxa dev`. A fat base build records the web crate's rustc and link
//! commands; each patch reruns that rustc alone and links its objects against the base.

mod statics;
pub mod wasm;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use serde::{Deserialize, Serialize};

use crate::error::{Error, IoContext, Result};

/// Set on cargo's rustc wrapper: where to record the web crate's rustc command.
const RUSTC_FILE: &str = "DOXA_HOT_RUSTC";
/// The crate whose rustc command is recorded.
const RUSTC_CRATE: &str = "DOXA_HOT_CRATE";
/// Set on rustc's linker: where to record the link arguments.
const LINK_FILE: &str = "DOXA_HOT_LINK";

/// How the web crate's rustc ran under cargo.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Rustc {
    args: Vec<String>,
    envs: Vec<(String, String)>,
    cwd: PathBuf,
}

/// Act as cargo's rustc wrapper or rustc's linker when `doxa` was started as one; call
/// this first in `main`.
pub fn intercept() -> Option<ExitCode> {
    let args: Vec<String> = std::env::args().collect();
    let wraps_rustc = std::env::var_os(RUSTC_FILE).is_some()
        && args
            .get(1)
            .is_some_and(|a| Path::new(a).file_stem().is_some_and(|s| s == "rustc"));
    if wraps_rustc {
        return Some(wrap_rustc(&args[1..]));
    }
    let file = std::env::var_os(LINK_FILE)?;
    Some(match record_link(&args[1..], Path::new(&file)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    })
}

fn wrap_rustc(rustc: &[String]) -> ExitCode {
    let name = rustc
        .iter()
        .position(|a| a == "--crate-name")
        .and_then(|i| rustc.get(i + 1));
    let wanted = std::env::var(RUSTC_CRATE).ok();
    if name.is_some() && name == wanted.as_ref() {
        let record = Rustc {
            args: rustc.to_vec(),
            envs: std::env::vars().collect(),
            cwd: std::env::current_dir().unwrap_or_default(),
        };
        let file = std::env::var_os(RUSTC_FILE).expect("checked by intercept");
        let json = serde_json::to_string(&record).expect("json");
        if let Err(e) = std::fs::write(&file, json) {
            eprintln!("error: recording rustc: {e}");
            return ExitCode::FAILURE;
        }
    }
    match Command::new(&rustc[0]).args(&rustc[1..]).status() {
        Ok(s) if s.success() => ExitCode::SUCCESS,
        Ok(s) => ExitCode::from(s.code().unwrap_or(1).clamp(1, 255) as u8),
        Err(e) => {
            eprintln!("error: running {}: {e}", rustc[0]);
            ExitCode::FAILURE
        }
    }
}

/// Record the arguments and leave an empty module where rustc expects the output.
fn record_link(args: &[String], file: &Path) -> std::io::Result<()> {
    let args = expand_response_files(args)?;
    std::fs::write(file, args.join("\n"))?;
    if let Some(out) = args
        .iter()
        .position(|a| a == "-o")
        .and_then(|i| args.get(i + 1))
    {
        // Cargo hard-links the output; replace the file rather than write through the link.
        let _ = std::fs::remove_file(out);
        std::fs::write(out, b"\0asm\x01\0\0\0")?;
    }
    Ok(())
}

/// `@file` arguments, which rustc writes one per line with `\` escapes.
fn expand_response_files(args: &[String]) -> std::io::Result<Vec<String>> {
    let mut out = Vec::new();
    for a in args {
        let Some(path) = a.strip_prefix('@') else {
            out.push(a.clone());
            continue;
        };
        for line in std::fs::read_to_string(path)?.lines() {
            let mut arg = String::new();
            let mut chars = line.chars();
            while let Some(c) = chars.next() {
                arg.push(if c == '\\' {
                    chars.next().unwrap_or(c)
                } else {
                    c
                });
            }
            out.push(arg);
        }
    }
    Ok(out)
}

/// Where a base build records its commands.
pub(crate) struct Records {
    dir: PathBuf,
}

impl Records {
    pub(crate) fn new(stage: &Path) -> Result<Self> {
        let dir = stage.join("hot");
        std::fs::create_dir_all(&dir).at(&dir)?;
        Ok(Records { dir })
    }

    fn rustc(&self) -> PathBuf {
        self.dir.join("rustc.json")
    }

    fn link(&self) -> PathBuf {
        self.dir.join("link.txt")
    }

    fn thin_link(&self) -> PathBuf {
        self.dir.join("thin-link.txt")
    }

    /// The environment and rustc flags that make cargo's build a recorded fat base.
    pub(crate) fn configure(&self, cargo: &mut Command, lib_name: &str) -> Result<()> {
        let doxa = std::env::current_exe().at(Path::new("doxa"))?;
        for f in [self.rustc(), self.link()] {
            let _ = std::fs::remove_file(&f);
        }
        cargo
            .env("RUSTC_WRAPPER", &doxa)
            .env(RUSTC_FILE, self.rustc())
            .env(RUSTC_CRATE, lib_name)
            .env(LINK_FILE, self.link());
        cargo.arg(format!("-Clinker={}", doxa.display()));
        cargo.args(["-Csave-temps=true", "-Clink-dead-code", "--cfg", "doxa_hot"]);
        for a in [
            "--no-gc-sections",
            "--growable-table",
            "--export-table",
            "--export-memory",
            "--export=__stack_pointer",
            "--export=__heap_base",
            "--export=__data_end",
        ] {
            cargo.arg(format!("-Clink-arg={a}"));
        }
        Ok(())
    }

    /// Link the recorded objects with every workspace rlib whole, into `out`.
    pub(crate) fn fat_link(&self, target_dir: &Path, workspace: &Path, out: &Path) -> Result<Base> {
        let rustc: Rustc = read_json(&self.rustc())?;
        let link = read_lines(&self.link())?;
        let mut args = linker_args(&link);
        let target_dir = std::fs::canonicalize(target_dir).at(target_dir)?;
        let (ours, theirs): (Vec<_>, Vec<_>) = args
            .iter()
            .filter(|a| a.ends_with(".rlib"))
            .cloned()
            .partition(|a| std::fs::canonicalize(a).is_ok_and(|p| p.starts_with(&target_dir)));
        let archive = self.dir.join("libdeps.a");
        whole_archive(&ours, &archive)?;
        args.retain(|a| !a.ends_with(".rlib"));
        let at = args
            .iter()
            .rposition(|a| a.ends_with(".o"))
            .map_or(args.len(), |i| i + 1);
        let mut tail = vec![
            "--whole-archive".to_owned(),
            archive.display().to_string(),
            "--no-whole-archive".to_owned(),
        ];
        tail.extend(theirs);
        args.splice(at..at, tail);
        args.extend(["-o".to_owned(), out.display().to_string()]);
        let lld = rust_lld(workspace)?;
        lld_run(&lld, &args, "the fat link", &self.dir.join("lld.rsp"))?;
        Ok(Base {
            rustc,
            link,
            lld,
            records: Records {
                dir: self.dir.clone(),
            },
            cache: None,
            patches: 0,
        })
    }
}

/// What a patch attempt came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Patched {
    /// The jump table the page applies, as JSON.
    Table(String),
    /// The crate didn't compile; its errors are on stderr.
    NotCompiled,
    /// The change needs what a patch can't carry, for the reason given.
    NeedsRebuild(String),
}

/// The `#[story]` exports among a link's arguments, sorted.
fn story_exports(link: &[String]) -> Vec<&str> {
    let mut stories: Vec<&str> = link
        .windows(2)
        .filter(|pair| pair[0] == "--export" && pair[1].starts_with("__doxa_story_"))
        .map(|pair| pair[1].as_str())
        .collect();
    stories.sort_unstable();
    stories
}

/// A recorded base build, ready to patch.
pub struct Base {
    rustc: Rustc,
    link: Vec<String>,
    lld: PathBuf,
    records: Records,
    cache: Option<wasm::Cache>,
    patches: u32,
}

impl Base {
    /// Remember the module wasm-bindgen wrote, which patches resolve against.
    pub(crate) fn set_bindgened(&mut self, bytes: Vec<u8>) -> Result<()> {
        self.cache = Some(wasm::Cache::new(bytes).map_err(patch_error)?);
        Ok(())
    }

    /// Recompile the web crate and link a patch into `dir`, naming it by its path under `url`.
    pub(crate) fn patch(&mut self, dir: &Path, url: &str) -> Result<Patched> {
        let cache = self
            .cache
            .as_ref()
            .ok_or_else(|| Error::config("no base build to patch", "run a full build"))?;
        let thin = self.records.thin_link();
        let _ = std::fs::remove_file(&thin);
        let mut cmd = Command::new(&self.rustc.args[0]);
        cmd.args(&self.rustc.args[1..])
            .arg("-Crelocation-model=pic")
            .env_clear()
            .envs(
                self.rustc
                    .envs
                    .iter()
                    .filter(|(k, _)| {
                        !matches!(
                            k.as_str(),
                            RUSTC_FILE
                                | RUSTC_CRATE
                                | LINK_FILE
                                | "RUSTC_WRAPPER"
                                | "RUSTC_WORKSPACE_WRAPPER"
                                // Cargo's jobserver pipes are gone once cargo exits.
                                | "CARGO_MAKEFLAGS"
                                | "MAKEFLAGS"
                                | "MFLAGS"
                        )
                    })
                    .map(|(k, v)| (k, v)),
            )
            .env(LINK_FILE, &thin)
            .current_dir(&self.rustc.cwd);
        if !compile(&mut cmd)? {
            return Ok(Patched::NotCompiled);
        }
        if self.patches == 0 && dir.exists() {
            std::fs::remove_dir_all(dir).at(dir)?;
        }
        let thin_args = read_lines(&thin)?;
        // A story is a wasm export the JS glue lists, and a patch can't change either.
        if story_exports(&thin_args) != story_exports(&linker_args(&self.link)) {
            return Ok(Patched::NeedsRebuild(
                "the set of stories changed".to_owned(),
            ));
        }
        let mut objects: Vec<_> = thin_args
            .iter()
            .filter(|a| a.ends_with(".rcgu.o"))
            .cloned()
            .collect();
        objects.sort();
        self.patches += 1;
        std::fs::create_dir_all(dir).at(dir)?;
        let name = format!("patch-{}.wasm", self.patches);
        let out = dir.join(&name);
        let mut args = objects.clone();
        args.extend(
            [
                "--import-memory",
                "--import-table",
                "--growable-table",
                "--export",
                "main",
                "--allow-undefined",
                "--no-demangle",
                "--no-entry",
                "--pie",
                "--experimental-pic",
            ]
            .map(String::from),
        );
        let link = linker_args(&self.link);
        for (i, a) in link.iter().enumerate() {
            if a == "--export" {
                if let Some(sym) = link.get(i + 1) {
                    args.extend(["--export".to_owned(), sym.clone()]);
                }
            }
        }
        args.extend(["-o".to_owned(), out.display().to_string()]);
        lld_run(
            &self.lld,
            &args,
            "the patch link",
            &self.records.dir.join("lld.rsp"),
        )?;
        let mut sites = statics::Sites::default();
        for o in &objects {
            let object = std::fs::read(o).at(Path::new(o))?;
            sites.read(&object).map_err(patch_error)?;
            let _ = std::fs::remove_file(o);
        }
        let bytes = std::fs::read(&out).at(&out)?;
        let (bytes, mut table) = wasm::jump_table(&bytes, &sites, cache).map_err(patch_error)?;
        std::fs::write(&out, bytes).at(&out)?;
        table.lib = PathBuf::from(format!("{url}/{name}"));
        Ok(Patched::Table(serde_json::to_string(&table).expect("json")))
    }
}

/// Remove `package`'s fingerprints under `dir`, so cargo reruns its rustc.
pub(crate) fn forget_fingerprint(dir: &Path, package: &str) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        let ours = name
            .to_str()
            .and_then(|n| n.strip_prefix(package))
            .and_then(|rest| rest.strip_prefix('-'))
            .is_some_and(|hash| !hash.contains('-'));
        if ours {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

pub(crate) fn patch_error(e: anyhow::Error) -> Error {
    Error::config(
        format!("hot-patching failed: {e:#}"),
        "restart `doxa dev`, or run it with --no-hot",
    )
}

/// The recorded link arguments, without the flavor or output.
fn linker_args(recorded: &[String]) -> Vec<String> {
    let mut args = recorded.to_vec();
    for flag in ["-flavor", "-o"] {
        if let Some(i) = args.iter().position(|a| a == flag) {
            args.drain(i..(i + 2).min(args.len()));
        }
    }
    args
}

/// One archive holding every codegen object of `rlibs`, which wasm-ld loads whole.
fn whole_archive(rlibs: &[String], out: &Path) -> Result<()> {
    let mut builder = ar::Builder::new(Vec::new());
    for rlib in rlibs {
        let path = Path::new(rlib);
        let bytes = std::fs::read(path).at(path)?;
        let mut archive = ar::Archive::new(bytes.as_slice());
        while let Some(entry) = archive.next_entry() {
            let mut entry = entry.at(path)?;
            let id = String::from_utf8_lossy(entry.header().identifier()).into_owned();
            if !id.ends_with(".rcgu.o") || entry.header().size() == 0 {
                continue;
            }
            let header = entry.header().clone();
            builder.append(&header, &mut entry).at(out)?;
        }
    }
    let bytes = builder.into_inner().at(out)?;
    std::fs::write(out, bytes).at(out)
}

/// rustc's bundled lld, which links wasm as `-flavor wasm`.
fn rust_lld(workspace: &Path) -> Result<PathBuf> {
    let rustc = |args: &[&str]| -> Result<String> {
        let mut cmd = Command::new("rustc");
        cmd.args(args).current_dir(workspace);
        let out = cmd
            .output()
            .map_err(|e| Error::tool("rustc", &cmd, e.to_string(), "install Rust with rustup"))?;
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    };
    let sysroot = rustc(&["--print", "sysroot"])?;
    let host = rustc(&["-vV"])?
        .lines()
        .find_map(|l| l.strip_prefix("host: ").map(str::to_owned))
        .unwrap_or_default();
    let lld = Path::new(sysroot.trim())
        .join("lib/rustlib")
        .join(host)
        .join("bin")
        .join(format!("rust-lld{}", std::env::consts::EXE_SUFFIX));
    if lld.is_file() {
        Ok(lld)
    } else {
        Err(Error::config(
            format!("{} is missing", lld.display()),
            "hot-patching links with rustc's rust-lld; reinstall the toolchain, or run `doxa dev --no-hot`",
        ))
    }
}

fn lld_run(lld: &Path, args: &[String], what: &str, file: &Path) -> Result<()> {
    let escaped: Vec<String> = args
        .iter()
        .map(|a| {
            a.chars().fold(String::new(), |mut s, c| {
                if matches!(c, '\\' | ' ' | '"' | '\'') {
                    s.push('\\');
                }
                s.push(c);
                s
            })
        })
        .collect();
    std::fs::write(file, escaped.join("\n")).at(file)?;
    let mut cmd = Command::new(lld);
    cmd.args(["-flavor", "wasm"])
        .arg(format!("@{}", file.display()));
    // rust-lld loads the toolchain's libLLVM from `<sysroot>/lib`, as rustc tells it to.
    if let Some(lib) = lld.ancestors().nth(4) {
        let var = match std::env::consts::OS {
            "macos" => "DYLD_FALLBACK_LIBRARY_PATH",
            "windows" => "PATH",
            _ => "LD_LIBRARY_PATH",
        };
        let mut paths = vec![lib.to_owned()];
        paths.extend(std::env::var_os(var).iter().flat_map(std::env::split_paths));
        cmd.env(var, std::env::join_paths(paths).unwrap_or_default());
    }
    let out = cmd
        .output()
        .map_err(|e| Error::tool("rust-lld", &cmd, e.to_string(), "reinstall the toolchain"))?;
    if out.status.success() {
        return Ok(());
    }
    Err(Error::tool(
        "rust-lld",
        &cmd,
        format!("{what}: {}", String::from_utf8_lossy(&out.stderr).trim()),
        "run `doxa dev --no-hot` and report the error",
    ))
}

/// Run a recorded rustc, printing its JSON diagnostics as rendered text; whether it succeeded.
fn compile(cmd: &mut Command) -> Result<bool> {
    let out = cmd
        .output()
        .map_err(|e| Error::tool("rustc", cmd, e.to_string(), "install Rust with rustup"))?;
    for line in String::from_utf8_lossy(&out.stderr).lines() {
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(v) => {
                if let Some(text) = v.get("rendered").and_then(|r| r.as_str()) {
                    eprint!("{text}");
                }
            }
            Err(_) => eprintln!("{line}"),
        }
    }
    Ok(out.status.success())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let text = std::fs::read_to_string(path).map_err(|_| missing(path))?;
    serde_json::from_str(&text)
        .map_err(|e| Error::config(format!("{}: {e}", path.display()), "run a full build"))
}

fn read_lines(path: &Path) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(path).map_err(|_| missing(path))?;
    Ok(text.lines().map(str::to_owned).collect())
}

fn missing(path: &Path) -> Error {
    Error::config(
        format!("{} wasn't recorded", path.display()),
        "the build ran without doxa as its rustc wrapper and linker; run a full build",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn story_exports_ignore_other_exports_and_order() {
        let link = |args: &[&str]| args.iter().map(|a| a.to_string()).collect::<Vec<_>>();
        let base = link(&[
            "--export",
            "__doxa_story_b",
            "--export",
            "main",
            "--export",
            "__doxa_story_a",
        ]);
        let same = link(&["--export", "__doxa_story_a", "--export", "__doxa_story_b"]);
        let added = link(&[
            "--export",
            "__doxa_story_a",
            "--export",
            "__doxa_story_b",
            "--export",
            "__doxa_story_c",
        ]);
        assert_eq!(story_exports(&base), story_exports(&same));
        assert_ne!(story_exports(&base), story_exports(&added));
        assert!(story_exports(&link(&["__doxa_story_a.o"])).is_empty());
    }

    #[test]
    fn linker_args_drop_the_linker_flavor_and_output() {
        let recorded: Vec<String> = ["-flavor", "wasm", "a.o", "-o", "out.wasm", "--export", "f"]
            .map(String::from)
            .into();
        assert_eq!(linker_args(&recorded), ["a.o", "--export", "f"]);
    }

    #[test]
    fn response_files_unescape() {
        let dir = tempfile::tempdir().unwrap();
        let rsp = dir.path().join("args");
        std::fs::write(&rsp, "a\\ b.o\n--export\nc\\\\d\n").unwrap();
        let args = expand_response_files(&["x".into(), format!("@{}", rsp.display())]).unwrap();
        assert_eq!(args, ["x", "a b.o", "--export", "c\\d"]);
    }

    #[test]
    fn the_whole_archive_keeps_only_codegen_objects() {
        let dir = tempfile::tempdir().unwrap();
        let rlib = dir.path().join("libx.rlib");
        let mut b = ar::Builder::new(Vec::new());
        for (name, body) in [
            ("lib.rmeta", &b"meta"[..]),
            ("x.x.rcgu.o", b"obj"),
            ("e.rcgu.o", b""),
        ] {
            b.append(
                &ar::Header::new(name.as_bytes().to_vec(), body.len() as u64),
                body,
            )
            .unwrap();
        }
        std::fs::write(&rlib, b.into_inner().unwrap()).unwrap();
        let out = dir.path().join("libdeps.a");
        whole_archive(&[rlib.display().to_string()], &out).unwrap();
        let bytes = std::fs::read(&out).unwrap();
        let mut a = ar::Archive::new(bytes.as_slice());
        let mut names = Vec::new();
        while let Some(e) = a.next_entry() {
            names.push(String::from_utf8(e.unwrap().header().identifier().to_vec()).unwrap());
        }
        assert_eq!(names, ["x.x.rcgu.o"]);
    }
}
