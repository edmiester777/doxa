//! Building a workspace against local checkouts of its git and crates.io dependencies: the
//! workspaces `[workspace.metadata.doxa.dev]` lists under `services` and `patch`.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::Workspace;
use crate::error::{Error, Result};
use crate::graph::{Graph, Member};
use crate::BuildOptions;

/// The patches for one workspace.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Patches {
    /// `patch.<source>.<crate>.path=<dir>` values for `cargo --config`.
    pub config: Vec<String>,
    /// Each patched crate, in `config`'s order.
    pub patched: Vec<Patch>,
    /// Crates a local workspace owns that come from a source doxa can't patch, with that source.
    pub unpatchable: Vec<(String, String)>,
}

/// One `[patch.<table>] <name> = { path = <dir> }` entry.
#[derive(Debug, Clone, PartialEq)]
pub struct Patch {
    /// `crates-io`, or the git URL.
    pub table: String,
    /// The crate.
    pub name: String,
    /// The local directory it builds from.
    pub dir: PathBuf,
}

/// The local workspaces a `[workspace.metadata.doxa.dev]` table lists, and the entries whose
/// path has no `Cargo.toml` on this machine.
#[derive(Debug, Clone, Default)]
pub struct Locals {
    /// Each root once.
    pub workspaces: Vec<Workspace>,
    /// Entries left unpatched.
    pub absent: Vec<Absent>,
}

/// An entry whose path has no `Cargo.toml`.
#[derive(Debug, Clone, PartialEq)]
pub struct Absent {
    /// `services` or `patch`.
    pub table: &'static str,
    /// The entry's name.
    pub name: String,
    /// Its path, absolute.
    pub path: PathBuf,
}

impl std::fmt::Display for Absent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[workspace.metadata.doxa.dev.{}] {}: {} has no Cargo.toml, so its crates stay unpatched",
            self.table,
            self.name,
            self.path.display()
        )
    }
}

impl Locals {
    /// `[workspace.metadata.doxa.dev.services]` and `.patch` together.
    pub fn all(ws: &Workspace) -> Result<Locals> {
        let mut locals = Locals::services(ws)?;
        locals.extend(Locals::patch_table(ws)?);
        Ok(locals)
    }

    /// `[workspace.metadata.doxa.dev.services]`.
    pub fn services(ws: &Workspace) -> Result<Locals> {
        let entries = ws.dev_services()?.into_iter().map(|(n, s)| (n, s.path));
        Locals::load("services", entries)
    }

    /// `[workspace.metadata.doxa.dev.patch]`.
    pub fn patch_table(ws: &Workspace) -> Result<Locals> {
        Locals::load("patch", ws.dev_patches()?)
    }

    fn load(
        table: &'static str,
        entries: impl IntoIterator<Item = (String, PathBuf)>,
    ) -> Result<Locals> {
        let mut locals = Locals::default();
        for (name, path) in entries {
            if !path.join("Cargo.toml").is_file() {
                locals.absent.push(Absent { table, name, path });
                continue;
            }
            let hint = format!("check [workspace.metadata.doxa.dev.{table}] {name}");
            locals.push(Workspace::load_sibling(&path, &hint)?);
        }
        Ok(locals)
    }

    /// Add `ws` unless its root is already here.
    pub fn push(&mut self, ws: Workspace) {
        let root = canonical(&ws.workspace_root);
        if !self
            .workspaces
            .iter()
            .any(|w| canonical(&w.workspace_root) == root)
        {
            self.workspaces.push(ws);
        }
    }

    /// Add `other`'s workspaces and absent entries.
    pub fn extend(&mut self, other: Locals) {
        other.workspaces.into_iter().for_each(|ws| self.push(ws));
        self.absent.extend(other.absent);
    }

    /// The workspaces, borrowed.
    pub fn refs(&self) -> Vec<&Workspace> {
        self.workspaces.iter().collect()
    }
}

/// [`patches`] over every crate the workspace at `root` resolves, run with `cargo`; a local
/// workspace that is `root` itself is skipped.
pub fn for_workspace(root: &Path, cargo: Command, locals: &[&Workspace]) -> Result<Patches> {
    let me = canonical(root);
    let others: Vec<&Workspace> = locals
        .iter()
        .copied()
        .filter(|w| canonical(&w.workspace_root) != me)
        .collect();
    if others.is_empty() {
        return Ok(Patches::default());
    }
    patches(&Graph::resolved(root, cargo)?.members, &others)
}

/// Patches pointing each crate in `members` that one of `locals` owns at that local copy.
pub fn patches(members: &[Member], locals: &[&Workspace]) -> Result<Patches> {
    let mut out = Patches::default();
    for m in members {
        let owners: Vec<_> = locals
            .iter()
            .filter(|ws| ws.package(&m.name).is_some())
            .collect();
        let ws = match owners.as_slice() {
            [] => continue,
            [one] => one,
            many => {
                let roots: Vec<_> = many
                    .iter()
                    .map(|w| w.workspace_root.display().to_string())
                    .collect();
                return Err(Error::config(
                    format!(
                        "`{}` is in more than one local workspace: {}",
                        m.name,
                        roots.join(", ")
                    ),
                    "list only one of them in [workspace.metadata.doxa.dev]",
                ));
            }
        };
        let dir = canonical(ws.package(&m.name).expect("owned").dir());
        if canonical(&m.dir) == dir {
            continue;
        }
        let Some(table) = patch_table_of(m.source.as_deref()) else {
            let source = m.source.clone().unwrap_or_else(|| "a path".into());
            out.unpatchable.push((m.name.clone(), source));
            continue;
        };
        let config = format!(
            "patch.{}.{}.path={}",
            config_key(&table),
            toml_key(&m.name),
            toml_str(&dir.to_string_lossy())
        );
        if !out.config.contains(&config) {
            out.config.push(config);
            out.patched.push(Patch {
                table,
                name: m.name.clone(),
                dir,
            });
        }
    }
    Ok(out)
}

/// The `cargo` doxa runs under, for this workspace.
pub fn cargo() -> Command {
    Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
}

/// `cargo build` the server of a workspace without a web crate.
pub fn build_server(ws: &Workspace, server: &str, opts: &BuildOptions) -> Result<()> {
    opts.output.note(format!("building {server}"));
    let mut cmd = cargo();
    for c in &opts.cargo_config {
        cmd.args(["--config", c]);
    }
    cmd.args(["build", "-p", server])
        .current_dir(&ws.workspace_root);
    if opts.release {
        cmd.arg("--release");
    }
    opts.output
        .run("cargo", &mut cmd, "fix the compile error above")
}

/// The `[patch.<table>]` for a cargo source: `crates-io`, or the git URL.
fn patch_table_of(source: Option<&str>) -> Option<String> {
    let s = source?;
    if s == "registry+https://github.com/rust-lang/crates.io-index"
        || s.starts_with("sparse+https://index.crates.io")
    {
        return Some("crates-io".into());
    }
    // git+ssh://host/repo.git?branch=main#sha → ssh://host/repo.git
    let url = s.strip_prefix("git+")?;
    Some(url.split(['?', '#']).next()?.to_owned())
}

/// Puts a workspace's `.cargo/config.toml` back as it was when dropped, after
/// [`ConfigGuard::write`] adds the patches to it.
pub struct ConfigGuard {
    path: PathBuf,
    bytes: Option<Vec<u8>>,
    /// `.cargo`, when doxa created it.
    made_dir: Option<PathBuf>,
}

impl ConfigGuard {
    /// Merge `patches` into `root`'s cargo config, theirs winning over an entry for the same crate.
    pub fn write(root: &Path, patches: &[Patch]) -> Result<ConfigGuard> {
        let dir = root.join(".cargo");
        // Cargo reads the extensionless legacy name when it is the only one.
        let legacy = dir.join("config");
        let path = match legacy.is_file() && !dir.join("config.toml").exists() {
            true => legacy,
            false => dir.join("config.toml"),
        };
        let bytes = std::fs::read(&path).ok();
        let mut table: toml::Table = match &bytes {
            Some(b) => String::from_utf8_lossy(b).parse().map_err(|e| {
                Error::config(
                    format!("{}: {e}", path.display()),
                    "fix the file so doxa can add its [patch] tables",
                )
            })?,
            None => toml::Table::new(),
        };
        for p in patches {
            let mut entry = toml::Table::new();
            entry.insert("path".into(), p.dir.to_string_lossy().into_owned().into());
            table
                .entry("patch")
                .or_insert_with(|| toml::Table::new().into())
                .as_table_mut()
                .ok_or_else(|| {
                    Error::config(
                        format!("{}: `patch` isn't a table", path.display()),
                        "make it one",
                    )
                })?
                .entry(p.table.clone())
                .or_insert_with(|| toml::Table::new().into())
                .as_table_mut()
                .ok_or_else(|| {
                    Error::config(
                        format!("{}: `patch.{}` isn't a table", path.display(), p.table),
                        "make it one",
                    )
                })?
                .insert(p.name.clone(), entry.into());
        }
        let made_dir = (!dir.exists()).then(|| dir.clone());
        let guard = ConfigGuard {
            path: path.clone(),
            bytes,
            made_dir,
        };
        std::fs::create_dir_all(&dir)
            .and_then(|()| std::fs::write(&path, table.to_string()))
            .map_err(|e| {
                Error::config(
                    format!("writing {}: {e}", path.display()),
                    "check the directory is writable",
                )
            })?;
        Ok(guard)
    }
}

impl Drop for ConfigGuard {
    fn drop(&mut self) {
        let _ = match &self.bytes {
            Some(b) => std::fs::write(&self.path, b),
            None => std::fs::remove_file(&self.path),
        };
        if let Some(dir) = &self.made_dir {
            let _ = std::fs::remove_dir(dir);
        }
    }
}

/// The `--config` key for a patch table: `crates-io` bare, a git URL quoted.
fn config_key(table: &str) -> String {
    match table == "crates-io" {
        true => table.to_owned(),
        false => toml_str(table),
    }
}

fn toml_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn toml_key(s: &str) -> String {
    match s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        true => s.to_owned(),
        false => toml_str(s),
    }
}

fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned())
}

/// Puts a workspace's `Cargo.lock` back as it was when dropped.
pub struct LockGuard {
    path: PathBuf,
    bytes: Option<Vec<u8>>,
}

impl LockGuard {
    /// Remember `root`'s `Cargo.lock`, or that it has none.
    pub fn take(root: &Path) -> LockGuard {
        let path = root.join("Cargo.lock");
        let bytes = std::fs::read(&path).ok();
        LockGuard { path, bytes }
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = match &self.bytes {
            Some(b) => std::fs::write(&self.path, b),
            None => std::fs::remove_file(&self.path),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_git_or_crates_io_source_names_its_patch_table() {
        let patch_key = |s: Option<&str>| patch_table_of(s).map(|t| config_key(&t));
        let git = |s: &str| patch_key(Some(s));
        assert_eq!(
            git("git+ssh://git@host/b.git?branch=main#0123abc").as_deref(),
            Some("\"ssh://git@host/b.git\"")
        );
        assert_eq!(
            git("git+https://host/b.git?rev=0123#0123").as_deref(),
            Some("\"https://host/b.git\"")
        );
        assert_eq!(
            git("git+https://host/b.git#0123").as_deref(),
            Some("\"https://host/b.git\"")
        );
        assert_eq!(
            git("registry+https://github.com/rust-lang/crates.io-index").as_deref(),
            Some("crates-io")
        );
        assert_eq!(
            git("sparse+https://index.crates.io/").as_deref(),
            Some("crates-io")
        );
        assert_eq!(git("registry+https://my.registry/index"), None);
        assert_eq!(patch_key(None), None);
    }

    fn local(root: &Path) -> Workspace {
        let json = format!(
            r#"{{"workspace_root": "{r}", "target_directory": "{r}/target", "packages": [
              {{"name": "b-api", "manifest_path": "{r}/api/Cargo.toml", "targets": [], "dependencies": []}}]}}"#,
            r = root.display()
        );
        Workspace::from_json(&json).unwrap()
    }

    fn member(dir: &Path, source: Option<&str>) -> Member {
        Member {
            name: "b-api".into(),
            dir: dir.to_owned(),
            source: source.map(Into::into),
            npm: Default::default(),
            uses_ui: false,
        }
    }

    #[test]
    fn a_crate_already_resolved_to_the_local_copy_needs_no_patch() {
        let tmp = tempfile::tempdir().unwrap();
        let root = canonical(tmp.path());
        std::fs::create_dir_all(root.join("api")).unwrap();
        let p = patches(&[member(&root.join("api"), None)], &[&local(&root)]).unwrap();
        assert_eq!(p, Patches::default());
    }

    #[test]
    fn a_crate_from_git_is_patched_once_to_the_local_copy() {
        let tmp = tempfile::tempdir().unwrap();
        let root = canonical(tmp.path());
        std::fs::create_dir_all(root.join("api")).unwrap();
        let checkout = Path::new("/home/me/.cargo/git/checkouts/b/api");
        let m = member(checkout, Some("git+https://host/b.git#01"));
        let p = patches(&[m.clone(), m], &[&local(&root)]).unwrap();
        assert_eq!(
            p.config,
            [format!(
                "patch.\"https://host/b.git\".b-api.path=\"{}\"",
                root.join("api").display()
            )]
        );
        assert_eq!(
            p.patched,
            [Patch {
                table: "https://host/b.git".into(),
                name: "b-api".into(),
                dir: root.join("api"),
            }]
        );
    }

    #[test]
    fn a_crate_from_another_path_is_unpatchable_and_two_owners_fail() {
        let tmp = tempfile::tempdir().unwrap();
        let root = canonical(tmp.path());
        std::fs::create_dir_all(root.join("api")).unwrap();
        let ws = local(&root);
        let p = patches(&[member(Path::new("/elsewhere/api"), None)], &[&ws]).unwrap();
        assert_eq!(p.unpatchable, [("b-api".to_owned(), "a path".to_owned())]);
        assert!(p.config.is_empty());
        let m = member(
            Path::new("/elsewhere/api"),
            Some("git+https://host/b.git#01"),
        );
        assert!(patches(&[m], &[&ws, &ws]).is_err());
    }

    #[test]
    fn locals_keep_each_root_once_and_an_entry_without_a_manifest_is_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let mut locals = Locals::default();
        locals.push(local(tmp.path()));
        locals.push(local(&tmp.path().join(".")));
        assert_eq!(locals.workspaces.len(), 1);
        let gone = tmp.path().join("gone");
        let loaded = Locals::load("patch", [("lib".to_owned(), gone.clone())]).unwrap();
        assert!(loaded.workspaces.is_empty());
        assert_eq!(
            loaded.absent,
            [Absent {
                table: "patch",
                name: "lib".into(),
                path: gone
            }]
        );
    }

    #[test]
    fn the_config_guard_merges_patches_and_puts_the_config_back() {
        let tmp = tempfile::tempdir().unwrap();
        let patch = |name: &str| Patch {
            table: "ssh://git@host/b.git".into(),
            name: name.into(),
            dir: "/src/b/api".into(),
        };
        drop(ConfigGuard::write(tmp.path(), &[patch("b-api")]).unwrap());
        assert!(!tmp.path().join(".cargo").exists());

        let config = tmp.path().join(".cargo/config.toml");
        let before = "[build]\njobs = 2\n\n[patch.\"ssh://git@host/b.git\"]\nb-api = { path = \"/old\" }\nb-db = { path = \"/db\" }\n";
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(&config, before).unwrap();
        let guard = ConfigGuard::write(tmp.path(), &[patch("b-api")]).unwrap();
        let during: toml::Table = std::fs::read_to_string(&config).unwrap().parse().unwrap();
        let table = &during["patch"]["ssh://git@host/b.git"];
        assert_eq!(table["b-api"]["path"].as_str(), Some("/src/b/api"));
        assert_eq!(table["b-db"]["path"].as_str(), Some("/db"));
        assert_eq!(during["build"]["jobs"].as_integer(), Some(2));
        drop(guard);
        assert_eq!(std::fs::read_to_string(&config).unwrap(), before);
    }

    #[test]
    fn the_lock_guard_restores_the_bytes_or_removes_a_new_file() {
        let tmp = tempfile::tempdir().unwrap();
        let lock = tmp.path().join("Cargo.lock");
        std::fs::write(&lock, "before").unwrap();
        drop({
            let guard = LockGuard::take(tmp.path());
            std::fs::write(&lock, "patched").unwrap();
            guard
        });
        assert_eq!(std::fs::read_to_string(&lock).unwrap(), "before");
        std::fs::remove_file(&lock).unwrap();
        drop({
            let guard = LockGuard::take(tmp.path());
            std::fs::write(&lock, "patched").unwrap();
            guard
        });
        assert!(!lock.exists());
    }
}
