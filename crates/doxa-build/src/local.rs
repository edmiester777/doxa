//! Building a workspace against local checkouts of its git and crates.io dependencies: the
//! workspaces `[workspace.metadata.doxa.dev]` lists under `services` and `patch`.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::Workspace;
use crate::error::{Error, Result};
use crate::graph::{Graph, Member};
use crate::BuildOptions;

/// The `--config` patches for one workspace.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Patches {
    /// `patch.<source>.<crate>.path=<dir>` values.
    pub config: Vec<String>,
    /// Each patched crate and the local directory it builds from.
    pub patched: Vec<(String, PathBuf)>,
    /// Crates a local workspace owns that come from a source doxa can't patch, with that source.
    pub unpatchable: Vec<(String, String)>,
}

/// The workspaces under `[workspace.metadata.doxa.dev.services]`.
pub fn services(ws: &Workspace) -> Result<Vec<Workspace>> {
    ws.dev_services()?
        .into_iter()
        .map(|(name, s)| {
            let hint = format!("check [workspace.metadata.doxa.dev.services] {name}.path");
            Workspace::load_sibling(&s.path, &hint)
        })
        .collect()
}

/// The workspaces under `[workspace.metadata.doxa.dev.patch]`.
pub fn patch_table(ws: &Workspace) -> Result<Vec<Workspace>> {
    ws.dev_patches()?
        .into_iter()
        .map(|(name, path)| {
            let hint = format!("check [workspace.metadata.doxa.dev.patch] {name}");
            Workspace::load_sibling(&path, &hint)
        })
        .collect()
}

/// `all` with each workspace root once.
pub fn unique(all: Vec<Workspace>) -> Vec<Workspace> {
    let mut out: Vec<Workspace> = Vec::with_capacity(all.len());
    for ws in all {
        let root = canonical(&ws.workspace_root);
        if !out.iter().any(|w| canonical(&w.workspace_root) == root) {
            out.push(ws);
        }
    }
    out
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
        let Some(key) = patch_key(m.source.as_deref()) else {
            let source = m.source.clone().unwrap_or_else(|| "a path".into());
            out.unpatchable.push((m.name.clone(), source));
            continue;
        };
        let config = format!(
            "patch.{key}.{}.path={}",
            toml_key(&m.name),
            toml_str(&dir.to_string_lossy())
        );
        if !out.config.contains(&config) {
            out.config.push(config);
            out.patched.push((m.name.clone(), dir));
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

/// The `[patch.<key>]` table for a cargo source: `crates-io`, or the quoted git URL.
fn patch_key(source: Option<&str>) -> Option<String> {
    let s = source?;
    if s == "registry+https://github.com/rust-lang/crates.io-index"
        || s.starts_with("sparse+https://index.crates.io")
    {
        return Some("crates-io".into());
    }
    // git+ssh://host/repo.git?branch=main#sha → ssh://host/repo.git
    let url = s.strip_prefix("git+")?;
    let url = url.split(['?', '#']).next()?;
    Some(toml_str(url))
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
        assert_eq!(p.patched, [("b-api".to_owned(), root.join("api"))]);
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
    fn unique_keeps_the_first_of_each_root() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (local(tmp.path()), local(&tmp.path().join(".")));
        assert_eq!(unique(vec![a, b]).len(), 1);
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
