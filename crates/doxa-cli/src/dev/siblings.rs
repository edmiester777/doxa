//! Compiling the web crate against each dev service's local source.

use std::path::{Path, PathBuf};

use doxa_build::config::Workspace;
use doxa_build::graph::Graph;
use doxa_build::pipeline::note;

use super::watch::{canonical, Foreign};

/// The `--config` patches that point the web crate's git or crates.io copies of dev service
/// crates at the local ones, and the directories those crates add to the watch.
pub fn wire(graph: &Graph, siblings: &[&Workspace]) -> Result<(Vec<String>, Foreign), String> {
    let (mut patches, mut foreign) = (Vec::new(), Foreign::default());
    let mut used = Vec::new();
    for m in &graph.members {
        let owners: Vec<_> = siblings
            .iter()
            .filter(|ws| ws.package(&m.name).is_some())
            .collect();
        let ws = match owners.as_slice() {
            [] => continue,
            [one] => one,
            _ => {
                return Err(format!(
                    "`{}` is in more than one [workspace.metadata.doxa.dev.services] workspace",
                    m.name
                ))
            }
        };
        let dir = canonical(ws.package(&m.name).expect("owned").dir());
        if canonical(&m.dir) != dir {
            let Some(key) = patch_key(m.source.as_deref()) else {
                note(format!(
                    "{} comes from {}, which doxa can't patch; its edits won't reach the browser",
                    m.name,
                    m.source.as_deref().unwrap_or("a path")
                ));
                continue;
            };
            patches.push(format!(
                "patch.{key}.{}.path={}",
                toml_key(&m.name),
                toml_str(&dir.to_string_lossy())
            ));
        }
        foreign.wasm_dirs.push(dir);
        if !used.contains(&ws.workspace_root) {
            used.push(ws.workspace_root.clone());
            let (server_only, client_only) = ws.sided_dirs();
            foreign.server_only.extend(server_only);
            foreign.client_only.extend(client_only);
        }
    }
    Ok((patches, foreign))
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

/// Puts `Cargo.lock` back as it was, however `doxa dev` returns.
pub struct LockGuard {
    path: PathBuf,
    bytes: Option<Vec<u8>>,
}

impl LockGuard {
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
    use doxa_build::graph::Member;

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

    fn sibling(root: &Path) -> Workspace {
        let json = format!(
            r#"{{"workspace_root": "{r}", "target_directory": "{r}/target", "packages": [
              {{"name": "b-api", "manifest_path": "{r}/api/Cargo.toml", "targets": [], "dependencies": [],
                "metadata": {{"doxa": {{"server_only": ["src/server"]}}}}}}]}}"#,
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
    fn a_member_already_resolved_to_the_sibling_needs_no_patch() {
        let tmp = tempfile::tempdir().unwrap();
        let root = canonical(tmp.path());
        std::fs::create_dir_all(root.join("api")).unwrap();
        let ws = sibling(&root);
        let graph = Graph {
            members: vec![member(&root.join("api"), None)],
        };
        let (patches, foreign) = wire(&graph, &[&ws]).unwrap();
        assert!(patches.is_empty());
        assert_eq!(foreign.wasm_dirs, [root.join("api")]);
        assert_eq!(foreign.server_only, [root.join("api/src/server")]);
    }

    #[test]
    fn a_member_from_a_git_checkout_is_patched_to_the_sibling() {
        let tmp = tempfile::tempdir().unwrap();
        let root = canonical(tmp.path());
        std::fs::create_dir_all(root.join("api")).unwrap();
        let ws = sibling(&root);
        let checkout = Path::new("/home/me/.cargo/git/checkouts/b/api");
        let graph = Graph {
            members: vec![member(checkout, Some("git+https://host/b.git#01"))],
        };
        let (patches, foreign) = wire(&graph, &[&ws]).unwrap();
        assert_eq!(
            patches,
            [format!(
                "patch.\"https://host/b.git\".b-api.path=\"{}\"",
                root.join("api").display()
            )]
        );
        assert_eq!(foreign.wasm_dirs, [root.join("api")]);
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
