//! The directories local workspaces add to the web crate's watch.

use doxa_build::config::Workspace;
use doxa_build::graph::Graph;

use super::watch::{canonical, Foreign};

/// Each local crate the web crate compiles, and the sided directories of their workspaces.
pub fn watched(graph: &Graph, locals: &[&Workspace]) -> Foreign {
    let mut foreign = Foreign::default();
    let mut used = Vec::new();
    for m in &graph.members {
        let Some((ws, pkg)) = locals
            .iter()
            .find_map(|ws| Some((ws, ws.package(&m.name)?)))
        else {
            continue;
        };
        foreign.wasm_dirs.push(canonical(pkg.dir()));
        if !used.contains(&ws.workspace_root) {
            used.push(ws.workspace_root.clone());
            let (server_only, client_only) = ws.sided_dirs();
            foreign.server_only.extend(server_only);
            foreign.client_only.extend(client_only);
        }
    }
    foreign
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use doxa_build::graph::Member;

    fn local(root: &Path) -> Workspace {
        let json = format!(
            r#"{{"workspace_root": "{r}", "target_directory": "{r}/target", "packages": [
              {{"name": "b-api", "manifest_path": "{r}/api/Cargo.toml", "targets": [], "dependencies": [],
                "metadata": {{"doxa": {{"server_only": ["src/server"]}}}}}}]}}"#,
            r = root.display()
        );
        Workspace::from_json(&json).unwrap()
    }

    #[test]
    fn a_local_crate_and_its_sided_dirs_are_watched_wherever_cargo_resolved_it() {
        let tmp = tempfile::tempdir().unwrap();
        let root = canonical(tmp.path());
        std::fs::create_dir_all(root.join("api")).unwrap();
        let ws = local(&root);
        let graph = Graph {
            members: vec![Member {
                name: "b-api".into(),
                dir: "/home/me/.cargo/git/checkouts/b/api".into(),
                source: Some("git+https://host/b.git#01".into()),
                npm: Default::default(),
                uses_ui: false,
            }],
        };
        let foreign = watched(&graph, &[&ws]);
        assert_eq!(foreign.wasm_dirs, [root.join("api")]);
        assert_eq!(foreign.server_only, [root.join("api/src/server")]);
    }
}
