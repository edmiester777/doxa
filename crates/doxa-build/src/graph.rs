//! The web crate's resolved dependency graph, git dependencies included: the npm packages its
//! crates ask for, and the ones whose Tailwind classes the stylesheet must scan.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use crate::error::{Error, Result};

/// A crate the web crate depends on, directly or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// Package name.
    pub name: String,
    /// Where cargo resolved it: a workspace, registry or git checkout directory.
    pub dir: PathBuf,
    /// Its `[package.metadata.doxa.npm]`.
    pub npm: BTreeMap<String, String>,
    /// Whether it depends on doxa-ui, itself or through doxa.
    pub uses_ui: bool,
}

/// Every crate the web crate reaches through normal dependencies, for the wasm target.
#[derive(Debug, Clone, Default)]
pub struct Graph {
    /// Sorted by name; the web crate isn't one.
    pub members: Vec<Member>,
}

impl Graph {
    /// Run `cargo metadata` from `cwd` for the graph under `web`.
    pub fn load(cwd: &Path, web: &str) -> Result<Self> {
        let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
        cmd.args([
            "metadata",
            "--format-version",
            "1",
            "--filter-platform",
            "wasm32-unknown-unknown",
        ])
        .current_dir(cwd);
        let out = cmd.output().map_err(|e| {
            Error::tool(
                "cargo",
                &cmd,
                format!("could not start: {e}"),
                "install Rust from https://rustup.rs",
            )
        })?;
        if !out.status.success() {
            return Err(Error::tool(
                "cargo",
                &cmd,
                String::from_utf8_lossy(&out.stderr).trim().to_owned(),
                "run doxa from inside a cargo workspace",
            ));
        }
        let json: Value = serde_json::from_slice(&out.stdout)
            .map_err(|e| Error::tool("cargo", &cmd, e.to_string(), "upgrade cargo"))?;
        Ok(Self::from_metadata(&json, web))
    }

    /// The graph under the package named `web` in `cargo metadata` output.
    pub fn from_metadata(meta: &Value, web: &str) -> Self {
        let items = |v: &Value| v.as_array().cloned().unwrap_or_default();
        let packages: HashMap<String, Value> = items(&meta["packages"])
            .into_iter()
            .filter_map(|p| Some((p["id"].as_str()?.to_owned(), p)))
            .collect();
        let deps: HashMap<String, Vec<String>> = items(&meta["resolve"]["nodes"])
            .into_iter()
            .filter_map(|n| {
                let normal = items(&n["deps"])
                    .into_iter()
                    .filter(|d| items(&d["dep_kinds"]).iter().any(|k| k["kind"].is_null()))
                    .filter_map(|d| d["pkg"].as_str().map(str::to_owned))
                    .collect();
                Some((n["id"].as_str()?.to_owned(), normal))
            })
            .collect();
        let name = |id: &str| packages.get(id).and_then(|p| p["name"].as_str());
        let ui: HashSet<&str> = {
            let direct: HashSet<&str> = packages
                .keys()
                .map(String::as_str)
                .filter(|id| name(id) == Some("doxa-ui"))
                .collect();
            let facades = packages.keys().map(String::as_str).filter(|id| {
                name(id) == Some("doxa")
                    && deps
                        .get(*id)
                        .is_some_and(|d| d.iter().any(|d| direct.contains(d.as_str())))
            });
            facades.chain(direct.iter().copied()).collect()
        };
        let Some(root) = items(&meta["workspace_members"])
            .iter()
            .filter_map(Value::as_str)
            .find(|id| name(id) == Some(web))
            .map(str::to_owned)
        else {
            return Self::default();
        };
        let mut seen = HashSet::from([root.clone()]);
        let mut queue = VecDeque::from([root.clone()]);
        let mut members = Vec::new();
        while let Some(id) = queue.pop_front() {
            let own = deps.get(&id).cloned().unwrap_or_default();
            if id != root {
                let p = &packages[&id];
                let npm = p["metadata"]["doxa"]["npm"]
                    .as_object()
                    .map(|o| {
                        o.iter()
                            .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                            .collect()
                    })
                    .unwrap_or_default();
                members.push(Member {
                    name: p["name"].as_str().unwrap_or_default().to_owned(),
                    dir: Path::new(p["manifest_path"].as_str().unwrap_or_default())
                        .parent()
                        .map(Path::to_owned)
                        .unwrap_or_default(),
                    npm,
                    uses_ui: own.iter().any(|d| ui.contains(d.as_str())),
                });
            }
            for d in own {
                if seen.insert(d.clone()) {
                    queue.push_back(d);
                }
            }
        }
        members.sort_by(|a, b| a.name.cmp(&b.name).then(a.dir.cmp(&b.dir)));
        Self { members }
    }

    /// The directories of the crates whose components carry Tailwind classes: each that uses
    /// doxa-ui, other than doxa's own.
    pub fn tailwind_sources(&self) -> Vec<PathBuf> {
        self.members
            .iter()
            .filter(|m| m.uses_ui && m.name != "doxa" && !m.name.starts_with("doxa-"))
            .map(|m| m.dir.clone())
            .collect()
    }

    /// The npm packages the graph asks for, each with its range and the crate asking. `app`, the
    /// web crate's own, wins; two other crates asking different ranges stop the build.
    pub fn npm(
        &self,
        app_name: &str,
        app: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, (String, String)>> {
        let mut out: BTreeMap<String, (String, String)> = app
            .iter()
            .map(|(k, v)| (k.clone(), (v.clone(), app_name.to_owned())))
            .collect();
        for m in &self.members {
            for (pkg, range) in &m.npm {
                match out.get(pkg) {
                    None => {
                        out.insert(pkg.clone(), (range.clone(), m.name.clone()));
                    }
                    Some((_, by)) if by == app_name => {}
                    Some((theirs, by)) if theirs != range => {
                        return Err(Error::config(
                            format!(
                                "npm `{pkg}` is `{theirs}` in `{by}` and `{range}` in `{}`",
                                m.name
                            ),
                            format!(
                                "pick one range in `{app_name}`'s [package.metadata.doxa.npm]; the \
                                 app's own wins"
                            ),
                        ));
                    }
                    Some(_) => {}
                }
            }
        }
        Ok(out)
    }
}

/// Each package `needed` names that the app's own `package.json` doesn't list.
pub fn missing_from(
    package_json: &Value,
    needed: &BTreeMap<String, (String, String)>,
) -> Vec<String> {
    let listed = |name: &str| {
        ["dependencies", "devDependencies", "peerDependencies"]
            .iter()
            .any(|k| package_json[k].get(name).is_some())
    };
    needed
        .iter()
        .filter(|(name, _)| !listed(name))
        .map(|(name, (range, by))| format!("`{name}` (`{range}`, for `{by}`)"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn meta() -> Value {
        let normal = json!([{ "kind": null }]);
        let dev = json!([{ "kind": "dev" }]);
        json!({
            "packages": [
                { "id": "w", "name": "web", "manifest_path": "/app/web/Cargo.toml",
                  "metadata": { "doxa": { "role": "client", "npm": { "react": "^19" } } } },
                { "id": "k", "name": "kit",
                  "manifest_path": "/home/.cargo/git/checkouts/kit-1/abc/Cargo.toml",
                  "metadata": { "doxa": { "npm": { "react": "^18", "motion": "^11" } } } },
                { "id": "c", "name": "charts", "manifest_path": "/app/charts/Cargo.toml",
                  "metadata": { "doxa": { "npm": { "d3": "^7", "react": "^19" } } } },
                { "id": "t", "name": "testkit", "manifest_path": "/app/testkit/Cargo.toml",
                  "metadata": { "doxa": { "npm": { "vitest": "^1" } } } },
                { "id": "d", "name": "doxa", "manifest_path": "/doxa/crates/doxa/Cargo.toml", "metadata": null },
                { "id": "u", "name": "doxa-ui", "manifest_path": "/doxa/crates/doxa-ui/Cargo.toml", "metadata": null },
            ],
            "workspace_members": ["w", "c", "t"],
            "resolve": { "nodes": [
                { "id": "w", "deps": [
                    { "pkg": "k", "dep_kinds": normal }, { "pkg": "c", "dep_kinds": normal },
                    { "pkg": "d", "dep_kinds": normal }, { "pkg": "t", "dep_kinds": dev },
                ] },
                { "id": "k", "deps": [{ "pkg": "d", "dep_kinds": normal }] },
                { "id": "c", "deps": [] },
                { "id": "t", "deps": [] },
                { "id": "d", "deps": [{ "pkg": "u", "dep_kinds": normal }] },
                { "id": "u", "deps": [] },
            ]}
        })
    }

    #[test]
    fn a_git_dependency_using_doxa_ui_is_scanned_at_its_checkout() {
        let graph = Graph::from_metadata(&meta(), "web");
        assert_eq!(
            graph.tailwind_sources(),
            [PathBuf::from("/home/.cargo/git/checkouts/kit-1/abc")]
        );
        assert!(
            graph.members.iter().all(|m| m.name != "testkit"),
            "a dev-dependency isn't in the build"
        );
    }

    #[test]
    fn the_graphs_npm_packages_merge_and_the_apps_range_wins() {
        let graph = Graph::from_metadata(&meta(), "web");
        let app = BTreeMap::from([("react".to_owned(), "^19".to_owned())]);
        let npm = graph.npm("web", &app).unwrap();
        assert_eq!(npm["react"], ("^19".into(), "web".into()));
        assert_eq!(npm["motion"], ("^11".into(), "kit".into()));
        assert_eq!(npm["d3"], ("^7".into(), "charts".into()));
        assert!(!npm.contains_key("vitest"));
    }

    #[test]
    fn two_crates_asking_different_ranges_stop_the_build_naming_both() {
        let graph = Graph::from_metadata(&meta(), "web");
        let err = graph.npm("web", &BTreeMap::new()).unwrap_err().to_string();
        assert!(err.contains("`react`"), "{err}");
        assert!(
            err.contains("`^19` in `charts` and `^18` in `kit`"),
            "{err}"
        );
        assert!(err.contains("`web`'s [package.metadata.doxa.npm]"), "{err}");
    }

    #[test]
    fn an_own_package_json_is_checked_for_what_the_graph_needs() {
        let needed = BTreeMap::from([
            ("react".to_owned(), ("^19".to_owned(), "web".to_owned())),
            ("motion".to_owned(), ("^11".to_owned(), "kit".to_owned())),
        ]);
        let own = json!({ "dependencies": { "react": "^19.1.0" } });
        assert_eq!(missing_from(&own, &needed), ["`motion` (`^11`, for `kit`)"]);
    }
}
