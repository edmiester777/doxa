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
        Self::from_metadata(&json, web)
    }

    /// The graph under the package named `web` in `cargo metadata` output.
    pub fn from_metadata(meta: &Value, web: &str) -> Result<Self> {
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
            return Ok(Self::default());
        };
        let mut seen = HashSet::from([root.clone()]);
        let mut queue = VecDeque::from([root.clone()]);
        let mut members = Vec::new();
        while let Some(id) = queue.pop_front() {
            let own = deps.get(&id).cloned().unwrap_or_default();
            if id != root {
                let p = &packages[&id];
                let pkg_name = p["name"].as_str().unwrap_or_default();
                let npm = p["metadata"]["doxa"]["npm"]
                    .as_object()
                    .map(|o| {
                        o.iter()
                            .map(|(k, v)| match v.as_str() {
                                Some(range) => Ok((k.clone(), range.to_owned())),
                                None => Err(Error::config(
                                    format!("`{pkg_name}`'s npm `{k}` is {v}, not a version range"),
                                    "write it as a string, like \"^1.2\"",
                                )),
                            })
                            .collect::<Result<_>>()
                    })
                    .transpose()?
                    .unwrap_or_default();
                members.push(Member {
                    name: pkg_name.to_owned(),
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
        Ok(Self { members })
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

    /// The web crate's npm packages, each with its range and the crate asking. A package another
    /// crate asks for installs only once `app`, the web crate's own, lists it.
    pub fn npm(
        &self,
        app_name: &str,
        app: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, (String, String)>> {
        let unlisted: Vec<String> = self
            .members
            .iter()
            .flat_map(|m| m.npm.iter().map(move |(pkg, range)| (m, pkg, range)))
            .filter(|(_, pkg, _)| !app.contains_key(*pkg))
            .map(|(m, pkg, range)| format!("{pkg} = \"{range}\" (for `{}`)", m.name))
            .collect();
        if !unlisted.is_empty() {
            return Err(Error::config(
                format!(
                    "dependencies ask for npm packages `{app_name}` doesn't list: {}",
                    unlisted.join(", ")
                ),
                format!("add them to `{app_name}`'s [package.metadata.doxa.npm] to install them"),
            ));
        }
        Ok(app
            .iter()
            .map(|(k, v)| (k.clone(), (v.clone(), app_name.to_owned())))
            .collect())
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
        let graph = Graph::from_metadata(&meta(), "web").unwrap();
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
    fn a_package_the_app_lists_installs_at_the_apps_range() {
        let graph = Graph::from_metadata(&meta(), "web").unwrap();
        let app = BTreeMap::from(
            [("react", "^19"), ("motion", "^11"), ("d3", "^7")].map(|(k, v)| (k.into(), v.into())),
        );
        let npm = graph.npm("web", &app).unwrap();
        assert_eq!(npm["react"], ("^19".into(), "web".into()));
        assert_eq!(npm["motion"], ("^11".into(), "web".into()));
        assert!(!npm.contains_key("vitest"));
    }

    #[test]
    fn a_package_only_a_dependency_asks_for_stops_the_build() {
        let graph = Graph::from_metadata(&meta(), "web").unwrap();
        let app = BTreeMap::from([("react".to_owned(), "^19".to_owned())]);
        let err = graph.npm("web", &app).unwrap_err().to_string();
        assert!(err.contains("motion = \"^11\" (for `kit`)"), "{err}");
        assert!(err.contains("d3 = \"^7\" (for `charts`)"), "{err}");
        assert!(!err.contains("react"), "{err}");
        assert!(err.contains("`web`'s [package.metadata.doxa.npm]"), "{err}");
    }

    #[test]
    fn an_npm_range_that_isnt_a_string_is_an_error() {
        let mut meta = meta();
        meta["packages"][1]["metadata"]["doxa"]["npm"]["motion"] = json!(11);
        let err = Graph::from_metadata(&meta, "web").unwrap_err().to_string();
        assert!(err.contains("`kit`'s npm `motion` is 11"), "{err}");
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
