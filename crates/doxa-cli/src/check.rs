//! `doxa check --wire`: whether an API crate builds for the browser, and which dependency stops it;
//! and, for it and `doxa build`, whether the graph links two copies of a crate that must be one.

use std::collections::{HashMap, HashSet, VecDeque};
use std::process::Command;

use serde_json::Value;

pub const TARGET: &str = "wasm32-unknown-unknown";

type Failure = Box<dyn std::error::Error>;

/// Check `package` for wasm, naming each dependency that doesn't build and how it is reached.
pub fn wire(package: &str) -> Result<(), Failure> {
    let meta = metadata(Some(TARGET))?;
    let graph = Graph::new(&meta);
    let root = graph
        .member(package)
        .ok_or_else(|| format!("no package `{package}` in the workspace"))?;
    graph.one_copy(root)?;
    let out = cargo()
        .args([
            "check",
            "-p",
            package,
            "--lib",
            "--target",
            TARGET,
            "--message-format=json",
        ])
        .output()?;
    if out.status.success() {
        println!("{package} builds for {TARGET}");
        return Ok(());
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let (rendered, failed) = failures(&stdout, &stderr);
    if rendered
        .iter()
        .any(|(_, r)| r.contains("may not be installed"))
    {
        return Err(
            format!("the {TARGET} target isn't installed: rustup target add {TARGET}").into(),
        );
    }
    let deps: Vec<&str> = failed
        .iter()
        .map(String::as_str)
        .filter(|n| *n != package)
        .collect();
    if deps.is_empty() {
        let own: Vec<_> = rendered.iter().filter(|(n, _)| n == package).collect();
        own.iter().for_each(|(_, r)| eprint!("{r}"));
        if own.is_empty() {
            eprint!("{stderr}");
        }
        return Err(format!("{package} doesn't build for {TARGET}").into());
    }
    for dep in &deps {
        match graph.chain(root, dep) {
            Some(chain) => eprintln!(
                "`{dep}` doesn't build for {TARGET}; {package} reaches it through\n  {}",
                chain.join(" → ")
            ),
            None => eprintln!("`{dep}` doesn't build for {TARGET}"),
        }
    }
    Err(format!(
        "{package} pulls in {} dependenc{} the browser can't build; list {} under \
         [target.'cfg(not(target_arch = \"wasm32\"))'.dependencies] and keep what uses it behind `#[server]`",
        deps.len(),
        if deps.len() == 1 { "y" } else { "ies" },
        if deps.len() == 1 { "it" } else { "them" },
    )
    .into())
}

/// Crates an app links once: a second copy is a second cache, service registry and route table.
const SINGLE: &[&str] = &["doxa-client", "doxa-wire"];

/// Stop when `package`'s graph, for `platform` or every one, links two copies of a [`SINGLE`]
/// crate, naming how each is reached.
pub fn one_copy(package: &str, platform: Option<&str>) -> Result<(), Failure> {
    let meta = metadata(platform)?;
    let graph = Graph::new(&meta);
    let root = graph
        .member(package)
        .ok_or_else(|| format!("no package `{package}` in the workspace"))?;
    graph.one_copy(root)
}

fn cargo() -> Command {
    Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
}

fn metadata(platform: Option<&str>) -> Result<Value, Failure> {
    let mut cmd = cargo();
    cmd.args(["metadata", "--format-version", "1"]);
    if let Some(p) = platform {
        cmd.args(["--filter-platform", p]);
    }
    let out = cmd.output()?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr)
            .trim()
            .to_owned()
            .into());
    }
    Ok(serde_json::from_slice(&out.stdout)?)
}

/// Each package's rendered errors in cargo's JSON output, and the names of the packages that failed.
fn failures(stdout: &str, stderr: &str) -> (Vec<(String, String)>, Vec<String>) {
    let mut rendered = Vec::new();
    let mut failed = Vec::new();
    let mut push = |name: &str| {
        if !failed.iter().any(|f| f == name) {
            failed.push(name.to_owned());
        }
    };
    for line in stdout.lines() {
        let Ok(msg) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if msg["reason"] != "compiler-message" || msg["message"]["level"] != "error" {
            continue;
        }
        let Some(name) = msg["package_id"].as_str().and_then(package_name) else {
            continue;
        };
        if let Some(r) = msg["message"]["rendered"].as_str() {
            rendered.push((name.to_owned(), r.to_owned()));
        }
        push(name);
    }
    for line in stderr.lines() {
        let quoted = [
            "could not compile `",
            "failed to run custom build command for `",
        ]
        .iter()
        .find_map(|p| line.split_once(p).map(|(_, rest)| rest));
        if let Some(name) = quoted.and_then(|q| q.split(['`', ' ']).next()) {
            push(name);
        }
    }
    (rendered, failed)
}

/// The name in a package id: `registry+…#mio@1.0.2`, `path+file:///…/api#0.1.0` or `mio 1.0.2 (…)`.
fn package_name(id: &str) -> Option<&str> {
    if let Some((source, spec)) = id.rsplit_once('#') {
        return match spec.split_once('@') {
            Some((name, _)) => Some(name),
            None => source.rsplit('/').next(),
        };
    }
    id.split(' ').next()
}

fn items(v: &Value) -> &[Value] {
    v.as_array().map_or(&[], Vec::as_slice)
}

/// One copy of a crate: its label, and the package names on the path to it.
type Found<'g, 'a> = (&'g str, Vec<&'a str>);

/// The resolved dependency graph for the wasm target, normal edges only.
struct Graph<'a> {
    names: HashMap<&'a str, &'a str>,
    /// `name version (source)`, to tell copies apart.
    labels: HashMap<&'a str, String>,
    members: Vec<&'a str>,
    deps: HashMap<&'a str, Vec<&'a str>>,
}

impl<'a> Graph<'a> {
    fn new(meta: &'a Value) -> Self {
        let names = items(&meta["packages"])
            .iter()
            .filter_map(|p| Some((p["id"].as_str()?, p["name"].as_str()?)))
            .collect();
        let labels = items(&meta["packages"])
            .iter()
            .filter_map(|p| {
                let source = p["source"].as_str().unwrap_or("path");
                let source = source.split('#').next().unwrap_or(source);
                let label = format!(
                    "{} {} ({source})",
                    p["name"].as_str()?,
                    p["version"].as_str().unwrap_or("?")
                );
                Some((p["id"].as_str()?, label))
            })
            .collect();
        let members = items(&meta["workspace_members"])
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let deps = items(&meta["resolve"]["nodes"])
            .iter()
            .filter_map(|n| {
                let normal = n["deps"]
                    .as_array()?
                    .iter()
                    .filter(|d| {
                        d["dep_kinds"]
                            .as_array()
                            .is_some_and(|k| k.iter().any(|k| k["kind"].is_null()))
                    })
                    .filter_map(|d| d["pkg"].as_str())
                    .collect();
                Some((n["id"].as_str()?, normal))
            })
            .collect();
        Self {
            names,
            labels,
            members,
            deps,
        }
    }

    fn member(&self, name: &str) -> Option<&'a str> {
        self.members
            .iter()
            .copied()
            .find(|id| self.names.get(id) == Some(&name))
    }

    /// Every package `root` reaches, in breadth-first order, each with the one it was reached from.
    fn reach(&self, root: &'a str) -> (Vec<&'a str>, HashMap<&'a str, &'a str>) {
        let mut seen = HashSet::from([root]);
        let mut back = HashMap::new();
        let mut order = Vec::new();
        let mut queue = VecDeque::from([root]);
        while let Some(id) = queue.pop_front() {
            order.push(id);
            for dep in self.deps.get(id).into_iter().flatten() {
                if seen.insert(dep) {
                    back.insert(*dep, id);
                    queue.push_back(dep);
                }
            }
        }
        (order, back)
    }

    /// Package names from the root to `id`, along `back`.
    fn path(&self, back: &HashMap<&'a str, &'a str>, id: &'a str) -> Vec<&'a str> {
        let mut path = vec![self.names[id]];
        let mut at = id;
        while let Some(prev) = back.get(at) {
            path.push(self.names[prev]);
            at = prev;
        }
        path.reverse();
        path
    }

    /// The shortest path of package names from `root` to the package named `to`.
    fn chain(&self, root: &'a str, to: &str) -> Option<Vec<&'a str>> {
        let (order, back) = self.reach(root);
        let id = order
            .into_iter()
            .find(|id| self.names.get(id) == Some(&to))?;
        Some(self.path(&back, id))
    }

    /// Each [`SINGLE`] crate `root` reaches more than one copy of, with the path to each copy.
    fn copies(&self, root: &'a str) -> Vec<(&'static str, Vec<Found<'_, 'a>>)> {
        let (order, back) = self.reach(root);
        SINGLE
            .iter()
            .filter_map(|name| {
                let found: Vec<_> = order
                    .iter()
                    .filter(|id| self.names.get(*id) == Some(name))
                    .map(|id| (self.labels[id].as_str(), self.path(&back, id)))
                    .collect();
                (found.len() > 1).then_some((*name, found))
            })
            .collect()
    }

    /// `Err` naming each crate `root` links twice and how it reaches each copy.
    fn one_copy(&self, root: &'a str) -> Result<(), Failure> {
        let twice = self.copies(root);
        if twice.is_empty() {
            return Ok(());
        }
        let mut msg = String::new();
        for (name, found) in &twice {
            msg.push_str(&format!("`{name}` is linked {} times:\n", found.len()));
            for (label, path) in found {
                msg.push_str(&format!("  {label}: {}\n", path.join(" → ")));
            }
        }
        msg.push_str("depend on one doxa, from one source, everywhere in the graph");
        Err(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_package_is_named_by_any_id_cargo_writes() {
        assert_eq!(
            package_name("registry+https://github.com/rust-lang/crates.io-index#mio@1.0.2"),
            Some("mio")
        );
        assert_eq!(package_name("path+file:///w/orders/api#0.0.0"), Some("api"));
        assert_eq!(
            package_name("path+file:///w/x#orders-api@0.0.0"),
            Some("orders-api")
        );
        assert_eq!(package_name("mio 1.0.2 (registry+https://x)"), Some("mio"));
    }

    #[test]
    fn the_failures_are_the_errors_and_the_crates_that_wouldnt_build() {
        let stdout = json!({
            "reason": "compiler-message",
            "package_id": "registry+https://x#mio@1.0.2",
            "message": { "level": "error", "rendered": "error: no socket\n" }
        })
        .to_string()
            + "\n"
            + &json!({ "reason": "compiler-message", "package_id": "registry+https://x#ok@1.0.0", "message": { "level": "warning", "rendered": "w" } }).to_string();
        let stderr = "error: could not compile `mio` (lib) due to 1 previous error\n\
                      error: failed to run custom build command for `ring v0.17.8`\n";
        let (rendered, failed) = failures(&stdout, stderr);
        assert_eq!(rendered, [("mio".into(), "error: no socket\n".into())]);
        assert_eq!(failed, ["mio", "ring"]);
    }

    #[test]
    fn the_chain_is_the_shortest_normal_path_to_the_dependency() {
        let normal = json!([{ "kind": null }]);
        let dev = json!([{ "kind": "dev" }]);
        let meta = json!({
            "packages": [
                { "id": "a", "name": "api" }, { "id": "c", "name": "core" },
                { "id": "o", "name": "orm" }, { "id": "m", "name": "mio" },
            ],
            "workspace_members": ["a"],
            "resolve": { "nodes": [
                { "id": "a", "deps": [{ "pkg": "c", "dep_kinds": normal }, { "pkg": "m", "dep_kinds": dev }] },
                { "id": "c", "deps": [{ "pkg": "o", "dep_kinds": normal }] },
                { "id": "o", "deps": [{ "pkg": "m", "dep_kinds": normal }] },
                { "id": "m", "deps": [] },
            ]}
        });
        let graph = Graph::new(&meta);
        let root = graph.member("api").unwrap();
        assert_eq!(
            graph.chain(root, "mio").unwrap(),
            ["api", "core", "orm", "mio"]
        );
        assert!(graph.member("mio").is_none());
    }
}

#[cfg(test)]
mod copies {
    use super::*;
    use serde_json::json;

    #[test]
    fn two_copies_of_doxa_client_are_named_with_the_path_to_each() {
        let normal = json!([{ "kind": null }]);
        let meta = json!({
            "packages": [
                { "id": "w", "name": "web", "version": "0.1.0" },
                { "id": "k", "name": "kit", "version": "0.2.0", "source": "git+https://x/kit#abc" },
                { "id": "c1", "name": "doxa-client", "version": "0.1.6" },
                { "id": "c2", "name": "doxa-client", "version": "0.1.5", "source": "registry+https://crates" },
                { "id": "r", "name": "doxa-wire", "version": "0.1.6" },
            ],
            "workspace_members": ["w"],
            "resolve": { "nodes": [
                { "id": "w", "deps": [{ "pkg": "c1", "dep_kinds": normal }, { "pkg": "k", "dep_kinds": normal }] },
                { "id": "k", "deps": [{ "pkg": "c2", "dep_kinds": normal }] },
                { "id": "c1", "deps": [{ "pkg": "r", "dep_kinds": normal }] },
                { "id": "c2", "deps": [{ "pkg": "r", "dep_kinds": normal }] },
                { "id": "r", "deps": [] },
            ]}
        });
        let graph = Graph::new(&meta);
        let root = graph.member("web").unwrap();
        let err = graph.one_copy(root).unwrap_err().to_string();
        assert!(err.contains("`doxa-client` is linked 2 times"), "{err}");
        assert!(
            err.contains("doxa-client 0.1.6 (path): web → doxa-client"),
            "{err}"
        );
        assert!(
            err.contains("doxa-client 0.1.5 (registry+https://crates): web → kit → doxa-client"),
            "{err}"
        );
        assert!(!err.contains("doxa-wire"), "one doxa-wire: {err}");
    }

    #[test]
    fn one_copy_of_each_passes() {
        let meta = json!({
            "packages": [{ "id": "w", "name": "web" }, { "id": "c", "name": "doxa-client" }],
            "workspace_members": ["w"],
            "resolve": { "nodes": [
                { "id": "w", "deps": [{ "pkg": "c", "dep_kinds": [{ "kind": null }] }] },
                { "id": "c", "deps": [] },
            ]}
        });
        let graph = Graph::new(&meta);
        assert!(graph.one_copy(graph.member("web").unwrap()).is_ok());
    }
}
