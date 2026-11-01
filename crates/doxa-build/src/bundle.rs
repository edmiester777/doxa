//! The JS bundle: a generated entry over the wasm-bindgen glue and island modules.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use crate::error::{run, Error, IoContext, Result};

/// The prefix island modules are imported under, followed by a path relative to
/// the web crate root.
pub const ISLAND_SCHEME: &str = "doxa-island:";

/// What to bundle.
#[derive(Debug, Clone)]
pub struct BundleRequest<'a> {
    /// The entry module.
    pub entry: &'a Path,
    /// An empty directory to write into.
    pub out_dir: &'a Path,
    /// A directory holding `node_modules`, if there are npm dependencies.
    pub node_modules: Option<&'a Path>,
    /// Minify.
    pub release: bool,
}

/// What a bundler wrote, as paths relative to its `out_dir`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BundleOutput {
    /// The entry chunk.
    pub entry: String,
    /// Chunks the entry imports statically, transitively.
    pub chunks: Vec<String>,
    /// CSS imported from JS, bundled.
    pub css: Option<String>,
    /// Every file written.
    pub files: Vec<String>,
}

/// Bundles an entry module and everything it imports.
pub trait Bundler {
    /// Bundle `req.entry` into `req.out_dir`.
    fn bundle(&self, req: &BundleRequest<'_>) -> Result<BundleOutput>;
}

/// esbuild, run as a managed binary.
#[derive(Debug, Clone)]
pub struct Esbuild {
    bin: PathBuf,
}

impl Esbuild {
    /// esbuild at `bin`.
    pub fn new(bin: impl Into<PathBuf>) -> Self {
        Self { bin: bin.into() }
    }

    /// The pinned esbuild, downloaded on first use.
    pub fn managed() -> Result<Self> {
        crate::tool::esbuild().map(Self::new)
    }

    /// Command-line arguments for `req`, writing the metafile to `metafile`.
    pub fn args(req: &BundleRequest<'_>, metafile: &Path) -> Vec<OsString> {
        let mut args: Vec<OsString> = vec![
            req.entry.into(),
            "--bundle".into(),
            "--format=esm".into(),
            "--splitting".into(),
            "--outdir=.".into(),
            "--entry-names=[name]".into(),
            "--chunk-names=chunks/[name]-[hash]".into(),
            "--asset-names=assets/[name]-[hash]".into(),
            "--loader:.tsx=tsx".into(),
            "--jsx=automatic".into(),
            "--log-level=warning".into(),
        ];
        let mut meta = OsString::from("--metafile=");
        meta.push(metafile);
        args.push(meta);
        if req.release {
            args.push("--minify".into());
        }
        args
    }
}

impl Bundler for Esbuild {
    fn bundle(&self, req: &BundleRequest<'_>) -> Result<BundleOutput> {
        if req.out_dir.exists() {
            std::fs::remove_dir_all(req.out_dir).at(req.out_dir)?;
        }
        std::fs::create_dir_all(req.out_dir).at(req.out_dir)?;
        let metafile = req.out_dir.with_extension("meta.json");
        let mut cmd = Command::new(&self.bin);
        cmd.args(Self::args(req, &metafile))
            .current_dir(req.out_dir);
        if let Some(dir) = req.node_modules {
            cmd.env("NODE_PATH", dir.join("node_modules"));
        }
        run(
            "esbuild",
            &mut cmd,
            "check the import named above; npm packages belong in [package.metadata.doxa.npm]",
        )?;
        let json = std::fs::read_to_string(&metafile).at(&metafile)?;
        parse_metafile(&json).map_err(|detail| Error::tool("esbuild", &cmd, detail, "upgrade doxa"))
    }
}

#[derive(Deserialize)]
struct Metafile {
    outputs: BTreeMap<String, MetaOutput>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MetaOutput {
    #[serde(default)]
    imports: Vec<MetaImport>,
    entry_point: Option<String>,
    css_bundle: Option<String>,
}

#[derive(Deserialize)]
struct MetaImport {
    path: String,
    kind: String,
    #[serde(default)]
    external: bool,
}

/// Read esbuild's `--metafile` output.
pub fn parse_metafile(json: &str) -> Result<BundleOutput, String> {
    let meta: Metafile = serde_json::from_str(json).map_err(|e| format!("bad metafile: {e}"))?;
    let normal = |p: &str| p.trim_start_matches("./").to_owned();
    let (entry, out) = meta
        .outputs
        .iter()
        .find(|(_, o)| o.entry_point.is_some())
        .ok_or("metafile has no entry output")?;
    let mut chunks = BTreeSet::new();
    let mut stack = vec![out];
    while let Some(o) = stack.pop() {
        for import in &o.imports {
            if import.kind == "import-statement" && !import.external {
                let path = normal(&import.path);
                if let Some(next) = meta
                    .outputs
                    .get(&path)
                    .or_else(|| meta.outputs.get(&import.path))
                {
                    if chunks.insert(path) {
                        stack.push(next);
                    }
                }
            }
        }
    }
    Ok(BundleOutput {
        entry: normal(entry),
        chunks: chunks.into_iter().collect(),
        css: out.css_bundle.as_deref().map(normal),
        files: meta
            .outputs
            .keys()
            .map(|k| normal(k))
            .filter(|k| !k.ends_with(".map"))
            .collect(),
    })
}

/// The prefix `#[react]` components and their runtime are imported under.
pub const REACT_SCHEME: &str = "doxa-react:";

/// Replace each import specifier in `js` that starts with `scheme` by `f(rest)`.
/// Other strings, like the keys of wasm's imports object, keep the name the wasm asks for.
fn rewrite_specifiers(js: &str, scheme: &str, mut f: impl FnMut(&str) -> String) -> String {
    let mut out = String::with_capacity(js.len());
    let mut rest = js;
    while let Some(at) = rest.find(scheme) {
        let quote = rest[..at].chars().next_back();
        let before = rest[..at.saturating_sub(1)].trim_end();
        let imported = before.ends_with("from") || before.ends_with("import");
        let close = match quote {
            Some(q @ ('"' | '\'')) if imported => rest[at..].find(q).map(|end| (q, end)),
            _ => None,
        };
        let Some((q, end)) = close else {
            out.push_str(&rest[..at + scheme.len()]);
            rest = &rest[at + scheme.len()..];
            continue;
        };
        out.push_str(&rest[..at]);
        out.push_str(&f(&rest[at + scheme.len()..at + end]));
        out.push(q);
        rest = &rest[at + end + 1..];
    }
    out.push_str(rest);
    out
}

/// Point every `doxa-island:<path>` specifier in the glue at the real file under
/// `web_root`, returning the rewritten glue and the islands found.
pub fn rewrite_islands(glue: &str, web_root: &Path) -> (String, Vec<PathBuf>) {
    let mut islands = Vec::new();
    let out = rewrite_specifiers(glue, ISLAND_SCHEME, |rel| {
        let path = web_root.join(rel);
        let js = js_path(&path);
        if !islands.contains(&path) {
            islands.push(path);
        }
        js
    });
    (out, islands)
}

/// Generated modules the glue imports instead of `doxa-react:` specifiers, as paths
/// relative to the glue, with their contents.
pub type ReactModules = Vec<(String, String)>;

/// Point every `doxa-react:` specifier in the glue at a generated module: the
/// shipped runtime, or a loader per `#[react]` component.
pub fn rewrite_react(glue: &str, web_root: &Path) -> (String, ReactModules) {
    let mut modules: ReactModules = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    let mut found = false;
    let out = rewrite_specifiers(glue, REACT_SCHEME, |spec| {
        found = true;
        let file = if spec == "runtime" {
            "react/runtime.js".to_owned()
        } else {
            match seen.iter().position(|s| s == spec) {
                Some(i) => format!("react/island-{i}.js"),
                None => {
                    seen.push(spec.to_owned());
                    let file = format!("react/island-{}.js", seen.len() - 1);
                    modules.push((file.clone(), island_js(spec, web_root)));
                    file
                }
            }
        };
        format!("./{file}")
    });
    if found {
        modules.push((
            "react/runtime.js".to_owned(),
            include_str!("../js/react-runtime.js").to_owned(),
        ));
    }
    (out, modules)
}

/// A loader for `<eager|lazy>:<export>:<module>`; `load()` returns the component.
fn island_js(spec: &str, web_root: &Path) -> String {
    let mut parts = spec.splitn(3, ':');
    let (mode, export, module) = (
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
    );
    let module = match module.strip_prefix(ISLAND_SCHEME) {
        Some(rel) => js_path(&web_root.join(rel)),
        None => module.to_owned(),
    };
    let lit = serde_json::to_string(&module).expect("json");
    if mode == "lazy" {
        format!(
            "import {{ lazy }} from \"react\";\n\
             const C = lazy(() => import({lit}).then((m) => ({{ default: m.{export} }})));\n\
             export const load = () => C;\n"
        )
    } else if export == "default" {
        format!("import C from {lit};\nexport const load = () => C;\n")
    } else {
        format!("import {{ {export} as C }} from {lit};\nexport const load = () => C;\n")
    }
}

/// The generated entry: load the glue, start the wasm, and pull in islands.
pub fn entry_js(glue: &Path, islands: &[PathBuf], wasm_file: &str) -> String {
    let lit = |p: &Path| serde_json::to_string(&js_path(p)).expect("json");
    let mut js = format!("import init from {};\n", lit(glue));
    for island in islands {
        js.push_str(&format!("import {};\n", lit(island)));
    }
    js.push_str(&format!(
        "await init({{ module_or_path: new URL({}, import.meta.url) }});\n",
        serde_json::to_string(&format!("./{wasm_file}")).expect("json")
    ));
    js
}

fn js_path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn islands_are_rewritten_to_real_paths() {
        let glue = "import { a } from 'doxa-island:ts/editor.tsx';\n\
                    import * as b from \"doxa-island:ts/chart.tsx\";\n\
                    import { c } from 'doxa-island:ts/editor.tsx';\n\
                    const s = `doxa-island: in prose`;\n";
        let (out, islands) = rewrite_islands(glue, Path::new("/app/web"));
        assert_eq!(
            islands,
            [
                PathBuf::from("/app/web/ts/editor.tsx"),
                PathBuf::from("/app/web/ts/chart.tsx")
            ]
        );
        assert!(out.contains("from '/app/web/ts/editor.tsx';"), "{out}");
        assert!(out.contains("from \"/app/web/ts/chart.tsx\";"), "{out}");
        assert!(out.contains("`doxa-island: in prose`"), "{out}");
        assert!(!out.contains("'doxa-island:"), "{out}");
    }

    #[test]
    fn react_specifiers_become_generated_modules() {
        let glue = "import { mount } from 'doxa-react:runtime';\n\
                    import { load } from 'doxa-react:eager:Editor:doxa-island:ts/editor.tsx';\n\
                    import { load as load2 } from 'doxa-react:lazy:default:@monaco-editor/react';\n\
                    import { load as load3 } from 'doxa-react:eager:default:react-select';\n\
                    import { load as load4 } from 'doxa-react:eager:Editor:doxa-island:ts/editor.tsx';\n\
                    const imports = { \"doxa-react:eager:default:react-select\": import3 };\n";
        let (out, modules) = rewrite_react(glue, Path::new("/app/web"));
        assert!(
            out.contains("{ \"doxa-react:eager:default:react-select\": import3 }"),
            "the wasm still asks for its own module name: {out}"
        );
        assert_eq!(out.matches("doxa-react:").count(), 1, "{out}");
        assert!(out.contains("from './react/runtime.js'"), "{out}");
        assert_eq!(out.matches("'./react/island-0.js'").count(), 2, "{out}");
        let files: BTreeMap<_, _> = modules.into_iter().collect();
        assert_eq!(
            files.keys().collect::<Vec<_>>(),
            [
                "react/island-0.js",
                "react/island-1.js",
                "react/island-2.js",
                "react/runtime.js"
            ]
        );
        assert_eq!(
            files["react/island-0.js"],
            "import { Editor as C } from \"/app/web/ts/editor.tsx\";\nexport const load = () => C;\n"
        );
        assert!(
            files["react/island-1.js"].contains(
                "lazy(() => import(\"@monaco-editor/react\").then((m) => ({ default: m.default })))"
            ),
            "{}",
            files["react/island-1.js"]
        );
        assert_eq!(
            files["react/island-2.js"],
            "import C from \"react-select\";\nexport const load = () => C;\n"
        );
        assert!(files["react/runtime.js"].contains("createPortal"));
    }

    #[test]
    fn no_react_runtime_without_islands() {
        let (out, modules) = rewrite_react("import x from 'y';\n", Path::new("/app/web"));
        assert_eq!(out, "import x from 'y';\n");
        assert!(modules.is_empty());
    }

    #[test]
    fn the_entry_inits_with_the_hashed_wasm() {
        let js = entry_js(
            Path::new("/s/bindgen/app.js"),
            &[PathBuf::from("/app/web/ts/editor.tsx")],
            "app-0123abcd.wasm",
        );
        assert_eq!(
            js,
            "import init from \"/s/bindgen/app.js\";\n\
             import \"/app/web/ts/editor.tsx\";\n\
             await init({ module_or_path: new URL(\"./app-0123abcd.wasm\", import.meta.url) });\n"
        );
    }

    #[test]
    fn metafile_gives_entry_and_its_static_chunks() {
        let json = r#"{"outputs": {
            "app.js": {"imports": [
                {"path": "chunks/chunk-AAAA.js", "kind": "import-statement"},
                {"path": "chunks/lazy-CCCC.js", "kind": "dynamic-import"},
                {"path": "https://cdn/x.js", "kind": "import-statement", "external": true}
            ], "entryPoint": "../entry.js", "cssBundle": "app.css"},
            "chunks/chunk-AAAA.js": {"imports": [{"path": "chunks/chunk-BBBB.js", "kind": "import-statement"}]},
            "chunks/chunk-BBBB.js": {"imports": []},
            "chunks/lazy-CCCC.js": {"imports": []},
            "app.css": {"imports": []},
            "app.js.map": {"imports": []}
        }}"#;
        let out = parse_metafile(json).unwrap();
        assert_eq!(out.entry, "app.js");
        assert_eq!(out.chunks, ["chunks/chunk-AAAA.js", "chunks/chunk-BBBB.js"]);
        assert_eq!(out.css.as_deref(), Some("app.css"));
        assert_eq!(out.files.len(), 5);
    }

    #[test]
    fn esbuild_arguments() {
        let req = BundleRequest {
            entry: Path::new("/s/app.js"),
            out_dir: Path::new("/s/out"),
            node_modules: None,
            release: true,
        };
        let args: Vec<String> = Esbuild::args(&req, Path::new("/s/meta.json"))
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect();
        for want in [
            "--bundle",
            "--format=esm",
            "--splitting",
            "--loader:.tsx=tsx",
            "--jsx=automatic",
            "--minify",
            "--metafile=/s/meta.json",
        ] {
            assert!(args.iter().any(|a| a == want), "{want} in {args:?}");
        }
        let debug = BundleRequest {
            release: false,
            ..req
        };
        assert!(!Esbuild::args(&debug, Path::new("m"))
            .iter()
            .any(|a| a == "--minify"));
    }
}
