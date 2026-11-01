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

/// Point every `doxa-island:<path>` specifier in the glue at the real file under
/// `web_root`, returning the rewritten glue and the islands found.
pub fn rewrite_islands(glue: &str, web_root: &Path) -> (String, Vec<PathBuf>) {
    let mut out = String::with_capacity(glue.len());
    let mut islands = Vec::new();
    let mut rest = glue;
    while let Some(at) = rest.find(ISLAND_SCHEME) {
        let quote = rest[..at].chars().next_back();
        let close = match quote {
            Some(q @ ('"' | '\'')) => rest[at..].find(q).map(|end| (q, end)),
            _ => None,
        };
        let Some((q, end)) = close else {
            out.push_str(&rest[..at + ISLAND_SCHEME.len()]);
            rest = &rest[at + ISLAND_SCHEME.len()..];
            continue;
        };
        let rel = &rest[at + ISLAND_SCHEME.len()..at + end];
        let path = web_root.join(rel);
        out.push_str(&rest[..at]);
        out.push_str(&js_path(&path));
        out.push(q);
        if !islands.contains(&path) {
            islands.push(path);
        }
        rest = &rest[at + end + 1..];
    }
    out.push_str(rest);
    (out, islands)
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
