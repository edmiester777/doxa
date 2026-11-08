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
    /// For an npm package: leave npm imports to the host's bundler, and keep chunks beside the entry.
    pub library: bool,
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
        if req.library {
            args.push("--packages=external".into());
            args.push("--chunk-names=[name]-[hash]".into());
            args.push("--banner:js=\"use client\";".into());
            args.retain(|a| a != "--chunk-names=chunks/[name]-[hash]");
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
        let mut output = parse_metafile(&json)
            .map_err(|detail| Error::tool("esbuild", &cmd, detail, "upgrade doxa"))?;
        ship_npm_assets(&json, req.out_dir, &mut output)?;
        Ok(output)
    }
}

/// esbuild leaves `new URL("x", import.meta.url)` alone, so a file an npm module loads that way
/// would never reach the output: copy it, content-hashed, and point the URL at the copy.
pub fn ship_npm_assets(metafile: &str, out_dir: &Path, output: &mut BundleOutput) -> Result<()> {
    let meta: Metafile = serde_json::from_str(metafile)
        .map_err(|e| Error::config(format!("bad metafile: {e}"), "upgrade doxa"))?;
    for (file, chunk) in &meta.outputs {
        let modules: Vec<PathBuf> = chunk
            .inputs
            .keys()
            .filter(|input| input.contains("node_modules/"))
            .filter_map(|input| Some(out_dir.join(input).parent()?.to_owned()))
            .collect();
        if modules.is_empty() || !file.ends_with(".js") {
            continue;
        }
        let path = out_dir.join(file);
        let js = std::fs::read_to_string(&path).at(&path)?;
        let up = "../".repeat(file.trim_start_matches("./").matches('/').count());
        let mut failed = Ok(());
        let rewritten = rewrite_asset_urls(&js, |url| {
            let found = match asset_beside(&modules, url) {
                Ok(found) => found?,
                Err(error) => {
                    failed = Err(error);
                    return None;
                }
            };
            let name = Path::new(url).file_name()?.to_string_lossy().into_owned();
            let shipped = format!("assets/{}", crate::dist::hashed_name(&name, &found));
            let target = out_dir.join(&shipped);
            if let Err(error) = write_asset(&target, &found) {
                failed = Err(error);
                return None;
            }
            if !output.files.contains(&shipped) {
                output.files.push(shipped.clone());
            }
            Some(if up.is_empty() {
                format!("./{shipped}")
            } else {
                format!("{up}{shipped}")
            })
        });
        failed?;
        if rewritten != js {
            std::fs::write(&path, rewritten).at(&path)?;
        }
    }
    Ok(())
}

fn write_asset(target: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(dir) = target.parent() {
        std::fs::create_dir_all(dir).at(dir)?;
    }
    std::fs::write(target, bytes).at(target)
}

/// The file `url` names beside one of `modules`; a chunk doesn't record which module held the URL,
/// so different files under one name can't be told apart and fail the build.
fn asset_beside(modules: &[PathBuf], url: &str) -> Result<Option<Vec<u8>>> {
    if url.contains(':') || url.starts_with('/') {
        return Ok(None);
    }
    let mut found: Option<(PathBuf, Vec<u8>)> = None;
    for dir in modules {
        let path = dir.join(url);
        if !path.is_file() {
            continue;
        }
        let bytes = std::fs::read(&path).at(&path)?;
        match &found {
            Some((first, seen)) if *seen != bytes => {
                return Err(Error::config(
                    format!(
                        "`{url}` is two different files in one chunk: {} and {}",
                        first.display(),
                        path.display()
                    ),
                    "load one of the packages from its own lazy module, so they split apart",
                ));
            }
            Some(_) => {}
            None => found = Some((path, bytes)),
        }
    }
    Ok(found.map(|(_, bytes)| bytes))
}

/// Replace the literal in each `new URL("…", import.meta.url)` that `f` answers for.
fn rewrite_asset_urls(js: &str, mut f: impl FnMut(&str) -> Option<String>) -> String {
    const OPEN: &str = "new URL(";
    let mut out = String::with_capacity(js.len());
    let mut rest = js;
    while let Some(at) = rest.find(OPEN) {
        let start = at + OPEN.len();
        out.push_str(&rest[..start]);
        rest = &rest[start..];
        let Some((url, after)) = literal_then_meta_url(rest) else {
            continue;
        };
        let Some(next) = f(url) else {
            continue;
        };
        out.push_str(&format!("\"{next}\""));
        rest = &rest[rest.len() - after.len()..];
    }
    out.push_str(rest);
    out
}

/// The string literal opening `js`, and what follows it, when `, import.meta.url)` comes next.
fn literal_then_meta_url(js: &str) -> Option<(&str, &str)> {
    let quote = js
        .chars()
        .next()
        .filter(|q| matches!(q, '"' | '\'' | '`'))?;
    let body = &js[1..];
    let url = &body[..body.find(quote)?];
    let after = &body[url.len() + 1..];
    let meta = after.trim_start().strip_prefix(',')?.trim_start();
    meta.strip_prefix("import.meta.url")?
        .trim_start()
        .starts_with(')')
        .then_some((url, after))
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
    #[serde(default)]
    inputs: BTreeMap<String, serde::de::IgnoredAny>,
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

/// The prefix a `lazy` `#[npm]` block's module is imported under.
pub const NPM_SCHEME: &str = "doxa-npm:";

/// Point every `doxa-npm:lazy:<names>:<module>` specifier at a generated module whose
/// exports load the real one on first call, so esbuild splits it into a chunk of its own.
pub fn rewrite_npm(glue: &str, web_root: &Path) -> (String, ReactModules) {
    let mut modules: ReactModules = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    let out = rewrite_specifiers(glue, NPM_SCHEME, |spec| {
        let i = match seen.iter().position(|s| s == spec) {
            Some(i) => i,
            None => {
                seen.push(spec.to_owned());
                let i = seen.len() - 1;
                modules.push((format!("npm/lazy-{i}.js"), lazy_npm_js(spec, web_root)));
                i
            }
        };
        format!("./npm/lazy-{i}.js")
    });
    (out, modules)
}

/// `lazy:toString,parse:cronstrue` as async proxies over a dynamic import.
fn lazy_npm_js(spec: &str, web_root: &Path) -> String {
    let rest = spec.strip_prefix("lazy:").unwrap_or(spec);
    let (names, module) = rest.split_once(':').unwrap_or(("", rest));
    let module = match module.strip_prefix(ISLAND_SCHEME) {
        Some(rel) => js_path(&web_root.join(rel)),
        None => module.to_owned(),
    };
    let lit = serde_json::to_string(&module).expect("json");
    let mut js = format!("let m;\nconst load = () => (m ??= import({lit}));\n");
    for (i, name) in names.split(',').filter(|n| !n.is_empty()).enumerate() {
        let key = serde_json::to_string(name).expect("json");
        js.push_str(&format!(
            "async function f{i}(...a) {{ return (await load())[{key}](...a); }}\nexport {{ f{i} as {key} }};\n"
        ));
    }
    js
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
    // `Popover.Trigger`: import `Popover`, then read `.Trigger` off it.
    let (head, rest) = export.split_once('.').unwrap_or((export, ""));
    let path = if rest.is_empty() {
        String::new()
    } else {
        format!(".{rest}")
    };
    if mode == "lazy" {
        format!(
            "import {{ lazy }} from \"react\";\n\
             const C = lazy(() => import({lit}).then((m) => ({{ default: m.{export} }})));\n\
             export const load = () => C;\n"
        )
    } else if head == "default" {
        format!("import M from {lit};\nconst C = M{path};\nexport const load = () => C;\n")
    } else {
        format!(
            "import {{ {head} as M }} from {lit};\nconst C = M{path};\nexport const load = () => C;\n"
        )
    }
}

/// The generated entry: load the glue and islands, read `services.json`, start the wasm.
/// A missing file, or a server answering it with `index.html`, means no overrides.
/// A `split` wasm's loader instantiates each part against the main module through `initSync`.
pub fn entry_js(glue: &Path, islands: &[PathBuf], wasm_file: &str, split: bool) -> String {
    let lit = |p: &Path| serde_json::to_string(&js_path(p)).expect("json");
    let mut js = if split {
        format!(
            "import init, {{ initSync }} from {};\nglobalThis.__wasm_split_main_initSync = initSync;\n",
            lit(glue)
        )
    } else {
        format!("import init from {};\n", lit(glue))
    };
    for island in islands {
        js.push_str(&format!("import {};\n", lit(island)));
    }
    js.push_str(SERVICES_JS);
    js.push_str(&format!(
        "await init({{ module_or_path: new URL({}, import.meta.url) }});\n",
        serde_json::to_string(&format!("./{wasm_file}")).expect("json")
    ));
    js
}

/// The gallery's entry: [`entry_js`]'s imports, then doxa-ui's gallery over the glue and
/// `stories`, the JSON list of [`Story`](crate::stories::Story).
pub fn gallery_js(
    glue: &Path,
    islands: &[PathBuf],
    wasm_file: &str,
    stories: &str,
    split: bool,
) -> String {
    let lit = |p: &Path| serde_json::to_string(&js_path(p)).expect("json");
    let mut js = format!("import init, * as glue from {};\n", lit(glue));
    for island in islands {
        js.push_str(&format!("import {};\n", lit(island)));
    }
    js.push_str("globalThis.__DOXA_HOSTED__ = true;\n");
    if split {
        js.push_str("globalThis.__wasm_split_main_initSync = glue.initSync;\n");
    }
    js.push_str(SERVICES_JS);
    js.push_str(&format!(
        "await init({{ module_or_path: new URL({}, import.meta.url) }});\nglue.__doxa_gallery(glue, {});\n",
        serde_json::to_string(&format!("./{wasm_file}")).expect("json"),
        serde_json::to_string(stories).expect("json")
    ));
    js
}

const SERVICES_JS: &str = "globalThis.__DOXA_SERVICES__ = await fetch(new URL(\"./services.json\", import.meta.url), { cache: \"no-cache\" })\n  .then((r) => (r.ok && /json/.test(r.headers.get(\"content-type\") ?? \"\") ? r.json() : {}))\n  .catch(() => ({}));\n";

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
            "import { Editor as M } from \"/app/web/ts/editor.tsx\";\nconst C = M;\nexport const load = () => C;\n"
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
            "import M from \"react-select\";\nconst C = M;\nexport const load = () => C;\n"
        );
        assert!(files["react/runtime.js"].contains("createPortal"));
    }

    #[test]
    fn a_dotted_export_reads_the_member_off_its_import() {
        let eager = island_js(
            "eager:Popover.Trigger:@base-ui/react/popover",
            Path::new("/w"),
        );
        assert_eq!(
            eager,
            "import { Popover as M } from \"@base-ui/react/popover\";\nconst C = M.Trigger;\nexport const load = () => C;\n"
        );
        let lazy = island_js(
            "lazy:Popover.Trigger:@base-ui/react/popover",
            Path::new("/w"),
        );
        assert!(lazy.contains("default: m.Popover.Trigger"), "{lazy}");
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
            false,
        );
        assert_eq!(
            js,
            "import init from \"/s/bindgen/app.js\";\n\
             import \"/app/web/ts/editor.tsx\";\n\
             globalThis.__DOXA_SERVICES__ = await fetch(new URL(\"./services.json\", import.meta.url), { cache: \"no-cache\" })\n  \
             .then((r) => (r.ok && /json/.test(r.headers.get(\"content-type\") ?? \"\") ? r.json() : {}))\n  \
             .catch(() => ({}));\n\
             await init({ module_or_path: new URL(\"./app-0123abcd.wasm\", import.meta.url) });\n"
        );
        let split = entry_js(Path::new("/s/bindgen/app.js"), &[], "app.wasm", true);
        assert!(
            split.starts_with(
                "import init, { initSync } from \"/s/bindgen/app.js\";\n\
             globalThis.__wasm_split_main_initSync = initSync;\n"
            ),
            "{split}"
        );
    }

    #[test]
    fn the_gallery_entry_starts_the_wasm_hosted() {
        let js = gallery_js(
            Path::new("/s/glue.js"),
            &[],
            "app-01.wasm",
            "[{\"name\":\"a\"}]",
            false,
        );
        assert!(
            js.starts_with(
                "import init, * as glue from \"/s/glue.js\";\nglobalThis.__DOXA_HOSTED__ = true;\n"
            ),
            "{js}"
        );
        assert!(
            js.ends_with(
                "await init({ module_or_path: new URL(\"./app-01.wasm\", import.meta.url) });\n\
             glue.__doxa_gallery(glue, \"[{\\\"name\\\":\\\"a\\\"}]\");\n"
            ),
            "{js}"
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

    fn bundled(js: &str, pkg_files: &[(&str, &[u8])]) -> (tempfile::TempDir, String) {
        let root = tempfile::tempdir().unwrap();
        let pkg = root.path().join("node_modules/pkg");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::create_dir_all(root.path().join("out/chunks")).unwrap();
        for (name, bytes) in pkg_files {
            std::fs::write(pkg.join(name), bytes).unwrap();
        }
        std::fs::write(root.path().join("out/chunks/c.js"), js).unwrap();
        let meta = r#"{"outputs": {"chunks/c.js": {"imports": [], "exports": [],
            "inputs": {"../node_modules/pkg/index.js": {"bytesInOutput": 1}}}}}"#;
        (root, meta.to_owned())
    }

    #[test]
    fn a_file_an_npm_module_loads_by_url_ships_with_the_bundle() {
        let js = r#"let u = new URL("pkg_bg.wasm", import.meta.url);"#;
        let (root, meta) = bundled(js, &[("pkg_bg.wasm", b"binary")]);
        let out_dir = root.path().join("out");
        let mut output = BundleOutput::default();
        ship_npm_assets(&meta, &out_dir, &mut output).unwrap();

        let name = crate::dist::hashed_name("pkg_bg.wasm", b"binary");
        let shipped = format!("assets/{name}");
        assert_eq!(output.files, std::slice::from_ref(&shipped));
        assert_eq!(std::fs::read(out_dir.join(&shipped)).unwrap(), b"binary");
        let chunk = std::fs::read_to_string(out_dir.join("chunks/c.js")).unwrap();
        assert_eq!(
            chunk,
            format!(r#"let u = new URL("../{shipped}", import.meta.url);"#)
        );
    }

    #[test]
    fn a_url_naming_no_file_beside_the_module_is_left_alone() {
        let js = r#"new URL("./services.json",import.meta.url);new URL("https://a.b/c",import.meta.url);new URL("x.wasm",base);"#;
        let (root, meta) = bundled(js, &[("x.wasm", b"binary")]);
        let out_dir = root.path().join("out");
        let mut output = BundleOutput::default();
        ship_npm_assets(&meta, &out_dir, &mut output).unwrap();
        assert!(output.files.is_empty());
        let chunk = std::fs::read_to_string(out_dir.join("chunks/c.js")).unwrap();
        assert_eq!(chunk, js);
    }

    #[test]
    fn a_chunk_with_no_npm_module_is_not_touched() {
        let js = r#"new URL("local.wasm",import.meta.url);"#;
        let (root, _) = bundled(js, &[]);
        let out_dir = root.path().join("out");
        std::fs::write(out_dir.join("chunks/local.wasm"), b"binary").unwrap();
        let meta = r#"{"outputs": {"chunks/c.js": {"inputs": {"../ts/own.js": {}}}}}"#;
        let mut output = BundleOutput::default();
        ship_npm_assets(meta, &out_dir, &mut output).unwrap();
        assert!(output.files.is_empty());
    }

    #[test]
    fn one_name_for_two_different_files_fails_the_build() {
        let js = r#"new URL("bg.wasm",import.meta.url);"#;
        let (root, _) = bundled(js, &[("bg.wasm", b"one")]);
        let other = root.path().join("node_modules/other");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("bg.wasm"), b"two").unwrap();
        let meta = r#"{"outputs": {"chunks/c.js": {"inputs": {
            "../node_modules/pkg/index.js": {}, "../node_modules/other/index.js": {}}}}}"#;
        let mut output = BundleOutput::default();
        let error = ship_npm_assets(meta, &root.path().join("out"), &mut output).unwrap_err();
        assert!(error.to_string().contains("two different files"), "{error}");
    }

    #[test]
    fn esbuild_arguments() {
        let req = BundleRequest {
            entry: Path::new("/s/app.js"),
            out_dir: Path::new("/s/out"),
            node_modules: None,
            release: true,
            library: false,
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

    #[test]
    fn a_lazy_npm_module_is_imported_on_first_call() {
        let glue = "import { toString, parse } from 'doxa-npm:lazy:toString,parse:cronstrue';\n\
                    import { pad } from 'doxa-npm:lazy:pad:doxa-island:ts/pad.js';\n";
        let (out, modules) = rewrite_npm(glue, Path::new("/app/web"));
        assert!(out.contains("from './npm/lazy-0.js'"), "{out}");
        assert!(out.contains("from './npm/lazy-1.js'"), "{out}");
        let (file, js) = &modules[0];
        assert_eq!(file, "npm/lazy-0.js");
        assert!(js.contains("import(\"cronstrue\")"), "{js}");
        assert!(js.contains("export { f1 as \"parse\" }"), "{js}");
        assert!(
            modules[1].1.contains("/app/web/ts/pad.js"),
            "{}",
            modules[1].1
        );
    }
}
