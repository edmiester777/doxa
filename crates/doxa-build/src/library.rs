//! `doxa build --lib`: the `#[component(export)]` components as an npm package a React host imports.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::bundle::{rewrite_islands, rewrite_npm, rewrite_react, BundleRequest};
use crate::config::Library;
use crate::error::{Error, IoContext, Result};
use crate::pipeline::{note, Pipeline};
use crate::{css, npm, split};

/// The custom section `#[component(export)]` writes each component's props into.
const SECTION: &str = "doxa_exports";

/// One exported component, as its macro described it.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Export {
    /// The component's name, and its wrapper's.
    pub component: String,
    /// The wasm export that mounts it.
    pub export: String,
    /// Its props, as JS sees them.
    pub props: Vec<Prop>,
}

/// One prop of an [`Export`].
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Prop {
    /// Its JS name.
    pub name: String,
    /// Its TypeScript type.
    pub ts: String,
    /// Whether a host may leave it out.
    pub optional: bool,
}

/// The exported components described in the linked `wasm`.
pub fn exports(wasm: &[u8]) -> Result<Vec<Export>> {
    let mut text = Vec::new();
    let mut at = 8;
    while at < wasm.len() {
        let id = wasm[at];
        let Some((size, len)) = split::leb128(&wasm[at + 1..]) else {
            break;
        };
        let payload = at + 1 + len;
        let end = (payload + size).min(wasm.len());
        if id == 0 {
            if let Some((n, l)) = split::leb128(&wasm[payload..end]) {
                if wasm.get(payload + l..payload + l + n) == Some(SECTION.as_bytes()) {
                    text.extend_from_slice(&wasm[payload + l + n..end]);
                }
            }
        }
        at = end;
    }
    String::from_utf8_lossy(&text)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str(l).map_err(|e| {
                Error::config(
                    format!("a `{SECTION}` entry doesn't parse: {e}"),
                    "build with the same doxa version as the web crate",
                )
            })
        })
        .collect()
}

/// The class a scope selector names: `.kit-root` → `kit-root`.
fn scope_class(scope: &str) -> Result<&str> {
    scope
        .strip_prefix('.')
        .filter(|c| {
            !c.is_empty()
                && c.chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        })
        .ok_or_else(|| {
            Error::config(
                format!("library scope `{scope}` isn't a class selector"),
                "set `scope = \".my-kit\"`; each component's wrapper element gets that class",
            )
        })
}

/// The package entry: no side effects, the wasm started on first mount, one wrapper per export.
pub fn index_js(
    exports: &[Export],
    glue: &Path,
    runtime: Option<&Path>,
    split: bool,
    class: Option<&str>,
) -> String {
    let lit = |s: &str| serde_json::to_string(s).expect("json");
    let path = |p: &Path| lit(&p.to_string_lossy().replace('\\', "/"));
    let mut js = String::from(
        "import { createElement, useEffect, useLayoutEffect, useRef, useState } from \"react\";\n",
    );
    if let Some(rt) = runtime {
        js.push_str(&format!(
            "import {{ Portals, libraryMode }} from {};\n",
            path(rt)
        ));
    }
    js.push_str("\nlet started = null;\nlet options = {};\n\n");
    js.push_str("function start() {\n  started ??= import(");
    js.push_str(&path(glue));
    js.push_str(").then(async (m) => {\n    globalThis.__DOXA_HOSTED__ = true;\n");
    if runtime.is_some() {
        js.push_str("    libraryMode();\n");
    }
    if split {
        js.push_str("    globalThis.__wasm_split_main_initSync = m.initSync;\n");
    }
    js.push_str(
        "    await m.default({ module_or_path: new URL(\"./app.wasm\", import.meta.url) });\n    \
         m.__doxa_configure(options.services, options.token);\n    \
         return m;\n  });\n  return started;\n}\n\n",
    );
    js.push_str(
        "/** Base URLs by client crate, and a bearer token; call before the first component mounts. */\n\
         export function configure(next = {}) {\n  \
         options = { ...options, ...next };\n  \
         started?.then((m) => m.__doxa_configure(next.services, next.token));\n}\n\n",
    );
    js.push_str(&format!(
        "function wrap(name, mount) {{\n  \
         function Wrapper(props) {{\n    \
         const host = useRef(null);\n    \
         const handle = useRef(null);\n    \
         const latest = useRef(props);\n    \
         const [root, setRoot] = useState(null);\n    \
         latest.current = props;\n    \
         useLayoutEffect(() => {{\n      \
         handle.current?.update(props);\n    \
         }});\n    \
         useEffect(() => {{\n      \
         let live = true;\n      \
         start().then((m) => {{\n        \
         if (!live) return;\n        \
         handle.current = m[mount](host.current, latest.current);\n        \
         setRoot(handle.current.root());\n      \
         }}).catch((e) => console.error(`${{name}} failed to mount`, e));\n      \
         return () => {{\n        \
         live = false;\n        \
         handle.current?.free();\n        \
         handle.current = null;\n      \
         }};\n    \
         }}, []);\n    \
         // Only portals go inside, which add no DOM, so React leaves doxa's nodes alone.\n    \
         return createElement(\"div\", {{ ref: host, className: {class}, \"data-doxa\": name }}, {portals});\n  \
         }}\n  \
         Wrapper.displayName = name;\n  \
         return Wrapper;\n}}\n\n",
        class = class.map_or("undefined".to_owned(), lit),
        portals = if runtime.is_some() {
            "root === null ? null : createElement(Portals, { root })"
        } else {
            "null"
        },
    ));
    for e in exports {
        js.push_str(&format!(
            "export const {} = wrap({}, {});\n",
            e.component,
            lit(&e.component),
            lit(&e.export)
        ));
    }
    js
}

/// TypeScript declarations for the entry.
pub fn index_dts(exports: &[Export]) -> String {
    let mut ts = String::from("import type { ReactElement } from \"react\";\n\n");
    ts.push_str(
        "export interface ConfigureOptions {\n  \
         /** Base URL by client crate; unlisted ones are the page's own origin. */\n  \
         services?: Record<string, string>;\n  \
         /** Sent as `Authorization: Bearer …` with every request. */\n  \
         token?: () => string | null | undefined;\n}\n\n\
         export declare function configure(options: ConfigureOptions): void;\n",
    );
    for e in exports {
        ts.push_str(&format!("\nexport interface {}Props {{\n", e.component));
        for p in &e.props {
            let q = if p.optional { "?" } else { "" };
            ts.push_str(&format!("  {}{q}: {};\n", p.name, p.ts));
        }
        ts.push_str(&format!(
            "}}\n\nexport declare function {0}(props: {0}Props): ReactElement;\n",
            e.component
        ));
    }
    ts
}

/// `package.json`: the islands' npm modules as dependencies, React as the host's.
pub fn package_json(
    lib: &Library,
    version: &str,
    npm: &BTreeMap<String, String>,
    css: bool,
) -> String {
    let peer = |name: &str| npm.get(name).cloned().unwrap_or_else(|| ">=18".into());
    let mut deps = npm.clone();
    deps.remove("react");
    deps.remove("react-dom");
    let mut exports = serde_json::json!({
        ".": { "types": "./index.d.ts", "default": "./index.js" },
    });
    if css {
        exports["./style.css"] = "./style.css".into();
    }
    let pkg = serde_json::json!({
        "name": lib.name,
        "version": version,
        "type": "module",
        "main": "./index.js",
        "module": "./index.js",
        "types": "./index.d.ts",
        "exports": exports,
        "sideEffects": ["*.css"],
        "peerDependencies": { "react": peer("react"), "react-dom": peer("react-dom") },
        "dependencies": deps,
    });
    serde_json::to_string_pretty(&pkg).expect("json") + "\n"
}

/// The npm dependencies the app declares, from its metadata or its own `package.json`.
fn npm_deps(source: &npm::Source) -> Result<BTreeMap<String, String>> {
    match source {
        npm::Source::None => Ok(BTreeMap::new()),
        npm::Source::Synced { deps, .. } => Ok(deps.clone()),
        npm::Source::Own(dir) => {
            #[derive(Deserialize)]
            struct Pkg {
                #[serde(default)]
                dependencies: BTreeMap<String, String>,
            }
            let path = dir.join("package.json");
            let text = std::fs::read_to_string(&path).at(&path)?;
            let pkg: Pkg = serde_json::from_str(&text)
                .map_err(|e| Error::config(format!("{}: {e}", path.display()), "fix the JSON"))?;
            Ok(pkg.dependencies)
        }
    }
}

impl Pipeline {
    /// Build the npm package into `target/doxa/lib`.
    pub fn build_library(&mut self) -> Result<PathBuf> {
        let lib = self.web.config.library.clone().ok_or_else(|| {
            Error::config(
                format!("`{}` declares no library", self.web.name),
                "add `library = { name = \"@acme/kit\", scope = \".kit\" }` to [package.metadata.doxa]",
            )
        })?;
        if lib.react.as_deref().is_some_and(|r| r != "peer") {
            return Err(Error::config(
                format!("library react = {:?}", lib.react),
                "React is always the host's: set `react = \"peer\"` or leave it out",
            ));
        }
        let class = lib.scope.as_deref().map(scope_class).transpose()?;
        self.library = true;
        self.npm()?;
        self.wasm()?;
        let linked = self.linked_wasm();
        let found = exports(&std::fs::read(&linked).at(&linked)?)?;
        if found.is_empty() {
            return Err(Error::config(
                format!("`{}` exports no components", self.web.name),
                "mark the components a host mounts `#[component(export)]`",
            ));
        }
        self.css()?;

        let out = self.layout.lib();
        if out.exists() {
            std::fs::remove_dir_all(&out).at(&out)?;
        }
        let dir = self.bindgen_dir();
        let glue_path = dir.join("app.js");
        let glue = std::fs::read_to_string(&glue_path).at(&glue_path)?;
        let glue = split::dedupe_loader_imports(&glue);
        let (glue, mut react) = rewrite_react(&glue, &self.web.dir);
        let (glue, npm) = rewrite_npm(&glue, &self.web.dir);
        react.extend(npm);
        let runtime = react
            .iter()
            .any(|(f, _)| f == "react/runtime.js")
            .then(|| dir.join("react/runtime.js"));
        for (file, js) in react {
            let path = dir.join(file);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).at(parent)?;
            }
            std::fs::write(&path, js).at(&path)?;
        }
        let (glue, _) = rewrite_islands(&glue, &self.web.dir);
        let rewritten = dir.join("glue.js");
        std::fs::write(&rewritten, glue).at(&rewritten)?;
        let entry_dir = self.layout.stage().join("lib-entry");
        std::fs::create_dir_all(&entry_dir).at(&entry_dir)?;
        let entry = entry_dir.join("index.js");
        let split = !self.split_files.is_empty();
        let js = index_js(&found, &rewritten, runtime.as_deref(), split, class);
        std::fs::write(&entry, js).at(&entry)?;
        note("bundling the library");
        self.bundler.bundle(&BundleRequest {
            entry: &entry,
            out_dir: &out,
            node_modules: self.npm.dir(),
            release: self.opts.release,
            library: true,
        })?;
        let _ = std::fs::remove_file(out.with_extension("meta.json"));

        let app_wasm = dir.join("app_bg.wasm");
        let wasm_out = out.join("app.wasm");
        std::fs::copy(&app_wasm, &wasm_out).at(&wasm_out)?;
        for (name, bytes) in &self.split_files {
            let path = out.join(name);
            std::fs::write(&path, bytes).at(&path)?;
        }
        let mut sheet = String::new();
        for (_, built) in &self.stylesheets {
            for (_, hashed, bytes) in &built.assets {
                let path = out.join(hashed);
                std::fs::write(&path, bytes).at(&path)?;
            }
            sheet.push_str(&built.css);
        }
        let has_css = !sheet.is_empty();
        if has_css {
            if let Some(scope) = &lib.scope {
                sheet = css::scope(&sheet, scope);
            }
            let path = out.join("style.css");
            std::fs::write(&path, sheet).at(&path)?;
        }
        let dts = out.join("index.d.ts");
        std::fs::write(&dts, index_dts(&found)).at(&dts)?;
        let pkg = out.join("package.json");
        let deps = npm_deps(&self.npm)?;
        std::fs::write(&pkg, package_json(&lib, &self.web.version, &deps, has_css)).at(&pkg)?;
        note(format!(
            "wrote {} ({} components)",
            out.display(),
            found.len()
        ));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn picker() -> Export {
        Export {
            component: "WidgetPicker".into(),
            export: "__doxa_export_WidgetPicker".into(),
            props: vec![
                Prop {
                    name: "contains".into(),
                    ts: "string".into(),
                    optional: true,
                },
                Prop {
                    name: "onOpen".into(),
                    ts: "(value: string) => void".into(),
                    optional: true,
                },
                Prop {
                    name: "limit".into(),
                    ts: "number".into(),
                    optional: false,
                },
            ],
        }
    }

    #[test]
    fn exports_are_read_from_the_custom_section() {
        let line = b"{\"component\":\"WidgetPicker\",\"export\":\"__doxa_export_WidgetPicker\",\"props\":[]}\n";
        let name = SECTION.as_bytes();
        let mut payload = vec![name.len() as u8];
        payload.extend_from_slice(name);
        payload.extend_from_slice(line);
        let mut wasm = b"\0asm\x01\0\0\0".to_vec();
        wasm.push(0);
        wasm.push(payload.len() as u8);
        wasm.extend(payload);
        let found = exports(&wasm).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].export, "__doxa_export_WidgetPicker");
    }

    #[test]
    fn declarations_type_each_prop() {
        let ts = index_dts(&[picker()]);
        assert!(ts.contains(
            "export interface WidgetPickerProps {\n  contains?: string;\n  onOpen?: (value: string) => void;\n  limit: number;\n}"
        ), "{ts}");
        assert!(ts.contains(
            "export declare function WidgetPicker(props: WidgetPickerProps): ReactElement;"
        ));
        assert!(ts.contains("export declare function configure(options: ConfigureOptions): void;"));
    }

    #[test]
    fn the_entry_only_starts_the_wasm_from_an_effect() {
        let js = index_js(
            &[picker()],
            Path::new("/s/glue.js"),
            Some(Path::new("/s/react/runtime.js")),
            false,
            Some("kit"),
        );
        assert!(js.contains(
            "export const WidgetPicker = wrap(\"WidgetPicker\", \"__doxa_export_WidgetPicker\");"
        ));
        assert!(js.contains("started ??= import(\"/s/glue.js\")"));
        assert!(js.contains("libraryMode();"));
        assert!(js.contains("className: \"kit\""));
        assert!(js.contains("createElement(Portals, { root })"));
        let top: Vec<_> = js
            .lines()
            .filter(|l| !l.starts_with(' ') && !l.starts_with('}'))
            .collect();
        assert!(
            top.iter().all(|l| l.is_empty()
                || l.starts_with("import ")
                || l.starts_with("let ")
                || l.starts_with("function ")
                || l.starts_with("export ")
                || l.starts_with("/**")),
            "{top:?}"
        );
    }

    #[test]
    fn react_is_a_peer_and_the_rest_are_dependencies() {
        let lib = Library {
            name: "@acme/kit".into(),
            scope: None,
            react: None,
        };
        let npm = BTreeMap::from([
            ("react".to_owned(), "^19".to_owned()),
            ("xterm".to_owned(), "^5".to_owned()),
        ]);
        let pkg: serde_json::Value =
            serde_json::from_str(&package_json(&lib, "1.2.0", &npm, true)).unwrap();
        assert_eq!(pkg["peerDependencies"]["react"], "^19");
        assert_eq!(pkg["peerDependencies"]["react-dom"], ">=18");
        assert_eq!(pkg["dependencies"], serde_json::json!({ "xterm": "^5" }));
        assert_eq!(pkg["exports"]["./style.css"], "./style.css");
        assert_eq!(pkg["version"], "1.2.0");
    }

    #[test]
    fn a_scope_must_be_a_class() {
        assert_eq!(scope_class(".kit-root").unwrap(), "kit-root");
        assert!(scope_class("#kit").is_err());
        assert!(scope_class(".a .b").is_err());
    }
}
