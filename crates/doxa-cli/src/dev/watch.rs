//! Which directories feed which build, and what a batch of changes needs redone.

use std::path::{Path, PathBuf};

use doxa_build::config::{WebCrate, Workspace};
use notify_debouncer_mini::notify::RecursiveMode;

use crate::view::ClientViews;

/// What a batch of changes needs redone.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    pub wasm: bool,
    /// Every wasm change is a web crate source file, which a hot patch covers.
    pub patch: bool,
    pub server: bool,
    pub bundle: bool,
    pub css: bool,
}

impl Plan {
    pub fn is_empty(self) -> bool {
        self == Plan::default()
    }
}

/// What dev services add: the directories of their crates the web crate compiles, and sides.
#[derive(Debug, Clone, Default)]
pub struct Foreign {
    pub wasm_dirs: Vec<PathBuf>,
    pub server_only: Vec<PathBuf>,
    pub client_only: Vec<PathBuf>,
}

/// Which directories feed which build.
#[derive(Debug, Clone)]
pub struct Watch {
    root: PathBuf,
    ignore: Vec<PathBuf>,
    web_dir: PathBuf,
    wasm_dirs: Vec<PathBuf>,
    server_dirs: Vec<PathBuf>,
    /// An API crate's `server_only` directories, which the wasm build never reads.
    server_only: Vec<PathBuf>,
    /// An API crate's `client_only` directories, which the server build never reads.
    client_only: Vec<PathBuf>,
    /// A dev service's `server_only` directories; its own supervisor rebuilds for them.
    foreign: Vec<PathBuf>,
    extra_dirs: Vec<PathBuf>,
    public: Option<PathBuf>,
    /// Extensions a preprocessor turns into CSS.
    styles: Vec<String>,
    /// Absolute `watch` globs of the preprocessors.
    style_globs: Vec<glob::Pattern>,
}

pub fn canonical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_owned())
}

/// The directories none of the others contain.
pub fn outermost(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirs = dirs.to_vec();
    dirs.sort();
    dirs.dedup();
    dirs.iter()
        .filter(|d| !dirs.iter().any(|o| o != *d && d.starts_with(o)))
        .cloned()
        .collect()
}

impl Watch {
    pub fn new(ws: &Workspace, web: &WebCrate, server: Option<&str>, foreign: Foreign) -> Watch {
        let root = canonical(&ws.workspace_root);
        let extra_dirs = [
            root.join("style"),
            root.join("ts"),
            web.dir.join("style"),
            web.dir.join("ts"),
        ]
        .iter()
        .filter(|d| d.is_dir())
        .map(|d| canonical(d))
        .collect::<Vec<_>>();
        let web_dir = canonical(&web.dir);
        let globs: Vec<String> = web
            .config
            .preprocess
            .values()
            .flat_map(|p| &p.watch)
            .map(|g| web_dir.join(g).to_string_lossy().into_owned())
            .collect();
        let mut extra_dirs = extra_dirs;
        extra_dirs.extend(globs.iter().map(|g| glob_root(g)).filter(|d| d.is_dir()));
        let (server_only, client_only) = ws.sided_dirs();
        let canon = |dirs: &[PathBuf]| dirs.iter().map(|d| canonical(d)).collect::<Vec<_>>();
        let mut wasm_dirs = canon(&ws.source_dirs(&web.name));
        wasm_dirs.extend(canon(&foreign.wasm_dirs));
        let mut client_only = canon(&client_only);
        client_only.extend(canon(&foreign.client_only));
        Watch {
            server_only: canon(&server_only),
            client_only,
            foreign: canon(&foreign.server_only),
            styles: web.config.preprocess.keys().cloned().collect(),
            style_globs: globs
                .iter()
                .filter_map(|g| glob::Pattern::new(g).ok())
                .collect(),
            ignore: vec![canonical(&ws.target_directory)],
            web_dir: web_dir.clone(),
            wasm_dirs,
            server_dirs: server
                .map(|s| ws.source_dirs(s))
                .unwrap_or_default()
                .iter()
                .map(|d| canonical(d))
                .collect(),
            extra_dirs,
            public: web
                .config
                .public
                .as_ref()
                .map(|p| canonical(&web.dir.join(p))),
            root,
        }
    }

    /// The browser view of every shared file: those the wasm build reads beyond the web crate.
    pub fn client_views(&self) -> ClientViews {
        let shared: Vec<PathBuf> = self
            .wasm_dirs
            .iter()
            .filter(|d| !d.starts_with(&self.web_dir))
            .cloned()
            .collect();
        let mut skip = self.ignore.clone();
        skip.extend(
            self.server_only
                .iter()
                .chain(&self.client_only)
                .chain(&self.foreign)
                .cloned(),
        );
        skip.push(self.web_dir.clone());
        ClientViews::of(&shared, &skip)
    }

    /// Directories to watch recursively, outermost only, plus the root itself.
    pub fn roots(&self) -> Vec<(PathBuf, RecursiveMode)> {
        let dirs: Vec<PathBuf> = self
            .wasm_dirs
            .iter()
            .chain(&self.server_dirs)
            .chain(&self.extra_dirs)
            .filter(|d| d.is_dir() && !self.ignore.iter().any(|i| d.starts_with(i)))
            .cloned()
            .collect();
        let mut roots: Vec<_> = outermost(&dirs)
            .into_iter()
            .map(|d| (d, RecursiveMode::Recursive))
            .collect();
        if !roots.iter().any(|(d, _)| *d == self.root) {
            roots.push((self.root.clone(), RecursiveMode::NonRecursive));
        }
        roots
    }
}

/// The directory a glob starts in: everything before its first wildcard.
fn glob_root(glob: &str) -> PathBuf {
    let fixed = glob.split(['*', '?', '[', '{']).next().unwrap_or(glob);
    let p = Path::new(fixed);
    if fixed.ends_with('/') {
        p.to_owned()
    } else {
        p.parent().unwrap_or(p).to_owned()
    }
}

/// Decide what to rebuild for a batch of changed paths. A shared file whose browser view is
/// unchanged rebuilds only the server.
pub fn classify<'a>(
    paths: impl IntoIterator<Item = &'a Path>,
    w: &Watch,
    views: &mut ClientViews,
) -> Plan {
    let mut plan = Plan::default();
    let mut unpatchable = false;
    let under = |p: &Path, dirs: &[PathBuf]| dirs.iter().any(|d| p.starts_with(d));
    for p in paths {
        let skipped = w.ignore.iter().any(|i| p.starts_with(i))
            || p.components()
                .any(|c| c.as_os_str() == "node_modules" || c.as_os_str() == ".git");
        if skipped {
            continue;
        }
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
        // A preprocessor's own output, written and removed by the build.
        if w.styles
            .iter()
            .any(|s| name.ends_with(&format!(".{s}.css")))
        {
            continue;
        }
        if w.styles.iter().any(|s| s == ext) || w.style_globs.iter().any(|g| g.matches_path(p)) {
            plan.css = true;
            continue;
        }
        match ext {
            "rs" if under(p, &w.foreign) => {}
            "rs" if under(p, &w.server_only) => plan.server = true,
            "rs" if under(p, &w.client_only) => {
                plan.wasm = true;
                unpatchable = true;
            }
            "rs" if under(p, &w.wasm_dirs) && !p.starts_with(&w.web_dir) && views.unchanged(p) => {
                plan.server |= under(p, &w.server_dirs);
            }
            "rs" | "toml" if ext == "rs" || name == "Cargo.toml" => {
                if p.parent() == Some(w.root.as_path()) && name == "Cargo.toml" {
                    plan.wasm = true;
                    plan.server = true;
                    unpatchable = true;
                }
                if under(p, &w.wasm_dirs) {
                    plan.wasm = true;
                    unpatchable |= ext != "rs" || !p.starts_with(&w.web_dir);
                }
                plan.server |= under(p, &w.server_dirs);
            }
            "ts" | "tsx" | "js" | "jsx" | "mjs" => plan.bundle = true,
            "css" => plan.css = true,
            _ if name == "index.html" || w.public.as_deref().is_some_and(|d| p.starts_with(d)) => {
                plan.bundle = true
            }
            _ => {}
        }
    }
    plan.patch = plan.wasm && !unpatchable;
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watch() -> Watch {
        Watch {
            root: "/app".into(),
            ignore: vec!["/app/target".into()],
            web_dir: "/app/web".into(),
            wasm_dirs: vec![
                "/app/web".into(),
                "/app/client".into(),
                "/app/api/src".into(),
                "/sib/api".into(),
            ],
            server_dirs: vec!["/app/server".into(), "/app/api".into()],
            server_only: vec!["/app/api/src/server".into()],
            client_only: vec!["/app/api/src/browser".into()],
            foreign: vec!["/sib/api/src/server".into()],
            extra_dirs: vec!["/app/style".into()],
            public: Some("/app/web/public".into()),
            styles: vec!["scss".into()],
            style_globs: vec![glob::Pattern::new("/app/web/theme/**/*.json").unwrap()],
        }
    }

    fn plan(paths: &[&str]) -> Plan {
        classify(
            paths.iter().map(Path::new),
            &watch(),
            &mut ClientViews::default(),
        )
    }

    #[test]
    fn a_dev_services_shared_file_rebuilds_wasm_and_its_server_file_nothing_here() {
        assert!(plan(&["/sib/api/src/server/db.rs"]).is_empty());
        assert_eq!(
            plan(&["/sib/api/src/routes.rs"]),
            Plan {
                wasm: true,
                ..Plan::default()
            }
        );
    }

    #[test]
    fn a_one_sided_directory_rebuilds_only_its_half() {
        assert_eq!(
            plan(&["/app/api/src/server/db.rs"]),
            Plan {
                server: true,
                ..Plan::default()
            }
        );
        assert_eq!(
            plan(&["/app/api/src/browser/dom.rs"]),
            Plan {
                wasm: true,
                ..Plan::default()
            }
        );
    }

    #[test]
    fn a_shared_file_whose_browser_view_holds_rebuilds_only_the_server() {
        let dir = tempfile::tempdir().unwrap();
        let root = canonical(dir.path());
        let api = root.join("api/src");
        std::fs::create_dir_all(&api).unwrap();
        let routes = api.join("routes.rs");
        let route = "#[get(\"/n\")]\npub async fn n() -> Json<u32> { Json(1) }\n";
        std::fs::write(&routes, route).unwrap();
        let mut w = watch();
        w.root = root.clone();
        w.web_dir = root.join("web");
        w.wasm_dirs = vec![root.join("web"), api.clone()];
        w.server_dirs = vec![root.join("api")];
        let mut views = w.client_views();
        std::fs::write(&routes, route.replace("Json(1)", "Json(2)")).unwrap();
        let body = classify([routes.as_path()], &w, &mut views);
        assert_eq!(
            body,
            Plan {
                server: true,
                ..Plan::default()
            }
        );
        std::fs::write(&routes, route.replace("u32", "u64")).unwrap();
        let sig = classify([routes.as_path()], &w, &mut views);
        assert!(sig.wasm && sig.server && !sig.patch, "{sig:?}");
    }

    #[test]
    fn rust_changes_rebuild_wasm_and_restart_the_server_they_feed() {
        assert_eq!(
            plan(&["/app/api/src/widgets.rs"]),
            Plan {
                wasm: true,
                server: true,
                ..Plan::default()
            }
        );
        assert_eq!(
            plan(&["/app/web/src/lib.rs"]),
            Plan {
                wasm: true,
                patch: true,
                ..Plan::default()
            }
        );
        assert_eq!(
            plan(&["/app/server/src/main.rs"]),
            Plan {
                server: true,
                ..Plan::default()
            }
        );
        assert_eq!(
            plan(&["/app/Cargo.toml"]),
            Plan {
                wasm: true,
                server: true,
                ..Plan::default()
            }
        );
        assert_eq!(
            plan(&["/app/web/Cargo.toml"]),
            Plan {
                wasm: true,
                ..Plan::default()
            }
        );
    }

    #[test]
    fn only_web_crate_sources_are_patched() {
        assert!(plan(&["/app/web/src/a.rs", "/app/web/src/b.rs"]).patch);
        assert!(!plan(&["/app/web/src/a.rs", "/app/client/src/lib.rs"]).patch);
        assert!(!plan(&["/app/web/src/a.rs", "/app/web/Cargo.toml"]).patch);
        assert!(!plan(&["/app/web/src/a.rs", "/app/Cargo.toml"]).patch);
    }

    #[test]
    fn scripts_bundle_and_styles_rebuild_css() {
        assert_eq!(
            plan(&["/app/web/ts/editor.tsx"]),
            Plan {
                bundle: true,
                ..Plan::default()
            }
        );
        assert_eq!(
            plan(&["/app/style/app.css"]),
            Plan {
                css: true,
                ..Plan::default()
            }
        );
        assert_eq!(
            plan(&["/app/web/public/logo.svg"]),
            Plan {
                bundle: true,
                ..Plan::default()
            }
        );
        assert_eq!(
            plan(&["/app/web/ts/a.ts", "/app/web/style/app.css"]),
            Plan {
                bundle: true,
                css: true,
                ..Plan::default()
            }
        );
    }

    #[test]
    fn preprocessed_styles_and_their_globs_rebuild_css_but_not_their_output() {
        let css = Plan {
            css: true,
            ..Plan::default()
        };
        assert_eq!(plan(&["/app/web/style/_vars.scss"]), css);
        assert_eq!(plan(&["/app/web/theme/brand/colors.json"]), css);
        assert!(plan(&["/app/web/style/app.scss.css"]).is_empty());
        assert_eq!(glob_root("/w/style/**/*.scss"), Path::new("/w/style"));
    }

    #[test]
    fn build_output_and_noise_are_ignored() {
        assert!(plan(&["/app/target/doxa/stage/css/app.tailwind-in.css"]).is_empty());
        assert!(plan(&["/app/web/node_modules/react/index.js"]).is_empty());
        assert!(plan(&["/app/Cargo.lock", "/app/README.md", "/app/rustfmt.toml"]).is_empty());
    }

    #[test]
    fn roots_are_outermost_dirs_plus_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = canonical(dir.path());
        for d in ["api/src", "server", "web", "target/x"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        let w = Watch {
            root: root.clone(),
            ignore: vec![root.join("target")],
            web_dir: root.join("web"),
            wasm_dirs: vec![
                root.join("web"),
                root.join("api/src"),
                root.join("target/x"),
            ],
            server_dirs: vec![root.join("server"), root.join("api")],
            server_only: vec![],
            client_only: vec![],
            foreign: vec![],
            extra_dirs: vec![],
            public: None,
            styles: vec![],
            style_globs: vec![],
        };
        let roots: Vec<_> = w.roots().into_iter().map(|(d, _)| d).collect();
        assert_eq!(
            roots,
            [
                root.join("api"),
                root.join("server"),
                root.join("web"),
                root
            ]
        );
    }
}
