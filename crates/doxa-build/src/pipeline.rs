//! The steps of `doxa build`, runnable alone so `doxa dev` can redo only what changed.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::bundle::{
    entry_js, gallery_js, rewrite_islands, rewrite_npm, rewrite_react, BundleOutput, BundleRequest,
    Bundler, Esbuild,
};
use crate::config::{Layout, WebCrate, Workspace};
use crate::dist::{self, Dist};
use crate::error::{run, Error, IoContext, Result};
use crate::graph::Graph;
use crate::hot::Patched;
use crate::{bindgen, css, hot, npm, split, stories};

/// How to build.
#[derive(Debug, Clone, Default)]
pub struct BuildOptions {
    /// Optimize: `--release` cargo profile, minified JS and CSS, `wasm-opt`.
    pub release: bool,
    /// The web crate; found by its metadata when `None`.
    pub package: Option<String>,
    /// Install npm dependencies without touching the lockfile.
    pub locked: bool,
    /// Write `.br` and `.gz` siblings.
    pub compress: bool,
    /// Build the `#[story]` gallery into `target/doxa/gallery` instead of the app.
    pub gallery: bool,
    /// Build a fat base that [`Pipeline::patch`] can hot-patch.
    pub hot: bool,
    /// The path served under; overrides the web crate's `base`.
    pub base: Option<String>,
}

/// One app's build, holding what earlier steps produced.
pub struct Pipeline {
    /// The workspace.
    pub workspace: Workspace,
    /// The crate compiled to wasm.
    pub web: WebCrate,
    /// Output directories.
    pub layout: Layout,
    pub(crate) opts: BuildOptions,
    pub(crate) npm: npm::Source,
    /// `css_sources`, and the directory of each crate in the graph that uses doxa-ui.
    pub(crate) tailwind_sources: Vec<String>,
    pub(crate) bundler: Box<dyn Bundler + Send>,
    /// Building an npm package: no Preflight, relative stylesheet urls.
    pub(crate) library: bool,
    pub(crate) wasm_file: Option<String>,
    /// Modules split off the app wasm, as (hashed name, bytes).
    pub(crate) split_files: Vec<(String, Vec<u8>)>,
    stories: Vec<stories::Story>,
    hot: Option<hot::Base>,
    bundle: Option<BundleOutput>,
    pub(crate) stylesheets: Vec<(String, css::Built)>,
}

const PATCH_URL: &str = "/__doxa_patch";

/// Print a progress line.
pub fn note(msg: impl std::fmt::Display) {
    eprintln!("[doxa] {msg}");
}

impl Pipeline {
    /// Read the workspace containing `cwd`.
    pub fn new(cwd: &Path, opts: BuildOptions) -> Result<Self> {
        let workspace = Workspace::load(cwd)?;
        let web = workspace.web_crate(opts.package.as_deref())?;
        let layout = workspace.layout();
        let layout = if opts.gallery {
            layout.apart("gallery-build")
        } else {
            layout
        };
        let graph = Graph::load(cwd, &web.name)?;
        let needed = graph.npm(&web.name, &web.config.npm)?;
        let npm = npm::Source::for_app(&web, &workspace.workspace_root, &layout, &needed)?;
        let mut tailwind_sources = web.config.css_sources.clone();
        tailwind_sources.extend(
            graph
                .tailwind_sources()
                .into_iter()
                .map(|d| d.to_string_lossy().into_owned()),
        );
        Ok(Self {
            workspace,
            web,
            layout,
            opts,
            npm,
            tailwind_sources,
            bundler: Box::new(Esbuild::managed()?),
            library: false,
            wasm_file: None,
            split_files: Vec::new(),
            stories: Vec::new(),
            hot: None,
            bundle: None,
            stylesheets: Vec::new(),
        })
    }

    /// The served directory.
    pub fn dist_dir(&self) -> PathBuf {
        if self.opts.gallery {
            self.layout.gallery()
        } else {
            self.layout.dist()
        }
    }

    /// The path served under, with a leading and trailing `/`.
    pub fn base(&self) -> String {
        let base = self.opts.base.as_ref().or(self.web.config.base.as_ref());
        dist::normalize_base(base.map_or("/", String::as_str))
    }

    /// Every step, then the dist.
    pub fn build(&mut self) -> Result<Dist> {
        self.npm()?;
        self.wasm()?;
        self.js()?;
        self.css()?;
        self.assemble()
    }

    /// Install npm dependencies, when there are any.
    pub fn npm(&self) -> Result<()> {
        if self.npm != npm::Source::None {
            note("installing npm dependencies");
        }
        npm::install(&self.npm, self.opts.locked)
    }

    /// Compile the web crate to wasm and generate its bindings.
    pub fn wasm(&mut self) -> Result<()> {
        let lock = self.workspace.workspace_root.join("Cargo.lock");
        let checked = self.check_lock(&lock)?;
        note(format!("compiling {} to wasm", self.web.name));
        let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
        cmd.args([
            "rustc",
            "--lib",
            "-p",
            &self.web.name,
            "--target",
            "wasm32-unknown-unknown",
        ])
        .env("CARGO_TARGET_DIR", self.layout.wasm_target())
        .current_dir(&self.workspace.workspace_root);
        // Where `#[icons]` resolves package imports.
        if let Some(dir) = self.npm.dir() {
            cmd.env("DOXA_NODE_MODULES", dir.join("node_modules"));
        }
        if self.opts.release {
            cmd.arg("--release");
        }
        if self.opts.gallery {
            cmd.args(["--features", "doxa/gallery"]);
        }
        // wasm-split builds its call graph from the relocations and finds functions by name;
        // only this crate links. Both are stripped from what ships.
        cmd.args(["--", "-C", "link-arg=--emit-relocs", "-C", "strip=none"]);
        if self.opts.gallery {
            cmd.args(["--cfg", "doxa_gallery"]);
        }
        let records = if self.opts.hot {
            let records = hot::Records::new(&self.layout.stage())?;
            records.configure(&mut cmd, &self.web.lib_name)?;
            // Cargo only runs rustc for a stale crate, and the run is what gets recorded.
            hot::forget_fingerprint(&self.profile_dir().join(".fingerprint"), &self.web.name);
            Some(records)
        } else {
            None
        };
        run(
            "cargo",
            &mut cmd,
            "fix the compile error above; if the target is missing, run `rustup target add wasm32-unknown-unknown`",
        )?;
        if !checked {
            self.check_lock(&lock)?;
        }
        let wasm = self.linked_wasm();
        let out = self.bindgen_dir();
        self.hot = None;
        if let Some(records) = &records {
            note("linking the hot-patchable base");
            let base = records.fat_link(
                &self.layout.wasm_target(),
                &self.workspace.workspace_root,
                &wasm,
            )?;
            let fat = std::fs::read(&wasm).at(&wasm)?;
            let prepared = hot::wasm::prepare_base(&fat).map_err(hot::patch_error)?;
            std::fs::write(&wasm, prepared).at(&wasm)?;
            self.hot = Some(base);
        }
        let original = std::fs::read(&wasm).at(&wasm)?;
        if self.opts.gallery {
            self.stories = stories::stories(&original, &self.workspace.workspace_root);
        }
        let splits = split::has_split_points(&original);
        bindgen::generate(&wasm, &out, self.opts.release, splits, self.opts.hot)?;
        let app_wasm = out.join("app_bg.wasm");
        self.split_files.clear();
        if let Some(base) = &mut self.hot {
            let bytes = std::fs::read(&app_wasm).at(&app_wasm)?;
            let bytes = hot::wasm::stub_placeholder_imports(&bytes).map_err(hot::patch_error)?;
            base.set_bindgened(bytes.clone())?;
            std::fs::write(&app_wasm, split::strip_link_sections(&bytes, true)).at(&app_wasm)?;
        } else if splits {
            self.split(&original, &app_wasm)?;
        } else {
            let bytes = std::fs::read(&app_wasm).at(&app_wasm)?;
            let stripped = split::strip_link_sections(&bytes, !self.opts.release);
            std::fs::write(&app_wasm, stripped).at(&app_wasm)?;
            if self.opts.release && !bindgen::wasm_opt(&app_wasm)? {
                note("wasm-opt not on PATH; skipping it");
            }
        }
        let bytes = std::fs::read(&app_wasm).at(&app_wasm)?;
        // The gallery carries its own UI and every story, so the app's budgets don't apply.
        if self.opts.release && !self.opts.gallery {
            check_budget(
                "the app wasm",
                bytes.len(),
                self.web.config.wasm_budget_kb,
                "wasm_budget_kb",
            )?;
        }
        self.wasm_file = Some(dist::hashed_name("app.wasm", &bytes));
        Ok(())
    }

    /// Split `app_wasm` in place, optimize each part, and write the `__wasm_split.js` the glue imports.
    fn split(&mut self, original: &[u8], app_wasm: &Path) -> Result<()> {
        note("splitting the wasm at its lazy pages");
        let bindgened = std::fs::read(app_wasm).at(app_wasm)?;
        let mut out = split::split(original, &bindgened)?;
        let names = !self.opts.release;
        out.main = split::strip_link_sections(&out.main, names);
        for part in out.chunks.iter_mut().chain(out.modules.iter_mut()) {
            part.bytes = split::strip_link_sections(&part.bytes, names);
        }
        std::fs::write(app_wasm, &out.main).at(app_wasm)?;
        let dir = self.bindgen_dir();
        let mut skipped = false;
        for part in out.chunks.iter_mut().chain(out.modules.iter_mut()) {
            if !self.opts.release {
                continue;
            }
            let path = dir.join(&part.file);
            std::fs::write(&path, &part.bytes).at(&path)?;
            skipped |= !bindgen::wasm_opt(&path)?;
            part.bytes = std::fs::read(&path).at(&path)?;
            check_budget(
                &part.file,
                part.bytes.len(),
                self.web
                    .config
                    .chunk_budget_kb
                    .filter(|_| !self.opts.gallery),
                "chunk_budget_kb",
            )?;
        }
        if self.opts.release {
            skipped |= !bindgen::wasm_opt(app_wasm)?;
        }
        if skipped {
            note("wasm-opt not on PATH; skipping it");
        }
        let hashed = |p: &split::Part| dist::hashed_name(&p.file, &p.bytes);
        let js = split::loader_js(&out, hashed);
        let loader = dir.join("__wasm_split.js");
        std::fs::write(&loader, js).at(&loader)?;
        note(format!(
            "main module: {} KiB",
            out.main.len().div_ceil(1024)
        ));
        for part in out.chunks.into_iter().chain(out.modules) {
            note(format!(
                "{}: {} KiB",
                part.file,
                part.bytes.len().div_ceil(1024)
            ));
            self.split_files.push((hashed(&part), part.bytes));
        }
        Ok(())
    }

    /// Recompile only the web crate and link it as a patch of the hot base into
    /// [`patch_dir`](Self::patch_dir).
    pub fn patch(&mut self) -> Result<Patched> {
        let dir = self.patch_dir();
        let base = self.hot.as_mut().ok_or_else(|| {
            Error::config("no hot-patchable base", "run a full build with hot on")
        })?;
        note(format!("patching {}", self.web.name));
        base.patch(&dir, PATCH_URL)
    }

    /// Where patches are written; the page fetches them from `/__doxa_patch/`.
    pub fn patch_dir(&self) -> PathBuf {
        self.layout.stage().join("hot").join("patches")
    }

    /// The wasm as the linker wrote it, before bindgen.
    pub(crate) fn linked_wasm(&self) -> PathBuf {
        self.profile_dir()
            .join(format!("{}.wasm", self.web.lib_name))
    }

    fn profile_dir(&self) -> PathBuf {
        let profile = if self.opts.release {
            "release"
        } else {
            "debug"
        };
        self.layout
            .wasm_target()
            .join("wasm32-unknown-unknown")
            .join(profile)
    }

    fn check_lock(&self, lock: &Path) -> Result<bool> {
        match std::fs::read_to_string(lock) {
            Ok(text) => bindgen::check_lock(&text, lock).map(|()| true),
            Err(_) => Ok(false),
        }
    }

    /// Bundle the glue, islands, and their imports.
    pub fn js(&mut self) -> Result<()> {
        let wasm_file = self.wasm_file.clone().ok_or_else(|| {
            Error::config(
                "the JS bundle needs the wasm step first",
                "run a full build",
            )
        })?;
        note("bundling JS");
        let dir = self.bindgen_dir();
        let glue_path = dir.join("app.js");
        let glue = std::fs::read_to_string(&glue_path).at(&glue_path)?;
        let glue = split::dedupe_loader_imports(&glue);
        let (glue, mut react) = rewrite_react(&glue, &self.web.dir);
        let (glue, npm) = rewrite_npm(&glue, &self.web.dir);
        react.extend(npm);
        for (file, js) in react {
            let path = dir.join(file);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).at(parent)?;
            }
            std::fs::write(&path, js).at(&path)?;
        }
        let (glue, islands) = rewrite_islands(&glue, &self.web.dir);
        let rewritten = dir.join("glue.js");
        std::fs::write(&rewritten, glue).at(&rewritten)?;
        let entry_dir = self.layout.stage().join("entry");
        std::fs::create_dir_all(&entry_dir).at(&entry_dir)?;
        let entry = entry_dir.join("app.js");
        let split = !self.split_files.is_empty();
        let js = if self.opts.gallery {
            let listed = serde_json::to_string(&self.stories).expect("json");
            gallery_js(&rewritten, &islands, &wasm_file, &listed, split)
        } else {
            entry_js(&rewritten, &islands, &wasm_file, split)
        };
        std::fs::write(&entry, js).at(&entry)?;
        let out_dir = self.esbuild_dir();
        self.bundle = Some(self.bundler.bundle(&BundleRequest {
            entry: &entry,
            out_dir: &out_dir,
            node_modules: self.npm.dir(),
            release: self.opts.release,
            library: false,
        })?);
        Ok(())
    }

    /// Build each stylesheet entry.
    pub fn css(&mut self) -> Result<()> {
        let stage = self.layout.stage().join("css");
        let cfg = &self.web.config;
        let mut out = Vec::new();
        let base = self.base();
        for entry in &cfg.css {
            note(format!("building {entry}"));
            let inputs = css::Inputs {
                web_dir: &self.web.dir,
                sources: &self.tailwind_sources,
                preprocess: &cfg.preprocess,
                node_modules: self.npm.dir(),
                library: self.library,
                base: &base,
            };
            let built = css::build(&inputs, entry, &stage, self.opts.release)?;
            let stem = Path::new(entry)
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy();
            out.push((format!("{stem}.css"), built));
        }
        self.stylesheets = out;
        Ok(())
    }

    /// Write the dist from the latest output of every step.
    pub fn assemble(&self) -> Result<Dist> {
        let (Some(wasm_file), Some(bundle)) = (&self.wasm_file, &self.bundle) else {
            return Err(Error::config("nothing built yet", "run a full build"));
        };
        let mut d = Dist {
            services: self.web.config.services.clone(),
            base: self.base(),
            ..Dist::default()
        };
        let app_wasm = self.bindgen_dir().join("app_bg.wasm");
        d.add(
            "app.wasm",
            wasm_file,
            std::fs::read(&app_wasm).at(&app_wasm)?,
        );
        for (hashed, bytes) in &self.split_files {
            d.add(hashed, hashed, bytes.clone());
        }

        for (logical, built) in &self.stylesheets {
            for (original, hashed, bytes) in &built.assets {
                d.add(original, hashed, bytes.clone());
            }
            let name = d.add_hashed(logical, built.css.clone().into_bytes());
            d.stylesheets.push(name);
        }
        let out = self.esbuild_dir();
        for file in &bundle.files {
            let path = out.join(file);
            let bytes = std::fs::read(&path).at(&path)?;
            if *file == bundle.entry {
                d.entry = d.add_hashed("app.js", bytes);
            } else if Some(file) == bundle.css.as_ref() {
                let name = d.add_hashed("bundle.css", bytes);
                d.stylesheets.push(name);
            } else {
                d.add(file, file, bytes);
            }
        }
        d.preload.push(d.entry.clone());
        d.preload.extend(bundle.chunks.iter().cloned());

        if let Some(public) = &self.web.config.public {
            copy_public(&self.web.dir.join(public), &mut d)?;
        }

        let custom = self.web.dir.join("index.html");
        let html = if custom.is_file() && !self.opts.gallery {
            dist::inject(
                &std::fs::read_to_string(&custom).at(&custom)?,
                &d.html_tags(),
            )
        } else {
            let title = if self.opts.gallery {
                "Stories"
            } else {
                &self.web.name
            };
            dist::generated_html(title, &d.html_tags())
        };
        let cache = self.layout.stage().join("compressed");
        dist::write(
            &self.dist_dir(),
            &d,
            &html,
            self.opts.compress.then_some(cache.as_path()),
        )?;
        note(format!("wrote {}", self.dist_dir().display()));
        Ok(d)
    }

    /// Build the server with the dist embedded.
    pub fn build_server(&self, server: &str) -> Result<()> {
        note(format!("building {server} with the dist embedded"));
        let dist = std::fs::canonicalize(self.dist_dir()).at(&self.dist_dir())?;
        let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
        cmd.args(["build", "-p", server, "--features", "embed"])
            .env("DOXA_DIST", dist)
            .current_dir(&self.workspace.workspace_root);
        if self.opts.release {
            cmd.arg("--release");
        }
        run(
            "cargo",
            &mut cmd,
            &format!("give {server} a feature `embed = [\"doxa/embed\"]`, and fix any compile error above"),
        )
    }

    pub(crate) fn bindgen_dir(&self) -> PathBuf {
        self.layout.stage().join("bindgen")
    }

    fn esbuild_dir(&self) -> PathBuf {
        self.layout.stage().join("esbuild")
    }
}

fn check_budget(what: &str, bytes: usize, budget_kb: Option<u64>, key: &str) -> Result<()> {
    let Some(budget) = budget_kb else {
        return Ok(());
    };
    let kb = (bytes as u64).div_ceil(1024);
    if kb <= budget {
        return Ok(());
    }
    Err(Error::config(
        format!("{what} is {kb} KiB, over its {budget} KiB budget"),
        format!("shrink it (put wasm-opt on PATH if it was skipped), or raise `{key}` in [package.metadata.doxa]"),
    ))
}

fn copy_public(root: &Path, d: &mut Dist) -> Result<()> {
    if !root.is_dir() {
        return Ok(());
    }
    let mut stack = vec![root.to_owned()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).at(&dir)? {
            let path = entry.at(&dir)?.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .expect("under root")
                .to_string_lossy()
                .replace('\\', "/");
            let bytes = std::fs::read(&path).at(&path)?;
            d.add(&rel, &rel, bytes);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::check_budget;

    #[test]
    fn a_wasm_over_its_budget_fails_with_its_size() {
        let k = "wasm_budget_kb";
        assert!(check_budget("the app wasm", 400 * 1024, None, k).is_ok());
        assert!(check_budget("the app wasm", 400 * 1024, Some(400), k).is_ok());
        let err = check_budget(
            "module_0_page.wasm",
            400 * 1024 + 1,
            Some(400),
            "chunk_budget_kb",
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("module_0_page.wasm is 401 KiB, over its 400 KiB budget"),
            "{err}"
        );
        assert!(err.contains("`chunk_budget_kb`"), "{err}");
    }
}
