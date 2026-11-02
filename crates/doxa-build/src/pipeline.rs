//! The steps of `doxa build`, runnable alone so `doxa dev` can redo only what changed.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::bundle::{
    entry_js, rewrite_islands, rewrite_react, BundleOutput, BundleRequest, Bundler, Esbuild,
};
use crate::config::{Layout, WebCrate, Workspace};
use crate::dist::{self, Dist};
use crate::error::{run, Error, IoContext, Result};
use crate::{bindgen, css, npm, split};

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
}

/// One app's build, holding what earlier steps produced.
pub struct Pipeline {
    /// The workspace.
    pub workspace: Workspace,
    /// The crate compiled to wasm.
    pub web: WebCrate,
    /// Output directories.
    pub layout: Layout,
    opts: BuildOptions,
    npm: npm::Source,
    bundler: Box<dyn Bundler + Send>,
    wasm_file: Option<String>,
    /// Modules split off the app wasm, as (hashed name, bytes).
    split_files: Vec<(String, Vec<u8>)>,
    bundle: Option<BundleOutput>,
    stylesheets: Vec<(String, css::Built)>,
}

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
        let npm = npm::Source::for_app(&web, &workspace.workspace_root, &layout);
        Ok(Self {
            workspace,
            web,
            layout,
            opts,
            npm,
            bundler: Box::new(Esbuild::managed()?),
            wasm_file: None,
            split_files: Vec::new(),
            bundle: None,
            stylesheets: Vec::new(),
        })
    }

    /// The served directory.
    pub fn dist_dir(&self) -> PathBuf {
        self.layout.dist()
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
        if self.opts.release {
            cmd.arg("--release");
        }
        // wasm-split builds its call graph from the relocations and finds functions by name;
        // only this crate links. Both are stripped from what ships.
        cmd.args(["--", "-C", "link-arg=--emit-relocs", "-C", "strip=none"]);
        run(
            "cargo",
            &mut cmd,
            "fix the compile error above; if the target is missing, run `rustup target add wasm32-unknown-unknown`",
        )?;
        if !checked {
            self.check_lock(&lock)?;
        }
        let profile = if self.opts.release {
            "release"
        } else {
            "debug"
        };
        let wasm = self
            .layout
            .wasm_target()
            .join("wasm32-unknown-unknown")
            .join(profile)
            .join(format!("{}.wasm", self.web.lib_name));
        let out = self.bindgen_dir();
        let original = std::fs::read(&wasm).at(&wasm)?;
        let splits = split::has_split_points(&original);
        bindgen::generate(&wasm, &out, self.opts.release, splits)?;
        let app_wasm = out.join("app_bg.wasm");
        self.split_files.clear();
        if splits {
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
        if self.opts.release {
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
                self.web.config.chunk_budget_kb,
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
        let (glue, react) = rewrite_react(&glue, &self.web.dir);
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
        std::fs::write(
            &entry,
            entry_js(
                &rewritten,
                &islands,
                &wasm_file,
                !self.split_files.is_empty(),
            ),
        )
        .at(&entry)?;
        let out_dir = self.esbuild_dir();
        self.bundle = Some(self.bundler.bundle(&BundleRequest {
            entry: &entry,
            out_dir: &out_dir,
            node_modules: self.npm.dir(),
            release: self.opts.release,
        })?);
        Ok(())
    }

    /// Build each stylesheet entry.
    pub fn css(&mut self) -> Result<()> {
        let stage = self.layout.stage().join("css");
        let cfg = &self.web.config;
        let mut out = Vec::new();
        for entry in &cfg.css {
            note(format!("building {entry}"));
            let inputs = css::Inputs {
                web_dir: &self.web.dir,
                sources: &cfg.css_sources,
                preprocess: &cfg.preprocess,
                node_modules: self.npm.dir(),
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
        let html = if custom.is_file() {
            dist::inject(
                &std::fs::read_to_string(&custom).at(&custom)?,
                &d.html_tags(),
            )
        } else {
            dist::generated_html(&self.web.name, &d.html_tags())
        };
        dist::write(&self.dist_dir(), &d, &html, self.opts.compress)?;
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

    fn bindgen_dir(&self) -> PathBuf {
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
