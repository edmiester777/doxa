//! The steps of `doxa build`, runnable alone so `doxa dev` can redo only what changed.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::bundle::{
    entry_js, rewrite_islands, rewrite_react, BundleOutput, BundleRequest, Bundler, Esbuild,
};
use crate::config::{Layout, WebCrate, Workspace};
use crate::dist::{self, Dist};
use crate::error::{run, Error, IoContext, Result};
use crate::{bindgen, css, npm};

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
    bundle: Option<BundleOutput>,
    stylesheets: Vec<(String, String)>,
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
            "build",
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
        bindgen::generate(&wasm, &out, self.opts.release)?;
        let app_wasm = out.join("app_bg.wasm");
        if self.opts.release && !bindgen::wasm_opt(&app_wasm)? {
            note("wasm-opt not on PATH; skipping it");
        }
        let bytes = std::fs::read(&app_wasm).at(&app_wasm)?;
        self.wasm_file = Some(dist::hashed_name("app.wasm", &bytes));
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
        std::fs::write(&entry, entry_js(&rewritten, &islands, &wasm_file)).at(&entry)?;
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
            let text = css::build(
                &self.web.dir,
                entry,
                &cfg.css_sources,
                &stage,
                self.opts.release,
            )?;
            let stem = Path::new(entry)
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy();
            out.push((format!("{stem}.css"), text));
        }
        self.stylesheets = out;
        Ok(())
    }

    /// Write the dist from the latest output of every step.
    pub fn assemble(&self) -> Result<Dist> {
        let (Some(wasm_file), Some(bundle)) = (&self.wasm_file, &self.bundle) else {
            return Err(Error::config("nothing built yet", "run a full build"));
        };
        let mut d = Dist::default();
        let app_wasm = self.bindgen_dir().join("app_bg.wasm");
        d.add(
            "app.wasm",
            wasm_file,
            std::fs::read(&app_wasm).at(&app_wasm)?,
        );

        for (logical, text) in &self.stylesheets {
            let name = d.add_hashed(logical, text.clone().into_bytes());
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
