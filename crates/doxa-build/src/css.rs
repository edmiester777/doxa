//! Stylesheets: Tailwind when asked for, then lightningcss to bundle and minify.

use std::path::{Path, PathBuf};
use std::process::Command;

use lightningcss::bundler::{Bundler, FileProvider};
use lightningcss::dependencies::{Dependency, DependencyOptions};
use lightningcss::stylesheet::{MinifyOptions, ParserOptions, PrinterOptions};

use std::collections::BTreeMap;

use crate::config::Preprocess;
use crate::error::{run, Error, IoContext, Result};

/// A built stylesheet and the local files its `url()`s point at, under hashed names.
#[derive(Debug, Default)]
pub struct Built {
    /// The CSS text, with each local `url()` pointing at its hashed file.
    pub css: String,
    /// `(original file name, hashed name, bytes)` for each referenced file.
    pub assets: Vec<(String, String, Vec<u8>)>,
}

/// Whether a stylesheet asks for Tailwind.
pub fn uses_tailwind(css: &str) -> bool {
    css.contains("@import \"tailwindcss\"") || css.contains("@import 'tailwindcss'")
}

/// A stylesheet that imports `input` and adds `sources` to Tailwind's scan.
pub fn tailwind_wrapper(input: &Path, sources: &[PathBuf]) -> String {
    let lit =
        |p: &Path| serde_json::to_string(&p.to_string_lossy().replace('\\', "/")).expect("json");
    let mut css = format!("@import {};\n", lit(input));
    for s in sources {
        css.push_str(&format!("@source {};\n", lit(s)));
    }
    css
}

/// What a stylesheet entry is built from.
#[derive(Debug, Clone, Copy)]
pub struct Inputs<'a> {
    /// The web crate's directory.
    pub web_dir: &'a Path,
    /// Extra directories Tailwind scans.
    pub sources: &'a [String],
    /// Preprocessors by extension.
    pub preprocess: &'a BTreeMap<String, Preprocess>,
    /// Where npm installed the tools a preprocessor runs.
    pub node_modules: Option<&'a Path>,
}

/// Where a preprocessor writes `input`'s CSS: beside it, so relative paths still resolve.
pub fn preprocessed_path(input: &Path) -> PathBuf {
    let mut name = input.file_name().unwrap_or_default().to_owned();
    name.push(".css");
    input.with_file_name(name)
}

/// Run the preprocessor for `input`'s extension, if there is one, returning its output.
fn preprocess(at: &Inputs<'_>, input: &Path) -> Result<Option<PathBuf>> {
    let ext = input.extension().and_then(|e| e.to_str()).unwrap_or("");
    let Some(pre) = at.preprocess.get(ext) else {
        return Ok(None);
    };
    let Some((program, args)) = pre.command.split_first() else {
        return Err(Error::config(
            format!("[package.metadata.doxa.preprocess.{ext}] has an empty command"),
            "set `command = [\"program\", \"{input}\", \"{output}\"]`",
        ));
    };
    let output = preprocessed_path(input);
    let fill = |a: &String| {
        a.replace("{input}", &input.to_string_lossy())
            .replace("{output}", &output.to_string_lossy())
    };
    let mut cmd = Command::new(program);
    cmd.args(args.iter().map(fill)).current_dir(at.web_dir);
    if let Some(bin) = at.node_modules.map(|d| d.join("node_modules").join(".bin")) {
        let path = std::env::var_os("PATH").unwrap_or_default();
        let joined = std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(&path)))
            .unwrap_or(path);
        cmd.env("PATH", joined);
    }
    run(
        "preprocessor",
        &mut cmd,
        &format!("fix the error above, or the `{ext}` preprocess command"),
    )?;
    if !output.is_file() {
        return Err(Error::config(
            format!(
                "the `{ext}` preprocessor wrote nothing to {}",
                output.display()
            ),
            "pass `{output}` where the command expects its output file",
        ));
    }
    Ok(Some(output))
}

/// Build one stylesheet entry of the web crate, returning the CSS text.
pub fn build(at: &Inputs<'_>, entry: &str, stage: &Path, release: bool) -> Result<Built> {
    let web_dir = at.web_dir;
    let sources = at.sources;
    let source = web_dir.join(entry);
    let pre = preprocess(at, &source)?;
    let built = build_css(web_dir, &source, pre.as_deref(), sources, stage, release);
    if let Some(out) = pre {
        let _ = std::fs::remove_file(out);
    }
    built
}

fn build_css(
    web_dir: &Path,
    source: &Path,
    pre: Option<&Path>,
    sources: &[String],
    stage: &Path,
    release: bool,
) -> Result<Built> {
    let input = pre.unwrap_or(source).to_owned();
    let text = std::fs::read_to_string(&input).at(&input)?;
    let to_bundle = if uses_tailwind(&text) {
        std::fs::create_dir_all(stage).at(stage)?;
        let stem = input.file_stem().unwrap_or_default().to_string_lossy();
        let wrapper = stage.join(format!("{stem}.tailwind-in.css"));
        let output = stage.join(format!("{stem}.tailwind-out.css"));
        let sources: Vec<_> = sources.iter().map(|s| web_dir.join(s)).collect();
        std::fs::write(&wrapper, tailwind_wrapper(&input, &sources)).at(&wrapper)?;
        let mut cmd = Command::new(crate::tool::tailwind()?);
        cmd.arg("--input")
            .arg(&wrapper)
            .arg("--output")
            .arg(&output)
            .current_dir(web_dir);
        if release {
            cmd.arg("--minify");
        }
        run(
            "tailwindcss",
            &mut cmd,
            "fix the stylesheet error reported above",
        )?;
        output
    } else {
        input.clone()
    };
    let entry_dir = input.parent().unwrap_or(web_dir);
    bundle(&to_bundle, entry_dir, release)
}

/// Inline `@import`s with lightningcss, minifying on release, and hash each local `url()`.
/// A url resolves against the file that wrote it, then against `fallback` (Tailwind's output
/// lives elsewhere).
pub fn bundle(path: &Path, fallback: &Path, release: bool) -> Result<Built> {
    let fs = FileProvider::new();
    let mut bundler = Bundler::new(&fs, None, ParserOptions::default());
    let fail = |detail: String| Error::Tool {
        tool: "lightningcss",
        command: format!("bundle {}", path.display()),
        detail,
        fix: "fix the CSS at the location above".into(),
    };
    let mut sheet = bundler.bundle(path).map_err(|e| fail(e.to_string()))?;
    if release {
        sheet
            .minify(MinifyOptions::default())
            .map_err(|e| fail(e.to_string()))?;
    }
    let out = sheet
        .to_css(PrinterOptions {
            minify: release,
            analyze_dependencies: Some(DependencyOptions {
                remove_imports: false,
            }),
            ..PrinterOptions::default()
        })
        .map_err(|e| fail(e.to_string()))?;
    let mut built = Built {
        css: out.code,
        assets: Vec::new(),
    };
    for dep in out.dependencies.unwrap_or_default() {
        let Dependency::Url(dep) = dep else { continue };
        let target = match local(&dep.url) {
            Some((file, suffix)) => {
                let from = Path::new(&dep.loc.file_path).parent().unwrap_or(fallback);
                let found = [from.join(file), fallback.join(file)]
                    .into_iter()
                    .find(|p| p.is_file())
                    .ok_or_else(|| {
                        fail(format!(
                            "`url({})` in {}: no such file",
                            dep.url, dep.loc.file_path
                        ))
                    })?;
                let bytes = std::fs::read(&found).at(&found)?;
                let name = found.file_name().unwrap_or_default().to_string_lossy();
                let hashed = crate::dist::hashed_name(&name, &bytes);
                let url = format!("/{hashed}{suffix}");
                built.assets.push((name.into_owned(), hashed, bytes));
                url
            }
            None => dep.url.clone(),
        };
        built.css = built.css.replace(&dep.placeholder, &target);
    }
    Ok(built)
}

/// A url naming a file beside the stylesheet: its path and any `?query` / `#fragment`.
fn local(url: &str) -> Option<(&str, &str)> {
    let external = url.contains(':') || url.starts_with('/') || url.starts_with('#');
    if external || url.is_empty() {
        return None;
    }
    let at = url.find(['?', '#']).unwrap_or(url.len());
    Some(url.split_at(at))
}

#[cfg(test)]
mod tests {
    use super::*;

    static NONE: BTreeMap<String, Preprocess> = BTreeMap::new();

    fn plain(web_dir: &Path) -> Inputs<'_> {
        Inputs {
            web_dir,
            sources: &[],
            preprocess: &NONE,
            node_modules: None,
        }
    }

    fn with(web_dir: &Path, pre: &BTreeMap<String, Preprocess>) -> String {
        let at = Inputs {
            preprocess: pre,
            ..plain(web_dir)
        };
        match build(&at, "style/app.scss", &web_dir.join("stage"), true) {
            Ok(b) => b.css,
            Err(e) => format!("error: {e}"),
        }
    }

    fn command(argv: &[&str]) -> BTreeMap<String, Preprocess> {
        let pre = Preprocess {
            command: argv.iter().map(|a| a.to_string()).collect(),
            watch: vec![],
        };
        BTreeMap::from([("scss".to_owned(), pre)])
    }

    #[cfg(unix)]
    #[test]
    fn a_preprocessed_entry_resolves_imports_beside_its_source_and_leaves_no_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("style")).unwrap();
        std::fs::write(dir.path().join("style/base.css"), "body { color: red; }\n").unwrap();
        std::fs::write(
            dir.path().join("style/app.scss"),
            "@import \"base.css\";\n.a { margin: 0px; }\n",
        )
        .unwrap();
        let css = with(dir.path(), &command(&["cp", "{input}", "{output}"]));
        assert_eq!(css, "body{color:red}.a{margin:0}");
        assert!(!dir.path().join("style/app.scss.css").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_failing_preprocessor_fails_the_build() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("style")).unwrap();
        std::fs::write(dir.path().join("style/app.scss"), "a {}").unwrap();
        let css = with(dir.path(), &command(&["false"]));
        assert!(
            css.starts_with("error:") && css.contains("preprocessor"),
            "{css}"
        );
        let css = with(dir.path(), &command(&["true"]));
        assert!(css.contains("wrote nothing"), "{css}");
    }

    #[test]
    fn tailwind_detection() {
        assert!(uses_tailwind("@import \"tailwindcss\";\n"));
        assert!(uses_tailwind("@import 'tailwindcss' source(none);"));
        assert!(!uses_tailwind("@import \"./base.css\";"));
    }

    #[test]
    fn wrapper_imports_the_entry_and_adds_sources() {
        let css = tailwind_wrapper(Path::new("/w/style/app.css"), &[PathBuf::from("/w/../api")]);
        assert_eq!(
            css,
            "@import \"/w/style/app.css\";\n@source \"/w/../api\";\n"
        );
    }

    #[test]
    fn imports_are_inlined_and_minified() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("base.css"), "body { color: red; }\n").unwrap();
        std::fs::write(
            dir.path().join("app.css"),
            "@import \"base.css\";\n.a  {  margin: 0px; }\n",
        )
        .unwrap();
        let out = build(
            &plain(dir.path()),
            "app.css",
            &dir.path().join("stage"),
            true,
        )
        .unwrap();
        assert_eq!(out.css, "body{color:red}.a{margin:0}");
    }

    #[test]
    fn a_local_url_points_at_a_hashed_copy() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("style/fonts")).unwrap();
        std::fs::write(dir.path().join("style/fonts/inter.woff2"), b"font").unwrap();
        std::fs::write(
            dir.path().join("style/fonts.css"),
            "@font-face { src: url(fonts/inter.woff2?v=2); }\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("style/app.css"),
            "@import \"fonts.css\";\n.a { background: url(\"https://x.test/a.png\"), url(#g), url(/logo.svg); }\n",
        )
        .unwrap();
        let out = build(
            &plain(dir.path()),
            "style/app.css",
            &dir.path().join("stage"),
            true,
        )
        .unwrap();
        let hashed = crate::dist::hashed_name("inter.woff2", b"font");
        assert_eq!(
            out.assets,
            [("inter.woff2".to_owned(), hashed.clone(), b"font".to_vec())]
        );
        assert!(
            out.css.contains(&format!("url(\"/{hashed}?v=2\")")),
            "{}",
            out.css
        );
        for kept in ["https://x.test/a.png", "#g", "/logo.svg"] {
            assert!(out.css.contains(kept), "{kept} in {}", out.css);
        }
    }

    #[test]
    fn a_missing_url_target_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("app.css"),
            ".a { background: url(gone.png); }\n",
        )
        .unwrap();
        let err = build(
            &plain(dir.path()),
            "app.css",
            &dir.path().join("stage"),
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("url(gone.png)"), "{err}");
    }
}
