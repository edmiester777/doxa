//! Stylesheets: Tailwind when asked for, then lightningcss to bundle and minify.

use std::path::{Path, PathBuf};
use std::process::Command;

use lightningcss::bundler::{Bundler, FileProvider};
use lightningcss::stylesheet::{MinifyOptions, ParserOptions, PrinterOptions};

use crate::error::{run, Error, IoContext, Result};

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

/// Build one stylesheet entry of the web crate, returning the CSS text.
pub fn build(
    web_dir: &Path,
    entry: &str,
    sources: &[String],
    stage: &Path,
    release: bool,
) -> Result<String> {
    let input = web_dir.join(entry);
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
        input
    };
    bundle(&to_bundle, release)
}

/// Inline `@import`s with lightningcss, minifying on release.
pub fn bundle(path: &Path, release: bool) -> Result<String> {
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
            ..PrinterOptions::default()
        })
        .map_err(|e| fail(e.to_string()))?;
    Ok(out.code)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let out = build(dir.path(), "app.css", &[], &dir.path().join("stage"), true).unwrap();
        assert_eq!(out, "body{color:red}.a{margin:0}");
    }
}
