//! The command line shared by `doxa-fmt` and `doxa fmt`.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use crate::{format_source, Config};

const USAGE: &str = "usage: doxa-fmt [--check] [--stdin] [paths...]";

/// Run with command-line `args` (without the program name): `[--check] [--stdin] [paths...]`.
pub fn run(args: impl IntoIterator<Item = String>) -> ExitCode {
    let mut check = false;
    let mut stdin = false;
    let mut paths = Vec::new();
    for arg in args {
        match arg.as_str() {
            "--check" => check = true,
            "--stdin" => stdin = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            flag if flag.starts_with('-') => {
                eprintln!("unknown flag {flag}\n{USAGE}");
                return ExitCode::from(2);
            }
            path => paths.push(PathBuf::from(path)),
        }
    }

    if stdin {
        return run_stdin();
    }
    if paths.is_empty() {
        paths.push(PathBuf::from("."));
    }

    let mut files = Vec::new();
    for path in &paths {
        if let Err(e) = collect(path, &mut files) {
            eprintln!("{}: {e}", path.display());
            return ExitCode::from(2);
        }
    }

    let mut would_change = false;
    let mut failed = false;
    for file in files {
        let src = match std::fs::read_to_string(&file) {
            Ok(src) => src,
            Err(e) => {
                eprintln!("{}: {e}", file.display());
                failed = true;
                continue;
            }
        };
        let result = format_source(&src, &Config::discover(&file));
        for w in &result.warnings {
            eprintln!("{}: {w}", file.display());
        }
        if !result.changed {
            continue;
        }
        if check {
            would_change = true;
            print_diff(&file, &src, &result.output);
        } else if let Err(e) = std::fs::write(&file, &result.output) {
            eprintln!("{}: {e}", file.display());
            failed = true;
        }
    }

    if failed {
        ExitCode::from(2)
    } else if would_change {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn run_stdin() -> ExitCode {
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("stdin: {e}");
        return ExitCode::from(2);
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let src = rustfmt(&input, &edition(&cwd)).unwrap_or(input);
    let result = format_source(&src, &Config::discover(&cwd));
    for w in &result.warnings {
        eprintln!("<stdin>: {w}");
    }
    if std::io::stdout()
        .write_all(result.output.as_bytes())
        .is_err()
    {
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}

/// The edition of the package around `dir`, as cargo would pass it to rustfmt.
fn edition(dir: &Path) -> String {
    let mut inherits = false;
    for ancestor in dir.ancestors() {
        let Ok(text) = std::fs::read_to_string(ancestor.join("Cargo.toml")) else {
            continue;
        };
        let (mut section, mut package, mut own, mut shared) = ("", false, None, None);
        for line in text.lines().map(str::trim) {
            if line.starts_with('[') {
                section = line.trim_matches(['[', ']']).trim();
                package |= section == "package";
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let (key, value) = (key.trim(), value.trim().trim_matches('"'));
            match (section, key) {
                ("package", "edition.workspace") => own = Some(None),
                ("package", "edition") if value.contains("workspace") => own = Some(None),
                ("package", "edition") => own = Some(Some(value.to_owned())),
                ("workspace.package", "edition") => shared = Some(value.to_owned()),
                _ => {}
            }
        }
        if package && !inherits {
            match own {
                Some(Some(edition)) => return edition,
                Some(None) => inherits = true,
                None => return "2015".to_owned(),
            }
        }
        if let (true, Some(edition)) = (inherits, shared) {
            return edition;
        }
    }
    "2021".to_owned()
}

fn rustfmt(input: &str, edition: &str) -> Option<String> {
    let mut child = Command::new("rustfmt")
        .args(["--edition", edition, "--emit", "stdout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .ok()?;
    let mut pipe = child.stdin.take()?;
    let owned = input.to_string();
    // Writing on a separate thread avoids a deadlock once rustfmt fills the stdout pipe.
    let writer = std::thread::spawn(move || pipe.write_all(owned.as_bytes()));
    let out = child.wait_with_output().ok()?;
    writer.join().ok()?.ok()?;
    if out.status.success() {
        String::from_utf8(out.stdout).ok()
    } else {
        None
    }
}

fn collect(path: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if path.is_file() {
        files.push(path.to_path_buf());
        return Ok(());
    }
    let mut entries: Vec<_> = std::fs::read_dir(path)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let p = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if entry.file_type()?.is_dir() {
            if name != "target" && !name.starts_with('.') {
                collect(&p, files)?;
            }
        } else if name.ends_with(".rs") {
            files.push(p);
        }
    }
    Ok(())
}

fn print_diff(file: &Path, old: &str, new: &str) {
    let name = file.display().to_string();
    let diff = similar::TextDiff::from_lines(old, new);
    print!(
        "{}",
        diff.unified_diff().context_radius(3).header(&name, &name)
    );
}

#[cfg(test)]
mod tests {
    use super::edition;

    #[test]
    fn the_edition_is_the_packages_or_its_workspaces() {
        let root = std::env::temp_dir().join(format!("doxa-fmt-edition-{}", std::process::id()));
        let (own, inherited, bare) = (root.join("own"), root.join("inh"), root.join("bare"));
        for dir in [&own, &inherited, &bare] {
            std::fs::create_dir_all(dir.join("src")).unwrap();
        }
        let write = |p: &std::path::Path, s: &str| std::fs::write(p.join("Cargo.toml"), s).unwrap();
        write(&root, "[workspace.package]\nedition = \"2024\"\n");
        write(&own, "[package]\nname = \"a\"\nedition = \"2018\"\n");
        write(
            &inherited,
            "[package]\nname = \"b\"\nedition.workspace = true\n",
        );
        write(&bare, "[package]\nname = \"c\"\n");
        assert_eq!(edition(&own.join("src")), "2018");
        assert_eq!(edition(&inherited.join("src")), "2024");
        assert_eq!(edition(&bare), "2015");
        std::fs::remove_dir_all(&root).unwrap();
    }
}
