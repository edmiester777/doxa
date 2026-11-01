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
    let src = rustfmt(&input).unwrap_or(input);
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
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

fn rustfmt(input: &str) -> Option<String> {
    let mut child = Command::new("rustfmt")
        .args(["--edition", "2021", "--emit", "stdout"])
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
