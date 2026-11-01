//! Managed binaries: downloaded once at a pinned version, verified, and cached
//! under `~/.cache/doxa`.

use std::io::Read;
use std::path::{Path, PathBuf};

use base64::Engine;
use sha2::{Digest, Sha256, Sha512};

use crate::error::{Error, IoContext, Result};

/// The esbuild release doxa bundles with.
pub const ESBUILD_VERSION: &str = "0.28.2";
/// The Tailwind standalone CLI release doxa runs.
pub const TAILWIND_VERSION: &str = "4.3.3";

const TAILWIND_SHA256: &[(&str, &str)] = &[
    (
        "tailwindcss-macos-arm64",
        "cdf646702987a743464dff4d9c60fd4480d1c1e73dd819a9a67f1078815dce9d",
    ),
    (
        "tailwindcss-macos-x64",
        "7922e0953f2110c05976e3bf58f14e643d90427575e766b7d433f5f80cbee7e1",
    ),
    (
        "tailwindcss-linux-arm64",
        "55fd0b241214eff3de1e8ee4f22796662f2d2e7a49bcfca7477cfd0bac398195",
    ),
    (
        "tailwindcss-linux-x64",
        "dc61b3ac6b8c9ca874c0cc4c57b2409791a64c5540404ca5f5367360babc313a",
    ),
    (
        "tailwindcss-windows-x64.exe",
        "e0e260ce048014e9268f6237ff18f8ccf02cef521cbd0ae04e82c2cdf7aa3955",
    ),
];

/// `~/.cache/doxa`.
pub fn cache_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or_else(|| Error::config("no home directory to cache tools in", "set HOME"))?;
    Ok(PathBuf::from(home).join(".cache").join("doxa"))
}

/// The `@esbuild/<platform>` package for a Rust `(os, arch)` pair.
pub fn esbuild_platform(os: &str, arch: &str) -> Option<String> {
    let os = match os {
        "macos" => "darwin",
        "windows" => "win32",
        "linux" | "freebsd" | "openbsd" | "netbsd" => os,
        _ => return None,
    };
    let arch = match arch {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" => "ia32",
        "arm" => "arm",
        _ => return None,
    };
    Some(format!("{os}-{arch}"))
}

/// The Tailwind release asset for a Rust `(os, arch)` pair.
pub fn tailwind_asset(os: &str, arch: &str) -> Option<String> {
    let os_name = match os {
        "macos" => "macos",
        "linux" => "linux",
        "windows" => "windows",
        _ => return None,
    };
    let arch = match arch {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        _ => return None,
    };
    let ext = if os == "windows" { ".exe" } else { "" };
    Some(format!("tailwindcss-{os_name}-{arch}{ext}"))
}

/// Check `bytes` against an npm `dist.integrity` string (`sha512-<base64>`).
pub fn verify_integrity(bytes: &[u8], integrity: &str) -> Result<(), String> {
    let digest = base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes));
    let mut saw_sha512 = false;
    for entry in integrity.split_whitespace() {
        if let Some(expected) = entry.strip_prefix("sha512-") {
            saw_sha512 = true;
            if expected == digest {
                return Ok(());
            }
        }
    }
    if saw_sha512 {
        Err(format!(
            "sha512 mismatch: expected {integrity}, got sha512-{digest}"
        ))
    } else {
        Err(format!("no sha512 in integrity `{integrity}`"))
    }
}

/// Check `bytes` against a hex sha256.
pub fn verify_sha256(bytes: &[u8], expected: &str) -> Result<(), String> {
    let actual = hex::encode(Sha256::digest(bytes));
    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(format!(
            "sha256 mismatch: expected {expected}, got {actual}"
        ))
    }
}

/// One file out of a gzipped tarball.
pub fn extract_file(tgz: &[u8], entry: &str) -> Result<Vec<u8>, String> {
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(tgz));
    for file in archive.entries().map_err(|e| e.to_string())? {
        let mut file = file.map_err(|e| e.to_string())?;
        let path = file.path().map_err(|e| e.to_string())?;
        if path == Path::new(entry) {
            let mut out = Vec::new();
            file.read_to_end(&mut out).map_err(|e| e.to_string())?;
            return Ok(out);
        }
    }
    Err(format!("`{entry}` not in the archive"))
}

/// The esbuild binary, downloading it on first use.
pub fn esbuild() -> Result<PathBuf> {
    let exe = if cfg!(windows) {
        "esbuild.exe"
    } else {
        "esbuild"
    };
    let path = cache_dir()?
        .join(format!("esbuild-{ESBUILD_VERSION}"))
        .join(exe);
    if path.is_file() {
        return Ok(path);
    }
    let platform =
        esbuild_platform(std::env::consts::OS, std::env::consts::ARCH).ok_or_else(|| {
            Error::config(
                format!(
                    "esbuild has no build for {}-{}",
                    std::env::consts::OS,
                    std::env::consts::ARCH
                ),
                "build on macOS, Linux, Windows, or a BSD",
            )
        })?;
    let meta_url = format!("https://registry.npmjs.org/@esbuild/{platform}/{ESBUILD_VERSION}");
    let what = format!("esbuild {ESBUILD_VERSION} ({platform})");
    let meta: serde_json::Value = serde_json::from_slice(&fetch(&what, &meta_url)?)
        .map_err(|e| download_error(&what, &meta_url, e))?;
    let integrity = meta["dist"]["integrity"]
        .as_str()
        .ok_or_else(|| download_error(&what, &meta_url, "no dist.integrity in package metadata"))?;
    let url = format!(
        "https://registry.npmjs.org/@esbuild/{platform}/-/{platform}-{ESBUILD_VERSION}.tgz"
    );
    let tgz = fetch(&what, &url)?;
    verify_integrity(&tgz, integrity).map_err(|e| download_error(&what, &url, e))?;
    let entry = if cfg!(windows) {
        "package/esbuild.exe"
    } else {
        "package/bin/esbuild"
    };
    let bin = extract_file(&tgz, entry).map_err(|e| download_error(&what, &url, e))?;
    install(&path, &bin)?;
    Ok(path)
}

/// The Tailwind standalone CLI, downloading it on first use.
pub fn tailwind() -> Result<PathBuf> {
    let (os, arch) = (std::env::consts::OS, std::env::consts::ARCH);
    let asset = tailwind_asset(os, arch).ok_or_else(|| {
        Error::config(
            format!("Tailwind publishes no standalone CLI for {os}-{arch}"),
            "remove @import \"tailwindcss\" from the stylesheet, or build on macOS, Linux, or Windows",
        )
    })?;
    let path = cache_dir()?
        .join(format!("tailwindcss-{TAILWIND_VERSION}"))
        .join(&asset);
    if path.is_file() {
        return Ok(path);
    }
    let url = format!(
        "https://github.com/tailwindlabs/tailwindcss/releases/download/v{TAILWIND_VERSION}/{asset}"
    );
    let what = format!("tailwindcss {TAILWIND_VERSION} ({asset})");
    let bin = fetch(&what, &url)?;
    match TAILWIND_SHA256.iter().find(|(name, _)| *name == asset) {
        Some((_, sha)) => verify_sha256(&bin, sha).map_err(|e| download_error(&what, &url, e))?,
        None => eprintln!("warning: no pinned checksum for {asset}; using it unverified"),
    }
    install(&path, &bin)?;
    Ok(path)
}

fn fetch(what: &str, url: &str) -> Result<Vec<u8>> {
    let client = reqwest::blocking::Client::builder()
        .user_agent(concat!("doxa-build/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| download_error(what, url, e))?;
    let resp = client
        .get(url)
        .send()
        .and_then(|r| r.error_for_status())
        .map_err(|e| download_error(what, url, e))?;
    Ok(resp
        .bytes()
        .map_err(|e| download_error(what, url, e))?
        .to_vec())
}

fn download_error(what: &str, url: &str, detail: impl std::fmt::Display) -> Error {
    Error::Download {
        what: what.to_owned(),
        url: url.to_owned(),
        detail: detail.to_string(),
        fix: "check the network connection and retry".into(),
    }
}

fn install(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().expect("cache path has a parent");
    std::fs::create_dir_all(dir).at(dir)?;
    // Written aside then renamed, so an interrupted download never looks installed.
    let tmp = path.with_extension("partial");
    std::fs::write(&tmp, bytes).at(&tmp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).at(&tmp)?;
    }
    std::fs::rename(&tmp, path).at(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_tarball() -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (path, body) in [
            ("package/package.json", &b"{}"[..]),
            ("package/bin/esbuild", b"#!bin"),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append_data(&mut header, path, body).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn integrity_accepts_the_right_tarball_only() {
        let tgz = fake_tarball();
        let good = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&tgz))
        );
        verify_integrity(&tgz, &good).unwrap();
        verify_integrity(&tgz, &format!("sha1-abc {good}")).unwrap();

        let mut tampered = tgz.clone();
        tampered[20] ^= 1;
        assert!(verify_integrity(&tampered, &good)
            .unwrap_err()
            .contains("mismatch"));
        assert!(verify_integrity(&tgz, "sha1-abc")
            .unwrap_err()
            .contains("no sha512"));
    }

    #[test]
    fn the_binary_comes_out_of_the_tarball() {
        let tgz = fake_tarball();
        assert_eq!(extract_file(&tgz, "package/bin/esbuild").unwrap(), b"#!bin");
        assert!(extract_file(&tgz, "package/esbuild.exe").is_err());
    }

    #[test]
    fn sha256_pins() {
        verify_sha256(
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        .unwrap();
        assert!(verify_sha256(
            b"abd",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        .is_err());
    }

    #[test]
    fn platform_names() {
        assert_eq!(
            esbuild_platform("macos", "aarch64").as_deref(),
            Some("darwin-arm64")
        );
        assert_eq!(
            esbuild_platform("windows", "x86_64").as_deref(),
            Some("win32-x64")
        );
        assert_eq!(
            esbuild_platform("linux", "x86_64").as_deref(),
            Some("linux-x64")
        );
        assert_eq!(esbuild_platform("plan9", "x86_64"), None);
        assert_eq!(
            tailwind_asset("macos", "aarch64").as_deref(),
            Some("tailwindcss-macos-arm64")
        );
        assert_eq!(
            tailwind_asset("windows", "x86_64").as_deref(),
            Some("tailwindcss-windows-x64.exe")
        );
        assert_eq!(tailwind_asset("freebsd", "x86_64"), None);
        for (os, arch) in [
            ("macos", "aarch64"),
            ("macos", "x86_64"),
            ("linux", "x86_64"),
            ("linux", "aarch64"),
            ("windows", "x86_64"),
        ] {
            let asset = tailwind_asset(os, arch).unwrap();
            assert!(TAILWIND_SHA256.iter().any(|(n, _)| *n == asset), "{asset}");
        }
    }
}
