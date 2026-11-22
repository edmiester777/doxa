//! `doxa build --desktop|--ios|--android` and `doxa native init`: the web crate as a native app.

pub mod init;
pub mod tauri;

use std::ffi::OsString;
use std::path::Path;

use doxa_build::config::WebCrate;
use doxa_build::native::{self, NativeConfig, Overrides, Package, Server};
use doxa_build::{BuildOptions, Output, Pipeline};
use doxa_role::Target;
use sha2::{Digest, Sha256};

type Error = Box<dyn std::error::Error>;

/// The web crate's `[package.metadata.doxa.native]`, or how to get one.
pub fn config(web: &WebCrate) -> Result<NativeConfig, Error> {
    web.config.native.clone().ok_or_else(|| {
        format!(
            "{} has no `[package.metadata.doxa.native]`; `doxa native init` adds one",
            web.name
        )
        .into()
    })
}

/// Writes what Tauri reads from the crate dir: the overrides, the icons, `tauri.conf.json`.
pub fn prepare(web: &WebCrate, cfg: &NativeConfig, out: &Output) -> Result<NativeConfig, Error> {
    let dir = &web.dir;
    let overrides = Overrides::from_env();
    write_if_changed(
        &dir.join(native::OVERRIDES),
        &(serde_json::to_string_pretty(&overrides)? + "\n"),
    )?;
    icons(dir, out)?;
    let cfg = cfg.clone().with(&overrides);
    native::write_generated(
        &cfg,
        &Package {
            name: &web.name,
            version: &web.version,
        },
        dir,
    )?;
    Ok(cfg)
}

const ICON: &str = "native/icon.png";
const ICON_STAMP: &str = "gen/doxa/icon.sha256";

/// The full icon set from `native/icon.png`, remade only when it changed.
fn icons(dir: &Path, out: &Output) -> Result<(), Error> {
    let src = dir.join(ICON);
    let bytes = std::fs::read(&src).map_err(|e| {
        format!(
            "reading {}: {e}; a native app needs a square icon of at least 1024px there",
            src.display()
        )
    })?;
    let hash = hex::encode(Sha256::digest(&bytes));
    let stamp = dir.join(ICON_STAMP);
    let fresh = std::fs::read_to_string(&stamp).is_ok_and(|s| s.trim() == hash)
        && dir.join("icons/icon.icns").is_file();
    if fresh {
        return Ok(());
    }
    out.note("making the app's icons from native/icon.png");
    tauri::run(dir, &["icon".into(), ICON.into()], &[], out)?;
    write_if_changed(&stamp, &hash)?;
    Ok(())
}

/// The Tauri `build` arguments for a web crate whose page is at `dist`.
fn build_args(
    cfg: &NativeConfig,
    api: Option<&str>,
    dist: &Path,
    release: bool,
    extra: &[String],
) -> Result<Vec<OsString>, Error> {
    let mut args: Vec<OsString> = vec!["build".into()];
    if !release {
        args.push("--debug".into());
    }
    args.extend(["--features".into(), "native".into()]);
    let mut cargo: Vec<OsString> = Vec::new();
    match cfg.server {
        Server::Local => {
            let api = api.ok_or(
                "`server = \"local\"` embeds the page in the api crate, which the web crate's \
                 `[package.metadata.doxa] server` names",
            )?;
            args.extend(["--features".into(), format!("{api}/embed").into()]);
            // Mobile IDE builds drop most of the environment, so this goes as cargo config.
            cargo.extend([
                "--config".into(),
                format!("env.DOXA_DIST='{}'", dist.display()).into(),
            ]);
        }
        Server::Remote => {
            let config = serde_json::json!({ "build": { "frontendDist": dist } });
            args.extend(["--config".into(), config.to_string().into()]);
        }
    }
    args.extend(extra.iter().map(Into::into));
    if !cargo.is_empty() {
        args.push("--".into());
        args.extend(cargo);
    }
    Ok(args)
}

/// The Tauri `dev` arguments: the shell opens `url`, which `doxa dev` serves and rebuilds.
pub fn dev_args(url: &str) -> Vec<OsString> {
    let config = serde_json::json!({ "build": { "devUrl": url } });
    ["dev", "--no-watch", "--features", "native", "--config"]
        .into_iter()
        .map(OsString::from)
        .chain([config.to_string().into()])
        .collect()
}

pub fn supported(target: Target) -> Result<(), Error> {
    match target {
        Target::Desktop => Ok(()),
        _ => Err(format!("`--{}` isn't supported yet", target.as_str()).into()),
    }
}

/// `doxa build --<target>`: the page for `target`, then Tauri's bundle.
pub fn build(opts: BuildOptions, target: Target, extra: &[String]) -> Result<(), Error> {
    supported(target)?;
    let (release, out) = (opts.release, opts.output.clone());
    let mut pipeline = Pipeline::new(
        &std::env::current_dir()?,
        BuildOptions {
            target: Some(target),
            ..opts
        },
    )?;
    crate::check::one_copy(
        &pipeline.web.name,
        Some(crate::check::TARGET),
        pipeline.cargo_config(),
    )?;
    let cfg = config(&pipeline.web)?;
    let _ = pipeline.build()?;
    let dist = pipeline.dist_dir();
    out.note(format!(
        "building the native app with Tauri {} (https://tauri.app)",
        tauri::version()
    ));
    let cfg = prepare(&pipeline.web, &cfg, &out)?;
    let args = build_args(
        &cfg,
        pipeline.web.config.server.as_deref(),
        &dist,
        release,
        extra,
    )?;
    tauri::run(
        &pipeline.web.dir,
        &args,
        &[(doxa_role::TARGET_ENV, target.as_str().into())],
        &out,
    )
}

fn write_if_changed(path: &Path, content: &str) -> std::io::Result<()> {
    if std::fs::read_to_string(path).is_ok_and(|c| c == content) {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(native: &str) -> NativeConfig {
        NativeConfig::from_manifest(&format!("[package.metadata.doxa.native]\n{native}"))
            .unwrap()
            .unwrap()
    }

    fn strings(args: Vec<OsString>) -> Vec<String> {
        args.into_iter().map(|a| a.into_string().unwrap()).collect()
    }

    #[test]
    fn local_embeds_the_page_in_the_api_and_passes_it_as_cargo_config() {
        let args = build_args(
            &cfg("identifier = \"com.a.b\""),
            Some("shop-api"),
            Path::new("/t/dist-desktop"),
            false,
            &["--verbose".into()],
        )
        .unwrap();
        assert_eq!(
            strings(args),
            [
                "build",
                "--debug",
                "--features",
                "native",
                "--features",
                "shop-api/embed",
                "--verbose",
                "--",
                "--config",
                "env.DOXA_DIST='/t/dist-desktop'",
            ]
        );
        assert!(build_args(
            &cfg("identifier = \"com.a.b\""),
            None,
            Path::new("/d"),
            true,
            &[]
        )
        .unwrap_err()
        .to_string()
        .contains("server"));
    }

    #[test]
    fn dev_opens_the_dev_server_and_leaves_rebuilding_to_doxa() {
        assert_eq!(
            strings(dev_args("http://127.0.0.1:3000/")),
            [
                "dev",
                "--no-watch",
                "--features",
                "native",
                "--config",
                r#"{"build":{"devUrl":"http://127.0.0.1:3000/"}}"#,
            ]
        );
    }

    #[test]
    fn remote_bundles_the_page_as_tauri_s_frontend() {
        let args = build_args(
            &cfg("identifier = \"com.a.b\"\nserver = \"remote\"\nurl = \"https://api.a.b\""),
            None,
            Path::new("/t/dist-desktop"),
            true,
            &[],
        )
        .unwrap();
        assert_eq!(
            strings(args),
            [
                "build",
                "--features",
                "native",
                "--config",
                r#"{"build":{"frontendDist":"/t/dist-desktop"}}"#,
            ]
        );
    }
}
