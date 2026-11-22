//! `doxa build --desktop|--ios|--android` and `doxa native init`: the web crate as a native app.

pub mod init;
pub mod mobile;
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

/// Writes what Tauri reads from the crate dir: the overrides, `tauri.conf.json`, a mobile
/// target's project under `gen/`, the icons.
pub fn prepare(
    web: &WebCrate,
    cfg: &NativeConfig,
    target: Target,
    out: &Output,
) -> Result<NativeConfig, Error> {
    let dir = &web.dir;
    let overrides = Overrides::from_env();
    write_if_changed(
        &dir.join(native::OVERRIDES),
        &(serde_json::to_string_pretty(&overrides)? + "\n"),
    )?;
    let cfg = cfg.clone().with(&overrides);
    native::write_generated(
        &cfg,
        &Package {
            name: &web.name,
            version: &web.version,
        },
        dir,
    )?;
    if target != Target::Desktop && mobile::project(dir, &cfg, &web.name, target, out)? {
        // `tauri icon` fills the new project's icon sets too.
        let _ = std::fs::remove_file(dir.join(ICON_STAMP));
    }
    icons(dir, out)?;
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

/// Tauri's subcommand for `target`, before `build` or `dev`.
fn subcommand(target: Target) -> Option<&'static str> {
    match target {
        Target::Desktop => None,
        Target::Ios => Some("ios"),
        Target::Android => Some("android"),
    }
}

/// The Tauri `build` arguments for a web crate whose page is at `dist`. A mobile local-mode
/// build gets `dist` from [`mobile::cargo_config`] instead: Xcode and Gradle run cargo.
fn build_args(
    cfg: &NativeConfig,
    api: Option<&str>,
    dist: &Path,
    release: bool,
    target: Target,
    extra: &[String],
) -> Result<Vec<OsString>, Error> {
    let mut args: Vec<OsString> = subcommand(target).into_iter().map(Into::into).collect();
    args.push("build".into());
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
            if target == Target::Desktop {
                cargo.extend([
                    "--config".into(),
                    format!(
                        "env.DOXA_DIST={}",
                        toml_edit::value(dist.to_string_lossy().as_ref())
                            .to_string()
                            .trim()
                    )
                    .into(),
                ]);
            }
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
pub fn dev_args(url: &str, target: Target, extra: &[String]) -> Vec<OsString> {
    let config = serde_json::json!({ "build": { "devUrl": url } });
    subcommand(target)
        .into_iter()
        .chain(["dev", "--no-watch", "--features", "native", "--config"])
        .map(OsString::from)
        .chain([config.to_string().into()])
        .chain(extra.iter().map(Into::into))
        .collect()
}

/// `doxa build --<target>`: the page for `target`, then Tauri's bundle.
pub fn build(opts: BuildOptions, target: Target, extra: &[String]) -> Result<(), Error> {
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
    let cfg = config(&pipeline.web)?.with(&Overrides::from_env());
    remote_services(&mut pipeline.web.config, &cfg);
    let _ = pipeline.build()?;
    let dist = pipeline.dist_dir();
    out.note(format!(
        "building the native app with Tauri {} (https://tauri.app)",
        tauri::version()
    ));
    let cfg = prepare(&pipeline.web, &cfg, target, &out)?;
    if target != Target::Desktop {
        let local = (cfg.server == Server::Local).then_some(dist.as_path());
        mobile::cargo_config(&pipeline.web.dir, target, local)?;
    }
    let args = build_args(
        &cfg,
        pipeline.web.config.server.as_deref(),
        &dist,
        release,
        target,
        extra,
    )?;
    tauri::run(&pipeline.web.dir, &args, &env(target), &out)
}

/// The env every Tauri run for `target` gets.
pub fn env(target: Target) -> Vec<(&'static str, OsString)> {
    vec![(doxa_role::TARGET_ENV, target.as_str().into())]
}

/// For `server = "remote"`, the page reaches its server at `url`, unless `services` says
/// otherwise; the app's own origin serves only the page.
fn remote_services(web: &mut doxa_build::config::DoxaConfig, cfg: &NativeConfig) {
    if let (Server::Remote, Some(server), Some(url)) = (cfg.server, &web.server, &cfg.url) {
        web.services
            .entry(server.clone())
            .or_insert_with(|| url.trim_end_matches('/').to_owned());
    }
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
            Target::Desktop,
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
                "env.DOXA_DIST=\"/t/dist-desktop\"",
            ]
        );
        let quoted = build_args(
            &cfg("identifier = \"com.a.b\""),
            Some("shop-api"),
            Path::new("/home/o'brien/dist"),
            true,
            Target::Desktop,
            &[],
        )
        .unwrap();
        let value = strings(quoted).pop().unwrap();
        let parsed: toml::Table = value.parse().unwrap();
        assert_eq!(
            parsed["env"]["DOXA_DIST"].as_str(),
            Some("/home/o'brien/dist")
        );
        assert!(build_args(
            &cfg("identifier = \"com.a.b\""),
            None,
            Path::new("/d"),
            true,
            Target::Desktop,
            &[]
        )
        .unwrap_err()
        .to_string()
        .contains("server"));
    }

    #[test]
    fn mobile_local_leaves_the_page_to_the_dist_config() {
        let args = build_args(
            &cfg("identifier = \"com.a.b\""),
            Some("shop-api"),
            Path::new("/t/dist-ios"),
            false,
            Target::Ios,
            &["--target".into(), "aarch64-sim".into()],
        )
        .unwrap();
        assert_eq!(
            strings(args),
            [
                "ios",
                "build",
                "--debug",
                "--features",
                "native",
                "--features",
                "shop-api/embed",
                "--target",
                "aarch64-sim",
            ]
        );
    }

    #[test]
    fn dev_opens_the_dev_server_and_leaves_rebuilding_to_doxa() {
        assert_eq!(
            strings(dev_args("http://127.0.0.1:3000/", Target::Desktop, &[])),
            [
                "dev",
                "--no-watch",
                "--features",
                "native",
                "--config",
                r#"{"build":{"devUrl":"http://127.0.0.1:3000/"}}"#,
            ]
        );
        let ios = strings(dev_args(
            "http://127.0.0.1:3000/",
            Target::Ios,
            &["iPhone 17".into()],
        ));
        assert_eq!(&ios[..2], ["ios", "dev"]);
        assert_eq!(ios.last().map(String::as_str), Some("iPhone 17"));
    }

    #[test]
    fn remote_points_the_page_s_server_at_its_url_unless_services_says() {
        let remote =
            cfg("identifier = \"com.a.b\"\nserver = \"remote\"\nurl = \"https://api.a.b/\"");
        let mut web = doxa_build::config::DoxaConfig {
            server: Some("shop-api".into()),
            ..Default::default()
        };
        remote_services(&mut web, &remote);
        assert_eq!(web.services["shop-api"], "https://api.a.b");
        web.services
            .insert("shop-api".into(), "https://other.a.b".into());
        remote_services(&mut web, &remote);
        assert_eq!(web.services["shop-api"], "https://other.a.b");
        let mut local = doxa_build::config::DoxaConfig {
            server: Some("shop-api".into()),
            ..Default::default()
        };
        remote_services(&mut local, &cfg("identifier = \"com.a.b\""));
        assert!(local.services.is_empty());
    }

    #[test]
    fn remote_bundles_the_page_as_tauri_s_frontend() {
        let args = build_args(
            &cfg("identifier = \"com.a.b\"\nserver = \"remote\"\nurl = \"https://api.a.b\""),
            None,
            Path::new("/t/dist-desktop"),
            true,
            Target::Desktop,
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
