//! The served output: hashed names, `manifest.json`, `index.html`, precompressed
//! siblings, and the `embed.rs` table `dist!()` includes.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::{IoContext, Result};

/// The first 8 hex digits of the content's sha256.
pub fn hash8(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))[..8].to_owned()
}

/// `app.js` becomes `app-<hash8>.js`.
pub fn hashed_name(logical: &str, bytes: &[u8]) -> String {
    let hash = hash8(bytes);
    match logical.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => format!("{stem}-{hash}.{ext}"),
        _ => format!("{logical}-{hash}"),
    }
}

/// Everything the dist holds, before it is written.
#[derive(Debug, Clone, Default)]
pub struct Dist {
    /// Files by dist-relative path.
    pub files: BTreeMap<String, Vec<u8>>,
    /// Logical name to dist-relative path.
    pub manifest: BTreeMap<String, String>,
    /// The entry module.
    pub entry: String,
    /// Modules to preload: the entry and its static chunks.
    pub preload: Vec<String>,
    /// Stylesheets to link.
    pub stylesheets: Vec<String>,
    /// Client crate to base URL, the default `services.json`.
    pub services: BTreeMap<String, String>,
    /// The path served under, as [`normalize_base`] gives it; empty means `/`.
    pub base: String,
}

/// `docs` and `/docs` become `/docs/`; empty becomes `/`.
pub fn normalize_base(base: &str) -> String {
    let inner = base.trim_matches('/');
    if inner.is_empty() {
        "/".to_owned()
    } else {
        format!("/{inner}/")
    }
}

impl Dist {
    /// Add a file under its content-hashed name, recording it in the manifest.
    pub fn add_hashed(&mut self, logical: &str, bytes: Vec<u8>) -> String {
        let name = hashed_name(logical, &bytes);
        self.add(logical, &name, bytes);
        name
    }

    /// Add a file under `path` as given.
    pub fn add(&mut self, logical: &str, path: &str, bytes: Vec<u8>) {
        self.manifest.insert(logical.to_owned(), path.to_owned());
        self.files.insert(path.to_owned(), bytes);
    }

    /// The tags `index.html` needs.
    pub fn html_tags(&self) -> String {
        let base = attr(if self.base.is_empty() {
            "/"
        } else {
            &self.base
        });
        let mut tags = String::new();
        if base != "/" {
            tags.push_str(&format!("<meta name=\"doxa-base\" content=\"{base}\">\n"));
        }
        for m in &self.preload {
            tags.push_str(&format!(
                "<link rel=\"modulepreload\" href=\"{base}{}\">\n",
                attr(m)
            ));
        }
        for s in &self.stylesheets {
            tags.push_str(&format!(
                "<link rel=\"stylesheet\" href=\"{base}{}\" data-doxa-css>\n",
                attr(s)
            ));
        }
        tags.push_str(&format!(
            "<script type=\"module\" src=\"{base}{}\"></script>\n",
            attr(&self.entry)
        ));
        tags
    }

    /// `manifest.json`.
    pub fn manifest_json(&self) -> String {
        serde_json::to_string_pretty(&self.manifest).expect("json") + "\n"
    }
}

/// `tags` placed before `</head>`, else before `<body`, else at the start.
pub fn inject(html: &str, tags: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let at = lower
        .find("</head>")
        .or_else(|| lower.find("<body"))
        .unwrap_or(0);
    format!("{}{}{}", &html[..at], tags, &html[at..])
}

/// The `index.html` used when the web crate has none, with the `#app` that `doxa new` mounts on.
pub fn generated_html(title: &str, tags: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{}</title>\n{tags}</head>\n<body>\n<div id=\"app\"></div>\n</body>\n</html>\n",
        text(title)
    )
}

/// The Rust expression `dist!()` includes: every file, by dist-relative path.
pub fn embed_rs(dist_dir: &Path, files: &[String]) -> String {
    let mut rs = String::from("&[\n");
    for f in files {
        let abs = dist_dir.join(f);
        rs.push_str(&format!(
            "    ({:?}, include_bytes!({:?}) as &'static [u8]),\n",
            f,
            abs.to_string_lossy()
        ));
    }
    rs.push(']');
    rs
}

/// Whether a file gets `.br` and `.gz` siblings.
pub fn compressible(path: &str) -> bool {
    [".js", ".wasm", ".css", ".html"]
        .iter()
        .any(|e| path.ends_with(e))
}

/// Replace `dir` with `dist`, `index.html`, `manifest.json`, `services.json` and `embed.rs`.
/// `compress` adds the precompressed siblings.
pub fn write(dir: &Path, dist: &Dist, index_html: &str, compress: bool) -> Result<()> {
    if dir.exists() {
        std::fs::remove_dir_all(dir).at(dir)?;
    }
    let mut files = dist.files.clone();
    files.insert("index.html".into(), index_html.as_bytes().to_vec());
    files.insert("manifest.json".into(), dist.manifest_json().into_bytes());
    let services = serde_json::to_string_pretty(&dist.services).expect("json") + "\n";
    files.insert("services.json".into(), services.into_bytes());
    let mut written = Vec::new();
    for (rel, bytes) in &files {
        put(dir, rel, bytes)?;
        written.push(rel.clone());
        if compress && compressible(rel) {
            put(dir, &format!("{rel}.br"), &brotli(bytes))?;
            put(dir, &format!("{rel}.gz"), &gzip(bytes))?;
            written.push(format!("{rel}.br"));
            written.push(format!("{rel}.gz"));
        }
    }
    let dir = std::fs::canonicalize(dir).at(dir)?;
    put(&dir, "embed.rs", embed_rs(&dir, &written).as_bytes())
}

/// Copy the written dist at `dist_dir` to `out` as a static site: no `embed.rs` or compressed
/// siblings, and `index.html` again as `404.html` so a static host serves deep links.
pub fn export(dist_dir: &Path, out: &Path) -> Result<()> {
    if out.exists() {
        std::fs::remove_dir_all(out).at(out)?;
    }
    copy_static(dist_dir, dist_dir, out)?;
    let index = out.join("index.html");
    let not_found = out.join("404.html");
    std::fs::copy(&index, &not_found).at(&not_found)?;
    Ok(())
}

fn copy_static(root: &Path, dir: &Path, out: &Path) -> Result<()> {
    for entry in std::fs::read_dir(dir).at(dir)? {
        let path = entry.at(dir)?.path();
        let rel = path.strip_prefix(root).expect("under root");
        if path.is_dir() {
            copy_static(root, &path, out)?;
            continue;
        }
        let name = rel.to_string_lossy();
        let compressed = name.ends_with(".br") || name.ends_with(".gz");
        if name == "embed.rs" || (compressed && root.join(&name[..name.len() - 3]).is_file()) {
            continue;
        }
        put(out, &name, &std::fs::read(&path).at(&path)?)?;
    }
    Ok(())
}

fn put(dir: &Path, rel: &str, bytes: &[u8]) -> Result<()> {
    let path = dir.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).at(parent)?;
    }
    std::fs::write(&path, bytes).at(&path)
}

/// Brotli at maximum quality.
pub fn brotli(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let params = brotli::enc::BrotliEncoderParams {
        quality: 11,
        ..Default::default()
    };
    brotli::BrotliCompress(&mut &bytes[..], &mut out, &params).expect("in-memory brotli");
    out
}

/// Gzip at maximum level.
pub fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(bytes).expect("in-memory gzip");
    enc.finish().expect("in-memory gzip")
}

fn attr(s: &str) -> String {
    text(s).replace('"', "&quot;")
}

fn text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn names_carry_a_content_hash() {
        assert_eq!(hash8(b"abc"), "ba7816bf");
        assert_eq!(hashed_name("app.js", b"abc"), "app-ba7816bf.js");
        assert_eq!(hashed_name("app.css", b"abc"), "app-ba7816bf.css");
        assert_eq!(hashed_name("LICENSE", b"abc"), "LICENSE-ba7816bf");
        assert_ne!(hashed_name("app.js", b"abd"), hashed_name("app.js", b"abc"));
    }

    fn sample() -> Dist {
        let mut d = Dist::default();
        let js = d.add_hashed("app.js", b"js".to_vec());
        d.add(
            "chunks/chunk-AB12CD34.js",
            "chunks/chunk-AB12CD34.js",
            b"chunk".to_vec(),
        );
        let css = d.add_hashed("app.css", b"css".to_vec());
        d.entry = js.clone();
        d.preload = vec![js, "chunks/chunk-AB12CD34.js".into()];
        d.stylesheets = vec![css];
        d.services
            .insert("orders-client".into(), "https://orders.example.com".into());
        d
    }

    #[test]
    fn manifest_maps_logical_to_hashed() {
        let d = sample();
        let m: BTreeMap<String, String> = serde_json::from_str(&d.manifest_json()).unwrap();
        assert_eq!(m["app.js"], hashed_name("app.js", b"js"));
        assert_eq!(m["app.css"], hashed_name("app.css", b"css"));
        assert_eq!(m["chunks/chunk-AB12CD34.js"], "chunks/chunk-AB12CD34.js");
    }

    #[test]
    fn a_base_prefixes_every_tag_and_is_announced() {
        let d = Dist {
            base: normalize_base("docs"),
            ..sample()
        };
        let tags = d.html_tags();
        assert!(
            tags.starts_with("<meta name=\"doxa-base\" content=\"/docs/\">\n"),
            "{tags}"
        );
        assert_eq!(tags.matches("=\"/docs/").count(), 5, "{tags}");
        assert!(!sample().html_tags().contains("doxa-base"));
        assert_eq!(normalize_base(""), "/");
        assert_eq!(normalize_base("/a/b"), "/a/b/");
    }

    #[test]
    fn tags_preload_link_and_boot() {
        let d = sample();
        let js = hashed_name("app.js", b"js");
        let css = hashed_name("app.css", b"css");
        assert_eq!(
            d.html_tags(),
            format!(
                "<link rel=\"modulepreload\" href=\"/{js}\">\n\
                 <link rel=\"modulepreload\" href=\"/chunks/chunk-AB12CD34.js\">\n\
                 <link rel=\"stylesheet\" href=\"/{css}\" data-doxa-css>\n\
                 <script type=\"module\" src=\"/{js}\"></script>\n"
            )
        );
    }

    #[test]
    fn injection_goes_before_head_close() {
        assert_eq!(
            inject(
                "<html><HEAD><title>x</title></HEAD><body></body></html>",
                "<T>"
            ),
            "<html><HEAD><title>x</title><T></HEAD><body></body></html>"
        );
        assert_eq!(inject("<body>hi</body>", "<T>"), "<T><body>hi</body>");
        assert_eq!(inject("hi", "<T>"), "<T>hi");
        let html = generated_html("a<b", "<T>\n");
        assert!(
            html.contains("<title>a&lt;b</title>\n<T>\n</head>"),
            "{html}"
        );
        assert!(html.contains("<div id=\"app\"></div>"), "{html}");
    }

    #[test]
    fn written_dist_has_siblings_and_an_embed_table() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("dist");
        let d = sample();
        write(&out, &d, "<html></html>", true).unwrap();
        let js = hashed_name("app.js", b"js");
        let br = std::fs::read(out.join(format!("{js}.br"))).unwrap();
        let mut plain = Vec::new();
        brotli::BrotliDecompress(&mut &br[..], &mut plain).unwrap();
        assert_eq!(plain, b"js");
        let gz = std::fs::read(out.join("index.html.gz")).unwrap();
        let mut html = String::new();
        flate2::read::GzDecoder::new(&gz[..])
            .read_to_string(&mut html)
            .unwrap();
        assert_eq!(html, "<html></html>");
        assert!(!out.join("manifest.json.br").exists());
        assert_eq!(
            std::fs::read_to_string(out.join("services.json")).unwrap(),
            "{\n  \"orders-client\": \"https://orders.example.com\"\n}\n"
        );

        let embed = std::fs::read_to_string(out.join("embed.rs")).unwrap();
        assert!(embed.starts_with("&["), "{embed}");
        assert!(
            embed.contains(&format!("(\"{js}.gz\", include_bytes!(")),
            "{embed}"
        );
        assert!(
            embed.contains("(\"chunks/chunk-AB12CD34.js\", include_bytes!("),
            "{embed}"
        );
        assert!(!embed.contains("embed.rs"), "{embed}");
    }

    #[test]
    fn an_export_is_plain_files_with_a_404_page() {
        let dir = tempfile::tempdir().unwrap();
        let (dist, out) = (dir.path().join("dist"), dir.path().join("site"));
        write(&dist, &sample(), "<html></html>", true).unwrap();
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("stale.txt"), "x").unwrap();
        export(&dist, &out).unwrap();
        let js = hashed_name("app.js", b"js");
        assert!(out.join(&js).is_file());
        assert!(out.join("chunks/chunk-AB12CD34.js").is_file());
        assert_eq!(
            std::fs::read_to_string(out.join("404.html")).unwrap(),
            "<html></html>"
        );
        for gone in [
            format!("{js}.br"),
            "index.html.gz".into(),
            "embed.rs".into(),
            "stale.txt".into(),
        ] {
            assert!(!out.join(&gone).exists(), "{gone}");
        }
    }
}
