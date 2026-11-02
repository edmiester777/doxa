//! Splitting the app wasm along `#[page(lazy)]` split points, with wasm-split.

use std::fmt::Write;

use crate::error::{Error, Result};

/// The export prefix wasm-split's macros give a split point.
const SPLIT_EXPORT: &[u8] = b"__wasm_split_00___";

/// Whether the linked wasm has any split points.
pub fn has_split_points(original: &[u8]) -> bool {
    original
        .windows(SPLIT_EXPORT.len())
        .any(|w| w == SPLIT_EXPORT)
}

/// `wasm` without the linker's relocation sections, and without its names unless `names`.
pub fn strip_link_sections(wasm: &[u8], names: bool) -> Vec<u8> {
    let Some(body) = wasm.get(8..).filter(|_| wasm.starts_with(b"\0asm")) else {
        return wasm.to_vec();
    };
    let mut out = wasm[..8].to_vec();
    let mut at = 0;
    while at < body.len() {
        let start = at;
        let id = body[at];
        let Some((size, len)) = leb128(&body[at + 1..]) else {
            return wasm.to_vec();
        };
        let payload = at + 1 + len;
        let end = payload + size;
        if end > body.len() {
            return wasm.to_vec();
        }
        at = end;
        if id == 0 {
            if let Some((n, l)) = leb128(&body[payload..end]) {
                let name = body.get(payload + l..payload + l + n).unwrap_or_default();
                let drop = name.starts_with(b"reloc.")
                    || name == b"linking"
                    || (!names && name == b"name");
                if drop {
                    continue;
                }
            }
        }
        out.extend_from_slice(&body[start..end]);
    }
    out
}

/// An unsigned LEB128 and how many bytes it took.
fn leb128(b: &[u8]) -> Option<(usize, usize)> {
    let mut value = 0usize;
    for (i, byte) in b.iter().enumerate().take(5) {
        value |= ((byte & 0x7f) as usize) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

/// A wasm module split off the main one.
#[derive(Debug, Clone)]
pub struct Part {
    /// The unhashed file name.
    pub file: String,
    /// What `__wasm_split.js` exports to load it.
    pub loader: String,
    /// The shared chunks it needs first, as indexes into the chunk parts.
    pub needs: Vec<usize>,
    /// Its bytes.
    pub bytes: Vec<u8>,
}

/// The main module and the parts split off it.
pub struct Split {
    /// What the page loads at start.
    pub main: Vec<u8>,
    /// Code shared by several split modules.
    pub chunks: Vec<Part>,
    /// One per split point.
    pub modules: Vec<Part>,
}

/// Split `bindgened` using the call graph of `original`, the wasm the linker wrote.
pub fn split(original: &[u8], bindgened: &[u8]) -> Result<Split> {
    let tool = |e: anyhow::Error| Error::Tool {
        tool: "wasm-split",
        command: "wasm-split".into(),
        detail: format!("{e:#}"),
        fix:
            "check the web crate links with `-C link-arg=--emit-relocs` and keeps its symbol names"
                .into(),
    };
    let out = wasm_split_cli::Splitter::new(original, bindgened)
        .and_then(|s| s.emit())
        .map_err(tool)?;
    let chunks = out
        .chunks
        .into_iter()
        .enumerate()
        .map(|(i, c)| Part {
            file: format!("chunk_{i}_{}.wasm", c.module_name),
            loader: format!("__wasm_split_load_chunk_{i}"),
            needs: Vec::new(),
            bytes: c.bytes,
        })
        .collect();
    let mut modules = Vec::new();
    for (i, m) in out.modules.into_iter().enumerate() {
        let (Some(hash), Some(name)) = (&m.hash_id, &m.component_name) else {
            return Err(tool(anyhow::anyhow!(
                "split module `{}` has no hash or name",
                m.module_name
            )));
        };
        let mut needs: Vec<usize> = m.relies_on_chunks.iter().copied().collect();
        needs.sort_unstable();
        modules.push(Part {
            file: format!("module_{i}_{}.wasm", m.module_name),
            loader: format!("__wasm_split_load_{}_{hash}_{name}", m.module_name),
            needs,
            bytes: m.bytes,
        });
    }
    Ok(Split {
        main: out.main.bytes,
        chunks,
        modules,
    })
}

/// `__wasm_split.js`: wasm-split's loader, with one export per part fetching its hashed file.
pub fn loader_js(split: &Split, hashed: impl Fn(&Part) -> String) -> String {
    let mut js = wasm_split_cli::MAKE_LOAD_JS.to_owned();
    for part in split.chunks.iter().chain(&split.modules) {
        let url = serde_json::to_string(&format!("./{}", hashed(part))).expect("json");
        let needs: Vec<_> = part
            .needs
            .iter()
            .map(|i| format!("__wasm_split_load_chunk_{i}"))
            .collect();
        writeln!(
            js,
            "export const {} = makeLoad(new URL({url}, import.meta.url).href, [{}], fusedImports);",
            part.loader,
            needs.join(", ")
        )
        .expect("string");
    }
    js
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_points_are_found_by_their_export_prefix() {
        assert!(has_split_points(
            b"\0asm...__wasm_split_00___page___00_export_ab_render..."
        ));
        assert!(!has_split_points(b"\0asm...__wasm_bindgen_start..."));
    }

    #[test]
    fn link_sections_are_dropped_and_names_kept_on_request() {
        let custom = |name: &str, payload: &[u8]| {
            let mut body = vec![name.len() as u8];
            body.extend_from_slice(name.as_bytes());
            body.extend_from_slice(payload);
            let mut s = vec![0, body.len() as u8];
            s.extend(body);
            s
        };
        let mut wasm = b"\0asm\x01\0\0\0".to_vec();
        let ty = [1u8, 1, 0];
        wasm.extend_from_slice(&ty);
        wasm.extend(custom("linking", &[2, 0]));
        wasm.extend(custom("reloc.CODE", &[3, 0, 0]));
        wasm.extend(custom("name", &[1]));
        let named = strip_link_sections(&wasm, true);
        let mut want = b"\0asm\x01\0\0\0".to_vec();
        want.extend_from_slice(&ty);
        assert_eq!(named, [want.clone(), custom("name", &[1])].concat());
        assert_eq!(strip_link_sections(&wasm, false), want);
    }

    #[test]
    fn the_loader_fetches_each_part_after_the_chunks_it_needs() {
        let part = |file: &str, loader: &str, needs: Vec<usize>| Part {
            file: file.into(),
            loader: loader.into(),
            needs,
            bytes: Vec::new(),
        };
        let split = Split {
            main: Vec::new(),
            chunks: vec![part("chunk_0_a.wasm", "__wasm_split_load_chunk_0", vec![])],
            modules: vec![part(
                "module_0_page.wasm",
                "__wasm_split_load_page_ab_render",
                vec![0],
            )],
        };
        let js = loader_js(&split, |p| p.file.replace(".wasm", "-0123.wasm"));
        assert!(js.contains("export function makeLoad"), "{js}");
        assert!(js.contains(
            "export const __wasm_split_load_page_ab_render = makeLoad(new URL(\"./module_0_page-0123.wasm\", import.meta.url).href, [__wasm_split_load_chunk_0], fusedImports);"
        ), "{js}");
    }
}
