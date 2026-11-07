//! Point a patch's code at the base module's statics, so it shares the running page's state.
//! Its own copies stay in its data, unreferenced. Pointers to them in that data aren't rebound.

use std::collections::{BTreeMap, HashMap};
use std::ops::Range;

use anyhow::{bail, Context, Result};
use walrus::ir::BinaryOp;
use walrus::{ExportItem, FunctionBuilder, ImportKind, Module};
use wasmparser::{
    BinaryReader, Linking, LinkingSectionReader, Name, NameSectionReader, RelocSectionReader,
    RelocationType, SectionLimited, SymbolInfo, TypeRef,
};

const CUSTOM: u8 = 0;
const IMPORT: u8 = 2;
const GLOBAL: u8 = 6;
const CODE: u8 = 10;
const GLOBAL_GET: u8 = 0x23;
const I32_CONST: u8 = 0x41;
const DATA_RELOCS: &str = "__wasm_apply_data_relocs";

/// A global appended to the patch, holding the address of a static in the base.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct Bound {
    pub address: i32,
    /// Code adds this global to `__memory_base`, rather than using it directly.
    pub relative: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Site {
    symbol: String,
    addend: i32,
    relative: bool,
}

/// Every place the compiled objects address a named static, read before linking: `rust-lld` can't
/// emit relocations for a `--pie` module.
#[derive(Debug, Default)]
pub(super) struct Sites {
    /// By function name, then immediate's offset in the function's body.
    by_function: BTreeMap<String, BTreeMap<usize, Site>>,
    sizes: HashMap<String, u32>,
}

struct Section {
    id: u8,
    whole: Range<usize>,
    payload: Range<usize>,
}

fn read_u32(bytes: &[u8], at: &mut usize) -> Result<u32> {
    let mut value = 0_u32;
    for shift in (0..35).step_by(7) {
        let byte = *bytes.get(*at).context("a truncated integer in a module")?;
        *at += 1;
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("an overlong integer in a module")
}

fn write_u32(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn sections(module: &[u8]) -> Result<Vec<Section>> {
    let mut found = vec![];
    let mut at = 8;
    while at < module.len() {
        let start = at;
        let id = module[at];
        at += 1;
        let size = read_u32(module, &mut at)? as usize;
        let payload = at..at + size;
        if payload.end > module.len() {
            bail!("a section runs past the end of a module");
        }
        at = payload.end;
        found.push(Section {
            id,
            whole: start..at,
            payload,
        });
    }
    Ok(found)
}

/// A custom section's name and contents.
fn custom<'a>(module: &'a [u8], section: &Section) -> Result<(&'a str, &'a [u8])> {
    let mut at = section.payload.start;
    let len = read_u32(module, &mut at)? as usize;
    let name = std::str::from_utf8(&module[at..at + len])?;
    Ok((name, &module[at + len..section.payload.end]))
}

fn reader(bytes: &[u8]) -> BinaryReader<'_> {
    BinaryReader::new(bytes, 0, wasmparser::WasmFeatures::all())
}

/// How many functions and globals `module` imports.
fn imports(module: &[u8], all: &[Section]) -> Result<(u32, u32)> {
    let (mut functions, mut globals) = (0, 0);
    for section in all.iter().filter(|s| s.id == IMPORT) {
        let bytes = &module[section.payload.clone()];
        for import in SectionLimited::<wasmparser::Import>::new(reader(bytes))? {
            match import?.ty {
                TypeRef::Func(_) => functions += 1,
                TypeRef::Global(_) => globals += 1,
                _ => {}
            }
        }
    }
    Ok((functions, globals))
}

/// Each function body's range, after its size prefix, relative to the code section's payload.
fn bodies(module: &[u8], code: &Section) -> Result<Vec<Range<usize>>> {
    let payload = &module[code.payload.clone()];
    let mut at = 0;
    let count = read_u32(payload, &mut at)?;
    let mut found = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let size = read_u32(payload, &mut at)? as usize;
        found.push(at..at + size);
        at += size;
    }
    Ok(found)
}

/// Whether `name` is a Rust static. Anonymous data is named by a counter, not by what it holds.
fn is_named_static(name: &str) -> bool {
    name.starts_with("_ZN") || name.starts_with("_R")
}

impl Sites {
    /// Take in one relocatable object. Same-named functions are one function once linked.
    pub(super) fn read(&mut self, object: &[u8]) -> Result<()> {
        let all = sections(object)?;
        let Some(code) = all.iter().position(|s| s.id == CODE) else {
            return Ok(());
        };
        let mut symbols = vec![];
        for section in all.iter().filter(|s| s.id == CUSTOM) {
            let (name, body) = custom(object, section)?;
            if name == "linking" {
                for sub in LinkingSectionReader::new(reader(body))?.subsections() {
                    if let Linking::SymbolTable(map) = sub? {
                        symbols = map.into_iter().collect::<Result<Vec<_>, _>>()?;
                    }
                }
            }
        }
        for symbol in &symbols {
            if let SymbolInfo::Data {
                name,
                symbol: Some(def),
                ..
            } = symbol
            {
                if is_named_static(name) {
                    self.sizes.insert((*name).to_owned(), def.size);
                }
            }
        }
        let (imported, _) = imports(object, &all)?;
        let bodies = bodies(object, &all[code])?;
        let mut functions = HashMap::new();
        for symbol in &symbols {
            if let SymbolInfo::Func {
                name: Some(name),
                index,
                ..
            } = symbol
            {
                if *index >= imported {
                    functions.insert((*index - imported) as usize, *name);
                }
            }
        }
        for section in all.iter().filter(|s| s.id == CUSTOM) {
            let (name, body) = custom(object, section)?;
            if !name.starts_with("reloc.") {
                continue;
            }
            let relocs = RelocSectionReader::new(reader(body))?;
            if relocs.section_index() as usize != code {
                continue;
            }
            for entry in relocs.entries() {
                let entry = entry?;
                let relative = match entry.ty {
                    RelocationType::MemoryAddrRelSleb => true,
                    RelocationType::GlobalIndexLeb => false,
                    _ => continue,
                };
                let Some(SymbolInfo::Data { name: symbol, .. }) = symbols.get(entry.index as usize)
                else {
                    continue;
                };
                if !is_named_static(symbol) {
                    continue;
                }
                let offset = entry.offset as usize;
                let index = bodies.partition_point(|b| b.end <= offset);
                let body = bodies.get(index).context("a relocation outside any body")?;
                let Some(function) = functions.get(&index) else {
                    continue;
                };
                self.by_function
                    .entry((*function).to_owned())
                    .or_default()
                    .insert(
                        offset - body.start,
                        Site {
                            symbol: (*symbol).to_owned(),
                            addend: entry.addend as i32,
                            relative,
                        },
                    );
            }
        }
        Ok(())
    }
}

/// Redirect `patch`'s code at `sites` to new globals, wherever `base(name, size)` knows the static
/// at that size. [`install`] then sets the globals.
pub(super) fn rebind(
    patch: &[u8],
    sites: &Sites,
    base: impl Fn(&str, u32) -> Option<i32>,
) -> Result<(Vec<u8>, Vec<Bound>)> {
    let all = sections(patch)?;
    let mut module = patch.to_vec();
    let mut bound: Vec<Bound> = vec![];
    let Some(code) = all.iter().find(|s| s.id == CODE) else {
        return Ok((module, bound));
    };
    let bodies = bodies(patch, code)?;
    let (imported_functions, imported_globals) = imports(patch, &all)?;
    let first_new = imported_globals + local_globals(patch, &all)?;
    let mut indices = HashMap::new();
    for section in all.iter().filter(|s| s.id == CUSTOM) {
        let (name, body) = custom(patch, section)?;
        if name != "name" {
            continue;
        }
        for sub in NameSectionReader::new(reader(body)) {
            let Name::Function(names) = sub? else {
                continue;
            };
            for naming in names {
                let naming = naming?;
                let Some(found) = sites.by_function.get(naming.name) else {
                    continue;
                };
                let Some(function) = naming
                    .index
                    .checked_sub(imported_functions)
                    .and_then(|i| bodies.get(i as usize))
                else {
                    continue;
                };
                for (offset, site) in found {
                    let Some(size) = sites.sizes.get(&site.symbol) else {
                        continue;
                    };
                    let Some(address) = base(&site.symbol, *size) else {
                        continue;
                    };
                    let immediate = code.payload.start + function.start + offset;
                    let opcode = if site.relative { I32_CONST } else { GLOBAL_GET };
                    if module.get(immediate - 1) != Some(&opcode) {
                        bail!("{} at {offset} of {} moved", site.symbol, naming.name);
                    }
                    let key = Bound {
                        address: address.wrapping_add(site.addend),
                        relative: site.relative,
                    };
                    let index = *indices.entry(key).or_insert_with(|| {
                        bound.push(key);
                        first_new + bound.len() as u32 - 1
                    });
                    module[immediate - 1] = GLOBAL_GET;
                    module[immediate..immediate + 5].copy_from_slice(&padded(index));
                }
            }
        }
    }
    Ok((append_globals(&module, &all, bound.len() as u32)?, bound))
}

fn local_globals(module: &[u8], all: &[Section]) -> Result<u32> {
    match all.iter().find(|s| s.id == GLOBAL) {
        Some(section) => read_u32(module, &mut section.payload.start.clone()),
        None => Ok(0),
    }
}

fn padded(mut value: u32) -> [u8; 5] {
    let mut out = [0; 5];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = (value & 0x7f) as u8 | if i < 4 { 0x80 } else { 0 };
        value >>= 7;
    }
    out
}

/// `module` with `added` zeroed mutable i32 globals after its own.
fn append_globals(module: &[u8], all: &[Section], added: u32) -> Result<Vec<u8>> {
    if added == 0 {
        return Ok(module.to_vec());
    }
    let global_section = |existing: u32, entries: &[u8]| {
        let mut payload = Vec::new();
        write_u32(&mut payload, existing + added);
        payload.extend(entries);
        for _ in 0..added {
            payload.extend([0x7f, 0x01, I32_CONST, 0x00, 0x0b]);
        }
        let mut out = vec![GLOBAL];
        write_u32(&mut out, payload.len() as u32);
        out.extend(payload);
        out
    };
    let mut out = module[..8].to_vec();
    let mut pending = !all.iter().any(|s| s.id == GLOBAL);
    for section in all {
        if pending && section.id != CUSTOM && section.id > GLOBAL {
            out.extend(global_section(0, &[]));
            pending = false;
        }
        if section.id == GLOBAL {
            let mut at = section.payload.start;
            let existing = read_u32(module, &mut at)?;
            out.extend(global_section(existing, &module[at..section.payload.end]));
        } else {
            out.extend(&module[section.whole.clone()]);
        }
    }
    if pending {
        out.extend(global_section(0, &[]));
    }
    Ok(out)
}

/// Set the appended globals before the patch's constructors run: the loader calls data
/// relocations first.
pub(super) fn install(patch: &mut Module, bound: &[Bound]) -> Result<()> {
    if bound.is_empty() {
        return Ok(());
    }
    let globals: Vec<_> = patch.globals.iter().map(|g| g.id()).collect();
    let appended = &globals[globals.len() - bound.len()..];
    let memory_base = patch.imports.iter().find_map(|i| match i.kind {
        ImportKind::Global(id) if i.name == "__memory_base" => Some(id),
        _ => None,
    });
    let existing = patch.exports.iter().find_map(|e| match e.item {
        ExportItem::Function(f) if e.name == DATA_RELOCS => Some((e.id(), f)),
        _ => None,
    });
    let mut builder = FunctionBuilder::new(&mut patch.types, &[], &[]);
    builder.name("__doxa_bind_statics".to_owned());
    let mut body = builder.func_body();
    for (bound, global) in bound.iter().zip(appended) {
        body.i32_const(bound.address);
        if bound.relative {
            let base = memory_base.context("the patch doesn't import __memory_base")?;
            body.global_get(base).binop(BinaryOp::I32Sub);
        }
        body.global_set(*global);
    }
    if let Some((_, relocs)) = existing {
        body.call(relocs);
    }
    let bind = builder.finish(Vec::new(), &mut patch.funcs);
    match existing {
        Some((export, _)) => patch.exports.get_mut(export).item = ExportItem::Function(bind),
        None => {
            patch.exports.add(DATA_RELOCS, bind);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATIC: &str = "_ZN3web5CHATS17h0123456789abcdefE";
    const READER: &str = "_ZN3web4read17h0123456789abcdefE";
    const SIZE: u8 = 8;
    /// The `i32.const` immediate's offset in the body: locals, `global.get`, the opcode.
    const IN_BODY: usize = 1 + 6 + 1;

    fn section(id: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![id];
        write_u32(&mut out, payload.len() as u32);
        out.extend(payload);
        out
    }

    fn named(name: &str, body: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        write_u32(&mut payload, name.len() as u32);
        payload.extend(name.as_bytes());
        payload.extend(body);
        section(CUSTOM, &payload)
    }

    fn string(out: &mut Vec<u8>, text: &str) {
        write_u32(out, text.len() as u32);
        out.extend(text.as_bytes());
    }

    /// `__memory_base + S@MBREL`, dropped.
    fn reading_body() -> Vec<u8> {
        let mut body = vec![0, GLOBAL_GET];
        body.extend(padded(0));
        body.push(I32_CONST);
        body.extend(padded(16));
        body.extend([0x6a, 0x1a, 0x0b]);
        body
    }

    /// A module with `before` empty functions ahead of the one reading a static.
    fn module(before: u8) -> Vec<u8> {
        let mut out = b"\0asm\x01\0\0\0".to_vec();
        out.extend(section(1, &[1, 0x60, 0, 0]));
        let mut imports = vec![2];
        imports.extend(b"\x03env\x0d__memory_base\x03\x7f\x00");
        imports.extend(b"\x03env\x06memory\x02\x00\x01");
        out.extend(section(IMPORT, &imports));
        let mut functions = vec![before + 1];
        functions.extend(std::iter::repeat_n(0, before as usize + 1));
        out.extend(section(3, &functions));
        let mut code = vec![before + 1];
        for _ in 0..before {
            code.extend([2, 0, 0x0b]);
        }
        let body = reading_body();
        code.push(body.len() as u8);
        code.extend(body);
        out.extend(section(CODE, &code));
        out.extend(section(11, &[1, 0, I32_CONST, 0, 0x0b, 1, 0xaa]));
        out
    }

    /// An object whose only function reads the data symbol `name`.
    fn object(name: &str, addend: u8) -> Vec<u8> {
        let mut out = module(0);
        let mut symbols = vec![2, 0, 0, 0];
        string(&mut symbols, READER);
        symbols.extend([1, 0]);
        string(&mut symbols, name);
        symbols.extend([0, 0, SIZE]);
        let mut linking = vec![2, 8];
        write_u32(&mut linking, symbols.len() as u32);
        linking.extend(symbols);
        out.extend(named("linking", &linking));
        // Section 3 is the code; its payload opens with the count and the body's size.
        let reloc = [
            3,
            1,
            RelocationType::MemoryAddrRelSleb as u8,
            (2 + IN_BODY) as u8,
            1,
            addend,
        ];
        out.extend(named("reloc.CODE", &reloc));
        out
    }

    /// A linked patch where the reader, called `READER`, is function `before`.
    fn patch(before: u8) -> Vec<u8> {
        let mut out = module(before);
        let mut names = vec![1];
        names.push(before);
        string(&mut names, READER);
        let mut payload = vec![1];
        write_u32(&mut payload, names.len() as u32);
        payload.extend(names);
        out.extend(named("name", &payload));
        out
    }

    fn sites(name: &str, addend: u8) -> Sites {
        let mut sites = Sites::default();
        sites.read(&object(name, addend)).unwrap();
        sites
    }

    /// The bytes at the reader's immediate, with its opcode, in a patch of `before` empty functions.
    fn site_of(bytes: &[u8], before: usize) -> Vec<u8> {
        let all = sections(bytes).unwrap();
        let code = all.iter().find(|s| s.id == CODE).unwrap();
        let body = bodies(bytes, code).unwrap()[before].clone();
        let start = code.payload.start + body.start + IN_BODY;
        bytes[start - 1..start + 5].to_vec()
    }

    #[test]
    fn code_addressing_a_static_reads_a_global_of_the_base_address() {
        let sites = sites(STATIC, 4);
        let (bytes, bound) = rebind(&patch(2), &sites, |name, size| {
            (name == STATIC && size == u32::from(SIZE)).then_some(1000)
        })
        .unwrap();
        assert_eq!(
            bound,
            [Bound {
                address: 1004,
                relative: true
            }]
        );
        // The one imported global is index 0, so the appended global is 1.
        let mut expected = vec![GLOBAL_GET];
        expected.extend(padded(1));
        assert_eq!(site_of(&bytes, 2), expected);

        let mut module = Module::from_buffer(&bytes).unwrap();
        install(&mut module, &bound).unwrap();
        assert!(module.exports.get_func(DATA_RELOCS).is_ok());
        wasmparser::Validator::new()
            .validate_all(&module.emit_wasm())
            .unwrap();
    }

    #[test]
    fn an_existing_data_relocation_export_still_runs() {
        let (bytes, bound) = rebind(&patch(0), &sites(STATIC, 0), |_, _| Some(1000)).unwrap();
        let mut module = Module::from_buffer(&bytes).unwrap();
        let mut builder = FunctionBuilder::new(&mut module.types, &[], &[]);
        builder.func_body();
        let relocs = builder.finish(Vec::new(), &mut module.funcs);
        module.exports.add(DATA_RELOCS, relocs);
        install(&mut module, &bound).unwrap();
        assert_ne!(module.exports.get_func(DATA_RELOCS).unwrap(), relocs);
        wasmparser::Validator::new()
            .validate_all(&module.emit_wasm())
            .unwrap();
    }

    #[test]
    fn a_static_the_base_lacks_stays_the_patchs_own() {
        let original = patch(0);
        let (bytes, bound) = rebind(&original, &sites(STATIC, 0), |_, _| None).unwrap();
        assert!(bound.is_empty());
        assert_eq!(bytes, original);
    }

    #[test]
    fn anonymous_data_stays_the_patchs_own() {
        let original = patch(0);
        let (bytes, bound) =
            rebind(&original, &sites("anon.0123.7", 0), |_, _| Some(1000)).unwrap();
        assert!(bound.is_empty());
        assert_eq!(bytes, original);
    }

    #[test]
    fn a_site_off_its_instruction_is_refused() {
        let mut moved = patch(0);
        let all = sections(&moved).unwrap();
        let code = all.iter().find(|s| s.id == CODE).unwrap();
        let body = bodies(&moved, code).unwrap()[0].clone();
        moved[code.payload.start + body.start + IN_BODY - 1] = 0x01;
        assert!(rebind(&moved, &sites(STATIC, 0), |_, _| Some(1000)).is_err());
    }

    #[test]
    fn padding_keeps_the_immediate_five_bytes_and_its_value() {
        let bytes = padded(300);
        let mut at = 0;
        assert_eq!(read_u32(&bytes, &mut at).unwrap(), 300);
        assert_eq!(at, 5);
    }
}
