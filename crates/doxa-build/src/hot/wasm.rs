//! The wasm half of dioxus-cli 0.7's patcher (MIT OR Apache-2.0): lift every function of
//! the fat module into its table, then resolve a `--pie` patch against that table.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, RwLock};

use anyhow::{anyhow, bail, Context, Result};
use subsecond_types::{AddressMap, JumpTable};
use walrus::{
    ConstExpr, DataKind, ElementItems, ElementKind, FunctionBuilder, FunctionId, FunctionKind,
    ImportKind, Module, ModuleConfig, TableId,
};
use wasmparser::{BinaryReader, Linking, LinkingSectionReader, Payload, SymbolInfo};

/// The bindgen'd fat module, parsed once per base build.
pub struct Cache {
    symbol_ifunc: HashMap<String, i32>,
    old: Module,
    old_bytes: Vec<u8>,
    old_exports: HashSet<String>,
    old_imports: HashSet<String>,
}

impl Cache {
    /// Parse the module wasm-bindgen wrote from the fat link.
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        let parsed = parse_with_ids(&bytes)?;
        if parsed.symbols.code_symbols.is_empty() {
            bail!("the fat wasm has no symbol table; it must be linked with --emit-relocs");
        }
        let ifuncs = collect_ifuncs(&parsed.module);
        let index_to_name: HashMap<usize, &str> = parsed
            .module
            .funcs
            .iter()
            .filter_map(|f| {
                let name = f.name.as_deref()?;
                Some((*parsed.symbols.code_symbols.get(name)?, name))
            })
            .collect();
        // Merged functions share an index; every name for it maps to the one table slot.
        let symbol_ifunc = parsed
            .symbols
            .code_symbols
            .iter()
            .filter_map(|(name, idx)| {
                let unified = index_to_name.get(idx)?;
                Some((name.to_string(), *ifuncs.get(unified)?))
            })
            .collect();
        let old_exports = parsed
            .module
            .exports
            .iter()
            .map(|e| e.name.clone())
            .collect();
        let old_imports = parsed
            .module
            .imports
            .iter()
            .map(|i| i.name.clone())
            .collect();
        let old = parsed.module;
        Ok(Cache {
            symbol_ifunc,
            old,
            old_bytes: bytes,
            old_exports,
            old_imports,
        })
    }
}

/// Satisfy the patch's GOT and `env` imports from the base module and return the table
/// mapping old table slots to the patch's; `patch` is rewritten in place.
pub fn jump_table(patch: &[u8], cache: &Cache) -> Result<(Vec<u8>, JumpTable)> {
    let old_symbols = parse_data_symbols(&cache.old_bytes)?;
    let mut new = Module::from_buffer(patch)?;
    let mut got_mems = vec![];
    let mut got_funcs = vec![];
    let mut wbg_funcs = vec![];
    let mut env_funcs = vec![];
    for import in new.imports.iter() {
        match import.module.as_str() {
            "GOT.func" => {
                let entry = *cache
                    .symbol_ifunc
                    .get(import.name.as_str())
                    .with_context(|| format!("no table slot for {}", import.name))?;
                got_funcs.push((import.id(), entry));
            }
            "GOT.mem" => got_mems.push(import.id()),
            "env" => env_funcs.push(import.id()),
            "__wbindgen_placeholder__" => wbg_funcs.push(import.id()),
            _ => {}
        }
    }

    for (import_id, slot) in got_funcs {
        let ImportKind::Global(id) = new.imports.get(import_id).kind else {
            bail!("a GOT.func import is not a global");
        };
        new.imports.delete(import_id);
        new.globals.get_mut(id).kind =
            walrus::GlobalKind::Local(ConstExpr::Value(walrus::ir::Value::I32(slot)));
    }

    for mem in got_mems {
        let import = new.imports.get(mem);
        let symbol = old_symbols
            .data_symbol_index
            .get(import.name.as_str())
            .and_then(|i| old_symbols.data_symbols.get(i))
            .with_context(|| format!("no data symbol {} in the base module", import.name))?;
        let data = cache
            .old
            .data
            .iter()
            .nth(symbol.segment)
            .context("a data segment missing from the base module")?;
        let offset = match data.kind {
            DataKind::Active {
                offset: ConstExpr::Value(walrus::ir::Value::I32(o)),
                ..
            } => o,
            DataKind::Active {
                offset: ConstExpr::Value(walrus::ir::Value::I64(o)),
                ..
            } => o as i32,
            _ => bail!("a passive data segment in the base module"),
        };
        let ImportKind::Global(global) = import.kind else {
            bail!("a GOT.mem import is not a global");
        };
        new.imports.delete(mem);
        new.globals.get_mut(global).kind = walrus::GlobalKind::Local(ConstExpr::Value(
            walrus::ir::Value::I32(offset + symbol.segment_offset as i32),
        ));
    }

    // The base can't export everything (wasm-bindgen caps exports), so the patch reaches
    // its functions through the table instead.
    let table = new
        .elements
        .iter()
        .find_map(|e| match e.kind {
            ElementKind::Active { table, .. } => Some(table),
            _ => None,
        })
        .context("the patch has no function table")?;
    for import_id in env_funcs {
        let import = new.imports.get(import_id);
        let ImportKind::Function(func) = import.kind else {
            continue;
        };
        let name = import.name.clone();
        if cache.old_exports.contains(&name) || cache.old_imports.contains(&name) {
            continue;
        }
        if let Some(slot) = cache.symbol_ifunc.get(&name) {
            new.imports.delete(import_id);
            call_through_table(&mut new, table, func, *slot, name.clone());
        }
        if is_bindgen_symbol(&name) {
            new.imports.delete(import_id);
            call_through_table(&mut new, table, func, 0, name);
        }
    }

    for import_id in wbg_funcs {
        let import = new.imports.get_mut(import_id);
        let ImportKind::Function(func) = import.kind else {
            continue;
        };
        import.module = "env".into();
        import.name = format!("__saved_wbg_{}", import.name);
        if is_bindgen_symbol(&import.name) {
            let name = import.name.clone();
            new.imports.delete(import_id);
            call_through_table(&mut new, table, func, 0, name);
        }
    }

    let customs: Vec<_> = new.customs.iter().map(|c| c.0).collect();
    for id in customs {
        if new
            .customs
            .get(id)
            .is_some_and(|c| c.name().contains("__wasm_bindgen"))
        {
            new.customs.delete(id);
        }
    }
    new.start = None;
    let bytes = new.emit_wasm();

    let new_ifuncs = collect_ifuncs(&new);
    let mut map = AddressMap::default();
    for (name, idx) in &new_ifuncs {
        if let Some(old) = cache.symbol_ifunc.get(*name) {
            map.insert(*old as u64, *idx as u64);
        }
    }
    Ok((
        bytes,
        JumpTable {
            lib: Default::default(),
            map,
            aslr_reference: 0,
            new_base_address: 0,
            ifunc_count: new_ifuncs.len() as u64,
        },
    ))
}

/// Before wasm-bindgen: put every local function in the table, and keep the wbg
/// intrinsics a patch imports alive as `__saved_wbg_*` exports.
pub fn prepare_base(bytes: &[u8]) -> Result<Vec<u8>> {
    let ParsedModule {
        mut module,
        ids,
        symbols,
    } = parse_with_ids(bytes)?;
    let in_table: HashSet<FunctionId> = {
        let ifuncs = collect_ifuncs(&module);
        module
            .funcs
            .iter()
            .filter(|f| f.name.as_deref().is_some_and(|n| ifuncs.contains_key(n)))
            .map(|f| f.id())
            .collect()
    };
    let imported: Vec<_> = module
        .imports
        .iter()
        .filter_map(|i| match i.kind {
            ImportKind::Function(id) => Some((id, i.id())),
            _ => None,
        })
        .collect();

    let mut exported = HashSet::new();
    let mut make_indirect = vec![];
    for (func, import_id) in imported {
        let name = module.imports.get(import_id).name.clone();
        let wbg = name.starts_with("__wbindgen") || name.starts_with("__wbg_");
        if !wbg || is_bindgen_symbol(&name) {
            continue;
        }
        let ty = module.types.get(module.funcs.get(func).ty());
        let (params, results) = (ty.params().to_vec(), ty.results().to_vec());
        let saved = format!("__saved_wbg_{name}");
        let mut builder = FunctionBuilder::new(&mut module.types, &params, &results);
        let mut body = builder.name(saved.clone()).func_body();
        let locals: Vec<_> = params.iter().map(|t| module.locals.add(*t)).collect();
        for l in &locals {
            body.local_get(*l);
        }
        body.call(func);
        let id = module.funcs.add_local(builder.local_func(locals));
        if exported.insert(saved.clone()) {
            module.exports.add(&saved, id);
        }
        make_indirect.push(id);
    }

    for (name, index) in &symbols.code_symbols {
        if is_bindgen_symbol(name) {
            continue;
        }
        let func = module.funcs.get(ids[*index]);
        let id = func.id();
        let local = matches!(func.kind, FunctionKind::Local(_));
        // wasm-bindgen deletes anything named `__wbindgen*`; the saved copy survives.
        if name.starts_with("__wbindgen") {
            let saved = format!("__saved_wbg_{name}");
            if exported.insert(saved.clone()) {
                module.exports.add(&saved, id);
            }
        }
        if local && !in_table.contains(&id) {
            make_indirect.push(id);
        }
    }

    let segment = module
        .elements
        .iter_mut()
        .last()
        .context("the fat wasm has no function table")?;
    let added = make_indirect.len() as u64;
    let ElementItems::Functions(items) = &mut segment.items else {
        bail!("the fat wasm's table segment holds expressions, not functions");
    };
    items.extend(make_indirect);
    if let ElementKind::Active { table, .. } = segment.kind {
        let table = module.tables.get_mut(table);
        table.initial += added;
        if let Some(max) = table.maximum {
            table.maximum = Some(max + added);
        }
    }
    Ok(module.emit_wasm())
}

/// After wasm-bindgen: trapping bodies for the describe intrinsics it leaves imported, which
/// only its own descriptor functions call, still in the table.
pub fn stub_placeholder_imports(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut module = Module::from_buffer(bytes)?;
    let left: Vec<_> = module
        .imports
        .iter()
        .filter(|i| i.module == "__wbindgen_placeholder__")
        .filter_map(|i| match i.kind {
            ImportKind::Function(f) => Some((i.id(), f)),
            _ => None,
        })
        .collect();
    for (import, func) in left {
        let ty = module.types.get(module.funcs.get(func).ty());
        let (params, results) = (ty.params().to_vec(), ty.results().to_vec());
        let locals: Vec<_> = params.iter().map(|t| module.locals.add(*t)).collect();
        let mut builder = FunctionBuilder::new(&mut module.types, &params, &results);
        builder.func_body().unreachable();
        module.imports.delete(import);
        module.funcs.get_mut(func).kind = FunctionKind::Local(builder.local_func(locals));
    }
    Ok(module.emit_wasm())
}

fn call_through_table(new: &mut Module, table: TableId, func: FunctionId, slot: i32, name: String) {
    use walrus::ir;
    let ty_id = new.funcs.get(func).ty();
    let ty = new.types.get(ty_id);
    let (params, results) = (ty.params().to_vec(), ty.results().to_vec());
    let locals: Vec<_> = params.iter().map(|t| new.locals.add(*t)).collect();
    let mut builder = FunctionBuilder::new(&mut new.types, &params, &results);
    let mut body = builder.name(name).func_body();
    for l in &locals {
        body.local_get(*l);
    }
    body.instr(ir::Instr::Const(ir::Const {
        value: ir::Value::I32(slot),
    }));
    body.instr(ir::Instr::CallIndirect(ir::CallIndirect {
        ty: ty_id,
        table,
    }));
    new.funcs.get_mut(func).kind = FunctionKind::Local(builder.local_func(locals));
}

/// Each named function in an active table segment, by its slot.
fn collect_ifuncs(m: &Module) -> HashMap<&str, i32> {
    let mut out = HashMap::new();
    for el in m.elements.iter() {
        let ElementKind::Active { offset, .. } = &el.kind else {
            continue;
        };
        let base = match offset {
            ConstExpr::Value(walrus::ir::Value::I32(o)) => *o,
            ConstExpr::Value(walrus::ir::Value::I64(o)) => *o as i32,
            ConstExpr::Global(_) => 0,
            _ => continue,
        };
        if let ElementItems::Functions(ids) = &el.items {
            for (i, id) in ids.iter().enumerate() {
                if let Some(name) = m.funcs.get(*id).name.as_deref() {
                    out.insert(name, base + i as i32);
                }
            }
        }
    }
    out
}

/// Symbols wasm-bindgen consumes itself, after its own heuristics, in legacy and v0 mangling.
fn is_bindgen_symbol(name: &str) -> bool {
    [
        "__wbindgen_describe",
        "__wbindgen_externref",
        "wasm_bindgen8describe6inform",
        "wasm_bindgen..describe..WasmDescribe",
        "12WasmDescribe8describe",
        "wasm_bindgen..closure..WasmClosure$GT$8describe",
        "11WasmClosure8describe",
        "wasm_bindgen7closure16Closure$LT$T$GT$4wrap8describe",
        "4wrap8describe",
        "wasm_bindgen4__rt8wbg_",
        "wasm_bindgen4___rt8wbg_",
    ]
    .iter()
    .any(|s| name.contains(s))
}

struct DataSymbol {
    segment: usize,
    segment_offset: usize,
}

struct Symbols<'a> {
    code_symbols: BTreeMap<&'a str, usize>,
    data_symbols: BTreeMap<usize, DataSymbol>,
    data_symbol_index: HashMap<&'a str, usize>,
}

/// The `linking` section's symbols, which walrus doesn't expose.
fn parse_data_symbols(bytes: &[u8]) -> Result<Symbols<'_>> {
    let mut segments = 0;
    let mut symbols = vec![];
    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        match payload? {
            Payload::DataSection(s) => segments = s.count() as usize,
            Payload::CustomSection(s) if s.name() == "linking" => {
                let data = BinaryReader::new(s.data(), 0, wasmparser::WasmFeatures::all());
                let reader = LinkingSectionReader::new(data)?;
                for sub in reader.subsections() {
                    if let Linking::SymbolTable(map) = sub? {
                        symbols = map.into_iter().collect::<Result<Vec<_>, _>>()?;
                    }
                }
            }
            _ => {}
        }
    }
    let mut out = Symbols {
        code_symbols: BTreeMap::new(),
        data_symbols: BTreeMap::new(),
        data_symbol_index: HashMap::new(),
    };
    for (index, symbol) in symbols.iter().enumerate() {
        match symbol {
            SymbolInfo::Func {
                name: Some(name),
                index: f,
                ..
            } => {
                out.code_symbols.insert(*name, *f as usize);
            }
            SymbolInfo::Data {
                symbol: Some(def),
                name,
                ..
            } => {
                if def.index as usize >= segments {
                    return Err(anyhow!("data symbol {name} names a missing segment"));
                }
                out.data_symbol_index.insert(*name, index);
                out.data_symbols.insert(
                    index,
                    DataSymbol {
                        segment: def.index as usize,
                        segment_offset: def.offset as usize,
                    },
                );
            }
            _ => {}
        }
    }
    Ok(out)
}

struct ParsedModule<'a> {
    module: Module,
    ids: Vec<FunctionId>,
    symbols: Symbols<'a>,
}

/// The module, and the walrus id of each function by its wasm index.
fn parse_with_ids(bytes: &[u8]) -> Result<ParsedModule<'_>> {
    let ids = Arc::new(RwLock::new(Vec::new()));
    let sink = ids.clone();
    let module = Module::from_buffer_with_config(
        bytes,
        ModuleConfig::new().on_parse(move |_, index| {
            let mut ids = sink.write().expect("one writer");
            let mut i = 0;
            while let Ok(id) = index.get_func(i) {
                ids.push(id);
                i += 1;
            }
            Ok(())
        }),
    )?;
    let ids = std::mem::take(&mut *ids.write().expect("one writer"));
    Ok(ParsedModule {
        module,
        ids,
        symbols: parse_data_symbols(bytes)?,
    })
}

#[cfg(test)]
mod tests {
    use super::is_bindgen_symbol;

    #[test]
    fn bindgen_symbols_match_in_both_manglings() {
        for name in [
            "_RNvXsu_NtCsisWeVXeeysB_12wasm_bindgen8describeNtB7_7JsValueNtB5_12WasmDescribe8describe",
            "_RINvNtCsisWeVXeeysB_12wasm_bindgen4___rt8wbg_castReNtB4_7JsValueEB4_",
            "_ZN12wasm_bindgen8describe6inform17h0123456789abcdefE",
            "_ZN12wasm_bindgen4__rt8wbg_cast17h0123456789abcdefE",
        ] {
            assert!(is_bindgen_symbol(name), "{name}");
        }
        assert!(!is_bindgen_symbol(
            "_RNvMs0_NtCsbeQQBaYUKJ5_7doxa_ui3appNtB5_3App5mount"
        ));
    }
}
