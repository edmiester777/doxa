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

use super::statics;

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
pub(super) fn jump_table(
    patch: &[u8],
    sites: &statics::Sites,
    cache: &Cache,
) -> Result<(Vec<u8>, JumpTable)> {
    let old_symbols = parse_data_symbols(&cache.old_bytes)?;
    let (patch, bound) = statics::rebind(patch, sites, |name, size| {
        let symbol = old_symbols
            .data_symbol_index
            .get(name)
            .and_then(|i| old_symbols.data_symbols.get(i))
            .filter(|symbol| symbol.size == size)?;
        data_address(cache, symbol).ok()
    })?;
    let mut new = Module::from_buffer(&patch)?;
    statics::install(&mut new, &bound)?;
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
        let address = data_address(cache, symbol)?;
        let ImportKind::Global(global) = import.kind else {
            bail!("a GOT.mem import is not a global");
        };
        new.imports.delete(mem);
        new.globals.get_mut(global).kind =
            walrus::GlobalKind::Local(ConstExpr::Value(walrus::ir::Value::I32(address)));
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

    redirect_casts(&mut new, table, |name| {
        cache.symbol_ifunc.get(name).copied()
    })?;

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
    export_global_relocs(&mut new);
    let bytes = new.emit_wasm();

    let new_ifuncs = collect_ifuncs(&new);
    let mut map = AddressMap::default();
    for (name, idx) in &new_ifuncs {
        // A redirected cast calls the base's slot, so jumping that slot here would loop.
        if is_cast(name) {
            continue;
        }
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

/// Where a data symbol of the base module lives in memory.
fn data_address(cache: &Cache, symbol: &DataSymbol) -> Result<i32> {
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
    Ok(offset + symbol.segment_offset as i32)
}

/// The loader adds the table and memory bases to the patch's GOT by calling this export, which
/// the linker doesn't write; without it, a pointer from the GOT is a slot of the base's table.
fn export_global_relocs(patch: &mut Module) {
    const GLOBAL_RELOCS: &str = "__wasm_apply_global_relocs";
    if patch.exports.iter().any(|e| e.name == GLOBAL_RELOCS) {
        return;
    }
    if let Some(func) = patch.funcs.by_name(GLOBAL_RELOCS) {
        patch.exports.add(GLOBAL_RELOCS, func);
    }
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

/// A `wbg_cast` monomorph. wasm-bindgen rewrites the base's to call a generated JS adapter, so
/// it stays callable, unlike the `breaks_if_inlined` descriptor inside it.
fn is_cast(name: &str) -> bool {
    name.contains("8wbg_cast") && !name.contains("breaks_if_inlined")
}

/// Patch code holds unrewritten copies of the casts, whose descriptors trap when run, so each
/// calls the base's instead. A cast new to the patch has no adapter without wasm-bindgen.
fn redirect_casts(
    new: &mut Module,
    table: TableId,
    slot_of: impl Fn(&str) -> Option<i32>,
) -> Result<()> {
    let casts: Vec<(FunctionId, String)> = new
        .funcs
        .iter()
        .filter(|f| matches!(f.kind, FunctionKind::Local(_)))
        .filter_map(|f| Some((f.id(), f.name.clone()?)))
        .filter(|(_, name)| is_cast(name))
        .collect();
    for (func, name) in casts {
        let slot = slot_of(&name).with_context(|| {
            format!("{name} casts a type new to this patch, which needs wasm-bindgen")
        })?;
        call_through_table(new, table, func, slot, name);
    }
    Ok(())
}

/// Symbols wasm-bindgen consumes itself, after its own heuristics, in legacy and v0 mangling.
fn is_bindgen_symbol(name: &str) -> bool {
    if is_cast(name) {
        return false;
    }
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
    size: u32,
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
                        size: def.size,
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
    use walrus::{ir, FunctionBuilder, FunctionId, FunctionKind, Module, TableId};

    use super::{export_global_relocs, is_bindgen_symbol, is_cast, redirect_casts};

    #[test]
    fn a_patch_exports_its_global_relocations_once() {
        let mut patch = Module::default();
        let mut builder = FunctionBuilder::new(&mut patch.types, &[], &[]);
        builder.name("__wasm_apply_global_relocs".to_owned());
        let relocs = builder.finish(Vec::new(), &mut patch.funcs);
        export_global_relocs(&mut patch);
        export_global_relocs(&mut patch);
        assert_eq!(patch.exports.iter().count(), 1);
        assert_eq!(
            patch
                .exports
                .get_func("__wasm_apply_global_relocs")
                .unwrap(),
            relocs,
        );
    }

    #[test]
    fn a_patch_without_global_relocations_exports_nothing() {
        let mut patch = Module::default();
        export_global_relocs(&mut patch);
        assert_eq!(patch.exports.iter().count(), 0);
    }

    #[test]
    fn bindgen_symbols_match_in_both_manglings() {
        for name in [
            "_RNvXsu_NtCsisWeVXeeysB_12wasm_bindgen8describeNtB7_7JsValueNtB5_12WasmDescribe8describe",
            "_RINvNvNtCsisWeVXeeysB_12wasm_bindgen4___rt8wbg_cast17breaks_if_inlinedReNtB4_7JsValueEB4_",
            "_ZN12wasm_bindgen8describe6inform17h0123456789abcdefE",
        ] {
            assert!(is_bindgen_symbol(name), "{name}");
        }
        assert!(!is_bindgen_symbol(
            "_RNvMs0_NtCsbeQQBaYUKJ5_7doxa_ui3appNtB5_3App5mount"
        ));
    }

    const CAST: &str = "_RINvNtCsisWeVXeeysB_12wasm_bindgen4___rt8wbg_castReNtB4_7JsValueEB4_";

    #[test]
    fn a_cast_stays_reachable_but_its_descriptor_doesnt() {
        for cast in [CAST, "_ZN12wasm_bindgen4__rt8wbg_cast17h0123456789abcdefE"] {
            assert!(is_cast(cast), "{cast}");
            assert!(!is_bindgen_symbol(cast), "{cast}");
        }
        let descriptor =
            "_RINvNvNtCsisWeVXeeysB_12wasm_bindgen4___rt8wbg_cast17breaks_if_inlinedReNtB4_7JsValueEB4_";
        assert!(!is_cast(descriptor));
    }

    fn patch_with(name: &str) -> (Module, TableId, FunctionId) {
        let mut patch = Module::default();
        let table = patch
            .tables
            .add_local(false, 8, None, walrus::RefType::Funcref);
        let mut builder = FunctionBuilder::new(&mut patch.types, &[], &[]);
        builder.name(name.to_owned()).func_body().unreachable();
        let func = builder.finish(Vec::new(), &mut patch.funcs);
        (patch, table, func)
    }

    fn calls_slot(patch: &Module, func: FunctionId) -> Option<i32> {
        let FunctionKind::Local(local) = &patch.funcs.get(func).kind else {
            return None;
        };
        let body = local.block(local.entry_block());
        let (
            ir::Instr::Const(ir::Const {
                value: ir::Value::I32(slot),
            }),
            _,
        ) = body.instrs.first()?
        else {
            return None;
        };
        matches!(body.instrs.last()?.0, ir::Instr::CallIndirect(_)).then_some(*slot)
    }

    #[test]
    fn a_patched_cast_calls_the_bases_slot() {
        let (mut patch, table, func) = patch_with(CAST);
        redirect_casts(&mut patch, table, |name| (name == CAST).then_some(5)).unwrap();
        assert_eq!(calls_slot(&patch, func), Some(5));
    }

    #[test]
    fn a_cast_the_base_lacks_refuses_the_patch() {
        let (mut patch, table, _) = patch_with(CAST);
        let error = redirect_casts(&mut patch, table, |_| None).unwrap_err();
        assert!(error.to_string().contains("needs wasm-bindgen"), "{error}");
    }

    #[test]
    fn other_patch_code_keeps_its_body() {
        let (mut patch, table, func) = patch_with("_RNvCs0_3app4draw");
        redirect_casts(&mut patch, table, |_| None).unwrap();
        assert_eq!(calls_slot(&patch, func), None);
    }
}
