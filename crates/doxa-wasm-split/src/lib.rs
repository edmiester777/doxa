//! wasm-split-cli 0.7.0 from Dioxus, keeping what its main module loses: callees of table entries
//! nothing reaches, targets of aliased symbols, and bytes of constants merged with a split's.
//! Split modules are re-encoded from the bytes, not re-parsed, so memory stays one module's.
//! Drop this crate once upstream does the same.

use anyhow::{Context, Result};
use itertools::Itertools;
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    hash::Hash,
    ops::Range,
    sync::{Arc, RwLock},
};
use walrus::{
    ir::{self, dfs_in_order, Visitor},
    ConstExpr, ElementItems, ElementKind, ExportId, ExportItem, FunctionBuilder, FunctionId,
    FunctionKind, ImportId, ImportKind, Module, ModuleConfig, RefType, TableId, TypeId,
};
use wasmparser::{
    BinaryReader, Linking, LinkingSectionReader, Payload, RelocSectionReader, RelocationEntry,
    SymbolInfo,
};

mod emit;

pub const MAKE_LOAD_JS: &str = include_str!("./__wasm_split.js");

/// A parsed wasm module with additional metadata and functionality for splitting and patching.
///
/// This struct assumes that relocations will be present in incoming wasm binary.
/// Upon construction, all the required metadata will be constructed.
pub struct Splitter<'a> {
    /// The original module we use as a reference
    source_module: Module,

    // The byte sources of the pre and post wasm-bindgen .wasm files
    // We need the original around since wasm-bindgen ruins the relocation locations.
    original: &'a [u8],
    bindgened: &'a [u8],

    // Mapping of indices of source functions
    // This lets us use a much faster approach to emitting split modules simply by maintaining a mapping
    // between the original Module and the new Module. Ideally we could just index the new module
    // with old FunctionIds but the underlying IndexMap actually checks that a key belongs to a particular
    // arena.
    fns_to_ids: HashMap<FunctionId, usize>,
    ids_to_fns: Vec<FunctionId>,

    shared_symbols: BTreeSet<Node>,
    split_points: Vec<SplitPoint>,
    chunks: Vec<HashSet<Node>>,
    data_symbols: BTreeMap<usize, DataSymbol>,
    main_graph: HashSet<Node>,
    call_graph: HashMap<Node, HashSet<Node>>,
    parent_graph: HashMap<Node, HashSet<Node>>,
}

/// The results of splitting the wasm module with some additional metadata for later use.
pub struct OutputModules {
    /// The main chunk
    pub main: SplitModule,

    /// The modules of the wasm module that were split.
    pub modules: Vec<SplitModule>,

    /// The chunks that might be imported by the main modules
    pub chunks: Vec<SplitModule>,
}

/// A wasm module that was split from the main module.
///
/// All IDs here correspond to *this* module - not the parent main module
pub struct SplitModule {
    pub module_name: String,
    pub hash_id: Option<String>,
    pub component_name: Option<String>,
    pub bytes: Vec<u8>,
    pub relies_on_chunks: HashSet<usize>,
}

impl<'a> Splitter<'a> {
    /// Create a new "splitter" instance using the original wasm and the wasm from the output of wasm-bindgen.
    ///
    /// This will use the relocation data from the original module to create a call graph that we
    /// then use with the post-bindgened module to create the split modules.
    ///
    /// It's important to compile the wasm with --emit-relocs such that the relocations are available
    /// to construct the callgraph.
    pub fn new(original: &'a [u8], bindgened: &'a [u8]) -> Result<Self> {
        let (module, ids, fns_to_ids) = parse_module_with_ids(bindgened)?;

        let split_points = accumulate_split_points(&module);

        // Note that we can't trust the normal symbols - just the data symbols - and we can't use the data offset
        // since that's not reliable after bindgening
        let raw_data = parse_bytes_to_data_segment(bindgened)?;

        let mut module = Self {
            source_module: module,
            original,
            bindgened,
            split_points,
            data_symbols: raw_data.data_symbols,
            ids_to_fns: ids,
            fns_to_ids,
            main_graph: Default::default(),
            chunks: Default::default(),
            call_graph: Default::default(),
            parent_graph: Default::default(),
            shared_symbols: Default::default(),
        };

        module.build_call_graph()?;
        module.build_split_chunks();

        Ok(module)
    }

    /// Split the module into multiple modules at the boundaries of split points.
    ///
    /// Note that the binaries might still be "large" at the end of this process. In practice, you
    /// need to push these binaries through wasm-bindgen and wasm-opt to take advantage of the
    /// optimizations and splitting. We perform a few steps like zero-ing out the data segments
    /// that will only be removed by the memory-packing step of wasm-opt.
    ///
    /// This returns the list of chunks, an import map, and some javascript to link everything together.
    pub fn emit(self) -> Result<OutputModules> {
        tracing::info!("Emitting split modules.");

        let tables: Vec<_> = self
            .source_module
            .tables
            .iter()
            .map(|t| t.name.clone())
            .collect();
        let memories: Vec<_> = self
            .source_module
            .memories
            .iter()
            .map(|m| m.name.clone())
            .collect();
        let extra = (self.split_points.len() + self.shared_symbols.len()) as u64;
        let src = emit::Source::new(self.bindgened, &tables, &memories, extra)?;
        let slots = self.shared_slots(src.slots_start);
        let chunks = (0..self.chunks.len())
            .into_par_iter()
            .map(|idx| self.emit_split_chunk(&src, &slots, idx))
            .collect::<Result<Vec<SplitModule>>>()?;
        let modules = (0..self.split_points.len())
            .into_par_iter()
            .map(|idx| self.emit_split_module(&src, &slots, idx))
            .collect::<Result<Vec<SplitModule>>>()?;

        let main = self.emit_main_module()?;

        Ok(OutputModules {
            modules,
            chunks,
            main,
        })
    }

    /// Emit the main module.
    ///
    /// This will analyze the call graph and then perform some transformations on the module.
    /// - Clear out active segments that the split modules will initialize
    /// - Wipe away unused functions and data symbols
    /// - Re-export the memories, globals, and other items that the split modules will need
    /// - Convert the split module import functions to real functions that call the indirect function
    ///
    /// Once this is done, all the split module functions will have been removed, making the main module smaller.
    ///
    /// Emitting the main module is conceptually pretty simple. Emitting the split modules is more
    /// complex.
    fn emit_main_module(mut self) -> Result<SplitModule> {
        tracing::info!("Emitting main bundle split module");

        // Perform some analysis of the module before we start messing with it
        let unused_symbols = self.unused_main_symbols();

        // Use the original module that contains all the right ids
        let mut out = std::mem::take(&mut self.source_module);

        // 1. Clear out the active segments that try to initialize functions for modules we just split off.
        //    When the side modules load, they will initialize functions into the table where the "holes" are.
        self.replace_segments_with_holes(&mut out, &unused_symbols);

        // 2. Wipe away the unused functions and data symbols
        self.prune_main_symbols(&mut out, &unused_symbols)?;

        // 3. Change the functions called from split modules to be local functions that call the indirect function
        self.create_ifunc_table(&mut out);

        // 4. Re-export the memories, globals, and other stuff
        self.re_export_items(&mut out);

        // 6. Remove the reloc and linking custom sections
        self.remove_custom_sections(&mut out);

        // 7. Run the garbage collector to remove unused functions
        walrus::passes::gc::run(&mut out);

        Ok(SplitModule {
            module_name: "main".to_string(),
            component_name: None,
            bytes: out.emit_wasm(),
            relies_on_chunks: Default::default(),
            hash_id: None,
        })
    }

    /// Write the contents of the split modules to the output
    fn emit_split_module(
        &self,
        src: &emit::Source,
        slots: &HashMap<FunctionId, u32>,
        split_idx: usize,
    ) -> Result<SplitModule> {
        let split = &self.split_points[split_idx];

        // These are the symbols that will only exist in this module and not in the main module.
        let mut unique_symbols = split
            .reachable_graph
            .difference(&self.main_graph)
            .cloned()
            .collect::<HashSet<_>>();

        // The functions we'll need to import
        let mut symbols_to_import: HashSet<_> = split
            .reachable_graph
            .intersection(&self.main_graph)
            .cloned()
            .collect();

        // Identify the functions we'll delete
        let symbols_to_delete: HashSet<_> = self
            .main_graph
            .difference(&split.reachable_graph)
            .cloned()
            .collect();

        // Convert split chunk functions to imports
        let mut relies_on_chunks = HashSet::new();
        for (idx, chunk) in self.chunks.iter().enumerate() {
            let nodes_to_extract = unique_symbols
                .intersection(chunk)
                .cloned()
                .collect::<Vec<_>>();
            for node in nodes_to_extract {
                if !self.main_graph.contains(&node) {
                    unique_symbols.remove(&node);
                    symbols_to_import.insert(node);
                    relies_on_chunks.insert(idx);
                }
            }
        }

        tracing::info!(
            "Emitting module {}/{} {}: {:?}",
            split_idx,
            self.split_points.len(),
            split.module_name,
            relies_on_chunks
        );

        let slot = src.slots_start + split.index as u32;
        let plan = self.plan(
            &split.module_name,
            Some((&split.export_name, split.export_func, slot)),
            [&unique_symbols, &symbols_to_import, &symbols_to_delete],
            slots,
        );

        Ok(SplitModule {
            bytes: src.emit(&plan, |i| self.func_name(i))?,
            module_name: split.module_name.clone(),
            component_name: Some(split.component_name.clone()),
            relies_on_chunks,
            hash_id: Some(split.hash_name.clone()),
        })
    }

    /// Write a split chunk - this is a chunk with no special functions, just exports + initializers
    fn emit_split_chunk(
        &self,
        src: &emit::Source,
        slots: &HashMap<FunctionId, u32>,
        idx: usize,
    ) -> Result<SplitModule> {
        tracing::info!("emitting chunk {}", idx);

        let unique_symbols = &self.chunks[idx];

        // The functions we'll need to import
        let symbols_to_import: HashSet<_> = unique_symbols
            .intersection(&self.main_graph)
            .cloned()
            .collect();

        // Delete everything except the symbols that are reachable from this module
        let symbols_to_delete: HashSet<_> = self
            .main_graph
            .difference(unique_symbols)
            .cloned()
            .collect();

        let plan = self.plan(
            "split chunk",
            None,
            [unique_symbols, &symbols_to_import, &symbols_to_delete],
            slots,
        );

        Ok(SplitModule {
            bytes: src.emit(&plan, |i| self.func_name(i))?,
            module_name: "split".to_string(),
            component_name: None,
            relies_on_chunks: Default::default(),
            hash_id: None,
        })
    }

    /// Each shared function's slot in main's funcref table, after one per split point.
    fn shared_slots(&self, start: u32) -> HashMap<FunctionId, u32> {
        let funcs = self.shared_symbols.iter().filter_map(|n| match n {
            Node::Function(id) => Some(*id),
            Node::DataSymbol(_) => None,
        });
        let first = start + self.split_points.len() as u32;
        funcs.zip(first..).collect()
    }

    /// `sets` are the part's unique symbols, the ones it calls in main, and the ones it drops.
    fn plan<'p>(
        &self,
        label: &'p str,
        export: Option<(&'p str, FunctionId, u32)>,
        [unique, import, delete]: [&HashSet<Node>; 3],
        slots: &HashMap<FunctionId, u32>,
    ) -> emit::Plan<'p> {
        let idx = |id: &FunctionId| self.fns_to_ids[id] as u32;
        let funcs = |set: &HashSet<Node>| -> HashSet<u32> {
            set.iter()
                .filter_map(|n| match n {
                    Node::Function(id) => Some(idx(id)),
                    Node::DataSymbol(_) => None,
                })
                .collect()
        };
        let stubs = import
            .iter()
            .filter_map(|n| match n {
                Node::Function(id) => Some((idx(id), *slots.get(id)?)),
                Node::DataSymbol(_) => None,
            })
            .collect();
        let mut data: Vec<_> = unique
            .iter()
            .filter_map(|n| match n {
                Node::DataSymbol(i) => self.data_symbols.get(i),
                Node::Function(_) => None,
            })
            .filter(|s| s.which_data_segment == 0)
            .map(|s| (s.segment_offset, s.symbol_size))
            .collect();
        data.sort_unstable();
        emit::Plan {
            label,
            export: export.map(|(name, func, slot)| (name, idx(&func), slot)),
            table_funcs: funcs(unique),
            stubs,
            deleted: funcs(delete),
            data,
        }
    }

    fn func_name(&self, idx: u32) -> Option<String> {
        let id = self.ids_to_fns[idx as usize];
        self.source_module.funcs.get(id).name.clone()
    }

    /// Convert split import functions to local functions that call an indirect function that will
    /// be filled in from the loaded split module.
    ///
    /// This is because these imports are going to be delayed until the split module is loaded
    /// and loading in the main module these as imports won't be possible since the imports won't
    /// be resolved until the split module is loaded.
    fn create_ifunc_table(&self, out: &mut Module) {
        let ifunc_table = self.load_funcref_table(out);
        let dummy_func = self.make_dummy_func(out);

        out.exports.add("__indirect_function_table", ifunc_table);

        // Expand the ifunc table to accommodate the new ifuncs
        let segment_start = self
            .expand_ifunc_table_max(
                out,
                ifunc_table,
                self.split_points.len() + self.shared_symbols.len(),
            )
            .expect("failed to expand ifunc table");

        // Delete the split import functions and replace them with local functions
        //
        // Start by pushing all the shared imports into the list
        // These don't require an additional stub function
        let mut ifuncs = vec![];

        // Push the split import functions into the list - after we've pushed in the shared imports
        for idx in 0..self.split_points.len() {
            // this is okay since we're in the main module
            let import_func = self.split_points[idx].import_func;
            let import_id = self.split_points[idx].import_id;
            let ty_id = out.funcs.get(import_func).ty();
            let stub_idx = segment_start + ifuncs.len();

            // Replace the import function with a local function that calls the indirect function
            out.funcs.get_mut(import_func).kind =
                self.make_stub_funcs(out, ifunc_table, ty_id, stub_idx as _);

            // And remove the corresponding import
            out.imports.delete(import_id);

            // Push into the list the properly typed dummy func so the entry is populated
            // unclear if the typing is important here
            ifuncs.push(dummy_func);
        }

        // Add the stub functions to the ifunc table
        // The callers of these functions will call the stub instead of the import
        let mut _idx = 0;
        for func in self.shared_symbols.iter() {
            if let Node::Function(id) = func {
                ifuncs.push(*id);
                _idx += 1;
            }
        }

        // Now add segments to the ifunc table
        out.tables
            .get_mut(ifunc_table)
            .elem_segments
            .insert(out.elements.add(
                ElementKind::Active {
                    table: ifunc_table,
                    offset: ConstExpr::Value(ir::Value::I32(segment_start as _)),
                },
                ElementItems::Functions(ifuncs),
            ));
    }

    /// Re-export the memories, globals, and other items from the main module to the side modules
    fn re_export_items(&self, out: &mut Module) {
        // Re-export memories
        for (idx, memory) in out.memories.iter().enumerate() {
            let name = memory
                .name
                .clone()
                .unwrap_or_else(|| format!("__memory_{}", idx));
            out.exports.add(&name, memory.id());
        }

        // Re-export globals
        for (idx, global) in out.globals.iter().enumerate() {
            let global_name = format!("__global__{idx}");
            out.exports.add(&global_name, global.id());
        }

        // Export any tables
        for (idx, table) in out.tables.iter().enumerate() {
            if table.element_ty != RefType::Funcref {
                let table_name = format!("__imported_table_{}", idx);
                out.exports.add(&table_name, table.id());
            }
        }
    }

    fn prune_main_symbols(&self, out: &mut Module, unused_symbols: &HashSet<Node>) -> Result<()> {
        // Wipe the split point exports
        for split in self.split_points.iter() {
            // it's okay that we're not re-mapping IDs since this is just used by the main module
            out.exports.delete(split.export_id);
        }

        // Merged constants give several symbols one range, so a kept symbol's bytes stay.
        let first_segment = out.data.iter().next().map_or(0, |data| data.value.len());
        let mut kept = vec![false; first_segment];
        for symbol in self.data_symbols.values() {
            if symbol.which_data_segment == 0
                && !unused_symbols.contains(&Node::DataSymbol(symbol.index))
            {
                kept[symbol.segment_offset..symbol.segment_offset + symbol.symbol_size].fill(true);
            }
        }

        // And then any actual symbols from the callgraph
        for symbol in unused_symbols.iter().cloned() {
            match symbol {
                // Simply delete functions
                Node::Function(id) => {
                    out.funcs.delete(id);
                }

                // Otherwise, zero out the data segment, which should lead to elimination by wasm-opt
                Node::DataSymbol(id) => {
                    let symbol = self
                        .data_symbols
                        .get(&id)
                        .context("Failed to find data symbol")?;

                    // VERY IMPORTANT
                    //
                    // apparently wasm-bindgen makes data segments that aren't the main one
                    // even *touching* those will break the vtable / binding layer
                    // We can only interact with the first data segment - the rest need to stay available
                    // for the `.js` to interact with.
                    if symbol.which_data_segment == 0 {
                        let data_id = out.data.iter().nth(symbol.which_data_segment).unwrap().id();
                        let data = out.data.get_mut(data_id);
                        let range =
                            symbol.segment_offset..symbol.segment_offset + symbol.symbol_size;
                        for (byte, kept) in data.value[range.clone()].iter_mut().zip(&kept[range]) {
                            if !kept {
                                *byte = 0;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    // 2.1 Create a dummy func that will be overridden later as modules pop in
    // 2.2 swap the segment entries with the dummy func, leaving hole in its placed that will be filled in later
    fn replace_segments_with_holes(&self, out: &mut Module, unused_symbols: &HashSet<Node>) {
        let dummy_func = self.make_dummy_func(out);
        for element in out.elements.iter_mut() {
            match &mut element.items {
                ElementItems::Functions(vec) => {
                    for item in vec.iter_mut() {
                        if unused_symbols.contains(&Node::Function(*item)) {
                            *item = dummy_func;
                        }
                    }
                }
                ElementItems::Expressions(_ref_type, const_exprs) => {
                    for item in const_exprs.iter_mut() {
                        if let &mut ConstExpr::RefFunc(id) = item {
                            if unused_symbols.contains(&Node::Function(id)) {
                                *item = ConstExpr::RefFunc(dummy_func);
                            }
                        }
                    }
                }
            }
        }
    }

    fn make_dummy_func(&self, out: &mut Module) -> FunctionId {
        let mut b = FunctionBuilder::new(&mut out.types, &[], &[]);
        b.name("dummy".into()).func_body().unreachable();
        b.finish(vec![], &mut out.funcs)
    }

    /// Load the funcref table from the main module. This *should* exist for all modules created by
    /// Rustc or Wasm-Bindgen, but we create it if it doesn't exist.
    fn load_funcref_table(&self, out: &mut Module) -> TableId {
        let ifunc_table = out
            .tables
            .iter()
            .find(|t| t.element_ty == RefType::Funcref)
            .map(|t| t.id());

        if let Some(table) = ifunc_table {
            table
        } else {
            out.tables.add_local(false, 0, None, RefType::Funcref)
        }
    }

    /// Convert the imported function to a local function that calls an indirect function from the table
    ///
    /// This will enable the main module (and split modules) to call functions from outside their own module.
    /// The functions might not exist when the main module is loaded, so we'll register some elements
    /// that fill those in eventually.
    fn make_stub_funcs(
        &self,
        out: &mut Module,
        table: TableId,
        ty_id: TypeId,
        table_idx: i32,
    ) -> FunctionKind {
        // Convert the import function to a local function that calls the indirect function from the table
        let ty = out.types.get(ty_id);

        let params = ty.params().to_vec();
        let results = ty.results().to_vec();
        let args: Vec<_> = params.iter().map(|ty| out.locals.add(*ty)).collect();

        // New function that calls the indirect function
        let mut builder = FunctionBuilder::new(&mut out.types, &params, &results);
        let mut body = builder.name("stub".into()).func_body();

        // Push the params onto the stack
        for arg in args.iter() {
            body.local_get(*arg);
        }

        // And then the address of the indirect function
        body.instr(ir::Instr::Const(ir::Const {
            value: ir::Value::I32(table_idx),
        }));

        // And call it
        body.instr(ir::Instr::CallIndirect(ir::CallIndirect {
            ty: ty_id,
            table,
        }));

        FunctionKind::Local(builder.local_func(args))
    }

    /// Expand the ifunc table to accommodate the new ifuncs
    ///
    /// returns the old maximum
    fn expand_ifunc_table_max(
        &self,
        out: &mut Module,
        table: TableId,
        num_ifuncs: usize,
    ) -> Option<usize> {
        let ifunc_table_ = out.tables.get_mut(table);

        if let Some(max) = ifunc_table_.maximum {
            ifunc_table_.maximum = Some(max + num_ifuncs as u64);
            ifunc_table_.initial += num_ifuncs as u64;
            return Some(max as usize);
        }

        None
    }

    // only keep the target-features and names section so wasm-opt can use it to optimize the output
    fn remove_custom_sections(&self, out: &mut Module) {
        let sections_to_delete = out
            .customs
            .iter()
            .filter_map(|(id, section)| {
                if section.name() == "target_features" {
                    None
                } else {
                    Some(id)
                }
            })
            .collect::<Vec<_>>();

        for id in sections_to_delete {
            out.customs.delete(id);
        }
    }

    /// Accumulate any shared funcs between multiple chunks into a single residual chunk.
    /// This prevents duplicates from being downloaded.
    /// Eventually we need to group the chunks into smarter "communities" - ie the Louvain algorithm
    ///
    /// Todo: we could chunk up the main module itself! Not going to now but it would enable parallel downloads of the main chunk
    fn build_split_chunks(&mut self) {
        // create a single chunk that contains all functions used by multiple modules
        let mut funcs_used_by_chunks: HashMap<Node, HashSet<usize>> = HashMap::new();
        for split in self.split_points.iter() {
            for item in split.reachable_graph.iter() {
                if self.main_graph.contains(item) {
                    continue;
                }
            }
        }

        // Only consider funcs that are used by multiple modules - otherwise they can just stay in their respective module
        funcs_used_by_chunks.retain(|_, v| v.len() > 1);

        // todo: break down this chunk if it exceeds a certain size (100kb?) by identifying different groups

        self.chunks
            .push(funcs_used_by_chunks.keys().cloned().collect());
    }

    fn unused_main_symbols(&self) -> HashSet<Node> {
        self.split_points
            .iter()
            .flat_map(|split| split.reachable_graph.iter())
            .filter(|sym| {
                // Make sure the symbol isn't in the main graph
                if self.main_graph.contains(sym) {
                    return false;
                }

                // And ensure we aren't also exporting it
                match sym {
                    Node::Function(u) => self.source_module.exports.get_exported_func(*u).is_none(),
                    _ => true,
                }
            })
            .cloned()
            .collect()
    }

    /// Accumulate the relocations from the original module, create a relocation map, and then convert
    /// that to our *new* module's symbols.
    fn build_call_graph(&mut self) -> Result<()> {
        let original = ModuleWithRelocations::new(self.original)?;

        let old_names: HashMap<String, FunctionId> = original
            .module
            .funcs
            .iter()
            .flat_map(|f| Some((f.name.clone()?, f.id())))
            .collect();

        let new_names: HashMap<String, FunctionId> = self
            .source_module
            .funcs
            .iter()
            .flat_map(|f| Some((f.name.clone()?, f.id())))
            .collect();

        let mut old_to_new = HashMap::new();
        let mut new_call_graph: HashMap<Node, HashSet<Node>> = HashMap::new();

        for (new_name, new_func) in new_names.iter() {
            if let Some(old_func) = old_names.get(new_name) {
                old_to_new.insert(*old_func, new_func);
            } else {
                new_call_graph.insert(Node::Function(*new_func), HashSet::new());
            }
        }

        let get_old = |old: &Node| -> Option<Node> {
            match old {
                Node::Function(id) => old_to_new.get(id).map(|new_id| Node::Function(**new_id)),
                Node::DataSymbol(id) => Some(Node::DataSymbol(*id)),
            }
        };

        // the symbols that we can't find in the original module touch functions that unfortunately
        // we can't figure out where should exist in the call graph
        //
        // we're going to walk and find every child we possibly can and then add it to the call graph
        // at the root
        //
        // wasm-bindgen will dissolve describe functions into the shim functions, but we don't have a
        // sense of lining up old to new, so we just assume everything ends up in the main chunk.
        let mut lost_children = HashSet::new();
        self.call_graph = original
            .call_graph
            .iter()
            .flat_map(|(old, children)| {
                // If the old function isn't in the new module, we need to move all its descendents into the main chunk
                let Some(new) = get_old(old) else {
                    for child in children {
                        fn descend(
                            lost_children: &mut HashSet<Node>,
                            old_graph: &HashMap<Node, HashSet<Node>>,
                            node: Node,
                        ) {
                            if !lost_children.insert(node) {
                                return;
                            }

                            if let Some(children) = old_graph.get(&node) {
                                for child in children {
                                    descend(lost_children, old_graph, *child);
                                }
                            }
                        }

                        descend(&mut lost_children, &original.call_graph, *child);
                    }
                    return None;
                };

                let mut new_children = HashSet::new();
                for child in children {
                    if let Some(new) = get_old(child) {
                        new_children.insert(new);
                    }
                }

                Some((new, new_children))
            })
            .collect();

        let mut recovered_children = HashSet::new();
        for lost in lost_children {
            match lost {
                // Functions need to be found - the wasm describe functions are usually completely dissolved
                Node::Function(id) => {
                    let func = original.module.funcs.get(id);
                    let name = func.name.as_ref().unwrap();
                    if let Some(entry) = new_names.get(name) {
                        recovered_children.insert(Node::Function(*entry));
                    }
                }

                // Data symbols are unchanged and fine to remap
                Node::DataSymbol(id) => {
                    recovered_children.insert(Node::DataSymbol(id));
                }
            }
        }

        // We're going to attach the recovered children to the main function
        let main_fn = self.source_module.funcs.by_name("main").context("Failed to find `main` function - was this built with LTO, --emit-relocs, and debug symbols?")?;
        let main_fn_entry = new_call_graph.entry(Node::Function(main_fn)).or_default();
        main_fn_entry.extend(recovered_children);

        // Also attach any truly new symbols to the main function. Usually these are the shim functions
        for (name, new) in new_names.iter() {
            if !old_names.contains_key(name) {
                main_fn_entry.insert(Node::Function(*new));
            }
        }

        // Walk the functions and try to disconnect any holes manually
        // This will attempt to resolve any of the new symbols like the shim functions
        for func in self.source_module.funcs.iter() {
            struct CallGrapher<'a> {
                cur: FunctionId,
                call_graph: &'a mut HashMap<Node, HashSet<Node>>,
            }
            impl<'a> Visitor<'a> for CallGrapher<'a> {
                fn visit_function_id(&mut self, function: &walrus::FunctionId) {
                    self.call_graph
                        .entry(Node::Function(self.cur))
                        .or_default()
                        .insert(Node::Function(*function));
                }
            }
            if let FunctionKind::Local(local) = &func.kind {
                let mut call_grapher = CallGrapher {
                    cur: func.id(),
                    call_graph: &mut self.call_graph,
                };
                dfs_in_order(&mut call_grapher, local, local.entry_block());
            }
        }

        // Fill in the parent graph
        for (parnet, children) in self.call_graph.iter() {
            for child in children {
                self.parent_graph.entry(*child).or_default().insert(*parnet);
            }
        }

        self.fill_reachability();

        Ok(())
    }

    fn fill_reachability(&mut self) {
        // Now go fill in the reachability graph for each of the split points
        // We want to be as narrow as possible since we've reparented any new symbols to the main module
        self.split_points.iter_mut().for_each(|split| {
            let roots: HashSet<_> = [Node::Function(split.export_func)].into();
            split.reachable_graph = reachable_graph(&self.call_graph, &roots);
        });

        // And then the reachability graph for main
        self.main_graph = reachable_graph(&self.call_graph, &self.main_roots());
        let unreached = self.unreached_table_entries();
        self.main_graph
            .extend(reachable_graph(&self.call_graph, &unreached));

        // And then the symbols shared between all
        self.shared_symbols = {
            let mut shared_funcs = HashSet::new();

            // Add all the symbols shared between the various modules
            for split in self.split_points.iter() {
                shared_funcs.extend(self.main_graph.intersection(&split.reachable_graph));
            }

            // And then all our imports will be callabale via the ifunc table too
            for import in self.source_module.imports.iter() {
                if let ImportKind::Function(id) = import.kind {
                    shared_funcs.insert(Node::Function(id));
                }
            }

            // Make sure to make this *ordered*
            shared_funcs.into_iter().collect()
        };
    }

    /// Table entries no export or split reaches, such as a closure shim whose describe function
    /// wasm-bindgen dissolved: they stay in main, so their callees must too.
    fn unreached_table_entries(&self) -> HashSet<Node> {
        let mut entries = HashSet::new();
        for element in self.source_module.elements.iter() {
            match &element.items {
                ElementItems::Functions(funcs) => {
                    entries.extend(funcs.iter().copied().map(Node::Function));
                }
                ElementItems::Expressions(_, exprs) => {
                    entries.extend(exprs.iter().filter_map(|expr| match expr {
                        ConstExpr::RefFunc(func) => Some(Node::Function(*func)),
                        _ => None,
                    }));
                }
            }
        }
        entries.retain(|entry| {
            !self.main_graph.contains(entry)
                && !self
                    .split_points
                    .iter()
                    .any(|split| split.reachable_graph.contains(entry))
        });
        entries
    }

    fn main_roots(&self) -> HashSet<Node> {
        // Accumulate all the split entrypoints
        // This will include wasm_bindgen functions too
        let exported_splits = self
            .split_points
            .iter()
            .map(|f| f.export_func)
            .collect::<HashSet<_>>();

        // And only return the functions that are reachable from the main module's start function
        let mut roots = self
            .source_module
            .exports
            .iter()
            .filter_map(|e| match e.item {
                ExportItem::Function(id) if !exported_splits.contains(&id) => {
                    Some(Node::Function(id))
                }
                _ => None,
            })
            .chain(self.source_module.start.map(Node::Function))
            .collect::<HashSet<Node>>();

        // Also add "imports" to the roots
        for import in self.source_module.imports.iter() {
            if let ImportKind::Function(id) = import.kind {
                roots.insert(Node::Function(id));
            }
        }

        roots
    }
}

/// Parse a module and return the mapping of index to FunctionID.
/// We'll use this mapping to remap ModuleIDs
fn parse_module_with_ids(
    bindgened: &[u8],
) -> Result<(Module, Vec<FunctionId>, HashMap<FunctionId, usize>)> {
    let ids = Arc::new(RwLock::new(Vec::new()));
    let ids_ = ids.clone();
    let module = Module::from_buffer_with_config(
        bindgened,
        ModuleConfig::new().on_parse(move |_m, our_ids| {
            let mut ids = ids_.write().expect("No shared writers");
            let mut idx = 0;
            while let Ok(entry) = our_ids.get_func(idx) {
                ids.push(entry);
                idx += 1;
            }

            Ok(())
        }),
    )?;
    let mut ids_ = ids.write().expect("No shared writers");
    let mut ids = vec![];
    std::mem::swap(&mut ids, &mut *ids_);

    let mut fns_to_ids = HashMap::new();
    for (idx, id) in ids.iter().enumerate() {
        fns_to_ids.insert(*id, idx);
    }

    Ok((module, ids, fns_to_ids))
}

struct ModuleWithRelocations<'a> {
    module: Module,
    symbols: Vec<SymbolInfo<'a>>,
    funcs_by_index: Vec<FunctionId>,
    call_graph: HashMap<Node, HashSet<Node>>,
    parents: HashMap<Node, HashSet<Node>>,
    relocation_map: HashMap<Node, Vec<RelocationEntry>>,
    data_symbols: BTreeMap<usize, DataSymbol>,
    data_section_range: Range<usize>,
}

impl<'a> ModuleWithRelocations<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self> {
        let (module, funcs_by_index, _) = parse_module_with_ids(bytes)?;
        let raw_data = parse_bytes_to_data_segment(bytes)?;

        let mut module = Self {
            module,
            data_symbols: raw_data.data_symbols,
            data_section_range: raw_data.data_range,
            symbols: raw_data.symbols,
            funcs_by_index,
            call_graph: Default::default(),
            relocation_map: Default::default(),
            parents: Default::default(),
        };

        module.build_code_call_graph()?;
        module.build_data_call_graph()?;

        for (func, children) in module.call_graph.iter() {
            for child in children {
                module.parents.entry(*child).or_default().insert(*func);
            }
        }

        Ok(module)
    }

    fn build_code_call_graph(&mut self) -> Result<()> {
        let codes_relocations = self.collect_relocations_from_section("reloc.CODE")?;
        let mut relocations = codes_relocations.iter().peekable();

        for (func_id, local) in self.module.funcs.iter_local() {
            let range = local
                .original_range
                .clone()
                .context("local function has no range")?;

            // Walk with relocation
            while let Some(entry) =
                relocations.next_if(|entry| entry.relocation_range().start < range.end)
            {
                let reloc_range = entry.relocation_range();
                assert!(reloc_range.start >= range.start);
                assert!(reloc_range.end <= range.end);

                if let Some(target) = self.get_symbol_dep_node(entry.index as usize)? {
                    let us = Node::Function(func_id);
                    self.call_graph.entry(us).or_default().insert(target);
                    self.relocation_map.entry(us).or_default().push(*entry);
                }
            }
        }

        assert!(relocations.next().is_none());

        Ok(())
    }

    fn build_data_call_graph(&mut self) -> Result<()> {
        let data_relocations = self.collect_relocations_from_section("reloc.DATA")?;
        let mut relocations = data_relocations.iter().peekable();

        let symbols_sorted = self
            .data_symbols
            .values()
            .sorted_by(|a, b| a.range.start.cmp(&b.range.start));

        for symbol in symbols_sorted {
            let start = symbol.range.start - self.data_section_range.start;
            let end = symbol.range.end - self.data_section_range.start;
            let range = start..end;

            while let Some(entry) =
                relocations.next_if(|entry| entry.relocation_range().start < range.end)
            {
                let reloc_range = entry.relocation_range();
                assert!(reloc_range.start >= range.start);
                assert!(reloc_range.end <= range.end);

                if let Some(target) = self.get_symbol_dep_node(entry.index as usize)? {
                    let dep = Node::DataSymbol(symbol.index);
                    self.call_graph.entry(dep).or_default().insert(target);
                    self.relocation_map.entry(dep).or_default().push(*entry);
                }
            }
        }

        assert!(relocations.next().is_none());

        Ok(())
    }

    /// Accumulate all relocations from a section.
    ///
    /// Parses the section using the RelocSectionReader and returns a vector of relocation entries.
    fn collect_relocations_from_section(&self, name: &str) -> Result<Vec<RelocationEntry>> {
        let (_reloc_id, code_reloc) = self
            .module
            .customs
            .iter()
            .find(|(_, c)| c.name() == name)
            .context("Module does not contain the reloc section")?;

        let code_reloc_data = code_reloc.data(&Default::default());
        let reader = BinaryReader::new(&code_reloc_data, 0);
        let relocations = RelocSectionReader::new(reader)
            .context("failed to parse reloc section")?
            .entries()
            .into_iter()
            .flatten()
            .collect();

        Ok(relocations)
    }

    /// The symbol's entry in the call graph, found by function index: merged functions are aliases
    /// the name section doesn't list.
    fn get_symbol_dep_node(&self, index: usize) -> Result<Option<Node>> {
        let res = match self.symbols[index] {
            SymbolInfo::Data { .. } => Some(Node::DataSymbol(index)),
            SymbolInfo::Func { index, .. } => self
                .funcs_by_index
                .get(index as usize)
                .map(|func| Node::Function(*func)),
            _ => None,
        };

        Ok(res)
    }
}

#[derive(Debug, Clone)]
pub struct SplitPoint {
    module_name: String,
    import_id: ImportId,
    export_id: ExportId,
    import_func: FunctionId,
    export_func: FunctionId,
    component_name: String,
    index: usize,
    reachable_graph: HashSet<Node>,
    hash_name: String,

    #[allow(unused)]
    import_name: String,

    #[allow(unused)]
    export_name: String,
}

/// Search the module's imports and exports for functions marked as split points.
///
/// These will be in the form of:
///
/// `__wasm_split_00<module>00_<import|export>_<hash>_<function>`
///
/// For a function named `SomeRoute2` in the module `add_body_element`, the pairings would be:
///
/// `__wasm_split_00add_body_element00_import_abef5ee3ebe66ff17677c56ee392b4c2_SomeRoute2`
/// `__wasm_split_00add_body_element00_export_abef5ee3ebe66ff17677c56ee392b4c2_SomeRoute2`
///
fn accumulate_split_points(module: &Module) -> Vec<SplitPoint> {
    let mut index = 0;

    module
        .imports
        .iter()
        .sorted_by(|a, b| a.name.cmp(&b.name))
        .flat_map(|import| {
            if !import.name.starts_with("__wasm_split_00") {
                return None;
            }

            let ImportKind::Function(import_func) = import.kind else {
                return None;
            };

            // Parse the import name to get the module name, the hash, and the function name
            let remain = import.name.trim_start_matches("__wasm_split_00___");
            let (module_name, rest) = remain.split_once("___00").unwrap();
            let (hash, fn_name) = rest.trim_start_matches("_import_").split_once("_").unwrap();

            // Look for the export with the same name
            let export_name =
                format!("__wasm_split_00___{module_name}___00_export_{hash}_{fn_name}");
            let export_func = module
                .exports
                .get_func(&export_name)
                .expect("Could not find export");
            let export = module.exports.get_exported_func(export_func).unwrap();

            let our_index = index;
            index += 1;

            Some(SplitPoint {
                export_id: export.id(),
                import_id: import.id(),
                module_name: module_name.to_string(),
                import_name: import.name.clone(),
                import_func,
                export_func,
                export_name,
                hash_name: hash.to_string(),
                component_name: fn_name.to_string(),
                index: our_index,
                reachable_graph: Default::default(),
            })
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq, Hash, Copy, PartialOrd, Ord, Clone)]
pub enum Node {
    Function(FunctionId),
    DataSymbol(usize),
}

fn reachable_graph(deps: &HashMap<Node, HashSet<Node>>, roots: &HashSet<Node>) -> HashSet<Node> {
    let mut queue: VecDeque<Node> = roots.iter().copied().collect();
    let mut reachable = HashSet::<Node>::new();
    let mut parents = HashMap::<Node, Node>::new();

    while let Some(node) = queue.pop_front() {
        reachable.insert(node);
        let Some(children) = deps.get(&node) else {
            continue;
        };
        for child in children {
            if reachable.contains(child) {
                continue;
            }
            parents.entry(*child).or_insert(node);
            queue.push_back(*child);
        }
    }

    reachable
}

struct RawDataSection<'a> {
    data_range: Range<usize>,
    symbols: Vec<SymbolInfo<'a>>,
    data_symbols: BTreeMap<usize, DataSymbol>,
}

#[derive(Debug)]
struct DataSymbol {
    index: usize,
    range: Range<usize>,
    segment_offset: usize,
    symbol_size: usize,
    which_data_segment: usize,
}

/// Manually parse the data section from a wasm module
///
/// We need to do this for data symbols because walrus doesn't provide the right range and offset
/// information for data segments. Fortunately, it provides it for code sections, so we only need to
/// do a small amount extra of parsing here.
fn parse_bytes_to_data_segment(bytes: &[u8]) -> Result<RawDataSection<'_>> {
    let parser = wasmparser::Parser::new(0);
    let mut parser = parser.parse_all(bytes);
    let mut segments = vec![];
    let mut data_range = 0..0;
    let mut symbols = vec![];

    // Process the payloads in the raw wasm file so we can extract the specific sections we need
    while let Some(Ok(payload)) = parser.next() {
        match payload {
            Payload::DataSection(section) => {
                data_range = section.range();
                segments = section.into_iter().collect::<Result<Vec<_>, _>>()?
            }
            Payload::CustomSection(section) if section.name() == "linking" => {
                let reader = BinaryReader::new(section.data(), 0);
                let reader = LinkingSectionReader::new(reader)?;
                for subsection in reader.subsections() {
                    if let Linking::SymbolTable(map) = subsection? {
                        symbols = map.into_iter().collect::<Result<Vec<_>, _>>()?;
                    }
                }
            }
            _ => {}
        }
    }

    // Accumulate the data symbols into a btreemap for later use
    let mut data_symbols = BTreeMap::new();
    for (index, symbol) in symbols.iter().enumerate() {
        let SymbolInfo::Data {
            symbol: Some(symbol),
            ..
        } = symbol
        else {
            continue;
        };

        if symbol.size == 0 {
            continue;
        }

        let data_segment = segments
            .get(symbol.index as usize)
            .context("Failed to find data segment")?;
        let offset: usize =
            data_segment.range.end - data_segment.data.len() + (symbol.offset as usize);
        let range = offset..(offset + symbol.size as usize);

        data_symbols.insert(
            index,
            DataSymbol {
                index,
                range,
                segment_offset: symbol.offset as usize,
                symbol_size: symbol.size as usize,
                which_data_segment: symbol.index as usize,
            },
        );
    }

    Ok(RawDataSection {
        data_range,
        symbols,
        data_symbols,
    })
}

#[cfg(test)]
mod tests;
