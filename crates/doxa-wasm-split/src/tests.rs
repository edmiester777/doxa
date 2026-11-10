use walrus::{DataKind, FunctionBuilder, Module, RefType};

use super::*;

const IMPORT: &str = "__wasm_split_00___page___00_import_ab_render";
const EXPORT: &str = "__wasm_split_00___page___00_export_ab_render";

fn func_calling(module: &mut Module, callee: Option<FunctionId>) -> FunctionId {
    let mut builder = FunctionBuilder::new(&mut module.types, &[], &[]);
    if let Some(callee) = callee {
        builder.func_body().call(callee);
    }
    builder.finish(Vec::new(), &mut module.funcs)
}

/// A split point reaching `callee`, and a table entry calling it that nothing reaches.
fn orphaned_table_entry() -> (Module, HashMap<Node, HashSet<Node>>, FunctionId, FunctionId) {
    let mut module = Module::default();
    let ty = module.types.add(&[], &[]);
    module.add_import_func("./__wasm_split.js", IMPORT, ty);
    let callee = func_calling(&mut module, None);
    let split = func_calling(&mut module, Some(callee));
    module.exports.add(EXPORT, split);
    let orphan = func_calling(&mut module, Some(callee));
    let table = module.tables.add_local(false, 1, Some(1), RefType::Funcref);
    let element = module.elements.add(
        ElementKind::Active {
            table,
            offset: ConstExpr::Value(ir::Value::I32(0)),
        },
        ElementItems::Functions(vec![orphan]),
    );
    module.tables.get_mut(table).elem_segments.insert(element);
    let graph = [
        (Node::Function(split), [Node::Function(callee)].into()),
        (Node::Function(orphan), [Node::Function(callee)].into()),
    ]
    .into();
    (module, graph, orphan, callee)
}

fn splitter(module: Module, call_graph: HashMap<Node, HashSet<Node>>) -> Splitter<'static> {
    let split_points = accumulate_split_points(&module);
    let mut splitter = Splitter {
        source_module: module,
        original: &[],
        bindgened: &[],
        fns_to_ids: HashMap::new(),
        ids_to_fns: Vec::new(),
        shared_symbols: BTreeSet::new(),
        split_points,
        chunks: Vec::new(),
        data_symbols: BTreeMap::new(),
        main_graph: HashSet::new(),
        call_graph,
        parent_graph: HashMap::new(),
    };
    splitter.fill_reachability();
    splitter
}

#[test]
fn zeroing_a_split_symbol_spares_bytes_another_symbol_covers() {
    let (mut module, mut graph, _, callee) = orphaned_table_entry();
    let split = module.exports.get_func(EXPORT).unwrap();
    let live_func = func_calling(&mut module, None);
    module.exports.add("kept", live_func);
    let memory = module.memories.add_local(false, false, 1, None, None);
    module.data.add(
        DataKind::Active {
            memory,
            offset: ConstExpr::Value(ir::Value::I32(16)),
        },
        vec![1, 2, 3, 4, 5, 6],
    );
    // The split's symbol spans bytes 0..4, main's merged constant 2..6.
    graph
        .get_mut(&Node::Function(split))
        .unwrap()
        .insert(Node::DataSymbol(1));
    graph.insert(
        Node::Function(live_func),
        [Node::DataSymbol(2)].into_iter().collect(),
    );
    let symbol = |index, segment_offset, symbol_size| DataSymbol {
        index,
        range: 0..0,
        segment_offset,
        symbol_size,
        which_data_segment: 0,
    };
    let mut splitter = splitter(module, graph);
    splitter.data_symbols = [(1, symbol(1, 0, 4)), (2, symbol(2, 2, 4))].into();
    assert!(splitter.main_graph.contains(&Node::Function(callee)));
    let main = splitter.emit_main_module().unwrap();
    let main = Module::from_buffer(&main.bytes).unwrap();
    let bytes = &main.data.iter().next().unwrap().value;
    assert_eq!(bytes, &[0, 0, 3, 4, 5, 6]);
}

#[test]
fn an_aliased_symbol_resolves_to_the_function_at_its_index() {
    let mut module = Module::default();
    let named = func_calling(&mut module, None);
    let relocations = ModuleWithRelocations {
        module,
        symbols: vec![SymbolInfo::Func {
            flags: wasmparser::SymbolFlags::empty(),
            index: 0,
            name: Some("a_merged_alias_the_name_section_never_lists"),
        }],
        funcs_by_index: vec![named],
        call_graph: HashMap::new(),
        parents: HashMap::new(),
        relocation_map: HashMap::new(),
        data_symbols: BTreeMap::new(),
        data_section_range: 0..0,
    };
    assert_eq!(
        relocations.get_symbol_dep_node(0).unwrap(),
        Some(Node::Function(named)),
    );
}

#[test]
fn a_table_entry_nothing_reaches_keeps_its_callees_in_main() {
    let (module, graph, orphan, callee) = orphaned_table_entry();
    let splitter = splitter(module, graph);
    assert!(splitter.main_graph.contains(&Node::Function(orphan)));
    assert!(splitter.main_graph.contains(&Node::Function(callee)));
    assert!(splitter.shared_symbols.contains(&Node::Function(callee)));
    let main = splitter.emit_main_module().unwrap();
    Module::from_buffer(&main.bytes).unwrap();
}

#[test]
fn a_table_entry_a_split_reaches_leaves_main() {
    let (mut module, mut graph, orphan, callee) = orphaned_table_entry();
    let split = module.exports.get_func(EXPORT).unwrap();
    graph
        .get_mut(&Node::Function(split))
        .unwrap()
        .insert(Node::Function(orphan));
    let local = func_calling(&mut module, None);
    module.exports.add("kept", local);
    let splitter = splitter(module, graph);
    assert!(!splitter.main_graph.contains(&Node::Function(orphan)));
    assert!(!splitter.main_graph.contains(&Node::Function(callee)));
    let main = splitter.emit_main_module().unwrap();
    Module::from_buffer(&main.bytes).unwrap();
}

/// A split point calling `unique` and `shared`, which main's `kept` also calls, and data at 16.
fn split_with_shared_callee() -> &'static [u8] {
    let mut module = Module::default();
    let ty = module.types.add(&[], &[]);
    module.add_import_func("./__wasm_split.js", IMPORT, ty);
    let named = |module: &mut Module, name: &str, callees: &[FunctionId]| {
        let mut builder = FunctionBuilder::new(&mut module.types, &[], &[]);
        builder.name(name.into());
        let mut body = builder.func_body();
        for callee in callees {
            body.call(*callee);
        }
        builder.finish(Vec::new(), &mut module.funcs)
    };
    let shared = named(&mut module, "shared", &[]);
    let unique = named(&mut module, "unique", &[]);
    let split = named(&mut module, "split", &[unique, shared]);
    let kept = named(&mut module, "kept", &[shared]);
    module.exports.add(EXPORT, split);
    module.exports.add("kept", kept);
    module.tables.add_local(false, 1, Some(1), RefType::Funcref);
    let memory = module.memories.add_local(false, false, 1, None, None);
    module.data.add(
        DataKind::Active {
            memory,
            offset: ConstExpr::Value(ir::Value::I32(16)),
        },
        vec![1, 2, 3, 4, 5, 6],
    );
    module.emit_wasm().leak()
}

#[test]
fn a_split_module_holds_its_own_functions_and_stubs_the_ones_main_keeps() {
    let bytes = split_with_shared_callee();
    let (module, ids, fns_to_ids) = parse_module_with_ids(bytes).unwrap();
    let f = |name| Node::Function(module.funcs.by_name(name).unwrap());
    let graph = [
        (
            f("split"),
            [f("unique"), f("shared"), Node::DataSymbol(1)].into(),
        ),
        (f("kept"), [f("shared")].into()),
    ]
    .into();
    let Node::Function(shared) = f("shared") else {
        unreachable!()
    };
    let mut splitter = splitter(module, graph);
    splitter.bindgened = bytes;
    splitter.fns_to_ids = fns_to_ids;
    splitter.ids_to_fns = ids;
    splitter.data_symbols = [(
        1,
        DataSymbol {
            index: 1,
            range: 0..0,
            segment_offset: 1,
            symbol_size: 2,
            which_data_segment: 0,
        },
    )]
    .into();
    let slot = splitter.shared_slots(1)[&shared];

    let out = splitter.emit().unwrap();
    Module::from_buffer(&out.main.bytes).unwrap();
    let part = Module::from_buffer(&out.modules[0].bytes).unwrap();
    let mut names: Vec<_> = part
        .funcs
        .iter()
        .filter_map(|f| f.name.as_deref())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["shared", "split", "unique"]);
    assert!(part.exports.get_func(EXPORT).is_ok());
    let imports: Vec<_> = part.imports.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(imports, ["__indirect_function_table", "__memory_0"]);

    let stub = part.funcs.by_name("shared").unwrap();
    let FunctionKind::Local(stub) = &part.funcs.get(stub).kind else {
        panic!("the stub has no body")
    };
    let calls = &stub.block(stub.entry_block()).instrs;
    assert!(matches!(
        calls[0].0,
        ir::Instr::Const(ir::Const { value: ir::Value::I32(s) }) if s as u32 == slot
    ));
    assert!(matches!(calls[1].0, ir::Instr::CallIndirect(_)));

    let data: Vec<_> = part.data.iter().map(|d| d.value.as_slice()).collect();
    assert_eq!(data, [&[][..], &[2, 3]]);
    let DataKind::Active { offset, .. } = part.data.iter().nth(1).unwrap().kind else {
        panic!("the split's data isn't active")
    };
    assert!(matches!(offset, ConstExpr::Value(ir::Value::I32(17))));
}
