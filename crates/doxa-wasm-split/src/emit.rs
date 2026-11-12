//! Split modules re-encoded straight from the bindgened bytes: only the functions a part reaches,
//! renumbered, with every table, memory and global imported from main at its original index.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use anyhow::{bail, Context, Result};
use wasm_encoder::reencode::{Error as ReencodeError, Reencode, RoundtripReencoder};
use wasm_encoder::{
    CodeSection, ConstExpr, CustomSection, DataCountSection, DataSection, ElementSection, Elements,
    EntityType, ExportKind, ExportSection, Function, FunctionSection, ImportSection, Instruction,
    NameMap, NameSection, RawSection,
};
use wasmparser::{CompositeInnerType, FunctionBody, Operator, Parser, Payload, RefType, TypeRef};

/// What every part copies or imports from the bindgened wasm, read once.
pub(crate) struct Source<'a> {
    types: &'a [u8],
    type_params: Vec<u32>,
    func_types: Vec<u32>,
    imported_funcs: usize,
    bodies: Vec<FunctionBody<'a>>,
    imports: Vec<(String, EntityType)>,
    funcref_table: u32,
    /// The first table slot past the bindgened table, where main puts its split and shared slots.
    pub(crate) slots_start: u32,
    elements: Vec<(i32, Vec<Option<u32>>)>,
    data: Vec<Segment<'a>>,
    data_count: bool,
    target_features: Option<&'a [u8]>,
}

/// A data segment: its memory and offset when active, the offset as an `i32` when constant.
struct Segment<'a> {
    active: Option<(u32, ConstExpr)>,
    offset: Option<i32>,
    bytes: &'a [u8],
}

/// One part to emit, in bindgened function indices.
pub(crate) struct Plan<'p> {
    pub label: &'p str,
    pub export: Option<(&'p str, u32, u32)>,
    pub table_funcs: HashSet<u32>,
    /// Functions this part puts in main's table for other parts' stubs, with their slots.
    pub placed: Vec<(u32, u32)>,
    /// Functions defined elsewhere, as the table slot their stub calls.
    pub stubs: HashMap<u32, u32>,
    pub deleted: HashSet<u32>,
    /// `(offset, size)` ranges of the first data segment this part initializes.
    pub data: Vec<(usize, usize)>,
}

impl<'a> Source<'a> {
    /// `table_names` and `memory_names` are walrus's, so imports match what main exports;
    /// `extra_slots` is how far main grows its funcref table.
    pub(crate) fn new(
        bytes: &'a [u8],
        table_names: &[Option<String>],
        memory_names: &[Option<String>],
        extra_slots: u64,
    ) -> Result<Self> {
        let mut src = Source {
            types: &[],
            type_params: Vec::new(),
            func_types: Vec::new(),
            imported_funcs: 0,
            bodies: Vec::new(),
            imports: Vec::new(),
            funcref_table: 0,
            slots_start: 0,
            elements: Vec::new(),
            data: Vec::new(),
            data_count: false,
            target_features: None,
        };
        let (mut tables, mut memories, mut globals) = (Vec::new(), Vec::new(), Vec::new());
        for payload in Parser::new(0).parse_all(bytes) {
            match payload? {
                Payload::TypeSection(reader) => {
                    src.types = &bytes[reader.range()];
                    for group in reader {
                        for ty in group?.into_types() {
                            let params = match &ty.composite_type.inner {
                                CompositeInnerType::Func(f) => f.params().len() as u32,
                                _ => 0,
                            };
                            src.type_params.push(params);
                        }
                    }
                }
                Payload::ImportSection(reader) => {
                    for import in reader {
                        match import?.ty {
                            TypeRef::Func(ty) => {
                                src.func_types.push(ty);
                                src.imported_funcs += 1;
                            }
                            TypeRef::Table(t) => tables.push(t),
                            TypeRef::Memory(m) => memories.push(m),
                            TypeRef::Global(g) => globals.push(g),
                            TypeRef::Tag(_) => bail!("wasm-split doesn't handle imported tags"),
                        }
                    }
                }
                Payload::FunctionSection(reader) => {
                    for ty in reader {
                        src.func_types.push(ty?);
                    }
                }
                Payload::TableSection(reader) => {
                    for table in reader {
                        tables.push(table?.ty);
                    }
                }
                Payload::MemorySection(reader) => {
                    for memory in reader {
                        memories.push(memory?);
                    }
                }
                Payload::GlobalSection(reader) => {
                    for global in reader {
                        globals.push(global?.ty);
                    }
                }
                Payload::ElementSection(reader) => {
                    for element in reader {
                        let element = element?;
                        let wasmparser::ElementKind::Active { offset_expr, .. } = element.kind
                        else {
                            continue;
                        };
                        let Some(offset) = const_i32(&offset_expr) else {
                            continue;
                        };
                        let items = match element.items {
                            wasmparser::ElementItems::Functions(funcs) => funcs
                                .into_iter()
                                .map(|f| f.map(Some))
                                .collect::<Result<_, _>>()?,
                            wasmparser::ElementItems::Expressions(_, exprs) => exprs
                                .into_iter()
                                .map(|e| e.map(|e| ref_func(&e)))
                                .collect::<Result<_, _>>()?,
                        };
                        src.elements.push((offset, items));
                    }
                }
                Payload::DataCountSection { .. } => src.data_count = true,
                Payload::DataSection(reader) => {
                    for data in reader {
                        let data = data?;
                        let (active, offset) = match data.kind {
                            wasmparser::DataKind::Passive => (None, None),
                            wasmparser::DataKind::Active {
                                memory_index,
                                offset_expr,
                            } => {
                                let expr = RoundtripReencoder.const_expr(offset_expr.clone())?;
                                (Some((memory_index, expr)), const_i32(&offset_expr))
                            }
                        };
                        src.data.push(Segment {
                            active,
                            offset,
                            bytes: data.data,
                        });
                    }
                }
                Payload::CodeSectionEntry(body) => src.bodies.push(body),
                Payload::CustomSection(reader) if reader.name() == "target_features" => {
                    src.target_features = Some(reader.data());
                }
                _ => {}
            }
        }
        if tables.len() != table_names.len() || memories.len() != memory_names.len() {
            bail!("walrus and wasmparser disagree on the tables and memories");
        }
        let funcref = tables
            .iter()
            .position(|t| t.element_type == RefType::FUNCREF)
            .context("the wasm has no funcref table")?;
        src.funcref_table = funcref as u32;
        let table = &mut tables[funcref];
        let max = table
            .maximum
            .context("the funcref table has no maximum to grow past")?;
        src.slots_start = u32::try_from(max)?;
        table.maximum = Some(max + extra_slots);
        table.initial += extra_slots;
        for (idx, (t, name)) in tables.into_iter().zip(table_names).enumerate() {
            let name = name.clone().unwrap_or_else(|| {
                if t.element_type == RefType::FUNCREF {
                    "__indirect_function_table".into()
                } else {
                    format!("__imported_table_{idx}")
                }
            });
            let ty = RoundtripReencoder.table_type(t)?;
            src.imports.push((name, EntityType::Table(ty)));
        }
        for (idx, (m, name)) in memories.into_iter().zip(memory_names).enumerate() {
            let name = name.clone().unwrap_or_else(|| format!("__memory_{idx}"));
            let ty = RoundtripReencoder.memory_type(m)?;
            src.imports.push((name, EntityType::Memory(ty)));
        }
        for (idx, g) in globals.into_iter().enumerate() {
            let ty = RoundtripReencoder.global_type(g)?;
            src.imports
                .push((format!("__global__{idx}"), EntityType::Global(ty)));
        }
        Ok(src)
    }

    /// The part's wasm. `name` gives a bindgened function's name for the name section.
    pub(crate) fn emit(
        &self,
        plan: &Plan,
        name: impl Fn(u32) -> Option<String>,
    ) -> Result<Vec<u8>> {
        let mut r = Renumber::default();
        if let Some((_, func, _)) = plan.export {
            r.index(func);
        }
        let mut slots = BTreeMap::new();
        for (offset, items) in &self.elements {
            for (i, func) in items.iter().enumerate() {
                if let Some(func) = func.filter(|f| plan.table_funcs.contains(f)) {
                    slots.insert(offset + i as i32, func);
                }
            }
        }
        for func in slots.values().chain(plan.placed.iter().map(|(f, _)| f)) {
            r.index(*func);
        }

        let (mut funcs, mut code, mut names) =
            (FunctionSection::new(), CodeSection::new(), NameMap::new());
        while let Some(old) = r.queue.pop_front() {
            let new = r.map[&old];
            let ty = self.func_types[old as usize];
            funcs.function(ty);
            if let Some(n) = name(old) {
                names.append(new, &n);
            }
            if let Some(slot) = plan.stubs.get(&old) {
                code.function(&self.stub(ty, *slot));
                continue;
            }
            if plan.deleted.contains(&old) {
                bail!(
                    "`{}` calls function {old}, which only main keeps",
                    plan.label
                );
            }
            let body = (old as usize)
                .checked_sub(self.imported_funcs)
                .and_then(|i| self.bodies.get(i))
                .with_context(|| format!("`{}` calls import {old} without a stub", plan.label))?;
            r.parse_function_body(&mut code, body.clone())
                .map_err(|e| anyhow::anyhow!("re-encoding function {old}: {e:?}"))?;
        }

        let mut module = wasm_encoder::Module::new();
        module.section(&RawSection {
            id: wasm_encoder::SectionId::Type as u8,
            data: self.types,
        });
        let mut imports = ImportSection::new();
        for (name, ty) in &self.imports {
            imports.import("__wasm_split", name, *ty);
        }
        module.section(&imports).section(&funcs);
        let mut exports = ExportSection::new();
        let table = (self.funcref_table != 0).then_some(self.funcref_table);
        let mut elements = ElementSection::new();
        if let Some((export, func, slot)) = plan.export {
            exports.export(export, ExportKind::Func, r.map[&func]);
            let at = ConstExpr::i32_const(slot as i32);
            elements.active(table, &at, Elements::Functions(vec![r.map[&func]].into()));
        }
        for (slot, func) in &slots {
            let at = ConstExpr::i32_const(*slot);
            elements.active(table, &at, Elements::Functions(vec![r.map[func]].into()));
        }
        for (func, slot) in &plan.placed {
            let at = ConstExpr::i32_const(*slot as i32);
            elements.active(table, &at, Elements::Functions(vec![r.map[func]].into()));
        }
        module.section(&exports).section(&elements);

        let mut data = DataSection::new();
        // Every segment stays, emptied, so `memory.init` and `data.drop` indices hold.
        for segment in &self.data {
            match &segment.active {
                Some((memory, offset)) => data.active(*memory, offset, []),
                None => data.passive([]),
            };
        }
        if let Some(Segment {
            active: Some((memory, _)),
            offset: Some(base),
            bytes,
        }) = self.data.first()
        {
            for &(offset, size) in &plan.data {
                let at = ConstExpr::i32_const(base + offset as i32);
                data.active(*memory, &at, bytes[offset..offset + size].iter().copied());
            }
        }
        if self.data_count {
            module.section(&DataCountSection { count: data.len() });
        }
        module.section(&code).section(&data);
        let mut name_section = NameSection::new();
        name_section.functions(&names);
        module.section(&name_section);
        if let Some(features) = self.target_features {
            module.section(&CustomSection {
                name: "target_features".into(),
                data: features.into(),
            });
        }
        Ok(module.finish())
    }

    /// A body passing its params to whatever main put in `slot`.
    fn stub(&self, ty: u32, slot: u32) -> Function {
        let mut f = Function::new([]);
        for local in 0..self.type_params[ty as usize] {
            f.instruction(&Instruction::LocalGet(local));
        }
        f.instruction(&Instruction::I32Const(slot as i32));
        f.instruction(&Instruction::CallIndirect {
            type_index: ty,
            table_index: self.funcref_table,
        });
        f.instruction(&Instruction::End);
        f
    }
}

/// Numbers functions in the order a part first reaches them, queueing each for emission.
#[derive(Default)]
struct Renumber {
    map: HashMap<u32, u32>,
    queue: VecDeque<u32>,
}

impl Renumber {
    fn index(&mut self, old: u32) -> u32 {
        let next = self.map.len() as u32;
        *self.map.entry(old).or_insert_with(|| {
            self.queue.push_back(old);
            next
        })
    }
}

impl Reencode for Renumber {
    type Error = std::convert::Infallible;

    fn function_index(&mut self, func: u32) -> Result<u32, ReencodeError<Self::Error>> {
        Ok(self.index(func))
    }
}

fn const_i32(expr: &wasmparser::ConstExpr) -> Option<i32> {
    let mut ops = expr.get_operators_reader();
    match (ops.read().ok()?, ops.read().ok()?) {
        (Operator::I32Const { value }, Operator::End) => Some(value),
        _ => None,
    }
}

fn ref_func(expr: &wasmparser::ConstExpr) -> Option<u32> {
    let mut ops = expr.get_operators_reader();
    match (ops.read().ok()?, ops.read().ok()?) {
        (Operator::RefFunc { function_index }, Operator::End) => Some(function_index),
        _ => None,
    }
}
