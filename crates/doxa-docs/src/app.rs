//! Handlers that mount themselves into services, under a state none of them names.

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};

use doxa_wire::RouteSpec;
use utoipa::openapi::OpenApi;
use utoipa_axum::router::{OpenApiRouter, UtoipaMethodRouter};

use crate::contribution::{apply_contribution, DocumentedLayer, LayerContribution};

/// Mounted routes, their state already applied.
pub type Routes = OpenApiRouter<()>;

/// `Key<crate>: Resolve<S>`: the crate's handlers share the state `S`.
#[diagnostic::on_unimplemented(
    message = "routes in this crate share a state: add `#[derive(doxa::State)]` to it",
    label = "no `#[derive(doxa::State)]` in this crate"
)]
pub trait Resolve<S> {}

/// A crate, by [`crate_key`] of its name.
pub struct Key<const N: u64>;

/// FNV-1a of a crate's name, so each crate's [`Resolve`] impl is its own.
pub const fn crate_key(name: Option<&str>) -> u64 {
    let bytes = match name {
        Some(name) => name.as_bytes(),
        None => b"",
    };
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(0x0100_0000_01b3);
        i += 1;
    }
    hash
}

/// One handler, submitted by its route attribute.
pub struct Mount {
    /// `module_path!()` where the handler is defined; it picks the service.
    pub module: &'static str,
    /// The handler's name.
    pub handler: &'static str,
    /// The declared route it implements, if any.
    pub declared: Option<&'static RouteSpec>,
    /// The handler routed under the given state, or `None` when it's another type.
    pub build: fn(&dyn Any) -> Option<Routes>,
    /// The handler's operation and schemas.
    pub doc: fn() -> OpenApi,
}

inventory::collect!(Mount);

/// One `#[doxa::service]`.
pub struct Service {
    /// The struct's name.
    pub name: &'static str,
    /// `module_path!()` of the struct: the service owns handlers in this module and below.
    pub module: &'static str,
    /// The stack its routes are wrapped in.
    pub layers: Option<Stacked>,
}

inventory::collect!(Service);

/// A `#[doxa::layers]` stack, type-erased.
#[derive(Clone, Copy)]
pub struct Stacked {
    /// The stack's function, or `None` when the state is another type.
    pub apply: fn(Routes, &dyn Any) -> Option<Routes>,
    /// What the stack adds to each operation.
    pub docs: fn() -> LayerContribution,
}

/// What a `docs = [...]` entry adds to each operation, without a state.
pub trait StackDocs {
    /// The contribution.
    fn docs() -> LayerContribution;
}

impl<T: DocumentedLayer + Default> StackDocs for T {
    fn docs() -> LayerContribution {
        T::default().contribution()
    }
}

/// A `#[doxa::layers]` function.
pub trait Layers: StackDocs {
    /// The state it reads.
    type State: 'static;
    /// Wrap `routes`.
    fn apply(routes: Routes, state: &Self::State) -> Routes;
}

/// `L` as a [`Stacked`].
pub const fn stacked<L: Layers>() -> Stacked {
    Stacked {
        apply: apply_stack::<L>,
        docs: L::docs,
    }
}

fn apply_stack<L: Layers>(routes: Routes, state: &dyn Any) -> Option<Routes> {
    Some(L::apply(routes, state.downcast_ref()?))
}

/// `routes` under `state`, where `S` is inferred from the crate's one [`Resolve`] impl.
pub fn mount<S, const K: u64>(routes: UtoipaMethodRouter<S>, state: &dyn Any) -> Option<Routes>
where
    S: Clone + Send + Sync + 'static,
    Key<K>: Resolve<S>,
{
    let state = state.downcast_ref::<S>()?;
    Some(
        OpenApiRouter::<S>::default()
            .routes(routes)
            .with_state(state.clone()),
    )
}

/// The document of `routes`, needing no state.
pub fn describe<S, const K: u64>(routes: UtoipaMethodRouter<S>) -> OpenApi
where
    S: Clone + Send + Sync + 'static,
    Key<K>: Resolve<S>,
{
    OpenApiRouter::<S>::default().routes(routes).into_openapi()
}

/// Every linked service with its handlers.
struct Plan {
    services: Vec<(&'static Service, Vec<&'static Mount>)>,
}

impl Plan {
    fn new() -> Self {
        let mut problems = Vec::new();
        let mut services: Vec<&'static Service> = inventory::iter::<Service>.into_iter().collect();
        services.sort_by_key(|s| (s.module, s.name));
        for pair in services.windows(2) {
            if pair[0].module == pair[1].module {
                problems.push(format!(
                    "`{}` and `{}` are both services of `{}`: a module has one, so move one \
                     into a module of its own",
                    pair[0].name, pair[1].name, pair[0].module
                ));
            }
        }

        let mut owned: Vec<Vec<&'static Mount>> = vec![Vec::new(); services.len()];
        let mut mounts: Vec<&'static Mount> = inventory::iter::<Mount>.into_iter().collect();
        mounts.sort_by_key(|m| (m.module, m.handler));
        for m in &mounts {
            let owner = services
                .iter()
                .enumerate()
                .filter(|(_, s)| within(m.module, s.module))
                .max_by_key(|(_, s)| s.module.len());
            match owner {
                Some((i, _)) => owned[i].push(m),
                None => problems.push(format!(
                    "`{}::{}` is under no service: add `#[doxa::service] pub struct …;` to its \
                     module or one above it",
                    m.module, m.handler
                )),
            }
        }

        problems.extend(unimplemented(&mounts));
        for (name, types) in crate::schemas::duplicate_schemas() {
            problems.push(format!(
                "the schema name `{name}` belongs to {}, and a document keeps only one: rename \
                 one with `#[schema(as = …)]`",
                types.join(" and ")
            ));
        }
        if !problems.is_empty() {
            panic!("this app can't start:\n  {}", problems.join("\n  "));
        }
        Plan {
            services: services.into_iter().zip(owned).collect(),
        }
    }
}

/// Declared routes no handler implements, in the API crates the app implements any route of.
fn unimplemented(mounts: &[&'static Mount]) -> Vec<String> {
    let done: Vec<&'static RouteSpec> = mounts.iter().filter_map(|m| m.declared).collect();
    let packages: BTreeSet<&str> = done.iter().map(|s| s.package).collect();
    let mut missing: BTreeMap<(&str, &str), &RouteSpec> = BTreeMap::new();
    for d in inventory::iter::<crate::contract::Declared> {
        let spec = d.0;
        if packages.contains(spec.package)
            && !done
                .iter()
                .any(|s| s.method == spec.method && s.path == spec.path)
        {
            missing.insert((spec.path, spec.method.as_str()), spec);
        }
    }
    missing
        .values()
        .map(|s| {
            format!(
                "{} declares `{}` ({} {}), which no handler implements: add \
                 `#[doxa::implements({}::{})]` to one",
                s.package,
                s.operation_id,
                s.method.as_str(),
                s.path,
                s.package.replace('-', "_"),
                s.operation_id
            )
        })
        .collect()
}

fn within(module: &str, service: &str) -> bool {
    module == service
        || module
            .strip_prefix(service)
            .is_some_and(|rest| rest.starts_with("::"))
}

/// Every mounted handler under `state`, each wrapped in its service's layers.
///
/// Panics, naming each problem, on a handler under no service, two services in one module, a
/// declared route nothing implements, a schema name two types claim, or a state the handlers
/// weren't written for.
pub fn app<S: Any>(state: &S) -> Routes {
    let plan = Plan::new();
    let mut app = Routes::default();
    for (service, mounts) in plan.services {
        let mut routes = Routes::default();
        for m in mounts {
            let built = (m.build)(state).unwrap_or_else(|| {
                panic!(
                    "`{}::{}` reads another state than `{}`",
                    m.module,
                    m.handler,
                    std::any::type_name::<S>()
                )
            });
            routes = routes.merge(built);
        }
        if let Some(stack) = service.layers {
            apply_contribution(routes.get_openapi_mut(), &(stack.docs)());
            routes = (stack.apply)(routes, state).unwrap_or_else(|| {
                panic!(
                    "the layers of `{}` read another state than `{}`",
                    service.name,
                    std::any::type_name::<S>()
                )
            });
        }
        app = app.merge(routes);
    }
    app
}

/// The document [`app`] serves, layer docs included, built with no state.
///
/// Panics on the problems [`app`] does, so a test calling it checks them.
pub fn spec() -> OpenApi {
    let plan = Plan::new();
    let mut api = Routes::default().into_openapi();
    for (service, mounts) in plan.services {
        let mut part = Routes::default().into_openapi();
        for m in mounts {
            part.merge((m.doc)());
        }
        if let Some(stack) = service.layers {
            apply_contribution(&mut part, &(stack.docs)());
        }
        api.merge(part);
    }
    api
}
