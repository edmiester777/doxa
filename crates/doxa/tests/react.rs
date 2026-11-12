//! `#[react]` islands against a fake JS side.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use doxa::ui::dom::{Dom, MemDom};
use doxa::ui::prelude::*;
use doxa::ui::react::{
    AsyncFunc, AsyncFuncFn, Bridge, Content, EventFn, Func, FuncFn, IslandProps, Mount, Render,
    RenderFns, Shell, SlotPlacer,
};

#[react(module = "./ts/editor.tsx", export = "Editor")]
pub struct Editor {
    pub value: String,
    #[react(optional)]
    pub read_only: Option<bool>,
    #[react(rename = "aria-label")]
    pub label: String,
    pub children: String,
    #[react(event)]
    pub on_change: impl Fn(String),
    #[react(event)]
    pub on_blur: impl Fn(),
}

#[react(module = "./ts/monaco.tsx", export = "default", lazy)]
pub struct Monaco {
    pub value: String,
}

#[react(module = "./ts/dialog.tsx", export = "Dialog")]
pub struct Dialog {
    pub title: String,
    pub children: View,
}

#[derive(Default)]
struct Calls {
    log: Vec<String>,
    hosts: Vec<u32>,
    slots: Rc<SlotPlacer>,
    parents: Vec<(&'static str, Option<u32>)>,
    roots: Vec<u64>,
    events: HashMap<u32, Vec<(&'static str, EventFn)>>,
    errors: HashMap<u32, EventFn>,
    shells: HashMap<u32, Vec<Shell>>,
    funcs: HashMap<u32, Vec<(&'static str, FuncFn)>>,
    async_funcs: HashMap<u32, Vec<(&'static str, AsyncFuncFn)>>,
    renders: HashMap<u32, Vec<(&'static str, RenderFns)>>,
    handles: HashMap<u32, doxa::ui::react::HandleSink>,
    feeds: HashMap<u32, Vec<(&'static str, doxa::ui::react::FeedFns)>>,
    holes: Vec<(u32, Option<u32>)>,
}

#[derive(Clone, Default)]
struct Fake(Rc<RefCell<Calls>>);

/// The props as sorted JSON, then any slot names and element shells.
fn describe(c: &Content) -> String {
    let map: std::collections::BTreeMap<_, _> = c.props.iter().collect();
    let mut out = serde_json::to_string(&map).unwrap();
    if !c.slots.is_empty() {
        let names: Vec<_> = c.slots.iter().map(|(n, _)| *n).collect();
        out.push_str(&format!(" slots:{}", names.join(",")));
    }
    for (name, _) in &c.raw {
        out.push_str(&format!(" raw:{name}"));
    }
    for (name, _) in &c.feeds {
        out.push_str(&format!(" feed:{name}"));
    }
    for (name, _) in &c.js {
        out.push_str(&format!(" js:{name}"));
    }
    for s in &c.shells {
        let attrs: Vec<_> = s.attrs.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let events: Vec<_> = s.events.iter().map(|(n, _)| *n).collect();
        out.push_str(&format!(
            " {}=<{} {}|{}>",
            s.prop,
            s.tag,
            attrs.join(" "),
            events.join(",")
        ));
    }
    out
}

impl Bridge for Fake {
    fn mount(&self, m: Mount<'_>) {
        let mut c = self.0.borrow_mut();
        c.log.push(format!(
            "mount {} {} {}",
            m.island.name,
            m.id,
            describe(m.content)
        ));
        c.hosts.push(m.host.id());
        c.parents.push((m.island.name, m.parent));
        c.roots.push(m.root);
        c.events.insert(m.id, m.events);
        c.errors.insert(m.id, m.on_error);
        c.shells.insert(m.id, m.content.shells.clone());
        c.feeds.insert(m.id, m.content.feeds.clone());
        c.funcs.insert(m.id, m.funcs);
        c.async_funcs.insert(m.id, m.async_funcs);
        c.renders.insert(m.id, m.renders);
        if let Some(h) = m.on_handle {
            c.handles.insert(m.id, h);
        }
        let slots = c.slots.clone();
        drop(c);
        slots.mount(m.id, m.host, &m.content.slots);
    }

    fn update(&self, id: u32, content: &Content) {
        let mut c = self.0.borrow_mut();
        c.log.push(format!("update {id} {}", describe(content)));
        c.shells.insert(id, content.shells.clone());
        let slots = c.slots.clone();
        drop(c);
        slots.update(id, &content.slots);
    }

    fn unmount(&self, id: u32) {
        self.0.borrow_mut().log.push(format!("unmount {id}"));
        let slots = self.0.borrow().slots.clone();
        slots.unmount(id);
    }

    fn children(&self, key: u32, node: Option<doxa::ui::NodeRef>) {
        self.0.borrow_mut().holes.push((key, node.map(|n| n.id())));
    }
}

impl Fake {
    fn log(&self) -> Vec<String> {
        std::mem::take(&mut self.0.borrow_mut().log)
    }

    fn fire(&self, id: u32, event: &str, json: &str) {
        let f = self.0.borrow().events[&id]
            .iter()
            .find(|(n, _)| *n == event)
            .map(|(_, f)| f.clone())
            .expect("event passed at mount");
        f(json);
    }
}

thread_local! {
    static SEEN: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

#[component]
fn Page() -> View {
    let text = state(String::from("a"));
    let shown = state(true);
    let tick = state(0u32);
    let t = tick.get();
    view! {
        <button id="edit" on:click={move |_| text.set("b".into())}>"edit"</button>
        <button id="tick" on:click={move |_| tick.update(|t| *t += 1)}>"tick"</button>
        <button id="hide" on:click={move |_| shown.toggle()}>"hide"</button>
        {shown.get().then(|| view! {
            <Editor
                value={text.get()}
                label="Source"
                on_change={move |v: String| SEEN.with(|s| s.borrow_mut().push(format!("{t}:{v}")))}
                on_blur={move || SEEN.with(|s| s.borrow_mut().push(format!("{t}:blur")))}
            >
                "hello"
            </Editor>
        })}
    }
}

fn mount() -> (MemDom, Fake) {
    let fake = Fake::default();
    doxa::ui::react::set_bridge(fake.clone());
    let dom = MemDom::new();
    App::new(|| view! { <Page/> })
        .mount_on(Rc::new(dom.clone()), dom.body())
        .keep();
    (dom, fake)
}

fn click(dom: &MemDom, id: &str) {
    dom.click(dom.find("id", id).unwrap());
    doxa::client::task::run_until_stalled();
}

#[test]
fn an_island_mounts_updates_and_unmounts_through_the_bridge() {
    let (dom, fake) = mount();
    assert_eq!(
        fake.log(),
        [r#"mount Editor 1 {"aria-label":"Source","children":"hello","value":"a"}"#]
    );
    let host = dom.find("data-island", "Editor").unwrap();
    assert_eq!(fake.0.borrow().hosts, [host]);

    click(&dom, "edit");
    assert_eq!(
        fake.log(),
        [r#"update 1 {"aria-label":"Source","children":"hello","value":"b"}"#]
    );

    click(&dom, "hide");
    assert_eq!(fake.log(), ["unmount 1"]);
    assert_eq!(dom.find("data-island", "Editor"), None);
}

#[test]
fn unchanged_props_are_not_sent_again() {
    let (dom, fake) = mount();
    fake.log();
    click(&dom, "tick");
    click(&dom, "tick");
    assert_eq!(fake.log(), Vec::<String>::new());
}

#[test]
fn an_event_keeps_its_js_function_and_reaches_the_latest_handler() {
    let (dom, fake) = mount();
    fake.fire(1, "onChange", r#""x""#);
    click(&dom, "tick");
    fake.fire(1, "onChange", r#""y""#);
    fake.fire(1, "onBlur", "{}");
    assert_eq!(
        SEEN.with(|s| s.take()),
        ["0:x", "1:y", "1:blur"],
        "the function from mount calls this render's closure"
    );
}

#[test]
fn the_island_names_its_module() {
    let e = <EditorProps as IslandProps>::ISLAND;
    assert_eq!(
        (e.module, e.export, e.lazy),
        ("doxa-island:ts/editor.tsx", "Editor", false)
    );
    let m = <MonacoProps as IslandProps>::ISLAND;
    assert_eq!(
        (m.module, m.export, m.lazy),
        ("doxa-island:ts/monaco.tsx", "default", true)
    );
}

#[test]
fn an_optional_prop_is_left_out_only_when_none() {
    let fake = Fake::default();
    doxa::ui::react::set_bridge(fake.clone());
    let dom = MemDom::new();
    App::new(|| {
        view! {
            <Editor
                value="v"
                label="l"
                read_only={Some(true)}
                on_change={|_: String| {}}
                on_blur={|| {}}
            />
        }
    })
    .mount_on(Rc::new(dom.clone()), dom.body())
    .keep();
    assert_eq!(
        fake.log(),
        [r#"mount Editor 1 {"aria-label":"l","children":"","readOnly":true,"value":"v"}"#]
    );
}

#[component]
fn Confirm() -> View {
    let n = state(0u32);
    view! {
        <Dialog title="Sure?">
            <button on:click={move |_| n.update(|n| *n += 1)}>{n.get()}</button>
        </Dialog>
    }
}

#[test]
fn view_children_render_before_the_marker_react_places() {
    let fake = Fake::default();
    doxa::ui::react::set_bridge(fake.clone());
    let dom = MemDom::new();
    App::new(|| view! { <Confirm/> })
        .mount_on(Rc::new(dom.clone()), dom.body())
        .keep();
    doxa::client::task::run_until_stalled();
    assert_eq!(
        fake.log(),
        [r#"mount Dialog 1 {"title":"Sure?"} slots:children"#]
    );

    let marker = dom
        .find("data-island-slot", "children")
        .expect("the marker React rendered");
    let button = dom.find_tag("button").expect("the slot rendered");
    assert_eq!(
        dom.next_sibling(button),
        Some(marker),
        "right before the marker, with no host around it"
    );
    dom.click(button);
    doxa::client::task::run_until_stalled();
    assert_eq!(dom.text(button), "1", "doxa keeps rendering the children");
    assert_eq!(fake.log(), Vec::<String>::new(), "React sees no new props");
}

#[react(module = "./ts/theme.tsx", export = "ThemeProvider")]
pub struct ThemeProvider {
    pub theme: String,
    pub children: View,
}

#[react(module = "./ts/badge.tsx", export = "Badge")]
pub struct Badge {
    pub label: String,
}

#[component]
fn Toolbar() -> View {
    view! {
        <nav>
            <Badge label="inner"/>
        </nav>
    }
}

#[test]
fn a_nested_island_mounts_inside_the_island_around_it() {
    let fake = Fake::default();
    doxa::ui::react::set_bridge(fake.clone());
    let dom = MemDom::new();
    App::new(|| {
        view! {
            <ThemeProvider theme="dark">
                <Toolbar/>
            </ThemeProvider>
            <Badge label="outer"/>
        }
    })
    .mount_on(Rc::new(dom.clone()), dom.body())
    .keep();
    doxa::client::task::run_until_stalled();
    let mut parents = fake.0.borrow().parents.clone();
    parents.sort();
    assert_eq!(
        parents,
        [("Badge", None), ("Badge", Some(1)), ("ThemeProvider", None)],
        "the badge under the provider, through a doxa component, is its child"
    );
}

#[test]
fn each_island_names_the_root_it_is_in() {
    let fake = Fake::default();
    doxa::ui::react::set_bridge(fake.clone());
    let dom = MemDom::new();
    let doc: Rc<dyn doxa::ui::dom::Dom> = Rc::new(dom.clone());
    let a =
        App::new(|| view! { <Monaco value={"a".to_string()}/> }).mount_on(doc.clone(), dom.body());
    let b = App::embedded(|| view! { <Monaco value={"b".to_string()}/> }).mount_on(doc, dom.body());
    assert_eq!(fake.0.borrow().roots, [a.id(), b.id()]);
    drop(b);
    assert!(
        fake.0.borrow().log.last().unwrap().starts_with("unmount"),
        "dropping a root unmounts its islands"
    );
    a.keep();
}

#[component]
fn TwoEditors() -> View {
    let caught = |e: &Thrown| view! { <p class="err">{e.to_string()}</p> };
    view! {
        <Catch fallback={caught}>
            <Monaco value={"a".to_string()}/>
        </Catch>
        <Catch fallback={caught}>
            <Monaco value={"b".to_string()}/>
        </Catch>
    }
}

#[test]
fn an_island_that_throws_in_react_reaches_its_catch_and_spares_its_siblings() {
    let fake = Fake::default();
    doxa::ui::react::set_bridge(fake.clone());
    let dom = MemDom::new();
    App::new(|| view! { <TwoEditors/> })
        .mount_on(Rc::new(dom.clone()), dom.body())
        .keep();
    let ids: Vec<u32> = fake.0.borrow().errors.keys().copied().collect();
    let (first, second) = (*ids.iter().min().unwrap(), *ids.iter().max().unwrap());
    fake.log();
    let fail = fake.0.borrow().errors[&first].clone();
    fail("editor exploded");
    doxa::client::task::run_until_stalled();
    let err = dom.find("class", "err").expect("the catch shows");
    assert_eq!(dom.text(err), "<Monaco> threw in React: editor exploded");
    assert_eq!(
        fake.log(),
        [format!("unmount {first}")],
        "island {second} stays"
    );
}

#[react(module = "./ts/popover.tsx", export = "Popover.Trigger")]
pub struct PopoverTrigger {
    #[react(element)]
    pub render: View,
    pub icon: Option<View>,
    pub children: View,
}

#[component]
fn Filter() -> View {
    let with_icon = state(false);
    view! {
        <i id="icon" on:click={move |_| with_icon.toggle()}/>
        <PopoverTrigger
            render={view! { <button class="btn" on:click={|_| ()}>"Filter"</button> }}
            icon={with_icon.get().then(|| view! { <b>"*"</b> })}
        />
    }
}

#[test]
fn an_element_prop_is_rendered_by_react_with_doxa_children_inside() {
    use doxa::ui::dom::Dom;
    let fake = Fake::default();
    doxa::ui::react::set_bridge(fake.clone());
    let dom = MemDom::new();
    App::new(|| view! { <Filter/> })
        .mount_on(Rc::new(dom.clone()), dom.body())
        .keep();
    assert_eq!(
        <PopoverTriggerProps as IslandProps>::ISLAND.export,
        "Popover.Trigger"
    );
    assert_eq!(
        fake.log(),
        ["mount PopoverTrigger 1 {} slots:children render=<button class=btn|click>"]
    );

    // React commits its element; doxa fills it.
    let shell = fake.0.borrow().shells[&1][0].clone();
    let button = dom.create_element("button", None);
    dom.insert(dom.body(), button, None);
    (shell.node)(Some(doxa::ui::NodeRef::from_id(button)));
    doxa::client::task::run_until_stalled();
    assert_eq!(dom.text(button), "Filter");

    // A second slot appearing is an update; the element and its children stay.
    dom.click(dom.find("id", "icon").unwrap());
    doxa::client::task::run_until_stalled();
    assert_eq!(
        fake.log(),
        ["update 1 {} slots:icon,children render=<button class=btn|click>"]
    );
    assert_eq!(dom.text(button), "Filter");

    (shell.node)(None);
    doxa::client::task::run_until_stalled();
    assert_eq!(dom.text(button), "");
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Row {
    id: u32,
    name: String,
}

#[react(module = "./ts/data-table.tsx", export = "DataTable")]
pub struct DataTable {
    pub rows: Vec<Row>,
    #[react(func)]
    pub row_id: Func<Row, String>,
    #[react(func)]
    pub load_more: AsyncFunc<u32, Vec<Row>>,
    #[react(render)]
    pub cell: Render<(Row, String)>,
}

#[derive(Clone)]
struct Tone(&'static str);

#[component]
fn CellText(text: String) -> View {
    let tone = context::<Tone>();
    view! { <span>{format!("{} {text}", tone.0)}</span> }
}

#[component]
fn Table() -> View {
    provide(Tone("loud"));
    view! {
        <DataTable
            rows={Vec::new()}
            row_id={|r: Row| format!("row-{}", r.id)}
            load_more={async |n: u32| Ok((0..n).map(|id| Row { id, name: "r".into() }).collect())}
            cell={|(row, col): (Row, String)| view! {
                <CellText text={format!("{}:{col}", row.name)}/>
            }}
        />
    }
}

thread_local! {
    static PROBE: RefCell<Option<FuncFn>> = const { RefCell::new(None) };
    static PROBED: RefCell<Vec<Result<serde_json::Value, String>>> = const { RefCell::new(Vec::new()) };
}

#[component]
fn Prober(n: u32) -> View {
    if let Some(f) = PROBE.with(|p| p.borrow().clone()) {
        PROBED.with(|p| {
            p.borrow_mut()
                .push(f(serde_json::json!({"id": n, "name": "x"})))
        });
    }
    view! { <b>{n}</b> }
}

#[test]
fn react_calls_funcs_awaits_async_funcs_and_places_renders() {
    use doxa::ui::dom::Dom;
    let fake = Fake::default();
    doxa::ui::react::set_bridge(fake.clone());
    let dom = MemDom::new();
    App::new(|| view! { <Table/> })
        .mount_on(Rc::new(dom.clone()), dom.body())
        .keep();
    let settle = doxa::client::task::run_until_stalled;
    let row_id = fake.0.borrow().funcs[&1][0].1.clone();
    assert_eq!(
        row_id(serde_json::json!({"id": 3, "name": "x"})),
        Ok(serde_json::json!("row-3"))
    );
    assert!(row_id(serde_json::json!("nope"))
        .unwrap_err()
        .contains("wrong arguments"));

    let load_more = fake.0.borrow().async_funcs[&1][0].1.clone();
    let page = doxa::client::task::block_on(load_more(serde_json::json!(2))).unwrap();
    assert_eq!(page.as_array().map(Vec::len), Some(2));

    // React mounts the render before a marker it owns; doxa fills in context from the island.
    let cell = fake.0.borrow().renders[&1][0].1.clone();
    let el = dom.create_element("td", None);
    dom.insert(dom.body(), el, None);
    let marker = dom.create_element("template", None);
    dom.insert(el, marker, None);
    (cell.mount)(
        7,
        doxa::ui::NodeRef::from_id(marker),
        serde_json::json!([{"id": 1, "name": "a"}, "name"]),
    );
    settle();
    assert_eq!(dom.text(el), "loud a:name");
    (cell.update)(7, serde_json::json!([{"id": 1, "name": "b"}, "name"]));
    settle();
    assert_eq!(dom.text(el), "loud b:name");
    (cell.unmount)(7);
    settle();
    assert_eq!(dom.text(el), "");

    // A Func called while doxa renders is refused rather than re-entering it.
    PROBE.with(|p| *p.borrow_mut() = Some(row_id));
    let _probe =
        App::new(|| view! { <Prober n={1u32}/> }).mount_on(Rc::new(dom.clone()), dom.body());
    settle();
    let probed = PROBED.with(|p| p.take());
    assert!(
        probed.iter().all(|r| r
            .as_ref()
            .is_err_and(|e| e.contains("while doxa was rendering"))),
        "{probed:?}"
    );
}

#[derive(Clone, Debug, PartialEq)]
pub struct CodeApi(&'static str);

#[react(module = "./ts/code.tsx", export = "Code", handle = CodeApi, lazy)]
pub struct Code {
    pub value: String,
}

thread_local! {
    static READY: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
}

#[component]
fn Coded() -> View {
    let ed = doxa::ui::react::handle::<Code>();
    effect((), async move |_| {
        let api = ed.ready().await;
        READY.with(|r| r.borrow_mut().push(api.0));
        Ok(())
    });
    view! {
        <Code handle={ed} value={"x".to_string()}/>
        <p>{ed.get().map_or("none", |a| a.0)}</p>
    }
}

#[test]
fn a_handle_is_ready_once_react_publishes_it() {
    let fake = Fake::default();
    doxa::ui::react::set_bridge(fake.clone());
    let dom = MemDom::new();
    App::new(|| view! { <Coded/> })
        .mount_on(Rc::new(dom.clone()), dom.body())
        .keep();
    let settle = doxa::client::task::run_until_stalled;
    settle();
    let p = || dom.text(dom.find_tag("p").unwrap());
    assert_eq!(p(), "none");
    assert!(READY.with(|r| r.borrow().is_empty()), "ready() waits");

    let publish = fake
        .0
        .borrow()
        .handles
        .values()
        .next()
        .cloned()
        .expect("a handle sink");
    publish(Some(Rc::new(CodeApi("api"))));
    settle();
    assert_eq!(p(), "api", "readers re-render");
    assert_eq!(READY.with(|r| r.take()), ["api"]);

    publish(None);
    settle();
    assert_eq!(p(), "none");
}

#[react(module = "./ts/plot.tsx", export = "Plot")]
pub struct Plot {
    #[react(raw)]
    pub ys: Rc<[f64]>,
    #[react(feed)]
    pub log: doxa::ui::react::Feed<String>,
}

#[component]
fn Charted() -> View {
    let ys = state::<Rc<[f64]>>(Rc::from(vec![1.0, 2.0]));
    let tick = state(0u32);
    let log = doxa::ui::react::feed::<String>(2);
    let _ = tick.get();
    view! {
        <button id="tick" on:click={move |_| tick.update(|t| *t += 1)}>"tick"</button>
        <button id="more" on:click={move |_| ys.set(Rc::from(vec![1.0, 2.0, 3.0]))}>"more"</button>
        <button
            id="say"
            on:click={{ let log = log.clone(); move |_| log.push(format!("line {}", tick.get())) }}
        >
            "say"
        </button>
        <Plot ys={ys.get()} log={log.clone()}/>
    }
}

#[test]
fn a_raw_array_is_sent_once_per_allocation_and_a_feed_streams() {
    let (fake, dom) = {
        let fake = Fake::default();
        doxa::ui::react::set_bridge(fake.clone());
        let dom = MemDom::new();
        App::new(|| view! { <Charted/> })
            .mount_on(Rc::new(dom.clone()), dom.body())
            .keep();
        (fake, dom)
    };
    assert_eq!(fake.log(), ["mount Plot 1 {} raw:ys feed:log"]);
    click(&dom, "tick");
    assert!(fake.log().is_empty(), "the same Rc isn't sent again");
    click(&dom, "more");
    assert_eq!(fake.log(), ["update 1 {} raw:ys feed:log"]);

    for _ in 0..3 {
        click(&dom, "say");
    }
    let feed = fake.0.borrow().feeds[&1][0].1.clone();
    let got = Rc::new(RefCell::new(Vec::new()));
    let sink = got.clone();
    let id = (feed.subscribe)(Rc::new(move |v| sink.borrow_mut().push(v)));
    assert_eq!(
        *got.borrow(),
        [serde_json::json!("line 1"), serde_json::json!("line 1")],
        "the last two, as backlog"
    );
    click(&dom, "say");
    assert_eq!(got.borrow().len(), 3, "then live");
    (feed.unsubscribe)(id);
    click(&dom, "say");
    assert_eq!(got.borrow().len(), 3);
}

#[derive(Clone, serde::Deserialize)]
pub struct CodeArgs {
    #[serde(rename = "className", default)]
    class_name: Option<String>,
    children: String,
}

#[react(module = "./ts/markdown.tsx", export = "Markdown")]
pub struct Markdown {
    pub children: String,
    #[react(js)]
    pub remark_plugins: Vec<doxa::ui::Js>,
    #[react(js)]
    pub url_transform: Option<doxa::ui::Js>,
    #[react(rename = "options.depth")]
    pub depth: u32,
    #[react(component, rename = "components.code")]
    pub code: doxa::ui::react::ComponentFn<CodeArgs>,
    #[react(element, rename = "icons.success")]
    pub success: View,
}

#[component]
fn Doc() -> View {
    let transform = state(false);
    let plugins = vec![
        doxa::ui::Js::json("gfm"),
        doxa::ui::Js::array([doxa::ui::Js::json("sanitize"), doxa::ui::Js::json(&1)]),
    ];
    view! {
        <button id="transform" on:click={move |_| transform.set(true)}>"t"</button>
        <Markdown
            remark_plugins={plugins}
            url_transform={transform.get().then(|| doxa::ui::Js::json("same-origin"))}
            depth={2u32}
            code={|p: CodeArgs, children: View| view! {
                <code class={p.class_name.unwrap_or_default()}>
                    {p.children}
                    {children}
                </code>
            }}
            success={view! { <svg class="ok"/> }}
        >
            "hi"
        </Markdown>
    }
}

#[test]
fn js_values_pass_untouched_and_dotted_names_reach_react_as_paths() {
    use doxa::ui::dom::Dom;
    let fake = Fake::default();
    doxa::ui::react::set_bridge(fake.clone());
    let dom = MemDom::new();
    App::new(|| view! { <Doc/> })
        .mount_on(Rc::new(dom.clone()), dom.body())
        .keep();
    assert_eq!(
        fake.log(),
        [
            r#"mount Markdown 1 {"children":"hi","options.depth":2} js:remarkPlugins icons.success=<svg class=ok|>"#
        ],
        "a `None` js value is left out; the runtime nests dotted names"
    );

    click(&dom, "transform");
    assert_eq!(
        fake.log(),
        [
            r#"update 1 {"children":"hi","options.depth":2} js:remarkPlugins js:urlTransform icons.success=<svg class=ok|>"#
        ]
    );

    // React renders the component with its props; doxa reads the ones it declared.
    let code = fake.0.borrow().renders[&1]
        .iter()
        .find(|(n, _)| *n == "components.code")
        .map(|(_, f)| f.clone())
        .expect("the component is passed");
    assert!(
        code.component,
        "React gets it as a component, not a render prop"
    );
    let el = dom.create_element("div", None);
    dom.insert(dom.body(), el, None);
    let marker = dom.create_element("template", None);
    dom.insert(el, marker, None);
    (code.mount)(
        1,
        doxa::ui::NodeRef::from_id(marker),
        serde_json::json!({"className": "language-rs", "children": "fn x", "node": {"type": "element"}}),
    );
    doxa::client::task::run_until_stalled();
    let shown = dom.find("class", "language-rs").expect("the code view");
    assert_eq!(dom.text(shown), "fn x");
    let hole = dom
        .find("data-react-children", "")
        .expect("a hole for React's children");
    assert_eq!(
        fake.0.borrow().holes,
        [(1, Some(hole))],
        "the bridge is told where they go"
    );
    (code.unmount)(1);
    doxa::client::task::run_until_stalled();
    assert_eq!(fake.0.borrow().holes.last(), Some(&(1, None)));
}
