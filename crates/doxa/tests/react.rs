//! `#[react]` islands against a fake JS side.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use doxa::ui::dom::MemDom;
use doxa::ui::prelude::*;
use doxa::ui::react::{Bridge, EventFn, IslandProps, Mount, Props};
use doxa::ui::NodeRef;

#[react(module = "./ts/editor.tsx", export = "Editor")]
pub struct Editor {
    pub value: String,
    #[react(optional)]
    pub read_only: Option<bool>,
    #[react(rename = "aria-label")]
    pub label: String,
    pub children: String,
    #[react(event)]
    pub on_change: Callback<String>,
    #[react(event)]
    pub on_blur: Callback<()>,
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
    children: Vec<Option<u32>>,
    parents: Vec<(&'static str, Option<u32>)>,
    roots: Vec<u64>,
    events: HashMap<u32, Vec<(&'static str, EventFn)>>,
}

#[derive(Clone, Default)]
struct Fake(Rc<RefCell<Calls>>);

fn sorted(props: &Props) -> String {
    let map: std::collections::BTreeMap<_, _> = props.iter().collect();
    serde_json::to_string(&map).unwrap()
}

impl Bridge for Fake {
    fn mount(&self, m: Mount<'_>) {
        let mut c = self.0.borrow_mut();
        c.log.push(format!(
            "mount {} {} {}",
            m.island.name,
            m.id,
            sorted(m.props)
        ));
        c.hosts.push(m.host.id());
        c.children.push(m.children.map(NodeRef::id));
        c.parents.push((m.island.name, m.parent));
        c.roots.push(m.root);
        c.events.insert(m.id, m.events);
    }

    fn update(&self, id: u32, props: &Props) {
        self.0
            .borrow_mut()
            .log
            .push(format!("update {id} {}", sorted(props)));
    }

    fn unmount(&self, id: u32) {
        self.0.borrow_mut().log.push(format!("unmount {id}"));
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
                on_blur={move |()| SEEN.with(|s| s.borrow_mut().push(format!("{t}:blur")))}
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
                on_blur={|()| {}}
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
fn view_children_render_into_a_host_the_island_is_given() {
    let fake = Fake::default();
    doxa::ui::react::set_bridge(fake.clone());
    let dom = MemDom::new();
    App::new(|| view! { <Confirm/> })
        .mount_on(Rc::new(dom.clone()), dom.body())
        .keep();
    assert_eq!(fake.log(), [r#"mount Dialog 1 {"title":"Sure?"}"#]);

    let host = dom
        .find("data-island-children", "")
        .expect("a children host");
    assert_eq!(fake.0.borrow().children, [Some(host)]);
    let button = dom.find_tag("button").unwrap();
    dom.click(button);
    doxa::client::task::run_until_stalled();
    assert_eq!(dom.text(host), "1", "doxa keeps rendering the children");
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
