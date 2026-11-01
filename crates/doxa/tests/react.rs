//! `#[react]` islands against a fake JS side.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use doxa::ui::dom::MemDom;
use doxa::ui::prelude::*;
use doxa::ui::react::{Bridge, EventFn, Island, IslandProps};
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

#[react(module = "@monaco-editor/react", export = "default", lazy)]
pub struct Monaco {
    pub value: String,
}

#[derive(Default)]
struct Calls {
    log: Vec<String>,
    hosts: Vec<u32>,
    events: HashMap<u32, Vec<(&'static str, EventFn)>>,
    next: u32,
}

#[derive(Clone, Default)]
struct Fake(Rc<RefCell<Calls>>);

fn sorted(json: &str) -> String {
    let map: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_str(json).expect("props are a JSON object");
    serde_json::to_string(&map).unwrap()
}

impl Bridge for Fake {
    fn mount(
        &self,
        host: NodeRef,
        island: &Island,
        props: &str,
        events: Vec<(&'static str, EventFn)>,
    ) -> u32 {
        let mut c = self.0.borrow_mut();
        c.next += 1;
        let id = c.next;
        c.log
            .push(format!("mount {} {id} {}", island.name, sorted(props)));
        c.hosts.push(host.id());
        c.events.insert(id, events);
        id
    }

    fn update(&self, id: u32, props: &str) {
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
    App::new(|| view! { <Page/> }).mount_on(Rc::new(dom.clone()), dom.body());
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
        ("@monaco-editor/react", "default", true)
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
    .mount_on(Rc::new(dom.clone()), dom.body());
    assert_eq!(
        fake.log(),
        [r#"mount Editor 1 {"aria-label":"l","children":"","readOnly":true,"value":"v"}"#]
    );
}
