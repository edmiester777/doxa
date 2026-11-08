// The React side of doxa islands: one root, created on first mount. A nested island is a
// portal inside the island around it, so it gets that island's React context. In a library,
// each exported component's wrapper renders its root's islands instead, inside the host's tree.
import {
  Component,
  createElement,
  Fragment,
  memo,
  Suspense,
  useLayoutEffect,
  useRef,
  useSyncExternalStore,
} from "react";
import { createPortal } from "react-dom";
import { createRoot } from "react-dom/client";

const islands = new Map();
const listeners = new Set();
let version = 0;
let root = null;
let library = false;

// Called by a library's entry before anything mounts: no root of our own.
export function libraryMode() {
  library = true;
}

function publish() {
  version++;
  for (const l of listeners) l();
}

function subscribe(l) {
  listeners.add(l);
  return () => listeners.delete(l);
}

// Moves a slot's host, which doxa renders into, to where React puts that prop, and shows it there.
function Adopt({ node }) {
  const ref = useRef(null);
  useLayoutEffect(() => {
    const el = ref.current;
    el.appendChild(node);
    node.style.display = "contents";
    return () => {
      node.style.display = "none";
      if (node.parentNode === el) el.removeChild(node);
    };
  }, [node]);
  return createElement("div", { ref, style: { display: "contents" } });
}

const IslandView = memo(({ component, props, handle }) =>
  createElement(component, handle === undefined ? props : { ...props, ref: handle }),
);

// One per island, so a throwing island goes blank and tells Rust instead of unmounting the shared root.
class Boundary extends Component {
  constructor(props) {
    super(props);
    this.state = { failed: false };
  }
  static getDerivedStateFromError() {
    return { failed: true };
  }
  componentDidCatch(error) {
    this.props.onError(String(error?.message ?? error));
  }
  render() {
    return this.state.failed ? null : this.props.children;
  }
}

// The islands whose nearest island is `parent`; `null` for the top ones, which also takes
// orphans, of every doxa root or only `root`.
export function Portals({ parent = null, root }) {
  useSyncExternalStore(subscribe, () => version);
  const mine = [...islands.values()].filter((i) =>
    parent === null
      ? !islands.has(i.parent) && (root === undefined || i.root === root)
      : i.parent === parent,
  );
  return mine.map((i) =>
    createPortal(
      createElement(
        Boundary,
        { onError: i.onError },
        createElement(Suspense, { fallback: null }, createElement(IslandView, { component: i.component, props: i.props, handle: i.ref })),
      ),
      i.host,
      String(i.id),
    ),
  );
}

function toJson(value) {
  try {
    return JSON.stringify(value) ?? "null";
  } catch {
    return "null";
  }
}

// doxa's DOM event names as React prop names: `click` → `onClick`, `keydown` → `onKeyDown`.
const REACT_EVENTS = {};
for (const name of [
  "Click", "DoubleClick", "ContextMenu", "KeyDown", "KeyUp", "KeyPress", "Focus", "Blur", "Change",
  "Input", "Submit", "Wheel", "Scroll", "PointerDown", "PointerUp", "PointerMove", "PointerEnter",
  "PointerLeave", "PointerOver", "PointerOut", "PointerCancel", "MouseDown", "MouseUp", "MouseMove",
  "MouseEnter", "MouseLeave", "MouseOver", "MouseOut", "TouchStart", "TouchEnd", "TouchMove",
  "DragStart", "Drag", "DragEnd", "DragEnter", "DragLeave", "DragOver", "Drop",
]) {
  REACT_EVENTS[name.toLowerCase()] = "on" + name;
}
REACT_EVENTS.dblclick = "onDoubleClick";

function reactEvent(name) {
  return REACT_EVENTS[name] ?? "on" + name[0].toUpperCase() + name.slice(1);
}

function styleObject(css) {
  const out = {};
  for (const decl of css.split(";")) {
    const at = decl.indexOf(":");
    if (at < 0) continue;
    const key = decl.slice(0, at).trim();
    const value = decl.slice(at + 1).trim();
    out[key.startsWith("--") ? key : key.replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = value;
  }
  return out;
}

// The element React renders for a `#[react(element)]` prop; doxa renders its children into it.
function shellElement(shell, portals) {
  const props = { ref: shell.ref };
  for (const [k, v] of Object.entries(shell.attrs)) {
    if (k === "class") props.className = v;
    else if (k === "for") props.htmlFor = v;
    else if (k === "style") props.style = styleObject(v);
    else props[k] = v;
  }
  for (const [name, f] of Object.entries(shell.events)) {
    props[reactEvent(name)] = (e) => f(e.nativeEvent ?? e);
  }
  // Only portals go inside, which add no DOM, so React leaves doxa's children alone.
  return createElement(shell.tag, props, portals);
}

// A dotted name, from a `rename`, is a path into nested objects, copied rather than mutated.
function nest(props) {
  const made = new Set();
  for (const key of Object.keys(props)) {
    if (!key.includes(".")) continue;
    const path = key.split(".");
    const last = path.pop();
    let at = props;
    for (const seg of path) {
      if (!made.has(at[seg])) {
        const had = at[seg];
        at[seg] = had !== null && typeof had === "object" ? { ...had } : {};
        made.add(at[seg]);
      }
      at = at[seg];
    }
    at[last] = props[key];
    delete props[key];
  }
  return props;
}

// Nested islands render inside `children`, or else the first slot or element, so they get this island's context.
function propsOf(island, content) {
  const props = { ...content.props, ...content.raw, ...content.feeds, ...content.js, ...island.events };
  const slots = Object.keys(content.slots);
  const home = slots.includes("children") ? "children" : (slots[0] ?? content.shells[0]?.prop);
  const portals = (name) => (name === home ? createElement(Portals, { parent: island.id }) : null);
  for (const [name, node] of Object.entries(content.slots)) {
    props[name] = createElement(Fragment, null, createElement(Adopt, { node }), portals(name));
  }
  for (const shell of content.shells) {
    props[shell.prop] = shellElement(shell, portals(shell.prop));
  }
  return nest(props);
}

// What of a component's props Rust can read: functions, symbols, React elements and class
// instances such as DOM nodes are left out, and are `null` in an array.
function plain(value, depth = 0) {
  if (value === null || ["string", "number", "boolean"].includes(typeof value)) return value;
  if (typeof value !== "object" || depth > 32 || "$$typeof" in value) return undefined;
  if (Array.isArray(value)) return value.map((v) => plain(v, depth + 1) ?? null);
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) return undefined;
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    const p = plain(v, depth + 1);
    if (p !== undefined) out[k] = p;
  }
  return out;
}

// One argument as itself, several as an array, which Rust reads as a tuple.
function pack(args) {
  return args.length === 1 ? args[0] : args;
}

let renders = 0;

// A doxa view React places, mounted after React commits its element and never during a render.
function DoxaRender({ fns, args }) {
  const ref = useRef(null);
  const key = useRef(0);
  const first = useRef(true);
  useLayoutEffect(() => {
    key.current = ++renders;
    fns.mount(key.current, ref.current, args);
    return () => fns.unmount(key.current);
  }, [fns]);
  useLayoutEffect(() => {
    if (first.current) first.current = false;
    else fns.update(key.current, args);
  }, [args]);
  return createElement("div", { ref, style: { display: "contents" } });
}

export function mount(id, parent, host, component, content, handlers, onError, calls, onHandle, rootId) {
  if (root === null && !library) {
    const el = document.createElement("div");
    el.hidden = true;
    document.body.appendChild(el);
    root = createRoot(el);
    root.render(createElement(Portals, { parent: null }));
  }
  const island = { id, parent: parent ?? null, root: rootId, host, component, live: true, events: {}, props: null };
  island.onError = (message) => {
    if (island.live) onError(message);
  };
  // React calls it with `ref.current` on commit and `null` on unmount.
  island.ref = onHandle === undefined ? undefined : (v) => {
    if (island.live || v === null) onHandle(v);
  };
  for (const [name, f] of Object.entries(handlers)) {
    // Created once per island, so React sees the same function on every update.
    island.events[name] = (arg) => {
      if (island.live) f(toJson(arg));
    };
  }
  for (const [name, f] of Object.entries(calls.funcs)) {
    island.events[name] = (...args) => (island.live ? f(pack(args)) : undefined);
  }
  for (const [name, f] of Object.entries(calls.asyncFuncs)) {
    island.events[name] = (...args) => (island.live ? f(pack(args)) : Promise.reject(new Error("unmounted")));
  }
  for (const [name, raw] of Object.entries(calls.renders)) {
    // Rust drops these when the island unmounts, before React runs the cleanups that call them.
    const fns = {
      mount: (...a) => island.live && raw.mount(...a),
      update: (...a) => island.live && raw.update(...a),
      unmount: (...a) => island.live && raw.unmount(...a),
    };
    island.events[name] = raw.component
      ? (props) => createElement(DoxaRender, { fns, args: plain(props) })
      : (...args) => createElement(DoxaRender, { fns, args: pack(args) });
  }
  island.props = propsOf(island, content);
  islands.set(id, island);
  publish();
}

export function update(id, content) {
  const island = islands.get(id);
  if (island === undefined) return;
  island.props = propsOf(island, content);
  publish();
}

export function unmount(id) {
  const island = islands.get(id);
  if (island === undefined) return;
  island.live = false;
  islands.delete(id);
  publish();
}
