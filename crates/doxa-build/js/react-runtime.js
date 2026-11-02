// The React side of doxa islands: one root, created on first mount. A nested island is a
// portal inside the island around it, so it gets that island's React context.
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

function publish() {
  version++;
  for (const l of listeners) l();
}

function subscribe(l) {
  listeners.add(l);
  return () => listeners.delete(l);
}

// Moves the element doxa renders an island's `View` children into to where React puts `children`.
function Adopt({ node }) {
  const ref = useRef(null);
  useLayoutEffect(() => {
    const el = ref.current;
    el.appendChild(node);
    return () => {
      if (node.parentNode === el) el.removeChild(node);
    };
  }, [node]);
  return createElement("div", { ref, style: { display: "contents" } });
}

const IslandView = memo(({ component, props }) => createElement(component, props));

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

// The islands whose nearest island is `parent`; `null` for the root, which also takes orphans.
function Portals({ parent }) {
  useSyncExternalStore(subscribe, () => version);
  const mine = [...islands.values()].filter((i) =>
    parent === null ? !islands.has(i.parent) : i.parent === parent,
  );
  return mine.map((i) =>
    createPortal(
      createElement(
        Boundary,
        { onError: i.onError },
        createElement(Suspense, { fallback: null }, createElement(IslandView, { component: i.component, props: i.props })),
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

function propsOf(island, data) {
  const props = { ...data, ...island.events };
  if (island.children) {
    props.children = createElement(
      Fragment,
      null,
      createElement(Adopt, { node: island.children }),
      createElement(Portals, { parent: island.id }),
    );
  }
  return props;
}

export function mount(id, parent, host, component, data, handlers, children, onError) {
  if (root === null) {
    const el = document.createElement("div");
    el.hidden = true;
    document.body.appendChild(el);
    root = createRoot(el);
    root.render(createElement(Portals, { parent: null }));
  }
  const island = { id, parent: parent ?? null, host, component, children, live: true, events: {}, props: null };
  island.onError = (message) => {
    if (island.live) onError(message);
  };
  for (const [name, f] of Object.entries(handlers)) {
    // Created once per island, so React sees the same function on every update.
    island.events[name] = (arg) => {
      if (island.live) f(toJson(arg));
    };
  }
  island.props = propsOf(island, data);
  islands.set(id, island);
  publish();
}

export function update(id, data) {
  const island = islands.get(id);
  if (island === undefined) return;
  island.props = propsOf(island, data);
  publish();
}

export function unmount(id) {
  const island = islands.get(id);
  if (island === undefined) return;
  island.live = false;
  islands.delete(id);
  publish();
}
