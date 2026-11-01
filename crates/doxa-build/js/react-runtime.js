// The React side of doxa islands: one root, created on first mount, renders
// every island as a portal into the host element doxa gave it.
import { createElement, Suspense, useSyncExternalStore } from "react";
import { createPortal } from "react-dom";
import { createRoot } from "react-dom/client";

const islands = new Map();
const listeners = new Set();
let snapshot = [];
let root = null;
let next = 0;

function publish() {
  snapshot = [...islands.values()];
  for (const l of listeners) l();
}

function subscribe(l) {
  listeners.add(l);
  return () => listeners.delete(l);
}

function Islands() {
  const list = useSyncExternalStore(subscribe, () => snapshot);
  return list.map((i) =>
    createPortal(
      createElement(Suspense, { fallback: null }, createElement(i.component, i.props)),
      i.host,
      i.key,
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

export function mount(host, component, json, handlers) {
  if (root === null) {
    const el = document.createElement("div");
    el.hidden = true;
    document.body.appendChild(el);
    root = createRoot(el);
    root.render(createElement(Islands));
  }
  const id = ++next;
  const island = { key: String(id), host, component, live: true, events: {}, props: null };
  for (const [name, f] of Object.entries(handlers)) {
    // Created once per island, so React sees the same function on every update.
    island.events[name] = (arg) => {
      if (island.live) f(toJson(arg));
    };
  }
  island.props = { ...JSON.parse(json), ...island.events };
  islands.set(id, island);
  publish();
  return id;
}

export function update(id, json) {
  const island = islands.get(id);
  if (island === undefined) return;
  island.props = { ...JSON.parse(json), ...island.events };
  publish();
}

export function unmount(id) {
  const island = islands.get(id);
  if (island === undefined) return;
  island.live = false;
  islands.delete(id);
  publish();
}
