// `doxa gallery`: every `#[story]` export, listed beside a frame showing one, with theme
// and viewport switches. The frame is this page again, with `?story=` set.
const PREFIX = "__doxa_story_";

const VIEWPORTS = { Phone: 390, Tablet: 768, Desktop: 1280, Full: 0 };

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  node.append(...children);
  return node;
}

function showStory(glue, name, theme) {
  document.documentElement.dataset.theme = theme;
  document.documentElement.style.colorScheme = theme;
  const host = el("div", { id: "story", "data-story": name });
  document.body.replaceChildren(host);
  const mount = glue[PREFIX + name];
  if (mount === undefined) {
    host.textContent = `no story named ${name}`;
    return;
  }
  // Kept so the story stays mounted for the frame's life.
  globalThis.__doxa_story = mount(host);
}

function showIndex(names) {
  const params = new URLSearchParams(location.search);
  const state = {
    story: params.get("show") ?? names[0],
    theme: params.get("theme") ?? "light",
    viewport: params.get("viewport") ?? "Full",
  };
  const frame = el("iframe", { title: "story", style: "border:1px solid #ccc;height:80vh;background:#fff" });
  const list = el("nav", { style: "display:flex;flex-direction:column;gap:4px;min-width:12rem" });
  const update = () => {
    const width = VIEWPORTS[state.viewport];
    frame.style.width = width === 0 ? "100%" : `${width}px`;
    frame.src = `?story=${encodeURIComponent(state.story)}&theme=${state.theme}`;
    for (const a of list.children) a.style.fontWeight = a.dataset.story === state.story ? "bold" : "normal";
    history.replaceState(null, "", `?show=${encodeURIComponent(state.story)}&theme=${state.theme}&viewport=${state.viewport}`);
  };
  for (const name of names) {
    list.append(el("a", { href: "#", "data-story": name, onclick: (e) => { e.preventDefault(); state.story = name; update(); } }, name.replaceAll("_", " ")));
  }
  const select = (label, options, key) =>
    el("label", {}, `${label} `, el("select", { onchange: (e) => { state[key] = e.target.value; update(); } },
      ...options.map((o) => { const opt = el("option", { value: o }, o); opt.selected = o === state[key]; return opt; })));
  const bar = el("header", { style: "display:flex;gap:1rem;padding:8px 0" },
    select("Theme", ["light", "dark"], "theme"), select("Viewport", Object.keys(VIEWPORTS), "viewport"));
  document.body.style.fontFamily = "system-ui, sans-serif";
  document.body.replaceChildren(el("div", { style: "display:flex;gap:1rem;padding:1rem" }, list, el("main", { style: "flex:1" }, bar, frame)));
  if (names.length === 0) list.append("No stories: mark a function `#[story]`.");
  else update();
}

export async function gallery(glue, start) {
  await start();
  const names = Object.keys(glue).filter((k) => k.startsWith(PREFIX)).map((k) => k.slice(PREFIX.length)).sort();
  const params = new URLSearchParams(location.search);
  if (params.has("story")) showStory(glue, params.get("story"), params.get("theme") ?? "light");
  else showIndex(names);
}
