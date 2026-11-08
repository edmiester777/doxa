// A plain JS module the app binds with `#[npm]`.
export function shout(word, opts) {
  return opts.times > 0 ? (word.toUpperCase() + "!").repeat(opts.times) : "";
}

export async function later(word) {
  return { word, length: word.length };
}

export function refuse() {
  throw new Error("no");
}
