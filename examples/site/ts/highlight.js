// highlight.js with only the languages the guides use, bound from Rust with `#[npm]`.
import hljs from "highlight.js/lib/core";
import bash from "highlight.js/lib/languages/bash";
import ini from "highlight.js/lib/languages/ini";
import javascript from "highlight.js/lib/languages/javascript";
import json from "highlight.js/lib/languages/json";
import rust from "highlight.js/lib/languages/rust";
import xml from "highlight.js/lib/languages/xml";
import yaml from "highlight.js/lib/languages/yaml";

hljs.registerLanguage("rust", rust);
hljs.registerLanguage("toml", ini);
hljs.registerLanguage("sh", bash);
hljs.registerLanguage("bash", bash);
hljs.registerLanguage("js", javascript);
hljs.registerLanguage("jsx", javascript);
hljs.registerLanguage("json", json);
hljs.registerLanguage("html", xml);
hljs.registerLanguage("yaml", yaml);
hljs.configure({ ignoreUnescapedHTML: true });

export function highlightAll() {
  for (const el of document.querySelectorAll("pre code:not(.hljs)")) {
    hljs.highlightElement(el);
  }
}
