//! Compiles `guides/NN-slug.md` into `GUIDES`, the HTML each guide page shows.

use std::fmt::Write as _;
use std::path::Path;

use pulldown_cmark::{html, CowStr, Event, HeadingLevel, Options, Parser, Tag, TagEnd};

const REPO: &str = "https://github.com/edmiester777/doxa/blob/main/examples/site/guides/";

fn main() {
    println!("cargo::rerun-if-changed=guides");
    let mut files: Vec<_> = std::fs::read_dir("guides")
        .expect("guides/")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "md"))
        .collect();
    files.sort();
    let mut out = String::from("pub static GUIDES: &[Guide] = &[\n");
    for path in &files {
        let g = guide(path);
        writeln!(
            out,
            "    Guide {{ slug: {:?}, title: {:?}, blurb: {:?}, html: {:?} }},",
            g.slug, g.title, g.blurb, g.html
        )
        .unwrap();
    }
    out.push_str("];\n");
    let dest = Path::new(&std::env::var("OUT_DIR").unwrap()).join("guides.rs");
    std::fs::write(dest, out).unwrap();
}

struct Compiled {
    slug: String,
    title: String,
    blurb: String,
    html: String,
}

fn guide(path: &Path) -> Compiled {
    let text = std::fs::read_to_string(path).unwrap();
    let stem = path.file_stem().unwrap().to_string_lossy();
    let slug = stem.split_once('-').map_or(&*stem, |(_, s)| s).to_owned();
    let (mut title, mut blurb) = (String::new(), String::new());
    let mut events = Vec::new();
    let mut heading: Option<(HeadingLevel, Vec<Event>)> = None;
    let mut first_paragraph = None::<String>;
    let opts = Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH;
    for ev in Parser::new_ext(&text, opts) {
        match ev {
            Event::Start(Tag::Heading { level, .. }) => heading = Some((level, Vec::new())),
            Event::End(TagEnd::Heading(_)) => {
                let (level, inner) = heading.take().unwrap();
                let plain = plain_text(&inner);
                if level == HeadingLevel::H1 && title.is_empty() {
                    title = plain;
                    continue;
                }
                let id = anchor(&plain);
                events.push(Event::Html(format!("<{level} id=\"{id}\">").into()));
                events.extend(inner);
                events.push(Event::Html(
                    format!("<a class=\"anchor\" href=\"#{id}\">#</a></{level}>").into(),
                ));
            }
            Event::Start(Tag::Link {
                link_type,
                dest_url,
                title: t,
                id,
            }) => {
                let ev = Event::Start(Tag::Link {
                    link_type,
                    dest_url: link(&dest_url),
                    title: t,
                    id,
                });
                push(&mut heading, &mut events, ev);
            }
            Event::Start(Tag::Paragraph) if first_paragraph.is_none() && heading.is_none() => {
                first_paragraph = Some(String::new());
                events.push(ev);
            }
            Event::End(TagEnd::Paragraph) if blurb.is_empty() => {
                blurb = first_paragraph
                    .clone()
                    .unwrap_or_default()
                    .trim()
                    .to_owned();
                events.push(ev);
            }
            Event::Text(ref t) | Event::Code(ref t) => {
                if let Some(p) = first_paragraph.as_mut().filter(|_| blurb.is_empty()) {
                    p.push_str(t);
                }
                push(&mut heading, &mut events, ev);
            }
            ev => push(&mut heading, &mut events, ev),
        }
    }
    let mut out = String::new();
    html::push_html(&mut out, events.into_iter());
    assert!(!title.is_empty(), "{} has no `# Title`", path.display());
    Compiled {
        slug,
        title,
        blurb,
        html: out,
    }
}

fn push<'a>(
    heading: &mut Option<(HeadingLevel, Vec<Event<'a>>)>,
    events: &mut Vec<Event<'a>>,
    ev: Event<'a>,
) {
    match heading {
        Some((_, inner)) => inner.push(ev),
        None => events.push(ev),
    }
}

fn plain_text(events: &[Event]) -> String {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Text(t) | Event::Code(t) => Some(t.as_ref()),
            _ => None,
        })
        .collect()
}

/// GitHub's heading anchors: lower case, spaces to `-`, punctuation dropped.
fn anchor(text: &str) -> String {
    text.chars()
        .filter_map(|c| match c {
            ' ' => Some('-'),
            c if c.is_alphanumeric() || c == '-' || c == '_' => Some(c.to_ascii_lowercase()),
            _ => None,
        })
        .collect()
}

/// A guide's link as the site serves it: `03-auth.md#x` is the sibling page `auth#x`, and a
/// path out of `guides/` points at the file on GitHub.
fn link(dest: &str) -> CowStr<'static> {
    if dest.contains("://") || dest.starts_with('#') || dest.starts_with('/') {
        return dest.to_owned().into();
    }
    let (path, frag) = dest.split_once('#').map_or((dest, ""), |(p, f)| (p, f));
    let frag = if frag.is_empty() {
        String::new()
    } else {
        format!("#{frag}")
    };
    match path.strip_suffix(".md").filter(|p| !p.contains('/')) {
        Some(file) => {
            let slug = file.split_once('-').map_or(file, |(_, s)| s);
            format!("{slug}{frag}").into()
        }
        None => format!("{REPO}{path}{frag}").into(),
    }
}
