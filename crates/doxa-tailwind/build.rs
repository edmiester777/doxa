//! Turns `data/tailwind-merge.json`, tailwind-merge's default config dumped as data, into
//! static tables, so nothing parses JSON at run time.

use std::fmt::Write;

use serde_json::Value;

fn main() {
    let path = "data/tailwind-merge.json";
    println!("cargo:rerun-if-changed={path}");
    let json = std::fs::read_to_string(path).expect("data/tailwind-merge.json");
    let c: Value = serde_json::from_str(&json).expect("tailwind-merge.json is JSON");
    let mut out = String::new();
    writeln!(
        out,
        "pub(crate) const CACHE_SIZE: usize = {};",
        c["cacheSize"]
    )
    .unwrap();
    writeln!(
        out,
        "pub(crate) static THEME: &[(&str, &[Def])] = {};",
        groups(&c["theme"])
    )
    .unwrap();
    writeln!(
        out,
        "pub(crate) static GROUPS: &[(&str, &[Def])] = {};",
        groups(&c["classGroups"])
    )
    .unwrap();
    for (name, key) in [
        ("CONFLICTS", "conflictingClassGroups"),
        ("MODIFIER_CONFLICTS", "conflictingClassGroupModifiers"),
    ] {
        writeln!(out, "pub(crate) static {name}: &[(&str, &[&str])] = &[").unwrap();
        for pair in c[key].as_array().expect("pairs") {
            write!(out, "({}, &[", lit(&pair[0])).unwrap();
            for id in pair[1].as_array().expect("ids") {
                write!(out, "{},", lit(id)).unwrap();
            }
            writeln!(out, "]),").unwrap();
        }
        writeln!(out, "];").unwrap();
    }
    let order: Vec<String> = c["orderSensitiveModifiers"]
        .as_array()
        .expect("modifiers")
        .iter()
        .map(lit)
        .collect();
    writeln!(
        out,
        "pub(crate) static ORDER_SENSITIVE: &[&str] = &[{}];",
        order.join(",")
    )
    .unwrap();
    let dest = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("config.rs");
    std::fs::write(dest, out).unwrap();
}

fn lit(v: &Value) -> String {
    format!("{:?}", v.as_str().expect("a string"))
}

fn groups(pairs: &Value) -> String {
    let mut out = String::from("&[");
    for pair in pairs.as_array().expect("pairs") {
        write!(out, "({}, {}),", lit(&pair[0]), defs(&pair[1])).unwrap();
    }
    out.push(']');
    out
}

fn defs(list: &Value) -> String {
    let mut out = String::from("&[");
    for d in list.as_array().expect("definitions") {
        match d {
            Value::String(s) => write!(out, "Def::Class({s:?}),").unwrap(),
            Value::Object(o) if o.contains_key("validator") => {
                let name = o["validator"].as_str().expect("a validator name");
                let variant = name.strip_prefix("is").expect("validators are named is…");
                write!(out, "Def::Valid(Validator::{variant}),").unwrap();
            }
            Value::Object(o) if o.contains_key("theme") => {
                write!(out, "Def::Theme({}),", lit(&o["theme"])).unwrap()
            }
            Value::Object(o) => write!(out, "Def::Parts({}),", groups(&o["parts"])).unwrap(),
            other => panic!("unexpected definition {other}"),
        }
    }
    out.push(']');
    out
}
