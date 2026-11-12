use doxa_fmt::{format_source, Config};

/// Formats `input`, asserts it equals `expected`, then asserts a second pass is a no-op.
#[track_caller]
fn golden(input: &str, expected: &str) {
    golden_with(&Config::default(), input, expected);
}

#[track_caller]
fn golden_with(config: &Config, input: &str, expected: &str) {
    let first = format_source(input, config);
    assert!(first.warnings.is_empty(), "warnings: {:?}", first.warnings);
    assert_eq!(first.output, expected, "\n--- got ---\n{}", first.output);
    assert_eq!(first.changed, input != expected);
    let second = format_source(&first.output, config);
    assert_eq!(
        second.output, expected,
        "not idempotent:\n{}",
        second.output
    );
    assert!(!second.changed);
}

#[test]
fn long_attributes_break_one_per_line() {
    let config = Config {
        max_width: 80,
        ..Config::default()
    };
    golden_with(
        &config,
        r#"fn row() {
    let v = view!{<div class="row"><WidgetRow key={w.id} widget={w.clone()} on_select={move |id| sel.set(Some(id))}/><span>{&w.name}</span></div>};
}
"#,
        r#"fn row() {
    let v = view! {
        <div class="row">
            <WidgetRow
                key={w.id}
                widget={w.clone()}
                on_select={move |id| sel.set(Some(id))}
            />
            <span>{&w.name}</span>
        </div>
    };
}
"#,
    );
}

#[test]
fn a_view_in_a_wrapped_attribute_is_measured_where_it_lands() {
    let src = "fn f() -> View {\n    view! {\n        <Suspense fallback={view! { <div class=\"skeleton\" aria-busy=\"true\"/> }}>\n            <p/>\n        </Suspense>\n    }\n}\n";
    for width in [72, 73] {
        let config = Config {
            max_width: width,
            ..Config::default()
        };
        let out = format_source(src, &config).output;
        golden_with(&config, src, &out);
        assert!(out.lines().all(|l| l.len() <= width), "{out}");
    }
}

#[test]
fn a_short_view_stays_inline_and_empty_self_closes() {
    golden(
        "fn f() {\n    view! { <div   class=\"a\"   id={ x }></div> }\n}\n",
        "fn f() {\n    view! { <div class=\"a\" id={x}/> }\n}\n",
    );
}

#[test]
fn a_multiline_closure_body_gets_the_block_rustfmt_would_add() {
    golden(
        "fn f() {\n    let dom = mount(|| view!{<div><Outlet/></div>});\n}\n",
        r#"fn f() {
    let dom = mount(|| {
        view! {
            <div>
                <Outlet/>
            </div>
        }
    });
}
"#,
    );
    golden(
        "fn f() {\n    mount(move || view!{<A/>});\n}\n",
        "fn f() {\n    mount(move || view! { <A/> });\n}\n",
    );
}

#[test]
fn key_moves_first() {
    golden(
        "fn f() {\n    view! { <Row a=\"1\" key={id} b=\"2\"/> }\n}\n",
        "fn f() {\n    view! { <Row key={id} a=\"1\" b=\"2\"/> }\n}\n",
    );
}

#[test]
fn nested_components_and_paths() {
    golden(
        r#"fn f() {
    doxa::ui::view!(<pages::Layout title="Home"><Card><Card.Header/><pages::Foo bar={1}/></Card></pages::Layout>)
}
"#,
        r#"fn f() {
    doxa::ui::view! {
        <pages::Layout title="Home">
            <Card>
                <Card.Header/>
                <pages::Foo bar={1}/>
            </Card>
        </pages::Layout>
    }
}
"#,
    );
}

#[test]
fn fragments() {
    golden(
        "fn f() {\n    view![<><A/><B/></>]\n}\n",
        "fn f() {\n    view! {\n        <>\n            <A/>\n            <B/>\n        </>\n    }\n}\n",
    );
}

#[test]
fn directive_attributes() {
    golden(
        r#"fn f() {
    view! { <input type="text" bind:value={name} prop:active={tab.get()} on:click={move |_| x.set(1)} disabled/> }
}
"#,
        r#"fn f() {
    view! {
        <input
            type="text"
            bind:value={name}
            prop:active={tab.get()}
            on:click={move |_| x.set(1)}
            disabled
        />
    }
}
"#,
    );
}

#[test]
fn string_literal_children() {
    golden(
        r#"fn f() {
    view! { <button class="primary">"Save"</button><p>"Hello, " {name} "!"</p> }
}
"#,
        r#"fn f() {
    view! {
        <button class="primary">"Save"</button>
        <p>
            "Hello, "
            {name}
            "!"
        </p>
    }
}
"#,
    );
}

#[test]
fn comments_are_preserved() {
    golden(
        r#"fn f() {
    view! {
        // header
        <div> <!-- "html comment" -->
        <A/> // trailing
        /* block */


        <B
           // why b
           x="1" /* after x */
        />
        </div>
        // footer
    }
}
"#,
        r#"fn f() {
    view! {
        // header
        <div>
            <!-- "html comment" -->
            <A/> // trailing
            /* block */

            <B
                // why b
                x="1" /* after x */
            />
        </div>
        // footer
    }
}
"#,
    );
}

#[test]
fn comments_inside_expressions_keep_original_text() {
    golden(
        r#"fn f() {
    view! { <button on:click={move |_| {
        // bump it
        count.set(count.get() + 1);
    }}>"+"</button> }
}
"#,
        r#"fn f() {
    view! {
        <button
            on:click={move |_| {
                // bump it
                count.set(count.get() + 1);
            }}
        >
            "+"
        </button>
    }
}
"#,
    );
}

#[test]
fn multiline_expressions_go_through_prettyplease() {
    golden(
        r#"fn f() {
    view! { <ul>{items.iter().map(|item| { let label = item.label.clone(); view_item(label, item.id, item.enabled, item.description.clone()) }).collect::<Vec<_>>()}</ul> }
}
"#,
        r#"fn f() {
    view! {
        <ul>
            {items
                .iter()
                .map(|item| {
                    let label = item.label.clone();
                    view_item(label, item.id, item.enabled, item.description.clone())
                })
                .collect::<Vec<_>>()}
        </ul>
    }
}
"#,
    );
}

#[test]
fn nested_view_inside_expression() {
    golden(
        r#"fn f() {
    view! { <div>{move || if open.get() { view!{<Panel a="1"/>} } else { view!{<span/>} }}</div> }
}
"#,
        r#"fn f() {
    view! {
        <div>{move || if open.get() { view! { <Panel a="1"/> } } else { view! { <span/> } }}</div>
    }
}
"#,
    );
}

#[test]
fn two_views_at_different_indentations() {
    golden(
        r#"fn a() -> View {
    view! { <A/> }
}

mod inner {
    fn b() -> View {
        if x {
            view!{<B   x="1"/>}
        } else {
            view! {}
        }
    }
}
"#,
        r#"fn a() -> View {
    view! { <A/> }
}

mod inner {
    fn b() -> View {
        if x {
            view! { <B x="1"/> }
        } else {
            view! {}
        }
    }
}
"#,
    );
}

#[test]
fn postfix_call_keeps_delimiter() {
    golden(
        "fn f() {\n    view!(<A/>).into_any()\n}\n",
        "fn f() {\n    view!(<A/>).into_any()\n}\n",
    );
}

#[test]
fn single_child_wraps_when_too_long() {
    let config = Config {
        max_width: 30,
        tab_spaces: 2,
    };
    golden_with(
        &config,
        "fn f() {\n  view! { <span class=\"x\">{some_long_name}</span> }\n}\n",
        "fn f() {\n  view! {\n    <span class=\"x\">\n      {some_long_name}\n    </span>\n  }\n}\n",
    );
}

#[test]
fn unparseable_body_is_untouched() {
    let input = "fn f() {\n    view!{ <div class=\"a\"></span>  }\n    let y   =  1;\n}\n";
    let out = format_source(input, &Config::default());
    assert_eq!(out.output, input);
    assert!(!out.changed);
    assert_eq!(out.warnings.len(), 1, "{:?}", out.warnings);
    assert!(out.warnings[0].starts_with("line 2:"), "{:?}", out.warnings);
}

#[test]
fn literals_blocks_and_raw_text() {
    golden(
        r#"fn f() {
  view! {
<p>Hello  world</p>
      <pre>"line one
  line two"</pre>
    {
        // block child
        x
    }
    <div>
    // only a comment
    </div>
  }
}
"#,
        r#"fn f() {
  view! {
      <p>Hello  world</p>
      <pre>
          "line one
  line two"
      </pre>
      {
          // block child
          x
      }
      <div>
          // only a comment
      </div>
  }
}
"#,
    );
}

#[test]
fn comment_inside_attribute_is_untouched() {
    let input = "fn f() {\n    view!{<div class=/* c */\"x\"/>}\n}\n";
    let out = format_source(input, &Config::default());
    assert_eq!(out.output, input);
    assert_eq!(out.warnings.len(), 1, "{:?}", out.warnings);
}

#[test]
fn code_outside_views_is_untouched() {
    let input = "fn f( ) {\n    let x   = 1;\n    other!{ <div></div> }\n}\n";
    let out = format_source(input, &Config::default());
    assert_eq!(out.output, input);
    assert!(out.warnings.is_empty());
}

#[test]
fn discover_reads_rustfmt_toml() {
    let dir = std::env::temp_dir().join(format!("doxa-fmt-discover-{}", std::process::id()));
    let nested = dir.join("a/b");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(
        dir.join(".rustfmt.toml"),
        "max_width = 80 # narrow\ntab_spaces=2\n",
    )
    .unwrap();
    let config = Config::discover(&nested);
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(
        config,
        Config {
            max_width: 80,
            tab_spaces: 2
        }
    );
}
