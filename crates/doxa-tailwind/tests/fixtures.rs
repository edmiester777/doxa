//! tailwind-merge 3.5's own test cases for its default config, run through `merge`.

#[test]
fn every_tailwind_merge_fixture_merges_the_same() {
    let cases: Vec<(String, String)> =
        serde_json::from_str(include_str!("fixtures.json")).expect("fixtures.json");
    let wrong: Vec<String> = cases
        .iter()
        .filter_map(|(input, want)| {
            let got = doxa_tailwind::merge(input);
            (&got != want).then(|| format!("{input:?}\n  want {want:?}\n  got  {got:?}"))
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "{} of {} differ:\n{}",
        wrong.len(),
        cases.len(),
        wrong.join("\n")
    );
}

#[test]
fn cn_joins_then_merges() {
    let rest: Option<&str> = Some("p-2");
    assert_eq!(
        doxa_tailwind::cn!["px-4 py-2", (true, "text-sm"), rest],
        "text-sm p-2"
    );
}

#[test]
fn an_extension_adds_to_a_theme_scale() {
    use doxa_tailwind::{Extension, Merger};
    assert_eq!(doxa_tailwind::merge("p-2 p-gutter"), "p-2 p-gutter");
    let m = Merger::extend(Extension::new().theme("spacing", ["gutter"]));
    assert_eq!(m.merge("p-2 p-gutter"), "p-gutter");
}
