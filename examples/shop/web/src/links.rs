//! `doxa-shop://widgets/<name>` opens that widget; compiled only for native builds.

use doxa::ui::native;
use doxa::ui::prelude::*;

/// Follows the links the app is opened with while the shell is mounted.
pub fn follow() {
    native::on_open_url(|urls| {
        if let Some(name) = urls.iter().rev().find_map(|u| widget(u)) {
            navigate(crate::WidgetPage::route(&name));
        }
    });
}

fn widget(url: &str) -> Option<String> {
    let name = url
        .strip_prefix("doxa-shop://widgets/")?
        .trim_end_matches('/');
    (!name.is_empty() && !name.contains('/')).then(|| name.to_owned())
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_a_widget_link_names_a_widget() {
        assert_eq!(
            super::widget("doxa-shop://widgets/gear/").as_deref(),
            Some("gear")
        );
        assert_eq!(super::widget("doxa-shop://other/gear"), None);
        assert_eq!(super::widget("doxa-shop://widgets/a/b"), None);
    }
}
