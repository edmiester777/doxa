//! The desktop app's menus, tray and shortcut; compiled only for desktop builds.

use doxa::ui::native::{self, Item, Menu, Standard, Tray};
use doxa::ui::prelude::*;

use crate::WidgetsPage;

/// The app menu, tray and global shortcut, while the shell is mounted.
pub fn chrome() {
    native::menu(
        Menu::new()
            .submenu("File", |m| {
                m.item(
                    Item::new("All Widgets")
                        .shortcut("CmdOrCtrl+1")
                        .on(|| navigate(WidgetsPage::route())),
                )
                .item(
                    Item::new("Export Widgets…")
                        .shortcut("CmdOrCtrl+E")
                        .on(crate::export::start),
                )
                .separator()
                .standard(Standard::Quit)
            })
            .submenu("Edit", |m| {
                m.standard(Standard::Undo)
                    .standard(Standard::Redo)
                    .separator()
                    .standard(Standard::Cut)
                    .standard(Standard::Copy)
                    .standard(Standard::Paste)
                    .standard(Standard::SelectAll)
            }),
    );
    native::tray(
        Tray::new()
            .tooltip("Shop")
            .on_click(|| native::window().focus())
            .menu(
                Menu::new()
                    .item(Item::new("Export Widgets…").on(crate::export::start))
                    .separator()
                    .standard(Standard::Quit),
            ),
    );
    native::shortcut("CmdOrCtrl+Shift+Space", || native::window().focus());
}

/// A widget row's context menu.
pub fn row_menu(e: &Event, name: String) {
    native::context_menu(
        e,
        Menu::new().item(
            Item::new(format!("Open {name}")).on(move || navigate(crate::WidgetPage::route(&name))),
        ),
    );
}
