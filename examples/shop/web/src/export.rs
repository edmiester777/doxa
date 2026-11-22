//! Exporting the widget list to a file the user picks; compiled only for native builds.

use doxa::ui::native::{self, dialog, Notification};
use shop_api::widgets::{list_widgets, Filter};

/// Runs [`export`] in the background, reporting a failure in a message box.
pub fn start() {
    doxa::client::task::spawn(async {
        if let Err(e) = export().await {
            let m = dialog::Message::new(e.to_string())
                .title("Export failed")
                .kind(dialog::Kind::Error);
            let _ = dialog::message(m).await;
        }
    });
}

async fn export() -> Result<(), Box<dyn std::error::Error>> {
    let picked = dialog::save(
        dialog::Save::new()
            .name("widgets.json")
            .filter("JSON", &["json"]),
    )
    .await?;
    let Some(path) = picked else {
        return Ok(());
    };
    let widgets = list_widgets(Filter { contains: None }).await?;
    let json = serde_json::to_string_pretty(&widgets)?;
    native::invoke::<()>(
        "export_widgets",
        &serde_json::json!({ "path": path, "json": json }),
    )
    .await?;
    // A refused notification isn't a failed export.
    let _ = native::notify(Notification::new("Exported widgets").body(path)).await;
    Ok(())
}
