//! Written once. The server runs these routes; the client calls them.

doxa::prelude!();

/// What the server says.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Greeting {
    pub message: String,
}

/// Who to greet.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema, IntoParams)]
pub struct Who {
    pub name: Option<String>,
}

/// Say hello.
#[get("/api/greeting")]
pub async fn greeting(Query(who): Query<Who>) -> Json<Greeting> {
    let name = who.name.unwrap_or_else(|| "world".into());
    Json(Greeting {
        message: format!("Hello, {name}!"),
    })
}
