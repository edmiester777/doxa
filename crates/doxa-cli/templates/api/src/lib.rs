//! Every route, declared once: the server implements them and the browser calls them.

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
pub async fn greeting(who: Query<Who>) -> Json<Greeting>;
