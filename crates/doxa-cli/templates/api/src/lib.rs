//! Every route, written once: the server runs its body and the browser calls it.

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

/// Every route.
#[doxa::service]
pub struct Api;

/// Say hello.
#[get("/api/greeting")]
pub async fn greeting(Query(who): Query<Who>) -> Json<Greeting> {
    Json(greet(who.name))
}
