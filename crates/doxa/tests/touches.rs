//! A route's cache entities: its guards, `touches`, and the entity it answers.

use doxa::wire::Keyed;

pub struct Thing;

impl Keyed for Thing {
    type Key = ();
    const ENTITY_TYPE: &'static str = "Thing";
}

doxa::client::__as_client! {
    #[post("/things/sweep", touches = [Thing])]
    pub async fn sweep() -> StatusCode { unreachable!() }
}

#[test]
fn touched_entities_are_the_routes() {
    assert_eq!(sweep::ROUTE.entities, ["Thing"]);
}

#[test]
fn the_entity_a_route_answers_is_found_by_its_type() {
    use doxa::wire::{
        AnswerOf, AnswersList as _, AnswersMaybe as _, AnswersNothing as _, AnswersOne as _,
    };
    assert_eq!((&&&AnswerOf::<Thing>::new()).answered(), Some("Thing"));
    assert_eq!((&&AnswerOf::<Vec<Thing>>::new()).answered(), Some("Thing"));
    assert_eq!(
        (&AnswerOf::<Option<Thing>>::new()).answered(),
        Some("Thing")
    );
    assert_eq!(AnswerOf::<u32>::new().answered(), None);
}
