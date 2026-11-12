//! Two `#[dto]` types under one schema name are refused; a renamed one isn't.

mod query {
    doxa::prelude!();

    #[dto]
    pub struct Relation {
        pub left: String,
    }
}

mod secrets {
    doxa::prelude!();

    #[dto]
    pub struct Relation {
        pub owner: u32,
    }

    #[dto]
    #[schema(as = SecretGrant)]
    pub struct Grant {
        pub id: u32,
    }
}

mod roles {
    doxa::prelude!();

    #[dto]
    pub struct Grant {
        pub role: String,
    }
}

#[test]
fn a_name_two_types_claim_is_reported_with_both() {
    assert_eq!(
        doxa::duplicate_schemas(),
        [(
            "Relation".to_owned(),
            vec![
                "schema_names::query::Relation",
                "schema_names::secrets::Relation"
            ]
        )]
    );
}

#[test]
#[should_panic(
    expected = "the schema name `Relation` belongs to schema_names::query::Relation and \
                schema_names::secrets::Relation"
)]
fn the_app_stops_on_the_clash() {
    doxa::spec();
}
