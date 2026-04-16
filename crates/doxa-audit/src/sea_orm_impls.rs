//! SeaORM trait implementations for audit event enums.

use crate::event::Outcome;

// ── Outcome ──

impl From<Outcome> for sea_orm::Value {
    fn from(val: Outcome) -> Self {
        sea_orm::Value::String(Some(Box::new(val.to_string())))
    }
}

impl sea_orm::TryGetable for Outcome {
    fn try_get_by<I: sea_orm::ColIdx>(
        res: &sea_orm::QueryResult,
        idx: I,
    ) -> Result<Self, sea_orm::TryGetError> {
        let s: String = res.try_get_by(idx)?;
        s.parse()
            .map_err(|e: String| sea_orm::TryGetError::DbErr(sea_orm::DbErr::Type(e)))
    }
}

impl sea_orm::sea_query::ValueType for Outcome {
    fn try_from(v: sea_orm::Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
        match v {
            sea_orm::Value::String(Some(s)) => {
                s.parse().map_err(|_| sea_orm::sea_query::ValueTypeErr)
            }
            _ => Err(sea_orm::sea_query::ValueTypeErr),
        }
    }

    fn type_name() -> String {
        "Outcome".to_string()
    }

    fn array_type() -> sea_orm::sea_query::ArrayType {
        sea_orm::sea_query::ArrayType::String
    }

    fn column_type() -> sea_orm::sea_query::ColumnType {
        sea_orm::sea_query::ColumnType::String(sea_orm::sea_query::StringLen::N(20))
    }
}

impl sea_orm::sea_query::Nullable for Outcome {
    fn null() -> sea_orm::Value {
        sea_orm::Value::String(None)
    }
}
