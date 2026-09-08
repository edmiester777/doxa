//! Turning a policy's residual into a `WHERE` clause.
//!
//! Cedar's partial evaluation answers three ways: allowed, denied, or a
//! **residual** — a `when` clause it could not finish because the value it
//! needed was not in the entity set. `permit(…) when { resource.region ==
//! "us" }` evaluated without a concrete resource is the whole clause,
//! handed back as JSON EST.
//!
//! That residual is a filter. Applying it a row at a time means loading
//! every row and asking the policy about each one; applying it as SQL means
//! the database never returns the rows the caller may not see. This module
//! is the translation between the two, and the reason a listing can be one
//! query rather than a query plus a loop.
//!
//! ## What it refuses
//!
//! Everything it does not recognize. A translator that skipped an
//! untranslatable clause would return a filter *wider* than the policy
//! authorized — every row the unskipped clause would have excluded, handed
//! to a caller the policy meant to exclude them from — and nothing about
//! the result would look wrong. So an unknown node, an attribute with no
//! column, a comparison between two attributes, and a literal type with no
//! SQL equivalent are all [`AuthError::PolicyFailed`], and the caller is
//! expected to treat that as a denial.
//!
//! Cedar's `in` is refused specifically. It is hierarchy membership —
//! `resource in Folder::"reports"` asks whether one entity is under
//! another, which is a question about the entity graph and not about any
//! column. Reading it as SQL `IN` would silently turn a parent check into a
//! set comparison against a column that may not even exist. Set membership
//! in Cedar is `contains`, which this does translate.
//!
//! ## Which residual this reads
//!
//! The one where `resource.<attr>` means a column of the table being
//! filtered. That is the shape a check against a *named* resource
//! produces: the request carries the entity's UID, the row's attributes go
//! into the entity set through
//! [`PolicyResource::cedar_attrs`](crate::PolicyResource::cedar_attrs), and
//! what survives partially evaluated is a condition over exactly those
//! attributes. [`ScopedTable::column_for_attr`] is derived from the same
//! field list, so the two cannot come apart.
//!
//! There is another shape, and this does not read it. A consumer that
//! withholds resource entities from the store on purpose — so that Cedar
//! hands back a residual it can push into a query over some *other* table,
//! the data a row describes rather than the row — gets attribute accesses
//! whose base is Cedar's `unknown` placeholder rather than the `resource`
//! variable, and a scope constraint (`resource in Tenant::"…"`) that
//! survives as an obligation nothing here can discharge. Both are refused,
//! which is correct but not useful: that residual is about a different
//! table, and translating it here would build a `WHERE` clause against the
//! wrong one — the single failure this module's refusals cannot catch,
//! because the result looks like an ordinary filter.
//!
//! A consumer in that position owns the translation, and owns discharging
//! the obligations against the caller it knows about. What ships here is
//! the mechanical half of the easy case.

use sea_orm::{ColumnTrait, Condition, EntityTrait, Value as DbValue};
use serde_json::Value;

use crate::error::AuthError;
use crate::scoped::ScopedTable;

/// Translate a residual condition body into a [`Condition`] over `R`'s
/// table.
///
/// The body is what
/// [`PolicyExtension::extract_residual_attrs`](crate::PolicyExtension::extract_residual_attrs)
/// receives — already merged into one expression when a policy had several
/// `when` clauses.
///
/// Attribute names resolve through [`ScopedTable::column_for_attr`], which
/// `#[derive(PolicyResource)]` writes from the same `#[resource(attr)]`
/// fields the policy sees, so a policy can only mention what the row
/// actually exposes.
///
/// ```ignore
/// fn extract_residual_attrs(
///     &self,
///     _policy: &cedar_policy::Policy,
///     body: Option<&Value>,
/// ) -> Result<Self::ResourceAttrs, AuthError> {
///     let filter = match body {
///         Some(body) => condition_from_residual::<Model>(body)?,
///         // No condition left means the grant is unconditional.
///         None => Condition::all(),
///     };
///     Ok(Grant { filter })
/// }
/// ```
pub fn condition_from_residual<R: ScopedTable>(body: &Value) -> Result<Condition, AuthError> {
    translate::<R>(body)
}

/// One EST node, in boolean position.
fn translate<R: ScopedTable>(node: &Value) -> Result<Condition, AuthError> {
    let (op, arg) = single_key(node)?;

    match op {
        "&&" => {
            let (left, right) = pair(arg)?;
            let (left, right) = (translate::<R>(left)?, translate::<R>(right)?);
            // `true` is the identity of a conjunction, and an empty
            // condition is how this spells it — so a resolved scope
            // constraint drops out instead of becoming `TRUE AND …`.
            Ok(match (is_true(&left), is_true(&right)) {
                (true, true) => Condition::all(),
                (true, false) => right,
                (false, true) => left,
                (false, false) => Condition::all().add(left).add(right),
            })
        }
        "||" => {
            let (left, right) = pair(arg)?;
            let (left, right) = (translate::<R>(left)?, translate::<R>(right)?);
            // The other way round: `true` *absorbs* a disjunction rather
            // than dropping out of it. A branch that holds unconditionally
            // makes the whole clause hold, so the answer is `true` — not
            // the other branch, which would be narrower than the policy.
            if is_true(&left) || is_true(&right) {
                return Ok(Condition::all());
            }
            Ok(Condition::any().add(left).add(right))
        }
        "!" => {
            let inner = arg.get("arg").ok_or_else(|| refused("`!` with no `arg`"))?;
            let inner = translate::<R>(inner)?;
            // `!true` is `false`, and refused for the reason a bare
            // `false` is: negating the empty condition would render as
            // nothing, which reads as granting everything.
            if is_true(&inner) {
                return Err(refused(
                    "a negated `true`, which grants nothing; an empty filter would grant \
                     everything",
                ));
            }
            Ok(inner.not())
        }
        "==" | "!=" | "<" | "<=" | ">" | ">=" => comparison::<R>(op, arg),
        "contains" => contains::<R>(arg),
        // A bare attribute used as a condition: `when { resource.active }`.
        "." => {
            let attr =
                attr_of(node).ok_or_else(|| refused("attribute access on a non-resource"))?;
            Ok(Condition::all().add(column::<R>(attr)?.eq(true)))
        }
        "in" => Err(refused(
            "`in` is Cedar hierarchy membership, not a column comparison; a parent check \
             cannot be pushed into a row filter",
        )),
        // Cedar leaves the parts of a policy's scope it *did* resolve as
        // `true` conjuncts inside the residual, so a clause that translates
        // perfectly well still arrives wrapped in them. `true` is the
        // identity of a conjunction, and an empty `Condition::all()` is how
        // SeaORM spells it — it contributes no SQL wherever it is added.
        //
        // `false` is not the mirror of that. It says the policy grants
        // nothing, and an empty condition would be read as granting
        // everything, so it refuses.
        "Value" => match arg.as_bool() {
            Some(true) => Ok(Condition::all()),
            Some(false) => Err(refused(
                "a `false` literal, which grants nothing; an empty filter would grant everything",
            )),
            None => Err(refused("a bare literal where a condition was expected")),
        },
        other => Err(refused(&format!("unsupported operator `{other}`"))),
    }
}

/// `attr <op> literal`, or the same written the other way round.
fn comparison<R: ScopedTable>(op: &str, arg: &Value) -> Result<Condition, AuthError> {
    let (left, right) = pair(arg)?;

    // Which side is the column decides whether the operator has to be
    // read backwards: `5 < resource.size` is `size > 5`.
    let (attr, literal, op) = match (attr_of(left), attr_of(right)) {
        (Some(attr), None) => (attr, right, op),
        (None, Some(attr)) => (attr, left, flip(op)),
        (Some(_), Some(_)) => {
            return Err(refused(
                "a comparison between two attributes has no single column to filter on",
            ))
        }
        (None, None) => return Err(refused("a comparison naming no resource attribute")),
    };

    let column = column::<R>(attr)?;
    let value =
        db_value(literal_of(literal).ok_or_else(|| {
            refused("a comparison against something that is not a literal value")
        })?)?;

    let expr = match op {
        "==" => column.eq(value),
        "!=" => column.ne(value),
        "<" => column.lt(value),
        "<=" => column.lte(value),
        ">" => column.gt(value),
        ">=" => column.gte(value),
        other => return Err(refused(&format!("unsupported comparison `{other}`"))),
    };

    Ok(Condition::all().add(expr))
}

/// `[…].contains(resource.attr)` — a literal set the column must be in.
///
/// The reverse, `resource.attr.contains(…)`, asks whether the *attribute*
/// is a set containing something. A column holding a scalar cannot answer
/// that, so it is refused rather than guessed at.
fn contains<R: ScopedTable>(arg: &Value) -> Result<Condition, AuthError> {
    let (left, right) = pair(arg)?;

    let attr = attr_of(right).ok_or_else(|| {
        refused(
            "`contains` whose argument is not a resource attribute; a set-valued column \
                 cannot be filtered as a scalar",
        )
    })?;

    let members =
        set_of(left).ok_or_else(|| refused("`contains` on something that is not a literal set"))?;
    let values = members
        .iter()
        .map(|member| db_value(literal_of(member).unwrap_or(member)))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Condition::all().add(column::<R>(attr)?.is_in(values)))
}

/// Whether a translated node is the unconditional `true`.
///
/// The only empty condition this module builds is the one the `true`
/// literal produces — every other arm adds at least one expression — so
/// emptiness and unconditional truth are the same fact here. They are not
/// the same fact in SeaORM generally: an empty `Condition::any()` is
/// `false`, and nothing below constructs one.
fn is_true(condition: &Condition) -> bool {
    condition.is_empty()
}

/// The column an attribute name resolves to, or a refusal.
fn column<R: ScopedTable>(attr: &str) -> Result<<R::Entity as EntityTrait>::Column, AuthError> {
    R::column_for_attr(attr).ok_or_else(|| {
        refused(&format!(
            "attribute `{attr}` has no column on this row, so the condition cannot be a filter"
        ))
    })
}

/// The sole key of a single-entry object, which is how EST spells a node.
fn single_key(node: &Value) -> Result<(&str, &Value), AuthError> {
    let object = node
        .as_object()
        .ok_or_else(|| refused("a residual node that is not an object"))?;

    if object.len() != 1 {
        return Err(refused("a residual node with more than one operator"));
    }

    object
        .iter()
        .next()
        .map(|(key, value)| (key.as_str(), value))
        .ok_or_else(|| refused("an empty residual node"))
}

/// The `left`/`right` operands of a binary node.
fn pair(arg: &Value) -> Result<(&Value, &Value), AuthError> {
    let left = arg
        .get("left")
        .ok_or_else(|| refused("a binary node with no `left`"))?;
    let right = arg
        .get("right")
        .ok_or_else(|| refused("a binary node with no `right`"))?;
    Ok((left, right))
}

/// The attribute name in `resource.<name>`, if that is what this node is.
///
/// Only `resource`. A residual still naming `principal` is one partial
/// evaluation could not resolve, and the row's columns say nothing about
/// the caller.
fn attr_of(node: &Value) -> Option<&str> {
    let access = node.get(".")?;
    let var = access.get("left")?.get("Var")?.as_str()?;
    if var != "resource" {
        return None;
    }
    access.get("attr")?.as_str()
}

/// The literal a `{"Value": …}` node carries.
fn literal_of(node: &Value) -> Option<&Value> {
    node.get("Value")
}

/// The members of a literal set, written either as an EST `Set` node or as
/// a JSON array inside a `Value`.
fn set_of(node: &Value) -> Option<&Vec<Value>> {
    if let Some(members) = node.get("Set").and_then(Value::as_array) {
        return Some(members);
    }
    literal_of(node)?.as_array()
}

/// A JSON literal as something a column can be compared to.
fn db_value(literal: &Value) -> Result<DbValue, AuthError> {
    match literal {
        Value::String(text) => Ok(DbValue::from(text.clone())),
        Value::Bool(flag) => Ok(DbValue::from(*flag)),
        Value::Number(number) => match (number.as_i64(), number.as_f64()) {
            (Some(int), _) => Ok(DbValue::from(int)),
            (None, Some(float)) => Ok(DbValue::from(float)),
            _ => Err(refused("a number with no SQL equivalent")),
        },
        // `null` compares false to everything in SQL, including itself, so
        // a filter built from one would silently match nothing. Whatever
        // the policy meant, it did not mean that.
        Value::Null => Err(refused("a comparison against `null`")),
        _ => Err(refused("a literal that is not a scalar")),
    }
}

/// The same comparison with its operands the other way round.
fn flip(op: &str) -> &str {
    match op {
        "<" => ">",
        "<=" => ">=",
        ">" => "<",
        ">=" => "<=",
        symmetric => symmetric,
    }
}

/// Every refusal is the same kind of failure: the policy said something
/// this cannot express, and the caller must not be handed a filter that
/// omits it.
fn refused(what: &str) -> AuthError {
    AuthError::PolicyFailed(format!("residual cannot become a row filter: {what}"))
}

#[cfg(test)]
mod tests {
    use sea_orm::entity::prelude::*;
    use sea_orm::{DbBackend, QueryTrait};
    use serde_json::{json, Value};

    use super::{condition_from_residual, Condition, ScopedTable};

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "widgets")]
    struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        name: String,
        region: String,
        size: i32,
        active: bool,
        tenant_id: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}

    impl ScopedTable for Model {
        type Entity = Entity;

        const SCOPE_COLUMN: Column = Column::TenantId;

        fn column_for_attr(attr: &str) -> Option<Column> {
            match attr {
                "region" => Some(Column::Region),
                "size" => Some(Column::Size),
                "active" => Some(Column::Active),
                _ => None,
            }
        }
    }

    /// `resource.<name>`, as EST spells it.
    fn attr(name: &str) -> Value {
        json!({".": {"left": {"Var": "resource"}, "attr": name}})
    }

    fn value(literal: Value) -> Value {
        json!({ "Value": literal })
    }

    /// The SQL a condition becomes, for comparing against an expectation.
    fn sql(condition: Condition) -> String {
        Entity::find()
            .filter(condition)
            .build(DbBackend::Postgres)
            .to_string()
    }

    #[test]
    fn an_equality_becomes_a_column_comparison() {
        let body = json!({"==": {"left": attr("region"), "right": value(json!("us"))}});
        let sql = sql(condition_from_residual::<Model>(&body).expect("translates"));

        assert!(sql.contains(r#""region" = 'us'"#), "{sql}");
    }

    /// `5 < resource.size` and `resource.size > 5` are the same filter, and
    /// a translator that read the first literally would produce the wrong
    /// one.
    #[test]
    fn a_literal_on_the_left_reads_the_operator_backwards() {
        let body = json!({"<": {"left": value(json!(5)), "right": attr("size")}});
        let sql = sql(condition_from_residual::<Model>(&body).expect("translates"));

        assert!(sql.contains(r#""size" > 5"#), "{sql}");
    }

    #[test]
    fn conjunction_and_disjunction_nest() {
        let body = json!({"&&": {
            "left": {"==": {"left": attr("region"), "right": value(json!("us"))}},
            "right": {"||": {
                "left": {">": {"left": attr("size"), "right": value(json!(10))}},
                "right": attr("active"),
            }},
        }});
        let sql = sql(condition_from_residual::<Model>(&body).expect("translates"));

        assert!(sql.contains(r#""region" = 'us'"#), "{sql}");
        assert!(sql.contains(r#""size" > 10"#), "{sql}");
        assert!(sql.contains(r#""active" = TRUE"#), "{sql}");
    }

    #[test]
    fn a_literal_set_containing_an_attribute_is_an_in_list() {
        let body = json!({"contains": {
            "left": {"Set": [value(json!("us")), value(json!("eu"))]},
            "right": attr("region"),
        }});
        let sql = sql(condition_from_residual::<Model>(&body).expect("translates"));

        assert!(sql.contains(r#""region" IN ('us', 'eu')"#), "{sql}");
    }

    /// The refusal that matters most. `in` is hierarchy membership, and
    /// reading it as SQL `IN` would turn `resource in Folder::"reports"`
    /// into a comparison against a column that means something else.
    #[test]
    fn hierarchy_membership_is_refused_rather_than_read_as_a_set() {
        let body = json!({"in": {"left": attr("region"), "right": value(json!("us"))}});

        let error = condition_from_residual::<Model>(&body).expect_err("refuses");
        assert!(
            format!("{error}").contains("hierarchy membership"),
            "{error}"
        );
    }

    /// An attribute the row does not expose as a column cannot be filtered
    /// on, and the answer is a refusal rather than a filter missing that
    /// clause.
    #[test]
    fn an_attribute_with_no_column_is_refused() {
        let body = json!({"==": {"left": attr("owner"), "right": value(json!("me"))}});

        let error = condition_from_residual::<Model>(&body).expect_err("refuses");
        assert!(format!("{error}").contains("no column"), "{error}");
    }

    /// The general case of the same rule: anything unrecognized refuses.
    /// A translator that returned `Condition::all()` for an operator it did
    /// not know would grant every row the clause meant to exclude.
    #[test]
    fn an_unknown_operator_is_refused() {
        let body = json!({"like": {"left": attr("region"), "right": value(json!("us%"))}});

        assert!(condition_from_residual::<Model>(&body).is_err());
    }

    /// Cedar leaves the scope constraints it resolved as `true` conjuncts
    /// inside the residual, so a translatable clause arrives wrapped in
    /// them. Refusing those would refuse every real residual; they have to
    /// vanish, which for a conjunction means contributing no SQL.
    #[test]
    fn a_true_literal_is_the_identity_of_a_conjunction() {
        let clause = json!({"==": {"left": attr("region"), "right": value(json!("us"))}});
        let body = json!({"&&": {
            "left": value(json!(true)),
            "right": {"&&": {"left": value(json!(true)), "right": clause}},
        }});

        let sql = sql(condition_from_residual::<Model>(&body).expect("translates"));

        assert!(sql.contains(r#""region" = 'us'"#), "{sql}");
        assert!(
            !sql.contains("TRUE AND") && !sql.contains("AND TRUE"),
            "a true conjunct must leave no trace: {sql}",
        );
    }

    /// `false` is not its mirror. It grants nothing, and an empty
    /// condition — which is what "contributes no SQL" means — would be
    /// read as granting everything. Same for the `!true` that says it the
    /// long way round.
    #[test]
    fn a_false_literal_is_refused_rather_than_dropped() {
        for body in [
            json!({"Value": false}),
            json!({"!": {"arg": value(json!(true))}}),
        ] {
            let error = condition_from_residual::<Model>(&body).expect_err("refuses");
            assert!(format!("{error}").contains("grants nothing"), "{error}");
        }
    }

    /// `true` absorbs a disjunction rather than dropping out of it. Taking
    /// the other branch instead would hand back a filter *narrower* than
    /// the policy — the mirror of the mistake every refusal here exists to
    /// prevent, and the one direction that is safe to get wrong is not
    /// this one.
    #[test]
    fn a_true_branch_of_a_disjunction_absorbs_it() {
        let body = json!({"||": {
            "left": value(json!(true)),
            "right": {"==": {"left": attr("region"), "right": value(json!("us"))}},
        }});

        let sql = sql(condition_from_residual::<Model>(&body).expect("translates"));

        assert!(
            !sql.contains("'us'"),
            "an unconditional branch grants every row, not the other branch's: {sql}",
        );
        assert!(sql.contains("WHERE TRUE"), "{sql}");
    }

    /// The shape this module does not read: partial evaluation over a
    /// *withheld* entity bases its attribute access on Cedar's `unknown`
    /// placeholder rather than the `resource` variable. Refusing is
    /// correct — that residual is about a different table — and silently
    /// translating it would build a `WHERE` clause against the wrong one.
    #[test]
    fn an_unknown_entity_base_is_refused_rather_than_read_as_the_resource() {
        let unknown = json!({".": {
            "left": {"unknown": [{"Value": "Widget::\"w-1\""}]},
            "attr": "region",
        }});
        let body = json!({"==": {"left": unknown, "right": value(json!("us"))}});

        assert!(condition_from_residual::<Model>(&body).is_err());
    }

    #[test]
    fn a_condition_on_the_caller_rather_than_the_row_is_refused() {
        let principal = json!({".": {"left": {"Var": "principal"}, "attr": "region"}});
        let body = json!({"==": {"left": principal, "right": value(json!("us"))}});

        assert!(condition_from_residual::<Model>(&body).is_err());
    }
}
