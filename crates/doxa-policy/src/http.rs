//! Optional axum HTTP surface for the policy engine.
//!
//! Exposes [`PolicyRouter`] over HTTP so external services can:
//!
//! 1. **Ask a single decision** via `POST /check` — the equivalent of an
//!    in-process [`PolicyRouter::check`] call but reachable as a remote Policy
//!    Decision Point (PDP).
//! 2. **Run a what-if simulation** via `POST /test` — modeled on AWS IAM's
//!    [`SimulatePrincipalPolicy`] API. Takes one or more labeled principals
//!    (each with a role list), one or more actions, and one or more resources,
//!    and returns the full `principals × actions × resources` decision matrix
//!    in a single round-trip. Useful for policy authoring tools, regression
//!    tests, and "who can do what" audits.
//!
//! Both endpoints share a single Cedar `is_authorized_partial` evaluation
//! per `(tenant, principal, action, resource)` tuple, served from the
//! tenant-store cache that the rest of the crate already populates.
//!
//! [`SimulatePrincipalPolicy`]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html
//!
//! ## Mounting the router
//!
//! [`router`] returns a fully-stateful axum [`Router`] with two routes at
//! the root:
//!
//! - `POST /check`
//! - `POST /test`
//!
//! Consuming services nest it wherever they want the policy surface to
//! live in their own URL space:
//!
//! ```ignore
//! use std::sync::Arc;
//! use axum::Router;
//! use doxa_policy::{PolicyRouter, http};
//!
//! let policy_router: Arc<PolicyRouter<MyExtension>> = /* … */;
//!
//! let app: Router = Router::new()
//!     .nest("/v1/policy", http::router(policy_router))
//!     .route("/health", axum::routing::get(|| async { "ok" }));
//! ```
//!
//! With that nesting the endpoints become `POST /v1/policy/check` and
//! `POST /v1/policy/test`. If you'd rather mount them at the root, just
//! `merge` instead of `nest`.

use std::str::FromStr;
use std::sync::Arc;

use axum::{extract::State, routing::post, Json, Router};
use cedar_policy::EntityUid;
use serde::{Deserialize, Serialize};

use crate::error::AuthError;
use crate::extension::PolicyExtension;
use crate::router::{AccessDecision, PolicyRouter};

// ---------------------------------------------------------------------------
// /check — single decision
// ---------------------------------------------------------------------------

/// Request body for `POST /check`.
#[derive(Debug, Deserialize)]
pub struct CheckRequest {
    /// Tenant whose policy set should be evaluated.
    pub tenant_id: String,
    /// Roles asserted on the principal. Each role is mapped through the
    /// active [`PolicyExtension::build_role_uid`] when the synthetic user
    /// entity is constructed.
    pub roles: Vec<String>,
    /// Cedar action name (e.g. `"query"`, `"admin_write"`).
    pub action: String,
    /// Fully-qualified Cedar entity UID for the resource being acted on,
    /// in the standard `Type::"id"` syntax — for example
    /// `Document::"abc-123"` or `AdminConfig::"global"`.
    pub resource: String,
}

/// Response body for `POST /check` and each row of `POST /test`.
#[derive(Debug, Serialize)]
pub struct CheckResponse {
    /// `"allowed"` or `"denied"`. Cedar's three-valued partial result
    /// (`Allow` / `None` / `Deny`) is collapsed into a binary decision by
    /// [`PolicyRouter::check`] — `None` (residual) is treated as a denial
    /// here because there is no per-request context to resolve the residual
    /// against.
    pub decision: Decision,
    /// Human-readable rationale, populated for denials so callers can
    /// surface a useful error message and emit it to an audit log.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Binary decision serialized as a lowercase string for AWS-style API
/// affinity.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allowed,
    Denied,
}

impl From<AccessDecision> for CheckResponse {
    fn from(d: AccessDecision) -> Self {
        Self {
            decision: if d.allowed {
                Decision::Allowed
            } else {
                Decision::Denied
            },
            reason: d.reason,
        }
    }
}

#[tracing::instrument(skip_all, fields(tenant_id = %req.tenant_id, action = %req.action))]
async fn check_handler<E: PolicyExtension + 'static>(
    State(router): State<Arc<PolicyRouter<E>>>,
    Json(req): Json<CheckRequest>,
) -> Result<Json<CheckResponse>, AuthError> {
    let resource = parse_uid(&req.resource)?;
    let decision = router
        .check(&req.tenant_id, &req.roles, &req.action, resource)
        .await?;
    Ok(Json(decision.into()))
}

// ---------------------------------------------------------------------------
// /test — multi-principal × multi-action × multi-resource simulation
// ---------------------------------------------------------------------------

/// Request body for `POST /test`.
///
/// Modeled on AWS IAM's
/// [`SimulatePrincipalPolicy`](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html)
/// API, but extended to compare multiple labeled principals in a single
/// call. Each principal is evaluated against the full
/// `actions × resources` matrix and the response holds one row per
/// `(principal, action, resource)` cell — letting policy authors see at a
/// glance which roles have which capabilities.
#[derive(Debug, Deserialize)]
pub struct TestRequest {
    /// Tenant whose policy set should be evaluated.
    pub tenant_id: String,
    /// Labeled role sets to compare. Each principal runs against every
    /// `(action, resource)` pair in the request.
    pub principals: Vec<TestPrincipal>,
    /// Cedar action names to evaluate.
    pub actions: Vec<String>,
    /// Fully-qualified Cedar entity UIDs for the resources to evaluate,
    /// in the standard `Type::"id"` syntax.
    pub resources: Vec<String>,
}

/// One labeled principal in a [`TestRequest`].
#[derive(Debug, Deserialize)]
pub struct TestPrincipal {
    /// Caller-supplied label echoed back in the response — typically a
    /// human-readable role name (`"analyst"`) or a JIRA ticket id.
    pub label: String,
    /// Roles asserted on this principal.
    pub roles: Vec<String>,
}

/// Response body for `POST /test`.
#[derive(Debug, Serialize)]
pub struct TestResponse {
    /// Flat list of evaluation results, one row per
    /// `(principal, action, resource)` cell.
    pub evaluation_results: Vec<EvaluationResult>,
}

/// One row of a [`TestResponse`].
#[derive(Debug, Serialize)]
pub struct EvaluationResult {
    /// Echo of the principal's label from the request.
    pub principal_label: String,
    /// Echo of the action name from the request.
    pub action: String,
    /// Echo of the resource UID from the request.
    pub resource: String,
    /// `"allowed"` or `"denied"`.
    pub decision: Decision,
    /// Human-readable rationale, populated for denials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[tracing::instrument(
    skip_all,
    fields(
        tenant_id = %req.tenant_id,
        principal_count = req.principals.len(),
        action_count = req.actions.len(),
        resource_count = req.resources.len(),
    ),
)]
async fn test_handler<E: PolicyExtension + 'static>(
    State(router): State<Arc<PolicyRouter<E>>>,
    Json(req): Json<TestRequest>,
) -> Result<Json<TestResponse>, AuthError> {
    // Parse all resource UIDs once up front so a malformed UID fails the
    // whole request before any Cedar work happens.
    let parsed_resources: Vec<(String, EntityUid)> = req
        .resources
        .iter()
        .map(|raw| parse_uid(raw).map(|uid| (raw.clone(), uid)))
        .collect::<Result<_, _>>()?;

    let mut evaluation_results =
        Vec::with_capacity(req.principals.len() * req.actions.len() * parsed_resources.len());

    for principal in &req.principals {
        for action in &req.actions {
            for (resource_str, resource_uid) in &parsed_resources {
                let decision = router
                    .check(
                        &req.tenant_id,
                        &principal.roles,
                        action,
                        resource_uid.clone(),
                    )
                    .await?;
                evaluation_results.push(EvaluationResult {
                    principal_label: principal.label.clone(),
                    action: action.clone(),
                    resource: resource_str.clone(),
                    decision: if decision.allowed {
                        Decision::Allowed
                    } else {
                        Decision::Denied
                    },
                    reason: decision.reason,
                });
            }
        }
    }

    Ok(Json(TestResponse { evaluation_results }))
}

// ---------------------------------------------------------------------------
// Router constructor
// ---------------------------------------------------------------------------

/// Build the policy axum router.
///
/// Returns a [`Router`] with two routes at the root — `POST /check` and
/// `POST /test` — and the supplied [`PolicyRouter`] baked in as state. The
/// returned router is a `Router<()>`, ready to be mounted into a host
/// application via [`Router::nest`] or [`Router::merge`]:
///
/// ```ignore
/// app = app.nest("/v1/policy", doxa_policy::http::router(policy_router));
/// ```
///
/// Errors propagate through [`AuthError`]'s
/// [`IntoResponse`](axum::response::IntoResponse) impl (also gated on the
/// `axum` feature) so callers receive the same status codes the rest of the
/// crate uses.
pub fn router<E: PolicyExtension + 'static>(policy_router: Arc<PolicyRouter<E>>) -> Router {
    Router::new()
        .route("/check", post(check_handler::<E>))
        .route("/test", post(test_handler::<E>))
        .with_state(policy_router)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_uid(raw: &str) -> Result<EntityUid, AuthError> {
    EntityUid::from_str(raw)
        .map_err(|e| AuthError::PolicyFailed(format!("invalid resource UID '{raw}': {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{build_stub_router, StubExtension};

    fn build_router(policy_text: &'static str) -> Arc<PolicyRouter<StubExtension>> {
        build_stub_router(policy_text)
    }

    // ── /check ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn check_returns_denied_when_no_policies_match() {
        let router = build_router("");
        let response = check_handler(
            State(router),
            Json(CheckRequest {
                tenant_id: "acme".into(),
                roles: vec!["analyst".into()],
                action: "query".into(),
                resource: r#"Model::"acme::orders""#.into(),
            }),
        )
        .await
        .expect("handler ok");
        assert!(matches!(response.decision, Decision::Denied));
        assert!(response.reason.is_some());
    }

    #[tokio::test]
    async fn check_returns_allowed_when_policy_matches() {
        // Permit any principal with `Role::"analyst"` to `query` any
        // `Model::"check_allow::orders"` resource. Each router owns its
        // own tenant-store cache, so there is no process-wide state to
        // avoid — unique tenant ids remain useful only for readability.
        let policy = r#"
            permit(
                principal in Role::"analyst",
                action == Action::"query",
                resource == Model::"check_allow::orders"
            );
        "#;
        let router = build_router(policy);
        let response = check_handler(
            State(router),
            Json(CheckRequest {
                tenant_id: "check_allow".into(),
                roles: vec!["analyst".into()],
                action: "query".into(),
                resource: r#"Model::"check_allow::orders""#.into(),
            }),
        )
        .await
        .expect("handler ok");
        assert!(matches!(response.decision, Decision::Allowed));
        assert!(response.reason.is_none());
    }

    #[tokio::test]
    async fn check_rejects_malformed_resource_uid() {
        let router = build_router("");
        let err = check_handler(
            State(router),
            Json(CheckRequest {
                tenant_id: "acme".into(),
                roles: vec![],
                action: "query".into(),
                resource: "not a valid uid".into(),
            }),
        )
        .await
        .expect_err("malformed UID should be rejected");
        match err {
            AuthError::PolicyFailed(msg) => assert!(msg.contains("invalid resource UID")),
            other => panic!("expected PolicyFailed, got {other:?}"),
        }
    }

    // ── /test ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_returns_full_principal_action_resource_matrix() {
        // Unique tenant id avoids cache bleed across tests.
        let policy = r#"
            permit(
                principal in Role::"analyst",
                action == Action::"query",
                resource == Model::"test_matrix::orders"
            );
        "#;
        let router = build_router(policy);
        let response = test_handler(
            State(router),
            Json(TestRequest {
                tenant_id: "test_matrix".into(),
                principals: vec![
                    TestPrincipal {
                        label: "analyst".into(),
                        roles: vec!["analyst".into()],
                    },
                    TestPrincipal {
                        label: "viewer".into(),
                        roles: vec!["viewer".into()],
                    },
                ],
                actions: vec!["query".into(), "write_model".into()],
                resources: vec![r#"Model::"test_matrix::orders""#.into()],
            }),
        )
        .await
        .expect("handler ok");

        // 2 principals × 2 actions × 1 resource = 4 rows.
        assert_eq!(response.evaluation_results.len(), 4);

        // Find the (analyst, query, orders) row — should be allowed.
        let allowed_row = response
            .evaluation_results
            .iter()
            .find(|r| {
                r.principal_label == "analyst"
                    && r.action == "query"
                    && r.resource == r#"Model::"test_matrix::orders""#
            })
            .expect("missing analyst/query row");
        assert!(matches!(allowed_row.decision, Decision::Allowed));

        // Every other row should be denied (analyst lacks write_model;
        // viewer lacks both).
        for row in &response.evaluation_results {
            if row.principal_label == "analyst" && row.action == "query" {
                continue;
            }
            assert!(
                matches!(row.decision, Decision::Denied),
                "expected denial for ({}, {}, {})",
                row.principal_label,
                row.action,
                row.resource,
            );
        }
    }

    #[tokio::test]
    async fn test_rejects_malformed_resource_uid_before_evaluation() {
        let router = build_router("");
        let err = test_handler(
            State(router),
            Json(TestRequest {
                tenant_id: "acme".into(),
                principals: vec![TestPrincipal {
                    label: "analyst".into(),
                    roles: vec!["analyst".into()],
                }],
                actions: vec!["query".into()],
                resources: vec![r#"Model::"acme::orders""#.into(), "garbage".into()],
            }),
        )
        .await
        .expect_err("malformed UID should fail the whole request");
        assert!(matches!(err, AuthError::PolicyFailed(_)));
    }

    // ── Decision serialization ─────────────────────────────────────────

    #[test]
    fn decision_serializes_lowercase() {
        // The wire format uses lowercase strings for AWS-style affinity.
        // Pin the contract here so a refactor doesn't accidentally drift
        // to PascalCase.
        let allowed = serde_json::to_string(&Decision::Allowed).unwrap();
        let denied = serde_json::to_string(&Decision::Denied).unwrap();
        assert_eq!(allowed, "\"allowed\"");
        assert_eq!(denied, "\"denied\"");
    }
}
