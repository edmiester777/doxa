//! Audit event types and outcomes.

use std::fmt;

/// Trait for audit event type enums.
///
/// **Applications are expected to define their own event-type enum** and
/// implement this trait for it. The event vocabulary — what counts as an
/// auditable category — is a domain concern and belongs to the consumer,
/// not this library.
///
/// The built-in [`EventType`] enum below is provided as a reference
/// implementation covering a handful of universally-applicable
/// categories (data access, admin CRUD, auth failure). Use it directly
/// if it fits; otherwise ignore it and ship your own.
///
/// Implementors provide a string representation that is persisted to the
/// `event_type` varchar(50) column.
///
/// # Example
///
/// ```
/// use doxa_audit::AuditEventType;
///
/// enum MyEventType {
///     WebhookReceived,
///     JobCompleted,
/// }
///
/// impl AuditEventType for MyEventType {
///     fn as_str(&self) -> &str {
///         match self {
///             Self::WebhookReceived => "webhook_received",
///             Self::JobCompleted => "job_completed",
///         }
///     }
/// }
/// ```
pub trait AuditEventType: Send + Sync {
    /// String representation persisted to the database.
    ///
    /// Must be ≤ 50 bytes to fit the `event_type` column.
    fn as_str(&self) -> &str;
}

/// Reference implementation of [`AuditEventType`] covering a handful of
/// universally-applicable categories.
///
/// Use this enum directly if its variants fit your domain. Most
/// applications will want to define their own enum — event categories are
/// a domain concern, and this one is deliberately minimal. See
/// [`AuditEventType`] for the trait your custom enum must implement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    DataAccess,
    AdminCreate,
    AdminUpdate,
    AdminDelete,
    AuthFailure,
}

impl EventType {
    /// The persisted string as `'static`, which `as_str` on a temporary can't return.
    pub const fn as_static(&self) -> &'static str {
        match self {
            Self::DataAccess => "data_access",
            Self::AdminCreate => "admin_create",
            Self::AdminUpdate => "admin_update",
            Self::AdminDelete => "admin_delete",
            Self::AuthFailure => "auth_failure",
        }
    }
}

impl AuditEventType for EventType {
    fn as_str(&self) -> &str {
        self.as_static()
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Result of an auditable operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Allowed,
    Denied,
    Error,
    /// A dry run asking whether the caller could; nothing was done.
    Probe,
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Outcome {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "allowed" => Ok(Self::Allowed),
            "denied" => Ok(Self::Denied),
            "error" => Ok(Self::Error),
            "probe" => Ok(Self::Probe),
            other => Err(format!("unknown outcome: {other}")),
        }
    }
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Error => "error",
            Self::Probe => "probe",
        }
    }
}

/// An error's audit outcome, read by [`AuditLayer`](crate::AuditLayer) from the response.
/// `#[derive(ApiError)]` implements it from `#[api(outcome = "…")]`, defaulting to `Error`.
///
/// ```
/// use doxa_audit::{AuditOutcome, Outcome};
///
/// enum MyError {
///     NotFound,
///     Forbidden,
///     Internal,
/// }
///
/// impl AuditOutcome for MyError {
///     fn audit_outcome(&self) -> Outcome {
///         match self {
///             Self::NotFound => Outcome::Allowed,  // legitimate miss
///             Self::Forbidden => Outcome::Denied,
///             Self::Internal => Outcome::Error,
///         }
///     }
/// }
/// ```
pub trait AuditOutcome {
    /// The audit outcome for this value.
    fn audit_outcome(&self) -> Outcome;
}

/// A fully-populated audit event ready for persistence.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// String representation of the event type (e.g. `"data_access"`).
    /// Produced by [`AuditEventType::as_str`] at builder time.
    pub event_type: String,
    pub action: String,
    pub outcome: Outcome,
    /// `None` when single-tenant, or recorded before a principal was resolved.
    pub tenant_id: Option<String>,
    pub actor_sub: Option<String>,
    pub actor_roles: Option<Vec<String>>,
    /// Consumer-defined identity attributes, persisted verbatim.
    pub actor_attrs: serde_json::Value,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub request_body: Option<serde_json::Value>,
    pub response_summary: Option<serde_json::Value>,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    /// HTTP method (GET, POST, etc.) — auto-populated by
    /// [`AuditLayer`](crate::AuditLayer).
    pub http_method: Option<String>,
    /// Request path (e.g. `/api/v1/widgets/42`) — auto-populated by
    /// [`AuditLayer`](crate::AuditLayer).
    pub http_path: Option<String>,
    /// Response status code — auto-populated by
    /// [`AuditLayer`](crate::AuditLayer).
    pub http_status: Option<u16>,
    pub duration_ms: Option<i64>,
    pub error_message: Option<String>,
}
