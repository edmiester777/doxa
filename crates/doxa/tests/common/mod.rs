//! Checkers shared by the auth tests.
#![allow(dead_code)]

use async_trait::async_trait;
use doxa::policy::{AuthError, Capability, CapabilityChecker, ResourceEntity};
use serde_json::json;

/// Allows everything.
pub struct AllowAll;

#[async_trait]
impl CapabilityChecker for AllowAll {
    async fn check(&self, _: &str, _: &[String], _: &Capability) -> Result<bool, AuthError> {
        Ok(true)
    }

    async fn check_instance(
        &self,
        _: &str,
        _: &[String],
        _: &str,
        _: &ResourceEntity,
    ) -> Result<bool, AuthError> {
        Ok(true)
    }
}

/// Grants the capability to `viewer`, and an instance only in region `us`.
pub struct RegionChecker;

#[async_trait]
impl CapabilityChecker for RegionChecker {
    async fn check(&self, _: &str, roles: &[String], _: &Capability) -> Result<bool, AuthError> {
        Ok(roles.iter().any(|r| r == "viewer"))
    }

    async fn check_instance(
        &self,
        _: &str,
        _: &[String],
        _: &str,
        resource: &ResourceEntity,
    ) -> Result<bool, AuthError> {
        Ok(resource.attrs.get("region") == Some(&json!("us")))
    }
}
