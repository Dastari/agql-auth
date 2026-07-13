//! Generic, purpose-bound authorization grant references.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::AuthPrincipal;

/// A non-secret reference to a purpose-bound grant or consent.
///
/// Domain-specific policy and payload manifests remain in the consuming
/// crate. This type only binds who granted what generic action, for which
/// audience/resource/purpose, and for how long.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PurposeBoundGrantReference {
    /// Stable grant identifier.
    pub grant_id: Uuid,
    /// Subject that granted or received the authority.
    pub subject: String,
    /// Intended audience/destination class.
    pub audience: String,
    /// Resource type.
    pub resource_type: String,
    /// Resource identifier.
    pub resource_id: String,
    /// Generic action being granted.
    pub action: String,
    /// Purpose limitation.
    pub purpose: String,
    /// Grant time.
    pub granted_at: OffsetDateTime,
    /// Expiry time.
    pub expires_at: OffsetDateTime,
    /// Revocation time, when revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<OffsetDateTime>,
    /// Optional assurance context reference, never an authentication secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assurance_ref: Option<String>,
}

impl PurposeBoundGrantReference {
    /// Evaluates this reference against the current principal and exact
    /// requested boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(
        &self,
        principal: &AuthPrincipal,
        audience: &str,
        resource_type: &str,
        resource_id: &str,
        action: &str,
        purpose: &str,
        now: OffsetDateTime,
    ) -> PurposeGrantStatus {
        if self.revoked_at.is_some_and(|revoked_at| revoked_at <= now) {
            return PurposeGrantStatus::Revoked;
        }
        if now < self.granted_at || now >= self.expires_at {
            return PurposeGrantStatus::Expired;
        }
        if principal.subject() != self.subject {
            return PurposeGrantStatus::SubjectMismatch;
        }
        if self.audience != audience {
            return PurposeGrantStatus::AudienceMismatch;
        }
        if self.resource_type != resource_type || self.resource_id != resource_id {
            return PurposeGrantStatus::ResourceMismatch;
        }
        if self.action != action {
            return PurposeGrantStatus::ActionMismatch;
        }
        if self.purpose != purpose {
            return PurposeGrantStatus::PurposeMismatch;
        }
        PurposeGrantStatus::Active
    }
}

/// Stable result of evaluating a purpose-bound grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurposeGrantStatus {
    /// Grant is currently valid for the exact boundary.
    Active,
    /// Grant has expired or is not active yet.
    Expired,
    /// Grant was revoked.
    Revoked,
    /// Current principal differs from the grant subject.
    SubjectMismatch,
    /// Audience differs.
    AudienceMismatch,
    /// Resource differs.
    ResourceMismatch,
    /// Action differs.
    ActionMismatch,
    /// Purpose differs.
    PurposeMismatch,
}
