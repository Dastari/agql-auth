use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::scopes::{
    has_all_scopes as scopes_include_all, has_any_scope as scopes_include_any,
    has_scope as scope_exists,
};
use crate::session::SessionContext;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthUser {
    pub user_id: String,
    pub session_id: Uuid,
    pub roles: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub session: SessionContext,
}

impl AuthUser {
    pub fn has_scope(&self, required: &str) -> bool {
        scope_exists(&self.scopes, required)
    }

    pub fn has_any_scope<S>(&self, required: &[S]) -> bool
    where
        S: AsRef<str>,
    {
        scopes_include_any(&self.scopes, required)
    }

    pub fn has_all_scopes<S>(&self, required: &[S]) -> bool
    where
        S: AsRef<str>,
    {
        scopes_include_all(&self.scopes, required)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredUser {
    pub id: String,
    pub principal: String,
    pub password_hash: String,
    pub roles: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub disabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RefreshTokenRevocationReason {
    Logout,
    Rotation,
    ReplayDetected,
    AdminRevoked,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRefreshToken {
    pub id: Uuid,
    pub user_id: String,
    pub session_id: Uuid,
    pub session_family_id: Uuid,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub session: SessionContext,
    pub token_hash: String,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
    pub replaced_by_token_id: Option<Uuid>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
}

impl StoredRefreshToken {
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        self.expires_at <= now
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthPayload {
    pub user: AuthUser,
    pub access_token: String,
    pub access_token_expires_at: OffsetDateTime,
    pub refresh_token: String,
    pub refresh_token_expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordResetToken {
    pub user_id: String,
    pub token_id: Uuid,
    pub token: String,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedPasswordResetToken {
    pub user_id: String,
    pub token_id: Uuid,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredLoginChallenge {
    pub id: Uuid,
    pub principal: String,
    pub code_hash: String,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub failed_attempts: u32,
    pub max_attempts: u32,
    pub consumed_at: Option<OffsetDateTime>,
    pub channel: Option<String>,
}

impl StoredLoginChallenge {
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        self.expires_at <= now
    }

    pub fn is_consumed(&self) -> bool {
        self.consumed_at.is_some()
    }

    pub fn attempts_exhausted(&self) -> bool {
        self.failed_attempts >= self.max_attempts
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginChallengeOptions {
    pub code_length: usize,
    pub ttl: Duration,
    pub max_attempts: u32,
    pub channel: Option<String>,
}

impl Default for LoginChallengeOptions {
    fn default() -> Self {
        Self {
            code_length: 6,
            ttl: Duration::minutes(10),
            max_attempts: 5,
            channel: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuedLoginChallenge {
    pub challenge_id: Uuid,
    pub principal: String,
    pub code: String,
    pub expires_at: OffsetDateTime,
    pub max_attempts: u32,
    pub channel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedLoginChallenge {
    pub challenge_id: Uuid,
    pub principal: String,
    pub verified_at: OffsetDateTime,
    pub channel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpSecret {
    pub raw_secret: Vec<u8>,
    pub base32_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpProvisioning {
    pub issuer: String,
    pub account_name: String,
    pub secret: String,
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpOptions {
    pub digits: u32,
    pub period_seconds: u64,
    pub allowed_skew: u64,
}

impl Default for TotpOptions {
    fn default() -> Self {
        Self {
            digits: 6,
            period_seconds: 30,
            allowed_skew: 1,
        }
    }
}
