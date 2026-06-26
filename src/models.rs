use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcAuthorizationRequest {
    pub authorization_url: String,
    pub provider_name: String,
    pub state: String,
    pub nonce: String,
    pub code_verifier: String,
    pub code_challenge: String,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcCallbackInput {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

impl OidcCallbackInput {
    pub fn code_and_state(code: impl Into<String>, state: impl Into<String>) -> Self {
        Self {
            code: Some(code.into()),
            state: Some(state.into()),
            error: None,
            error_description: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcTokenResponse {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: String,
    pub token_type: Option<String>,
    pub expires_in: Option<i64>,
    pub scope: Option<String>,
    #[serde(default)]
    pub raw: JsonValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedOidcClaims {
    pub provider_name: String,
    pub issuer: String,
    pub audiences: Vec<String>,
    pub subject: String,
    pub external_subject: String,
    pub expires_at: OffsetDateTime,
    pub not_before: OffsetDateTime,
    pub issued_at: OffsetDateTime,
    pub nonce: String,
    pub tenant_id: Option<String>,
    pub object_id: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
    #[serde(default)]
    pub raw: JsonValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalIdentity {
    pub provider_name: String,
    pub external_subject: String,
    pub user_id: String,
    pub issuer: String,
    pub tenant_id: Option<String>,
    pub provider_user_id: Option<String>,
    #[serde(default)]
    pub claims_snapshot: JsonValue,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthLoginState {
    pub provider_name: String,
    pub state_hash: String,
    pub nonce: String,
    pub code_verifier: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub consumed_at: Option<OffsetDateTime>,
}

impl OAuthLoginState {
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        self.expires_at <= now
    }

    pub fn is_consumed(&self) -> bool {
        self.consumed_at.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicrosoftEntraClaims {
    pub issuer: String,
    pub audience: Vec<String>,
    pub subject: String,
    pub tenant_id: String,
    pub object_id: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
}

impl TryFrom<&ValidatedOidcClaims> for MicrosoftEntraClaims {
    type Error = crate::AuthError;

    fn try_from(claims: &ValidatedOidcClaims) -> Result<Self, Self::Error> {
        let tenant_id = claims.tenant_id.clone().ok_or_else(|| {
            crate::AuthError::OidcTokenValidation(
                "Microsoft Entra ID token is missing tid".to_string(),
            )
        })?;

        Ok(Self {
            issuer: claims.issuer.clone(),
            audience: claims.audiences.clone(),
            subject: claims.subject.clone(),
            tenant_id,
            object_id: claims.object_id.clone(),
            email: claims.email.clone(),
            name: claims.name.clone(),
            preferred_username: claims.preferred_username.clone(),
            roles: claims.roles.clone(),
            groups: claims.groups.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcLoginResult {
    pub auth: AuthPayload,
    pub claims: ValidatedOidcClaims,
    pub external_identity: ExternalIdentity,
    pub token_response: OidcTokenResponse,
}
