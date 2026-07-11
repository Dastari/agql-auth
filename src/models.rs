use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::claims::AccessTokenMetadata;
use crate::scope_match::ScopeMatch;
use crate::scopes::{
    has_all_scopes as scopes_include_all, has_any_scope as scopes_include_any,
    has_scope as scope_exists,
};
use crate::session::SessionContext;

/// Authenticated local user attached to `async-graphql` request data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthUser {
    /// Stable local user ID.
    pub user_id: String,
    /// Local session ID.
    pub session_id: Uuid,
    /// Local roles assigned to the session.
    pub roles: Vec<String>,
    /// Local scopes assigned to the session.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Typed session context embedded in the access-token `ctx` claim.
    #[serde(default)]
    pub session: SessionContext,
    /// Optional standard access-token metadata (`jti`, tenant, `cnf`, etc.).
    #[serde(default)]
    pub token_claims: AccessTokenMetadata,
}

impl AuthUser {
    /// Returns `true` when the exact required scope is present.
    pub fn has_scope(&self, required: &str) -> bool {
        scope_exists(&self.scopes, required)
    }

    /// Returns `true` when any required scope is present.
    pub fn has_any_scope<S>(&self, required: &[S]) -> bool
    where
        S: AsRef<str>,
    {
        scopes_include_any(&self.scopes, required)
    }

    /// Returns `true` when all required scopes are present.
    pub fn has_all_scopes<S>(&self, required: &[S]) -> bool
    where
        S: AsRef<str>,
    {
        scopes_include_all(&self.scopes, required)
    }

    /// Returns `true` when the configured matcher satisfies the required scope.
    pub fn has_scope_with(&self, matcher: &dyn ScopeMatch, required: &str) -> bool {
        matcher.has_scope(&self.scopes, required)
    }

    /// Returns `true` when the configured matcher satisfies any required scope.
    pub fn has_any_scope_with<S>(&self, matcher: &dyn ScopeMatch, required: &[S]) -> bool
    where
        S: AsRef<str>,
    {
        required
            .iter()
            .any(|scope| self.has_scope_with(matcher, scope.as_ref()))
    }

    /// Returns `true` when the configured matcher satisfies all required scopes.
    pub fn has_all_scopes_with<S>(&self, matcher: &dyn ScopeMatch, required: &[S]) -> bool
    where
        S: AsRef<str>,
    {
        required
            .iter()
            .all(|scope| self.has_scope_with(matcher, scope.as_ref()))
    }
}

/// Extensible kind for API-token principals.
///
/// This is string-backed so host applications can use their own principal
/// categories while still having common constructors for service, integration,
/// and machine tokens.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct ApiTokenPrincipalKind(String);

impl ApiTokenPrincipalKind {
    /// Creates a custom principal kind.
    pub fn new(kind: impl Into<String>) -> Self {
        Self(kind.into())
    }

    /// Principal kind for service-to-service callers.
    pub fn service() -> Self {
        Self("service".to_string())
    }

    /// Principal kind for external integrations.
    pub fn integration() -> Self {
        Self("integration".to_string())
    }

    /// Principal kind for machine callers.
    pub fn machine() -> Self {
        Self("machine".to_string())
    }

    /// Returns the string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for ApiTokenPrincipalKind {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for ApiTokenPrincipalKind {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

/// Authenticated API-token principal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiTokenPrincipal {
    /// API token ID.
    pub token_id: Uuid,
    /// Principal subject, such as a service ID or integration ID.
    pub subject: String,
    /// Principal kind.
    pub principal_kind: ApiTokenPrincipalKind,
    /// Local scopes granted to this token.
    pub scopes: Vec<String>,
    /// Optional intended audience.
    pub audience: Option<String>,
    /// Optional generic resource type bound to this token.
    pub resource_type: Option<String>,
    /// Optional generic resource ID bound to this token.
    pub resource_id: Option<String>,
    /// Token expiry time.
    pub expires_at: OffsetDateTime,
}

impl ApiTokenPrincipal {
    /// Returns `true` when the exact required scope is present.
    pub fn has_scope(&self, required: &str) -> bool {
        scope_exists(&self.scopes, required)
    }

    /// Returns `true` when any required scope is present.
    pub fn has_any_scope<S>(&self, required: &[S]) -> bool
    where
        S: AsRef<str>,
    {
        scopes_include_any(&self.scopes, required)
    }

    /// Returns `true` when all required scopes are present.
    pub fn has_all_scopes<S>(&self, required: &[S]) -> bool
    where
        S: AsRef<str>,
    {
        scopes_include_all(&self.scopes, required)
    }

    /// Returns `true` when the configured matcher satisfies the required scope.
    pub fn has_scope_with(&self, matcher: &dyn ScopeMatch, required: &str) -> bool {
        matcher.has_scope(&self.scopes, required)
    }

    /// Returns `true` when the configured matcher satisfies any required scope.
    pub fn has_any_scope_with<S>(&self, matcher: &dyn ScopeMatch, required: &[S]) -> bool
    where
        S: AsRef<str>,
    {
        required
            .iter()
            .any(|scope| self.has_scope_with(matcher, scope.as_ref()))
    }

    /// Returns `true` when the configured matcher satisfies all required scopes.
    pub fn has_all_scopes_with<S>(&self, matcher: &dyn ScopeMatch, required: &[S]) -> bool
    where
        S: AsRef<str>,
    {
        required
            .iter()
            .all(|scope| self.has_scope_with(matcher, scope.as_ref()))
    }
}

/// Authenticated principal that can represent a user session or an API token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum AuthPrincipal {
    /// Existing local user-session principal.
    User(AuthUser),
    /// Opaque API/service-token principal.
    ApiToken(ApiTokenPrincipal),
}

impl AuthPrincipal {
    /// Returns the principal subject.
    pub fn subject(&self) -> &str {
        match self {
            Self::User(user) => &user.user_id,
            Self::ApiToken(token) => &token.subject,
        }
    }

    /// Returns local roles. API-token principals have no roles by default.
    pub fn roles(&self) -> &[String] {
        match self {
            Self::User(user) => &user.roles,
            Self::ApiToken(_) => &[],
        }
    }

    /// Returns local scopes.
    pub fn scopes(&self) -> &[String] {
        match self {
            Self::User(user) => &user.scopes,
            Self::ApiToken(token) => &token.scopes,
        }
    }

    /// Returns `true` when the exact required scope is present.
    pub fn has_scope(&self, required: &str) -> bool {
        scope_exists(self.scopes(), required)
    }

    /// Returns `true` when any required scope is present.
    pub fn has_any_scope<S>(&self, required: &[S]) -> bool
    where
        S: AsRef<str>,
    {
        scopes_include_any(self.scopes(), required)
    }

    /// Returns `true` when all required scopes are present.
    pub fn has_all_scopes<S>(&self, required: &[S]) -> bool
    where
        S: AsRef<str>,
    {
        scopes_include_all(self.scopes(), required)
    }

    /// Returns `true` when the configured matcher satisfies the required scope.
    pub fn has_scope_with(&self, matcher: &dyn ScopeMatch, required: &str) -> bool {
        match self {
            Self::User(user) => user.has_scope_with(matcher, required),
            Self::ApiToken(token) => token.has_scope_with(matcher, required),
        }
    }

    /// Returns `true` when the configured matcher satisfies any required scope.
    pub fn has_any_scope_with<S>(&self, matcher: &dyn ScopeMatch, required: &[S]) -> bool
    where
        S: AsRef<str>,
    {
        required
            .iter()
            .any(|scope| self.has_scope_with(matcher, scope.as_ref()))
    }

    /// Returns `true` when the configured matcher satisfies all required scopes.
    pub fn has_all_scopes_with<S>(&self, matcher: &dyn ScopeMatch, required: &[S]) -> bool
    where
        S: AsRef<str>,
    {
        required
            .iter()
            .all(|scope| self.has_scope_with(matcher, scope.as_ref()))
    }

    /// Returns the API-token audience, if this is an API-token principal.
    pub fn audience(&self) -> Option<&str> {
        match self {
            Self::User(_) => None,
            Self::ApiToken(token) => token.audience.as_deref(),
        }
    }

    /// Returns the API-token resource type, if this is an API-token principal.
    pub fn resource_type(&self) -> Option<&str> {
        match self {
            Self::User(_) => None,
            Self::ApiToken(token) => token.resource_type.as_deref(),
        }
    }

    /// Returns the API-token resource ID, if this is an API-token principal.
    pub fn resource_id(&self) -> Option<&str> {
        match self {
            Self::User(_) => None,
            Self::ApiToken(token) => token.resource_id.as_deref(),
        }
    }

    /// Returns the API token ID, if this is an API-token principal.
    pub fn token_id(&self) -> Option<Uuid> {
        match self {
            Self::User(_) => None,
            Self::ApiToken(token) => Some(token.token_id),
        }
    }

    /// Returns the API-token expiry, if this is an API-token principal.
    pub fn expires_at(&self) -> Option<OffsetDateTime> {
        match self {
            Self::User(_) => None,
            Self::ApiToken(token) => Some(token.expires_at),
        }
    }

    /// Returns the API-token principal kind, if this is an API-token principal.
    pub fn principal_kind(&self) -> Option<&ApiTokenPrincipalKind> {
        match self {
            Self::User(_) => None,
            Self::ApiToken(token) => Some(&token.principal_kind),
        }
    }

    /// Returns the contained user principal, if present.
    pub fn as_user(&self) -> Option<&AuthUser> {
        match self {
            Self::User(user) => Some(user),
            Self::ApiToken(_) => None,
        }
    }

    /// Returns the contained API-token principal, if present.
    pub fn as_api_token(&self) -> Option<&ApiTokenPrincipal> {
        match self {
            Self::User(_) => None,
            Self::ApiToken(token) => Some(token),
        }
    }

    /// Returns tenant ID from a user principal's token claims, if present.
    pub fn tenant_id(&self) -> Option<&str> {
        match self {
            Self::User(user) => user.token_claims.tenant_id.as_deref(),
            Self::ApiToken(_) => None,
        }
    }

    /// Returns `jti` / token reference suitable for audits (never a raw token).
    pub fn token_ref(&self) -> Option<String> {
        match self {
            Self::User(user) => user
                .token_claims
                .jti
                .clone()
                .or_else(|| Some(user.session_id.to_string())),
            Self::ApiToken(token) => Some(token.token_id.to_string()),
        }
    }

    /// Returns safe claim metadata for bridge layers such as `graphql-orm`.
    pub fn access_token_metadata(&self) -> Option<&AccessTokenMetadata> {
        match self {
            Self::User(user) => Some(&user.token_claims),
            Self::ApiToken(_) => None,
        }
    }
}

impl From<AuthUser> for AuthPrincipal {
    fn from(value: AuthUser) -> Self {
        Self::User(value)
    }
}

impl From<ApiTokenPrincipal> for AuthPrincipal {
    fn from(value: ApiTokenPrincipal) -> Self {
        Self::ApiToken(value)
    }
}

/// Authentication flow tracked by the abuse-protection store.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AuthRateLimitFlow {
    /// Username/password login.
    PasswordLogin,
    /// One-time login code verification.
    LoginCodeVerification,
    /// TOTP code verification.
    TotpVerification,
    /// Password-reset token consumption.
    PasswordResetTokenConsumption,
    /// Password-reset email request.
    PasswordResetRequest,
    /// Login-code email request.
    LoginCodeRequest,
}

impl AuthRateLimitFlow {
    /// Stable store value for this flow.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PasswordLogin => "password_login",
            Self::LoginCodeVerification => "login_code_verification",
            Self::TotpVerification => "totp_verification",
            Self::PasswordResetTokenConsumption => "password_reset_token_consumption",
            Self::PasswordResetRequest => "password_reset_request",
            Self::LoginCodeRequest => "login_code_request",
        }
    }
}

/// Abuse-protection bucket type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AuthRateLimitBucket {
    /// Bucket keyed by normalized principal or local user ID.
    Principal,
    /// Bucket keyed by client IP address.
    Client,
}

impl AuthRateLimitBucket {
    /// Stable store value for this bucket.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Principal => "principal",
            Self::Client => "client",
        }
    }
}

/// Opaque key for a persisted abuse-protection bucket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AuthRateLimitKey {
    /// Flow being protected.
    pub flow: AuthRateLimitFlow,
    /// Bucket type being protected.
    pub bucket: AuthRateLimitBucket,
    /// SHA-256 hash of the normalized bucket value.
    pub value_hash: String,
}

/// Persisted abuse-protection state for one flow/bucket key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthRateLimitState {
    /// Store key.
    pub key: AuthRateLimitKey,
    /// Attempts recorded in the current rolling window.
    pub attempts: u32,
    /// First attempt in the current rolling window.
    pub first_attempt_at: OffsetDateTime,
    /// Latest recorded attempt.
    pub last_attempt_at: OffsetDateTime,
    /// Backoff expiry, if exponential backoff is active.
    pub backoff_until: Option<OffsetDateTime>,
    /// Lockout expiry, if temporary lockout is active.
    pub locked_until: Option<OffsetDateTime>,
    /// Time after which stores may delete this state.
    pub expires_at: OffsetDateTime,
}

/// Reason an API token was revoked.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ApiTokenRevocationReason {
    /// Explicit manual revocation.
    Manual,
    /// Token expired and was marked revoked.
    Expired,
    /// All tokens for a principal were revoked.
    PrincipalRevoked,
    /// All tokens for a resource were revoked.
    ResourceRevoked,
}

/// Host-persisted API token record.
///
/// Stores should persist only `token_hash`; the raw token is returned once in
/// [`IssuedApiToken`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredApiToken {
    /// API token ID.
    pub id: Uuid,
    /// Hash of the raw opaque token.
    pub token_hash: String,
    /// Human-readable token display name.
    pub display_name: String,
    /// Principal subject, such as a service ID or integration ID.
    pub subject: String,
    /// Principal kind.
    pub principal_kind: ApiTokenPrincipalKind,
    /// Local scopes granted to this token.
    pub scopes: Vec<String>,
    /// Optional intended audience.
    pub audience: Option<String>,
    /// Optional generic resource type bound to this token.
    pub resource_type: Option<String>,
    /// Optional generic resource ID bound to this token.
    pub resource_id: Option<String>,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Expiry time.
    pub expires_at: OffsetDateTime,
    /// Last successful use time.
    pub last_used_at: Option<OffsetDateTime>,
    /// Revocation time, if revoked.
    pub revoked_at: Option<OffsetDateTime>,
    /// Last recorded user-agent metadata.
    pub user_agent: Option<String>,
    /// Last recorded IP metadata.
    pub ip_address: Option<String>,
}

impl StoredApiToken {
    /// Returns `true` when the token has expired.
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        self.expires_at <= now
    }

    /// Returns `true` when the token has been revoked.
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Builds an authenticated principal from this stored token.
    pub fn to_principal(&self) -> ApiTokenPrincipal {
        ApiTokenPrincipal {
            token_id: self.id,
            subject: self.subject.clone(),
            principal_kind: self.principal_kind.clone(),
            scopes: self.scopes.clone(),
            audience: self.audience.clone(),
            resource_type: self.resource_type.clone(),
            resource_id: self.resource_id.clone(),
            expires_at: self.expires_at,
        }
    }
}

/// API token returned once at issuance time.
#[derive(Clone, Serialize, Deserialize)]
pub struct IssuedApiToken {
    /// API token ID.
    pub token_id: Uuid,
    /// Raw opaque token. Store this only in the caller's secret store.
    pub token: String,
    /// Human-readable token display name.
    pub display_name: String,
    /// Principal subject.
    pub subject: String,
    /// Principal kind.
    pub principal_kind: ApiTokenPrincipalKind,
    /// Local scopes granted to this token.
    pub scopes: Vec<String>,
    /// Optional intended audience.
    pub audience: Option<String>,
    /// Optional generic resource type bound to this token.
    pub resource_type: Option<String>,
    /// Optional generic resource ID bound to this token.
    pub resource_id: Option<String>,
    /// Token creation time.
    pub created_at: OffsetDateTime,
    /// Token expiry time.
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for IssuedApiToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedApiToken")
            .field("token_id", &self.token_id)
            .field("token", &"[redacted]")
            .field("display_name", &self.display_name)
            .field("subject", &self.subject)
            .field("principal_kind", &self.principal_kind)
            .field("scopes", &self.scopes)
            .field("audience", &self.audience)
            .field("resource_type", &self.resource_type)
            .field("resource_id", &self.resource_id)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Request used to issue an opaque API token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiTokenIssueRequest {
    /// Human-readable token display name.
    pub display_name: String,
    /// Principal subject.
    pub subject: String,
    /// Principal kind.
    pub principal_kind: ApiTokenPrincipalKind,
    /// Local scopes granted to this token.
    pub scopes: Vec<String>,
    /// Token lifetime.
    pub ttl: Duration,
    /// Optional intended audience.
    pub audience: Option<String>,
    /// Optional generic resource type bound to this token.
    pub resource_type: Option<String>,
    /// Optional generic resource ID bound to this token.
    pub resource_id: Option<String>,
    /// Metadata to store on the initial token record.
    pub metadata: crate::ClientMetadata,
}

impl ApiTokenIssueRequest {
    /// Creates a token issue request with no scopes and no resource binding.
    pub fn new(
        display_name: impl Into<String>,
        subject: impl Into<String>,
        principal_kind: impl Into<ApiTokenPrincipalKind>,
        ttl: Duration,
    ) -> Self {
        Self {
            display_name: display_name.into(),
            subject: subject.into(),
            principal_kind: principal_kind.into(),
            scopes: Vec::new(),
            ttl,
            audience: None,
            resource_type: None,
            resource_id: None,
            metadata: crate::ClientMetadata::default(),
        }
    }

    /// Sets local scopes for the issued token.
    pub fn with_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Sets the intended audience for the issued token.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Sets a generic resource binding for the issued token.
    pub fn with_resource(
        mut self,
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Self {
        self.resource_type = Some(resource_type.into());
        self.resource_id = Some(resource_id.into());
        self
    }

    /// Sets initial token metadata.
    pub fn with_metadata(mut self, metadata: crate::ClientMetadata) -> Self {
        self.metadata = metadata;
        self
    }
}

/// User record returned by the host's [`crate::UserStore`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredUser {
    /// Stable local user ID.
    pub id: String,
    /// Login principal, such as email or username.
    pub principal: String,
    /// Argon2 password hash.
    pub password_hash: String,
    /// Local roles.
    pub roles: Vec<String>,
    /// Local scopes.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Whether login and refresh should be rejected.
    pub disabled: bool,
}

/// Reason a refresh token was revoked.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RefreshTokenRevocationReason {
    /// User logged out.
    Logout,
    /// Token was replaced during refresh-token rotation.
    Rotation,
    /// A revoked token was reused.
    ReplayDetected,
    /// Administrative revocation.
    AdminRevoked,
    /// Token expired.
    Expired,
}

/// Host-persisted refresh-token record.
///
/// The raw refresh token is returned only once in [`AuthPayload`]. Stores should
/// persist `token_hash`, not the raw token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRefreshToken {
    /// Refresh-token record ID.
    pub id: Uuid,
    /// Local user ID.
    pub user_id: String,
    /// Local session ID.
    pub session_id: Uuid,
    /// Session-family ID used for replay revocation.
    pub session_family_id: Uuid,
    /// Local scopes bound to refresh-token rotation.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Session context bound to refresh-token rotation.
    #[serde(default)]
    pub session: SessionContext,
    /// Explicitly allowlisted metadata that is safe to preserve on rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refreshable_metadata: Option<crate::RefreshableTokenMetadata>,
    /// Hash of the raw refresh token.
    pub token_hash: String,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Expiry time.
    pub expires_at: OffsetDateTime,
    /// Last successful use time.
    pub last_used_at: Option<OffsetDateTime>,
    /// Revocation time, if revoked.
    pub revoked_at: Option<OffsetDateTime>,
    /// Replacement token ID after rotation.
    pub replaced_by_token_id: Option<Uuid>,
    /// Last recorded user-agent metadata.
    pub user_agent: Option<String>,
    /// Last recorded IP metadata.
    pub ip_address: Option<String>,
}

impl StoredRefreshToken {
    /// Returns `true` when the record has expired.
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        self.expires_at <= now
    }

    /// Returns `true` when the record is revoked.
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}

/// Local session payload returned after login, refresh, or verified-session issuance.
#[derive(Clone, Serialize, Deserialize)]
pub struct AuthPayload {
    /// Authenticated local user.
    pub user: AuthUser,
    /// Short-lived local JWT access token.
    pub access_token: String,
    /// Access-token expiry time.
    pub access_token_expires_at: OffsetDateTime,
    /// Opaque refresh token returned once to the client.
    pub refresh_token: String,
    /// Refresh-token expiry time.
    pub refresh_token_expires_at: OffsetDateTime,
}

impl fmt::Debug for AuthPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthPayload")
            .field("user", &self.user)
            .field("access_token", &"[redacted]")
            .field("access_token_expires_at", &self.access_token_expires_at)
            .field("refresh_token", &"[redacted]")
            .field("refresh_token_expires_at", &self.refresh_token_expires_at)
            .finish()
    }
}

/// Request used to issue a short-lived JWT for one narrow purpose.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurposeTokenIssueRequest {
    /// Token subject.
    pub subject: String,
    /// Purpose expected by validators, such as `mobile_capture`.
    pub purpose: String,
    /// Intended audience for this token.
    pub audience: String,
    /// Token lifetime.
    pub ttl: Duration,
    /// Optional local session ID bound to the token.
    pub session_id: Option<Uuid>,
    /// Optional scopes carried by the token.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Additional custom JWT claims.
    #[serde(default)]
    pub claims: BTreeMap<String, JsonValue>,
}

impl PurposeTokenIssueRequest {
    /// Creates a purpose-token issue request.
    pub fn new(
        subject: impl Into<String>,
        purpose: impl Into<String>,
        audience: impl Into<String>,
        ttl: Duration,
    ) -> Self {
        Self {
            subject: subject.into(),
            purpose: purpose.into(),
            audience: audience.into(),
            ttl,
            session_id: None,
            scopes: Vec::new(),
            claims: BTreeMap::new(),
        }
    }

    /// Binds the token to a local session ID.
    pub fn with_session_id(mut self, session_id: Uuid) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Sets scopes carried by the token.
    pub fn with_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Adds a custom JWT claim.
    pub fn with_claim(mut self, name: impl Into<String>, value: JsonValue) -> Self {
        self.claims.insert(name.into(), value);
        self
    }
}

/// Purpose-token validation requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurposeTokenValidation {
    /// Required purpose claim.
    pub purpose: String,
    /// Required audience claim.
    pub audience: String,
}

impl PurposeTokenValidation {
    /// Creates purpose-token validation requirements.
    pub fn new(purpose: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            purpose: purpose.into(),
            audience: audience.into(),
        }
    }
}

/// Purpose token returned at issuance time.
#[derive(Clone, Serialize, Deserialize)]
pub struct IssuedPurposeToken {
    /// Raw signed JWT.
    pub token: String,
    /// Token subject.
    pub subject: String,
    /// Purpose claim.
    pub purpose: String,
    /// Audience claim.
    pub audience: String,
    /// Optional bound local session ID.
    pub session_id: Option<Uuid>,
    /// Token scopes.
    pub scopes: Vec<String>,
    /// Custom claims.
    pub claims: BTreeMap<String, JsonValue>,
    /// Token expiry time.
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for IssuedPurposeToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedPurposeToken")
            .field("token", &"[redacted]")
            .field("subject", &self.subject)
            .field("purpose", &self.purpose)
            .field("audience", &self.audience)
            .field("session_id", &self.session_id)
            .field("scopes", &self.scopes)
            .field("claims", &self.claims)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Validated short-lived purpose token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerifiedPurposeToken {
    /// Token subject.
    pub subject: String,
    /// Purpose claim.
    pub purpose: String,
    /// Audience claim.
    pub audience: String,
    /// Optional bound local session ID.
    pub session_id: Option<Uuid>,
    /// Token scopes.
    pub scopes: Vec<String>,
    /// Custom claims.
    pub claims: BTreeMap<String, JsonValue>,
    /// Issued-at time.
    pub issued_at: OffsetDateTime,
    /// Expiry time.
    pub expires_at: OffsetDateTime,
}

/// Password-reset token issued by [`crate::AuthService`].
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordResetToken {
    /// Local user ID.
    pub user_id: String,
    /// Token ID used for one-time storage.
    pub token_id: Uuid,
    /// Signed reset token sent to the user.
    pub token: String,
    /// Expiry time.
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for PasswordResetToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordResetToken")
            .field("user_id", &self.user_id)
            .field("token_id", &self.token_id)
            .field("token", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Verified password-reset token claims.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedPasswordResetToken {
    /// Local user ID.
    pub user_id: String,
    /// Token ID used for one-time consume.
    pub token_id: Uuid,
    /// Token issued-at time.
    pub issued_at: OffsetDateTime,
    /// Token expiry time.
    pub expires_at: OffsetDateTime,
}

/// Host-persisted one-time login challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredLoginChallenge {
    /// Challenge ID.
    pub id: Uuid,
    /// Principal being challenged.
    pub principal: String,
    /// Password hash of the one-time code.
    pub code_hash: String,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Expiry time.
    pub expires_at: OffsetDateTime,
    /// Failed verification attempts.
    pub failed_attempts: u32,
    /// Maximum allowed failed attempts.
    pub max_attempts: u32,
    /// Consumption time, if consumed.
    pub consumed_at: Option<OffsetDateTime>,
    /// Optional delivery channel label.
    pub channel: Option<String>,
}

impl StoredLoginChallenge {
    /// Returns `true` when the challenge has expired.
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        self.expires_at <= now
    }

    /// Returns `true` when the challenge has been consumed.
    pub fn is_consumed(&self) -> bool {
        self.consumed_at.is_some()
    }

    /// Returns `true` when failed attempts have reached the maximum.
    pub fn attempts_exhausted(&self) -> bool {
        self.failed_attempts >= self.max_attempts
    }
}

/// Options for a one-time login challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginChallengeOptions {
    /// Numeric code length.
    pub code_length: usize,
    /// Challenge lifetime.
    pub ttl: Duration,
    /// Maximum failed attempts before rejection.
    pub max_attempts: u32,
    /// Optional delivery channel label.
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

/// One-time login challenge returned to the host for delivery.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuedLoginChallenge {
    /// Challenge ID.
    pub challenge_id: Uuid,
    /// Principal being challenged.
    pub principal: String,
    /// Raw code to deliver to the user.
    pub code: String,
    /// Expiry time.
    pub expires_at: OffsetDateTime,
    /// Maximum failed attempts.
    pub max_attempts: u32,
    /// Optional delivery channel label.
    pub channel: Option<String>,
}

/// Result of a successfully verified login challenge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedLoginChallenge {
    /// Challenge ID.
    pub challenge_id: Uuid,
    /// Principal that completed the challenge.
    pub principal: String,
    /// Verification time.
    pub verified_at: OffsetDateTime,
    /// Optional delivery channel label.
    pub channel: Option<String>,
}

/// Generated TOTP secret.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpSecret {
    /// Raw random secret bytes.
    pub raw_secret: Vec<u8>,
    /// Base32-encoded secret used in authenticator apps.
    pub base32_secret: String,
}

impl fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpSecret")
            .field("raw_secret", &"[redacted]")
            .field("base32_secret", &"[redacted]")
            .finish()
    }
}

/// TOTP provisioning details for authenticator apps.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpProvisioning {
    /// Issuer displayed by authenticator apps.
    pub issuer: String,
    /// Account name displayed by authenticator apps.
    pub account_name: String,
    /// Base32 secret.
    pub secret: String,
    /// `otpauth://` provisioning URI.
    pub uri: String,
}

impl fmt::Debug for TotpProvisioning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpProvisioning")
            .field("issuer", &self.issuer)
            .field("account_name", &self.account_name)
            .field("secret", &"[redacted]")
            .field("uri", &"[redacted]")
            .finish()
    }
}

/// TOTP generation and validation options.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpOptions {
    /// Number of digits in generated codes.
    pub digits: u32,
    /// TOTP period length in seconds.
    pub period_seconds: u64,
    /// Allowed number of time steps before and after the current step.
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

/// Authorization redirect information returned by [`crate::OidcProvider`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcAuthorizationRequest {
    /// Fully built provider authorization URL.
    pub authorization_url: String,
    /// Provider name.
    pub provider_name: String,
    /// Raw OAuth state sent to the browser.
    pub state: String,
    /// Raw OIDC nonce.
    pub nonce: String,
    /// PKCE code verifier stored in state.
    pub code_verifier: String,
    /// PKCE S256 challenge sent to the provider.
    pub code_challenge: String,
    /// State expiry time.
    pub expires_at: OffsetDateTime,
}

/// Host-provided OIDC callback data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcCallbackInput {
    /// Authorization code from the provider callback.
    pub code: Option<String>,
    /// Raw state from the provider callback.
    pub state: Option<String>,
    /// Provider error code.
    pub error: Option<String>,
    /// Provider error description.
    pub error_description: Option<String>,
}

impl OidcCallbackInput {
    /// Creates callback input for a successful authorization-code callback.
    pub fn code_and_state(code: impl Into<String>, state: impl Into<String>) -> Self {
        Self {
            code: Some(code.into()),
            state: Some(state.into()),
            error: None,
            error_description: None,
        }
    }
}

/// OIDC token endpoint response.
#[derive(Clone, Serialize, Deserialize)]
pub struct OidcTokenResponse {
    /// Provider access token, if returned.
    pub access_token: Option<String>,
    /// Provider refresh token, if returned and requested.
    pub refresh_token: Option<String>,
    /// Provider ID token.
    pub id_token: String,
    /// Token type.
    pub token_type: Option<String>,
    /// Access-token lifetime in seconds.
    pub expires_in: Option<i64>,
    /// Provider-returned scope string.
    pub scope: Option<String>,
    /// Raw token response.
    #[serde(default)]
    pub raw: JsonValue,
}

impl fmt::Debug for OidcTokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcTokenResponse")
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[redacted]"),
            )
            .field("id_token", &"[redacted]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field("raw", &"[redacted]")
            .finish()
    }
}

/// Claims accepted after OIDC ID-token validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedOidcClaims {
    /// Provider name.
    pub provider_name: String,
    /// Token issuer.
    pub issuer: String,
    /// Token audiences.
    pub audiences: Vec<String>,
    /// OIDC subject.
    pub subject: String,
    /// Stable external subject used for linking.
    pub external_subject: String,
    /// Expiry time.
    pub expires_at: OffsetDateTime,
    /// Not-before time, when the provider supplied one.
    pub not_before: Option<OffsetDateTime>,
    /// Issued-at time.
    pub issued_at: OffsetDateTime,
    /// Provider-reported authentication time. This is not local MFA acceptance.
    #[serde(default)]
    pub auth_time: Option<OffsetDateTime>,
    /// Normalized provider-reported authentication methods.
    #[serde(default)]
    pub amr: Option<Vec<String>>,
    /// Provider-reported authentication context class.
    #[serde(default)]
    pub acr: Option<String>,
    /// Validated nonce.
    pub nonce: String,
    /// Provider tenant ID, when present.
    pub tenant_id: Option<String>,
    /// Provider object ID, when present.
    pub object_id: Option<String>,
    /// Email claim, when present.
    pub email: Option<String>,
    /// Display name, when present.
    pub name: Option<String>,
    /// Preferred username, when present.
    pub preferred_username: Option<String>,
    /// Provider roles claim.
    pub roles: Vec<String>,
    /// Provider groups claim.
    pub groups: Vec<String>,
    /// Raw accepted claims.
    #[serde(default)]
    pub raw: JsonValue,
}

/// Link between a provider identity and a local user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalIdentity {
    /// Provider name.
    pub provider_name: String,
    /// Stable provider subject selected by `agql-auth`.
    pub external_subject: String,
    /// Local user ID.
    pub user_id: String,
    /// Issuer associated with the link.
    pub issuer: String,
    /// Tenant ID, when present.
    pub tenant_id: Option<String>,
    /// Provider-specific user ID, when present.
    pub provider_user_id: Option<String>,
    /// Raw claims snapshot from the latest successful login.
    #[serde(default)]
    pub claims_snapshot: JsonValue,
    /// Link creation time.
    pub created_at: OffsetDateTime,
    /// Last update time.
    pub updated_at: OffsetDateTime,
}

/// Stored OIDC authorization state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthLoginState {
    /// Provider name.
    pub provider_name: String,
    /// Hash of the raw state value.
    pub state_hash: String,
    /// OIDC nonce bound to this authorization request.
    pub nonce: String,
    /// PKCE code verifier.
    pub code_verifier: String,
    /// Redirect URI used during authorization.
    pub redirect_uri: String,
    /// Requested scopes.
    pub scopes: Vec<String>,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Expiry time.
    pub expires_at: OffsetDateTime,
    /// Consumption time, if consumed.
    pub consumed_at: Option<OffsetDateTime>,
}

impl OAuthLoginState {
    /// Returns `true` when the state has expired.
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        self.expires_at <= now
    }

    /// Returns `true` when the state has already been consumed.
    pub fn is_consumed(&self) -> bool {
        self.consumed_at.is_some()
    }
}

/// Microsoft-specific view of validated OIDC claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicrosoftEntraClaims {
    /// Token issuer.
    pub issuer: String,
    /// Token audiences.
    pub audience: Vec<String>,
    /// OIDC subject.
    pub subject: String,
    /// Microsoft tenant ID.
    pub tenant_id: String,
    /// Microsoft object ID.
    pub object_id: Option<String>,
    /// Email claim, when present.
    pub email: Option<String>,
    /// Display name, when present.
    pub name: Option<String>,
    /// Preferred username, when present.
    pub preferred_username: Option<String>,
    /// Microsoft roles claim.
    pub roles: Vec<String>,
    /// Microsoft groups claim.
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

/// Result of a completed OIDC login and local session issuance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcLoginResult {
    /// Local `agql-auth` session payload.
    pub auth: AuthPayload,
    /// Validated OIDC claims.
    pub claims: ValidatedOidcClaims,
    /// External identity that was linked or updated.
    pub external_identity: ExternalIdentity,
    /// Provider token endpoint response.
    pub token_response: OidcTokenResponse,
}
