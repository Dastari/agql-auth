use time::{Duration, OffsetDateTime};

use crate::models::AuthUser;
use crate::session::SessionContext;

/// Request to issue a short-lived access token without a refresh token.
#[derive(Debug, Clone)]
pub struct AccessTokenOnlyRequest {
    /// Principal subject placed in the access token `sub` claim.
    pub user_id: String,
    /// Roles embedded in the access token.
    pub roles: Vec<String>,
    /// Scopes embedded in the access token.
    pub scopes: Vec<String>,
    /// Session context embedded in the access token `ctx` claim.
    pub session: SessionContext,
    /// Optional token lifetime. Defaults to [`crate::AuthConfig::access_token_ttl`].
    pub ttl: Option<Duration>,
}

/// Short-lived access-token-only grant.
#[derive(Debug, Clone)]
pub struct AccessTokenOnlyGrant {
    /// Raw JWT access token.
    pub access_token: String,
    /// Access-token expiry time.
    pub access_token_expires_at: OffsetDateTime,
    /// User-shaped principal represented by the access token.
    pub user: AuthUser,
}
