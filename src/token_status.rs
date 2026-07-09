//! Generic token/session status checks for request and long-lived connection paths.

use async_trait::async_trait;
use time::{Duration, OffsetDateTime};

use crate::AuthResult;
use crate::claims::AccessTokenMetadata;
use crate::errors::AuthError;
use crate::models::AuthPrincipal;

/// Status of an authenticated principal relative to revocation/expiry policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenStatus {
    /// Principal remains valid.
    Active,
    /// Principal or token has been revoked.
    Revoked,
    /// Principal or token has expired under policy.
    Expired,
}

/// Failure mode when a status checker cannot complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StatusCheckFailureMode {
    /// Treat checker failures as authentication failures (security default).
    #[default]
    FailClosed,
    /// Treat checker failures as active. Hosts must opt in deliberately.
    FailOpen,
}

/// Input for a status check.
#[derive(Debug, Clone)]
pub struct TokenStatusRequest<'a> {
    /// Authenticated principal.
    pub principal: &'a AuthPrincipal,
    /// Token identifier (`jti` or opaque token id).
    pub token_id: Option<&'a str>,
    /// Session identifier.
    pub session_id: Option<&'a str>,
    /// Session-family identifier.
    pub session_family_id: Option<&'a str>,
    /// Tenant identifier when present.
    pub tenant_id: Option<&'a str>,
}

/// Host-provided revocation and session-status checker.
#[async_trait]
pub trait TokenStatusChecker: Send + Sync {
    /// Checks whether a principal/token/session remains valid.
    async fn check(&self, request: TokenStatusRequest<'_>) -> AuthResult<TokenStatus>;
}

/// Always-active checker used when hosts have no revocation store.
#[derive(Debug, Default, Clone, Copy)]
pub struct AlwaysActiveTokenStatus;

#[async_trait]
impl TokenStatusChecker for AlwaysActiveTokenStatus {
    async fn check(&self, _request: TokenStatusRequest<'_>) -> AuthResult<TokenStatus> {
        Ok(TokenStatus::Active)
    }
}

/// Policy for periodic reauthorization of long-lived connections.
#[derive(Debug, Clone, PartialEq)]
pub struct ReauthorizationPolicy {
    /// Minimum interval between reauthorization checks.
    pub min_interval: Duration,
    /// Fraction of remaining token lifetime after which reauthorization is due.
    ///
    /// For example `0.5` reauthorizes halfway to expiry. Clamped to `(0, 1]`.
    pub lifetime_fraction: f64,
    /// Absolute maximum connection lifetime without reauthorization.
    pub max_connection_ttl: Option<Duration>,
    /// Failure mode for status-checker errors.
    pub failure_mode: StatusCheckFailureMode,
}

impl Default for ReauthorizationPolicy {
    fn default() -> Self {
        Self {
            min_interval: Duration::minutes(1),
            lifetime_fraction: 0.5,
            max_connection_ttl: None,
            failure_mode: StatusCheckFailureMode::FailClosed,
        }
    }
}

impl ReauthorizationPolicy {
    /// Computes the next reauthorization deadline from token metadata and now.
    pub fn next_deadline(
        &self,
        now: OffsetDateTime,
        metadata: &AccessTokenMetadata,
        connection_started_at: OffsetDateTime,
    ) -> OffsetDateTime {
        let mut deadline = now + self.min_interval;

        if let Some(expires_at) = metadata.expires_at {
            let remaining = expires_at - now;
            if remaining > Duration::ZERO {
                let fraction = self.lifetime_fraction.clamp(0.01, 1.0);
                let fraction_secs = (remaining.whole_seconds() as f64 * fraction).ceil() as i64;
                let candidate = now + Duration::seconds(fraction_secs.max(1));
                if candidate < deadline {
                    deadline = candidate;
                }
                if expires_at < deadline {
                    deadline = expires_at;
                }
            } else {
                deadline = now;
            }
        }

        if let Some(max_ttl) = self.max_connection_ttl {
            let max_deadline = connection_started_at + max_ttl;
            if max_deadline < deadline {
                deadline = max_deadline;
            }
        }

        deadline
    }

    /// Applies failure-mode policy to a checker result.
    pub fn map_checker_result(&self, result: AuthResult<TokenStatus>) -> AuthResult<TokenStatus> {
        match result {
            Ok(status) => Ok(status),
            Err(err) => match self.failure_mode {
                StatusCheckFailureMode::FailClosed => Err(err),
                StatusCheckFailureMode::FailOpen => Ok(TokenStatus::Active),
            },
        }
    }

    /// Converts a terminal status into an [`AuthError`].
    pub fn status_to_error(status: TokenStatus) -> AuthResult<()> {
        match status {
            TokenStatus::Active => Ok(()),
            TokenStatus::Revoked => Err(AuthError::TokenRevoked),
            TokenStatus::Expired => Err(AuthError::AccessTokenExpired),
        }
    }
}
