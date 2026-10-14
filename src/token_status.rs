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

/// Revalidates an accepted credential immediately before a sensitive operation.
///
/// `now` must come from the host's trusted evaluation clock immediately before
/// this call, using the same time basis as token expiry. Never cache or reuse a
/// successful result across operations/events. Asynchronous store reads observe
/// their state during this evaluation, not an atomic cross-store snapshot.
///
/// Both dependencies are mandatory. The checker must perform an authoritative
/// online check for this principal kind (including account, token, session and
/// family revocation where applicable); an always-active placeholder does not
/// meet this contract. The resolver must reject disabled/deleted principals and
/// read current grants. Errors propagate without fail-open or periodic caching.
///
/// The result preserves the accepted credential's bindings and assurance while
/// intersecting its roles/scopes with current authority. Resolvers must retain
/// the exact credential reference for this operation, including token identity;
/// a replacement credential is not proof that the accepted token is active.
/// Session-bound delegation is the explicit exception: the resolver supplies
/// its authoritative parent session using the existing reference contract, while
/// the checker must independently check the original delegated token's status.
///
/// The decision observes authoritative state at evaluation. Hosts needing an
/// atomic relationship to a subsequent write must supply transaction/version
/// fencing; revocation after evaluation cannot undo an external write.
pub async fn revalidate_sensitive_principal(
    accepted: &AuthPrincipal,
    resolver: &dyn crate::CurrentPrincipalResolver,
    checker: &dyn TokenStatusChecker,
    now: OffsetDateTime,
) -> AuthResult<AuthPrincipal> {
    let reference = accepted.reference();
    if reference.subject.trim().is_empty()
        || reference
            .token_id
            .as_ref()
            .is_none_or(|id| id.trim().is_empty())
    {
        return Err(AuthError::Forbidden);
    }
    if reference.expires_at.is_none_or(|expiry| expiry <= now) {
        return Err(AuthError::AccessTokenExpired);
    }
    let status = checker
        .check(TokenStatusRequest {
            principal: accepted,
            token_id: reference.token_id.as_deref(),
            session_id: reference.session_id.as_deref(),
            session_family_id: reference.session_family_id.as_deref(),
            tenant_id: reference.tenant_id.as_deref(),
        })
        .await?;
    ReauthorizationPolicy::status_to_error(status)?;
    let resolved = resolver.resolve(&reference).await?;
    let delegation =
        reference.grant_kind == Some(crate::AccessTokenGrantKind::SessionBoundDelegation);
    if resolved.reference() != &reference
        || if delegation {
            !reference.matches(resolved.principal())
        } else {
            resolved.principal().reference() != reference
        }
    {
        return Err(AuthError::Forbidden);
    }
    let current = resolved.principal();
    if current
        .reference()
        .expires_at
        .is_none_or(|expiry| expiry <= now)
    {
        return Err(AuthError::AccessTokenExpired);
    }
    let mut narrowed = accepted.clone();
    match (&mut narrowed, current) {
        (AuthPrincipal::User(accepted), AuthPrincipal::User(current)) => {
            if delegation
                && (reference
                    .session_version
                    .as_ref()
                    .is_none_or(|v| v.trim().is_empty())
                    || reference
                        .session_family_id
                        .as_ref()
                        .is_none_or(|v| v.trim().is_empty()))
            {
                return Err(AuthError::Forbidden);
            }
            if accepted.session.active_scope != current.session.active_scope {
                return Err(AuthError::Forbidden);
            }
            accepted.roles.retain(|role| current.roles.contains(role));
            accepted
                .scopes
                .retain(|scope| current.scopes.contains(scope));
            accepted
                .token_claims
                .authorization_roles
                .retain(|role| current.token_claims.authorization_roles.contains(role));
        }
        (AuthPrincipal::ApiToken(accepted), AuthPrincipal::ApiToken(current)) => {
            accepted
                .scopes
                .retain(|scope| current.scopes.contains(scope));
        }
        _ => return Err(AuthError::Forbidden),
    }
    Ok(narrowed)
}
