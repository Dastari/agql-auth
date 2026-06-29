use std::sync::Arc;

use async_graphql::Request;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::ClientMetadata;
use crate::models::{ApiTokenIssueRequest, AuthPrincipal, IssuedApiToken, StoredApiToken};
use crate::stores::ApiTokenStore;
use crate::util::{generate_opaque_token, hash_api_token, strip_bearer_prefix};
use crate::{AuthError, AuthResult};

/// Default prefix for generated API tokens.
///
/// The prefix is intentionally not JWT-like and generated tokens contain no
/// period separators.
pub const DEFAULT_API_TOKEN_PREFIX: &str = "agql_api_";

/// Service for issuing and authenticating long-lived opaque API tokens.
///
/// This service is independent of [`crate::AuthService`] and does not require
/// `UserStore` or `RefreshTokenStore`.
pub struct ApiTokenService<S> {
    store: Arc<S>,
    token_prefix: String,
}

impl<S> ApiTokenService<S>
where
    S: ApiTokenStore + 'static,
{
    /// Creates an API-token service with [`DEFAULT_API_TOKEN_PREFIX`].
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            token_prefix: DEFAULT_API_TOKEN_PREFIX.to_string(),
        }
    }

    /// Creates an API-token service with a custom token prefix.
    pub fn with_prefix(store: Arc<S>, token_prefix: impl Into<String>) -> AuthResult<Self> {
        let token_prefix = token_prefix.into();
        validate_token_prefix(&token_prefix)?;
        Ok(Self {
            store,
            token_prefix,
        })
    }

    /// Returns the configured token prefix.
    pub fn token_prefix(&self) -> &str {
        &self.token_prefix
    }

    /// Issues a new opaque API token and stores only its hash.
    pub async fn issue_token(&self, request: ApiTokenIssueRequest) -> AuthResult<IssuedApiToken> {
        validate_issue_request(&request)?;

        let now = OffsetDateTime::now_utc();
        let expires_at = now + request.ttl;
        let token_id = Uuid::new_v4();
        let raw_token = format!("{}{}", self.token_prefix, generate_opaque_token());
        let token_hash = hash_api_token(&raw_token);
        let stored = StoredApiToken {
            id: token_id,
            token_hash,
            display_name: request.display_name.clone(),
            subject: request.subject.clone(),
            principal_kind: request.principal_kind.clone(),
            scopes: request.scopes.clone(),
            audience: request.audience.clone(),
            resource_type: request.resource_type.clone(),
            resource_id: request.resource_id.clone(),
            created_at: now,
            expires_at,
            last_used_at: None,
            revoked_at: None,
            user_agent: request.metadata.user_agent.clone(),
            ip_address: request.metadata.ip_address.clone(),
        };

        self.store.insert_api_token(stored).await?;

        Ok(IssuedApiToken {
            token_id,
            token: raw_token,
            display_name: request.display_name,
            subject: request.subject,
            principal_kind: request.principal_kind,
            scopes: request.scopes,
            audience: request.audience,
            resource_type: request.resource_type,
            resource_id: request.resource_id,
            created_at: now,
            expires_at,
        })
    }

    /// Authenticates a bearer value with or without the `Bearer ` prefix.
    pub async fn authenticate_bearer(
        &self,
        bearer_or_token: &str,
        metadata: ClientMetadata,
    ) -> AuthResult<crate::ApiTokenPrincipal> {
        let token = strip_bearer_prefix(bearer_or_token)?;
        self.authenticate_token(token, metadata).await
    }

    /// Authenticates a raw API token.
    pub async fn authenticate_token(
        &self,
        token: &str,
        metadata: ClientMetadata,
    ) -> AuthResult<crate::ApiTokenPrincipal> {
        if !token.starts_with(&self.token_prefix) {
            return Err(AuthError::InvalidApiToken);
        }

        let token_hash = hash_api_token(token);
        let stored = self
            .store
            .find_api_token_by_hash(&token_hash)
            .await?
            .ok_or(AuthError::InvalidApiToken)?;

        if stored.is_revoked() {
            return Err(AuthError::ApiTokenRevoked);
        }

        if stored.is_expired(OffsetDateTime::now_utc()) {
            return Err(AuthError::ApiTokenExpired);
        }

        let used_at = OffsetDateTime::now_utc();
        self.store
            .touch_api_token(stored.id, used_at, metadata.ip_address, metadata.user_agent)
            .await?;

        Ok(stored.to_principal())
    }

    /// Revokes a single API token.
    pub async fn revoke_token(
        &self,
        token_id: Uuid,
        reason: crate::ApiTokenRevocationReason,
    ) -> AuthResult<()> {
        self.store
            .revoke_api_token(token_id, OffsetDateTime::now_utc(), reason)
            .await
    }

    /// Injects an API-token principal into an `async-graphql` request when a token is present.
    ///
    /// Passing `None` leaves the request unchanged.
    pub async fn inject_http_auth(
        &self,
        mut request: Request,
        bearer_or_token: Option<&str>,
        metadata: ClientMetadata,
    ) -> AuthResult<Request> {
        if let Some(raw) = bearer_or_token {
            let principal = self.authenticate_bearer(raw, metadata).await?;
            request = request
                .data(principal.clone())
                .data(AuthPrincipal::ApiToken(principal));
        }

        Ok(request)
    }
}

fn validate_token_prefix(token_prefix: &str) -> AuthResult<()> {
    if token_prefix.trim().is_empty() {
        return Err(AuthError::InvalidConfiguration(
            "api token prefix must not be empty".to_string(),
        ));
    }

    if token_prefix.chars().any(char::is_whitespace) {
        return Err(AuthError::InvalidConfiguration(
            "api token prefix must not contain whitespace".to_string(),
        ));
    }

    if token_prefix.contains('.') {
        return Err(AuthError::InvalidConfiguration(
            "api token prefix must not contain '.'".to_string(),
        ));
    }

    Ok(())
}

fn validate_issue_request(request: &ApiTokenIssueRequest) -> AuthResult<()> {
    if request.display_name.trim().is_empty() {
        return Err(AuthError::InvalidConfiguration(
            "api token display_name must not be empty".to_string(),
        ));
    }

    if request.subject.trim().is_empty() {
        return Err(AuthError::InvalidConfiguration(
            "api token subject must not be empty".to_string(),
        ));
    }

    if request.principal_kind.as_str().trim().is_empty() {
        return Err(AuthError::InvalidConfiguration(
            "api token principal_kind must not be empty".to_string(),
        ));
    }

    if request.ttl <= Duration::ZERO {
        return Err(AuthError::InvalidConfiguration(
            "api token ttl must be greater than zero".to_string(),
        ));
    }

    Ok(())
}
