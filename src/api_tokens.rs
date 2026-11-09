use std::fmt;
use std::sync::Arc;

use async_graphql::Request;
use async_trait::async_trait;
use time::Duration;
use uuid::Uuid;

use crate::clock::{Clock, SystemClock};
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

/// Receives API-token last-used updates that failed, for host monitoring.
///
/// Recording last-used metadata is best effort: a failed
/// [`ApiTokenStore::touch_api_token`] does not fail authentication. Without an
/// observer the failure is dropped.
#[async_trait]
pub trait ApiTokenTouchObserver: Send + Sync {
    /// Called once, after authentication succeeded, when the touch failed.
    async fn api_token_touch_failed(&self, token_id: Uuid, error: &AuthError);
}

/// Service for issuing and authenticating long-lived opaque API tokens.
///
/// This service is independent of [`crate::AuthService`] and does not require
/// `UserStore` or `RefreshTokenStore`.
///
/// Authentication refuses a token issued for another audience or resource; see
/// [`Self::with_expected_audience`] and [`Self::with_expected_resource`].
pub struct ApiTokenService<S> {
    store: Arc<S>,
    token_prefix: String,
    expected_audience: Option<String>,
    expected_resource: Option<(String, String)>,
    touch_observer: Option<Arc<dyn ApiTokenTouchObserver>>,
    clock: Arc<dyn Clock>,
}

impl<S> fmt::Debug for ApiTokenService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiTokenService")
            .field("token_prefix", &self.token_prefix)
            .field("expected_audience", &self.expected_audience)
            .field("expected_resource", &self.expected_resource)
            .field("touch_observer", &self.touch_observer.is_some())
            .finish()
    }
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
            expected_audience: None,
            expected_resource: None,
            touch_observer: None,
            clock: Arc::new(SystemClock),
        }
    }

    /// Creates an API-token service with a custom token prefix.
    pub fn with_prefix(store: Arc<S>, token_prefix: impl Into<String>) -> AuthResult<Self> {
        let token_prefix = token_prefix.into();
        validate_token_prefix(&token_prefix)?;
        Ok(Self {
            token_prefix,
            ..Self::new(store)
        })
    }

    /// Declares the audience this service authenticates for.
    ///
    /// Authentication then accepts only tokens issued with exactly this
    /// audience. Without it, a token issued with any audience is refused, since
    /// this service cannot show it is that audience; tokens without an audience
    /// are accepted. A refused token fails as [`AuthError::InvalidApiToken`].
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfiguration`] for an empty value or one
    /// with surrounding whitespace or control characters.
    pub fn with_expected_audience(mut self, audience: impl Into<String>) -> AuthResult<Self> {
        let audience = audience.into();
        validate_binding_value("api token expected audience", &audience)?;
        self.expected_audience = Some(audience);
        Ok(self)
    }

    /// Declares the one resource this service authenticates for.
    ///
    /// Authentication then accepts only tokens bound to exactly this resource
    /// type and ID; unbound tokens and tokens for another resource fail as
    /// [`AuthError::InvalidApiToken`]. Without it, resource-bound tokens are
    /// accepted and carry their binding on [`crate::ApiTokenPrincipal`], which
    /// the host must enforce for each request.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidConfiguration`] for an invalid value, as for
    /// [`Self::with_expected_audience`].
    pub fn with_expected_resource(
        mut self,
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> AuthResult<Self> {
        let resource_type = resource_type.into();
        let resource_id = resource_id.into();
        validate_binding_value("api token expected resource type", &resource_type)?;
        validate_binding_value("api token expected resource id", &resource_id)?;
        self.expected_resource = Some((resource_type, resource_id));
        Ok(self)
    }

    /// Uses `clock` for issuance, expiry checks, last-used stamps and
    /// revocation times instead of the system clock.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Reports failed last-used updates to `observer`.
    pub fn with_touch_observer<O>(mut self, observer: Arc<O>) -> Self
    where
        O: ApiTokenTouchObserver + 'static,
    {
        self.touch_observer = Some(observer);
        self
    }

    /// Returns the configured token prefix.
    pub fn token_prefix(&self) -> &str {
        &self.token_prefix
    }

    /// Issues a new opaque API token and stores only its hash.
    pub async fn issue_token(&self, request: ApiTokenIssueRequest) -> AuthResult<IssuedApiToken> {
        validate_issue_request(&request)?;

        let now = self.clock.now();
        let expires_at = crate::util::checked_expiry(now, request.ttl, "API-token ttl")?;
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
    ///
    /// Unknown tokens and tokens issued for another audience or resource fail
    /// as [`AuthError::InvalidApiToken`]; revoked and expired tokens then fail
    /// with their own errors. Last-used metadata is recorded best effort: a
    /// store error there does not fail authentication and goes to the
    /// [`ApiTokenTouchObserver`], if one is configured.
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

        // A token for another audience or resource is unknown here, whatever
        // its status.
        if !self.accepts_binding(&stored) {
            return Err(AuthError::InvalidApiToken);
        }

        if stored.is_revoked() {
            return Err(AuthError::ApiTokenRevoked);
        }

        if stored.is_expired(self.clock.now()) {
            return Err(AuthError::ApiTokenExpired);
        }

        let used_at = self.clock.now();
        if let Err(error) = self
            .store
            .touch_api_token(stored.id, used_at, metadata.ip_address, metadata.user_agent)
            .await
            && let Some(observer) = &self.touch_observer
        {
            observer.api_token_touch_failed(stored.id, &error).await;
        }

        Ok(stored.to_principal())
    }

    fn accepts_binding(&self, stored: &StoredApiToken) -> bool {
        let audience = match (&self.expected_audience, &stored.audience) {
            (Some(expected), Some(audience)) => expected == audience,
            (None, None) => true,
            _ => false,
        };
        let resource =
            self.expected_resource
                .as_ref()
                .is_none_or(|(resource_type, resource_id)| {
                    stored.resource_type.as_ref() == Some(resource_type)
                        && stored.resource_id.as_ref() == Some(resource_id)
                });
        audience && resource
    }

    /// Revokes a single API token.
    pub async fn revoke_token(
        &self,
        token_id: Uuid,
        reason: crate::ApiTokenRevocationReason,
    ) -> AuthResult<()> {
        self.store
            .revoke_api_token(token_id, self.clock.now(), reason)
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

fn validate_binding_value(field: &str, value: &str) -> AuthResult<()> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        return Err(AuthError::InvalidConfiguration(format!(
            "{field} must be non-empty without surrounding whitespace or control characters"
        )));
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

    if let Some(audience) = &request.audience {
        validate_binding_value("api token audience", audience)?;
    }

    match (&request.resource_type, &request.resource_id) {
        (Some(resource_type), Some(resource_id)) => {
            validate_binding_value("api token resource type", resource_type)?;
            validate_binding_value("api token resource id", resource_id)?;
        }
        (None, None) => {}
        _ => {
            return Err(AuthError::InvalidConfiguration(
                "api token resource type and id must be set together".to_string(),
            ));
        }
    }

    if request.ttl <= Duration::ZERO {
        return Err(AuthError::InvalidConfiguration(
            "api token ttl must be greater than zero".to_string(),
        ));
    }

    Ok(())
}
