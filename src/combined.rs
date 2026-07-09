use std::sync::Arc;

use async_graphql::Request;

use crate::api_tokens::ApiTokenService;
use crate::config::ClientMetadata;
use crate::scope_match::{AuthRuntime, ExactScopeMatch, ScopeMatch};
use crate::stores::{ApiTokenStore, RefreshTokenStore, UserStore};
use crate::util::strip_bearer_prefix;
use crate::{AccessTokenValidator, AuthError, AuthPrincipal, AuthResult, AuthService, AuthUser};

/// Access-token authentication surface shared by issuers and resource servers.
pub trait AccessTokenAuth: Send + Sync {
    /// Authenticates a bearer value with or without the `Bearer ` prefix.
    fn authenticate_bearer(&self, bearer_or_token: &str) -> AuthResult<AuthUser>;

    /// Returns the matcher that should be injected for request-time guards.
    fn scope_matcher(&self) -> Arc<dyn ScopeMatch> {
        Arc::new(ExactScopeMatch)
    }
}

impl AccessTokenAuth for AccessTokenValidator {
    fn authenticate_bearer(&self, bearer_or_token: &str) -> AuthResult<AuthUser> {
        AccessTokenValidator::authenticate_bearer(self, bearer_or_token)
    }

    fn scope_matcher(&self) -> Arc<dyn ScopeMatch> {
        AccessTokenValidator::scope_matcher(self)
    }
}

impl<U, R> AccessTokenAuth for AuthService<U, R>
where
    U: UserStore + 'static,
    R: RefreshTokenStore + 'static,
{
    fn authenticate_bearer(&self, bearer_or_token: &str) -> AuthResult<AuthUser> {
        AuthService::authenticate_bearer(self, bearer_or_token)
    }

    fn scope_matcher(&self) -> Arc<dyn ScopeMatch> {
        AuthService::scope_matcher(self)
    }
}

/// Combined GraphQL injector for endpoints that accept user JWTs or API tokens.
pub struct CombinedAuth<'a, V, S>
where
    V: AccessTokenAuth + ?Sized,
    S: ApiTokenStore,
{
    /// User access-token authenticator.
    pub access_tokens: &'a V,
    /// Opaque API-token service.
    pub api_tokens: &'a ApiTokenService<S>,
}

impl<'a, V, S> CombinedAuth<'a, V, S>
where
    V: AccessTokenAuth + ?Sized,
    S: ApiTokenStore + 'static,
{
    /// Creates a combined injector.
    pub fn new(access_tokens: &'a V, api_tokens: &'a ApiTokenService<S>) -> Self {
        Self {
            access_tokens,
            api_tokens,
        }
    }

    /// Injects a user JWT or API-token principal into an `async-graphql` request.
    ///
    /// Missing auth leaves the request unchanged. Expired user JWTs are never
    /// treated as API-token candidates.
    pub async fn inject_http_auth(
        &self,
        request: Request,
        authorization: Option<&str>,
        metadata: ClientMetadata,
    ) -> AuthResult<Request> {
        let Some(raw) = authorization else {
            return Ok(request);
        };
        let token = strip_bearer_prefix(raw)?;
        let runtime = AuthRuntime::new(self.access_tokens.scope_matcher());

        if token.contains('.') {
            match self.access_tokens.authenticate_bearer(token) {
                Ok(user) => return Ok(inject_user(request, runtime, user)),
                Err(AuthError::AccessTokenExpired) => return Err(AuthError::AccessTokenExpired),
                Err(AuthError::InvalidAccessToken)
                    if token.starts_with(self.api_tokens.token_prefix()) => {}
                Err(err) => return Err(err),
            }
        }

        let principal = self.api_tokens.authenticate_token(token, metadata).await?;
        Ok(request
            .data(runtime)
            .data(principal.clone())
            .data(AuthPrincipal::ApiToken(principal)))
    }
}

fn inject_user(request: Request, runtime: AuthRuntime, user: AuthUser) -> Request {
    request
        .data(runtime)
        .data(AuthPrincipal::User(user.clone()))
        .data(user)
}
