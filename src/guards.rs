//! `async-graphql` guards for local users and generic principals.
//!
//! Every user and principal guard refuses delegated credentials by default: a
//! session-bound delegation (`grant_kind = session_bound_delegation`) or any
//! access token carrying an `actor` claim. Those tokens act on behalf of
//! someone else and are not ordinary bearers. A resolver that is meant to run
//! under delegation opts in with `allow_delegated()` on its guard. API-token
//! principals are not delegations and are unaffected.
//!
//! Guards built from an empty role or scope list deny every request.

use async_graphql::{Context, ErrorExtensions, Guard, Result as GraphqlResult};

use crate::{AuthError, AuthPrincipal, AuthUser, ChannelIdentity};
use crate::{AuthRuntime, ExactScopeMatch, ScopeMatch};
use std::sync::Arc;

/// `async-graphql` guard requiring an authenticated `AuthUser` in request data.
///
/// Delegated and actor tokens are refused unless [`Self::allow_delegated`] is
/// set.
#[derive(Clone, Copy, Debug, Default)]
pub struct RequireAuth {
    allow_delegated: bool,
}

impl RequireAuth {
    /// Creates an authentication guard.
    pub fn new() -> Self {
        Self::default()
    }

    /// Also admits delegated and actor tokens.
    pub fn allow_delegated(mut self) -> Self {
        self.allow_delegated = true;
        self
    }
}

impl Guard for RequireAuth {
    fn check(
        &self,
        ctx: &Context<'_>,
    ) -> impl std::future::Future<Output = GraphqlResult<()>> + Send {
        let result = user_from_ctx(ctx, self.allow_delegated).map(|_| ());
        async move { result }
    }
}

/// `async-graphql` guard requiring at least one matching role.
///
/// An empty role list denies. Delegated and actor tokens are refused unless
/// [`Self::allow_delegated`] is set.
#[derive(Clone, Debug)]
pub struct RequireAnyRole {
    roles: Vec<String>,
    allow_delegated: bool,
}

impl RequireAnyRole {
    /// Creates a guard from accepted role names.
    pub fn new<I, S>(roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            roles: roles.into_iter().map(Into::into).collect(),
            allow_delegated: false,
        }
    }

    /// Also admits delegated and actor tokens.
    pub fn allow_delegated(mut self) -> Self {
        self.allow_delegated = true;
        self
    }
}

impl Guard for RequireAnyRole {
    fn check(
        &self,
        ctx: &Context<'_>,
    ) -> impl std::future::Future<Output = GraphqlResult<()>> + Send {
        let allowed = user_from_ctx(ctx, self.allow_delegated).and_then(|user| {
            if self
                .roles
                .iter()
                .any(|role| user.roles.iter().any(|r| r == role))
            {
                Ok(())
            } else {
                Err(AuthError::Forbidden.extend())
            }
        });
        async move { allowed }
    }
}

/// `async-graphql` guard requiring every configured role.
///
/// An empty role list denies. Delegated and actor tokens are refused unless
/// [`Self::allow_delegated`] is set.
#[derive(Clone, Debug)]
pub struct RequireAllRoles {
    roles: Vec<String>,
    allow_delegated: bool,
}

impl RequireAllRoles {
    /// Creates a guard from required role names.
    pub fn new<I, S>(roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            roles: roles.into_iter().map(Into::into).collect(),
            allow_delegated: false,
        }
    }

    /// Also admits delegated and actor tokens.
    pub fn allow_delegated(mut self) -> Self {
        self.allow_delegated = true;
        self
    }
}

/// `async-graphql` guard requiring one exact scope.
///
/// Delegated and actor tokens are refused unless [`Self::allow_delegated`] is
/// set.
#[derive(Clone, Debug)]
pub struct RequireScope {
    scope: String,
    allow_delegated: bool,
}

impl RequireScope {
    /// Creates a guard from the required scope.
    pub fn new(scope: impl Into<String>) -> Self {
        Self {
            scope: scope.into(),
            allow_delegated: false,
        }
    }

    /// Also admits delegated and actor tokens.
    pub fn allow_delegated(mut self) -> Self {
        self.allow_delegated = true;
        self
    }
}

impl Guard for RequireScope {
    fn check(
        &self,
        ctx: &Context<'_>,
    ) -> impl std::future::Future<Output = GraphqlResult<()>> + Send {
        let matcher = matcher_from_ctx(ctx);
        let allowed = user_from_ctx(ctx, self.allow_delegated).and_then(|user| {
            if user.has_scope_with(matcher.as_ref(), &self.scope) {
                Ok(())
            } else {
                Err(AuthError::Forbidden.extend())
            }
        });
        async move { allowed }
    }
}

/// `async-graphql` guard requiring at least one exact scope match.
///
/// An empty scope list denies. Delegated and actor tokens are refused unless
/// [`Self::allow_delegated`] is set.
#[derive(Clone, Debug)]
pub struct RequireAnyScope {
    scopes: Vec<String>,
    allow_delegated: bool,
}

impl RequireAnyScope {
    /// Creates a guard from accepted scopes.
    pub fn new<I, S>(scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            scopes: scopes.into_iter().map(Into::into).collect(),
            allow_delegated: false,
        }
    }

    /// Also admits delegated and actor tokens.
    pub fn allow_delegated(mut self) -> Self {
        self.allow_delegated = true;
        self
    }
}

impl Guard for RequireAnyScope {
    fn check(
        &self,
        ctx: &Context<'_>,
    ) -> impl std::future::Future<Output = GraphqlResult<()>> + Send {
        let matcher = matcher_from_ctx(ctx);
        let allowed = user_from_ctx(ctx, self.allow_delegated).and_then(|user| {
            if user.has_any_scope_with(matcher.as_ref(), &self.scopes) {
                Ok(())
            } else {
                Err(AuthError::Forbidden.extend())
            }
        });
        async move { allowed }
    }
}

/// `async-graphql` guard requiring every configured scope.
///
/// An empty scope list denies. Delegated and actor tokens are refused unless
/// [`Self::allow_delegated`] is set.
#[derive(Clone, Debug)]
pub struct RequireAllScopes {
    scopes: Vec<String>,
    allow_delegated: bool,
}

impl RequireAllScopes {
    /// Creates a guard from required scopes.
    pub fn new<I, S>(scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            scopes: scopes.into_iter().map(Into::into).collect(),
            allow_delegated: false,
        }
    }

    /// Also admits delegated and actor tokens.
    pub fn allow_delegated(mut self) -> Self {
        self.allow_delegated = true;
        self
    }
}

impl Guard for RequireAllScopes {
    fn check(
        &self,
        ctx: &Context<'_>,
    ) -> impl std::future::Future<Output = GraphqlResult<()>> + Send {
        let matcher = matcher_from_ctx(ctx);
        let allowed = user_from_ctx(ctx, self.allow_delegated).and_then(|user| {
            if !self.scopes.is_empty() && user.has_all_scopes_with(matcher.as_ref(), &self.scopes) {
                Ok(())
            } else {
                Err(AuthError::Forbidden.extend())
            }
        });
        async move { allowed }
    }
}

impl Guard for RequireAllRoles {
    fn check(
        &self,
        ctx: &Context<'_>,
    ) -> impl std::future::Future<Output = GraphqlResult<()>> + Send {
        let allowed = user_from_ctx(ctx, self.allow_delegated).and_then(|user| {
            if !self.roles.is_empty()
                && self
                    .roles
                    .iter()
                    .all(|role| user.roles.iter().any(|r| r == role))
            {
                Ok(())
            } else {
                Err(AuthError::Forbidden.extend())
            }
        });
        async move { allowed }
    }
}

/// `async-graphql` guard requiring any authenticated principal.
///
/// Delegated and actor user tokens are refused unless
/// [`Self::allow_delegated`] is set.
#[derive(Clone, Copy, Debug, Default)]
pub struct RequirePrincipal {
    allow_delegated: bool,
}

impl RequirePrincipal {
    /// Creates a generic principal guard.
    pub fn new() -> Self {
        Self::default()
    }

    /// Also admits delegated and actor user tokens.
    pub fn allow_delegated(mut self) -> Self {
        self.allow_delegated = true;
        self
    }
}

impl Guard for RequirePrincipal {
    fn check(
        &self,
        ctx: &Context<'_>,
    ) -> impl std::future::Future<Output = GraphqlResult<()>> + Send {
        let result = principal_from_ctx(ctx, self.allow_delegated).map(|_| ());
        async move { result }
    }
}

/// `async-graphql` guard requiring one exact scope on any authenticated principal.
///
/// Delegated and actor user tokens are refused unless
/// [`Self::allow_delegated`] is set.
#[derive(Clone, Debug)]
pub struct RequirePrincipalScope {
    scope: String,
    allow_delegated: bool,
}

impl RequirePrincipalScope {
    /// Creates a generic principal scope guard.
    pub fn new(scope: impl Into<String>) -> Self {
        Self {
            scope: scope.into(),
            allow_delegated: false,
        }
    }

    /// Also admits delegated and actor user tokens.
    pub fn allow_delegated(mut self) -> Self {
        self.allow_delegated = true;
        self
    }
}

impl Guard for RequirePrincipalScope {
    fn check(
        &self,
        ctx: &Context<'_>,
    ) -> impl std::future::Future<Output = GraphqlResult<()>> + Send {
        let matcher = matcher_from_ctx(ctx);
        let allowed = principal_from_ctx(ctx, self.allow_delegated).and_then(|principal| {
            if principal.has_scope_with(matcher.as_ref(), &self.scope) {
                Ok(())
            } else {
                Err(AuthError::Forbidden.extend())
            }
        });
        async move { allowed }
    }
}

/// `async-graphql` guard requiring at least one exact scope on any authenticated principal.
///
/// An empty scope list denies. Delegated and actor user tokens are refused
/// unless [`Self::allow_delegated`] is set.
#[derive(Clone, Debug)]
pub struct RequireAnyPrincipalScope {
    scopes: Vec<String>,
    allow_delegated: bool,
}

impl RequireAnyPrincipalScope {
    /// Creates a generic principal scope guard from accepted scopes.
    pub fn new<I, S>(scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            scopes: scopes.into_iter().map(Into::into).collect(),
            allow_delegated: false,
        }
    }

    /// Also admits delegated and actor user tokens.
    pub fn allow_delegated(mut self) -> Self {
        self.allow_delegated = true;
        self
    }
}

impl Guard for RequireAnyPrincipalScope {
    fn check(
        &self,
        ctx: &Context<'_>,
    ) -> impl std::future::Future<Output = GraphqlResult<()>> + Send {
        let matcher = matcher_from_ctx(ctx);
        let allowed = principal_from_ctx(ctx, self.allow_delegated).and_then(|principal| {
            if principal.has_any_scope_with(matcher.as_ref(), &self.scopes) {
                Ok(())
            } else {
                Err(AuthError::Forbidden.extend())
            }
        });
        async move { allowed }
    }
}

/// `async-graphql` guard requiring every configured scope on any authenticated principal.
///
/// An empty scope list denies. Delegated and actor user tokens are refused
/// unless [`Self::allow_delegated`] is set.
#[derive(Clone, Debug)]
pub struct RequireAllPrincipalScopes {
    scopes: Vec<String>,
    allow_delegated: bool,
}

impl RequireAllPrincipalScopes {
    /// Creates a generic principal scope guard from required scopes.
    pub fn new<I, S>(scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            scopes: scopes.into_iter().map(Into::into).collect(),
            allow_delegated: false,
        }
    }

    /// Also admits delegated and actor user tokens.
    pub fn allow_delegated(mut self) -> Self {
        self.allow_delegated = true;
        self
    }
}

impl Guard for RequireAllPrincipalScopes {
    fn check(
        &self,
        ctx: &Context<'_>,
    ) -> impl std::future::Future<Output = GraphqlResult<()>> + Send {
        let matcher = matcher_from_ctx(ctx);
        let allowed = principal_from_ctx(ctx, self.allow_delegated).and_then(|principal| {
            if !self.scopes.is_empty()
                && principal.has_all_scopes_with(matcher.as_ref(), &self.scopes)
            {
                Ok(())
            } else {
                Err(AuthError::Forbidden.extend())
            }
        });
        async move { allowed }
    }
}

/// `async-graphql` guard requiring a host-verified channel scheme.
#[derive(Clone, Debug)]
pub struct RequireChannelScheme {
    scheme: String,
}

impl RequireChannelScheme {
    /// Creates a channel-scheme guard.
    pub fn new(scheme: impl Into<String>) -> Self {
        Self {
            scheme: scheme.into(),
        }
    }
}

impl Guard for RequireChannelScheme {
    fn check(
        &self,
        ctx: &Context<'_>,
    ) -> impl std::future::Future<Output = GraphqlResult<()>> + Send {
        let allowed = match ctx.data_opt::<ChannelIdentity>() {
            Some(identity) if identity.scheme == self.scheme => Ok(()),
            _ => Err(AuthError::Forbidden.extend()),
        };
        async move { allowed }
    }
}

fn user_from_ctx<'a>(ctx: &'a Context<'_>, allow_delegated: bool) -> GraphqlResult<&'a AuthUser> {
    let user = crate::auth_user_from_ctx(ctx)?;
    if !allow_delegated && user.token_claims.is_delegated() {
        return Err(AuthError::Forbidden.extend());
    }
    Ok(user)
}

fn principal_from_ctx(ctx: &Context<'_>, allow_delegated: bool) -> GraphqlResult<AuthPrincipal> {
    let principal = crate::principal_from_ctx(ctx)?;
    if !allow_delegated
        && principal
            .access_token_metadata()
            .is_some_and(|claims| claims.is_delegated())
    {
        return Err(AuthError::Forbidden.extend());
    }
    Ok(principal)
}

fn matcher_from_ctx(ctx: &Context<'_>) -> Arc<dyn ScopeMatch> {
    ctx.data_opt::<AuthRuntime>()
        .map(|runtime| runtime.scope_matcher.clone())
        .unwrap_or_else(|| Arc::new(ExactScopeMatch))
}
