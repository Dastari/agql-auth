use async_graphql::{Context, ErrorExtensions, Guard, Result as GraphqlResult};

use crate::{AuthError, auth_user_from_ctx, principal_from_ctx};
use crate::{AuthRuntime, ExactScopeMatch, ScopeMatch};
use std::sync::Arc;

/// `async-graphql` guard requiring an authenticated `AuthUser` in request data.
#[derive(Clone, Copy, Debug, Default)]
pub struct RequireAuth;

impl RequireAuth {
    /// Creates an authentication guard.
    pub fn new() -> Self {
        Self
    }
}

impl Guard for RequireAuth {
    fn check(
        &self,
        ctx: &Context<'_>,
    ) -> impl std::future::Future<Output = GraphqlResult<()>> + Send {
        let result = auth_user_from_ctx(ctx).map(|_| ());
        async move { result }
    }
}

/// `async-graphql` guard requiring at least one matching role.
#[derive(Clone, Debug)]
pub struct RequireAnyRole {
    roles: Vec<String>,
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
        }
    }
}

impl Guard for RequireAnyRole {
    fn check(
        &self,
        ctx: &Context<'_>,
    ) -> impl std::future::Future<Output = GraphqlResult<()>> + Send {
        let allowed = auth_user_from_ctx(ctx).and_then(|user| {
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
#[derive(Clone, Debug)]
pub struct RequireAllRoles {
    roles: Vec<String>,
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
        }
    }
}

/// `async-graphql` guard requiring one exact scope.
#[derive(Clone, Debug)]
pub struct RequireScope {
    scope: String,
}

impl RequireScope {
    /// Creates a guard from the required scope.
    pub fn new(scope: impl Into<String>) -> Self {
        Self {
            scope: scope.into(),
        }
    }
}

impl Guard for RequireScope {
    fn check(
        &self,
        ctx: &Context<'_>,
    ) -> impl std::future::Future<Output = GraphqlResult<()>> + Send {
        let matcher = matcher_from_ctx(ctx);
        let allowed = auth_user_from_ctx(ctx).and_then(|user| {
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
#[derive(Clone, Debug)]
pub struct RequireAnyScope {
    scopes: Vec<String>,
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
        }
    }
}

impl Guard for RequireAnyScope {
    fn check(
        &self,
        ctx: &Context<'_>,
    ) -> impl std::future::Future<Output = GraphqlResult<()>> + Send {
        let matcher = matcher_from_ctx(ctx);
        let allowed = auth_user_from_ctx(ctx).and_then(|user| {
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
#[derive(Clone, Debug)]
pub struct RequireAllScopes {
    scopes: Vec<String>,
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
        }
    }
}

impl Guard for RequireAllScopes {
    fn check(
        &self,
        ctx: &Context<'_>,
    ) -> impl std::future::Future<Output = GraphqlResult<()>> + Send {
        let matcher = matcher_from_ctx(ctx);
        let allowed = auth_user_from_ctx(ctx).and_then(|user| {
            if user.has_all_scopes_with(matcher.as_ref(), &self.scopes) {
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
        let allowed = auth_user_from_ctx(ctx).and_then(|user| {
            if self
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
#[derive(Clone, Copy, Debug, Default)]
pub struct RequirePrincipal;

impl RequirePrincipal {
    /// Creates a generic principal guard.
    pub fn new() -> Self {
        Self
    }
}

impl Guard for RequirePrincipal {
    fn check(
        &self,
        ctx: &Context<'_>,
    ) -> impl std::future::Future<Output = GraphqlResult<()>> + Send {
        let result = principal_from_ctx(ctx).map(|_| ());
        async move { result }
    }
}

/// `async-graphql` guard requiring one exact scope on any authenticated principal.
#[derive(Clone, Debug)]
pub struct RequirePrincipalScope {
    scope: String,
}

impl RequirePrincipalScope {
    /// Creates a generic principal scope guard.
    pub fn new(scope: impl Into<String>) -> Self {
        Self {
            scope: scope.into(),
        }
    }
}

impl Guard for RequirePrincipalScope {
    fn check(
        &self,
        ctx: &Context<'_>,
    ) -> impl std::future::Future<Output = GraphqlResult<()>> + Send {
        let matcher = matcher_from_ctx(ctx);
        let allowed = principal_from_ctx(ctx).and_then(|principal| {
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
#[derive(Clone, Debug)]
pub struct RequireAnyPrincipalScope {
    scopes: Vec<String>,
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
        }
    }
}

impl Guard for RequireAnyPrincipalScope {
    fn check(
        &self,
        ctx: &Context<'_>,
    ) -> impl std::future::Future<Output = GraphqlResult<()>> + Send {
        let matcher = matcher_from_ctx(ctx);
        let allowed = principal_from_ctx(ctx).and_then(|principal| {
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
#[derive(Clone, Debug)]
pub struct RequireAllPrincipalScopes {
    scopes: Vec<String>,
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
        }
    }
}

impl Guard for RequireAllPrincipalScopes {
    fn check(
        &self,
        ctx: &Context<'_>,
    ) -> impl std::future::Future<Output = GraphqlResult<()>> + Send {
        let matcher = matcher_from_ctx(ctx);
        let allowed = principal_from_ctx(ctx).and_then(|principal| {
            if principal.has_all_scopes_with(matcher.as_ref(), &self.scopes) {
                Ok(())
            } else {
                Err(AuthError::Forbidden.extend())
            }
        });
        async move { allowed }
    }
}

fn matcher_from_ctx(ctx: &Context<'_>) -> Arc<dyn ScopeMatch> {
    ctx.data_opt::<AuthRuntime>()
        .map(|runtime| runtime.scope_matcher.clone())
        .unwrap_or_else(|| Arc::new(ExactScopeMatch))
}
