use async_graphql::{Context, ErrorExtensions, Guard, Result as GraphqlResult};

use crate::{AuthError, auth_user_from_ctx};

#[derive(Clone, Copy, Debug, Default)]
pub struct RequireAuth;

impl RequireAuth {
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

#[derive(Clone, Debug)]
pub struct RequireAnyRole {
    roles: Vec<String>,
}

impl RequireAnyRole {
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

#[derive(Clone, Debug)]
pub struct RequireAllRoles {
    roles: Vec<String>,
}

impl RequireAllRoles {
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

#[derive(Clone, Debug)]
pub struct RequireScope {
    scope: String,
}

impl RequireScope {
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
        let allowed = auth_user_from_ctx(ctx).and_then(|user| {
            if user.has_scope(&self.scope) {
                Ok(())
            } else {
                Err(AuthError::Forbidden.extend())
            }
        });
        async move { allowed }
    }
}

#[derive(Clone, Debug)]
pub struct RequireAnyScope {
    scopes: Vec<String>,
}

impl RequireAnyScope {
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
        let allowed = auth_user_from_ctx(ctx).and_then(|user| {
            if user.has_any_scope(&self.scopes) {
                Ok(())
            } else {
                Err(AuthError::Forbidden.extend())
            }
        });
        async move { allowed }
    }
}

#[derive(Clone, Debug)]
pub struct RequireAllScopes {
    scopes: Vec<String>,
}

impl RequireAllScopes {
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
        let allowed = auth_user_from_ctx(ctx).and_then(|user| {
            if user.has_all_scopes(&self.scopes) {
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
