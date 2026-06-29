use async_graphql::{Context, ErrorExtensions, Result as GraphqlResult};

use crate::{ApiTokenPrincipal, AuthError, AuthPrincipal, AuthUser};

/// Reads the authenticated user from an `async-graphql` context.
///
/// Returns an unauthenticated GraphQL error when no user has been injected.
pub fn auth_user_from_ctx<'a>(ctx: &'a Context<'_>) -> GraphqlResult<&'a AuthUser> {
    ctx.data_opt::<AuthUser>()
        .ok_or(AuthError::Unauthenticated.extend())
}

/// Reads the authenticated user from an `async-graphql` context, if present.
pub fn auth_user_from_ctx_opt<'a>(ctx: &'a Context<'_>) -> Option<&'a AuthUser> {
    ctx.data_opt::<AuthUser>()
}

/// Reads a generic authenticated principal from an `async-graphql` context.
///
/// This accepts either an explicitly injected [`AuthPrincipal`], an existing
/// user-session [`AuthUser`], or an API-token [`ApiTokenPrincipal`].
pub fn principal_from_ctx(ctx: &Context<'_>) -> GraphqlResult<AuthPrincipal> {
    principal_from_ctx_opt(ctx).ok_or(AuthError::Unauthenticated.extend())
}

/// Reads a generic authenticated principal from an `async-graphql` context, if present.
pub fn principal_from_ctx_opt(ctx: &Context<'_>) -> Option<AuthPrincipal> {
    if let Some(principal) = ctx.data_opt::<AuthPrincipal>() {
        return Some(principal.clone());
    }

    if let Some(user) = ctx.data_opt::<AuthUser>() {
        return Some(AuthPrincipal::User(user.clone()));
    }

    ctx.data_opt::<ApiTokenPrincipal>()
        .map(|principal| AuthPrincipal::ApiToken(principal.clone()))
}
