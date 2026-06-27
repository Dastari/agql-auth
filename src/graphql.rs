use async_graphql::{Context, ErrorExtensions, Result as GraphqlResult};

use crate::{AuthError, AuthUser};

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
