//! Sensitive-operation boundary: hosts provide authoritative resolver/checker
//! implementations and enforce original resource/operation bindings as well.
use agql_auth::{
    AuthError, AuthPrincipal, AuthResult, CurrentPrincipalResolver, TokenStatusChecker,
    revalidate_sensitive_principal,
};
use time::OffsetDateTime;

async fn authorize_sensitive_write(
    accepted: &AuthPrincipal,
    resolver: &dyn CurrentPrincipalResolver,
    status: &dyn TokenStatusChecker,
) -> AuthResult<AuthPrincipal> {
    let current =
        revalidate_sensitive_principal(accepted, resolver, status, OffsetDateTime::now_utc())
            .await?;
    if !current.has_scope("records.write") {
        return Err(AuthError::Forbidden);
    }
    Ok(current)
}

fn main() {
    // Call this at each operation/event boundary, then inject the returned
    // narrowed principal and consistently derived host authorization context.
    let _ = authorize_sensitive_write;
}
