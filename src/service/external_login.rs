//! Local account checks for sessions issued from external (OIDC / OAuth 2.0)
//! logins.

use super::AuthService;
use crate::AuthResult;
use crate::errors::AuthError;
use crate::stores::{RefreshTokenStore, UserStore};

impl<U, R> AuthService<U, R>
where
    U: UserStore + 'static,
    R: RefreshTokenStore + 'static,
{
    /// Re-reads a provisioned local user immediately before an external login
    /// links an identity or issues a session.
    ///
    /// A missing user is [`AuthError::ExternalLoginRejected`], a disabled user
    /// is [`AuthError::UserDisabled`], and a store returning another user is
    /// [`AuthError::AuthServiceUnavailable`].
    pub(crate) async fn require_enabled_external_user(&self, user_id: &str) -> AuthResult<()> {
        let user = self
            .user_store
            .find_user_by_id(user_id)
            .await?
            .ok_or_else(|| {
                AuthError::ExternalLoginRejected(
                    "provisioner returned an unknown local user".to_string(),
                )
            })?;
        if user.id != user_id {
            return Err(AuthError::AuthServiceUnavailable);
        }
        if user.disabled {
            return Err(AuthError::UserDisabled);
        }
        Ok(())
    }
}
