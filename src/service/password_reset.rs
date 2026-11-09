use jsonwebtoken::decode;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::{
    AuthService, PASSWORD_RESET_TOKEN_PURPOSE, PASSWORD_RESET_TOKEN_TYPE, PasswordResetTokenClaims,
};
use crate::config::ClientMetadata;
use crate::models::AuthRateLimitFlow;
use crate::models::{PasswordResetToken, VerifiedPasswordResetToken};
use crate::stores::{PasswordResetTokenStore, RefreshTokenStore, UserStore};
use crate::util::map_password_reset_decode_error;
use crate::{AuthError, AuthResult};

impl<U, R> AuthService<U, R>
where
    U: UserStore + 'static,
    R: RefreshTokenStore + 'static,
{
    /// Issues a password-reset token with the default one-hour TTL and records
    /// it in `store`.
    ///
    /// Shares the contract of [`Self::issue_password_reset_token_with_store`].
    pub async fn issue_password_reset_token<S>(
        &self,
        store: &S,
        user_id: impl Into<String>,
    ) -> AuthResult<PasswordResetToken>
    where
        S: PasswordResetTokenStore,
    {
        self.issue_password_reset_token_with_store(store, user_id, Duration::hours(1))
            .await
    }

    /// Signs a reset token. Callers must record it before returning it: a
    /// token without a store record could only pass validation, which is
    /// repeatable until expiry, so the crate never hands one out.
    fn sign_password_reset_token(
        &self,
        user_id: impl Into<String>,
        ttl: Duration,
    ) -> AuthResult<PasswordResetToken> {
        let user_id = user_id.into();
        let issued_at = OffsetDateTime::now_utc();
        let expires_at = crate::util::checked_jwt_expiry(issued_at, ttl, "password-reset ttl")?;
        let token_id = Uuid::new_v4();
        let claims = PasswordResetTokenClaims {
            sub: user_id.clone(),
            jti: token_id.to_string(),
            typ: Some(PASSWORD_RESET_TOKEN_TYPE.to_string()),
            purpose: PASSWORD_RESET_TOKEN_PURPOSE.to_string(),
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            exp: expires_at.unix_timestamp(),
            iat: issued_at.unix_timestamp(),
        };

        let token = self.encode_local_jwt(&claims)?;

        Ok(PasswordResetToken {
            user_id,
            token_id,
            token,
            expires_at,
        })
    }

    /// Issues a password-reset token, records its token ID in a store, and
    /// invalidates the user's other outstanding reset tokens.
    ///
    /// Only the newest token for a user can be consumed. If invalidation fails
    /// the error is returned and the new token must not be delivered. This does
    /// not send delivery, check user state or apply request admission; call
    /// [`Self::should_process_password_reset_request`] first.
    pub async fn issue_password_reset_token_with_store<S>(
        &self,
        store: &S,
        user_id: impl Into<String>,
        ttl: Duration,
    ) -> AuthResult<PasswordResetToken>
    where
        S: PasswordResetTokenStore,
    {
        let issued = self.sign_password_reset_token(user_id, ttl)?;
        store
            .insert_password_reset_token(issued.token_id, &issued.user_id, issued.expires_at)
            .await?;
        store
            .invalidate_password_reset_tokens_for_user(
                &issued.user_id,
                Some(issued.token_id),
                OffsetDateTime::now_utc(),
            )
            .await?;
        Ok(issued)
    }

    /// Validates a signed reset token without consulting or consuming its store.
    ///
    /// Checks cryptographic claims, the reset `typ` and purpose, and expiry, not
    /// one-time use, store
    /// revocation, attempt limits, current user state or a password change.
    /// Repeated validation can succeed for the same token. Never use validation
    /// alone to authorize a reset; use
    /// [`Self::consume_password_reset_token_with_metadata`], then perform the
    /// host's password update and required session revocation with appropriate
    /// transaction/fencing and recovery behavior.
    pub fn authenticate_password_reset_token(
        &self,
        token: &str,
    ) -> AuthResult<VerifiedPasswordResetToken> {
        let decoding_key = self
            .local_jwt_decoding_key(token)
            .map_err(|_| AuthError::InvalidPasswordResetToken)?;
        let token_data = decode::<PasswordResetTokenClaims>(token, decoding_key, &self.validation)
            .map_err(map_password_reset_decode_error)?;
        let claims = token_data.claims;
        if claims.typ.as_deref() != Some(PASSWORD_RESET_TOKEN_TYPE)
            || claims.purpose != PASSWORD_RESET_TOKEN_PURPOSE
        {
            return Err(AuthError::InvalidPasswordResetToken);
        }

        let token_id =
            Uuid::parse_str(&claims.jti).map_err(|_| AuthError::InvalidPasswordResetToken)?;
        let issued_at = OffsetDateTime::from_unix_timestamp(claims.iat)
            .map_err(|_| AuthError::InvalidPasswordResetToken)?;
        let expires_at = OffsetDateTime::from_unix_timestamp(claims.exp)
            .map_err(|_| AuthError::InvalidPasswordResetToken)?;
        if expires_at <= OffsetDateTime::now_utc() {
            return Err(AuthError::PasswordResetTokenExpired);
        }

        Ok(VerifiedPasswordResetToken {
            user_id: claims.sub,
            token_id,
            issued_at,
            expires_at,
        })
    }

    /// Validates and consumes a password-reset token exactly once.
    pub async fn consume_password_reset_token<S>(
        &self,
        store: &S,
        token: &str,
    ) -> AuthResult<VerifiedPasswordResetToken>
    where
        S: PasswordResetTokenStore,
    {
        self.consume_password_reset_token_with_metadata(store, token, ClientMetadata::default())
            .await
    }

    /// Validates and atomically consumes a reset ID with configured abuse
    /// protection, then invalidates the user's other outstanding reset tokens.
    ///
    /// Requires an atomic [`PasswordResetTokenStore`] implementation. If sibling
    /// invalidation fails the token stays consumed and the error is returned;
    /// the user needs a fresh reset. This does not update a password or revoke
    /// sessions/API tokens. The host binds the verified user, persists the new
    /// password and implements revocation and recovery/fencing if any step
    /// fails after consumption.
    pub async fn consume_password_reset_token_with_metadata<S>(
        &self,
        store: &S,
        token: &str,
        metadata: ClientMetadata,
    ) -> AuthResult<VerifiedPasswordResetToken>
    where
        S: PasswordResetTokenStore,
    {
        let verified = self
            .consume_one_password_reset_token(store, token, metadata)
            .await?;
        store
            .invalidate_password_reset_tokens_for_user(
                &verified.user_id,
                None,
                OffsetDateTime::now_utc(),
            )
            .await?;
        // INTEGRATION: the `sessions` stream adds an `AuthService` method that
        // revokes all of a user's refresh families. Call it here for
        // `verified.user_id` so completing a reset ends every refresh session,
        // and update this method's docs and docs/secure-primitive-flows.md.
        Ok(verified)
    }

    async fn consume_one_password_reset_token<S>(
        &self,
        store: &S,
        token: &str,
        metadata: ClientMetadata,
    ) -> AuthResult<VerifiedPasswordResetToken>
    where
        S: PasswordResetTokenStore,
    {
        let client_keys = self.rate_limit_keys(
            AuthRateLimitFlow::PasswordResetTokenConsumption,
            None,
            &metadata,
        );
        self.reject_if_rate_limited(&self.config.rate_limits.credential, &client_keys)
            .await?;

        let verified = match self.authenticate_password_reset_token(token) {
            Ok(verified) => verified,
            Err(err) => {
                self.record_rate_limit_attempt(&self.config.rate_limits.credential, &client_keys)
                    .await?;
                return Err(err);
            }
        };
        let rate_limit_keys = self.rate_limit_keys(
            AuthRateLimitFlow::PasswordResetTokenConsumption,
            Some(&verified.user_id),
            &metadata,
        );
        let rate_limit_permit = self
            .reject_if_rate_limited(&self.config.rate_limits.credential, &rate_limit_keys)
            .await?;

        let consumed = store
            .consume_password_reset_token(verified.token_id, OffsetDateTime::now_utc())
            .await?;
        if !consumed {
            self.record_rate_limit_attempt(&self.config.rate_limits.credential, &rate_limit_keys)
                .await?;
            return Err(AuthError::PasswordResetTokenReplayed);
        }
        self.clear_rate_limit_attempts(&self.config.rate_limits.credential, &rate_limit_permit)
            .await?;
        Ok(verified)
    }
}
