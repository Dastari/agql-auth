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
    /// Issues a password-reset token with the default one-hour TTL.
    pub fn issue_password_reset_token(
        &self,
        user_id: impl Into<String>,
    ) -> AuthResult<PasswordResetToken> {
        self.issue_password_reset_token_with_ttl(user_id, Duration::hours(1))
    }

    /// Issues a password-reset token with a custom TTL.
    pub fn issue_password_reset_token_with_ttl(
        &self,
        user_id: impl Into<String>,
        ttl: Duration,
    ) -> AuthResult<PasswordResetToken> {
        let user_id = user_id.into();
        let issued_at = OffsetDateTime::now_utc();
        let expires_at = issued_at + ttl;
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

    /// Issues a password-reset token and records its token ID in a store.
    pub async fn issue_password_reset_token_with_store<S>(
        &self,
        store: &S,
        user_id: impl Into<String>,
        ttl: Duration,
    ) -> AuthResult<PasswordResetToken>
    where
        S: PasswordResetTokenStore,
    {
        let issued = self.issue_password_reset_token_with_ttl(user_id, ttl)?;
        store
            .insert_password_reset_token(issued.token_id, &issued.user_id, issued.expires_at)
            .await?;
        Ok(issued)
    }

    /// Validates a password-reset token without consuming its stored token ID.
    pub fn authenticate_password_reset_token(
        &self,
        token: &str,
    ) -> AuthResult<VerifiedPasswordResetToken> {
        self.validate_local_jwt_header(token)
            .map_err(|_| AuthError::InvalidPasswordResetToken)?;
        let token_data =
            decode::<PasswordResetTokenClaims>(token, &self.decoding_key, &self.validation)
                .map_err(map_password_reset_decode_error)?;
        let claims = token_data.claims;
        if !matches!(
            claims.typ.as_deref(),
            None | Some(PASSWORD_RESET_TOKEN_TYPE)
        ) || claims.purpose != PASSWORD_RESET_TOKEN_PURPOSE
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

    /// Validates and consumes a password-reset token with abuse protection.
    pub async fn consume_password_reset_token_with_metadata<S>(
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
