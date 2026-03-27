use jsonwebtoken::{Algorithm, Header, decode, encode};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::{AuthService, PasswordResetTokenClaims};
use crate::models::{PasswordResetToken, VerifiedPasswordResetToken};
use crate::stores::{PasswordResetTokenStore, RefreshTokenStore, UserStore};
use crate::util::map_password_reset_decode_error;
use crate::{AuthError, AuthResult};

impl<U, R> AuthService<U, R>
where
    U: UserStore + 'static,
    R: RefreshTokenStore + 'static,
{
    pub fn issue_password_reset_token(
        &self,
        user_id: impl Into<String>,
    ) -> AuthResult<PasswordResetToken> {
        self.issue_password_reset_token_with_ttl(user_id, Duration::hours(1))
    }

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
            purpose: "password_reset".to_string(),
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            exp: expires_at.unix_timestamp(),
            iat: issued_at.unix_timestamp(),
        };

        let token = encode(&Header::new(Algorithm::HS256), &claims, &self.encoding_key)
            .map_err(|err| AuthError::TokenCreation(err.to_string()))?;

        Ok(PasswordResetToken {
            user_id,
            token_id,
            token,
            expires_at,
        })
    }

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

    pub fn authenticate_password_reset_token(
        &self,
        token: &str,
    ) -> AuthResult<VerifiedPasswordResetToken> {
        let token_data =
            decode::<PasswordResetTokenClaims>(token, &self.decoding_key, &self.validation)
                .map_err(map_password_reset_decode_error)?;
        let claims = token_data.claims;
        if claims.purpose != "password_reset" {
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

    pub async fn consume_password_reset_token<S>(
        &self,
        store: &S,
        token: &str,
    ) -> AuthResult<VerifiedPasswordResetToken>
    where
        S: PasswordResetTokenStore,
    {
        let verified = self.authenticate_password_reset_token(token)?;
        let consumed = store
            .consume_password_reset_token(verified.token_id, OffsetDateTime::now_utc())
            .await?;
        if !consumed {
            return Err(AuthError::PasswordResetTokenReplayed);
        }
        Ok(verified)
    }
}
