use time::OffsetDateTime;
use uuid::Uuid;

use super::AuthService;
use crate::config::ClientMetadata;
use crate::models::AuthRateLimitFlow;
use crate::models::{
    IssuedLoginChallenge, LoginChallengeOptions, StoredLoginChallenge, VerifiedLoginChallenge,
};
use crate::stores::{LoginChallengeStore, RefreshTokenStore, UserStore};
use crate::util::{generate_numeric_code, validate_login_challenge_options};
use crate::{AuthError, AuthResult};

impl<U, R> AuthService<U, R>
where
    U: UserStore + 'static,
    R: RefreshTokenStore + 'static,
{
    /// Creates a one-time login challenge and returns the raw code for delivery.
    pub async fn create_login_challenge<S>(
        &self,
        store: &S,
        principal: impl Into<String>,
        options: LoginChallengeOptions,
    ) -> AuthResult<IssuedLoginChallenge>
    where
        S: LoginChallengeStore,
    {
        validate_login_challenge_options(&options)?;
        let code = generate_numeric_code(options.code_length);
        let code_hash = self.hash_password(&code)?;
        let now = OffsetDateTime::now_utc();
        let challenge = StoredLoginChallenge {
            id: Uuid::new_v4(),
            principal: principal.into(),
            code_hash,
            created_at: now,
            expires_at: now + options.ttl,
            failed_attempts: 0,
            max_attempts: options.max_attempts,
            consumed_at: None,
            channel: options.channel.clone(),
        };
        store.insert_login_challenge(challenge.clone()).await?;

        Ok(IssuedLoginChallenge {
            challenge_id: challenge.id,
            principal: challenge.principal,
            code,
            expires_at: challenge.expires_at,
            max_attempts: challenge.max_attempts,
            channel: challenge.channel,
        })
    }

    /// Verifies and consumes a one-time login challenge.
    pub async fn verify_login_challenge<S>(
        &self,
        store: &S,
        challenge_id: Uuid,
        code: &str,
    ) -> AuthResult<VerifiedLoginChallenge>
    where
        S: LoginChallengeStore,
    {
        self.verify_login_challenge_with_metadata(
            store,
            challenge_id,
            code,
            ClientMetadata::default(),
        )
        .await
    }

    /// Verifies and consumes a one-time login challenge with abuse protection.
    pub async fn verify_login_challenge_with_metadata<S>(
        &self,
        store: &S,
        challenge_id: Uuid,
        code: &str,
        metadata: ClientMetadata,
    ) -> AuthResult<VerifiedLoginChallenge>
    where
        S: LoginChallengeStore,
    {
        let now = OffsetDateTime::now_utc();
        let client_keys =
            self.rate_limit_keys(AuthRateLimitFlow::LoginCodeVerification, None, &metadata);
        self.reject_if_rate_limited(&self.config.rate_limits.credential, &client_keys)
            .await?;

        let challenge = store
            .find_login_challenge(challenge_id)
            .await?
            .ok_or(AuthError::InvalidLoginChallenge)?;
        let rate_limit_keys = self.rate_limit_keys(
            AuthRateLimitFlow::LoginCodeVerification,
            Some(&challenge.principal),
            &metadata,
        );
        let rate_limit_permit = self
            .reject_if_rate_limited(&self.config.rate_limits.credential, &rate_limit_keys)
            .await?;

        if challenge.is_consumed() {
            return Err(AuthError::LoginChallengeReplayed);
        }

        if challenge.is_expired(now) {
            return Err(AuthError::LoginChallengeExpired);
        }

        if challenge.attempts_exhausted() {
            return Err(AuthError::LoginChallengeAttemptsExhausted);
        }

        if self.verify_password(code, &challenge.code_hash).is_err() {
            self.record_rate_limit_attempt(&self.config.rate_limits.credential, &rate_limit_keys)
                .await?;
            let attempts = store
                .increment_login_challenge_attempts(challenge_id, now)
                .await?;
            if attempts >= challenge.max_attempts {
                return Err(AuthError::LoginChallengeAttemptsExhausted);
            }
            return Err(AuthError::InvalidLoginCode);
        }

        let consumed = store.consume_login_challenge(challenge_id, now).await?;
        if !consumed {
            self.record_rate_limit_attempt(&self.config.rate_limits.credential, &rate_limit_keys)
                .await?;
            return Err(AuthError::LoginChallengeReplayed);
        }
        self.clear_rate_limit_attempts(&self.config.rate_limits.credential, &rate_limit_permit)
            .await?;

        Ok(VerifiedLoginChallenge {
            challenge_id,
            principal: challenge.principal,
            verified_at: now,
            channel: challenge.channel,
        })
    }
}
