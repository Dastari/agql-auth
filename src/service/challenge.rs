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
        let code_hash = self.hash_password_async(&code).await?;
        let now = self.login_challenge_clock.now();
        let challenge = StoredLoginChallenge {
            id: Uuid::new_v4(),
            principal: principal.into(),
            code_hash,
            created_at: now,
            expires_at: crate::util::checked_expiry(now, options.ttl, "login challenge ttl")?,
            attempts: 0,
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

        let now = self.login_challenge_clock.now();
        if challenge.is_consumed() {
            return Err(AuthError::LoginChallengeReplayed);
        }

        if challenge.is_expired(now) {
            return Err(AuthError::LoginChallengeExpired);
        }

        if challenge.attempts_exhausted() {
            return Err(AuthError::LoginChallengeAttemptsExhausted);
        }

        let reserved = store
            .reserve_login_challenge_attempt(challenge_id, self.login_challenge_clock.now())
            .await?;
        if !same_challenge_definition(&challenge, &reserved)
            || reserved.is_consumed()
            || reserved.attempts <= challenge.attempts
            || reserved.attempts > reserved.max_attempts
        {
            return Err(AuthError::AuthServiceUnavailable);
        }
        // The store may return long after it atomically admitted this attempt.
        // Do not spend password work on authority that has already expired.
        if reserved.is_expired(self.login_challenge_clock.now()) {
            return Err(AuthError::LoginChallengeExpired);
        }
        let verified = self
            .verify_password_async_before(
                code,
                &reserved.code_hash,
                Some((self.login_challenge_clock.clone(), reserved.expires_at)),
            )
            .await;
        // Password work and storage awaits can outlive the admission timestamp.
        let verified_at = self.login_challenge_clock.now();
        if reserved.is_expired(verified_at) {
            return Err(AuthError::LoginChallengeExpired);
        }
        if let Err(error) = verified {
            if matches!(
                error,
                AuthError::AuthServiceUnavailable | AuthError::LoginChallengeExpired
            ) {
                return Err(error);
            }
            self.record_rate_limit_attempt(&self.config.rate_limits.credential, &rate_limit_keys)
                .await?;
            if reserved.attempts >= reserved.max_attempts {
                return Err(AuthError::LoginChallengeAttemptsExhausted);
            }
            return Err(AuthError::InvalidLoginCode);
        }

        let consumed = store
            .consume_login_challenge(challenge_id, verified_at)
            .await?;
        if reserved.is_expired(self.login_challenge_clock.now()) {
            return Err(AuthError::LoginChallengeExpired);
        }
        if !consumed {
            self.record_rate_limit_attempt(&self.config.rate_limits.credential, &rate_limit_keys)
                .await?;
            return Err(AuthError::LoginChallengeReplayed);
        }
        self.clear_rate_limit_attempts(&self.config.rate_limits.credential, &rate_limit_permit)
            .await?;

        let verified_at = self.login_challenge_clock.now();
        if reserved.is_expired(verified_at) {
            return Err(AuthError::LoginChallengeExpired);
        }
        Ok(VerifiedLoginChallenge {
            challenge_id,
            principal: reserved.principal,
            verified_at,
            channel: reserved.channel,
        })
    }
}

fn same_challenge_definition(a: &StoredLoginChallenge, b: &StoredLoginChallenge) -> bool {
    a.id == b.id
        && a.principal == b.principal
        && a.code_hash == b.code_hash
        && a.created_at == b.created_at
        && a.expires_at == b.expires_at
        && a.max_attempts == b.max_attempts
        && a.channel == b.channel
}
