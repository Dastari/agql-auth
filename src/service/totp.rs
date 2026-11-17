use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use rand::RngCore;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;

use super::AuthService;
use crate::config::ClientMetadata;
use crate::models::AuthRateLimitFlow;
use crate::models::{TotpOptions, TotpProvisioning, TotpSecret};
use crate::stores::{RefreshTokenStore, TotpReplayStore, UserStore};
use crate::util::{
    MAX_GENERATED_TOTP_SECRET_BYTES, MIN_GENERATED_TOTP_SECRET_BYTES, decode_base32_secret,
    generate_totp_code_for_step, totp_step, validate_totp_options,
};
use crate::{AuthError, AuthResult};

impl<U, R> AuthService<U, R>
where
    U: UserStore + 'static,
    R: RefreshTokenStore + 'static,
{
    /// Generates a random TOTP secret of `num_bytes` bytes.
    ///
    /// `num_bytes` must be between 20 (the 160-bit length RFC 4226 recommends)
    /// and 64 (the HMAC-SHA1 block size; longer keys are hashed down).
    pub fn generate_totp_secret(&self, num_bytes: usize) -> AuthResult<TotpSecret> {
        if !(MIN_GENERATED_TOTP_SECRET_BYTES..=MAX_GENERATED_TOTP_SECRET_BYTES).contains(&num_bytes)
        {
            return Err(AuthError::InvalidConfiguration(format!(
                "totp secret must be between {MIN_GENERATED_TOTP_SECRET_BYTES} and \
                 {MAX_GENERATED_TOTP_SECRET_BYTES} bytes"
            )));
        }

        let mut raw_secret = vec![0u8; num_bytes];
        rand::rngs::OsRng.fill_bytes(&mut raw_secret);
        let base32_secret = data_encoding::BASE32_NOPAD.encode(&raw_secret);
        Ok(TotpSecret {
            raw_secret,
            base32_secret,
        })
    }

    /// Builds an `otpauth://` provisioning URI for an authenticator app.
    ///
    /// Rejects options and secrets that verification would refuse.
    pub fn build_totp_provisioning(
        &self,
        secret: &TotpSecret,
        issuer: impl Into<String>,
        account_name: impl Into<String>,
        options: TotpOptions,
    ) -> AuthResult<TotpProvisioning> {
        validate_totp_options(&options)?;
        decode_base32_secret(&secret.base32_secret)?;
        let issuer = issuer.into();
        let account_name = account_name.into();
        let label = format!("{}:{}", issuer, account_name);
        let uri = format!(
            "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
            utf8_percent_encode(&label, NON_ALPHANUMERIC),
            utf8_percent_encode(&secret.base32_secret, NON_ALPHANUMERIC),
            utf8_percent_encode(&issuer, NON_ALPHANUMERIC),
            options.digits,
            options.period_seconds
        );

        Ok(TotpProvisioning {
            issuer,
            account_name,
            secret: secret.base32_secret.clone(),
            uri,
        })
    }

    /// Verifies a TOTP code for the supplied secret and time.
    ///
    /// This method is stateless and can accept the same valid code more than
    /// once within the configured skew window. It has no principal/factor
    /// ownership check, attempt limiter, replay consumption, enrollment update
    /// or session/MFA state transition. `now` and the secret must come from the
    /// trusted host. Production MFA flows should prefer
    /// [`Self::verify_totp_code_with_replay_store_and_metadata`], then bind the
    /// result to the exact authenticated session before recording step-up.
    pub fn verify_totp_code(
        &self,
        secret_base32: &str,
        code: &str,
        options: TotpOptions,
        now: OffsetDateTime,
    ) -> AuthResult<()> {
        self.verify_totp_code_step(secret_base32, code, options, now)
            .map(|_| ())
    }

    /// Verifies a TOTP code with configured principal/client abuse protection.
    ///
    /// This does not consume a replay step: the same valid code can succeed
    /// again within its time window. It does not check factor ownership or
    /// establish MFA/session state. For one-time acceptance use
    /// [`Self::verify_totp_code_with_replay_store_and_metadata`].
    ///
    /// The attempt is counted against the principal and client buckets before
    /// the code is checked, so concurrent guesses cannot exceed the lockout
    /// budget and a store that cannot count fails with
    /// `AuthServiceUnavailable` for every code. Success clears the principal
    /// bucket and refunds only this attempt from the client bucket.
    pub async fn verify_totp_code_for_principal(
        &self,
        principal_id: &str,
        secret_base32: &str,
        code: &str,
        options: TotpOptions,
        now: OffsetDateTime,
        metadata: ClientMetadata,
    ) -> AuthResult<()> {
        let policy = &self.config.rate_limits.credential;
        let secret = prepare_totp_secret(secret_base32, &options)?;
        let rate_limit_keys = self.rate_limit_keys(
            AuthRateLimitFlow::TotpVerification,
            Some(principal_id),
            &metadata,
        );
        let reservation = self
            .reserve_credential_attempt(policy, &rate_limit_keys)
            .await?;

        match match_totp_code(&secret, code, &options, now) {
            Ok(_) => self.settle_rate_limit_success(policy, reservation).await,
            Err(AuthError::InvalidTotpCode) => {
                self.settle_rate_limit_failure(policy, reservation).await?;
                Err(AuthError::InvalidTotpCode)
            }
            Err(err) => {
                self.refund_rate_limit_reservation(policy, reservation)
                    .await?;
                Err(err)
            }
        }
    }

    /// Verifies a TOTP code and consumes the accepted time step once.
    ///
    /// `store.consume_totp_step` must atomically return `true` only for the
    /// first use of `(principal_id, factor_id, step)`. Configured principal
    /// abuse protection applies; client protection requires the metadata variant.
    /// The host still binds the stored factor and accepted result to the exact
    /// authenticated principal/session and records any resulting assurance.
    #[allow(clippy::too_many_arguments)]
    pub async fn verify_totp_code_with_replay_store<S>(
        &self,
        store: &S,
        principal_id: &str,
        factor_id: Option<&str>,
        secret_base32: &str,
        code: &str,
        options: TotpOptions,
        now: OffsetDateTime,
    ) -> AuthResult<()>
    where
        S: TotpReplayStore,
    {
        self.verify_totp_code_with_replay_store_and_metadata(
            store,
            principal_id,
            factor_id,
            secret_base32,
            code,
            options,
            now,
            ClientMetadata::default(),
        )
        .await
    }

    /// Verifies a TOTP code, consumes the accepted time step once, and applies
    /// configured abuse protection using principal and client metadata.
    ///
    /// Replay safety requires an atomic, durable [`TotpReplayStore`] shared by
    /// all workers. The host supplies the correct factor/secret and trusted
    /// time, verifies factor ownership and session binding, and only then records
    /// accepted MFA (for example through [`Self::step_up_session`]). This method
    /// neither enrolls a factor nor changes session assurance itself.
    ///
    /// Attempts are counted before the code is checked, as for
    /// [`Self::verify_totp_code_for_principal`]; a replayed step stays counted.
    #[allow(clippy::too_many_arguments)]
    pub async fn verify_totp_code_with_replay_store_and_metadata<S>(
        &self,
        store: &S,
        principal_id: &str,
        factor_id: Option<&str>,
        secret_base32: &str,
        code: &str,
        options: TotpOptions,
        now: OffsetDateTime,
        metadata: ClientMetadata,
    ) -> AuthResult<()>
    where
        S: TotpReplayStore,
    {
        let policy = &self.config.rate_limits.credential;
        let secret = prepare_totp_secret(secret_base32, &options)?;
        let rate_limit_keys = self.rate_limit_keys(
            AuthRateLimitFlow::TotpVerification,
            Some(principal_id),
            &metadata,
        );
        let reservation = self
            .reserve_credential_attempt(policy, &rate_limit_keys)
            .await?;

        let step = match match_totp_code(&secret, code, &options, now) {
            Ok(step) => step,
            Err(AuthError::InvalidTotpCode) => {
                self.settle_rate_limit_failure(policy, reservation).await?;
                return Err(AuthError::InvalidTotpCode);
            }
            Err(err) => {
                self.refund_rate_limit_reservation(policy, reservation)
                    .await?;
                return Err(err);
            }
        };
        // A replayed step and a replay-store error stay counted.
        if !store
            .consume_totp_step(principal_id, factor_id, step, now)
            .await?
        {
            self.settle_rate_limit_failure(policy, reservation).await?;
            return Err(AuthError::TotpCodeReplayed);
        }
        self.settle_rate_limit_success(policy, reservation).await
    }

    fn verify_totp_code_step(
        &self,
        secret_base32: &str,
        code: &str,
        options: TotpOptions,
        now: OffsetDateTime,
    ) -> AuthResult<i64> {
        let secret = prepare_totp_secret(secret_base32, &options)?;
        match_totp_code(&secret, code, &options, now)
    }
}

/// Validates host-supplied options and secret before any attempt is counted.
fn prepare_totp_secret(secret_base32: &str, options: &TotpOptions) -> AuthResult<Vec<u8>> {
    validate_totp_options(options)?;
    decode_base32_secret(secret_base32)
}

fn match_totp_code(
    secret: &[u8],
    code: &str,
    options: &TotpOptions,
    now: OffsetDateTime,
) -> AuthResult<i64> {
    if !code.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(AuthError::InvalidTotpCode);
    }

    let current_step = totp_step(now, options.period_seconds)?;
    let skew = i64::try_from(options.allowed_skew)
        .map_err(|_| AuthError::InvalidConfiguration("invalid totp skew".to_string()))?;

    for offset in -skew..=skew {
        let step = current_step + offset;
        if step < 0 {
            continue;
        }
        let expected = generate_totp_code_for_step(
            secret,
            u64::try_from(step)
                .map_err(|_| AuthError::InvalidConfiguration("invalid totp step".to_string()))?,
            options.digits,
        )?;
        if expected.as_bytes().ct_eq(code.as_bytes()).into() {
            return Ok(step);
        }
    }

    Err(AuthError::InvalidTotpCode)
}
