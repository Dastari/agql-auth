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
    decode_base32_secret, generate_totp_code_for_step, totp_step, validate_totp_options,
};
use crate::{AuthError, AuthResult};

impl<U, R> AuthService<U, R>
where
    U: UserStore + 'static,
    R: RefreshTokenStore + 'static,
{
    /// Generates a random TOTP secret.
    pub fn generate_totp_secret(&self, num_bytes: usize) -> AuthResult<TotpSecret> {
        if num_bytes < 10 {
            return Err(AuthError::InvalidConfiguration(
                "totp secret must be at least 10 bytes".to_string(),
            ));
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
    pub fn build_totp_provisioning(
        &self,
        secret: &TotpSecret,
        issuer: impl Into<String>,
        account_name: impl Into<String>,
        options: TotpOptions,
    ) -> AuthResult<TotpProvisioning> {
        validate_totp_options(&options)?;
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
    /// once within the configured skew window. Production MFA flows should
    /// prefer [`AuthService::verify_totp_code_with_replay_store`].
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

    /// Verifies a TOTP code for a principal with abuse protection.
    pub async fn verify_totp_code_for_principal(
        &self,
        principal_id: &str,
        secret_base32: &str,
        code: &str,
        options: TotpOptions,
        now: OffsetDateTime,
        metadata: ClientMetadata,
    ) -> AuthResult<()> {
        let rate_limit_keys = self.rate_limit_keys(
            AuthRateLimitFlow::TotpVerification,
            Some(principal_id),
            &metadata,
        );
        let rate_limit_permit = self
            .reject_if_rate_limited(&self.config.rate_limits.credential, &rate_limit_keys)
            .await?;

        match self.verify_totp_code_step(secret_base32, code, options, now) {
            Ok(_) => {
                self.clear_rate_limit_attempts(
                    &self.config.rate_limits.credential,
                    &rate_limit_permit,
                )
                .await?;
                Ok(())
            }
            Err(err) => {
                if matches!(err, AuthError::InvalidTotpCode) {
                    self.record_rate_limit_attempt(
                        &self.config.rate_limits.credential,
                        &rate_limit_keys,
                    )
                    .await?;
                }
                Err(err)
            }
        }
    }

    /// Verifies a TOTP code and consumes the accepted time step once.
    ///
    /// `store.consume_totp_step` must atomically return `true` only for the
    /// first use of `(principal_id, factor_id, step)`.
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
    /// abuse protection using principal and client metadata.
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
        let rate_limit_keys = self.rate_limit_keys(
            AuthRateLimitFlow::TotpVerification,
            Some(principal_id),
            &metadata,
        );
        let rate_limit_permit = self
            .reject_if_rate_limited(&self.config.rate_limits.credential, &rate_limit_keys)
            .await?;

        let step = match self.verify_totp_code_step(secret_base32, code, options, now) {
            Ok(step) => step,
            Err(err) => {
                if matches!(err, AuthError::InvalidTotpCode) {
                    self.record_rate_limit_attempt(
                        &self.config.rate_limits.credential,
                        &rate_limit_keys,
                    )
                    .await?;
                }
                return Err(err);
            }
        };
        let consumed = store
            .consume_totp_step(principal_id, factor_id, step, now)
            .await?;
        if consumed {
            self.clear_rate_limit_attempts(&self.config.rate_limits.credential, &rate_limit_permit)
                .await?;
            Ok(())
        } else {
            self.record_rate_limit_attempt(&self.config.rate_limits.credential, &rate_limit_keys)
                .await?;
            Err(AuthError::TotpCodeReplayed)
        }
    }

    fn verify_totp_code_step(
        &self,
        secret_base32: &str,
        code: &str,
        options: TotpOptions,
        now: OffsetDateTime,
    ) -> AuthResult<i64> {
        validate_totp_options(&options)?;
        if !code.chars().all(|ch| ch.is_ascii_digit()) {
            return Err(AuthError::InvalidTotpCode);
        }

        let secret = decode_base32_secret(secret_base32)?;
        let current_step = totp_step(now, options.period_seconds)?;
        let skew = i64::try_from(options.allowed_skew)
            .map_err(|_| AuthError::InvalidConfiguration("invalid totp skew".to_string()))?;

        for offset in -skew..=skew {
            let step = current_step + offset;
            if step < 0 {
                continue;
            }
            let expected = generate_totp_code_for_step(
                &secret,
                u64::try_from(step).map_err(|_| {
                    AuthError::InvalidConfiguration("invalid totp step".to_string())
                })?,
                options.digits,
            )?;
            if expected.as_bytes().ct_eq(code.as_bytes()).into() {
                return Ok(step);
            }
        }

        Err(AuthError::InvalidTotpCode)
    }
}
