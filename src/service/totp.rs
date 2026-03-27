use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use rand::RngCore;
use time::OffsetDateTime;

use super::AuthService;
use crate::models::{TotpOptions, TotpProvisioning, TotpSecret};
use crate::stores::{RefreshTokenStore, UserStore};
use crate::util::{
    decode_base32_secret, generate_totp_code_for_step, totp_step, validate_totp_options,
};
use crate::{AuthError, AuthResult};

impl<U, R> AuthService<U, R>
where
    U: UserStore + 'static,
    R: RefreshTokenStore + 'static,
{
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

    pub fn verify_totp_code(
        &self,
        secret_base32: &str,
        code: &str,
        options: TotpOptions,
        now: OffsetDateTime,
    ) -> AuthResult<()> {
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
            if expected == code {
                return Ok(());
            }
        }

        Err(AuthError::InvalidTotpCode)
    }
}
