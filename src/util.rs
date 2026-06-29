use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use jsonwebtoken::errors::ErrorKind as JwtErrorKind;
use rand::RngCore;
use serde_json::Value as JsonValue;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

use crate::{AuthError, AuthResult, LoginChallengeOptions, TotpOptions};

type HmacSha1 = Hmac<Sha1>;

pub(crate) fn strip_bearer_prefix(input: &str) -> AuthResult<&str> {
    let trimmed = input.trim();
    if let Some(rest) = trimmed.strip_prefix("Bearer ") {
        Ok(rest.trim())
    } else if let Some(rest) = trimmed.strip_prefix("bearer ") {
        Ok(rest.trim())
    } else if trimmed.is_empty() {
        Err(AuthError::InvalidBearerToken)
    } else {
        Ok(trimmed)
    }
}

pub(crate) fn extract_connection_init_token(value: &JsonValue) -> AuthResult<String> {
    let Some(object) = value.as_object() else {
        return Err(AuthError::MissingConnectionInitAuth);
    };

    for key in [
        "authorization",
        "Authorization",
        "access_token",
        "accessToken",
    ] {
        if let Some(raw) = object.get(key).and_then(JsonValue::as_str) {
            return Ok(raw.to_string());
        }
    }

    Err(AuthError::MissingConnectionInitAuth)
}

pub(crate) fn map_access_token_decode_error(err: jsonwebtoken::errors::Error) -> AuthError {
    match err.kind() {
        JwtErrorKind::ExpiredSignature => AuthError::AccessTokenExpired,
        _ => AuthError::InvalidAccessToken,
    }
}

pub(crate) fn map_password_reset_decode_error(err: jsonwebtoken::errors::Error) -> AuthError {
    match err.kind() {
        JwtErrorKind::ExpiredSignature => AuthError::PasswordResetTokenExpired,
        _ => AuthError::InvalidPasswordResetToken,
    }
}

pub(crate) fn validate_login_challenge_options(options: &LoginChallengeOptions) -> AuthResult<()> {
    if options.code_length == 0 {
        return Err(AuthError::InvalidConfiguration(
            "login challenge code length must be greater than zero".to_string(),
        ));
    }

    if options.max_attempts == 0 {
        return Err(AuthError::InvalidConfiguration(
            "login challenge max_attempts must be greater than zero".to_string(),
        ));
    }

    if options.ttl <= Duration::ZERO {
        return Err(AuthError::InvalidConfiguration(
            "login challenge ttl must be greater than zero".to_string(),
        ));
    }

    Ok(())
}

pub(crate) fn validate_totp_options(options: &TotpOptions) -> AuthResult<()> {
    if !(6..=8).contains(&options.digits) {
        return Err(AuthError::InvalidConfiguration(
            "totp digits must be between 6 and 8".to_string(),
        ));
    }

    if options.period_seconds == 0 {
        return Err(AuthError::InvalidConfiguration(
            "totp period must be greater than zero".to_string(),
        ));
    }

    Ok(())
}

pub(crate) fn generate_numeric_code(length: usize) -> String {
    let mut bytes = vec![0u8; length];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity(length);
    for byte in bytes {
        out.push(char::from(b'0' + (byte % 10)));
    }
    out
}

pub(crate) fn generate_opaque_token() -> String {
    let mut bytes = [0u8; 48];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn hash_refresh_token(token: &str) -> String {
    hash_opaque_token(token)
}

pub(crate) fn hash_api_token(token: &str) -> String {
    hash_opaque_token(token)
}

fn hash_opaque_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let digest = hasher.finalize();
    encode_hex(digest)
}

fn encode_hex(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}"));
    }
    out
}

pub(crate) fn totp_step(now: OffsetDateTime, period_seconds: u64) -> AuthResult<i64> {
    let period = i64::try_from(period_seconds)
        .map_err(|_| AuthError::InvalidConfiguration("totp period is too large".to_string()))?;
    Ok(now.unix_timestamp() / period)
}

pub(crate) fn generate_totp_code_for_step(
    secret: &[u8],
    step: u64,
    digits: u32,
) -> AuthResult<String> {
    let mut mac = HmacSha1::new_from_slice(secret).map_err(|_| AuthError::InvalidTotpSecret)?;
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let binary = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let modulo = 10u32
        .checked_pow(digits)
        .ok_or_else(|| AuthError::InvalidConfiguration("invalid totp digits".to_string()))?;
    Ok(format!(
        "{:0width$}",
        binary % modulo,
        width = usize::try_from(digits)
            .map_err(|_| AuthError::InvalidConfiguration("invalid totp digits".to_string()))?
    ))
}

pub(crate) fn decode_base32_secret(secret_base32: &str) -> AuthResult<Vec<u8>> {
    BASE32_NOPAD
        .decode(secret_base32.as_bytes())
        .map_err(|_| AuthError::InvalidTotpSecret)
}
