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

/// Login-code length bounds: at least one million codes, at most twelve digits.
pub(crate) const LOGIN_CHALLENGE_CODE_LENGTH: std::ops::RangeInclusive<usize> = 6..=12;
/// Upper bound for admitted guesses against one login challenge.
pub(crate) const MAX_LOGIN_CHALLENGE_ATTEMPTS: u32 = 10;
/// TOTP period bounds in seconds.
pub(crate) const TOTP_PERIOD_SECONDS: std::ops::RangeInclusive<u64> = 15..=300;
/// Largest accepted number of TOTP steps before and after the current one.
pub(crate) const MAX_TOTP_ALLOWED_SKEW: u64 = 2;
/// Shortest TOTP secret accepted anywhere: the 128-bit minimum of RFC 4226.
pub(crate) const MIN_TOTP_SECRET_BYTES: usize = 16;
/// Shortest generated TOTP secret: the 160-bit length RFC 4226 recommends.
pub(crate) const MIN_GENERATED_TOTP_SECRET_BYTES: usize = 20;
/// Longest generated TOTP secret: the HMAC-SHA1 block size.
pub(crate) const MAX_GENERATED_TOTP_SECRET_BYTES: usize = 64;

/// Validates a trusted duration before constructing an expiry. All callers fail
/// before signing or persisting a credential if the result is unrepresentable.
pub(crate) fn checked_expiry(
    now: OffsetDateTime,
    ttl: Duration,
    name: &str,
) -> AuthResult<OffsetDateTime> {
    if ttl <= Duration::ZERO {
        return Err(AuthError::InvalidConfiguration(format!(
            "{name} must be positive"
        )));
    }
    now.checked_add(ttl).ok_or_else(|| {
        AuthError::InvalidConfiguration(format!("{name} exceeds the supported timestamp range"))
    })
}

pub(crate) fn checked_jwt_expiry(
    now: OffsetDateTime,
    ttl: Duration,
    name: &str,
) -> AuthResult<OffsetDateTime> {
    let expiry = checked_expiry(now, ttl, name)?;
    if expiry.unix_timestamp() <= now.unix_timestamp() {
        return Err(AuthError::InvalidConfiguration(format!(
            "{name} expires within the issuance second"
        )));
    }
    Ok(expiry)
}

/// Removes duplicates while keeping first-seen order.
pub(crate) fn dedupe_stable(values: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        if seen.insert(value.clone()) {
            out.push(value);
        }
    }
    out
}

pub(crate) fn strip_bearer_prefix(input: &str) -> AuthResult<&str> {
    strip_bearer_prefix_with_mode(input, crate::token_decode::BearerParseMode::BearerOrRaw)
}

pub(crate) fn strip_bearer_prefix_with_mode(
    input: &str,
    mode: crate::token_decode::BearerParseMode,
) -> AuthResult<&str> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(AuthError::InvalidBearerToken);
    }
    if trimmed.eq_ignore_ascii_case("Bearer") {
        return Err(AuthError::InvalidBearerToken);
    }

    let Some((scheme, rest)) = trimmed.split_once(char::is_whitespace) else {
        return match mode {
            crate::token_decode::BearerParseMode::BearerOrRaw => Ok(trimmed),
            crate::token_decode::BearerParseMode::RequireBearer => {
                Err(AuthError::InvalidBearerToken)
            }
        };
    };

    if !scheme.eq_ignore_ascii_case("Bearer") {
        // Explicitly reject Basic and other schemes.
        return Err(AuthError::InvalidBearerToken);
    }

    let token = rest.trim();
    if token.is_empty() || token.split_whitespace().count() != 1 {
        return Err(AuthError::InvalidBearerToken);
    }

    Ok(token)
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

pub(crate) fn map_purpose_token_decode_error(err: jsonwebtoken::errors::Error) -> AuthError {
    match err.kind() {
        JwtErrorKind::ExpiredSignature => AuthError::PurposeTokenExpired,
        _ => AuthError::InvalidPurposeToken,
    }
}

pub(crate) fn validate_login_challenge_options(options: &LoginChallengeOptions) -> AuthResult<()> {
    if !LOGIN_CHALLENGE_CODE_LENGTH.contains(&options.code_length) {
        return Err(AuthError::InvalidConfiguration(format!(
            "login challenge code length must be between {} and {}",
            LOGIN_CHALLENGE_CODE_LENGTH.start(),
            LOGIN_CHALLENGE_CODE_LENGTH.end()
        )));
    }

    if !(1..=MAX_LOGIN_CHALLENGE_ATTEMPTS).contains(&options.max_attempts) {
        return Err(AuthError::InvalidConfiguration(format!(
            "login challenge max_attempts must be between 1 and {MAX_LOGIN_CHALLENGE_ATTEMPTS}"
        )));
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

    if !TOTP_PERIOD_SECONDS.contains(&options.period_seconds) {
        return Err(AuthError::InvalidConfiguration(format!(
            "totp period must be between {} and {} seconds",
            TOTP_PERIOD_SECONDS.start(),
            TOTP_PERIOD_SECONDS.end()
        )));
    }

    if options.allowed_skew > MAX_TOTP_ALLOWED_SKEW {
        return Err(AuthError::InvalidConfiguration(format!(
            "totp allowed_skew must not exceed {MAX_TOTP_ALLOWED_SKEW}"
        )));
    }

    Ok(())
}

pub(crate) fn generate_numeric_code(length: usize) -> String {
    let mut out = String::with_capacity(length);
    while out.len() < length {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        for byte in bytes {
            if byte < 250 {
                out.push(char::from(b'0' + (byte % 10)));
                if out.len() == length {
                    break;
                }
            }
        }
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

pub(crate) fn hash_rate_limit_value(value: &str) -> String {
    hash_opaque_token(value)
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

/// Decodes a stored TOTP secret, rejecting secrets shorter than 128 bits.
pub(crate) fn decode_base32_secret(secret_base32: &str) -> AuthResult<Vec<u8>> {
    BASE32_NOPAD
        .decode(secret_base32.as_bytes())
        .ok()
        .filter(|secret| secret.len() >= MIN_TOTP_SECRET_BYTES)
        .ok_or(AuthError::InvalidTotpSecret)
}
