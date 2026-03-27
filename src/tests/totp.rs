use data_encoding::BASE32_NOPAD;
use time::OffsetDateTime;

use super::test_auth_service;
use crate::prelude::*;

#[tokio::test]
async fn totp_supports_known_vector_and_invalid_code_rejection() {
    let auth = test_auth_service(Default::default(), Default::default());
    let options = TotpOptions {
        digits: 8,
        period_seconds: 30,
        allowed_skew: 0,
    };
    let secret = TotpSecret {
        raw_secret: b"12345678901234567890".to_vec(),
        base32_secret: BASE32_NOPAD.encode(b"12345678901234567890"),
    };

    auth.verify_totp_code(
        &secret.base32_secret,
        "94287082",
        options.clone(),
        OffsetDateTime::from_unix_timestamp(59).unwrap(),
    )
    .unwrap();

    let err = auth
        .verify_totp_code(
            &secret.base32_secret,
            "00000000",
            options.clone(),
            OffsetDateTime::from_unix_timestamp(59).unwrap(),
        )
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidTotpCode));

    let provisioning = auth
        .build_totp_provisioning(&secret, "agql-auth", "alice@example.com", options)
        .unwrap();
    assert!(provisioning.uri.starts_with("otpauth://totp/"));
    assert!(provisioning.uri.contains("issuer="));
}
