use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
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

#[tokio::test]
async fn totp_replay_store_rejects_reused_step() {
    let auth = test_auth_service(Default::default(), Default::default());
    let store = MemoryTotpReplayStore::default();
    let options = TotpOptions {
        digits: 8,
        period_seconds: 30,
        allowed_skew: 0,
    };
    let secret = TotpSecret {
        raw_secret: b"12345678901234567890".to_vec(),
        base32_secret: BASE32_NOPAD.encode(b"12345678901234567890"),
    };
    let now = OffsetDateTime::from_unix_timestamp(59).unwrap();

    auth.verify_totp_code_with_replay_store(
        &store,
        "user-1",
        Some("primary"),
        &secret.base32_secret,
        "94287082",
        options.clone(),
        now,
    )
    .await
    .unwrap();

    let err = auth
        .verify_totp_code_with_replay_store(
            &store,
            "user-1",
            Some("primary"),
            &secret.base32_secret,
            "94287082",
            options,
            now,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::TotpCodeReplayed));
}

#[test]
fn totp_secret_and_provisioning_debug_redact_secret_material() {
    let secret = TotpSecret {
        raw_secret: b"super-secret".to_vec(),
        base32_secret: "JBSWY3DPEHPK3PXP".to_string(),
    };
    let debug_secret = format!("{secret:?}");
    assert!(!debug_secret.contains("super-secret"));
    assert!(!debug_secret.contains("JBSWY3DPEHPK3PXP"));

    let provisioning = TotpProvisioning {
        issuer: "agql-auth".to_string(),
        account_name: "alice@example.com".to_string(),
        secret: "JBSWY3DPEHPK3PXP".to_string(),
        uri: "otpauth://totp/agql-auth:alice@example.com?secret=JBSWY3DPEHPK3PXP".to_string(),
    };
    let debug_provisioning = format!("{provisioning:?}");
    assert!(!debug_provisioning.contains("JBSWY3DPEHPK3PXP"));
    assert!(!debug_provisioning.contains("otpauth://"));
    assert!(debug_provisioning.contains("alice@example.com"));
}

type ConsumedTotpSteps = HashSet<(String, Option<String>, i64)>;

#[derive(Clone, Default)]
struct MemoryTotpReplayStore {
    consumed: Arc<Mutex<ConsumedTotpSteps>>,
}

#[async_trait]
impl TotpReplayStore for MemoryTotpReplayStore {
    async fn consume_totp_step(
        &self,
        principal_id: &str,
        factor_id: Option<&str>,
        step: i64,
        _consumed_at: OffsetDateTime,
    ) -> crate::AuthResult<bool> {
        Ok(self.consumed.lock().unwrap().insert((
            principal_id.to_string(),
            factor_id.map(str::to_string),
            step,
        )))
    }
}
