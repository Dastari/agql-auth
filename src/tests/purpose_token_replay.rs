use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value as JsonValue, json};
use time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{MemoryRefreshTokenStore, MemoryUserStore, TEST_HS256_SECRET};
use crate::prelude::*;

fn service() -> AuthService<MemoryUserStore, MemoryRefreshTokenStore> {
    AuthService::new(
        AuthConfig::new(TEST_HS256_SECRET),
        Arc::new(MemoryUserStore::default()),
        Arc::new(MemoryRefreshTokenStore::default()),
    )
    .unwrap()
}

fn request() -> PurposeTokenIssueRequest {
    PurposeTokenIssueRequest::new(
        "user-1",
        "capture_upload",
        "capture-upload-clients",
        Duration::minutes(5),
    )
}

fn expected() -> PurposeTokenValidation {
    PurposeTokenValidation::new("capture_upload", "capture-upload-clients")
}

fn payload(token: &str) -> JsonValue {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()
}

// every purpose token carries a unique `jti`.
#[test]
fn purpose_tokens_carry_a_unique_jti() {
    let auth = service();
    let first = auth.issue_purpose_token(request()).unwrap();
    let second = auth.issue_purpose_token(request()).unwrap();
    let first_jti = payload(&first.token)["jti"].as_str().unwrap().to_string();
    let second_jti = payload(&second.token)["jti"].as_str().unwrap().to_string();
    assert_ne!(first_jti, second_jti);
    uuid::Uuid::parse_str(&first_jti).unwrap();
}

#[test]
fn purpose_token_custom_claims_cannot_supply_a_jti() {
    let auth = service();
    assert!(matches!(
        auth.issue_purpose_token(request().with_claim("jti", json!("chosen"))),
        Err(AuthError::InvalidConfiguration(_))
    ));
}

#[derive(Default)]
struct MemoryReplayStore {
    consumed: Mutex<HashSet<Uuid>>,
    fail: bool,
}

#[async_trait]
impl PurposeTokenReplayStore for MemoryReplayStore {
    async fn consume_purpose_token(
        &self,
        token_id: Uuid,
        _expires_at: OffsetDateTime,
    ) -> crate::AuthResult<bool> {
        if self.fail {
            return Err(AuthError::Store("replay store offline".into()));
        }
        Ok(self.consumed.lock().unwrap().insert(token_id))
    }
}

#[tokio::test]
async fn consumed_purpose_tokens_succeed_once() {
    let auth = service();
    let store = MemoryReplayStore::default();
    let issued = auth.issue_purpose_token(request()).unwrap();
    let verified = auth
        .consume_purpose_token(&issued.token, expected(), &store)
        .await
        .unwrap();
    assert_eq!(verified.token_id, Some(issued.token_id));
    assert!(matches!(
        auth.consume_purpose_token(&issued.token, expected(), &store)
            .await,
        Err(AuthError::PurposeTokenReplayed)
    ));
    assert_eq!(
        AuthError::PurposeTokenReplayed.public_code(),
        "PURPOSE_TOKEN_REPLAYED"
    );

    // Another token is independent, and a wrong purpose never reaches the store.
    let other = auth.issue_purpose_token(request()).unwrap();
    assert!(matches!(
        auth.consume_purpose_token(
            &other.token,
            PurposeTokenValidation::new("other", "capture-upload-clients"),
            &store,
        )
        .await,
        Err(AuthError::InvalidPurposeToken)
    ));
    auth.consume_purpose_token(&other.token, expected(), &store)
        .await
        .unwrap();
}

#[tokio::test]
async fn purpose_token_consumption_fails_closed() {
    let auth = service();
    let issued = auth.issue_purpose_token(request()).unwrap();
    let failing = MemoryReplayStore {
        fail: true,
        ..MemoryReplayStore::default()
    };
    assert!(matches!(
        auth.consume_purpose_token(&issued.token, expected(), &failing)
            .await,
        Err(AuthError::Store(_))
    ));

    // A token minted without a jti (before 0.27) validates but cannot be consumed.
    let mut claims = payload(&issued.token);
    claims.as_object_mut().unwrap().remove("jti");
    let legacy = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(TEST_HS256_SECRET.as_bytes()),
    )
    .unwrap();
    assert_eq!(
        auth.authenticate_purpose_token(&legacy, expected())
            .unwrap()
            .token_id,
        None
    );
    assert!(matches!(
        auth.consume_purpose_token(&legacy, expected(), &MemoryReplayStore::default())
            .await,
        Err(AuthError::InvalidPurposeToken)
    ));
}

// Plain validation stays repeatable; it is the consuming call that is single-use.
#[test]
fn plain_purpose_token_validation_is_repeatable() {
    let auth = service();
    let issued = auth.issue_purpose_token(request()).unwrap();
    for _ in 0..2 {
        auth.authenticate_purpose_token(&issued.token, expected())
            .unwrap();
    }
}
