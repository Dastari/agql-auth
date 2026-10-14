use time::Duration;

use super::{
    MemoryPasswordResetStore, MemoryRefreshTokenStore, MemoryUserStore, metadata, stored_user,
    test_auth_service,
};
use crate::prelude::*;

#[tokio::test]
async fn password_reset_tokens_support_success_expiry_and_replay() {
    let auth = test_auth_service(Default::default(), Default::default());
    let store = MemoryPasswordResetStore::default();

    let issued = auth
        .issue_password_reset_token_with_store(&store, "user-1", Duration::hours(1))
        .await
        .unwrap();
    let debug = format!("{issued:?}");
    assert!(!debug.contains(&issued.token));
    assert!(debug.contains("user-1"));

    let verified = auth
        .consume_password_reset_token(&store, &issued.token)
        .await
        .unwrap();
    assert_eq!(verified.user_id, "user-1");
    assert_eq!(verified.token_id, issued.token_id);

    let replay = auth
        .consume_password_reset_token(&store, &issued.token)
        .await
        .unwrap_err();
    assert!(matches!(replay, AuthError::PasswordResetTokenReplayed));

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let expired = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &serde_json::json!({
            "sub": "user-2", "jti": uuid::Uuid::new_v4().to_string(),
            "typ": "password_reset", "purpose": "password_reset",
            "iss": "agql-auth", "aud": "agql-auth-clients",
            "iat": now - 60, "exp": now - 5,
        }),
        &jsonwebtoken::EncodingKey::from_secret(super::TEST_HS256_SECRET.as_bytes()),
    )
    .unwrap();
    let err = auth
        .authenticate_password_reset_token(&expired)
        .unwrap_err();
    assert!(matches!(err, AuthError::PasswordResetTokenExpired));
}

#[tokio::test]
async fn password_reset_tokens_reject_non_reset_tokens() {
    let user_store = MemoryUserStore::default();
    let refresh_store = MemoryRefreshTokenStore::default();
    let auth = test_auth_service(user_store.clone(), refresh_store);

    user_store.insert(stored_user(
        &auth,
        "user-1",
        "alice@example.com",
        "password123",
    ));
    let payload = auth
        .login("alice@example.com", "password123", metadata())
        .await
        .unwrap();

    let err = auth
        .authenticate_password_reset_token(&payload.access_token)
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidPasswordResetToken));
}
