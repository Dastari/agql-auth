use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::{MemoryPasswordResetStore, TEST_HS256_SECRET, test_auth_service};
use crate::prelude::*;

fn signed_reset_token(user_id: &str, token_id: Uuid, typ: Option<&str>) -> String {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut claims = serde_json::json!({
        "sub": user_id, "jti": token_id.to_string(), "purpose": "password_reset",
        "iss": "agql-auth", "aud": "agql-auth-clients", "iat": now, "exp": now + 600,
    });
    if let Some(typ) = typ {
        claims["typ"] = typ.into();
    }
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(TEST_HS256_SECRET.as_bytes()),
    )
    .unwrap()
}

async fn record(store: &MemoryPasswordResetStore, user_id: &str, token_id: Uuid) {
    store
        .insert_password_reset_token(
            token_id,
            user_id,
            OffsetDateTime::now_utc() + Duration::minutes(10),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn reset_tokens_without_the_reset_type_are_refused() {
    let auth = test_auth_service(Default::default(), Default::default());
    let store = MemoryPasswordResetStore::default();
    let token_id = Uuid::new_v4();
    record(&store, "user-1", token_id).await;
    for typ in [None, Some("access"), Some("")] {
        let token = signed_reset_token("user-1", token_id, typ);
        assert!(matches!(
            auth.authenticate_password_reset_token(&token),
            Err(AuthError::InvalidPasswordResetToken)
        ));
        assert!(matches!(
            auth.consume_password_reset_token(&store, &token).await,
            Err(AuthError::InvalidPasswordResetToken)
        ));
    }
    let typed = signed_reset_token("user-1", token_id, Some("password_reset"));
    assert_eq!(
        auth.consume_password_reset_token(&store, &typed)
            .await
            .unwrap()
            .token_id,
        token_id
    );
}

#[tokio::test]
async fn issuing_a_reset_token_invalidates_the_users_outstanding_tokens() {
    let auth = test_auth_service(Default::default(), Default::default());
    let store = MemoryPasswordResetStore::default();
    let first = auth
        .issue_password_reset_token_with_store(&store, "user-1", Duration::hours(1))
        .await
        .unwrap();
    let other_user = auth
        .issue_password_reset_token_with_store(&store, "user-2", Duration::hours(1))
        .await
        .unwrap();
    let second = auth
        .issue_password_reset_token_with_store(&store, "user-1", Duration::hours(1))
        .await
        .unwrap();

    assert!(matches!(
        auth.consume_password_reset_token(&store, &first.token)
            .await,
        Err(AuthError::PasswordResetTokenReplayed)
    ));
    assert_eq!(
        auth.consume_password_reset_token(&store, &second.token)
            .await
            .unwrap()
            .user_id,
        "user-1"
    );
    assert_eq!(
        auth.consume_password_reset_token(&store, &other_user.token)
            .await
            .unwrap()
            .user_id,
        "user-2"
    );
}

#[tokio::test]
async fn consuming_a_reset_token_invalidates_the_users_other_tokens() {
    let auth = test_auth_service(Default::default(), Default::default());
    let store = MemoryPasswordResetStore::default();
    let issued = auth
        .issue_password_reset_token_with_store(&store, "user-1", Duration::hours(1))
        .await
        .unwrap();
    // A sibling recorded concurrently with, or after, the issued token.
    let sibling_id = Uuid::new_v4();
    record(&store, "user-1", sibling_id).await;
    let sibling = signed_reset_token("user-1", sibling_id, Some("password_reset"));
    let unrelated_id = Uuid::new_v4();
    record(&store, "user-2", unrelated_id).await;
    let unrelated = signed_reset_token("user-2", unrelated_id, Some("password_reset"));

    auth.consume_password_reset_token(&store, &issued.token)
        .await
        .unwrap();
    assert!(matches!(
        auth.consume_password_reset_token(&store, &sibling).await,
        Err(AuthError::PasswordResetTokenReplayed)
    ));
    auth.consume_password_reset_token(&store, &unrelated)
        .await
        .unwrap();
}

#[tokio::test]
async fn store_less_reset_tokens_are_never_consumable() {
    let auth = test_auth_service(Default::default(), Default::default());
    let store = MemoryPasswordResetStore::default();
    // Signed with the service key but never recorded: validation alone passes,
    // which is why the crate no longer issues such tokens.
    let token = signed_reset_token("user-1", Uuid::new_v4(), Some("password_reset"));
    assert!(auth.authenticate_password_reset_token(&token).is_ok());
    assert!(matches!(
        auth.consume_password_reset_token(&store, &token).await,
        Err(AuthError::PasswordResetTokenReplayed)
    ));
}

#[tokio::test]
async fn consuming_a_reset_revokes_every_refresh_session_of_the_user() {
    let users = super::MemoryUserStore::default();
    let auth = test_auth_service(users.clone(), Default::default());
    users.insert(super::stored_user(
        &auth,
        "user-1",
        "alice@example.com",
        "password123",
    ));
    users.insert(super::stored_user(
        &auth,
        "user-2",
        "bob@example.com",
        "password456",
    ));
    let first = auth
        .login("alice@example.com", "password123", super::metadata())
        .await
        .unwrap();
    let second = auth
        .login(
            "alice@example.com",
            "password123",
            ClientMetadata::default(),
        )
        .await
        .unwrap();
    let other = auth
        .login("bob@example.com", "password456", ClientMetadata::default())
        .await
        .unwrap();

    let store = MemoryPasswordResetStore::default();
    let reset = auth
        .issue_password_reset_token_with_store(&store, "user-1", Duration::hours(1))
        .await
        .unwrap();
    auth.consume_password_reset_token(&store, &reset.token)
        .await
        .unwrap();

    for payload in [first, second] {
        assert!(
            auth.refresh(&payload.refresh_token, ClientMetadata::default())
                .await
                .is_err(),
            "a refresh session survived the password reset"
        );
    }
    auth.refresh(&other.refresh_token, ClientMetadata::default())
        .await
        .expect("another user's session is untouched");
}
