use time::{Duration, OffsetDateTime};

use super::{MemoryLoginChallengeStore, test_auth_service};
use crate::prelude::*;

#[tokio::test]
async fn login_challenges_support_success_invalid_code_exhaustion_and_replay() {
    let auth = test_auth_service(Default::default(), Default::default());
    let store = MemoryLoginChallengeStore::default();
    let issued = auth
        .create_login_challenge(
            &store,
            "alice@example.com",
            LoginChallengeOptions {
                max_attempts: 2,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let invalid = auth
        .verify_login_challenge(&store, issued.challenge_id, "not-a-numeric-code")
        .await
        .unwrap_err();
    assert!(matches!(invalid, AuthError::InvalidLoginCode));

    let exhausted = auth
        .verify_login_challenge(&store, issued.challenge_id, "another-nonnumeric-code")
        .await
        .unwrap_err();
    assert!(matches!(
        exhausted,
        AuthError::LoginChallengeAttemptsExhausted
    ));

    let fresh = auth
        .create_login_challenge(&store, "bob@example.com", Default::default())
        .await
        .unwrap();
    let verified = auth
        .verify_login_challenge(&store, fresh.challenge_id, &fresh.code)
        .await
        .unwrap();
    assert_eq!(verified.principal, "bob@example.com");

    let replay = auth
        .verify_login_challenge(&store, fresh.challenge_id, &fresh.code)
        .await
        .unwrap_err();
    assert!(matches!(replay, AuthError::LoginChallengeReplayed));
}

#[tokio::test]
async fn login_challenges_reject_expired_codes() {
    let auth = test_auth_service(Default::default(), Default::default());
    let store = MemoryLoginChallengeStore::default();
    let issued = auth
        .create_login_challenge(
            &store,
            "alice@example.com",
            LoginChallengeOptions {
                ttl: Duration::seconds(1),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    store
        .challenges
        .lock()
        .unwrap()
        .get_mut(&issued.challenge_id)
        .unwrap()
        .expires_at = OffsetDateTime::now_utc() - Duration::seconds(1);

    let err = auth
        .verify_login_challenge(&store, issued.challenge_id, &issued.code)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::LoginChallengeExpired));
}

#[tokio::test]
async fn numeric_login_codes_are_ascii_digits_and_requested_length() {
    let auth = test_auth_service(Default::default(), Default::default());
    let store = MemoryLoginChallengeStore::default();
    for length in [1, 6, 12] {
        let issued = auth
            .create_login_challenge(
                &store,
                "alice@example.com",
                LoginChallengeOptions {
                    code_length: length,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(issued.code.len(), length);
        assert!(issued.code.chars().all(|ch| ch.is_ascii_digit()));
    }
}

#[tokio::test]
async fn concurrent_challenge_guesses_do_not_exceed_atomic_attempt_budget() {
    use async_trait::async_trait;
    use std::sync::Arc;
    use uuid::Uuid;

    struct ConcurrentReads {
        inner: MemoryLoginChallengeStore,
        reads: tokio::sync::Barrier,
    }
    #[async_trait]
    impl LoginChallengeStore for ConcurrentReads {
        async fn insert_login_challenge(
            &self,
            challenge: StoredLoginChallenge,
        ) -> crate::AuthResult<()> {
            self.inner.insert_login_challenge(challenge).await
        }
        async fn find_login_challenge(
            &self,
            id: Uuid,
        ) -> crate::AuthResult<Option<StoredLoginChallenge>> {
            let snapshot = self.inner.find_login_challenge(id).await?;
            self.reads.wait().await;
            Ok(snapshot)
        }
        async fn reserve_login_challenge_attempt(
            &self,
            id: Uuid,
            now: OffsetDateTime,
        ) -> crate::AuthResult<StoredLoginChallenge> {
            self.inner.reserve_login_challenge_attempt(id, now).await
        }
        async fn consume_login_challenge(
            &self,
            id: Uuid,
            now: OffsetDateTime,
        ) -> crate::AuthResult<bool> {
            self.inner.consume_login_challenge(id, now).await
        }
    }
    let auth = test_auth_service(Default::default(), Default::default());
    let store = Arc::new(ConcurrentReads {
        inner: Default::default(),
        reads: tokio::sync::Barrier::new(2),
    });
    let issued = auth
        .create_login_challenge(
            store.as_ref(),
            "synthetic@example.invalid",
            LoginChallengeOptions {
                max_attempts: 1,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    auth.password_work.lock().unwrap().clear();
    let (first, second) = tokio::join!(
        auth.verify_login_challenge(store.as_ref(), issued.challenge_id, "synthetic-wrong"),
        auth.verify_login_challenge(store.as_ref(), issued.challenge_id, "synthetic-wrong"),
    );
    assert!(first.is_err() && second.is_err());
    assert_eq!(
        auth.password_work.lock().unwrap().len(),
        1,
        "one admission must allow at most one expensive verification"
    );
}
