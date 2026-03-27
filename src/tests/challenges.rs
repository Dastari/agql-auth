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
        .verify_login_challenge(&store, issued.challenge_id, "000000")
        .await
        .unwrap_err();
    assert!(matches!(invalid, AuthError::InvalidLoginCode));

    let exhausted = auth
        .verify_login_challenge(&store, issued.challenge_id, "111111")
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
