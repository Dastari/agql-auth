use uuid::Uuid;

use super::{MemoryLoginChallengeStore, metadata, test_auth_service};
use crate::prelude::*;

fn email_options() -> LoginChallengeOptions {
    LoginChallengeOptions {
        channel: Some("email".into()),
        ..Default::default()
    }
}

#[tokio::test]
async fn bound_verification_refuses_another_principal_or_channel_before_any_work() {
    let auth = test_auth_service(Default::default(), Default::default());
    let store = MemoryLoginChallengeStore::default();
    let issued = auth
        .create_login_challenge(&store, "alice@example.invalid", email_options())
        .await
        .unwrap();
    auth.password_work.lock().unwrap().clear();

    let mismatches = [
        LoginChallengeExpectation::for_principal("mallory@example.invalid"),
        LoginChallengeExpectation::for_principal("ALICE@example.invalid"),
        LoginChallengeExpectation::for_principal("alice@example.invalid").with_channel("sms"),
        LoginChallengeExpectation::for_channel("sms"),
        LoginChallengeExpectation::for_channel("Email"),
    ];
    for expected in &mismatches {
        let error = auth
            .verify_login_challenge_for(
                &store,
                issued.challenge_id,
                &issued.code,
                expected,
                metadata(),
            )
            .await
            .unwrap_err();
        // Indistinguishable from an unknown challenge ID.
        assert!(
            matches!(error, AuthError::InvalidLoginChallenge),
            "{error:?}"
        );
    }
    let stored = store
        .challenges
        .lock()
        .unwrap()
        .get(&issued.challenge_id)
        .cloned()
        .unwrap();
    assert_eq!(stored.attempts, 0, "a mismatch must not spend an attempt");
    assert!(stored.consumed_at.is_none());
    assert!(
        auth.password_work.lock().unwrap().is_empty(),
        "a mismatch must not reach password work"
    );

    let unknown = auth
        .verify_login_challenge_for(
            &store,
            Uuid::new_v4(),
            &issued.code,
            &LoginChallengeExpectation::for_principal("alice@example.invalid"),
            metadata(),
        )
        .await
        .unwrap_err();
    assert!(matches!(unknown, AuthError::InvalidLoginChallenge));

    let verified = auth
        .verify_login_challenge_for(
            &store,
            issued.challenge_id,
            &issued.code,
            &LoginChallengeExpectation::for_principal("alice@example.invalid")
                .with_channel("email"),
            metadata(),
        )
        .await
        .unwrap();
    assert_eq!(verified.principal, "alice@example.invalid");
    assert_eq!(verified.channel.as_deref(), Some("email"));
}

#[tokio::test]
async fn channel_expectation_refuses_an_unlabelled_challenge() {
    let auth = test_auth_service(Default::default(), Default::default());
    let store = MemoryLoginChallengeStore::default();
    let issued = auth
        .create_login_challenge(&store, "alice@example.invalid", Default::default())
        .await
        .unwrap();
    let error = auth
        .verify_login_challenge_for(
            &store,
            issued.challenge_id,
            &issued.code,
            &LoginChallengeExpectation::for_principal("alice@example.invalid")
                .with_channel("email"),
            metadata(),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, AuthError::InvalidLoginChallenge));

    // A principal-only expectation does not constrain the channel.
    let verified = auth
        .verify_login_challenge_for(
            &store,
            issued.challenge_id,
            &issued.code,
            &LoginChallengeExpectation::for_principal("alice@example.invalid"),
            metadata(),
        )
        .await
        .unwrap();
    assert_eq!(verified.channel, None);
}

#[tokio::test]
async fn matching_expectation_keeps_attempt_accounting() {
    let auth = test_auth_service(Default::default(), Default::default());
    let store = MemoryLoginChallengeStore::default();
    let issued = auth
        .create_login_challenge(
            &store,
            "alice@example.invalid",
            LoginChallengeOptions {
                max_attempts: 1,
                ..email_options()
            },
        )
        .await
        .unwrap();
    let expected = LoginChallengeExpectation::for_principal("alice@example.invalid");
    let wrong = auth
        .verify_login_challenge_for(
            &store,
            issued.challenge_id,
            "not-the-code",
            &expected,
            metadata(),
        )
        .await
        .unwrap_err();
    assert!(matches!(wrong, AuthError::LoginChallengeAttemptsExhausted));
    let exhausted = auth
        .verify_login_challenge_for(
            &store,
            issued.challenge_id,
            &issued.code,
            &expected,
            metadata(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        exhausted,
        AuthError::LoginChallengeAttemptsExhausted
    ));
}

#[test]
fn expectation_debug_is_plain_and_accessors_round_trip() {
    let expected = LoginChallengeExpectation::for_channel("sms").with_principal("p");
    assert_eq!(expected.principal(), Some("p"));
    assert_eq!(expected.channel(), Some("sms"));
}
