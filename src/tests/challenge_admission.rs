use super::*;
use crate::AuthResult;
use time::Duration;
use tokio::sync::{Barrier, Notify};

#[derive(Default)]
struct ControlledChallenges {
    inner: MemoryLoginChallengeStore,
    read_barrier: Option<Barrier>,
    consume_barrier: Option<Barrier>,
    pause_admission: Option<Notify>,
    advance_after_reserve: Option<FixedClock>,
    advance_after_consume: Option<FixedClock>,
    corrupt_identity: bool,
}

#[async_trait]
impl LoginChallengeStore for ControlledChallenges {
    async fn insert_login_challenge(&self, challenge: StoredLoginChallenge) -> AuthResult<()> {
        self.inner.insert_login_challenge(challenge).await
    }
    async fn find_login_challenge(&self, id: Uuid) -> AuthResult<Option<StoredLoginChallenge>> {
        let record = self.inner.find_login_challenge(id).await?;
        if let Some(barrier) = &self.read_barrier {
            barrier.wait().await;
        }
        Ok(record)
    }
    async fn reserve_login_challenge_attempt(
        &self,
        id: Uuid,
        now: OffsetDateTime,
    ) -> AuthResult<StoredLoginChallenge> {
        let mut admitted = self.inner.reserve_login_challenge_attempt(id, now).await?;
        if let Some(clock) = &self.advance_after_reserve {
            clock.advance_seconds(60);
        }
        if self.corrupt_identity {
            admitted.principal = "different-synthetic-principal".into();
        }
        if let Some(notify) = &self.pause_admission {
            notify.notify_one();
            std::future::pending::<()>().await;
        }
        Ok(admitted)
    }
    async fn consume_login_challenge(&self, id: Uuid, now: OffsetDateTime) -> AuthResult<bool> {
        if let Some(barrier) = &self.consume_barrier {
            barrier.wait().await;
        }
        let consumed = self.inner.consume_login_challenge(id, now).await?;
        if let Some(clock) = &self.advance_after_consume {
            clock.advance_seconds(60);
        }
        Ok(consumed)
    }
}

#[tokio::test]
async fn concurrent_correct_codes_consume_exactly_once_with_reserved_budget() {
    let auth = test_auth_service(Default::default(), Default::default());
    let store = ControlledChallenges {
        read_barrier: Some(Barrier::new(2)),
        consume_barrier: Some(Barrier::new(2)),
        ..Default::default()
    };
    let issued = auth
        .create_login_challenge(
            &store,
            "fixture",
            LoginChallengeOptions {
                max_attempts: 2,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    auth.password_work.lock().unwrap().clear();
    let (a, b) = tokio::join!(
        auth.verify_login_challenge(&store, issued.challenge_id, &issued.code),
        auth.verify_login_challenge(&store, issued.challenge_id, &issued.code)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(auth.password_work.lock().unwrap().len(), 2);
    let row = store
        .inner
        .find_login_challenge(issued.challenge_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.attempts, 2);
    assert!(row.is_consumed());
}

#[tokio::test]
async fn wrong_and_correct_concurrent_guesses_share_the_same_single_admission() {
    let auth = test_auth_service(Default::default(), Default::default());
    let store = ControlledChallenges {
        read_barrier: Some(Barrier::new(2)),
        ..Default::default()
    };
    let issued = auth
        .create_login_challenge(
            &store,
            "fixture",
            LoginChallengeOptions {
                max_attempts: 1,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    auth.password_work.lock().unwrap().clear();
    let (wrong, correct) = tokio::join!(
        auth.verify_login_challenge(&store, issued.challenge_id, "not-a-numeric-code"),
        auth.verify_login_challenge(&store, issued.challenge_id, &issued.code)
    );
    assert!(wrong.is_err());
    assert!(correct.is_ok() || matches!(correct, Err(AuthError::LoginChallengeAttemptsExhausted)));
    assert_eq!(auth.password_work.lock().unwrap().len(), 1);
    assert_eq!(
        store
            .inner
            .find_login_challenge(issued.challenge_id)
            .await
            .unwrap()
            .unwrap()
            .attempts,
        1
    );
}

#[tokio::test]
async fn expiry_after_admission_or_during_consume_never_returns_verified_authority() {
    for after_consume in [false, true] {
        let clock = FixedClock::new(OffsetDateTime::UNIX_EPOCH);
        let auth = test_auth_service(Default::default(), Default::default())
            .with_login_challenge_clock(Arc::new(clock.clone()));
        let store = ControlledChallenges {
            advance_after_reserve: (!after_consume).then(|| clock.clone()),
            advance_after_consume: after_consume.then(|| clock.clone()),
            ..Default::default()
        };
        let issued = auth
            .create_login_challenge(
                &store,
                "fixture",
                LoginChallengeOptions {
                    ttl: Duration::seconds(30),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        auth.password_work.lock().unwrap().clear();
        let result = auth
            .verify_login_challenge(&store, issued.challenge_id, &issued.code)
            .await;
        assert!(matches!(result, Err(AuthError::LoginChallengeExpired)));
        assert_eq!(
            auth.password_work.lock().unwrap().len(),
            usize::from(after_consume),
            "an admission returned after expiry must not start password work"
        );
        let row = store
            .inner
            .find_login_challenge(issued.challenge_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.attempts, 1);
        assert_eq!(
            row.is_consumed(),
            after_consume,
            "a consumed-but-expired attempt remains terminal"
        );
    }
}

#[tokio::test]
async fn cancellation_after_atomic_reservation_does_not_refund_the_attempt() {
    let auth = Arc::new(test_auth_service(Default::default(), Default::default()));
    let store = Arc::new(ControlledChallenges {
        pause_admission: Some(Notify::new()),
        ..Default::default()
    });
    let issued = auth
        .create_login_challenge(
            store.as_ref(),
            "fixture",
            LoginChallengeOptions {
                max_attempts: 1,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let task_auth = auth.clone();
    let task_store = store.clone();
    let id = issued.challenge_id;
    let code = issued.code.clone();
    let task = tokio::spawn(async move {
        task_auth
            .verify_login_challenge(task_store.as_ref(), id, &code)
            .await
    });
    store.pause_admission.as_ref().unwrap().notified().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(matches!(
        auth.verify_login_challenge(store.as_ref(), id, &issued.code)
            .await,
        Err(AuthError::LoginChallengeAttemptsExhausted)
    ));
    assert_eq!(
        store
            .inner
            .find_login_challenge(id)
            .await
            .unwrap()
            .unwrap()
            .attempts,
        1
    );
}

#[tokio::test]
async fn changed_definition_from_store_is_rejected_before_password_work() {
    let auth = test_auth_service(Default::default(), Default::default());
    let store = ControlledChallenges {
        corrupt_identity: true,
        ..Default::default()
    };
    let issued = auth
        .create_login_challenge(&store, "fixture", Default::default())
        .await
        .unwrap();
    auth.password_work.lock().unwrap().clear();
    assert!(matches!(
        auth.verify_login_challenge(&store, issued.challenge_id, &issued.code)
            .await,
        Err(AuthError::AuthServiceUnavailable)
    ));
    assert!(auth.password_work.lock().unwrap().is_empty());
}
