//! Abuse-control regressions: counting before verification, bounded memory
//! partitions, success refunds, account binding and option bounds.
use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use data_encoding::BASE32_NOPAD;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::{
    MemoryLoginChallengeStore, MemoryPasswordResetStore, MemoryRefreshTokenStore, MemoryUserStore,
    TEST_HS256_SECRET, metadata, stored_user,
};
use crate::prelude::*;

type Service = AuthService<MemoryUserStore, MemoryRefreshTokenStore>;

const RFC_SECRET: &[u8] = b"12345678901234567890";
const RFC_CODE_AT_59: &str = "94287082";

fn rfc_secret() -> String {
    BASE32_NOPAD.encode(RFC_SECRET)
}

fn rfc_options() -> TotpOptions {
    TotpOptions {
        digits: 8,
        period_seconds: 30,
        allowed_skew: 0,
    }
}

fn rfc_now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(59).unwrap()
}

fn lockout_policy() -> AuthRateLimitPolicy {
    AuthRateLimitPolicy {
        enabled: true,
        window: Duration::minutes(15),
        backoff_after_attempts: 1,
        max_attempts_before_lockout: 2,
        base_backoff: Duration::ZERO,
        max_backoff: Duration::ZERO,
        lockout_duration: Duration::minutes(5),
        state_ttl: Duration::hours(1),
    }
}

fn client(ip: &str) -> ClientMetadata {
    ClientMetadata {
        ip_address: Some(ip.to_string()),
        ..ClientMetadata::default()
    }
}

fn memory_store(capacity: usize) -> (MemoryAuthRateLimitStore, FixedClock) {
    let clock = FixedClock::new(OffsetDateTime::from_unix_timestamp(1_800_100_000).unwrap());
    (
        MemoryAuthRateLimitStore::with_capacity_and_clock(
            NonZeroUsize::new(capacity).unwrap(),
            Arc::new(clock.clone()),
        ),
        clock,
    )
}

fn service_with<S: AuthRateLimitStore + 'static>(
    users: MemoryUserStore,
    store: Arc<S>,
    clock: FixedClock,
    credential: AuthRateLimitPolicy,
) -> Service {
    let mut config = AuthConfig::new(TEST_HS256_SECRET);
    config.rate_limits.credential = credential;
    AuthService::new_with_rate_limit_store_and_clock(
        config,
        Arc::new(users),
        Arc::new(MemoryRefreshTokenStore::default()),
        store,
        Arc::new(clock),
    )
    .unwrap()
}

fn throttled(users: MemoryUserStore, policy: AuthRateLimitPolicy) -> Service {
    let (store, clock) = memory_store(1024);
    service_with(users, Arc::new(store), clock, policy)
}

/// Fills a one-entry store with an unrelated credential record.
async fn full_store_service(users: MemoryUserStore) -> Service {
    let (store, clock) = memory_store(1);
    let filler = AuthRateLimitKey {
        flow: AuthRateLimitFlow::PasswordLogin,
        bucket: AuthRateLimitBucket::Principal,
        value_hash: "filler".into(),
    };
    let now = clock.now();
    assert!(
        store
            .compare_exchange_auth_rate_limit_state(
                &filler,
                None,
                AuthRateLimitSnapshot {
                    revision: Uuid::new_v4(),
                    state: AuthRateLimitState {
                        key: filler.clone(),
                        attempts: 1,
                        first_attempt_at: now,
                        last_attempt_at: now,
                        backoff_until: None,
                        locked_until: None,
                        expires_at: now + Duration::hours(6),
                    },
                },
            )
            .await
            .unwrap()
    );
    let mut config = AuthConfig::new(TEST_HS256_SECRET);
    config.rate_limits = AuthRateLimitConfig::default();
    AuthService::new_with_rate_limit_store_and_clock(
        config,
        Arc::new(users),
        Arc::new(MemoryRefreshTokenStore::default()),
        Arc::new(store),
        Arc::new(clock),
    )
    .unwrap()
}

type ConsumedSteps = HashSet<(String, Option<String>, i64)>;

#[derive(Clone, Default)]
struct ReplayStore(Arc<Mutex<ConsumedSteps>>);

#[async_trait]
impl TotpReplayStore for ReplayStore {
    async fn consume_totp_step(
        &self,
        principal_id: &str,
        factor_id: Option<&str>,
        step: i64,
        _consumed_at: OffsetDateTime,
    ) -> crate::AuthResult<bool> {
        Ok(self.0.lock().unwrap().insert((
            principal_id.to_string(),
            factor_id.map(str::to_string),
            step,
        )))
    }
}

/// Yields before every store operation so concurrent callers interleave
/// between observing state and writing it.
#[derive(Clone)]
struct YieldingStore(MemoryAuthRateLimitStore);

#[async_trait]
impl AuthRateLimitStore for YieldingStore {
    async fn find_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
    ) -> crate::AuthResult<Option<AuthRateLimitSnapshot>> {
        tokio::task::yield_now().await;
        self.0.find_auth_rate_limit_state(key).await
    }
    async fn compare_exchange_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
        expected_revision: Option<Uuid>,
        replacement: AuthRateLimitSnapshot,
    ) -> crate::AuthResult<bool> {
        tokio::task::yield_now().await;
        self.0
            .compare_exchange_auth_rate_limit_state(key, expected_revision, replacement)
            .await
    }
    async fn clear_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
        expected_revision: Option<Uuid>,
    ) -> crate::AuthResult<bool> {
        tokio::task::yield_now().await;
        self.0
            .clear_auth_rate_limit_state(key, expected_revision)
            .await
    }
}

// Counting before verification: a store that cannot record fails closed.

#[tokio::test]
async fn full_store_does_not_make_password_login_an_uncounted_oracle() {
    for case in ["enabled", "disabled"] {
        let users = MemoryUserStore::default();
        let auth = full_store_service(users.clone()).await;
        let mut user = stored_user(&auth, "user-1", "alice@example.com", "password123");
        user.disabled = case == "disabled";
        users.insert(user);
        for _ in 0..20 {
            assert!(
                auth.login("alice@example.com", "wrong", metadata())
                    .await
                    .is_err()
            );
        }
        let correct = auth
            .login("alice@example.com", "password123", metadata())
            .await
            .unwrap_err();
        assert!(
            matches!(correct, AuthError::AuthServiceUnavailable),
            "{case}: a correct password must fail closed while failures cannot be recorded, got {correct:?}"
        );
        // Nothing was verified while the attempt could not be counted.
        assert!(auth.password_work.lock().unwrap().is_empty(), "{case}");
    }
    let auth = full_store_service(MemoryUserStore::default()).await;
    assert!(matches!(
        auth.login("missing@example.com", "wrong", metadata())
            .await
            .unwrap_err(),
        AuthError::AuthServiceUnavailable
    ));
    assert!(auth.password_work.lock().unwrap().is_empty());
}

#[tokio::test]
async fn full_store_does_not_make_totp_verification_an_uncounted_oracle() {
    let auth = full_store_service(MemoryUserStore::default()).await;
    let replay = ReplayStore::default();
    for n in 0..20 {
        let code = format!("{n:08}");
        assert!(
            auth.verify_totp_code_for_principal(
                "user-1",
                &rfc_secret(),
                &code,
                rfc_options(),
                rfc_now(),
                metadata(),
            )
            .await
            .is_err()
        );
        assert!(
            auth.verify_totp_code_with_replay_store_and_metadata(
                &replay,
                "user-1",
                Some("primary"),
                &rfc_secret(),
                &code,
                rfc_options(),
                rfc_now(),
                metadata(),
            )
            .await
            .is_err()
        );
    }
    assert!(matches!(
        auth.verify_totp_code_for_principal(
            "user-1",
            &rfc_secret(),
            RFC_CODE_AT_59,
            rfc_options(),
            rfc_now(),
            metadata(),
        )
        .await,
        Err(AuthError::AuthServiceUnavailable)
    ));
    assert!(matches!(
        auth.verify_totp_code_with_replay_store_and_metadata(
            &replay,
            "user-1",
            Some("primary"),
            &rfc_secret(),
            RFC_CODE_AT_59,
            rfc_options(),
            rfc_now(),
            metadata(),
        )
        .await,
        Err(AuthError::AuthServiceUnavailable)
    ));
    assert!(replay.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn full_store_does_not_verify_login_codes_uncounted() {
    let auth = full_store_service(MemoryUserStore::default()).await;
    let challenges = MemoryLoginChallengeStore::default();
    let issued = auth
        .create_login_challenge(&challenges, "alice@example.com", Default::default())
        .await
        .unwrap();
    assert!(matches!(
        auth.verify_login_challenge_with_metadata(
            &challenges,
            issued.challenge_id,
            &issued.code,
            metadata(),
        )
        .await,
        Err(AuthError::AuthServiceUnavailable)
    ));
    assert!(
        challenges
            .challenges
            .lock()
            .unwrap()
            .values()
            .all(|challenge| challenge.consumed_at.is_none())
    );
}

#[tokio::test]
async fn request_flows_cannot_exhaust_credential_capacity() {
    let (store, clock) = memory_store(4);
    let users = MemoryUserStore::default();
    let auth = service_with(
        users.clone(),
        Arc::new(store.clone()),
        clock,
        AuthRateLimitConfig::default().credential,
    );
    users.insert(stored_user(
        &auth,
        "user-1",
        "alice@example.com",
        "password123",
    ));
    for n in 0..8 {
        let _ = auth
            .should_process_password_reset_request(
                &format!("spray-{n}@example.invalid"),
                client(&format!("198.51.100.{n}")),
            )
            .await;
    }
    let error = auth
        .login("alice@example.com", "wrong", client("192.0.2.200"))
        .await
        .unwrap_err();
    assert!(
        matches!(error, AuthError::InvalidCredentials),
        "credential flows keep reserved capacity, got {error:?}"
    );
    auth.login("alice@example.com", "password123", client("192.0.2.200"))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_throttled_client_cannot_add_principal_request_state() {
    for flow in [
        AuthRateLimitFlow::PasswordResetRequest,
        AuthRateLimitFlow::LoginCodeRequest,
    ] {
        let (store, clock) = memory_store(64);
        let auth = AuthService::new_with_rate_limit_store_and_clock(
            AuthConfig::new(TEST_HS256_SECRET),
            Arc::new(MemoryUserStore::default()),
            Arc::new(MemoryRefreshTokenStore::default()),
            Arc::new(store.clone()),
            Arc::new(clock.clone()),
        )
        .unwrap();
        let request = |principal: String| {
            let auth = &auth;
            let flow = flow.clone();
            async move {
                match flow {
                    AuthRateLimitFlow::PasswordResetRequest => {
                        auth.should_process_password_reset_request(&principal, client("192.0.2.1"))
                            .await
                    }
                    _ => {
                        auth.should_process_login_code_request(&principal, client("192.0.2.1"))
                            .await
                    }
                }
            }
        };
        assert!(request("first@example.invalid".into()).await.unwrap());
        for n in 0..8 {
            assert!(
                !request(format!("victim-{n}@example.invalid"))
                    .await
                    .unwrap()
            );
            let victim = auth.rate_limit_keys(
                flow.clone(),
                Some(&format!("victim-{n}@example.invalid")),
                &ClientMetadata::default(),
            );
            assert!(store.get(&victim[0]).is_none(), "victim bucket untouched");
        }
        clock.advance_seconds(24 * 3600);
        assert_eq!(
            store.purge_expired().unwrap(),
            2,
            "denied requests must not leave principal state"
        );
    }
}

// A success refunds only its own client reservation.

#[tokio::test]
async fn successful_login_does_not_reset_the_shared_client_bucket() {
    let users = MemoryUserStore::default();
    let auth = throttled(users.clone(), lockout_policy());
    users.insert(stored_user(
        &auth,
        "attacker",
        "mallory@example.com",
        "password123",
    ));
    let ip = "192.0.2.90";
    assert!(matches!(
        auth.login("victim-a@example.com", "wrong", client(ip))
            .await
            .unwrap_err(),
        AuthError::InvalidCredentials
    ));
    auth.login("mallory@example.com", "password123", client(ip))
        .await
        .unwrap();
    // Second failure from this client: the client bucket must now lock.
    let _ = auth
        .login("victim-b@example.com", "wrong", client(ip))
        .await
        .unwrap_err();
    let third = auth
        .login("victim-c@example.com", "wrong", client(ip))
        .await
        .unwrap_err();
    assert!(
        matches!(third, AuthError::AuthLocked { .. }),
        "got {third:?}"
    );
}

#[tokio::test]
async fn successful_totp_does_not_reset_the_shared_client_bucket() {
    for replay in [false, true] {
        let auth = throttled(MemoryUserStore::default(), lockout_policy());
        let store = ReplayStore::default();
        let ip = "192.0.2.91";
        let verify = |principal: &'static str, code: &'static str| {
            let auth = &auth;
            let store = &store;
            async move {
                if replay {
                    auth.verify_totp_code_with_replay_store_and_metadata(
                        store,
                        principal,
                        None,
                        &rfc_secret(),
                        code,
                        rfc_options(),
                        rfc_now(),
                        client(ip),
                    )
                    .await
                } else {
                    auth.verify_totp_code_for_principal(
                        principal,
                        &rfc_secret(),
                        code,
                        rfc_options(),
                        rfc_now(),
                        client(ip),
                    )
                    .await
                }
            }
        };
        assert!(matches!(
            verify("victim-a", "00000000").await,
            Err(AuthError::InvalidTotpCode)
        ));
        verify("attacker", RFC_CODE_AT_59).await.unwrap();
        assert!(matches!(
            verify("victim-b", "00000000").await,
            Err(AuthError::InvalidTotpCode)
        ));
        let third = verify("victim-c", "00000000").await.unwrap_err();
        assert!(
            matches!(third, AuthError::AuthLocked { .. }),
            "replay={replay}: got {third:?}"
        );
    }
}

#[tokio::test]
async fn successful_login_code_does_not_reset_the_shared_client_bucket() {
    let auth = throttled(MemoryUserStore::default(), lockout_policy());
    let store = MemoryLoginChallengeStore::default();
    let ip = "192.0.2.92";
    let mut issue = Vec::new();
    for principal in ["victim-a", "attacker", "victim-b", "victim-c"] {
        issue.push(
            auth.create_login_challenge(&store, principal, Default::default())
                .await
                .unwrap(),
        );
    }
    assert!(matches!(
        auth.verify_login_challenge_with_metadata(&store, issue[0].challenge_id, "x", client(ip))
            .await,
        Err(AuthError::InvalidLoginCode)
    ));
    auth.verify_login_challenge_with_metadata(
        &store,
        issue[1].challenge_id,
        &issue[1].code,
        client(ip),
    )
    .await
    .unwrap();
    assert!(matches!(
        auth.verify_login_challenge_with_metadata(&store, issue[2].challenge_id, "x", client(ip))
            .await,
        Err(AuthError::InvalidLoginCode)
    ));
    let third = auth
        .verify_login_challenge_with_metadata(&store, issue[3].challenge_id, "x", client(ip))
        .await
        .unwrap_err();
    assert!(
        matches!(third, AuthError::AuthLocked { .. }),
        "got {third:?}"
    );
}

#[tokio::test]
async fn consumed_reset_token_does_not_reset_the_shared_client_bucket() {
    let auth = throttled(MemoryUserStore::default(), lockout_policy());
    let store = MemoryPasswordResetStore::default();
    let ip = "192.0.2.93";
    let own = auth
        .issue_password_reset_token_with_store(&store, "attacker", Duration::hours(1))
        .await
        .unwrap();
    assert!(matches!(
        auth.consume_password_reset_token_with_metadata(&store, "invalid", client(ip))
            .await,
        Err(AuthError::InvalidPasswordResetToken)
    ));
    auth.consume_password_reset_token_with_metadata(&store, &own.token, client(ip))
        .await
        .unwrap();
    assert!(matches!(
        auth.consume_password_reset_token_with_metadata(&store, "invalid", client(ip))
            .await,
        Err(AuthError::InvalidPasswordResetToken)
    ));
    let third = auth
        .consume_password_reset_token_with_metadata(&store, "invalid", client(ip))
        .await
        .unwrap_err();
    assert!(
        matches!(third, AuthError::AuthLocked { .. }),
        "got {third:?}"
    );
}

#[tokio::test]
async fn shared_client_successes_never_accumulate_client_state() {
    let users = MemoryUserStore::default();
    let auth = throttled(users.clone(), lockout_policy());
    for n in 0..5 {
        users.insert(stored_user(
            &auth,
            &format!("user-{n}"),
            &format!("user-{n}@example.com"),
            "password123",
        ));
    }
    let ip = "203.0.113.7";
    for round in 0..3 {
        for n in 0..5 {
            auth.login(&format!("user-{n}@example.com"), "password123", client(ip))
                .await
                .unwrap_or_else(|error| panic!("round {round} user {n}: {error:?}"));
        }
    }
    let client_key = auth
        .rate_limit_keys(AuthRateLimitFlow::PasswordLogin, None, &client(ip))
        .pop()
        .unwrap();
    assert!(
        auth.rate_limit_store
            .find_auth_rate_limit_state(&client_key)
            .await
            .unwrap()
            .is_none()
    );
    // One earlier failure from the same client survives later successes.
    let _ = auth
        .login("user-0@example.com", "wrong", client(ip))
        .await
        .unwrap_err();
    auth.login("user-1@example.com", "password123", client(ip))
        .await
        .unwrap();
    assert_eq!(
        auth.rate_limit_store
            .find_auth_rate_limit_state(&client_key)
            .await
            .unwrap()
            .unwrap()
            .state
            .attempts,
        1
    );
}

// Atomic pre-admission bounds concurrent bursts.

#[tokio::test]
async fn concurrent_totp_burst_cannot_overrun_the_lockout_budget() {
    const BURST: usize = 16;
    for replay in [false, true] {
        let (memory, clock) = memory_store(1024);
        let mut policy = lockout_policy();
        policy.backoff_after_attempts = 3;
        policy.max_attempts_before_lockout = 3;
        let auth = Arc::new(service_with(
            MemoryUserStore::default(),
            Arc::new(YieldingStore(memory)),
            clock,
            policy,
        ));
        let replay_store = ReplayStore::default();
        let mut tasks = Vec::new();
        for n in 0..BURST {
            let auth = auth.clone();
            let replay_store = replay_store.clone();
            tasks.push(tokio::spawn(async move {
                let code = format!("{n:08}");
                if replay {
                    auth.verify_totp_code_with_replay_store_and_metadata(
                        &replay_store,
                        "user-burst",
                        None,
                        &rfc_secret(),
                        &code,
                        rfc_options(),
                        rfc_now(),
                        ClientMetadata::default(),
                    )
                    .await
                } else {
                    auth.verify_totp_code_for_principal(
                        "user-burst",
                        &rfc_secret(),
                        &code,
                        rfc_options(),
                        rfc_now(),
                        ClientMetadata::default(),
                    )
                    .await
                }
            }));
        }
        let mut verified = 0;
        for task in tasks {
            match task.await.unwrap() {
                Err(AuthError::InvalidTotpCode) => verified += 1,
                Err(AuthError::AuthLocked { .. } | AuthError::AuthThrottled { .. }) => {}
                other => panic!("unexpected burst result {other:?}"),
            }
        }
        assert_eq!(verified, 3, "replay={replay}: only the budget is verified");
    }
}

#[tokio::test]
async fn concurrent_password_burst_cannot_overrun_the_lockout_budget() {
    const BURST: usize = 12;
    let (memory, clock) = memory_store(1024);
    let mut policy = lockout_policy();
    policy.backoff_after_attempts = 3;
    policy.max_attempts_before_lockout = 3;
    let users = MemoryUserStore::default();
    let auth = Arc::new(service_with(
        users.clone(),
        Arc::new(YieldingStore(memory)),
        clock,
        policy,
    ));
    users.insert(stored_user(
        &auth,
        "user-1",
        "burst@example.com",
        "password123",
    ));
    let mut tasks = Vec::new();
    for _ in 0..BURST {
        let auth = auth.clone();
        tasks.push(tokio::spawn(async move {
            auth.login("burst@example.com", "wrong", ClientMetadata::default())
                .await
        }));
    }
    for task in tasks {
        match task.await.unwrap() {
            Err(
                AuthError::InvalidCredentials
                | AuthError::AuthLocked { .. }
                | AuthError::AuthThrottled { .. },
            ) => {}
            other => panic!("unexpected burst result {other:?}"),
        }
    }
    assert_eq!(auth.password_work.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn concurrent_correct_logins_behind_one_address_are_never_throttled() {
    // Default thresholds: backoff after 3, lockout at 10 failures per client.
    const USERS: usize = 12;
    let (memory, clock) = memory_store(1024);
    let users = MemoryUserStore::default();
    let auth = Arc::new(service_with(
        users.clone(),
        Arc::new(YieldingStore(memory)),
        clock,
        AuthRateLimitConfig::default().credential,
    ));
    for n in 0..USERS {
        users.insert(stored_user(
            &auth,
            &format!("user-{n}"),
            &format!("nat-{n}@example.com"),
            "password123",
        ));
    }
    let mut tasks = Vec::new();
    for n in 0..USERS {
        let auth = auth.clone();
        tasks.push(tokio::spawn(async move {
            auth.login(&format!("nat-{n}@example.com"), "password123", metadata())
                .await
        }));
    }
    for task in tasks {
        if let Err(error) = task.await.unwrap() {
            panic!("a correct login behind a shared address failed: {error:?}");
        }
    }
    // Failures from that address are still counted and still throttle it.
    for n in 0..3 {
        let _ = auth
            .login(&format!("nat-{n}@example.com"), "wrong", metadata())
            .await;
    }
    assert!(matches!(
        auth.login("nat-5@example.com", "password123", metadata())
            .await,
        Err(AuthError::AuthThrottled { .. })
    ));
}

// Principal counting binds to the resolved account.

/// A host store whose lookup ignores `+tag` aliases.
#[derive(Clone, Default)]
struct AliasUserStore(MemoryUserStore);

#[async_trait]
impl UserStore for AliasUserStore {
    async fn find_user_by_principal(
        &self,
        principal: &str,
    ) -> crate::AuthResult<Option<StoredUser>> {
        let canonical = match principal.split_once('@') {
            Some((local, domain)) => {
                format!("{}@{domain}", local.split('+').next().unwrap_or(local))
            }
            None => principal.to_string(),
        };
        self.0.find_user_by_principal(&canonical).await
    }
    async fn find_user_by_id(&self, user_id: &str) -> crate::AuthResult<Option<StoredUser>> {
        self.0.find_user_by_id(user_id).await
    }
}

#[tokio::test]
async fn principal_aliases_share_one_account_budget() {
    let users = MemoryUserStore::default();
    let hasher = throttled(users.clone(), lockout_policy());
    users.insert(stored_user(
        &hasher,
        "user-1",
        "alice@example.com",
        "password123",
    ));
    let mut config = AuthConfig::new(TEST_HS256_SECRET);
    config.rate_limits.credential = lockout_policy();
    let auth = AuthService::new_with_rate_limit_store(
        config,
        Arc::new(AliasUserStore(users)),
        Arc::new(MemoryRefreshTokenStore::default()),
        Arc::new(MemoryAuthRateLimitStore::default()),
    )
    .unwrap();
    for alias in ["alice+1@example.com", "alice+2@example.com"] {
        assert!(matches!(
            auth.login(alias, "wrong", ClientMetadata::default())
                .await
                .unwrap_err(),
            AuthError::InvalidCredentials
        ));
    }
    let third = auth
        .login(
            "alice+3@example.com",
            "password123",
            ClientMetadata::default(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(third, AuthError::AuthLocked { .. }),
        "got {third:?}"
    );
    // Unknown principals keep their own counted budget.
    for _ in 0..2 {
        let _ = auth
            .login("nobody+1@example.com", "wrong", ClientMetadata::default())
            .await;
    }
    assert!(matches!(
        auth.login("nobody+1@example.com", "wrong", ClientMetadata::default())
            .await
            .unwrap_err(),
        AuthError::AuthLocked { .. }
    ));
}

// Account state is revealed only with proof of the password.

const DUMMY_HASH_PREFIX: &str = "$argon2id$v=19$m=19456,t=2,p=1$YWdxbC1hdXRoLWR1bW15LXNsdA$";

#[tokio::test]
async fn disabled_state_requires_the_correct_password() {
    let users = MemoryUserStore::default();
    let mut policy = lockout_policy();
    policy.backoff_after_attempts = 10;
    policy.max_attempts_before_lockout = 10;
    let auth = throttled(users.clone(), policy);
    let mut user = stored_user(&auth, "user-1", "alice@example.com", "password123");
    user.disabled = true;
    users.insert(user.clone());
    assert!(matches!(
        auth.login("alice@example.com", "wrong", client("192.0.2.94"))
            .await
            .unwrap_err(),
        AuthError::InvalidCredentials
    ));
    assert!(matches!(
        auth.login("alice@example.com", "password123", client("192.0.2.94"))
            .await
            .unwrap_err(),
        AuthError::UserDisabled
    ));
    // Both attempts did one verification against the real hash and both count.
    assert_eq!(
        *auth.password_work.lock().unwrap(),
        vec![user.password_hash.clone(), user.password_hash.clone()]
    );
    let client_key = auth
        .rate_limit_keys(
            AuthRateLimitFlow::PasswordLogin,
            None,
            &client("192.0.2.94"),
        )
        .pop()
        .unwrap();
    assert_eq!(
        auth.rate_limit_store
            .find_auth_rate_limit_state(&client_key)
            .await
            .unwrap()
            .unwrap()
            .state
            .attempts,
        2
    );
}

#[tokio::test]
async fn unverifiable_stored_hashes_do_dummy_work_and_count() {
    for (index, stored) in [
        "corrupt",
        "$pbkdf2-sha256$i=1000$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA",
        "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaGhhc2hoYXNoaGFzaA",
    ]
    .into_iter()
    .enumerate()
    {
        for disabled in [false, true] {
            let users = MemoryUserStore::default();
            let mut policy = lockout_policy();
            policy.backoff_after_attempts = 10;
            policy.max_attempts_before_lockout = 10;
            let auth = throttled(users.clone(), policy);
            let mut user = stored_user(&auth, "user-1", "alice@example.com", "password123");
            user.password_hash = stored.into();
            user.disabled = disabled;
            users.insert(user);
            let ip = format!("192.0.2.{}", 100 + index);
            let error = auth
                .login("alice@example.com", "password123", client(&ip))
                .await
                .unwrap_err();
            assert!(
                matches!(error, AuthError::InvalidCredentials),
                "{stored} disabled={disabled}: got {error:?}"
            );
            let work = auth.password_work.lock().unwrap().clone();
            assert_eq!(work.len(), 1, "{stored}: one verification");
            assert!(
                work[0].starts_with(DUMMY_HASH_PREFIX),
                "{stored}: dummy work"
            );
            let client_key = auth
                .rate_limit_keys(AuthRateLimitFlow::PasswordLogin, None, &client(&ip))
                .pop()
                .unwrap();
            assert_eq!(
                auth.rate_limit_store
                    .find_auth_rate_limit_state(&client_key)
                    .await
                    .unwrap()
                    .unwrap()
                    .state
                    .attempts,
                1,
                "{stored}: counted"
            );
        }
    }
}

// Option and secret bounds.

#[tokio::test]
async fn login_challenge_options_are_bounded() {
    let auth = throttled(MemoryUserStore::default(), lockout_policy());
    let store = MemoryLoginChallengeStore::default();
    for (code_length, max_attempts, ok) in [
        (0, 5, false),
        (1, 5, false),
        (5, 5, false),
        (6, 5, true),
        (12, 5, true),
        (13, 5, false),
        (6, 0, false),
        (6, 1, true),
        (6, 10, true),
        (6, 11, false),
        (6, u32::MAX, false),
    ] {
        let result = auth
            .create_login_challenge(
                &store,
                "alice@example.com",
                LoginChallengeOptions {
                    code_length,
                    max_attempts,
                    ..Default::default()
                },
            )
            .await;
        assert_eq!(
            result.is_ok(),
            ok,
            "code_length={code_length} max_attempts={max_attempts}"
        );
        if !ok {
            assert!(matches!(result, Err(AuthError::InvalidConfiguration(_))));
        }
    }
}

#[tokio::test]
async fn totp_options_and_secrets_are_bounded() {
    let auth = throttled(MemoryUserStore::default(), lockout_policy());
    for (options, ok) in [
        (rfc_options(), true),
        (TotpOptions::default(), true),
        (
            TotpOptions {
                allowed_skew: 2,
                ..TotpOptions::default()
            },
            true,
        ),
        (
            TotpOptions {
                allowed_skew: 3,
                ..TotpOptions::default()
            },
            false,
        ),
        (
            TotpOptions {
                allowed_skew: u64::MAX,
                ..TotpOptions::default()
            },
            false,
        ),
        (
            TotpOptions {
                period_seconds: 14,
                ..TotpOptions::default()
            },
            false,
        ),
        (
            TotpOptions {
                period_seconds: 300,
                ..TotpOptions::default()
            },
            true,
        ),
        (
            TotpOptions {
                period_seconds: 301,
                ..TotpOptions::default()
            },
            false,
        ),
    ] {
        let result = auth.verify_totp_code(&rfc_secret(), "00000000", options.clone(), rfc_now());
        if ok {
            assert!(
                matches!(result, Err(AuthError::InvalidTotpCode)),
                "{options:?}"
            );
        } else {
            assert!(
                matches!(result, Err(AuthError::InvalidConfiguration(_))),
                "{options:?}"
            );
        }
    }

    for (bytes, ok) in [
        (10, false),
        (19, false),
        (20, true),
        (64, true),
        (65, false),
    ] {
        assert_eq!(
            auth.generate_totp_secret(bytes).is_ok(),
            ok,
            "{bytes} bytes"
        );
    }
    for bytes in [0usize, 10, 15] {
        let short = BASE32_NOPAD.encode(&RFC_SECRET[..bytes]);
        assert!(
            matches!(
                auth.verify_totp_code(&short, "00000000", rfc_options(), rfc_now()),
                Err(AuthError::InvalidTotpSecret)
            ),
            "{bytes}-byte secrets are rejected"
        );
        assert!(matches!(
            auth.verify_totp_code_for_principal(
                "user-1",
                &short,
                "00000000",
                rfc_options(),
                rfc_now(),
                ClientMetadata::default(),
            )
            .await,
            Err(AuthError::InvalidTotpSecret)
        ));
        let secret = TotpSecret {
            raw_secret: RFC_SECRET[..bytes].to_vec(),
            base32_secret: short,
        };
        assert!(
            auth.build_totp_provisioning(&secret, "agql-auth", "alice", TotpOptions::default())
                .is_err()
        );
    }
    let sixteen = BASE32_NOPAD.encode(&RFC_SECRET[..16]);
    assert!(matches!(
        auth.verify_totp_code(&sixteen, "00000000", rfc_options(), rfc_now()),
        Err(AuthError::InvalidTotpCode)
    ));
}
