//! Refresh reuse grace: behavior, boundaries, races, widening and theft cost.
//!
//! The `*_contract` functions are generic so that the same assertions run here on
//! the in-memory store and in `consumer_refresh_store` on real transactions.
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::{MemoryRefreshTokenStore, MemoryUserStore, TEST_HS256_SECRET, metadata};
use crate::prelude::*;
use crate::util::hash_refresh_token;

const WINDOW_SECONDS: i64 = 10;
const USER_ID: &str = "user-1";
const SEED_TOKEN: &str = "seed-token-a";

fn grant(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn seed_record(raw: &str, family: Uuid, session: Uuid, now: OffsetDateTime) -> StoredRefreshToken {
    StoredRefreshToken {
        id: Uuid::new_v4(),
        user_id: USER_ID.to_string(),
        session_id: session,
        session_family_id: family,
        grant_source: RefreshGrantSource::StoredUser,
        authorization_roles: vec![],
        roles: grant(&["member", "editor"]),
        scopes: grant(&["records.read", "records.write"]),
        session: SessionContext::default(),
        refreshable_metadata: None,
        token_hash: hash_refresh_token(raw),
        created_at: now,
        expires_at: now + Duration::days(30),
        last_used_at: None,
        revoked_at: None,
        replaced_by_token_id: None,
        user_agent: None,
        ip_address: None,
    }
}

fn stored_user(roles: &[&str], scopes: &[&str], disabled: bool) -> StoredUser {
    StoredUser {
        id: USER_ID.to_string(),
        principal: "alice@example.com".to_string(),
        password_hash: "unused".to_string(),
        roles: grant(roles),
        scopes: grant(scopes),
        disabled,
    }
}

pub(super) struct Harness<S> {
    pub(super) auth: Arc<AuthService<MemoryUserStore, S>>,
    pub(super) store: Arc<S>,
    pub(super) users: MemoryUserStore,
    pub(super) clock: FixedClock,
    pub(super) family: Uuid,
}

impl<S: RefreshTokenStore + 'static> Harness<S> {
    pub(super) async fn new(store: Arc<S>) -> Self {
        Self::with(store, Some(WINDOW_SECONDS), |auth| auth).await
    }

    async fn with(
        store: Arc<S>,
        window: Option<i64>,
        configure: impl FnOnce(AuthService<MemoryUserStore, S>) -> AuthService<MemoryUserStore, S>,
    ) -> Self {
        let users = MemoryUserStore::default();
        users.insert(stored_user(
            &["member", "editor"],
            &["records.read", "records.write"],
            false,
        ));
        let clock = FixedClock::new(OffsetDateTime::now_utc());
        let mut auth = AuthService::new(
            AuthConfig::new(TEST_HS256_SECRET),
            Arc::new(users.clone()),
            store.clone(),
        )
        .unwrap()
        .with_refresh_rotation_clock(Arc::new(clock.clone()));
        if let Some(window) = window {
            auth = auth
                .with_refresh_reuse_grace(Duration::seconds(window))
                .unwrap();
        }
        let auth = configure(auth);
        let family = Uuid::new_v4();
        store
            .insert_refresh_token(seed_record(
                SEED_TOKEN,
                family,
                Uuid::new_v4(),
                clock.now() - Duration::minutes(1),
            ))
            .await
            .unwrap();
        Self {
            auth: Arc::new(auth),
            store,
            users,
            clock,
            family,
        }
    }

    async fn refresh(&self, raw: &str) -> crate::AuthResult<AuthPayload> {
        self.auth.refresh(raw, metadata()).await
    }

    async fn rotated(&self, raw: &str) -> String {
        self.refresh(raw).await.unwrap().refresh_token
    }

    async fn record(&self, raw: &str) -> StoredRefreshToken {
        self.store
            .find_refresh_token_by_hash(&hash_refresh_token(raw))
            .await
            .unwrap()
            .unwrap()
    }

    async fn live_count(&self) -> usize {
        self.store
            .find_live_refresh_tokens_in_family(self.family)
            .await
            .unwrap()
            .unwrap()
            .len()
    }

    /// Asserts that `raw` is the family's one live token.
    async fn assert_only_live(&self, raw: &str) {
        let live = self
            .store
            .find_live_refresh_tokens_in_family(self.family)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(live.len(), 1, "a family keeps exactly one live token");
        assert_eq!(live[0].token_hash, hash_refresh_token(raw));
    }

    async fn assert_replay_ends_family(&self, raw: &str) {
        assert!(matches!(
            self.refresh(raw).await,
            Err(AuthError::RefreshTokenReplayDetected)
        ));
        assert_eq!(self.live_count().await, 0, "replay revokes the family");
    }
}

fn memory_harness() -> impl Future<Output = Harness<MemoryRefreshTokenStore>> {
    Harness::new(Arc::new(MemoryRefreshTokenStore::default()))
}

// Behavior that a window must not change.

#[tokio::test]
async fn off_by_default_reuse_is_replay_and_the_new_operation_is_never_called() {
    let store = Arc::new(ScriptedStore::default());
    let h = Harness::with(store.clone(), None, |auth| auth).await;
    let next = h.rotated(SEED_TOKEN).await;

    assert!(matches!(
        h.refresh(SEED_TOKEN).await,
        Err(AuthError::RefreshTokenReplayDetected)
    ));
    assert_eq!(store.find_live_calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.inner.family_revocations.lock().unwrap().len(), 1);
    assert!(h.record(&next).await.is_revoked());
}

#[tokio::test]
async fn off_by_default_a_lost_race_is_replay_and_logout_of_a_revoked_token_still_revokes() {
    let store = Arc::new(ScriptedStore::default());
    *store.before_first_rotate.lock().unwrap() = BeforeRotate::CompetitorRotates(0);
    let h = Harness::with(store.clone(), None, |auth| auth).await;

    assert!(matches!(
        h.refresh(SEED_TOKEN).await,
        Err(AuthError::RefreshTokenReplayDetected)
    ));
    assert_eq!(store.find_live_calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.inner.family_revocations.lock().unwrap().len(), 1);

    h.auth.logout(SEED_TOKEN, false).await.unwrap();
    assert_eq!(store.revoke_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_store_without_the_operation_behaves_as_off() {
    let store = Arc::new(ScriptedStore {
        grace_support: false,
        ..Default::default()
    });
    let h = Harness::with(store.clone(), Some(WINDOW_SECONDS), |auth| auth).await;
    let next = h.rotated(SEED_TOKEN).await;

    assert!(matches!(
        h.refresh(SEED_TOKEN).await,
        Err(AuthError::RefreshTokenReplayDetected)
    ));
    assert_eq!(store.inner.family_revocations.lock().unwrap().len(), 1);
    assert!(h.record(&next).await.is_revoked());
}

#[tokio::test]
async fn a_store_without_the_operation_treats_a_lost_race_as_replay() {
    let store = Arc::new(ScriptedStore {
        grace_support: false,
        ..Default::default()
    });
    *store.before_first_rotate.lock().unwrap() = BeforeRotate::CompetitorRotates(0);
    let h = Harness::with(store.clone(), Some(WINDOW_SECONDS), |auth| auth).await;

    assert!(matches!(
        h.refresh(SEED_TOKEN).await,
        Err(AuthError::RefreshTokenReplayDetected)
    ));
    assert_eq!(store.inner.family_revocations.lock().unwrap().len(), 1);
}

// Inside the window.

pub(super) async fn sequential_contract<S: RefreshTokenStore + 'static>(store: Arc<S>) {
    let h = Harness::new(store).await;
    h.assert_only_live(SEED_TOKEN).await;

    let second = h.rotated(SEED_TOKEN).await;
    h.assert_only_live(&second).await;
    let superseded = h.record(SEED_TOKEN).await;

    h.clock.advance_seconds(3);
    let reused = h.refresh(SEED_TOKEN).await.unwrap();
    h.assert_only_live(&reused.refresh_token).await;
    assert_eq!(h.record(&second).await.revoked_at, Some(h.clock.now()));
    assert_eq!(
        h.record(&second).await.replaced_by_token_id,
        Some(h.record(&reused.refresh_token).await.id),
        "the reuse is the newest token's successor, not a branch"
    );
    let presented = h.record(SEED_TOKEN).await;
    assert_eq!(presented.revoked_at, superseded.revoked_at);
    assert_eq!(
        presented.replaced_by_token_id,
        superseded.replaced_by_token_id
    );

    let authenticated = h
        .auth
        .authenticate_access_token(&reused.access_token)
        .unwrap();
    assert_eq!(authenticated.user_id, USER_ID);
    assert_eq!(authenticated.session_id, presented.session_id);

    let last = h.rotated(&reused.refresh_token).await;
    h.assert_only_live(&last).await;

    h.clock.advance_seconds(WINDOW_SECONDS);
    h.assert_replay_ends_family(SEED_TOKEN).await;
    assert!(h.record(&last).await.is_revoked());
}

#[tokio::test]
async fn sequential_reuse_succeeds_and_keeps_one_live_token() {
    sequential_contract(Arc::new(MemoryRefreshTokenStore::default())).await;
}

#[tokio::test]
async fn the_previous_newest_token_is_eligible_only_for_its_own_window() {
    let h = memory_harness().await;
    let second = h.rotated(SEED_TOKEN).await;
    h.clock.advance_seconds(4);
    let third = h.rotated(SEED_TOKEN).await;
    h.assert_only_live(&third).await;

    // The seed token's window has ended, and the second's runs from the reuse.
    h.clock.advance_seconds(WINDOW_SECONDS - 1);
    let fourth = h.rotated(&second).await;
    h.assert_only_live(&fourth).await;

    h.clock.advance_seconds(1);
    h.assert_replay_ends_family(&second).await;
}

#[tokio::test]
async fn the_window_is_exclusive_at_its_boundary() {
    let h = memory_harness().await;
    let _second = h.rotated(SEED_TOKEN).await;
    let start = h.clock.now();

    h.clock
        .set(start + Duration::seconds(WINDOW_SECONDS) - Duration::milliseconds(1));
    let inside = h.rotated(SEED_TOKEN).await;
    h.assert_only_live(&inside).await;

    h.clock.set(start + Duration::seconds(WINDOW_SECONDS));
    h.assert_replay_ends_family(SEED_TOKEN).await;

    let h = memory_harness().await;
    let _second = h.rotated(SEED_TOKEN).await;
    h.clock
        .set(h.clock.now() + Duration::seconds(WINDOW_SECONDS) + Duration::milliseconds(1));
    h.assert_replay_ends_family(SEED_TOKEN).await;
}

#[tokio::test]
async fn a_revocation_time_ahead_of_this_clock_is_bounded_by_the_same_window() {
    let h = memory_harness().await;
    let _second = h.rotated(SEED_TOKEN).await;
    let revoked_at = h.clock.now();

    h.clock
        .set(revoked_at - Duration::seconds(WINDOW_SECONDS) + Duration::milliseconds(1));
    let inside = h.rotated(SEED_TOKEN).await;
    h.assert_only_live(&inside).await;

    h.clock.set(revoked_at - Duration::seconds(WINDOW_SECONDS));
    h.assert_replay_ends_family(SEED_TOKEN).await;
}

#[tokio::test]
async fn a_chain_of_reuses_cannot_extend_an_old_token_past_its_window() {
    let h = memory_harness().await;
    let _second = h.rotated(SEED_TOKEN).await;
    let revoked_at = h.record(SEED_TOKEN).await.revoked_at;

    for _ in 0..WINDOW_SECONDS - 1 {
        h.clock.advance_seconds(1);
        let reused = h.rotated(SEED_TOKEN).await;
        h.assert_only_live(&reused).await;
        assert_eq!(h.record(SEED_TOKEN).await.revoked_at, revoked_at);
    }

    h.clock.advance_seconds(1);
    h.assert_replay_ends_family(SEED_TOKEN).await;
}

#[tokio::test]
async fn logout_of_a_superseded_token_cannot_renew_its_window() {
    let store = Arc::new(ScriptedStore::default());
    let h = Harness::new(store.clone()).await;
    let second = h.rotated(SEED_TOKEN).await;
    let before = h.record(SEED_TOKEN).await;

    h.clock.advance_seconds(WINDOW_SECONDS - 1);
    h.auth.logout(SEED_TOKEN, false).await.unwrap();
    assert_eq!(store.revoke_calls.load(Ordering::SeqCst), 0);
    let after = h.record(SEED_TOKEN).await;
    assert_eq!(after.revoked_at, before.revoked_at);
    h.assert_only_live(&second).await;

    h.clock.advance_seconds(1);
    h.assert_replay_ends_family(SEED_TOKEN).await;
}

// Revoked families and ineligible tokens.

#[tokio::test]
async fn a_revoked_family_gets_no_grace_inside_the_window() {
    for reason in [
        RefreshTokenRevocationReason::Logout,
        RefreshTokenRevocationReason::AdminRevoked,
        RefreshTokenRevocationReason::ReplayDetected,
    ] {
        let h = memory_harness().await;
        let _second = h.rotated(SEED_TOKEN).await;
        h.store
            .revoke_refresh_token_family(h.family, h.clock.now(), reason)
            .await
            .unwrap();

        // The record still names its replacement and has a recent revoked_at.
        let record = h.record(SEED_TOKEN).await;
        assert!(record.replaced_by_token_id.is_some());
        assert_eq!(record.revoked_at, Some(h.clock.now()));

        h.clock.advance_seconds(1);
        h.assert_replay_ends_family(SEED_TOKEN).await;
        assert_eq!(h.store.family_revocations.lock().unwrap().len(), 2);
    }
}

#[tokio::test]
async fn logging_out_the_newest_token_ends_the_grace_of_older_tokens() {
    let h = memory_harness().await;
    let second = h.rotated(SEED_TOKEN).await;
    h.auth.logout(&second, false).await.unwrap();

    h.assert_replay_ends_family(SEED_TOKEN).await;
}

#[tokio::test]
async fn a_token_revoked_without_a_replacement_gets_no_grace() {
    let h = memory_harness().await;
    let seed = h.record(SEED_TOKEN).await;
    let other = seed_record("other", h.family, seed.session_id, h.clock.now());
    h.store.insert_refresh_token(other).await.unwrap();
    h.store
        .revoke_refresh_token(
            seed.id,
            h.clock.now(),
            None,
            RefreshTokenRevocationReason::AdminRevoked,
        )
        .await
        .unwrap();

    h.assert_replay_ends_family(SEED_TOKEN).await;
}

#[tokio::test]
async fn an_expired_presented_token_gets_no_grace() {
    let h = memory_harness().await;
    let _second = h.rotated(SEED_TOKEN).await;
    let seed_id = h.record(SEED_TOKEN).await.id;
    h.store
        .tokens_by_id
        .lock()
        .unwrap()
        .get_mut(&seed_id)
        .unwrap()
        .expires_at = h.clock.now();

    h.assert_replay_ends_family(SEED_TOKEN).await;
}

#[tokio::test]
async fn an_expired_newest_token_gets_no_grace() {
    let h = memory_harness().await;
    let second = h.rotated(SEED_TOKEN).await;
    let second_id = h.record(&second).await.id;
    h.store
        .tokens_by_id
        .lock()
        .unwrap()
        .get_mut(&second_id)
        .unwrap()
        .expires_at = h.clock.now();

    h.assert_replay_ends_family(SEED_TOKEN).await;
}

#[tokio::test]
async fn an_inconsistent_store_answer_fails_closed() {
    for answer in [Inconsistent::TwoLive, Inconsistent::OtherSession] {
        let store = Arc::new(ScriptedStore {
            inconsistent: Some(answer),
            ..Default::default()
        });
        let h = Harness::new(store.clone()).await;
        let _second = h.rotated(SEED_TOKEN).await;

        assert!(matches!(
            h.refresh(SEED_TOKEN).await,
            Err(AuthError::RefreshTokenReplayDetected)
        ));
        assert_eq!(store.inner.family_revocations.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn a_store_error_during_the_read_revokes_nothing() {
    let store = Arc::new(ScriptedStore {
        find_live_fails: true,
        ..Default::default()
    });
    let h = Harness::new(store.clone()).await;
    let second = h.rotated(SEED_TOKEN).await;

    assert!(matches!(
        h.refresh(SEED_TOKEN).await,
        Err(AuthError::Store(_))
    ));
    assert!(store.inner.family_revocations.lock().unwrap().is_empty());
    assert!(!h.record(&second).await.is_revoked());
}

// Losing the rotation race.

#[tokio::test]
async fn losing_the_rotation_race_in_the_window_succeeds_for_both_callers() {
    let store = Arc::new(ScriptedStore::default());
    *store.before_first_rotate.lock().unwrap() = BeforeRotate::CompetitorRotates(0);
    let h = Harness::new(store.clone()).await;

    let payload = h.refresh(SEED_TOKEN).await.unwrap();

    h.assert_only_live(&payload.refresh_token).await;
    assert!(h.record(COMPETITOR_TOKEN).await.is_revoked());
    assert!(store.inner.family_revocations.lock().unwrap().is_empty());
}

#[tokio::test]
async fn losing_the_rotation_race_outside_the_window_is_replay() {
    let store = Arc::new(ScriptedStore::default());
    *store.before_first_rotate.lock().unwrap() = BeforeRotate::CompetitorRotates(WINDOW_SECONDS);
    let h = Harness::new(store.clone()).await;

    h.assert_replay_ends_family(SEED_TOKEN).await;
}

#[tokio::test]
async fn losing_the_rotation_race_to_a_family_revocation_is_replay() {
    let store = Arc::new(ScriptedStore::default());
    *store.before_first_rotate.lock().unwrap() = BeforeRotate::FamilyRevoked;
    let h = Harness::new(store.clone()).await;

    h.assert_replay_ends_family(SEED_TOKEN).await;
}

#[tokio::test]
async fn contention_that_outlasts_the_retries_is_an_error_and_revokes_nothing() {
    let store = Arc::new(ScriptedStore::default());
    let h = Harness::new(store.clone()).await;
    let second = h.rotated(SEED_TOKEN).await;
    store.rotate_conflicts.store(true, Ordering::SeqCst);

    assert!(matches!(
        h.refresh(SEED_TOKEN).await,
        Err(AuthError::Store(_))
    ));
    assert!(store.find_live_calls.load(Ordering::SeqCst) > 1);
    assert!(store.inner.family_revocations.lock().unwrap().is_empty());
    h.assert_only_live(&second).await;
}

/// Runs racing refreshes, then checks that all succeeded with one live token left.
async fn race<S: RefreshTokenStore + 'static>(h: &Harness<S>, tokens: Vec<String>) {
    let tasks: Vec<_> = tokens
        .into_iter()
        .map(|raw| {
            let auth = h.auth.clone();
            tokio::spawn(async move { auth.refresh(&raw, metadata()).await })
        })
        .collect();
    let mut issued = Vec::new();
    for task in tasks {
        issued.push(task.await.unwrap().unwrap().refresh_token);
    }
    assert_eq!(h.live_count().await, 1, "a family keeps one live token");
    let mut live = 0;
    for raw in &issued {
        if !h.record(raw).await.is_revoked() {
            live += 1;
        }
    }
    assert_eq!(live, 1, "exactly one issued token is the live one");
}

pub(super) async fn double_refresh_contract<S: RefreshTokenStore + 'static>(store: Arc<S>) {
    let h = Harness::new(store).await;
    race(&h, vec![SEED_TOKEN.to_string(); 2]).await;
}

pub(super) async fn racing_reuses_contract<S: RefreshTokenStore + 'static>(store: Arc<S>) {
    let h = Harness::new(store).await;
    let _second = h.rotated(SEED_TOKEN).await;
    race(&h, vec![SEED_TOKEN.to_string(); 8]).await;
}

pub(super) async fn racing_different_tokens_contract<S: RefreshTokenStore + 'static>(
    store: Arc<S>,
) {
    let h = Harness::new(store).await;
    let second = h.rotated(SEED_TOKEN).await;
    let third = h.rotated(&second).await;
    let mut tokens = vec![SEED_TOKEN.to_string(); 3];
    tokens.extend(vec![second; 3]);
    tokens.extend(vec![third; 2]);
    race(&h, tokens).await;
}

pub(super) async fn reuse_races_family_revocation_contract<S: RefreshTokenStore + 'static>(
    store: Arc<S>,
) {
    let h = Harness::new(store).await;
    let second = h.rotated(SEED_TOKEN).await;
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let auth = h.auth.clone();
        tasks.push(tokio::spawn(async move {
            auth.refresh(SEED_TOKEN, metadata()).await.map(|_| ())
        }));
    }
    let auth = h.auth.clone();
    tasks.push(tokio::spawn(
        async move { auth.logout(&second, true).await },
    ));
    for task in tasks {
        match task.await.unwrap() {
            Ok(()) | Err(AuthError::RefreshTokenReplayDetected) => {}
            Err(error) => panic!("unexpected error: {error}"),
        }
    }
    assert_eq!(
        h.live_count().await,
        0,
        "a replacement committed during sign-out must not survive it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_concurrent_double_refresh_succeeds_for_both_callers() {
    double_refresh_contract(Arc::new(MemoryRefreshTokenStore::default())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn racing_reuses_of_one_token_leave_one_live_token() {
    racing_reuses_contract(Arc::new(MemoryRefreshTokenStore::default())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn racing_reuses_of_different_tokens_leave_one_live_token() {
    racing_different_tokens_contract(Arc::new(MemoryRefreshTokenStore::default())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reuse_racing_a_family_revocation_leaves_no_live_token() {
    reuse_races_family_revocation_contract(Arc::new(MemoryRefreshTokenStore::default())).await;
}

// No widening.

#[tokio::test]
async fn a_disabled_user_is_refused_inside_the_window_and_nothing_changes() {
    let h = memory_harness().await;
    let second = h.rotated(SEED_TOKEN).await;
    h.users.insert(stored_user(&["member"], &[], true));

    assert!(matches!(
        h.refresh(SEED_TOKEN).await,
        Err(AuthError::UserDisabled)
    ));
    h.assert_only_live(&second).await;
    assert!(h.store.family_revocations.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_removed_user_is_refused_inside_the_window() {
    let h = memory_harness().await;
    let second = h.rotated(SEED_TOKEN).await;
    h.users.remove(USER_ID);

    assert!(matches!(
        h.refresh(SEED_TOKEN).await,
        Err(AuthError::InvalidRefreshToken)
    ));
    h.assert_only_live(&second).await;
}

#[tokio::test]
async fn grants_narrowed_during_the_window_apply_to_the_reuse() {
    let h = memory_harness().await;
    let _second = h.rotated(SEED_TOKEN).await;
    h.users
        .insert(stored_user(&["member"], &["records.read"], false));

    let reused = h.refresh(SEED_TOKEN).await.unwrap();

    assert_eq!(reused.user.roles, grant(&["member"]));
    assert_eq!(reused.user.scopes, grant(&["records.read"]));
    let record = h.record(&reused.refresh_token).await;
    assert_eq!(record.roles, grant(&["member"]));
    assert_eq!(record.scopes, grant(&["records.read"]));
}

#[derive(Default)]
struct FixedRoles(Mutex<Vec<String>>);

#[async_trait]
impl AdditionalTokenRolesProvider for FixedRoles {
    async fn additional_token_roles(&self, _: &AuthUser) -> crate::AuthResult<Vec<String>> {
        Ok(self.0.lock().unwrap().clone())
    }
}

#[tokio::test]
async fn a_reuse_cannot_regain_grants_the_newest_token_already_lost() {
    let provider = Arc::new(FixedRoles::default());
    let store = Arc::new(MemoryRefreshTokenStore::default());
    let h = Harness::with(store, Some(WINDOW_SECONDS), {
        let provider = provider.clone();
        |auth| auth.with_additional_token_roles_provider(provider)
    })
    .await;
    let seed_id = h.record(SEED_TOKEN).await.id;
    h.store
        .tokens_by_id
        .lock()
        .unwrap()
        .get_mut(&seed_id)
        .unwrap()
        .authorization_roles = grant(&["reader", "auditor"]);

    // Everything is narrowed at the first rotation, then restored.
    h.users
        .insert(stored_user(&["member"], &["records.read"], false));
    *provider.0.lock().unwrap() = grant(&["reader"]);
    let second = h.rotated(SEED_TOKEN).await;
    let narrowed = h.record(&second).await;
    assert_eq!(narrowed.authorization_roles, grant(&["reader"]));
    h.users.insert(stored_user(
        &["member", "editor"],
        &["records.read", "records.write"],
        false,
    ));
    *provider.0.lock().unwrap() = grant(&["reader", "auditor"]);

    let reused = h.refresh(SEED_TOKEN).await.unwrap();

    assert_eq!(reused.user.roles, grant(&["member"]));
    assert_eq!(reused.user.scopes, grant(&["records.read"]));
    assert_eq!(
        reused.user.token_claims.authorization_roles,
        grant(&["reader"])
    );
    let record = h.record(&reused.refresh_token).await;
    assert_eq!(record.roles, grant(&["member"]));
    assert_eq!(record.scopes, grant(&["records.read"]));
    assert_eq!(record.authorization_roles, grant(&["reader"]));
}

#[tokio::test]
async fn legacy_grants_are_refused_inside_the_window() {
    let h = memory_harness().await;
    let second = h.rotated(SEED_TOKEN).await;
    let ids = [h.record(SEED_TOKEN).await.id, h.record(&second).await.id];
    {
        let mut tokens = h.store.tokens_by_id.lock().unwrap();
        for id in ids {
            tokens.get_mut(&id).unwrap().grant_source = RefreshGrantSource::Legacy;
        }
    }

    assert!(matches!(
        h.refresh(SEED_TOKEN).await,
        Err(AuthError::Forbidden)
    ));
    h.assert_only_live(&second).await;
    assert!(h.store.family_revocations.lock().unwrap().is_empty());
}

#[derive(Default)]
struct RecordingAuthority(Mutex<Vec<Uuid>>);

#[async_trait]
impl RefreshGrantAuthority for RecordingAuthority {
    async fn current_grant(
        &self,
        previous: &StoredRefreshToken,
        _: &StoredUser,
    ) -> crate::AuthResult<CurrentRefreshGrant> {
        self.0.lock().unwrap().push(previous.id);
        Ok(CurrentRefreshGrant {
            roles: grant(&["member"]),
            scopes: vec![],
        })
    }
}

async fn host_grant_harness(
    configure: impl FnOnce(
        AuthService<MemoryUserStore, MemoryRefreshTokenStore>,
    ) -> AuthService<MemoryUserStore, MemoryRefreshTokenStore>,
) -> Harness<MemoryRefreshTokenStore> {
    let store = Arc::new(MemoryRefreshTokenStore::default());
    let h = Harness::with(store, Some(WINDOW_SECONDS), configure).await;
    let seed_id = h.record(SEED_TOKEN).await.id;
    h.store
        .tokens_by_id
        .lock()
        .unwrap()
        .get_mut(&seed_id)
        .unwrap()
        .grant_source = RefreshGrantSource::Host;
    h
}

#[tokio::test]
async fn host_grants_are_read_against_the_newest_token_being_replaced() {
    let authority = Arc::new(RecordingAuthority::default());
    let h = host_grant_harness({
        let authority = authority.clone();
        |auth| auth.with_refresh_grant_authority(authority)
    })
    .await;
    let second = h.rotated(SEED_TOKEN).await;
    let second_id = h.record(&second).await.id;

    let reused = h.refresh(SEED_TOKEN).await.unwrap();

    assert_eq!(authority.0.lock().unwrap().last(), Some(&second_id));
    assert_eq!(reused.user.roles, grant(&["member"]));
    assert!(reused.user.scopes.is_empty());
}

#[tokio::test]
async fn host_grants_without_an_authority_are_refused_inside_the_window() {
    let authority = Arc::new(RecordingAuthority::default());
    let h = host_grant_harness(|auth| auth.with_refresh_grant_authority(authority)).await;
    let second = h.rotated(SEED_TOKEN).await;

    let strict = AuthService::new(
        AuthConfig::new(TEST_HS256_SECRET),
        Arc::new(h.users.clone()),
        h.store.clone(),
    )
    .unwrap()
    .with_refresh_rotation_clock(Arc::new(h.clock.clone()))
    .with_refresh_reuse_grace(Duration::seconds(WINDOW_SECONDS))
    .unwrap();

    assert!(matches!(
        strict.refresh(SEED_TOKEN, metadata()).await,
        Err(AuthError::Forbidden)
    ));
    h.assert_only_live(&second).await;
}

fn step_up() -> StepUpAuthentication {
    StepUpAuthentication {
        methods: vec!["otp".to_string()],
        acr: Some("urn:example:loa:2".to_string()),
        context: Some("local-totp".to_string()),
    }
}

#[tokio::test]
async fn a_reuse_keeps_the_assurance_of_the_presented_token() {
    let h = memory_harness().await;
    let stepped = h
        .auth
        .step_up_session(SEED_TOKEN, step_up(), metadata(), &h.clock)
        .await
        .unwrap();
    assert!(stepped.user.session.assurance.is_some());

    // The holder of the older token does not inherit the step-up.
    let reused = h.refresh(SEED_TOKEN).await.unwrap();
    assert!(reused.user.session.assurance.is_none());
    assert!(
        h.record(&reused.refresh_token)
            .await
            .session
            .assurance
            .is_none()
    );

    // The holder of the stepped-up token keeps it.
    let reused_stepped = h.refresh(&stepped.refresh_token).await.unwrap();
    assert_eq!(
        reused_stepped.user.session.assurance,
        stepped.user.session.assurance
    );
}

#[tokio::test]
async fn a_step_up_presenting_a_superseded_token_applies_only_the_verified_step_up() {
    let h = memory_harness().await;
    let second = h.rotated(SEED_TOKEN).await;

    let stepped = h
        .auth
        .step_up_session(SEED_TOKEN, step_up(), metadata(), &h.clock)
        .await
        .unwrap();

    h.assert_only_live(&stepped.refresh_token).await;
    assert!(h.record(&second).await.is_revoked());
    assert_eq!(stepped.user.token_claims.amr, Some(vec!["otp".to_string()]));
}

// Observable.

#[derive(Default)]
struct RecordingObserver(Mutex<Vec<RefreshReuseGraceEvent>>);

#[async_trait]
impl RefreshReuseGraceObserver for RecordingObserver {
    async fn refresh_reuse_granted(&self, event: &RefreshReuseGraceEvent) {
        self.0.lock().unwrap().push(event.clone());
    }
}

#[tokio::test]
async fn the_observer_sees_a_grace_reuse_and_nothing_else() {
    let observer = Arc::new(RecordingObserver::default());
    let store = Arc::new(MemoryRefreshTokenStore::default());
    let h = Harness::with(store, Some(WINDOW_SECONDS), {
        let observer = observer.clone();
        |auth| auth.with_refresh_reuse_grace_observer(observer)
    })
    .await;

    let second = h.rotated(SEED_TOKEN).await;
    assert!(
        observer.0.lock().unwrap().is_empty(),
        "ordinary rotation does not report"
    );

    h.clock.advance_seconds(2);
    let reused = h.refresh(SEED_TOKEN).await.unwrap();

    let events = observer.0.lock().unwrap().clone();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    let seed = h.record(SEED_TOKEN).await;
    assert_eq!(event.session_family_id, h.family);
    assert_eq!(event.session_id, seed.session_id);
    assert_eq!(event.user_id, USER_ID);
    assert_eq!(event.presented_token_id, seed.id);
    assert_eq!(Some(event.presented_revoked_at), seed.revoked_at);
    assert_eq!(event.superseded_token_id, h.record(&second).await.id);
    assert_eq!(
        event.replacement_token_id,
        h.record(&reused.refresh_token).await.id
    );
    assert_eq!(event.occurred_at, h.clock.now());
    assert_eq!(event.ip_address, metadata().ip_address);
    assert_eq!(event.user_agent, metadata().user_agent);

    let debug = format!("{event:?}");
    for raw in [SEED_TOKEN, second.as_str(), reused.refresh_token.as_str()] {
        assert!(!debug.contains(raw));
        assert!(!debug.contains(&hash_refresh_token(raw)));
    }

    h.clock.advance_seconds(WINDOW_SECONDS);
    h.assert_replay_ends_family(SEED_TOKEN).await;
    assert_eq!(
        observer.0.lock().unwrap().len(),
        1,
        "replay does not report"
    );
}

// The theft cost in the documentation.

#[tokio::test]
async fn a_thief_inside_the_window_is_detected_at_the_real_clients_next_refresh() {
    let h = memory_harness().await;
    // The real client rotated, and the thief presents the stolen older token.
    let client = h.rotated(SEED_TOKEN).await;
    h.clock.advance_seconds(1);
    let thief = h.rotated(SEED_TOKEN).await;
    h.assert_only_live(&thief).await;

    h.clock.advance_seconds(14 * 60);
    h.assert_replay_ends_family(&client).await;

    assert!(matches!(
        h.refresh(&thief).await,
        Err(AuthError::RefreshTokenReplayDetected)
    ));
}

#[tokio::test]
async fn a_thief_who_keeps_rotating_cannot_renew_the_real_clients_window() {
    let h = memory_harness().await;
    let client = h.rotated(SEED_TOKEN).await;
    h.clock.advance_seconds(1);
    let mut thief = h.rotated(SEED_TOKEN).await;
    let client_revoked_at = h.record(&client).await.revoked_at;

    for _ in 0..200 {
        h.clock.advance_seconds(5);
        thief = h.rotated(&thief).await;
        h.assert_only_live(&thief).await;
        assert_eq!(h.record(&client).await.revoked_at, client_revoked_at);
    }

    h.assert_replay_ends_family(&client).await;
    assert!(h.record(&thief).await.is_revoked());
}

#[tokio::test]
async fn when_the_real_client_returns_inside_the_window_the_thief_is_the_one_detected() {
    let h = memory_harness().await;
    let client = h.rotated(SEED_TOKEN).await;
    h.clock.advance_seconds(1);
    let thief = h.rotated(SEED_TOKEN).await;

    h.clock.advance_seconds(1);
    let client = h.rotated(&client).await;
    h.assert_only_live(&client).await;

    h.clock.advance_seconds(14 * 60);
    h.assert_replay_ends_family(&thief).await;
    assert!(h.record(&client).await.is_revoked());
}

// Configuration.

#[test]
fn configuration_refuses_a_window_outside_the_bound() {
    let service = || {
        AuthService::new(
            AuthConfig::new(TEST_HS256_SECRET),
            Arc::new(MemoryUserStore::default()),
            Arc::new(MemoryRefreshTokenStore::default()),
        )
        .unwrap()
    };
    assert_eq!(MAX_REFRESH_REUSE_GRACE, Duration::seconds(30));
    assert!(
        service()
            .with_refresh_reuse_grace(Duration::seconds(30))
            .is_ok()
    );
    assert!(
        service()
            .with_refresh_reuse_grace(Duration::milliseconds(1))
            .is_ok()
    );
    for refused in [
        Duration::seconds(30) + Duration::nanoseconds(1),
        Duration::seconds(31),
        Duration::ZERO,
        Duration::seconds(-1),
    ] {
        assert!(matches!(
            service().with_refresh_reuse_grace(refused),
            Err(AuthError::InvalidConfiguration(_))
        ));
    }

    let mut config = AuthConfig::new(TEST_HS256_SECRET);
    config.refresh_token_ttl = Duration::seconds(5);
    let short_lived = AuthService::new(
        config,
        Arc::new(MemoryUserStore::default()),
        Arc::new(MemoryRefreshTokenStore::default()),
    )
    .unwrap();
    assert!(matches!(
        short_lived.with_refresh_reuse_grace(Duration::seconds(5)),
        Err(AuthError::InvalidConfiguration(_))
    ));
}

// A store that can be told to misbehave at exact points.

const COMPETITOR_TOKEN: &str = "competitor-token";

#[derive(Clone, Copy, Default)]
enum BeforeRotate {
    #[default]
    Nothing,
    /// Another caller rotates first, stamped this many seconds in the past.
    CompetitorRotates(i64),
    /// The family is revoked after this call read the token.
    FamilyRevoked,
}

#[derive(Clone, Copy)]
enum Inconsistent {
    TwoLive,
    OtherSession,
}

struct ScriptedStore {
    inner: MemoryRefreshTokenStore,
    grace_support: bool,
    find_live_fails: bool,
    inconsistent: Option<Inconsistent>,
    rotate_conflicts: std::sync::atomic::AtomicBool,
    before_first_rotate: Mutex<BeforeRotate>,
    find_live_calls: AtomicUsize,
    revoke_calls: AtomicUsize,
}

impl Default for ScriptedStore {
    fn default() -> Self {
        Self {
            inner: MemoryRefreshTokenStore::default(),
            grace_support: true,
            find_live_fails: false,
            inconsistent: None,
            rotate_conflicts: false.into(),
            before_first_rotate: Mutex::default(),
            find_live_calls: AtomicUsize::new(0),
            revoke_calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl RefreshTokenStore for ScriptedStore {
    async fn insert_refresh_token(&self, token: StoredRefreshToken) -> crate::AuthResult<()> {
        self.inner.insert_refresh_token(token).await
    }

    async fn find_refresh_token_by_hash(
        &self,
        token_hash: &str,
    ) -> crate::AuthResult<Option<StoredRefreshToken>> {
        self.inner.find_refresh_token_by_hash(token_hash).await
    }

    async fn revoke_refresh_token(
        &self,
        token_id: Uuid,
        revoked_at: OffsetDateTime,
        replaced_by_token_id: Option<Uuid>,
        reason: RefreshTokenRevocationReason,
    ) -> crate::AuthResult<()> {
        self.revoke_calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .revoke_refresh_token(token_id, revoked_at, replaced_by_token_id, reason)
            .await
    }

    async fn revoke_refresh_token_family(
        &self,
        session_family_id: Uuid,
        revoked_at: OffsetDateTime,
        reason: RefreshTokenRevocationReason,
    ) -> crate::AuthResult<()> {
        self.inner
            .revoke_refresh_token_family(session_family_id, revoked_at, reason)
            .await
    }

    async fn touch_refresh_token(
        &self,
        token_id: Uuid,
        used_at: OffsetDateTime,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> crate::AuthResult<()> {
        self.inner
            .touch_refresh_token(token_id, used_at, ip_address, user_agent)
            .await
    }

    async fn rotate_refresh_token(
        &self,
        current_token_id: Uuid,
        replacement: StoredRefreshToken,
        rotated_at: OffsetDateTime,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> crate::AuthResult<bool> {
        if self.rotate_conflicts.load(Ordering::SeqCst) {
            return Ok(false);
        }
        let before = std::mem::take(&mut *self.before_first_rotate.lock().unwrap());
        match before {
            BeforeRotate::Nothing => {}
            BeforeRotate::CompetitorRotates(seconds_ago) => {
                let competitor = StoredRefreshToken {
                    id: Uuid::new_v4(),
                    token_hash: hash_refresh_token(COMPETITOR_TOKEN),
                    ..replacement.clone()
                };
                assert!(
                    self.inner
                        .rotate_refresh_token(
                            current_token_id,
                            competitor,
                            rotated_at - Duration::seconds(seconds_ago),
                            None,
                            None,
                        )
                        .await?
                );
            }
            BeforeRotate::FamilyRevoked => {
                self.inner
                    .revoke_refresh_token_family(
                        replacement.session_family_id,
                        rotated_at,
                        RefreshTokenRevocationReason::Logout,
                    )
                    .await?;
            }
        }
        self.inner
            .rotate_refresh_token(
                current_token_id,
                replacement,
                rotated_at,
                ip_address,
                user_agent,
            )
            .await
    }

    async fn find_live_refresh_tokens_in_family(
        &self,
        session_family_id: Uuid,
    ) -> crate::AuthResult<Option<Vec<StoredRefreshToken>>> {
        self.find_live_calls.fetch_add(1, Ordering::SeqCst);
        if !self.grace_support {
            return Ok(None);
        }
        if self.find_live_fails {
            return Err(AuthError::Store("read failed".to_string()));
        }
        let mut live = self
            .inner
            .find_live_refresh_tokens_in_family(session_family_id)
            .await?;
        if let (Some(answer), Some(tokens)) = (self.inconsistent, live.as_mut()) {
            match answer {
                Inconsistent::TwoLive => tokens.push(tokens[0].clone()),
                Inconsistent::OtherSession => tokens[0].session_id = Uuid::new_v4(),
            }
        }
        Ok(live)
    }
}
