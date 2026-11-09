//! Refresh reuse grace on a consumer store with real SQLite and PostgreSQL
//! transactions, without additional Cargo dependencies.
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration as StdDuration,
};

use async_trait::async_trait;
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use super::refresh_reuse_grace::{
    SEED_TOKEN, double_refresh_contract, logout_racing_rotation_contract,
    racing_different_tokens_contract, racing_reuses_contract, seed_record, sequential_contract,
};
use super::refresh_store_conformance::{
    racing_rotations_contract, rotation_racing_family_revocation_contract, user_revocation_contract,
};
use crate::prelude::*;

struct ConsumerRefreshStore {
    backend: &'static str,
    database: String,
    table: String,
    /// Holds the next rotation open before COMMIT until `release` appears here.
    pause_next_rotation: Mutex<Option<PathBuf>>,
    /// Holds the next family revocation open the same way.
    pause_next_family_revocation: Mutex<Option<PathBuf>>,
    /// Holds the next user revocation open the same way.
    pause_next_user_revocation: Mutex<Option<PathBuf>>,
}

impl ConsumerRefreshStore {
    async fn new(backend: &'static str, database: String) -> Arc<Self> {
        let store = Arc::new(Self {
            backend,
            database,
            table: format!("agql_refresh_conformance_{}", Uuid::new_v4().simple()),
            pause_next_rotation: Mutex::default(),
            pause_next_family_revocation: Mutex::default(),
            pause_next_user_revocation: Mutex::default(),
        });
        store.call(json!({"op": "init"})).await.unwrap();
        store
    }

    async fn call(&self, mut request: Value) -> crate::AuthResult<Value> {
        request["backend"] = json!(self.backend);
        request["database"] = json!(self.database);
        request["table"] = json!(self.table);
        tokio::task::spawn_blocking(move || {
            let mut child = Command::new("python3")
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/testdata/consumer_refresh_token_store.py"
                ))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| AuthError::Store(e.to_string()))?;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(&serde_json::to_vec(&request).unwrap())
                .map_err(|e| AuthError::Store(e.to_string()))?;
            let output = child
                .wait_with_output()
                .map_err(|e| AuthError::Store(e.to_string()))?;
            if !output.status.success() {
                return Err(AuthError::Store(
                    String::from_utf8_lossy(&output.stderr).into_owned(),
                ));
            }
            serde_json::from_slice(&output.stdout).map_err(|e| AuthError::Store(e.to_string()))
        })
        .await
        .unwrap()
    }

    async fn cleanup(&self) {
        self.call(json!({"op": "drop"})).await.unwrap();
        if self.backend == "sqlite" {
            for suffix in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(format!("{}{suffix}", self.database));
            }
        }
    }
}

fn reason_text(reason: &RefreshTokenRevocationReason) -> String {
    format!("{reason:?}")
}

#[async_trait]
impl RefreshTokenStore for ConsumerRefreshStore {
    async fn insert_refresh_token(&self, token: StoredRefreshToken) -> crate::AuthResult<()> {
        self.call(json!({"op": "insert", "token": token})).await?;
        Ok(())
    }

    async fn find_refresh_token_by_hash(
        &self,
        token_hash: &str,
    ) -> crate::AuthResult<Option<StoredRefreshToken>> {
        serde_json::from_value(
            self.call(json!({"op": "find_by_hash", "token_hash": token_hash}))
                .await?,
        )
        .map_err(|e| AuthError::Store(e.to_string()))
    }

    async fn revoke_refresh_token(
        &self,
        token_id: Uuid,
        revoked_at: OffsetDateTime,
        replaced_by_token_id: Option<Uuid>,
        reason: RefreshTokenRevocationReason,
    ) -> crate::AuthResult<()> {
        self.call(json!({
            "op": "revoke",
            "id": token_id,
            "revoked_at": revoked_at,
            "replaced_by": replaced_by_token_id,
            "reason": reason_text(&reason),
        }))
        .await?;
        Ok(())
    }

    async fn revoke_refresh_token_family(
        &self,
        session_family_id: Uuid,
        revoked_at: OffsetDateTime,
        reason: RefreshTokenRevocationReason,
    ) -> crate::AuthResult<()> {
        let pause = self.pause_next_family_revocation.lock().unwrap().take();
        self.call(json!({
            "op": "revoke_family",
            "family": session_family_id,
            "revoked_at": revoked_at,
            "reason": reason_text(&reason),
            "pause_dir": pause,
        }))
        .await?;
        Ok(())
    }

    async fn revoke_refresh_tokens_for_user(
        &self,
        user_id: &str,
        revoked_at: OffsetDateTime,
        reason: RefreshTokenRevocationReason,
    ) -> crate::AuthResult<u64> {
        let pause = self.pause_next_user_revocation.lock().unwrap().take();
        self.call(json!({
            "op": "revoke_user",
            "user_id": user_id,
            "revoked_at": revoked_at,
            "reason": reason_text(&reason),
            "pause_dir": pause,
        }))
        .await?
        .as_u64()
        .ok_or_else(|| AuthError::Store("revoke_user returned no count".to_string()))
    }

    async fn touch_refresh_token(
        &self,
        token_id: Uuid,
        used_at: OffsetDateTime,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> crate::AuthResult<()> {
        self.call(json!({
            "op": "touch",
            "id": token_id,
            "used_at": used_at,
            "ip_address": ip_address,
            "user_agent": user_agent,
        }))
        .await?;
        Ok(())
    }

    async fn rotate_refresh_token(
        &self,
        current_token_id: Uuid,
        replacement: StoredRefreshToken,
        rotated_at: OffsetDateTime,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> crate::AuthResult<bool> {
        let pause = self.pause_next_rotation.lock().unwrap().take();
        Ok(self
            .call(json!({
                "op": "rotate",
                "current": current_token_id,
                "replacement": replacement,
                "rotated_at": rotated_at,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "pause_dir": pause,
            }))
            .await?
            == json!(true))
    }

    async fn find_live_refresh_tokens_in_family(
        &self,
        session_family_id: Uuid,
    ) -> crate::AuthResult<Option<Vec<StoredRefreshToken>>> {
        serde_json::from_value(
            self.call(json!({"op": "find_live", "family": session_family_id}))
                .await?,
        )
        .map_err(|e| AuthError::Store(e.to_string()))
    }
}

/// The dev-dependency has no tokio timer, so sleep on the blocking pool.
async fn sleep_ms(ms: u64) {
    tokio::task::spawn_blocking(move || std::thread::sleep(StdDuration::from_millis(ms)))
        .await
        .unwrap();
}

async fn wait_for(what: &str, mut ready: impl AsyncFnMut() -> bool) {
    for _ in 0..1500 {
        if ready().await {
            return;
        }
        sleep_ms(20).await;
    }
    panic!("timed out waiting for {what}");
}

/// Family revocation that starts while a rotation is uncommitted.
///
/// The rotation is held after its writes and before COMMIT, the revocation is
/// started and shown to be blocked, then the rotation is released. Nothing else
/// runs, so a replacement the revocation missed is still live when both finish.
async fn family_revocation_during_rotation_contract(store: Arc<ConsumerRefreshStore>) {
    let now = OffsetDateTime::now_utc();
    let family = Uuid::new_v4();
    let current = seed_record(SEED_TOKEN, family, Uuid::new_v4(), now);
    store.insert_refresh_token(current.clone()).await.unwrap();
    let replacement = seed_record("replacement", family, current.session_id, now);

    let pause = std::env::temp_dir().join(format!("agql-refresh-pause-{}", Uuid::new_v4()));
    std::fs::create_dir(&pause).unwrap();
    *store.pause_next_rotation.lock().unwrap() = Some(pause.clone());

    let rotation = tokio::spawn({
        let store = store.clone();
        let id = current.id;
        async move {
            store
                .rotate_refresh_token(id, replacement, now, None, None)
                .await
        }
    });
    let paused = pause.join("paused");
    wait_for("the rotation to hold", async || Path::new(&paused).exists()).await;

    let revocation = tokio::spawn({
        let store = store.clone();
        async move {
            store
                .revoke_refresh_token_family(family, now, RefreshTokenRevocationReason::Logout)
                .await
        }
    });
    wait_for_blocked(&store).await;
    assert!(
        !revocation.is_finished(),
        "the revocation must wait for the rotation"
    );

    std::fs::write(pause.join("release"), b"").unwrap();
    assert!(rotation.await.unwrap().unwrap());
    revocation.await.unwrap().unwrap();
    let _ = std::fs::remove_dir_all(&pause);

    let live = store
        .find_live_refresh_tokens_in_family(family)
        .await
        .unwrap()
        .unwrap();
    assert!(
        live.is_empty(),
        "a replacement committed during sign-out must not survive it: {} live",
        live.len()
    );
}

/// Rotation that starts while a family revocation is uncommitted.
///
/// The revocation is held after its writes and before COMMIT, the rotation is
/// started and shown to be blocked, then the revocation is released. The
/// rotation must find the token revoked and insert nothing. A port that reads
/// without a lock, inserts, and ignores the row count of its update would
/// return `true` here and leave its replacement live after sign-out.
async fn rotation_during_family_revocation_contract(store: Arc<ConsumerRefreshStore>) {
    let now = OffsetDateTime::now_utc();
    let family = Uuid::new_v4();
    let current = seed_record(SEED_TOKEN, family, Uuid::new_v4(), now);
    store.insert_refresh_token(current.clone()).await.unwrap();
    let replacement = seed_record("replacement", family, current.session_id, now);

    let pause = std::env::temp_dir().join(format!("agql-refresh-pause-{}", Uuid::new_v4()));
    std::fs::create_dir(&pause).unwrap();
    *store.pause_next_family_revocation.lock().unwrap() = Some(pause.clone());

    let revocation = tokio::spawn({
        let store = store.clone();
        async move {
            store
                .revoke_refresh_token_family(family, now, RefreshTokenRevocationReason::Logout)
                .await
        }
    });
    let paused = pause.join("paused");
    wait_for("the revocation to hold", async || {
        Path::new(&paused).exists()
    })
    .await;

    let rotation = tokio::spawn({
        let store = store.clone();
        let id = current.id;
        async move {
            store
                .rotate_refresh_token(id, replacement, now, None, None)
                .await
        }
    });
    wait_for_blocked(&store).await;
    assert!(
        !rotation.is_finished(),
        "the rotation must wait for the revocation"
    );

    std::fs::write(pause.join("release"), b"").unwrap();
    revocation.await.unwrap().unwrap();
    assert!(
        !rotation.await.unwrap().unwrap(),
        "a rotation of a token revoked under it must report the conflict"
    );
    let _ = std::fs::remove_dir_all(&pause);

    let live = store
        .find_live_refresh_tokens_in_family(family)
        .await
        .unwrap()
        .unwrap();
    assert!(
        live.is_empty(),
        "a rotation that lost to sign-out must not insert: {} live",
        live.len()
    );
}

/// User-wide revocation that starts while a rotation is uncommitted.
///
/// As for family revocation: the rotation is held before COMMIT, the
/// revocation is shown to be blocked, then the rotation is released. The
/// replacement it commits must not survive.
async fn user_revocation_during_rotation_contract(store: Arc<ConsumerRefreshStore>) {
    let now = OffsetDateTime::now_utc();
    let family = Uuid::new_v4();
    let current = seed_record(SEED_TOKEN, family, Uuid::new_v4(), now);
    let user = current.user_id.clone();
    store.insert_refresh_token(current.clone()).await.unwrap();
    let replacement = seed_record("replacement", family, current.session_id, now);

    let pause = std::env::temp_dir().join(format!("agql-refresh-pause-{}", Uuid::new_v4()));
    std::fs::create_dir(&pause).unwrap();
    *store.pause_next_rotation.lock().unwrap() = Some(pause.clone());

    let rotation = tokio::spawn({
        let store = store.clone();
        let id = current.id;
        async move {
            store
                .rotate_refresh_token(id, replacement, now, None, None)
                .await
        }
    });
    let paused = pause.join("paused");
    wait_for("the rotation to hold", async || Path::new(&paused).exists()).await;

    let revocation = tokio::spawn({
        let store = store.clone();
        async move {
            store
                .revoke_refresh_tokens_for_user(
                    &user,
                    now,
                    RefreshTokenRevocationReason::AdminRevoked,
                )
                .await
        }
    });
    wait_for_blocked(&store).await;
    assert!(
        !revocation.is_finished(),
        "the revocation must wait for the rotation"
    );

    std::fs::write(pause.join("release"), b"").unwrap();
    assert!(rotation.await.unwrap().unwrap());
    assert_eq!(revocation.await.unwrap().unwrap(), 1);
    let _ = std::fs::remove_dir_all(&pause);

    let live = store
        .find_live_refresh_tokens_in_family(family)
        .await
        .unwrap()
        .unwrap();
    assert!(
        live.is_empty(),
        "a replacement committed during user revocation must not survive it: {} live",
        live.len()
    );
}

/// Waits until a second writer is blocked behind a held transaction.
async fn wait_for_blocked(store: &ConsumerRefreshStore) {
    let blocked = store
        .call(json!({"op": "blocked_lock_requests"}))
        .await
        .unwrap();
    if blocked.is_null() {
        // SQLite has no lock view. Its writer lock serializes the second
        // writer whenever it starts, so the order does not change the outcome.
        sleep_ms(300).await;
    } else {
        wait_for("the second writer to block", async || {
            store
                .call(json!({"op": "blocked_lock_requests"}))
                .await
                .unwrap()
                != json!(0)
        })
        .await;
    }
}

/// Races are repeated because one interleaving proves little.
const RACE_ROUNDS: usize = 8;

async fn contract(backend: &'static str, database: &str) {
    for contract in 0..11 {
        let rounds = match contract {
            0 => 1,
            // These repeat internally.
            7..=9 => 2,
            _ => RACE_ROUNDS,
        };
        for _ in 0..rounds {
            let database = if backend == "sqlite" {
                std::env::temp_dir()
                    .join(format!(
                        "agql-refresh-conformance-{}.sqlite",
                        Uuid::new_v4()
                    ))
                    .to_str()
                    .unwrap()
                    .to_owned()
            } else {
                database.to_owned()
            };
            let store = ConsumerRefreshStore::new(backend, database).await;
            match contract {
                0 => sequential_contract(store.clone()).await,
                1 => double_refresh_contract(store.clone()).await,
                2 => racing_reuses_contract(store.clone()).await,
                3 => racing_different_tokens_contract(store.clone()).await,
                4 => logout_racing_rotation_contract(store.clone()).await,
                5 => family_revocation_during_rotation_contract(store.clone()).await,
                6 => rotation_during_family_revocation_contract(store.clone()).await,
                7 => rotation_racing_family_revocation_contract(store.clone()).await,
                8 => racing_rotations_contract(store.clone()).await,
                9 => user_revocation_contract(store.clone()).await,
                _ => user_revocation_during_rotation_contract(store.clone()).await,
            }
            store.cleanup().await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "consumer fixture: requires Python 3 and SQLite >= 3.35"]
async fn sqlite_refresh_reuse_grace_consumer_conformance() {
    contract("sqlite", "").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "consumer fixture: requires Python 3, psql and AGQL_AUTH_TEST_POSTGRES_URL"]
async fn postgres_refresh_reuse_grace_consumer_conformance() {
    let database = std::env::var("AGQL_AUTH_TEST_POSTGRES_URL")
        .expect("set AGQL_AUTH_TEST_POSTGRES_URL to an isolated test database");
    contract("postgres", &database).await;
}
