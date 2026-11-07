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
use crate::prelude::*;

struct ConsumerRefreshStore {
    backend: &'static str,
    database: String,
    table: String,
    /// Holds the next rotation open before COMMIT until `release` appears here.
    pause_next_rotation: Mutex<Option<PathBuf>>,
}

impl ConsumerRefreshStore {
    async fn new(backend: &'static str, database: String) -> Arc<Self> {
        let store = Arc::new(Self {
            backend,
            database,
            table: format!("agql_refresh_conformance_{}", Uuid::new_v4().simple()),
            pause_next_rotation: Mutex::default(),
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
        self.call(json!({
            "op": "revoke_family",
            "family": session_family_id,
            "revoked_at": revoked_at,
            "reason": reason_text(&reason),
        }))
        .await?;
        Ok(())
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
    let blocked = store
        .call(json!({"op": "blocked_lock_requests"}))
        .await
        .unwrap();
    if blocked.is_null() {
        // SQLite has no lock view. Its writer lock serializes the revocation
        // whenever it starts, so the order does not change the outcome.
        sleep_ms(300).await;
    } else {
        wait_for("the revocation to block", async || {
            store
                .call(json!({"op": "blocked_lock_requests"}))
                .await
                .unwrap()
                != json!(0)
        })
        .await;
    }
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

/// Races are repeated because one interleaving proves little.
const RACE_ROUNDS: usize = 8;

async fn contract(backend: &'static str, database: &str) {
    for contract in 0..6 {
        let rounds = if contract == 0 { 1 } else { RACE_ROUNDS };
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
                _ => family_revocation_during_rotation_contract(store.clone()).await,
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
