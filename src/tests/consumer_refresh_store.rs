//! Refresh reuse grace on a consumer store with real SQLite and PostgreSQL
//! transactions, without additional Cargo dependencies.
use std::{
    io::Write,
    process::{Command, Stdio},
    sync::Arc,
};

use async_trait::async_trait;
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use super::refresh_reuse_grace::{
    double_refresh_contract, racing_different_tokens_contract, racing_reuses_contract,
    reuse_races_family_revocation_contract, sequential_contract,
};
use crate::prelude::*;

struct ConsumerRefreshStore {
    backend: &'static str,
    database: String,
    table: String,
}

impl ConsumerRefreshStore {
    async fn new(backend: &'static str, database: String) -> Arc<Self> {
        let store = Arc::new(Self {
            backend,
            database,
            table: format!("agql_refresh_conformance_{}", Uuid::new_v4().simple()),
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
        Ok(self
            .call(json!({
                "op": "rotate",
                "current": current_token_id,
                "replacement": replacement,
                "rotated_at": rotated_at,
                "ip_address": ip_address,
                "user_agent": user_agent,
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

/// Races are repeated because one interleaving proves little.
const RACE_ROUNDS: usize = 8;

async fn contract(backend: &'static str, database: &str) {
    for contract in 0..5 {
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
                _ => reuse_races_family_revocation_contract(store.clone()).await,
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
