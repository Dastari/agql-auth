//! Executable consumer-store conformance without additional Cargo dependencies.
use std::{
    io::Write,
    process::{Command, Stdio},
    sync::Arc,
};

use async_trait::async_trait;
use serde_json::{Value, json};
use uuid::Uuid;

use super::password_login::{
    clear_order_contract, concurrent_contract, independent_buckets_contract, rejection_contract,
    store_contract, success_contract,
};
use crate::prelude::*;

struct ConsumerStore {
    backend: &'static str,
    database: String,
    table: String,
}
impl ConsumerStore {
    async fn new(backend: &'static str, database: String) -> Arc<Self> {
        let store = Arc::new(Self {
            backend,
            database,
            table: format!("agql_conformance_{}", Uuid::new_v4().simple()),
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
                    "/testdata/consumer_rate_limit_store.py"
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
#[async_trait]
impl AuthRateLimitStore for ConsumerStore {
    async fn find_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
    ) -> crate::AuthResult<Option<AuthRateLimitSnapshot>> {
        serde_json::from_value(self.call(json!({"op": "find", "key": key})).await?)
            .map_err(|e| AuthError::Store(e.to_string()))
    }
    async fn compare_exchange_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
        expected_revision: Option<Uuid>,
        replacement: AuthRateLimitSnapshot,
    ) -> crate::AuthResult<bool> {
        if replacement.state.key != *key {
            return Err(AuthError::Store(
                "replacement key does not match compare key".into(),
            ));
        }
        Ok(self.call(json!({"op": "cas", "key": key, "expected_revision": expected_revision, "replacement": replacement})).await? == json!(true))
    }
    async fn clear_auth_rate_limit_state(
        &self,
        key: &AuthRateLimitKey,
        expected_revision: Option<Uuid>,
    ) -> crate::AuthResult<bool> {
        Ok(self
            .call(json!({"op": "clear", "key": key, "expected_revision": expected_revision}))
            .await?
            == json!(true))
    }
}

async fn contract(backend: &'static str, database: &str) {
    // Fresh stores keep every case isolated even though all use the same client.
    for contract in 0..6 {
        let database = if backend == "sqlite" {
            std::env::temp_dir()
                .join(format!("agql-conformance-{}.sqlite", Uuid::new_v4()))
                .to_str()
                .unwrap()
                .to_owned()
        } else {
            database.to_owned()
        };
        let store = ConsumerStore::new(backend, database).await;
        match contract {
            0 => rejection_contract(store.clone()).await,
            1 => success_contract(store.clone()).await,
            2 => concurrent_contract(store.clone()).await,
            3 => clear_order_contract(store.clone()).await,
            4 => store_contract(store.clone()).await,
            _ => independent_buckets_contract(store.clone()).await,
        }
        store.cleanup().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "consumer fixture: requires Python 3 and SQLite >= 3.35; see docs/password-login-review.md"]
async fn sqlite_password_login_consumer_conformance() {
    contract("sqlite", "").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "consumer fixture: requires Python 3, psql and AGQL_AUTH_TEST_POSTGRES_URL"]
async fn postgres_password_login_consumer_conformance() {
    let database = std::env::var("AGQL_AUTH_TEST_POSTGRES_URL")
        .expect("set AGQL_AUTH_TEST_POSTGRES_URL to an isolated test database");
    contract("postgres", &database).await;
}
